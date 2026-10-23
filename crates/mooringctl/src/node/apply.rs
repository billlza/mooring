// SPDX-License-Identifier: GPL-3.0-or-later

//! `node apply <id> --interface <bsd> --engines <dir>` (design §11.2,
//! §13.2 step 5): renders the node's bundle for the current generation,
//! uploads the blobs it lacks, runs the transaction, confirms it from a new
//! session and records what the node confirmed (`Bookkeeping::Applied`).

use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use mooring_agent_proto::{Generation, LineRequest, RequestKind, Response, TxnStage, TxnState};
use mooring_model::iface::BsdName;
use mooring_model::node::AppliedConfig;
use mooring_model::{Bookkeeping, NodeId};
use mooring_render::vps::bundle;
use mooring_store::{Store, read_snapshot};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::node::engines::Engines;
use crate::node::session::{deployed_node, ops_session};
use crate::node::{NodeError, NodeSession, upload_missing};
use crate::state::{load, output};

/// How often the transaction's state is read.
pub(crate) const POLL: Duration = Duration::from_secs(2);

/// How long the transaction may take before the command gives up waiting:
/// the agent's own confirm timer (120 s) after the health gate, which the
/// gate itself precedes.
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(300);

/// `node apply`.
pub(crate) fn apply(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    node: &NodeId,
    interface: &BsdName,
    engines: &Path,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let deployment = &state.deployment;
    let target = deployed_node(deployment.nodes(), node)?;
    let engines = Engines::open(engines, env.engine_pins)?;
    let secrets = read_snapshot(&*env.secrets, &deployment.required_secrets())
        .map_err(|error| LocalError::Secrets(Box::new(error)))?;
    let bundle =
        bundle(deployment, node, &secrets, engines.catalog()).map_err(LocalError::Render)?;
    let mut session = ops_session(env, target, interface, None)?;
    let reply = session.request(&LineRequest::Hello)?;
    let Response::Hello(hello) = reply else {
        return Err(unexpected(RequestKind::Hello, &reply));
    };
    let header = bundle.header(&hello.host).map_err(LocalError::Render)?;
    let uploaded = upload_missing(session.as_mut(), header.blobs(), |sha256| {
        if let Some((_, file)) = bundle.files().find(|(_, file)| file.sha256() == *sha256) {
            return Ok(file.expose_bytes().to_vec());
        }
        engines
            .blob(sha256)?
            .ok_or(LocalError::EngineMissing { sha256: *sha256 })
    })?;
    writeln!(
        out,
        "{node}: generation {}, bundle {}, {uploaded} blob(s) uploaded",
        deployment.config_generation(),
        bundle.digest()
    )
    .map_err(output)?;
    let reply = session.request(&LineRequest::Apply(Box::new(header)))?;
    let generation = match reply {
        Response::TxnLaunched { generation } => {
            wait_for_confirm(session.as_mut(), out, generation)?;
            let reply = session.request(&LineRequest::Confirm { generation })?;
            if reply != (Response::Confirmed { generation }) {
                return Err(unexpected(RequestKind::Confirm, &reply));
            }
            generation
        }
        Response::Unchanged { generation } => {
            writeln!(
                out,
                "{node} already serves this bundle (its generation {})",
                generation.get()
            )
            .map_err(output)?;
            generation
        }
        other => return Err(unexpected(RequestKind::Apply, &other)),
    };
    store
        .record(
            deployment.config_generation(),
            Bookkeeping::Applied {
                node: node.clone(),
                applied: AppliedConfig {
                    config_generation: deployment.config_generation(),
                    digest: bundle.digest(),
                },
            },
        )
        .map_err(|error| LocalError::StateChange(Box::new(error)))?;
    writeln!(
        out,
        "applied: {node} confirmed generation {} (node generation {}); users holding it can be exported",
        deployment.config_generation(),
        generation.get()
    )
    .map_err(output)?;
    Ok(())
}

/// Reads the transaction's state every [`POLL`] until it awaits
/// confirmation, printing each new stage; a failed or reverted transaction
/// is the error, and so is one still running after [`MAX_WAIT`].
fn wait_for_confirm(
    session: &mut dyn NodeSession,
    out: &mut dyn Write,
    generation: Generation,
) -> Result<(), CommandError> {
    let started = Instant::now();
    let mut shown: Option<TxnStage> = None;
    loop {
        let reply = session.request(&LineRequest::TxnStatus { generation })?;
        let Response::TxnStatus {
            generation: reported,
            state,
        } = reply
        else {
            return Err(unexpected(RequestKind::TxnStatus, &reply));
        };
        if reported != generation {
            return Err(unexpected(
                RequestKind::TxnStatus,
                &Response::TxnStatus {
                    generation: reported,
                    state,
                },
            ));
        }
        match state {
            TxnState::AwaitingConfirm => return Ok(()),
            TxnState::Running { stage } => {
                if shown != Some(stage) {
                    writeln!(out, "  {stage:?}").map_err(output)?;
                    shown = Some(stage);
                }
            }
            TxnState::Committed => {
                return Err(LocalError::TxnAlreadyCommitted {
                    generation: generation.get(),
                }
                .into());
            }
            TxnState::Reverted => {
                return Err(LocalError::TxnReverted {
                    generation: generation.get(),
                }
                .into());
            }
            TxnState::Failed { error } => {
                return Err(LocalError::TxnFailed {
                    generation: generation.get(),
                    source: error,
                }
                .into());
            }
        }
        if started.elapsed() >= MAX_WAIT {
            return Err(LocalError::TxnTimeout {
                generation: generation.get(),
                secs: MAX_WAIT.as_secs(),
            }
            .into());
        }
        thread::sleep(POLL);
    }
}

fn unexpected(request: RequestKind, reply: &Response) -> CommandError {
    NodeError::Unexpected {
        request,
        response: reply.kind(),
    }
    .into()
}
