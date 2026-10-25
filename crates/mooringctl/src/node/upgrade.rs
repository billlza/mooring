// SPDX-License-Identifier: GPL-3.0-or-later

//! `node upgrade-agent <id> --interface <bsd> --agent <binary>` (design
//! §11.2): uploads the agent if the node lacks it and has the node activate
//! it. The node installs it beside the running agent, runs its `self-test`,
//! makes it the forced command and arms the revert timer, which the
//! previous agent runs. The `Confirm` then goes out on a new session, so
//! the new agent must serve it, and a last `Hello` shows the agent that
//! runs. An activation changes neither the node's generation nor the
//! state.

use std::io::Write;
use std::path::Path;

use mooring_agent_proto::{LineRequest, RequestKind, Response, Sha256Hex};
use mooring_model::iface::BsdName;
use mooring_model::{NodeId, Sha256Digest};
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::node::adopt::read_agent;
use crate::node::session::{deployed_node, ops_session};
use crate::node::{NodeError, NodeSession, upload_missing};
use crate::state::{load, output};

/// `node upgrade-agent`.
pub(crate) fn upgrade_agent(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    node: &NodeId,
    interface: &BsdName,
    agent: &Path,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let target = deployed_node(state.deployment.nodes(), node)?;
    let bytes = read_agent(agent)?;
    let sha = Sha256Hex::from_bytes(*Sha256Digest::of(&bytes).as_bytes());
    let mut session = ops_session(env, target, interface, None)?;
    let running = running_agent(session.as_mut())?;
    if running == sha {
        writeln!(out, "{node} already runs agent {sha}").map_err(output)?;
        return Ok(());
    }
    let uploaded = upload_missing(session.as_mut(), [sha].into(), |_| Ok(bytes.clone()))?;
    writeln!(
        out,
        "{node}: runs agent {running}; agent {sha}, {uploaded} blob(s) uploaded"
    )
    .map_err(output)?;
    let reply = session.request(&LineRequest::ActivateAgent { sha })?;
    let Response::AwaitingConfirm { generation } = reply else {
        return Err(unexpected(RequestKind::ActivateAgent, &reply));
    };
    let reply = session.request(&LineRequest::Confirm { generation })?;
    if reply != (Response::Confirmed { generation }) {
        return Err(unexpected(RequestKind::Confirm, &reply));
    }
    let found = running_agent(session.as_mut())?;
    if found != sha {
        return Err(LocalError::AgentNotSwitched {
            node: node.clone(),
            expected: sha,
            found,
        }
        .into());
    }
    writeln!(
        out,
        "upgraded: {node} runs agent {sha} (node generation {})",
        generation.get()
    )
    .map_err(output)?;
    Ok(())
}

/// The digest of the agent the node runs, from its `Hello`.
fn running_agent(session: &mut dyn NodeSession) -> Result<Sha256Hex, CommandError> {
    match session.request(&LineRequest::Hello)? {
        Response::Hello(hello) => Ok(hello.agent_sha),
        other => Err(unexpected(RequestKind::Hello, &other)),
    }
}

fn unexpected(request: RequestKind, reply: &Response) -> CommandError {
    NodeError::Unexpected {
        request,
        response: reply.kind(),
    }
    .into()
}
