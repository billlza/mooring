// SPDX-License-Identifier: GPL-3.0-or-later

//! Inspect and converge the real watch process after an agent activation.

use std::io::Write;
use std::time::{Duration, Instant};

use mooring_agent_proto::{LineRequest, RequestKind, Response, Sha256Hex, WatchRuntime};
use mooring_daemon_core::control::{MAX_REPLY_LINE_BYTES, encode_line};
use mooring_model::NodeId;
use mooring_model::iface::BsdName;
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::node::session::{deployed_node, ops_session};
use crate::state::{load, output};

/// The read-only `node runtime` command.
pub(crate) fn inspect(
    env: &Env<'_>,
    out: &mut dyn Write,
    node: &NodeId,
    interface: &BsdName,
    json: bool,
) -> Result<(), CommandError> {
    let runtime = request(env, node, interface, None)?;
    if json {
        let bytes =
            encode_line(&runtime, MAX_REPLY_LINE_BYTES).map_err(LocalError::ClientEncode)?;
        out.write_all(&bytes).map_err(output)?;
    } else {
        writeln!(out, "{node}: control agent {}", runtime.agent_sha).map_err(output)?;
        match runtime.watch {
            Some(watch) => writeln!(
                out,
                "watch: {} (pid {}, start ticks {})",
                watch.executable_sha, watch.pid, watch.start_ticks
            ),
            None => writeln!(out, "watch: no main process"),
        }
        .map_err(output)?;
    }
    Ok(())
}

/// Verifies a watch, restarting only when it does not run `expected`.
pub(crate) fn converge(
    env: &Env<'_>,
    out: &mut dyn Write,
    node: &NodeId,
    interface: &BsdName,
    expected: Sha256Hex,
) -> Result<(), CommandError> {
    let before = request(env, node, interface, None)?;
    match &before.watch {
        Some(watch) => writeln!(
            out,
            "before refresh: {node} watch {} (pid {}, start ticks {})",
            watch.executable_sha, watch.pid, watch.start_ticks
        ),
        None => writeln!(out, "before refresh: {node} watch has no main process"),
    }
    .map_err(output)?;
    let runtime = request(env, node, interface, Some(expected))?;
    let found = runtime.watch.as_ref().map(|watch| watch.executable_sha);
    if runtime.agent_sha != expected || found != Some(expected) {
        return Err(LocalError::WatchNotSwitched {
            node: node.clone(),
            expected,
            found,
        }
        .into());
    }
    let Some(watch) = runtime.watch else {
        return Err(LocalError::WatchNotSwitched {
            node: node.clone(),
            expected,
            found: None,
        }
        .into());
    };
    writeln!(
        out,
        "verified: {node} watch runs {} (pid {}, start ticks {})",
        watch.executable_sha, watch.pid, watch.start_ticks
    )
    .map_err(output)
}

fn request(
    env: &Env<'_>,
    node: &NodeId,
    interface: &BsdName,
    expected: Option<Sha256Hex>,
) -> Result<WatchRuntime, CommandError> {
    let state = load(&Store::new(support_dir(env)?))?;
    let target = deployed_node(state.deployment.nodes(), node)?;
    let mut session = ops_session(
        env,
        target,
        interface,
        Some(Instant::now() + Duration::from_secs(45)),
    )?;
    let request = expected.map_or(LineRequest::WatchRuntime, |expected_agent_sha| {
        LineRequest::RefreshWatch { expected_agent_sha }
    });
    let reply = session.request(&request)?;
    match (request.kind(), reply) {
        (RequestKind::WatchRuntime, Response::WatchRuntime(runtime))
        | (RequestKind::RefreshWatch, Response::WatchRefreshed(runtime)) => Ok(runtime),
        (request, reply) => Err(NodeError::Unexpected {
            request,
            response: reply.kind(),
        }
        .into()),
    }
}
