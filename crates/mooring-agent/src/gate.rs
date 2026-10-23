// SPDX-License-Identifier: GPL-3.0-or-later

//! The gate, its holds and the halt marker (design §11.3). The agent only
//! ever closes the gate, under `gate.lock`; only `mooring-watch` opens it.

use std::time::Duration;

use mooring_agent_proto::{
    AgentError, ClearableHold, EgressViolationHold, EngineUser, GateReason, GateState, Generation,
    Halt, Holds, IoOp, MacDrainHold, NFT_GATE_SET, NFT_TABLE, OperatorHold, ShutdownReason,
    StderrTail, SystemdOp, UnitName, UnixTime, VIEWER_STOP_WAIT_SECS, WG_INTERFACE,
};
use serde::{Deserialize, Serialize};

use crate::host::{Node, Tool, run_ok};
use crate::paths::Paths;
use crate::store::{Lock, read_json, write_json};

/// Holds and the halt marker are read by the `mooring` group (the watch).
const STATE_MODE: u32 = 0o640;

/// A viewer's emergency stop, waiting for the watch
/// (`/var/lib/mooring/stop/request.json`): the watch records the
/// Operator hold at `at` or later and closes the gate (design §11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StopRequest {
    /// When the viewer asked.
    pub(crate) at: UnixTime,
}

/// The holds; none recorded is no holds.
pub(crate) fn holds(paths: &Paths) -> Result<Holds, AgentError> {
    Ok(read_json(&paths.holds())?.unwrap_or(Holds::NONE))
}

/// Writes the holds (under `gate.lock`, which the caller holds).
pub(crate) fn write_holds(paths: &Paths, held: &Holds) -> Result<(), AgentError> {
    write_json(&paths.holds(), held, STATE_MODE)
}

/// The halt marker, if the node is halted.
pub(crate) fn halted(paths: &Paths) -> Result<Option<Halt>, AgentError> {
    read_json(&paths.halted())
}

/// The current generation: the `gen-<N>` that `/etc/mooring/current`
/// points at, or [`Generation::ZERO`] before the first `Apply`.
pub(crate) fn current_generation(paths: &Paths) -> Result<Generation, AgentError> {
    let link = match std::fs::read_link(paths.current()) {
        Ok(link) => link,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Generation::ZERO);
        }
        Err(error) => return Err(crate::store::io_error(IoOp::ReadState, &error)),
    };
    link.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("gen-"))
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
        .map(Generation::new)
        .ok_or(crate::store::malformed(IoOp::ReadState))
}

/// Adds `wgexit` to `exit_closed`, which closes the gate (idempotent).
pub(crate) fn close(node: &dyn Node) -> Result<(), AgentError> {
    let element = format!("{{ \"{WG_INTERFACE}\" }}");
    match run_ok(
        node,
        Tool::Nft,
        &["add", "element", "inet", NFT_TABLE, NFT_GATE_SET, &element],
    )? {
        Ok(_) => Ok(()),
        Err(stderr) => Err(AgentError::GateCloseFailed {
            stderr_tail: StderrTail::scrubbed(&stderr, &[]),
        }),
    }
}

/// Whether `wgexit` is in `exit_closed`, from `nft -j list set`.
pub(crate) fn state(node: &dyn Node) -> Result<GateState, AgentError> {
    match run_ok(
        node,
        Tool::Nft,
        &["-j", "list", "set", "inet", NFT_TABLE, NFT_GATE_SET],
    )? {
        Ok(stdout) => parse_set(&stdout),
        Err(_) => Err(crate::store::malformed(IoOp::ReadState)),
    }
}

/// The gate from `nft -j list set inet mooring exit_closed`'s output.
pub(crate) fn parse_set(stdout: &[u8]) -> Result<GateState, AgentError> {
    let listing: serde_json::Value =
        serde_json::from_slice(stdout).map_err(|_| crate::store::malformed(IoOp::ReadState))?;
    let sets: Vec<&serde_json::Value> = listing["nftables"]
        .as_array()
        .map(|items| items.iter().filter_map(|item| item.get("set")).collect())
        .unwrap_or_default();
    let [set] = sets.as_slice() else {
        return Err(crate::store::malformed(IoOp::ReadState));
    };
    let closed = match set.get("elem") {
        None => false,
        Some(serde_json::Value::Array(elements)) => elements
            .iter()
            .any(|element| element.as_str() == Some(WG_INTERFACE)),
        Some(_) => return Err(crate::store::malformed(IoOp::ReadState)),
    };
    Ok(if closed {
        GateState::Closed
    } else {
        GateState::Open
    })
}

/// `GateSet` from the ops role: records the hold and closes the gate, both
/// under `gate.lock`, and answers with the holds once both are done. The
/// hold is written first, so a watch tick between the two finds it and
/// keeps the gate closed.
pub(crate) fn set_by_ops(
    paths: &Paths,
    node: &dyn Node,
    reason: GateReason,
) -> Result<Holds, AgentError> {
    let _lock = Lock::exclusive(&paths.gate_lock())?;
    let mut held = holds(paths)?;
    let now = node.now();
    match reason {
        GateReason::Operator => held.operator = Some(OperatorHold { at: now }),
        GateReason::EgressViolation => {
            held.egress_violation = Some(EgressViolationHold {
                at: now,
                generation: current_generation(paths)?,
            });
        }
        GateReason::MacDrain => match crate::wg::peer(node) {
            Ok(peer) => {
                held.mac_drain = Some(MacDrainHold {
                    handshake_at_drain: peer.latest_handshake,
                });
            }
            Err(error) => {
                // The Mac asked to close: close, but record no hold whose
                // clearing condition would rest on a value never read.
                close(node)?;
                return Err(error);
            }
        },
    }
    write_holds(paths, &held)?;
    close(node)?;
    Ok(held)
}

/// `GateSet{Operator}` from the viewer role, which cannot write the holds
/// or read the set: hands the stop to the watch and answers `GateClosed`
/// only once the Operator hold is recorded at or after the request and the
/// watch's view from a tick at or after it shows the gate closed, looking
/// once a second, else `GateStopUnconfirmed` after [`VIEWER_STOP_WAIT_SECS`]
/// seconds of waiting (counted in the sleeps themselves), leaving the
/// request for the watch.
pub(crate) fn set_by_viewer(paths: &Paths, node: &dyn Node) -> Result<Holds, AgentError> {
    let asked = node.now();
    {
        let _lock = Lock::exclusive(&paths.gate_lock())?;
        write_json(&paths.stop_request(), &StopRequest { at: asked }, 0o660)?;
    }
    let mut waited_secs = 0_u64;
    loop {
        let held = holds(paths)?;
        let recorded = held.operator.is_some_and(|hold| hold.at >= asked);
        let closed = crate::watch::status::read(paths)?
            .is_some_and(|view| view.at >= asked && view.observed.gate == GateState::Closed);
        if recorded && closed {
            return Ok(held);
        }
        if waited_secs >= VIEWER_STOP_WAIT_SECS {
            return Err(AgentError::GateStopUnconfirmed { waited_secs });
        }
        node.sleep(Duration::from_secs(1));
        waited_secs += 1;
    }
}

/// `ClearHold`: removes the hold, whether or not it was present, under
/// `gate.lock`. The gate stays as it is; the watch reopens it if nothing
/// else holds it.
pub(crate) fn clear(paths: &Paths, hold: ClearableHold) -> Result<Holds, AgentError> {
    let _lock = Lock::exclusive(&paths.gate_lock())?;
    let mut held = holds(paths)?;
    match hold {
        ClearableHold::EgressViolation => held.egress_violation = None,
        ClearableHold::Operator => held.operator = None,
    }
    write_holds(paths, &held)?;
    Ok(held)
}

/// `Shutdown`: writes the halt marker (without the transaction lock), then
/// closes the gate, then stops both engines (design §11.3), attempting each
/// step whatever the one before did and reporting the first failure. A
/// node already halted keeps its first marker. A marker that cannot be
/// written stops everything at once: without it, the engines' unit
/// condition would let them start again.
pub(crate) fn shutdown(
    paths: &Paths,
    node: &dyn Node,
    reason: ShutdownReason,
) -> Result<Halt, AgentError> {
    let halt = match halted(paths)? {
        Some(halt) => halt,
        None => {
            let halt = Halt {
                at: node.now(),
                reason,
            };
            write_json(&paths.halted(), &halt, STATE_MODE)?;
            halt
        }
    };
    // Every step is attempted even when an earlier one failed: a gate that
    // cannot be closed makes stopping the engines more urgent, not less.
    // The first failure is the one reported.
    let mut first: Option<AgentError> = None;
    let closed = Lock::exclusive(&paths.gate_lock()).and_then(|_lock| close(node));
    if let Err(error) = closed {
        first.get_or_insert(error);
    }
    for engine in [EngineUser::Xray, EngineUser::Hy2] {
        if let Err(error) = stop_engine(node, engine) {
            first.get_or_insert(error);
        }
    }
    match first {
        Some(error) => Err(error),
        None => Ok(halt),
    }
}

/// `systemctl stop` of one engine.
fn stop_engine(node: &dyn Node, engine: EngineUser) -> Result<(), AgentError> {
    let unit = engine_unit(engine)?;
    match run_ok(node, Tool::Systemctl, &["stop", unit.as_str()])? {
        Ok(_) => Ok(()),
        Err(_) => Err(AgentError::Systemd {
            unit,
            op: SystemdOp::Stop,
        }),
    }
}

/// `halted-check`, the engines' `ExecCondition`: whether the node may start
/// them. A marker that cannot be read counts as halted, so a damaged
/// marker never lets an engine start.
pub(crate) fn may_start_engines(paths: &Paths) -> bool {
    matches!(halted(paths), Ok(None))
}

/// An engine's systemd unit, `mooring-xray.service` or
/// `mooring-hy2.service` (design §5.2).
pub(crate) fn engine_unit(engine: EngineUser) -> Result<UnitName, AgentError> {
    // Both names are valid unit names (a test checks them); the error is
    // only kept so that no conversion can panic.
    UnitName::new(format!("{}.service", engine.name())).map_err(|_| AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: None,
    })
}
