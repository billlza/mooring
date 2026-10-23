// SPDX-License-Identifier: GPL-3.0-or-later

//! The engine units as systemd reports them (`StatusV1::engines`, design
//! §11.1): `systemctl show -p ActiveState,NRestarts,
//! ActiveEnterTimestampMonotonic`, which on Debian 13 (systemd 257, checked
//! on the London VPS on 2026-10-23) prints those properties as `key=value`
//! lines in its own order, with the timestamp in microseconds since boot
//! (0 for a unit never active) and exit status 0 even for a unit that is
//! not installed. The time since boot is the clock no step moves.

use mooring_agent_proto::{AgentError, EngineRun, EngineState, EngineUser, IoOp};

use crate::gate::engine_unit;
use crate::host::{Node, Tool, run_ok};
use crate::store::malformed;

/// One engine unit at a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unit {
    /// When it became active, in seconds since boot; `None` while it is
    /// not active.
    pub(crate) active_since: Option<u64>,
    /// systemd's `NRestarts`: the restarts its `Restart=` policy made.
    pub(crate) restarts: u32,
}

impl Unit {
    /// The unit as `StatusV1` reports it at `boot_secs` since boot, with
    /// the Go heap a running Xray reported.
    pub(crate) const fn state(self, boot_secs: u64, go_heap_bytes: Option<u64>) -> EngineState {
        EngineState {
            restarts: self.restarts,
            run: match self.active_since {
                Some(since) => EngineRun::Active {
                    // Both are rounded down to a second, so `since` can lead
                    // by one.
                    uptime_secs: boot_secs.saturating_sub(since),
                    go_heap_bytes,
                },
                None => EngineRun::Inactive,
            },
        }
    }
}

/// Reads `engine`'s unit.
pub(crate) fn read(node: &dyn Node, engine: EngineUser) -> Result<Unit, AgentError> {
    let unit = engine_unit(engine)?;
    let stdout = run_ok(
        node,
        Tool::Systemctl,
        &[
            "show",
            "-p",
            "ActiveState,NRestarts,ActiveEnterTimestampMonotonic",
            unit.as_str(),
        ],
    )?
    .map_err(|_| malformed(IoOp::ReadState))?;
    parse_show(&stdout)
}

/// A unit from `systemctl show`'s output: each of the three properties
/// exactly once, and an `ActiveState` systemd documents.
pub(crate) fn parse_show(stdout: &[u8]) -> Result<Unit, AgentError> {
    let text = std::str::from_utf8(stdout).map_err(|_| malformed(IoOp::ReadState))?;
    let (mut state, mut restarts, mut entered) = (None, None, None);
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once('=').ok_or(malformed(IoOp::ReadState))?;
        let slot = match key {
            "ActiveState" => &mut state,
            "NRestarts" => &mut restarts,
            "ActiveEnterTimestampMonotonic" => &mut entered,
            _ => return Err(malformed(IoOp::ReadState)),
        };
        if slot.replace(value).is_some() {
            return Err(malformed(IoOp::ReadState));
        }
    }
    let (Some(state), Some(restarts), Some(entered)) = (state, restarts, entered) else {
        return Err(malformed(IoOp::ReadState));
    };
    let number = |text: &str| text.parse::<u64>().map_err(|_| malformed(IoOp::ReadState));
    let restarts = u32::try_from(number(restarts)?).map_err(|_| malformed(IoOp::ReadState))?;
    let entered_secs = number(entered)? / 1_000_000;
    let active = match state {
        "active" | "reloading" | "refreshing" => true,
        "inactive" | "failed" | "activating" | "deactivating" | "maintenance" => false,
        _ => return Err(malformed(IoOp::ReadState)),
    };
    Ok(Unit {
        active_since: active.then_some(entered_secs),
        restarts,
    })
}
