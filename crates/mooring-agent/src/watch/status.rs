// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch's view (`/var/lib/mooring/watch/status.json`), written
//! atomically at every tick: what it observed, its latest reading (the
//! host, the engines, the uplink's transfer, accounting), and the
//! observation its journal last recorded, from which the next tick's
//! events are the differences. The agent's `Status` and the viewer's stop
//! read it; nothing but the watch writes it.

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    AgentError, EngineHealth, EngineUser, GateState, Generation, Halt, Holds, HostHealth, IoOp,
    StatsEmail, UnixTime, WatchConditions,
};
use serde::{Deserialize, Serialize};

use super::transfer::Transfer;
use crate::paths::Paths;
use crate::store::{io_error, malformed, read_json, write_json};

/// The view is read by the `mooring` group (the agent's viewer role).
const MODE: u32 = 0o640;

/// The watch's view at its latest tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WatchStatus {
    /// When the tick ran (`StatusV1::watch_at`).
    pub(crate) at: UnixTime,
    /// What the tick observed.
    pub(crate) observed: Observed,
    /// The Mac peer's latest handshake; `None` when none has completed, or
    /// when no generation is installed.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) latest_handshake: Option<UnixTime>,
    /// The host at the latest reading, which is taken less often than the
    /// ticks; the reading's time is its `at`.
    pub(crate) host: HostReading,
    /// The engine units at the latest reading.
    pub(crate) engines: EngineHealth,
    /// The uplink's transfer at the latest reading.
    pub(crate) transfer: Transfer,
    /// Accounting at the latest reading.
    pub(crate) accounting: AccountingView,
    /// The latest observation the journal recorded.
    pub(crate) journaled: Observed,
}

/// What accounting reports (design §11.5).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountingView {
    /// The latest poll recorded (`StatusV1::accounting_at`); `None` before
    /// the first.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) at: Option<UnixTime>,
    /// For each email of the applied configuration, the latest poll at
    /// which its counters grew (`StatusV1::last_active`).
    pub(crate) last_active: BTreeMap<StatsEmail, UnixTime>,
    /// Xray's API failed at the latest poll (`StatsQueryFailed`).
    pub(crate) query_failed: bool,
    /// Xray dispatched in-chain probes it did not count
    /// (`AccountingCanaryMissing`), until a probe counter exists.
    pub(crate) canary_missing: bool,
    /// A usage file failed at the latest reading (`StateWrite`).
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) failed: Option<Failure>,
}

/// A state file that could not be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Failure {
    /// The OS error number, when the OS reported one.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) errno: Option<i32>,
}

/// Each engine unit's `NRestarts`, whose growth is journaled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineRestarts {
    pub(crate) xray: u32,
    pub(crate) hy2: u32,
}

impl EngineRestarts {
    /// The restarts `engines` report.
    pub(crate) const fn of(engines: &EngineHealth) -> Self {
        Self {
            xray: engines.xray.restarts,
            hy2: engines.hy2.restarts,
        }
    }

    /// `engine`'s.
    pub(crate) const fn get(self, engine: EngineUser) -> u32 {
        match engine {
            EngineUser::Xray => self.xray,
            EngineUser::Hy2 => self.hy2,
        }
    }
}

/// What a tick observes whose changes are journaled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observed {
    /// The kernel's boot id (`/proc/sys/kernel/random/boot_id`).
    pub(crate) boot_id: String,
    /// The current generation.
    pub(crate) generation: Generation,
    /// The gate. With no generation installed there is no exit to open.
    pub(crate) gate: GateState,
    /// The holds.
    pub(crate) holds: Holds,
    /// The halt marker.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) halted: Option<Halt>,
    /// The current generation, once its transaction is committed.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) committed: Option<Generation>,
    /// The engine units' restarts.
    pub(crate) restarts: EngineRestarts,
    /// The active conditions.
    pub(crate) conditions: WatchConditions,
}

/// One reading of the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostReading {
    /// When it was taken.
    pub(crate) at: UnixTime,
    /// The figures `StatusV1::host` reports.
    pub(crate) health: HostHealth,
    /// The size of the filesystem holding `/var/lib/mooring`, for the
    /// share that `DiskLow` compares.
    pub(crate) disk_total_bytes: u64,
    /// When `/run/reboot-required` was created, while it exists.
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) reboot_required_since: Option<UnixTime>,
}

/// The watch's latest view; `None` before its first tick.
pub(crate) fn read(paths: &Paths) -> Result<Option<WatchStatus>, AgentError> {
    read_json(&paths.watch_status())
}

/// The watch's latest view, which must exist: before the watch's first
/// tick this is the OS's error for the missing file.
pub(crate) fn latest(paths: &Paths) -> Result<WatchStatus, AgentError> {
    let bytes =
        fs::read(paths.watch_status()).map_err(|error| io_error(IoOp::ReadState, &error))?;
    serde_json::from_slice(&bytes).map_err(|_| malformed(IoOp::ReadState))
}

/// Writes the view.
pub(crate) fn write(paths: &Paths, status: &WatchStatus) -> Result<(), AgentError> {
    write_json(&paths.watch_status(), status, MODE)
}
