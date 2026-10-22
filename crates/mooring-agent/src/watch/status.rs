// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch's view (`/var/lib/mooring/watch/status.json`), written
//! atomically at every tick: what it observed, the host as it last read it,
//! and the observation its journal last recorded, from which the next
//! tick's events are the differences. The agent's `Status` and the
//! viewer's stop read it; nothing but the watch writes it.

use mooring_agent_proto::{
    AgentError, GateState, Generation, Halt, Holds, HostHealth, UnixTime, WatchConditions,
};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::store::{read_json, write_json};

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
    /// ticks.
    pub(crate) host: HostReading,
    /// The latest observation the journal recorded.
    pub(crate) journaled: Observed,
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

/// Writes the view.
pub(crate) fn write(paths: &Paths, status: &WatchStatus) -> Result<(), AgentError> {
    write_json(&paths.watch_status(), status, MODE)
}
