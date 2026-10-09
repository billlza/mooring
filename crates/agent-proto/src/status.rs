// SPDX-License-Identifier: GPL-3.0-or-later

//! [`StatusV1`]: a node's status, the reply to `Status`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    EngineHealth, GateState, Generation, Halt, Holds, HostHealth, Sha256Hex, StatsEmail, UnixTime,
    UplinkTransfer, WatchConditions,
};

/// The generation a node last committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedGeneration {
    /// The generation.
    pub generation: Generation,
    /// The bundle digest it was applied with.
    pub digest: Sha256Hex,
}

/// A node's status: the agent's view at `now` combined with the watch's
/// latest tick at `watch_at`. Ages are differences of these timestamps, all
/// taken from the VPS clock, so Mac–VPS clock skew does not enter them; the
/// Mac marks the node `WatchStale` when `now − watch_at` exceeds
/// [`crate::WATCH_STALE_SECS`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusV1 {
    /// The agent's clock when it answered.
    pub now: UnixTime,
    /// The timestamp of the watch's latest status write.
    pub watch_at: UnixTime,
    /// The gate as the watch last set or read it.
    pub gate: GateState,
    /// The holds, read under `gate.lock` when answering.
    pub holds: Holds,
    /// The halt marker, if the node is halted.
    #[serde(deserialize_with = "Option::deserialize")]
    pub halted: Option<Halt>,
    /// The Mac peer's latest WireGuard handshake at `watch_at`; `None` when
    /// none has completed. Its age is `now − latest_handshake`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub latest_handshake: Option<UnixTime>,
    /// The last committed generation; `None` before the first `Apply`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub applied: Option<AppliedGeneration>,
    /// The watch's active conditions.
    pub conditions: WatchConditions,
    /// The watch's latest successful accounting poll (§11.5); `None` before
    /// the first.
    #[serde(deserialize_with = "Option::deserialize")]
    pub accounting_at: Option<UnixTime>,
    /// For each accounting email, the latest accounting poll at which its
    /// counters grew; an email with no recorded growth is absent. "Active
    /// now" in the console is a time here within the latest poll. Only
    /// opaque emails and times are kept: Xray's online-IP lists are never
    /// read (they skip loopback, so they would miss every Hysteria2 user,
    /// and they are addresses).
    pub last_active: BTreeMap<StatsEmail, UnixTime>,
    /// The engine units.
    pub engines: EngineHealth,
    /// The host.
    pub host: HostHealth,
    /// The uplink's transfer this month.
    pub transfer: UplinkTransfer,
}

impl StatusV1 {
    /// Seconds since the watch's latest tick, or `None` if `watch_at` is
    /// after `now` (a clock step on the VPS).
    pub const fn watch_age_secs(&self) -> Option<u64> {
        self.now.secs_since(self.watch_at)
    }
}
