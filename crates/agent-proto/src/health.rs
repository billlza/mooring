// SPDX-License-Identifier: GPL-3.0-or-later

//! Engine and host health and the uplink's monthly transfer, reported in
//! [`crate::StatusV1`] (console spec B.2.4). Every figure is a count, a
//! size or a time; nothing names a destination or an address.

use serde::{Deserialize, Serialize};

use crate::{UnixTime, UsageMonth};

/// Both engines' units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineHealth {
    /// `mooring-xray.service`.
    pub xray: EngineState,
    /// `mooring-hy2.service`.
    pub hy2: EngineState,
}

/// One engine unit, as systemd and, for Xray, `xray api statssys` report
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineState {
    /// systemd's `NRestarts` for the unit: the restarts its `Restart=`
    /// policy has made.
    pub restarts: u32,
    /// Whether the unit runs, and its figures while it does.
    pub run: EngineRun,
}

/// Whether an engine unit runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EngineRun {
    /// The unit is not active: stopped, failed, or kept down by the halt
    /// marker.
    Inactive,
    /// The unit is active.
    Active {
        /// Seconds since the unit became active.
        uptime_secs: u64,
        /// The Go runtime's heap in use, in bytes (`statssys` `Alloc`,
        /// Go's `runtime.MemStats.Alloc`): Go runtime memory, not the
        /// process's resident set (critique A-6). `None` for
        /// `mooring-hy2`, which exposes no runtime statistics, and for
        /// Xray while `statssys` fails, which the watch reports as
        /// [`crate::WatchError::StatsQueryFailed`].
        #[serde(deserialize_with = "Option::deserialize")]
        go_heap_bytes: Option<u64>,
    },
}

/// The VPS host, as the watch read it at its latest tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHealth {
    /// Seconds since boot (`/proc/uptime`).
    pub uptime_secs: u64,
    /// The one-minute load average in thousandths (`/proc/loadavg`).
    pub load_milli: u32,
    /// `MemAvailable` from `/proc/meminfo`, in bytes.
    pub mem_available_bytes: u64,
    /// The bytes available on the filesystem holding `/var/lib/mooring`
    /// (`statvfs`: available blocks × fragment size).
    pub disk_free_bytes: u64,
    /// The bytes journald's persistent journal occupies.
    pub journal_bytes: u64,
    /// Whether an upgrade asked for a reboot (`/run/reboot-required`
    /// exists).
    pub reboot_required: bool,
    /// When unattended-upgrades last installed packages; `None` when it
    /// never has on this host.
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_unattended_upgrade: Option<UnixTime>,
    /// Whether chrony reports the clock synchronised.
    pub ntp_synced: bool,
}

/// The uplink interface's transfer this month, which the provider bills
/// (console spec B.2.4; critique D-8). The kernel's interface counters
/// restart at every boot, including the nightly unattended-upgrades
/// reboot, so the watch persists the deltas between its readings and
/// counts a reading below the previous one as a reset: from it, the new
/// reading counts from zero. Bytes moved between the last reading before
/// a reset and the reset are not counted, so after a reset the totals are
/// a lower bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UplinkTransfer {
    /// The UTC calendar month the totals cover.
    pub month: UsageMonth,
    /// The watch's first reading this month: the month's first tick, or
    /// later when the watch started counting during the month, in which
    /// case the totals omit the month before it.
    pub counted_from: UnixTime,
    /// Bytes received on the uplink.
    pub rx_bytes: u64,
    /// Bytes sent on the uplink.
    pub tx_bytes: u64,
    /// The counter resets detected this month.
    pub counter_resets: u32,
}
