// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch loop's configuration ([`WatchConfig`], installed as
//! [`crate::ManagedFile::WatchConfig`]) and the conditions it reports in the
//! node status ([`WatchError`], design §14 "watch (VPS)").

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{InboundSet, StatsEmail, TargetHost, UnixTime, ValueError};

/// Seconds between watch ticks (§11.3).
pub const WATCH_TICK_SECS: u64 = 5;
/// The age, in seconds, of the watch's latest tick beyond which the watch
/// is stale: the Mac marks the node `WatchStale` (design §11.3), and the
/// node stops pinging its dead-man check ([`crate::dead_man_pings`]).
pub const WATCH_STALE_SECS: u64 = 30;
/// The oldest WireGuard handshake, in seconds, that still lets the gate open.
pub const HANDSHAKE_MAX_AGE_SECS: u64 = 180;
/// The gate opens only if rx grew within this many keepalive intervals.
pub const RX_GROWTH_KEEPALIVES: u64 = 3;
/// The longest, in seconds, a viewer's `GateSet{Operator}` waits for the
/// watch to record the Operator hold and close the gate (three ticks) before
/// it is answered with [`crate::AgentError::GateStopUnconfirmed`]; it is
/// never answered `GateClosed` before both are seen (design §11.3).
pub const VIEWER_STOP_WAIT_SECS: u64 = 3 * WATCH_TICK_SECS;
/// Seconds between re-reads of [`crate::NFT_GATE_SET`] membership with `nft -j`.
pub const GATE_SET_REREAD_SECS: u64 = 60;
/// Seconds between accounting polls (§11.5).
pub const ACCOUNTING_INTERVAL_SECS: u64 = 60;
/// Seconds between target checks.
pub const TARGET_CHECK_INTERVAL_SECS: u64 = 3600;
/// The handshake age, in seconds, beyond which the watch reports
/// [`WatchError::MacSilent`] unless an operator hold explains the silence.
pub const MAC_SILENT_SECS: u64 = 600;
/// [`WatchError::DiskLow`] is raised below this many free bytes (1 GiB) …
pub const DISK_LOW_FREE_BYTES: u64 = 1 << 30;
/// … or below this percentage of the filesystem free, whichever is
/// reached first.
pub const DISK_LOW_FREE_PERCENT: u8 = 10;

/// `watch.json`: the per-generation settings of `mooring-watch`. Constants
/// that never vary between generations are the `const`s of this module.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchConfig {
    /// The Mac peer's persistent keepalive, in seconds.
    pub keepalive_secs: NonZeroU16,
    /// The REALITY target the hourly check re-verifies.
    pub target: WatchTarget,
    /// The accounting emails the generation's `xray.json` gives its
    /// clients: every identity it serves, on each inbound. The watch keeps
    /// `StatusV1::last_active` for these only (design §11.5), and reads
    /// them here so that it never needs `xray.json`, which holds secrets.
    pub emails: BTreeSet<StatsEmail>,
}

impl WatchConfig {
    /// The window, in seconds, within which rx must have grown for the gate
    /// to open: [`RX_GROWTH_KEEPALIVES`] keepalive intervals.
    pub fn rx_growth_window_secs(&self) -> u64 {
        RX_GROWTH_KEEPALIVES * u64::from(self.keepalive_secs.get())
    }
}

/// The REALITY target as the bundle pins it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchTarget {
    /// The target's name.
    pub host: TargetHost,
    /// The address the configuration uses; a re-resolution that no longer
    /// yields it records [`WatchError::TargetDegraded`].
    pub ipv4: Ipv4Addr,
}

/// A condition the watch reports in the node status (design §14,
/// "watch (VPS)").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WatchError {
    /// `wg show <interface> dump` of [`crate::WG_INTERFACE`] failed; the gate
    /// was closed.
    #[error("reading WireGuard state failed; the gate is closed")]
    WgReadFailed,
    /// `nft` failed; the unit restarts and `ExecStopPost` closes the gate.
    #[error("nft failed; the watch restarts with the gate closed")]
    NftFailed,
    /// `xray api statsquery` or `statssys` failed.
    #[error("the Xray stats query failed")]
    StatsQueryFailed,
    /// The hourly target check failed or the target's address changed.
    #[error("the REALITY target is degraded")]
    TargetDegraded,
    /// The exit flow cap rejected new flows.
    #[error("the exit flow cap has rejected {count} flows")]
    ExitFlowCapHit {
        /// The value of the [`crate::NftCounter::FlowCap`] counter.
        count: u64,
    },
    /// Writing watch state failed.
    #[error("writing watch state failed ({})", crate::error::describe_errno(.errno))]
    StateWrite {
        /// The OS error number, when the failure came from the OS.
        #[serde(deserialize_with = "Option::deserialize")]
        errno: Option<i32>,
    },
    /// The Mac peer's handshake is older than [`MAC_SILENT_SECS`] and no
    /// operator hold is set: the Mac is asleep, crashed or waiting at the
    /// login window after a reboot, or the M7 or the carrier has lost
    /// service. The gate is closed by the handshake rule already; this
    /// condition is what reports it.
    #[error("no handshake from the Mac for over {MAC_SILENT_SECS} s")]
    MacSilent {
        /// The Mac peer's latest handshake; `None` when none has completed
        /// since the interface came up.
        #[serde(deserialize_with = "Option::deserialize")]
        since: Option<UnixTime>,
    },
    /// The filesystem holding the agent's state has less than
    /// [`DISK_LOW_FREE_BYTES`] or [`DISK_LOW_FREE_PERCENT`] free, so
    /// accounting and state writes are about to fail.
    #[error("only {free} bytes are free on the agent's filesystem")]
    DiskLow {
        /// The bytes available, as of the watch's latest tick.
        free: u64,
    },
    /// The clock is not synchronised by NTP. REALITY refuses a client
    /// whose clock differs by more than 60 s (design §8.2), so a drifting
    /// node clock locks every user out.
    #[error("the clock is not synchronised by NTP")]
    ClockUnsynced,
    /// An upgrade asked for a reboot (`/run/reboot-required`) that has not
    /// happened yet; the nightly reboot window (§5.2) normally takes it.
    #[error("a reboot has been required since {since}")]
    RebootPending {
        /// When the reboot became required.
        since: UnixTime,
    },
    /// The probe identity has no accounting counter although the Mac's
    /// in-chain probes reached the node (critique C-11): Xray is not
    /// counting what the bundle routes through it (the stats policy or the
    /// accounting emails are wrong), so every user's usage on this node
    /// would read zero. The watch's evidence of a probe is the nft counter
    /// [`crate::NftCounter::ProbeFlows`], which counts the exit flows to
    /// the node's own reflector, which only the probe identity may open:
    /// the condition is raised when that counter grew between two polls in
    /// one run of Xray and the later poll holds no counter for a probe
    /// email. The nft counter does not tell the inbounds apart, so the
    /// watch names every inbound; one condition holds every inbound
    /// concerned, so both can be reported at once (the likely case when
    /// the stats policy is off). The Mac, which knows the inbound of each
    /// of its probes, can narrow it from [`crate::StatusV1::last_active`]
    /// and its own probe results.
    #[error("the probe's traffic on {inbounds} is not being counted")]
    AccountingCanaryMissing {
        /// The inbounds whose probe counters are missing.
        inbounds: InboundSet,
    },
}

closed_enum! {
    /// The variant of a [`WatchError`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum WatchErrorKind {
        /// [`WatchError::WgReadFailed`].
        WgReadFailed,
        /// [`WatchError::NftFailed`].
        NftFailed,
        /// [`WatchError::StatsQueryFailed`].
        StatsQueryFailed,
        /// [`WatchError::TargetDegraded`].
        TargetDegraded,
        /// [`WatchError::ExitFlowCapHit`].
        ExitFlowCapHit,
        /// [`WatchError::StateWrite`].
        StateWrite,
        /// [`WatchError::MacSilent`].
        MacSilent,
        /// [`WatchError::DiskLow`].
        DiskLow,
        /// [`WatchError::ClockUnsynced`].
        ClockUnsynced,
        /// [`WatchError::RebootPending`].
        RebootPending,
        /// [`WatchError::AccountingCanaryMissing`].
        AccountingCanaryMissing,
    }
}

impl WatchError {
    /// The variant, without its data.
    pub const fn kind(&self) -> WatchErrorKind {
        match self {
            Self::WgReadFailed => WatchErrorKind::WgReadFailed,
            Self::NftFailed => WatchErrorKind::NftFailed,
            Self::StatsQueryFailed => WatchErrorKind::StatsQueryFailed,
            Self::TargetDegraded => WatchErrorKind::TargetDegraded,
            Self::ExitFlowCapHit { .. } => WatchErrorKind::ExitFlowCapHit,
            Self::StateWrite { .. } => WatchErrorKind::StateWrite,
            Self::MacSilent { .. } => WatchErrorKind::MacSilent,
            Self::DiskLow { .. } => WatchErrorKind::DiskLow,
            Self::ClockUnsynced => WatchErrorKind::ClockUnsynced,
            Self::RebootPending { .. } => WatchErrorKind::RebootPending,
            Self::AccountingCanaryMissing { .. } => WatchErrorKind::AccountingCanaryMissing,
        }
    }
}

/// The conditions active at the watch's latest tick, at most one of each
/// kind (a condition about several inbounds holds them all). On the wire it
/// is a list in [`WatchErrorKind::ALL`] order; a list that repeats a kind
/// is rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<WatchError>", into = "Vec<WatchError>")]
pub struct WatchConditions(BTreeMap<WatchErrorKind, WatchError>);

impl WatchConditions {
    /// Collects conditions, rejecting a repeated kind.
    pub fn new(conditions: impl IntoIterator<Item = WatchError>) -> Result<Self, ValueError> {
        let mut by_kind = BTreeMap::new();
        for condition in conditions {
            let kind = condition.kind();
            if by_kind.insert(kind, condition).is_some() {
                return Err(ValueError::DuplicateWatchCondition { kind });
            }
        }
        Ok(Self(by_kind))
    }

    /// The condition of `kind`, if active.
    pub fn get(&self, kind: WatchErrorKind) -> Option<&WatchError> {
        self.0.get(&kind)
    }

    /// Whether no condition is active.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The active conditions in [`WatchErrorKind::ALL`] order.
    pub fn iter(&self) -> impl Iterator<Item = &WatchError> {
        self.0.values()
    }
}

impl TryFrom<Vec<WatchError>> for WatchConditions {
    type Error = ValueError;

    fn try_from(conditions: Vec<WatchError>) -> Result<Self, Self::Error> {
        Self::new(conditions)
    }
}

impl From<WatchConditions> for Vec<WatchError> {
    fn from(conditions: WatchConditions) -> Self {
        conditions.0.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Inbound;

    #[test]
    fn conditions_hold_one_per_kind_in_kind_order() {
        let conditions = WatchConditions::new([
            WatchError::ExitFlowCapHit { count: 3 },
            WatchError::WgReadFailed,
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_string(&conditions).unwrap(),
            r#"["WgReadFailed",{"ExitFlowCapHit":{"count":3}}]"#
        );
        assert_eq!(
            conditions.get(WatchErrorKind::ExitFlowCapHit),
            Some(&WatchError::ExitFlowCapHit { count: 3 })
        );
        assert_eq!(conditions.iter().count(), 2);
        assert!(WatchConditions::default().is_empty());
        assert_eq!(
            WatchConditions::new([
                WatchError::ExitFlowCapHit { count: 1 },
                WatchError::ExitFlowCapHit { count: 2 }
            ]),
            Err(ValueError::DuplicateWatchCondition {
                kind: WatchErrorKind::ExitFlowCapHit
            })
        );
        assert!(serde_json::from_str::<WatchConditions>(r#"["NftFailed","NftFailed"]"#).is_err());
    }

    /// Both inbounds' canaries can be missing at once (the stats policy
    /// rendered off, or wrong accounting emails, critique C-11): one
    /// condition holds every such inbound, so the one-per-kind rule never
    /// drops one.
    #[test]
    fn one_canary_condition_holds_every_inbound_it_concerns() {
        let both = InboundSet::of(Inbound::Reality).with(Inbound::Hy2);
        let conditions = WatchConditions::new([
            WatchError::AccountingCanaryMissing { inbounds: both },
            WatchError::MacSilent { since: None },
        ])
        .unwrap();
        let json = serde_json::to_string(&conditions).unwrap();
        assert_eq!(
            json,
            r#"[{"MacSilent":{"since":null}},{"AccountingCanaryMissing":{"inbounds":["Reality","Hy2"]}}]"#
        );
        assert_eq!(
            serde_json::from_str::<WatchConditions>(&json).unwrap(),
            conditions
        );
        assert_eq!(both.iter().collect::<Vec<_>>(), Inbound::ALL);
        assert!(both.contains(Inbound::Hy2));
        let hy2 = InboundSet::of(Inbound::Hy2);
        assert!(!hy2.contains(Inbound::Reality));
        assert_eq!(hy2.with(Inbound::Hy2), hy2);
        assert_eq!(
            WatchError::AccountingCanaryMissing { inbounds: both }.to_string(),
            "the probe's traffic on reality, hy2 is not being counted"
        );
        // On the wire a set is a non-empty list in inbound order, each once.
        for bad in [
            r#"[]"#,
            r#"["Hy2","Reality"]"#,
            r#"["Hy2","Hy2"]"#,
            r#"["Vless"]"#,
        ] {
            assert!(serde_json::from_str::<InboundSet>(bad).is_err(), "{bad}");
        }
        assert_eq!(
            InboundSet::try_from(Vec::new()),
            Err(ValueError::InboundSet)
        );
        assert_eq!(
            serde_json::from_str::<InboundSet>(r#"["Reality","Hy2"]"#).unwrap(),
            both
        );
    }

    #[test]
    fn the_rx_window_is_three_keepalives() {
        let config = WatchConfig {
            keepalive_secs: NonZeroU16::new(10).unwrap(),
            target: WatchTarget {
                host: TargetHost::new("www.example.com").unwrap(),
                ipv4: Ipv4Addr::new(198, 51, 100, 7),
            },
            emails: ["u01@reality", "probe@hy2"]
                .into_iter()
                .map(|email| email.parse().unwrap())
                .collect(),
        };
        assert_eq!(config.rx_growth_window_secs(), 30);
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(
            json,
            r#"{"keepalive_secs":10,"target":{"host":"www.example.com","ipv4":"198.51.100.7"},"emails":["probe@hy2","u01@reality"]}"#
        );
        assert_eq!(serde_json::from_str::<WatchConfig>(&json).unwrap(), config);
        assert!(serde_json::from_str::<WatchConfig>(&json.replace(":10,", ":0,")).is_err());
    }
}
