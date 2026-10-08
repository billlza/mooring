// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch loop's configuration ([`WatchConfig`], installed as
//! [`crate::ManagedFile::WatchConfig`]) and the conditions it reports in the
//! node status ([`WatchError`], design §14 "watch (VPS)").

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{TargetHost, ValueError};

/// Seconds between watch ticks (§11.3).
pub const WATCH_TICK_SECS: u64 = 5;
/// The oldest WireGuard handshake, in seconds, that still lets the gate open.
pub const HANDSHAKE_MAX_AGE_SECS: u64 = 180;
/// The gate opens only if rx grew within this many keepalive intervals.
pub const RX_GROWTH_KEEPALIVES: u64 = 3;
/// Seconds between re-reads of [`crate::NFT_GATE_SET`] membership with `nft -j`.
pub const GATE_SET_REREAD_SECS: u64 = 60;
/// Seconds between accounting polls (§11.5).
pub const ACCOUNTING_INTERVAL_SECS: u64 = 60;
/// Seconds between target checks.
pub const TARGET_CHECK_INTERVAL_SECS: u64 = 3600;

/// `watch.json`: the per-generation settings of `mooring-watch`. Constants
/// that never vary between generations are the `const`s of this module.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchConfig {
    /// The Mac peer's persistent keepalive, in seconds.
    pub keepalive_secs: NonZeroU16,
    /// The REALITY target the hourly check re-verifies.
    pub target: WatchTarget,
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
}

closed_enum! {
    /// The variant of a [`WatchError`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        }
    }
}

/// The conditions active at the watch's latest tick, at most one of each
/// kind. On the wire it is a list in [`WatchErrorKind::ALL`] order; a list
/// that repeats a kind is rejected.
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

    #[test]
    fn the_rx_window_is_three_keepalives() {
        let config = WatchConfig {
            keepalive_secs: NonZeroU16::new(10).unwrap(),
            target: WatchTarget {
                host: TargetHost::new("www.example.com").unwrap(),
                ipv4: Ipv4Addr::new(198, 51, 100, 7),
            },
        };
        assert_eq!(config.rx_growth_window_secs(), 30);
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(
            json,
            r#"{"keepalive_secs":10,"target":{"host":"www.example.com","ipv4":"198.51.100.7"}}"#
        );
        assert_eq!(serde_json::from_str::<WatchConfig>(&json).unwrap(), config);
        assert!(serde_json::from_str::<WatchConfig>(&json.replace(":10,", ":0,")).is_err());
    }
}
