// SPDX-License-Identifier: GPL-3.0-or-later

//! The dead-man pings (design §15.8, decision F6, 2026-10-08): each node
//! pings two Healthchecks checks while what they watch is alive, and
//! Healthchecks alerts the operator when the pings stop. The node decides
//! from its own status alone, so the rule lives here, beside the status it
//! reads, where the agent can use it while the Mac is gone.

use std::collections::BTreeSet;

use crate::macros::closed_enum;
use crate::{HANDSHAKE_MAX_AGE_SECS, StatusV1, WATCH_STALE_SECS, WatchErrorKind};

closed_enum! {
    /// A Healthchecks check a node pings.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum DeadManCheck {
        /// The node's watch is working.
        Node,
        /// The Mac is alive: its WireGuard handshake is fresh.
        MacAlive,
    }
}

/// Whether an active watch condition of `kind` means the watch's own work
/// has stopped, so the node must stop pinging [`DeadManCheck::Node`]: it
/// cannot read WireGuard, drive nftables or record its state. Every other
/// condition leaves the watch working and is reported by a push notice
/// instead. The match names every kind, so a new condition cannot be added
/// without deciding it here.
const fn stops_the_watch(kind: WatchErrorKind) -> bool {
    match kind {
        WatchErrorKind::WgReadFailed | WatchErrorKind::NftFailed | WatchErrorKind::StateWrite => {
            true
        }
        WatchErrorKind::StatsQueryFailed
        | WatchErrorKind::TargetDegraded
        | WatchErrorKind::ExitFlowCapHit
        | WatchErrorKind::MacSilent
        | WatchErrorKind::DiskLow
        | WatchErrorKind::ClockUnsynced
        | WatchErrorKind::RebootPending
        | WatchErrorKind::AccountingCanaryMissing => false,
    }
}

/// The checks a node pings now, from its status:
///
/// - [`DeadManCheck::Node`] while the watch is healthy: its latest tick is
///   at most [`WATCH_STALE_SECS`] old and no active condition stops its
///   work (`WgReadFailed`, `NftFailed` or `StateWrite`; every other
///   condition leaves the watch working and is reported by a push notice);
/// - [`DeadManCheck::MacAlive`] while the Mac's handshake is fresh: at most
///   [`HANDSHAKE_MAX_AGE_SECS`] old, the gate's own freshness rule. An
///   operator hold does not stop it: the handshake stays fresh.
///
/// A clock that stepped back (an age that cannot be computed) or a missing
/// handshake pings nothing for that check: silence is what makes
/// Healthchecks alert.
pub fn dead_man_pings(status: &StatusV1) -> BTreeSet<DeadManCheck> {
    let watch_fresh = status
        .watch_age_secs()
        .is_some_and(|age| age <= WATCH_STALE_SECS);
    let watch_working = status
        .conditions
        .iter()
        .all(|condition| !stops_the_watch(condition.kind()));
    let handshake_fresh = status
        .latest_handshake
        .and_then(|handshake| status.now.secs_since(handshake))
        .is_some_and(|age| age <= HANDSHAKE_MAX_AGE_SECS);
    let mut pings = BTreeSet::new();
    if watch_fresh && watch_working {
        pings.insert(DeadManCheck::Node);
    }
    if handshake_fresh {
        pings.insert(DeadManCheck::MacAlive);
    }
    pings
}
