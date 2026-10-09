// SPDX-License-Identifier: GPL-3.0-or-later

//! The dead-man pings (design §15.8, decision F6): `Node` while the watch
//! is fresh and working, `MacAlive` while the Mac's handshake is fresh.

use std::collections::BTreeSet;

use mooring_agent_proto::{
    DeadManCheck, HANDSHAKE_MAX_AGE_SECS, Holds, OperatorHold, StatusV1, UnixTime,
    WATCH_STALE_SECS, WatchConditions, WatchErrorKind, dead_man_pings,
};
use proptest::prelude::*;
use proptest::sample::subsequence;

use crate::fixtures;

const NOW: u64 = 1_790_000_000;

/// The conditions that stop the watch's work, written out independently
/// of the implementation.
const STOPPING: [WatchErrorKind; 3] = [
    WatchErrorKind::WgReadFailed,
    WatchErrorKind::NftFailed,
    WatchErrorKind::StateWrite,
];

/// The fixture status at [`NOW`], with the watch's tick and the handshake
/// at the given instants and exactly `conditions` active.
fn status(watch_at: u64, handshake: Option<u64>, conditions: &[WatchErrorKind]) -> StatusV1 {
    let mut status = fixtures::status();
    status.now = UnixTime::from_secs(NOW);
    status.watch_at = UnixTime::from_secs(watch_at);
    status.latest_handshake = handshake.map(UnixTime::from_secs);
    status.conditions =
        WatchConditions::new(conditions.iter().map(|kind| fixtures::watch_error(*kind))).unwrap();
    status
}

/// The pings the stated rule expects.
fn expected(
    watch_at: u64,
    handshake: Option<u64>,
    conditions: &[WatchErrorKind],
) -> BTreeSet<DeadManCheck> {
    let mut pings = BTreeSet::new();
    let watch_fresh = watch_at <= NOW && NOW - watch_at <= WATCH_STALE_SECS;
    if watch_fresh && !conditions.iter().any(|kind| STOPPING.contains(kind)) {
        pings.insert(DeadManCheck::Node);
    }
    if handshake.is_some_and(|at| at <= NOW && NOW - at <= HANDSHAKE_MAX_AGE_SECS) {
        pings.insert(DeadManCheck::MacAlive);
    }
    pings
}

#[test]
fn the_constants_are_the_designed_ones() {
    assert_eq!((WATCH_STALE_SECS, HANDSHAKE_MAX_AGE_SECS), (30, 180));
}

/// Every watch age at and around its bound, with no condition and with
/// each condition alone, against every handshake age at and around its
/// bound, a missing handshake, and clocks that stepped back.
#[test]
fn the_ping_table() {
    let watch_ticks = [
        (NOW, true),
        (NOW - WATCH_STALE_SECS, true),
        (NOW - WATCH_STALE_SECS - 1, false),
        (NOW + 1, false),
    ];
    let handshakes = [
        (None, false),
        (Some(NOW - 10), true),
        (Some(NOW - HANDSHAKE_MAX_AGE_SECS), true),
        (Some(NOW - HANDSHAKE_MAX_AGE_SECS - 1), false),
        (Some(NOW + 1), false),
    ];
    let condition_sets: Vec<Vec<WatchErrorKind>> = std::iter::once(Vec::new())
        .chain(WatchErrorKind::ALL.iter().map(|kind| vec![*kind]))
        .collect();
    for (watch_at, watch_fresh) in watch_ticks {
        for (handshake, handshake_fresh) in handshakes {
            for conditions in &condition_sets {
                let stopped = conditions.iter().any(|kind| STOPPING.contains(kind));
                let pings = dead_man_pings(&status(watch_at, handshake, conditions));
                assert_eq!(
                    pings.contains(&DeadManCheck::Node),
                    watch_fresh && !stopped,
                    "{watch_at} {conditions:?}"
                );
                assert_eq!(
                    pings.contains(&DeadManCheck::MacAlive),
                    handshake_fresh,
                    "{handshake:?}"
                );
                assert_eq!(pings, expected(watch_at, handshake, conditions));
            }
        }
    }
}

/// An operator hold closes the gate but leaves the handshake fresh, so
/// `MacAlive` keeps pinging; and a silent Mac stops only `MacAlive`.
#[test]
fn an_operator_hold_and_a_silent_mac_stop_only_what_they_should() {
    let mut held = status(NOW - 5, Some(NOW - 20), &[]);
    held.holds = Holds {
        operator: Some(OperatorHold {
            at: UnixTime::from_secs(NOW - 100),
        }),
        ..Holds::NONE
    };
    assert_eq!(
        dead_man_pings(&held),
        BTreeSet::from([DeadManCheck::Node, DeadManCheck::MacAlive])
    );
    let silent = status(NOW - 5, Some(NOW - 900), &[WatchErrorKind::MacSilent]);
    assert_eq!(
        dead_man_pings(&silent),
        BTreeSet::from([DeadManCheck::Node])
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn the_pings_follow_the_stated_rule(
        watch_offset in -5_i64..=40,
        handshake_offset in proptest::option::of(-5_i64..=200),
        conditions in subsequence(WatchErrorKind::ALL, 0..=WatchErrorKind::ALL.len()),
    ) {
        let at = |offset: i64| NOW.checked_add_signed(-offset).unwrap();
        let watch_at = at(watch_offset);
        let handshake = handshake_offset.map(at);
        let pings = dead_man_pings(&status(watch_at, handshake, &conditions));
        prop_assert_eq!(pings, expected(watch_at, handshake, &conditions));
    }
}
