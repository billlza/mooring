// SPDX-License-Identifier: GPL-3.0-or-later

//! The downloads that were open at the refund in full of a traffic pack
//! (design §9.6), on the daemon's puller. The use learned says which nodes
//! may still count one; the nodes' statuses are read every minute while
//! one may; a node leaves once its status shows that its Xray began after
//! the refund and the usage tells what it had counted, or when the pack's
//! billing cycle ends; and the log names orders and nodes, never a user.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use mooring_daemon_core::error::UsageErrorKind;
use mooring_daemon_core::payments::{PackUse, RunBegan};
use mooring_daemon_core::usage::{DownlinkCount, ServedBefore};
use mooring_model::{NodeId, UnixTime, UserId};

use super::super::support::{Harness, NOW};
use super::settle::{A, DAY, GB, at, cycle, fault_line, held, pack_refunded, recorded};
use super::{FIRST, harness};
use crate::collected_usage::Told;
use crate::payments::pull::{Puller, RefundReadings, SETTLE_EVERY};

/// The first five-minute boundary at least three minutes after the
/// refund, which the portal recorded a minute past [`NOW`]: five minutes
/// past it.
const BOUNDARY: u64 = NOW + 300;

/// When the use is learned: 2026-10-13 19:30:00 UTC.
const LEARNED: u64 = NOW + 600;

fn node(name: &str) -> NodeId {
    NodeId::parse(name).unwrap()
}

/// What the usage and the nodes' statuses tell in these tests, of
/// whichever user is asked about, and how often each was asked.
struct Shown {
    served: Told<ServedBefore>,
    downlink: Told<BTreeMap<NodeId, DownlinkCount>>,
    began: BTreeMap<NodeId, RunBegan>,
    /// How often the downlink was asked for.
    asked_downlink: Cell<u32>,
    /// How often a node's status was asked for.
    asked_status: Cell<u32>,
}

impl Shown {
    /// Readings that cannot tell anything yet, and show no status.
    fn nothing() -> Self {
        Self {
            served: Ok(None),
            downlink: Ok(None),
            began: BTreeMap::new(),
            asked_downlink: Cell::new(0),
            asked_status: Cell::new(0),
        }
    }

    /// Readings in which each node of `counted` has counted that many
    /// bytes, sampled at `sampled`, and each node of `began` shows a run
    /// of Xray that began in the two minutes from that time.
    fn with(counted: &[(&str, u64)], sampled: u64, began: &[(&str, u64)]) -> Self {
        Self {
            downlink: Ok(Some(
                counted
                    .iter()
                    .map(|(name, bytes)| {
                        (
                            node(name),
                            DownlinkCount {
                                bytes: *bytes,
                                sampled_at: at(sampled),
                            },
                        )
                    })
                    .collect(),
            )),
            began: began
                .iter()
                .map(|(name, from)| {
                    (
                        node(name),
                        RunBegan {
                            no_earlier_than: at(*from),
                            no_later_than: at(from + 122),
                        },
                    )
                })
                .collect(),
            ..Self::nothing()
        }
    }
}

impl RefundReadings for Shown {
    fn served_before(&self, _: &UserId, _: UnixTime) -> Told<ServedBefore> {
        self.served.clone()
    }

    fn reality_downlink(&self, _: &UserId) -> Told<BTreeMap<NodeId, DownlinkCount>> {
        self.asked_downlink.set(self.asked_downlink.get() + 1);
        self.downlink.clone()
    }

    fn xray_began(&self, node: &NodeId) -> Option<RunBegan> {
        self.asked_status.set(self.asked_status.get() + 1);
        self.began.get(node).copied()
    }
}

/// A puller whose pack's refund was settled at [`LEARNED`], on the tick at
/// `began`: 70 GB used, of which lon1 had counted 30 GB as REALITY
/// downlink and ams1 none. And the lines that logged.
fn learned(harness: &mut Harness, began: Instant) -> (Puller, Vec<String>) {
    let (mut puller, _) = pack_refunded(harness);
    let told = Shown {
        served: Ok(Some(ServedBefore {
            bytes: 70 * GB,
            reality_downlink: BTreeMap::from([(node("lon1"), 30 * GB), (node("ams1"), 0)]),
        })),
        ..Shown::nothing()
    };
    let notes = puller.settle(began, at(LEARNED), cycle(NOW), &told);
    (puller, notes)
}

/// A use of `bytes` learned at [`LEARNED`], with what it held from each
/// node still open.
fn used(bytes: u64, open: &[(&str, u64)]) -> PackUse {
    PackUse::Served {
        bytes,
        learned_at: at(LEARNED),
        open_downloads: open
            .iter()
            .map(|(name, held)| (node(name), *held))
            .collect(),
    }
}

/// The use as both nodes are open.
fn both_open() -> PackUse {
    used(70 * GB, &[("ams1", 0), ("lon1", 30 * GB)])
}

/// The use learned is logged with the nodes that may still count a
/// download that was open at the refund, by the order and without the
/// user, and recorded with what it held from each.
#[test]
fn the_use_learned_names_the_nodes_that_may_still_count_a_download() {
    let mut harness = harness();
    let (puller, notes) = learned(&mut harness, Instant::now());
    assert_eq!(
        notes,
        [format!(
            "payment: order {A}'s refund in full no longer waits for the usage; its pack counts from 2026-10-13 19:30:00 UTC on only what the user had used of it beyond the rest of their quota: 70000000000 bytes served this cycle by the refund's time; a REALITY download that was open then is counted only when it ends, so what ams1, lon1 count(s) of the user's REALITY downloads beyond that counts as used then too, until that node's Xray has started again or the billing cycle ends"
        )]
    );
    assert!(!notes[0].contains(FIRST), "{notes:?}");
    assert_eq!(recorded(&harness), Some(both_open()));
    assert_eq!(held(&puller).map(|refund| refund.used), Some(both_open()));
}

/// While a node may still count such a download, the open nodes' statuses
/// are read every minute: not a second before the minute has passed, and
/// again once it has. The usage is not asked while no status shows a run
/// since the refund. A puller opened anew (the daemon started again)
/// reads them at once. Nothing is logged or written meanwhile.
#[test]
fn the_statuses_are_read_every_minute_while_a_download_may_be_open() {
    let mut harness = harness();
    let began = Instant::now();
    let (mut puller, _) = learned(&mut harness, began);
    let second = Duration::from_secs(1);
    let quiet = Shown::nothing();
    let mut look = |tick: Instant| puller.settle(tick, at(LEARNED + 200), cycle(NOW), &quiet);
    assert!(look(began + SETTLE_EVERY - second).is_empty());
    assert_eq!(quiet.asked_status.get(), 0);
    assert!(look(began + SETTLE_EVERY).is_empty());
    assert_eq!(quiet.asked_status.get(), 2);
    assert!(look(began + SETTLE_EVERY * 2 - second).is_empty());
    assert_eq!(quiet.asked_status.get(), 2);
    assert!(look(began + SETTLE_EVERY * 2).is_empty());
    assert_eq!(quiet.asked_status.get(), 4);
    assert_eq!(quiet.asked_downlink.get(), 0);
    let mut anew = Puller::open(&harness.support_dir());
    assert!(
        anew.settle(began, at(LEARNED + 200), cycle(NOW), &quiet)
            .is_empty()
    );
    assert_eq!(quiet.asked_status.get(), 6);
    assert_eq!(quiet.asked_downlink.get(), 0);
    assert_eq!(recorded(&harness), Some(both_open()));
}

/// A node whose status shows that its Xray began after the refund leaves:
/// what it had counted since the use was learned (12 GB on lon1) is
/// written into the use, kept, and logged by the order and the node,
/// without the user. ams1 stays, and only its status is read from then
/// on. Once ams1's Xray has begun again too, no node is open, and nothing
/// is read any more.
#[test]
fn a_node_whose_xray_began_after_the_refund_leaves_and_is_logged_by_order() {
    let mut harness = harness();
    let began = Instant::now();
    let (mut puller, _) = learned(&mut harness, began);
    let an_hour_on = LEARNED + 3600;
    let restarted = Shown::with(
        &[("lon1", 42 * GB), ("ams1", 3 * GB)],
        an_hour_on,
        &[("lon1", BOUNDARY)],
    );
    let notes = puller.settle(began + SETTLE_EVERY, at(an_hour_on), cycle(NOW), &restarted);
    assert_eq!(
        notes,
        [format!(
            "payment: order {A}'s refunded pack: Xray on lon1 has started again since the refund, so no download that was open at it is left there; the 12000000000 bytes of REALITY downloads counted there since the use was learned are part of it for good, 82000000000 bytes now; 1 node(s) may still count such a download"
        )]
    );
    assert!(!notes[0].contains(FIRST), "{notes:?}");
    assert_eq!(restarted.asked_downlink.get(), 1);
    let closed = used(82 * GB, &[("ams1", 0)]);
    assert_eq!(recorded(&harness), Some(closed.clone()));
    assert_eq!(held(&puller).map(|refund| refund.used), Some(closed));

    let quiet = Shown::nothing();
    assert!(
        puller
            .settle(
                began + SETTLE_EVERY * 2,
                at(an_hour_on + 60),
                cycle(NOW),
                &quiet
            )
            .is_empty()
    );
    assert_eq!(quiet.asked_status.get(), 1);

    let two_hours_on = LEARNED + 7200;
    let both = Shown::with(
        &[("lon1", 60 * GB), ("ams1", 4 * GB)],
        two_hours_on,
        &[("ams1", an_hour_on + 600), ("lon1", BOUNDARY)],
    );
    let notes = puller.settle(
        began + SETTLE_EVERY * 3,
        at(two_hours_on),
        cycle(NOW),
        &both,
    );
    assert_eq!(
        notes,
        [format!(
            "payment: order {A}'s refunded pack: Xray on ams1 has started again since the refund, so no download that was open at it is left there; the 4000000000 bytes of REALITY downloads counted there since the use was learned are part of it for good, 86000000000 bytes now; no node may still count such a download"
        )]
    );
    assert_eq!(recorded(&harness), Some(used(86 * GB, &[])));
    let after = Shown::with(
        &[("lon1", 90 * GB), ("ams1", 90 * GB)],
        two_hours_on + 60,
        &[("ams1", an_hour_on + 600), ("lon1", BOUNDARY)],
    );
    assert!(
        puller
            .settle(
                began + SETTLE_EVERY * 4,
                at(two_hours_on + 60),
                cycle(NOW),
                &after
            )
            .is_empty()
    );
    assert_eq!(after.asked_status.get(), 0);
    assert_eq!(after.asked_downlink.get(), 0);
    assert_eq!(recorded(&harness), Some(used(86 * GB, &[])));
}

/// A fault of the usage, when a node could leave, leaves it open and is
/// logged by its kind once while it lasts, with no order and no user.
/// Usage that only cannot tell yet is not logged, and leaves it open too.
#[test]
fn a_fault_of_the_usage_leaves_the_node_open_and_is_logged_once() {
    let mut harness = harness();
    let began = Instant::now();
    let (mut puller, _) = learned(&mut harness, began);
    let an_hour_on = LEARNED + 3600;
    let mut look = |nth: u32, downlink: Told<BTreeMap<NodeId, DownlinkCount>>| {
        let shown = Shown {
            downlink,
            ..Shown::with(&[], an_hour_on, &[("lon1", BOUNDARY)])
        };
        let notes = puller.settle(
            began + SETTLE_EVERY * nth,
            at(an_hour_on),
            cycle(NOW),
            &shown,
        );
        assert_eq!(shown.asked_downlink.get(), 1);
        notes
    };
    assert_eq!(
        look(1, Err(UsageErrorKind::LedgerCorrupt)),
        [fault_line("LedgerCorrupt")]
    );
    assert!(look(2, Err(UsageErrorKind::LedgerCorrupt)).is_empty());
    assert!(look(3, Ok(None)).is_empty());
    assert_eq!(
        look(4, Err(UsageErrorKind::LedgerCorrupt)),
        [fault_line("LedgerCorrupt")]
    );
    assert_eq!(recorded(&harness), Some(both_open()));
}

/// Once the pack's billing cycle has ended, no download is open, and
/// nothing is added: that is written and logged by the order, and neither
/// the usage nor a status is asked.
#[test]
fn once_the_packs_cycle_has_ended_the_open_downloads_end_unasked() {
    let mut harness = harness();
    let began = Instant::now();
    let (mut puller, _) = learned(&mut harness, began);
    let later = NOW + 40 * DAY;
    let shown = Shown::with(
        &[("lon1", 90 * GB), ("ams1", 90 * GB)],
        later,
        &[("ams1", BOUNDARY), ("lon1", BOUNDARY)],
    );
    let notes = puller.settle(began + SETTLE_EVERY, at(later), cycle(later), &shown);
    assert_eq!(
        notes,
        [format!(
            "payment: order {A}'s refunded pack: its billing cycle has ended, so its use at the refund's time takes in nothing more (70000000000 bytes)"
        )]
    );
    assert_eq!(shown.asked_downlink.get(), 0);
    assert_eq!(shown.asked_status.get(), 0);
    assert_eq!(recorded(&harness), Some(used(70 * GB, &[])));
    assert!(
        puller
            .settle(
                began + SETTLE_EVERY * 2,
                at(later + 60),
                cycle(later),
                &shown
            )
            .is_empty()
    );
    assert_eq!(shown.asked_status.get(), 0);
}
