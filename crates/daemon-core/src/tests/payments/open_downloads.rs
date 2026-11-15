// SPDX-License-Identifier: GPL-3.0-or-later

//! The downloads that were open at the refund in full of a traffic pack
//! (design §9.6). Xray counts the downlink of a REALITY connection only
//! when the connection closes, so a download open at the refund is counted
//! after it, whole. The use learned at the refund therefore holds what each
//! node had counted of the user's REALITY downlink, and what a node counts
//! beyond that counts as used at the refund too, until the node's Xray is
//! seen to have started again since the refund, which no connection
//! outlives, or the pack's billing cycle ends. So nothing the user had used
//! is taken back, and a pack bought later does not pay for it.

use std::collections::BTreeMap;

use mooring_agent_proto::{EngineRun, HOST_READING_SECS};
use mooring_model::NodeId;
use serde_json::{Value, json};

use super::refunds::{A, B, GB, HOUR, cycle, quota, recorded, step, users};
use super::{DAY, NOW, Terms, Told, id, order, secs};
use crate::payments::{
    Closed, LedgerError, LedgerEvent, PackUse, PaymentLedger, RunBegan, Settlement,
};
use crate::policy::effective_policy;
use crate::tests::support::{status, wire};
use crate::usage::{DownlinkCount, ServedBefore};

/// When the portal recorded the refund: an hour after [`NOW`].
const REFUND: u64 = NOW.as_secs() + HOUR;

/// The first five-minute boundary at least three minutes after the
/// refund: [`NOW`] is 100 seconds past one, so it is 200 seconds on.
const BOUNDARY: u64 = REFUND + 200;

/// When the use at the refund is learned.
const LEARNED: u64 = NOW.as_secs() + 2 * HOUR;

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// `list` in GB, by node.
fn per_node(list: &[(&str, u64)]) -> BTreeMap<NodeId, u64> {
    list.iter()
        .map(|(name, gigabytes)| (node(name), gigabytes * GB))
        .collect()
}

/// Each node's count of the user's REALITY downlink in GB, every node's
/// figures sampled at `sampled`.
fn counts(list: &[(&str, u64)], sampled: u64) -> BTreeMap<NodeId, DownlinkCount> {
    list.iter()
        .map(|(name, gigabytes)| {
            (
                node(name),
                DownlinkCount {
                    bytes: gigabytes * GB,
                    sampled_at: secs(sampled),
                },
            )
        })
        .collect()
}

/// A run of Xray that began between `from` and `to`.
fn run(from: u64, to: u64) -> RunBegan {
    RunBegan {
        no_earlier_than: secs(from),
        no_later_than: secs(to),
    }
}

/// The usage that tells a use of 120 GB, of which lon1 had counted 30 GB
/// as REALITY downlink and ams1 none.
fn telling_the_use() -> Told {
    Told {
        served: Some(ServedBefore {
            bytes: 120 * GB,
            reality_downlink: per_node(&[("lon1", 30), ("ams1", 0)]),
        }),
        ..Told::default()
    }
}

/// The ledger with user a's 50 GB pack, granted at [`NOW`] and refunded in
/// full at [`REFUND`]: the refund waits for the usage.
fn refunded() -> PaymentLedger {
    let pack = Terms::pack(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), NOW.as_secs());
    step(&ledger, recorded(pack.refund(2, 800, true), REFUND), REFUND).0
}

/// [`refunded`] with the use learned at [`LEARNED`] ([`telling_the_use`]).
fn learned() -> PaymentLedger {
    refunded()
        .settle(secs(LEARNED), cycle(secs(LEARNED)), &telling_the_use())
        .unwrap()
        .ledger
}

/// The use the refund of order A records.
fn recorded_use(ledger: &PaymentLedger) -> PackUse {
    ledger.orders()[&order(A)].refunds[0]
        .pack_use
        .clone()
        .unwrap()
}

/// A use of `gigabytes` GB learned at [`LEARNED`], with `open` (GB) held
/// from the nodes still open.
fn served(gigabytes: u64, open: &[(&str, u64)]) -> PackUse {
    PackUse::Served {
        bytes: gigabytes * GB,
        learned_at: secs(LEARNED),
        open_downloads: per_node(open),
    }
}

/// User a's quota at `at`, in bytes, with an automatic quota of 100 GB,
/// what `ledger` gives, and `downlink`, what each node has counted of the
/// user's REALITY downlink in the cycle.
fn quota_bytes(ledger: &PaymentLedger, at: u64, downlink: Option<&BTreeMap<NodeId, u64>>) -> u64 {
    let pilot = &users()[&id("pilotusera")];
    let at = secs(at);
    effective_policy(
        pilot,
        Some(quota(100)),
        &ledger.entitlements(false),
        cycle(at),
        at,
        downlink,
    )
    .quota
    .unwrap()
    .cycle_served_bytes
    .get()
}

/// [`quota_bytes`] in GB, with `downlink` in GB.
fn quota_with(ledger: &PaymentLedger, at: u64, downlink: &[(&str, u64)]) -> u64 {
    quota_bytes(ledger, at, Some(&per_node(downlink))) / GB
}

/// The use learned holds what each node of the report had counted of the
/// user's REALITY downlink in the cycle, a node that had counted none
/// included: each of them may still count a download that was open at the
/// refund. No status shows a run of Xray, so the usage is asked no more.
#[test]
fn the_use_learned_holds_what_each_node_had_counted_of_the_reality_downlink() {
    let waiting = refunded();
    assert_eq!(waiting.open_downloads().count(), 0);
    let told = telling_the_use();
    let Settlement { ledger, events } = waiting
        .settle(secs(LEARNED), cycle(secs(LEARNED)), &told)
        .unwrap();
    let used = served(120, &[("ams1", 0), ("lon1", 30)]);
    assert_eq!(
        events,
        [LedgerEvent::Settled {
            order: order(A),
            used: used.clone()
        }]
    );
    assert_eq!(recorded_use(&ledger), used);
    assert_eq!(
        ledger
            .open_downloads()
            .map(|record| record.order.clone())
            .collect::<Vec<_>>(),
        [order(A)]
    );
    assert_eq!(ledger.awaiting_usage().count(), 0);
    assert_eq!(told.asked_served.get(), 1);
    assert!(told.asked_downlink.borrow().is_empty());
}

/// What a node still open has counted of the user's REALITY downlink
/// beyond what the use held from it counts as used at the refund: it may
/// be a download that was open then. With 100 GB of quota and 120 GB used,
/// the pack keeps 20 GB; 10 GB more on lon1 make it 30. A count below what
/// the use held, a node that is not open and a report without a figure add
/// nothing, and the pack never keeps more than its 50 GB.
#[test]
fn what_an_open_node_counts_beyond_what_the_use_held_counts_as_used() {
    let ledger = learned();
    let at = LEARNED + HOUR;
    // No report, or none with a figure for the user.
    assert_eq!(quota_bytes(&ledger, at, None), 120 * GB);
    for (downlink, expected) in [
        // Nothing more counted. A node that has counted none is left out.
        (&[("lon1", 30)][..], 120),
        (&[][..], 120),
        // 10 GB more on lon1.
        (&[("lon1", 40)][..], 130),
        // And 5 GB on ams1, which had counted none.
        (&[("lon1", 40), ("ams1", 5)][..], 135),
        // Fewer than the use held from lon1.
        (&[("lon1", 20), ("ams1", 5)][..], 125),
        // par1 is not open.
        (&[("lon1", 30), ("par1", 99)][..], 120),
        // More than the pack.
        (&[("lon1", 100)][..], 150),
    ] {
        assert_eq!(quota_with(&ledger, at, downlink), expected, "{downlink:?}");
    }
    // A single byte more counts.
    let one_more = BTreeMap::from([(node("lon1"), 30 * GB + 1)]);
    assert_eq!(quota_bytes(&ledger, at, Some(&one_more)), 120 * GB + 1);
    // Counts past what a u64 holds keep the whole pack.
    let huge = BTreeMap::from([(node("lon1"), u64::MAX), (node("ams1"), u64::MAX)]);
    assert_eq!(quota_bytes(&ledger, at, Some(&huge)), 150 * GB);
    // Until the use was learned the pack counts in full, whatever a node
    // has counted.
    assert_eq!(quota_with(&ledger, LEARNED - 1, &[("lon1", 40)]), 150);
    assert_eq!(quota_with(&ledger, LEARNED, &[("lon1", 40)]), 130);
}

/// A pack bought after the refund does not pay for a download that was
/// open at it. The user had used 120 GB against 100 GB of quota and the
/// refunded pack, and buys another 50 GB: 170 GB. A download of 10 GB that
/// was open at the refund is then counted on lon1. It was used of the
/// refunded pack, so the user's quota grows with their use, to 180 GB, and
/// the new pack is still whole.
#[test]
fn a_pack_bought_later_does_not_pay_for_a_download_counted_after_the_refund() {
    let later = Terms::pack(B, "pilotusera");
    let (ledger, _) = step(&learned(), later.grant(3), LEARNED + HOUR);
    let at = LEARNED + 2 * HOUR;
    assert_eq!(quota_with(&ledger, at, &[("lon1", 30)]), 170);
    assert_eq!(quota_with(&ledger, at, &[("lon1", 40)]), 180);
    // The refunded pack is used up at 50 GB; from there the new one pays.
    assert_eq!(quota_with(&ledger, at, &[("lon1", 60)]), 200);
    assert_eq!(quota_with(&ledger, at, &[("lon1", 61)]), 200);
}

/// A node whose Xray is seen to have started again since the refund holds
/// no connection that was open at it. What the node has counted since the
/// use was learned becomes part of the use for good (12 GB on lon1), and
/// the node leaves: what it counts from then on is the user's use after
/// the refund. The use was learned when it was. Leaving changes nothing of
/// what the user may use at that instant. ams1 stays until its own Xray
/// has started again.
#[test]
fn a_node_whose_xray_began_after_the_refund_leaves_the_open_downloads() {
    let ledger = learned();
    let at = LEARNED + 4 * HOUR;
    let now_counted = [("lon1", 42), ("ams1", 3)];
    assert_eq!(quota_with(&ledger, at, &now_counted), 135);
    let told = Told {
        downlink: Some(counts(&now_counted, at - 60)),
        began: BTreeMap::from([(node("lon1"), run(BOUNDARY, BOUNDARY + 61))]),
        ..Told::default()
    };
    let Settlement {
        ledger: closed,
        events,
    } = ledger.settle(secs(at), cycle(secs(at)), &told).unwrap();
    assert_eq!(
        events,
        [LedgerEvent::DownloadsClosed {
            order: order(A),
            why: Closed::XrayBegan,
            nodes: vec![node("lon1")],
            added: 12 * GB,
            bytes: 132 * GB,
            open: 1,
        }]
    );
    assert_eq!(recorded_use(&closed), served(132, &[("ams1", 0)]));
    // The use itself was not asked for again; the downlink of the order's
    // user was, once.
    assert_eq!(told.asked_served.get(), 0);
    assert_eq!(*told.asked_downlink.borrow(), [id("pilotusera")]);
    assert_eq!(quota_with(&closed, at, &now_counted), 135);
    assert_eq!(quota_with(&closed, at, &[("lon1", 60), ("ams1", 3)]), 135);
    assert_eq!(quota_with(&closed, at, &[("lon1", 60), ("ams1", 4)]), 136);
    assert_eq!(closed.open_downloads().count(), 1);

    // ams1's Xray starts again too: no download is open any more.
    let told = Told {
        downlink: Some(counts(&[("lon1", 60), ("ams1", 4)], at)),
        began: BTreeMap::from([
            (node("ams1"), run(BOUNDARY + 5, BOUNDARY + 66)),
            (node("lon1"), run(BOUNDARY, BOUNDARY + 61)),
        ]),
        ..Told::default()
    };
    let Settlement {
        ledger: all,
        events,
    } = closed
        .settle(secs(at + 60), cycle(secs(at + 60)), &told)
        .unwrap();
    assert_eq!(
        events,
        [LedgerEvent::DownloadsClosed {
            order: order(A),
            why: Closed::XrayBegan,
            nodes: vec![node("ams1")],
            added: 4 * GB,
            bytes: 136 * GB,
            open: 0,
        }]
    );
    assert_eq!(recorded_use(&all), served(136, &[]));
    assert_eq!(all.open_downloads().count(), 0);
    assert_eq!(
        quota_with(&all, at + 60, &[("lon1", 90), ("ams1", 90)]),
        136
    );
    // Nothing is left to settle, and nothing is asked.
    let idle = Told {
        downlink: Some(counts(&[("lon1", 90), ("ams1", 90)], at + 120)),
        began: told.began.clone(),
        ..Told::default()
    };
    assert_eq!(
        all.settle(secs(at + 120), cycle(secs(at + 120)), &idle),
        None
    );
    assert!(idle.asked_downlink.borrow().is_empty());
}

/// A node leaves only when both hold: the run of Xray its status shows
/// began no earlier than the boundary a poll's gap after the refund, and
/// the node's figures were sampled no earlier than the run can have begun,
/// so that they hold all the node counted before it. A run that may have
/// begun a second before the boundary, figures sampled a second too
/// early, a node with no status or no running Xray, usage that cannot
/// tell, and a report without the node all leave it open.
#[test]
fn a_node_leaves_only_once_its_run_began_after_the_refund_and_its_figures_follow_the_run() {
    let ledger = learned();
    let at = LEARNED + 4 * HOUR;
    let sampled = BOUNDARY + 500;
    let both = |sampled| Some(counts(&[("lon1", 42), ("ams1", 3)], sampled));
    let leaves = |began: Option<RunBegan>, downlink: Option<BTreeMap<NodeId, DownlinkCount>>| {
        let told = Told {
            downlink,
            began: began.into_iter().map(|run| (node("lon1"), run)).collect(),
            ..Told::default()
        };
        ledger.settle(secs(at), cycle(secs(at)), &told).is_some()
    };
    assert!(leaves(Some(run(BOUNDARY, BOUNDARY + 61)), both(sampled)));
    assert!(!leaves(
        Some(run(BOUNDARY - 1, BOUNDARY + 60)),
        both(sampled)
    ));
    // The refund's own second, and three minutes after it, are before the
    // boundary.
    assert!(!leaves(Some(run(REFUND, REFUND + 61)), both(sampled)));
    assert!(!leaves(
        Some(run(REFUND + 180, REFUND + 241)),
        both(sampled)
    ));
    assert!(leaves(Some(run(BOUNDARY, sampled)), both(sampled)));
    assert!(!leaves(Some(run(BOUNDARY, sampled + 1)), both(sampled)));
    assert!(!leaves(None, both(sampled)));
    assert!(!leaves(Some(run(BOUNDARY, BOUNDARY + 61)), None));
    assert!(!leaves(
        Some(run(BOUNDARY, BOUNDARY + 61)),
        Some(counts(&[("ams1", 3)], sampled))
    ));
}

/// While no open node's run began after the refund, the usage is not
/// asked at all: it is aggregated only when a node may leave.
#[test]
fn the_usage_is_asked_only_once_an_open_nodes_run_began_after_the_refund() {
    let ledger = learned();
    let at = LEARNED + 4 * HOUR;
    for began in [
        BTreeMap::new(),
        BTreeMap::from([(node("lon1"), run(BOUNDARY - 1, BOUNDARY + 60))]),
        // par1 is not open.
        BTreeMap::from([(node("par1"), run(BOUNDARY, BOUNDARY + 61))]),
    ] {
        let told = Told {
            downlink: Some(counts(&[("lon1", 42), ("ams1", 3), ("par1", 9)], at)),
            began,
            ..Told::default()
        };
        assert_eq!(ledger.settle(secs(at), cycle(secs(at)), &told), None);
        assert_eq!(told.asked_served.get(), 0);
        assert!(told.asked_downlink.borrow().is_empty());
    }
}

/// Once the pack's billing cycle has ended every node leaves, and nothing
/// is added: the pack counts in its own cycle only, so nothing reads its
/// use again. The usage, which is the new cycle's, is not asked. In a
/// cycle before the pack's, as after a clock that stepped back, nothing is
/// done.
#[test]
fn once_the_packs_cycle_has_ended_no_download_is_open() {
    let ledger = learned();
    let next = cycle(NOW).ends_at();
    let told = Told {
        downlink: Some(counts(&[("lon1", 99), ("ams1", 99)], next.as_secs())),
        began: BTreeMap::from([
            (node("ams1"), run(BOUNDARY, BOUNDARY + 61)),
            (node("lon1"), run(BOUNDARY, BOUNDARY + 61)),
        ]),
        ..Told::default()
    };
    let Settlement {
        ledger: ended,
        events,
    } = ledger.settle(next, cycle(next), &told).unwrap();
    assert_eq!(
        events,
        [LedgerEvent::DownloadsClosed {
            order: order(A),
            why: Closed::CycleEnded,
            nodes: vec![node("ams1"), node("lon1")],
            added: 0,
            bytes: 120 * GB,
            open: 0,
        }]
    );
    assert_eq!(recorded_use(&ended), served(120, &[]));
    assert_eq!(ended.open_downloads().count(), 0);
    assert_eq!(told.asked_served.get(), 0);
    assert!(told.asked_downlink.borrow().is_empty());
    assert_eq!(ended.settle(next, cycle(next), &told), None);
    let earlier = secs(NOW.as_secs() - 40 * DAY);
    assert_eq!(ledger.settle(earlier, cycle(earlier), &told), None);
    assert!(told.asked_downlink.borrow().is_empty());
}

/// A use learned when a node's Xray has already started again since the
/// refund: the node leaves in the same step, with nothing added, since the
/// use holds all the node has counted.
#[test]
fn a_node_whose_xray_had_begun_again_when_the_use_is_learned_leaves_at_once() {
    let told = Told {
        downlink: Some(counts(&[("lon1", 30), ("ams1", 0)], LEARNED - 60)),
        began: BTreeMap::from([(node("lon1"), run(BOUNDARY, BOUNDARY + 61))]),
        ..telling_the_use()
    };
    let Settlement { ledger, events } = refunded()
        .settle(secs(LEARNED), cycle(secs(LEARNED)), &told)
        .unwrap();
    assert_eq!(
        events,
        [
            LedgerEvent::Settled {
                order: order(A),
                used: served(120, &[("ams1", 0), ("lon1", 30)]),
            },
            LedgerEvent::DownloadsClosed {
                order: order(A),
                why: Closed::XrayBegan,
                nodes: vec![node("lon1")],
                added: 0,
                bytes: 120 * GB,
                open: 1,
            },
        ]
    );
    assert_eq!(recorded_use(&ledger), served(120, &[("ams1", 0)]));
}

/// The open downloads are in the file, by node, and are read back; one
/// that names no node, or counts no bytes, is refused.
#[test]
fn the_open_downloads_are_in_the_file() {
    let ledger = learned();
    let bytes = ledger.encode().unwrap();
    assert_eq!(PaymentLedger::decode(&bytes).unwrap(), ledger);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["orders"][0]["refunds"][0]["pack_use"],
        json!({"served": {
            "bytes": 120 * GB,
            "learned_at": LEARNED,
            "open_downloads": {"ams1": 0, "lon1": 30 * GB},
        }})
    );
    for open in [
        json!({"Not a node": 1}),
        json!({"lon1": -1}),
        json!({"lon1": "many"}),
        json!(["lon1"]),
        Value::Null,
    ] {
        let mut broken = value.clone();
        broken["orders"][0]["refunds"][0]["pack_use"]["served"]["open_downloads"] = open.clone();
        assert!(
            matches!(
                PaymentLedger::decode(&serde_json::to_vec(&broken).unwrap()),
                Err(LedgerError::Decode(_))
            ),
            "{open}"
        );
    }
}

/// A status tells when the run of Xray it shows began, between two bounds:
/// the reading is dated at most a reading's interval before `watch_at`,
/// the watch reads the unit later in that tick, for which as long is
/// allowed, and the time since the unit became active is the difference
/// of two figures each rounded down to a second. Without a running Xray,
/// or with a time since then that is longer than the clock allows, it
/// tells nothing.
#[test]
fn a_status_tells_when_its_run_of_xray_began_between_two_bounds() {
    assert_eq!(HOST_READING_SECS, 60);
    let now = secs(BOUNDARY + 10_000);
    let mut shown = status(now, None, Vec::new());
    let watch_at = now.as_secs() - 2;
    assert_eq!(shown.watch_at, wire(secs(watch_at)));
    let heap = Some(48_000_000);
    for uptime in [0, 1, 7_000, 86_400] {
        shown.engines.xray.run = EngineRun::Active {
            uptime_secs: uptime,
            go_heap_bytes: heap,
        };
        assert_eq!(
            RunBegan::of(&shown),
            Some(run(watch_at - uptime - 61, watch_at - uptime + 61)),
            "{uptime}"
        );
    }
    // Hysteria2's unit says nothing of Xray's.
    shown.engines.hy2.run = EngineRun::Inactive;
    assert!(RunBegan::of(&shown).is_some());
    shown.engines.xray.run = EngineRun::Inactive;
    shown.engines.hy2.run = EngineRun::Active {
        uptime_secs: 5,
        go_heap_bytes: None,
    };
    assert_eq!(RunBegan::of(&shown), None);
    // A time since the start that goes before the epoch is no time.
    for uptime in [watch_at - 60, watch_at, u64::MAX] {
        shown.engines.xray.run = EngineRun::Active {
            uptime_secs: uptime,
            go_heap_bytes: heap,
        };
        assert_eq!(RunBegan::of(&shown), None, "{uptime}");
    }
    shown.engines.xray.run = EngineRun::Active {
        uptime_secs: watch_at - 61,
        go_heap_bytes: heap,
    };
    assert_eq!(RunBegan::of(&shown), Some(run(0, 122)));
}
