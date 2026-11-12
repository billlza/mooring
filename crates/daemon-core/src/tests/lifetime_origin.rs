// SPDX-License-Identifier: GPL-3.0-or-later

//! A node's lifetime origin. On a host new to Mooring, which adoption
//! requires (design §13.2), a node's agent records its first month only
//! once Xray runs, normally at the node's first apply, and no client
//! reaches the node before the Mac records it applied. So the origin is
//! the latest sighting of the node planned or adopted while the Mac held
//! nothing from it, and a node planned in one month and first applied in a
//! later one still has a lifetime.

use std::collections::BTreeMap;

use mooring_agent_proto::{Inbound, Resolution, Traffic, UsageMonth, UsageV1};
use mooring_model::node::{LifecycleStage, NodeLifecycle};
use mooring_model::{Bookkeeping, UnixTime};

use super::support::{
    at, deployment_billed_on, edited, email, node, series, traffic, user_ids, wire,
};
use crate::usage::history::UsageScope;
use crate::usage::{CollectedUsage, NodeUsageHistory, ProtocolTraffic};

/// Records `count` months from `first` on `name`'s history, each sampled
/// at its last second and received at its end; the month `now` is in is
/// sampled and received at `now`. On lon1 the fixture's first user sends
/// ten bytes and receives twenty in each month; ams1 counts nothing.
fn record_months(
    history: &mut NodeUsageHistory,
    name: &str,
    first: &str,
    count: usize,
    now: UnixTime,
) {
    let mut month: UsageMonth = first.parse().unwrap();
    for _ in 0..count {
        let end = month.next().unwrap().start().as_secs();
        let bytes = if name == "lon1" {
            BTreeMap::from([(email(&user_ids()[0], Inbound::Reality), traffic(10, 20))])
        } else {
            BTreeMap::new()
        };
        history
            .record_month(
                &node(name),
                UsageV1 {
                    month,
                    updated_at: wire(UnixTime::from_secs(now.as_secs().min(end - 1))),
                    traffic: bytes,
                },
                UnixTime::from_secs(now.as_secs().min(end)),
            )
            .unwrap();
        month = month.next().unwrap();
    }
}

/// The fixture's nodes, each seen unserved at `sightings` in that order,
/// then holding `count` months from `first`.
fn collected(sightings: &[UnixTime], first: &str, count: usize, now: UnixTime) -> CollectedUsage {
    let mut collected = CollectedUsage::default();
    for name in ["lon1", "ams1"] {
        for sighting in sightings {
            collected.observe_unserved(node(name), *sighting);
        }
        let mut history = collected.node(&node(name)).unwrap().clone();
        record_months(&mut history, name, first, count, now);
        collected.set_node(node(name), history);
    }
    collected
}

/// Planned on 28 October, adopted, and last seen unserved on 2 November,
/// just before its first apply.
fn planned_then_applied() -> [UnixTime; 2] {
    [at("2026-10-28", 12 * 3600), at("2026-11-02", 9 * 3600)]
}

/// lon1's history as stored.
fn lon1(collected: &CollectedUsage) -> serde_json::Value {
    serde_json::to_value(collected).unwrap()["nodes"]["lon1"].clone()
}

/// ams1's history as stored.
fn ams1(collected: &CollectedUsage) -> serde_json::Value {
    serde_json::to_value(collected).unwrap()["nodes"]["ams1"].clone()
}

/// lon1's lifetime in the fixture's first user's history at `now`.
fn history_lifetime(collected: &CollectedUsage, now: UnixTime) -> Option<ProtocolTraffic> {
    let history = collected
        .user_history(
            &deployment_billed_on(1),
            &user_ids()[0],
            now,
            UsageScope::All,
        )
        .unwrap();
    let lon1 = history
        .nodes()
        .iter()
        .find(|held| held.node == node("lon1"))
        .unwrap();
    lon1.totals.as_ref().unwrap().lifetime
}

#[test]
fn a_node_first_applied_in_a_later_month_than_it_was_planned_has_a_lifetime() {
    let now = at("2026-12-15", 12 * 3600);
    let collected = collected(&planned_then_applied(), "2026-11", 2, now);
    let report = collected.aggregate(&deployment_billed_on(1), now).unwrap();
    assert_eq!(
        report.users[&user_ids()[0]].lifetime(),
        Some(traffic(20, 40))
    );
    assert_eq!(
        history_lifetime(&collected, now),
        Some(ProtocolTraffic {
            reality: traffic(20, 40),
            hy2: Traffic::default(),
        })
    );
}

#[test]
fn its_lifetime_stays_complete_once_its_first_months_are_folded() {
    let deployment = deployment_billed_on(1);
    let now = at("2028-02-05", 3600);
    let mut collected = collected(&planned_then_applied(), "2026-11", 16, now);
    collected.prune(&deployment, now).unwrap();
    assert_eq!(lon1(&collected)["folded_before"], "2027-01");
    assert_eq!(lon1(&collected)["lifetime_complete"], true);
    let report = collected.aggregate(&deployment, now).unwrap();
    assert_eq!(
        report.users[&user_ids()[0]].lifetime(),
        Some(traffic(160, 320))
    );
}

#[test]
fn a_cycle_that_began_while_the_node_was_unserved_is_its_months_total() {
    // The cycle starts on 2 November; the node was unserved at 09:00.
    let deployment = deployment_billed_on(2);
    let now = at("2026-11-05", 12 * 3600);
    let late = collected(&planned_then_applied(), "2026-11", 1, now);
    let report = late.aggregate(&deployment, now).unwrap();
    assert_eq!(report.users[&user_ids()[0]].cycle(), Some(traffic(10, 20)));
    // Last seen unserved before the cycle, the node may have counted bytes
    // in November before it: without detail the split is unknown.
    let early = collected(&[at("2026-10-28", 12 * 3600)], "2026-11", 1, now);
    let report = early.aggregate(&deployment, now).unwrap();
    assert_eq!(report.users[&user_ids()[0]].cycle(), None);
}

#[test]
fn a_sighting_with_the_clock_fast_does_not_outlast_the_next() {
    // One maintenance on 1 November ran with the Mac six hours fast; the
    // next ones had the right time. The node served from 21:00, before the
    // cycle that starts on 2 November.
    let fast = at("2026-11-02", 2 * 3600);
    let right = at("2026-11-01", 20 * 3600 + 59 * 60);
    let now = at("2026-11-05", 12 * 3600);
    let collected = collected(&[fast, right], "2026-11", 1, now);
    assert_eq!(lon1(&collected)["origin"], right.as_secs());
    // Without detail the bytes before the cycle cannot be told apart, so
    // the cycle is unknown rather than the whole month.
    let report = collected.aggregate(&deployment_billed_on(2), now).unwrap();
    assert_eq!(report.users[&user_ids()[0]].cycle(), None);
}

#[test]
fn the_origin_follows_the_latest_sighting() {
    let mut collected = CollectedUsage::default();
    collected.observe_unserved(node("lon1"), at("2026-10-28", 0));
    assert_eq!(lon1(&collected)["origin"], at("2026-10-28", 0).as_secs());
    collected.observe_unserved(node("lon1"), at("2026-11-02", 0));
    assert_eq!(lon1(&collected)["origin"], at("2026-11-02", 0).as_secs());
    // After a clock that stepped back, the earlier origin is still one the
    // node was unserved after.
    collected.observe_unserved(node("lon1"), at("2026-11-01", 0));
    assert_eq!(lon1(&collected)["origin"], at("2026-11-01", 0).as_secs());
}

#[test]
fn a_month_held_from_before_the_origin_leaves_the_lifetime_unknown() {
    // The agent polled in October, but the Mac reached the node only after
    // its last sighting, on 2 November at 09:00, and then pulled October at
    // 10:00: October may hold bytes the origin does not cover, as a VPS
    // adopted again with its old files did before adoption refused one.
    let now = at("2026-11-05", 12 * 3600);
    let mut collected = CollectedUsage::default();
    for name in ["lon1", "ams1"] {
        for sighting in planned_then_applied() {
            collected.observe_unserved(node(name), sighting);
        }
        let mut history = collected.node(&node(name)).unwrap().clone();
        for (month, sampled, received) in [
            (
                "2026-10",
                at("2026-10-31", 86_399),
                at("2026-11-02", 10 * 3600),
            ),
            ("2026-11", now, now),
        ] {
            history
                .record_month(
                    &node(name),
                    UsageV1 {
                        month: month.parse().unwrap(),
                        updated_at: wire(sampled),
                        traffic: BTreeMap::new(),
                    },
                    received,
                )
                .unwrap();
        }
        collected.set_node(node(name), history);
    }
    let report = collected.aggregate(&deployment_billed_on(1), now).unwrap();
    assert_eq!(report.users[&user_ids()[0]].lifetime(), None);
    assert_eq!(history_lifetime(&collected, now), None);
}

#[test]
fn a_batch_installed_while_the_node_held_nothing_keeps_the_latest_sighting() {
    let mut collected = CollectedUsage::default();
    // Taken with the clock six hours fast.
    let fast = at("2026-11-02", 6 * 3600);
    collected.observe_unserved(node("lon1"), fast);
    // The batch begins from this copy; the next sighting, with the clock
    // right, comes while it runs.
    let mut batch = collected.node(&node("lon1")).unwrap().clone();
    collected.observe_unserved(node("lon1"), at("2026-11-02", 60));
    record_months(&mut batch, "lon1", "2026-11", 1, at("2026-11-02", 120));
    collected.set_node(node("lon1"), batch.clone());
    assert_eq!(lon1(&collected)["origin"], at("2026-11-02", 60).as_secs());
    assert_eq!(
        lon1(&collected)["months"],
        serde_json::to_value(&batch).unwrap()["months"]
    );
    // Once the node holds a record, a batch replaces the history whole.
    collected.set_node(node("lon1"), batch);
    assert_eq!(lon1(&collected)["origin"], fast.as_secs());

    // With the clock right throughout, the sighting made while the batch
    // ran is also the later one.
    collected.observe_unserved(node("ams1"), at("2026-11-02", 0));
    let mut batch = collected.node(&node("ams1")).unwrap().clone();
    collected.observe_unserved(node("ams1"), at("2026-11-02", 60));
    record_months(&mut batch, "ams1", "2026-11", 1, at("2026-11-02", 120));
    collected.set_node(node("ams1"), batch);
    assert_eq!(
        serde_json::to_value(&collected).unwrap()["nodes"]["ams1"]["origin"],
        at("2026-11-02", 60).as_secs()
    );
}

#[test]
fn a_batch_begun_before_the_first_sighting_keeps_it_and_a_complete_lifetime() {
    let mut collected = CollectedUsage::default();
    // The batch begins from a new history, as for a node the Mac holds
    // nothing of; the node's first sighting comes while it runs.
    let mut batch = NodeUsageHistory::default();
    let now = at("2026-11-02", 120);
    collected.observe_unserved(node("lon1"), at("2026-11-02", 60));
    record_months(&mut batch, "lon1", "2026-11", 1, now);
    collected.set_node(node("lon1"), batch);
    assert_eq!(lon1(&collected)["origin"], at("2026-11-02", 60).as_secs());
    assert_eq!(lon1(&collected)["lifetime_complete"], true);
    assert_eq!(
        history_lifetime(&collected, now),
        Some(ProtocolTraffic {
            reality: traffic(10, 20),
            hy2: Traffic::default(),
        })
    );
}

#[test]
fn a_last_sighting_before_a_month_boundary_leaves_the_lifetime_unknown() {
    // Last seen unserved one minute before November, first month November:
    // October is never held, as before this fix.
    let sightings = [at("2026-10-28", 0), at("2026-10-31", 86_340)];
    let now = at("2026-12-15", 12 * 3600);
    let report = collected(&sightings, "2026-11", 2, now)
        .aggregate(&deployment_billed_on(1), now)
        .unwrap();
    assert_eq!(report.users[&user_ids()[0]].lifetime(), None);
    let deployment = deployment_billed_on(1);
    let now = at("2028-02-05", 3600);
    let mut folded = collected(&sightings, "2026-11", 16, now);
    folded.prune(&deployment, now).unwrap();
    assert_eq!(lon1(&folded)["lifetime_complete"], false);
}

#[test]
fn a_cycle_that_began_before_the_origins_month_stays_unknown() {
    // The cycle runs from 20 October; the node was first applied on
    // 2 November. Its October holds nothing, but the Mac holds no October
    // to show it.
    let now = at("2026-11-05", 12 * 3600);
    let collected = collected(&planned_then_applied(), "2026-11", 1, now);
    let report = collected.aggregate(&deployment_billed_on(20), now).unwrap();
    assert_eq!(report.users[&user_ids()[0]].cycle(), None);
    assert_eq!(
        report.users[&user_ids()[0]].lifetime(),
        Some(traffic(10, 20))
    );
}

#[test]
fn nothing_changes_while_the_mac_holds_any_record_of_the_node() {
    let first = at("2026-11-02", 0);
    let later = at("2026-11-05", 3600);
    let mut sighted = CollectedUsage::default();
    sighted.observe_unserved(node("lon1"), first);
    let document = serde_json::to_value(&sighted).unwrap();
    let edited_document = |field: &str, value: serde_json::Value| {
        let mut document = document.clone();
        document["nodes"]["lon1"][field] = value;
        CollectedUsage::decode(&serde_json::to_vec(&document).unwrap()).unwrap()
    };
    let bin = |at: UnixTime| serde_json::json!({ at.as_secs().to_string(): {} });
    let mut month = sighted.clone();
    let mut history = month.node(&node("lon1")).unwrap().clone();
    record_months(&mut history, "lon1", "2026-11", 1, later);
    month.set_node(node("lon1"), history);
    // November folded while not final: a lower bound.
    let mut folded = month.clone();
    folded
        .prune(&deployment_billed_on(1), at("2028-01-02", 0))
        .unwrap();
    assert_eq!(lon1(&folded)["months"], serde_json::json!({}));
    assert_eq!(lon1(&folded)["lifetime_complete"], false);
    // A node collected before any sighting: a month, and no origin.
    let mut unsighted = CollectedUsage::default();
    let mut history = NodeUsageHistory::default();
    record_months(&mut history, "lon1", "2026-11", 1, later);
    unsighted.set_node(node("lon1"), history);
    for (held, mut collected) in [
        ("a month", month),
        (
            "a five-minute bin",
            edited_document("five_min", bin(at("2026-11-04", 300))),
        ),
        (
            "an hour bin",
            edited_document("hour", bin(at("2026-11-04", 3600))),
        ),
        (
            "a day bin",
            edited_document("day", bin(at("2026-11-04", 0))),
        ),
        (
            "an empty folded month",
            edited_document("folded_before", "2026-11".into()),
        ),
        ("a folded lower bound", folded),
        ("a month with no origin", unsighted),
    ] {
        let before = lon1(&collected);
        collected.observe_unserved(node("lon1"), later);
        assert_eq!(lon1(&collected), before, "{held}");
    }
    sighted.observe_unserved(node("lon1"), later);
    assert_eq!(lon1(&sighted)["origin"], later.as_secs(), "nothing held");
}

#[test]
fn a_history_whose_records_all_expired_holds_nothing_again() {
    let deployment = deployment_billed_on(1);
    let mut collected = CollectedUsage::default();
    collected.observe_unserved(node("lon1"), at("2026-11-02", 0));
    let mut history = collected.node(&node("lon1")).unwrap().clone();
    let detail = series(
        at("2026-11-02", 300),
        at("2026-11-02", 600),
        Resolution::FiveMin,
        vec![],
    );
    history.record_series(&node("lon1"), &detail).unwrap();
    collected.set_node(node("lon1"), history);
    collected.observe_unserved(node("lon1"), at("2026-11-02", 900));
    assert_eq!(lon1(&collected)["origin"], at("2026-11-02", 0).as_secs());
    // A five-minute bin is kept 7 days, and this one makes no hour.
    collected.prune(&deployment, at("2026-11-10", 0)).unwrap();
    collected.observe_unserved(node("lon1"), at("2026-11-10", 60));
    assert_eq!(lon1(&collected)["origin"], at("2026-11-10", 60).as_secs());
}

#[test]
fn a_history_that_holds_nothing_gets_an_origin_and_a_complete_lifetime() {
    // The collector stores what it pulled from an adopted node, nothing,
    // before the daemon has seen the node unserved.
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), NodeUsageHistory::default());
    assert_eq!(lon1(&collected)["origin"], serde_json::Value::Null);
    collected.observe_unserved(node("lon1"), at("2026-11-02", 0));
    assert_eq!(lon1(&collected)["origin"], at("2026-11-02", 0).as_secs());
    assert_eq!(lon1(&collected)["lifetime_complete"], true);
    // A stored origin with an incomplete lifetime and nothing held.
    let mut document = serde_json::to_value(&collected).unwrap();
    document["nodes"]["lon1"]["lifetime_complete"] = false.into();
    let mut decoded = CollectedUsage::decode(&serde_json::to_vec(&document).unwrap()).unwrap();
    decoded.observe_unserved(node("lon1"), at("2026-11-03", 0));
    assert_eq!(lon1(&decoded)["origin"], at("2026-11-03", 0).as_secs());
    assert_eq!(lon1(&decoded)["lifetime_complete"], true);
}

#[test]
fn only_planned_and_adopted_nodes_are_sighted() {
    let at_now = at("2026-11-02", 0);
    for stage in LifecycleStage::ALL {
        let deployment = edited(|parts| {
            let lon1 = parts
                .nodes
                .iter_mut()
                .find(|held| held.id == node("lon1"))
                .unwrap();
            let NodeLifecycle::Applied { site, applied } = lon1.lifecycle.clone() else {
                panic!("the fixture's lon1 is applied");
            };
            lon1.lifecycle = match stage {
                LifecycleStage::Planned => NodeLifecycle::Planned,
                LifecycleStage::Adopted => NodeLifecycle::Adopted { site },
                LifecycleStage::Applied => NodeLifecycle::Applied { site, applied },
                LifecycleStage::Retiring => NodeLifecycle::Retiring { site },
                LifecycleStage::RetiredPendingProviderDeletion => {
                    NodeLifecycle::RetiredPendingProviderDeletion {
                        address: site.address,
                    }
                }
                LifecycleStage::Retired => NodeLifecycle::Retired,
            };
            // A retired node holds no user's credentials.
            if !lon1.lifecycle.is_active() {
                for user in &mut parts.users {
                    user.per_node.remove(&node("lon1"));
                }
            }
        });
        let mut collected = CollectedUsage::default();
        collected.observe_unserved_nodes(&deployment, at_now);
        if matches!(stage, LifecycleStage::Planned | LifecycleStage::Adopted) {
            assert_eq!(lon1(&collected)["origin"], at_now.as_secs(), "{stage:?}");
            assert_eq!(lon1(&collected)["lifetime_complete"], true, "{stage:?}");
        } else {
            assert!(collected.node(&node("lon1")).is_none(), "{stage:?}");
        }
        assert!(collected.node(&node("ams1")).is_none(), "ams1 is applied");
    }
}

/// A cancelled plan changes no figure: the aggregate needs nothing from a
/// node the deployment no longer holds. The sighting the cancelled node
/// left is replaced when its id is planned again, since it holds nothing,
/// and the prune drops it before that.
#[test]
fn a_cancelled_plan_changes_no_figure_and_its_id_is_sighted_afresh() {
    let now = at("2026-12-15", 12 * 3600);
    let planned = edited(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|held| held.id == node("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
    });
    let cancelled = planned
        .clone()
        .record(Bookkeeping::PlanCancelled {
            node: node("ams1"),
            at: UnixTime::from_secs(1_791_417_600),
        })
        .unwrap();
    let mut collected = CollectedUsage::default();
    collected.observe_unserved(node("lon1"), at("2026-10-28", 0));
    let mut history = collected.node(&node("lon1")).unwrap().clone();
    record_months(&mut history, "lon1", "2026-11", 2, now);
    collected.set_node(node("lon1"), history);
    collected.observe_unserved_nodes(&planned, at("2026-12-01", 0));
    assert_eq!(ams1(&collected)["origin"], at("2026-12-01", 0).as_secs());
    let report = collected.aggregate(&cancelled, now).unwrap();
    assert_eq!(collected.aggregate(&planned, now).unwrap(), report);

    let mut replanned = collected.clone();
    replanned.observe_unserved_nodes(&planned, at("2026-12-10", 0));
    assert_eq!(ams1(&replanned)["origin"], at("2026-12-10", 0).as_secs());

    collected.prune(&cancelled, now).unwrap();
    assert!(collected.node(&node("ams1")).is_none());
    assert!(collected.node(&node("lon1")).is_some());
    collected.observe_unserved_nodes(&planned, now);
    assert_eq!(ams1(&collected)["origin"], now.as_secs());
    assert_eq!(ams1(&collected)["lifetime_complete"], true);
}
