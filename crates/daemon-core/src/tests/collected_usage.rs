// SPDX-License-Identifier: GPL-3.0-or-later

//! Collected accounting across replay, lost detail, billing boundaries,
//! source contradictions and retention. Probe bytes never become users'.

use std::collections::BTreeMap;

use mooring_agent_proto::{Inbound, Resolution, StatsEmail, Traffic, UsageMonth, UsageV1};
use mooring_model::{Deployment, UnixTime, UserStatus};

use super::support::{
    at, deployment_billed_on, email, node, probe, series, traffic, user_ids, wire,
};
use crate::error::{UsageError, UsageErrorKind};
use crate::usage::{CollectedUsage, MAX_COLLECTED_USAGE_BYTES, NodeUsageHistory, UserUsage};

/// A node's month `text` as sampled at `updated`, with `entries`.
pub(super) fn month(text: &str, updated: UnixTime, entries: Vec<(StatsEmail, Traffic)>) -> UsageV1 {
    UsageV1 {
        month: text.parse::<UsageMonth>().unwrap(),
        updated_at: wire(updated),
        traffic: entries.into_iter().collect(),
    }
}

fn empty_other(history: &mut CollectedUsage, now: UnixTime) {
    let mut other = NodeUsageHistory::default();
    other
        .record_month(
            &node("ams1"),
            month("2026-10", at("2026-10-31", 86_399), vec![]),
            now,
        )
        .unwrap();
    other
        .record_month(&node("ams1"), month("2026-11", now, vec![]), now)
        .unwrap();
    history.set_node(node("ams1"), other);
}

fn today_history() -> (CollectedUsage, UnixTime) {
    let now = at("2026-11-05", 12 * 3600);
    let user = &user_ids()[0];
    let mut lon = NodeUsageHistory::default();
    let detail = series(
        at("2026-11-05", 0),
        now,
        Resolution::FiveMin,
        vec![(
            at("2026-11-05", 300),
            vec![
                (email(user, Inbound::Reality), traffic(10, 10)),
                (email(user, Inbound::Hy2), traffic(5, 5)),
                (probe(Inbound::Reality), traffic(0, 500)),
            ],
        )],
    );
    lon.record_series(&node("lon1"), &detail).unwrap();
    lon.record_series(&node("lon1"), &detail).unwrap();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-11",
            now,
            vec![
                (email(user, Inbound::Reality), traffic(30, 40)),
                (email(user, Inbound::Hy2), traffic(10, 20)),
                (probe(Inbound::Reality), traffic(0, 900)),
            ],
        ),
        now,
    )
    .unwrap();
    let mut history = CollectedUsage::default();
    history.set_node(node("lon1"), lon);
    empty_other(&mut history, now);
    (history, now)
}

#[test]
fn known_origins_and_final_months_survive_retention_as_one_lifetime_total() {
    let deployment = deployment_billed_on(1);
    let now = at("2028-02-05", 3600);
    let origin = at("2026-11-01", 0);
    let mut collected = CollectedUsage::default();
    let user = &user_ids()[0];
    for name in ["lon1", "ams1"] {
        let id = node(name);
        collected.observe_unserved(id.clone(), origin);
        let mut history = collected.node(&id).unwrap().clone();
        let mut cursor: UsageMonth = "2026-11".parse().unwrap();
        for _ in 0..16 {
            let end = cursor.next().unwrap().start().as_secs();
            let updated = now.as_secs().min(end - 1);
            let received = now.as_secs().min(end);
            history
                .record_month(
                    &id,
                    UsageV1 {
                        month: cursor,
                        updated_at: mooring_agent_proto::UnixTime::from_secs(updated),
                        traffic: if name == "lon1" {
                            BTreeMap::from([(email(user, Inbound::Reality), traffic(10, 20))])
                        } else {
                            BTreeMap::new()
                        },
                    },
                    UnixTime::from_secs(received),
                )
                .unwrap();
            cursor = cursor.next().unwrap();
        }
        collected.set_node(id, history);
    }
    collected.prune(&deployment, now).unwrap();
    let encoded = collected.encode().unwrap();
    let report = CollectedUsage::decode(&encoded)
        .unwrap()
        .aggregate(&deployment, now)
        .unwrap();
    assert_eq!(report.users[user].lifetime(), Some(traffic(160, 320)));
    assert_eq!(report.users[user].month(), Some(traffic(10, 20)));
    let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(json["nodes"]["lon1"]["folded_before"], "2027-01");
    assert_eq!(
        json["nodes"]["lon1"]["months"].as_object().unwrap().len(),
        14
    );
    collected.prune(&deployment, now).unwrap();
    assert_eq!(
        collected.encode().unwrap(),
        encoded,
        "expired totals fold exactly once"
    );
}

#[test]
fn retention_overflow_preserves_the_whole_previous_document() {
    let deployment = deployment_billed_on(1);
    let mut collected = CollectedUsage::default();
    let id = node("lon1");
    collected.observe_unserved(id.clone(), at("2026-10-01", 0));
    let mut history = collected.node(&id).unwrap().clone();
    for (name, bytes) in [("2026-10", u64::MAX), ("2026-11", 1)] {
        let month: UsageMonth = name.parse().unwrap();
        let end = month.next().unwrap().start().as_secs();
        history
            .record_month(
                &id,
                UsageV1 {
                    month,
                    updated_at: mooring_agent_proto::UnixTime::from_secs(end - 1),
                    traffic: BTreeMap::from([(
                        email(&user_ids()[0], Inbound::Reality),
                        traffic(bytes, 0),
                    )]),
                },
                UnixTime::from_secs(end),
            )
            .unwrap();
    }
    collected.set_node(id, history);
    let before = collected.encode().unwrap();
    assert_eq!(
        collected.prune(&deployment, at("2028-01-01", 0)),
        Err(UsageError::CounterOverflow)
    );
    assert_eq!(collected.encode().unwrap(), before);
}

#[test]
fn corrupted_rollups_and_overlapping_lifetime_indexes_are_rejected_on_reload() {
    let (history, _) = today_history();
    let json: serde_json::Value = serde_json::from_slice(&history.encode().unwrap()).unwrap();
    let mut conflict = json.clone();
    let hour = at("2026-11-05", 0).as_secs().to_string();
    conflict["nodes"]["lon1"]["hour"][&hour] = serde_json::json!({});
    let error = CollectedUsage::decode(&serde_json::to_vec(&conflict).unwrap()).unwrap_err();
    assert_eq!(error.kind(), UsageErrorKind::LedgerCorrupt);
    assert!(error.to_string().contains("rollup"));
    let mut overlap = json;
    overlap["nodes"]["lon1"]["folded_before"] = "2026-12".into();
    assert!(
        CollectedUsage::decode(&serde_json::to_vec(&overlap).unwrap())
            .unwrap_err()
            .to_string()
            .contains("overlaps")
    );
}

#[test]
fn replay_and_restart_keep_exact_monthly_totals_and_probes_separate() {
    let deployment = deployment_billed_on(1);
    let (history, now) = today_history();
    let saved = history.encode().unwrap();
    let restored = CollectedUsage::decode(&saved).unwrap();
    let report = restored.aggregate(&deployment, now).unwrap();
    let row = &report.users[&user_ids()[0]];
    assert_eq!(row.today(), Some(traffic(15, 15)));
    assert_eq!(row.month(), Some(traffic(40, 60)));
    assert_eq!(row.cycle(), row.month());
    assert_eq!(row.cycle_served_bytes(), Some(100));
    assert_eq!(
        row.lifetime(),
        None,
        "no fabricated lifetime origin on an existing node"
    );
    assert_eq!(
        row.cycle_by_node().unwrap(),
        &BTreeMap::from([(node("lon1"), traffic(40, 60))])
    );
    assert_eq!(
        report.probe_cycle[&node("lon1")].unwrap().reality,
        traffic(0, 900)
    );
    for user in &user_ids()[1..] {
        assert_eq!(report.users[user].month(), Some(traffic(0, 0)));
    }
    assert_eq!(restored.encode().unwrap(), saved);
    assert_eq!(report.sampled_at[&node("lon1")].detail_through, Some(now));
}

#[test]
fn a_lost_split_across_the_bill_day_is_unknown_but_the_month_is_known() {
    let deployment = deployment_billed_on(28);
    let (mut history, now) = today_history();
    let user = &user_ids()[0];
    let mut lon = history.node(&node("lon1")).unwrap().clone();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-10",
            at("2026-10-31", 86_399),
            vec![(email(user, Inbound::Reality), traffic(100, 100))],
        ),
        now,
    )
    .unwrap();
    history.set_node(node("lon1"), lon);
    let report = history.aggregate(&deployment, now).unwrap();
    let row = &report.users[user];
    assert_eq!(row.cycle(), None);
    assert_eq!(row.cycle_served_bytes(), None);
    assert_eq!(row.cycle_by_node(), None);
    assert_eq!(row.cycle_by_protocol(), None);
    assert_eq!(row.cycle_shares(), None);
    assert_eq!(row.month(), Some(traffic(40, 60)));
    assert_eq!(row.today(), Some(traffic(15, 15)));
    assert!(report.cycle_usage().is_none());
    let bytes = serde_json::to_vec(row).unwrap();
    assert_eq!(serde_json::from_slice::<UserUsage>(&bytes).unwrap(), *row);
    let mut mixed = serde_json::to_value(row).unwrap();
    mixed["cycle_served_bytes"] = 0.into();
    assert!(serde_json::from_value::<UserUsage>(mixed).is_err());
}

#[test]
fn zero_in_the_uncertain_prefix_does_not_hide_known_later_months() {
    let (mut history, now) = today_history();
    let mut lon = history.node(&node("lon1")).unwrap().clone();
    lon.record_month(
        &node("lon1"),
        month("2026-10", at("2026-10-31", 86_399), vec![]),
        now,
    )
    .unwrap();
    history.set_node(node("lon1"), lon);
    assert_eq!(
        history
            .aggregate(&deployment_billed_on(28), now)
            .unwrap()
            .users[&user_ids()[0]]
            .cycle_served_bytes(),
        Some(100)
    );
}

#[test]
fn a_month_snapshot_read_before_month_end_is_not_a_final_month() {
    let (mut history, now) = today_history();
    let mut lon = history.node(&node("lon1")).unwrap().clone();
    let sample = month("2026-10", at("2026-10-31", 86_399), vec![]);
    lon.record_month(&node("lon1"), sample.clone(), at("2026-10-31", 86_399))
        .unwrap();
    history.set_node(node("lon1"), lon.clone());
    assert_eq!(
        history
            .aggregate(&deployment_billed_on(28), now)
            .unwrap()
            .users[&user_ids()[0]]
            .cycle(),
        None
    );
    lon.record_month(&node("lon1"), sample, now).unwrap();
    history.set_node(node("lon1"), lon);
    assert_eq!(
        history
            .aggregate(&deployment_billed_on(28), now)
            .unwrap()
            .users[&user_ids()[0]]
            .cycle_served_bytes(),
        Some(100)
    );
}

#[test]
fn a_gap_within_one_cycle_is_recovered_from_monthly_totals_minus_its_prefix() {
    let now = at("2026-11-05", 12 * 3600);
    let user = &user_ids()[0];
    let mut lon = NodeUsageHistory::default();
    // A proven two-day prefix; the later two-day gap lies wholly in the cycle.
    for half in 0..4 {
        let from = at("2026-11-01", half * 12 * 3600);
        let to = UnixTime::from_secs(from.as_secs() + 12 * 3600);
        let entries = if half == 0 {
            vec![(from, vec![(email(user, Inbound::Reality), traffic(0, 40))])]
        } else {
            vec![]
        };
        lon.record_series(
            &node("lon1"),
            &series(from, to, Resolution::FiveMin, entries),
        )
        .unwrap();
    }
    lon.record_month(
        &node("lon1"),
        month(
            "2026-11",
            now,
            vec![(email(user, Inbound::Reality), traffic(0, 100))],
        ),
        now,
    )
    .unwrap();
    let mut history = CollectedUsage::default();
    history.set_node(node("lon1"), lon);
    empty_other(&mut history, now);
    let report = history.aggregate(&deployment_billed_on(3), now).unwrap();
    assert_eq!(report.users[user].cycle(), Some(traffic(0, 60)));
    assert_eq!(report.users[user].today(), None);
    assert_eq!(report.users[user].month(), Some(traffic(0, 100)));
}

#[test]
fn inconsistent_inputs_and_missing_history_are_errors_not_zero_figures() {
    let (history, now) = today_history();
    let mut lon = history.node(&node("lon1")).unwrap().clone();
    let user = &user_ids()[0];
    let regression = month("2026-11", UnixTime::from_secs(now.as_secs() + 1), vec![]);
    assert_eq!(
        lon.record_month(
            &node("lon1"),
            regression,
            UnixTime::from_secs(now.as_secs() + 1)
        )
        .unwrap_err()
        .kind(),
        UsageErrorKind::MonthlyInconsistent
    );
    let changed = series(
        at("2026-11-05", 300),
        at("2026-11-05", 600),
        Resolution::FiveMin,
        vec![(
            at("2026-11-05", 300),
            vec![(email(user, Inbound::Reality), traffic(999, 0))],
        )],
    );
    assert!(matches!(
        lon.record_series(&node("lon1"), &changed),
        Err(UsageError::MonthlyInconsistent { .. })
    ));
    assert_eq!(
        CollectedUsage::default()
            .aggregate(&deployment_billed_on(1), now)
            .unwrap_err()
            .kind(),
        UsageErrorKind::MissingLedger
    );
    assert_eq!(
        history
            .aggregate(
                &deployment_billed_on(1),
                UnixTime::from_secs(now.as_secs() + 181)
            )
            .unwrap_err()
            .kind(),
        UsageErrorKind::NotCoveredThrough
    );
    let mut malformed = serde_json::to_value(&history).unwrap();
    malformed["version"] = 2.into();
    assert_eq!(
        CollectedUsage::decode(&serde_json::to_vec(&malformed).unwrap())
            .unwrap_err()
            .kind(),
        UsageErrorKind::LedgerCorrupt
    );
    assert!(CollectedUsage::decode(b"{").is_err());
    assert!(CollectedUsage::decode(&vec![b' '; MAX_COLLECTED_USAGE_BYTES + 1]).is_err());
}

#[test]
fn detail_rolls_up_before_expiry_and_revoked_user_bytes_are_deleted_everywhere() {
    let deployment = deployment_billed_on(1);
    let (mut history, now) = today_history();
    history.prune(&deployment, now).unwrap();
    let later = at("2026-11-13", 0);
    history.prune(&deployment, later).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&history.encode().unwrap()).unwrap();
    assert_eq!(
        value["nodes"]["lon1"]["five_min"]
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        value["nodes"]["lon1"]["hour"].as_object().unwrap().len(),
        12
    );
    let id = user_ids()[0].clone();
    let mut parts = deployment.into_parts();
    for user in &mut parts.users {
        if user.id == id {
            user.status = UserStatus::Revoked {
                since: UnixTime::from_secs(1_791_417_600),
            };
            user.per_node.clear();
        }
    }
    let revoked = Deployment::try_from(parts).unwrap();
    history.prune(&revoked, at("2027-12-13", 0)).unwrap();
    let encoded = history.encode().unwrap();
    assert!(
        !String::from_utf8(encoded.clone())
            .unwrap()
            .contains(id.as_str())
    );
    let mut replay = BTreeMap::from([(email(&id, Inbound::Reality), traffic(1, 2))]);
    history
        .retain_counter_users(&node("lon1"), &mut replay, &revoked, at("2027-12-13", 0))
        .unwrap();
    assert!(
        replay.is_empty(),
        "expired counters cannot reappear from a node replay"
    );
    assert!(CollectedUsage::decode(&encoded).is_ok());
}
