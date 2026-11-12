// SPDX-License-Identifier: GPL-3.0-or-later

//! The status line the daemon assembles before it has polled any node
//! (design §15.2): every node row is `NotPolled` unless a poll failed, the
//! usage is unavailable with its reason, or `NotPulled` while the daemon
//! pulls no ledger, rather than zeros, nobody is read as idle, and the SIM
//! figures are the meter's as given.

use std::collections::BTreeMap;

use mooring_agent_proto::Inbound;
use mooring_model::{Deployment, NodeId, UnixTime};

use super::collected_usage::month;
use super::payments::Told;
use super::support::{deployment_billed_on, email, node, traffic, user_ids};
use crate::error::UsageErrorKind;
use crate::payments::Entitlements;
use crate::period::BillingCycle;
use crate::policy::QuotaState;
use crate::router::{RouterReading, RouterUnavailableReason};
use crate::snapshot::{Ledgers, SimTotals, StatusInputs, assemble};
use crate::status::{
    AgentUnreachable, ExitSection, ExitState, MacEngines, MacStatusV2, MeterAccuracy,
    NodeAgentState, PowerSource, PowerStatus, UsageView,
};
use crate::usage::{ActiveNow, CollectedUsage, NodeUsageHistory, ServedBefore};

fn exit(at: UnixTime) -> ExitSection {
    ExitSection {
        state: ExitState::Disabled,
        since: at,
        latches: Vec::new(),
        egress: None,
        carrier_check: None,
        engines: MacEngines {
            exit: crate::status::EngineProcess {
                pid: None,
                restarts: 0,
                last_exit: None,
            },
            probe: crate::status::EngineProcess {
                pid: None,
                restarts: 0,
                last_exit: None,
            },
        },
        power: PowerStatus {
            source: PowerSource::Ac,
            assertions_held: false,
            last_sleep: None,
            last_wake: None,
            last_drain: None,
        },
        foreign_networks: std::collections::BTreeSet::new(),
        allowed_networks: std::collections::BTreeSet::new(),
    }
}

/// An hour after the fixture's now.
fn at() -> UnixTime {
    UnixTime::from_secs(mooring_fixtures::FIXTURE_NOW.as_secs() + 3_600)
}

/// The status assembled before any node poll, with `ledgers` and the nodes
/// the last poll did not reach.
fn assembled(ledgers: Ledgers<'_>, unreachable: &BTreeMap<NodeId, NodeAgentState>) -> MacStatusV2 {
    assembled_with(ledgers, unreachable, &Entitlements::none())
}

/// [`assembled`], with what the users' paid orders gave.
fn assembled_with(
    ledgers: Ledgers<'_>,
    unreachable: &BTreeMap<NodeId, NodeAgentState>,
    entitlements: &Entitlements,
) -> MacStatusV2 {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    assembled_for(&fixture.deployment, ledgers, unreachable, entitlements)
}

/// [`assembled_with`], for `deployment`.
fn assembled_for(
    deployment: &Deployment,
    ledgers: Ledgers<'_>,
    unreachable: &BTreeMap<NodeId, NodeAgentState>,
    entitlements: &Entitlements,
) -> MacStatusV2 {
    assemble(StatusInputs {
        deployment,
        at: at(),
        exit: exit(at()),
        sim: SimTotals {
            rx_bytes: 3_000,
            tx_bytes: 1_000,
            daily: &[],
            accuracy: MeterAccuracy::LowerBound,
        },
        router: RouterReading::Unavailable {
            reason: RouterUnavailableReason::NotConfigured,
            last_polled_at: None,
        },
        capacity: None,
        ledgers,
        through: at(),
        polls: &BTreeMap::new(),
        unreachable,
        verdicts: &BTreeMap::new(),
        pending_apply: &BTreeMap::new(),
        alerts: Vec::new(),
        entitlements,
    })
    .unwrap()
}

#[test]
fn before_any_poll_nodes_are_not_polled_and_usage_says_why_it_is_missing() {
    let lon1 = NodeId::parse("lon1").unwrap();
    let unreachable = BTreeMap::from([(
        lon1.clone(),
        NodeAgentState::Unreachable {
            since: at(),
            cause: AgentUnreachable::Transport,
        },
    )]);
    let status = assembled(Ledgers::Pulled(&[]), &unreachable);
    let parts = status.parts();
    let agents: Vec<(&str, &NodeAgentState)> = parts
        .nodes
        .iter()
        .map(|(node, row)| (node.as_str(), &row.agent))
        .collect();
    assert_eq!(
        agents,
        [
            ("ams1", &NodeAgentState::NotPolled),
            ("lon1", &unreachable[&lon1]),
        ]
    );
    assert_eq!(
        parts.usage,
        UsageView::Unavailable {
            reason: UsageErrorKind::MissingLedger
        }
    );
    assert!(
        parts
            .users
            .values()
            .all(|row| row.usage.is_none() && row.activity.active_now == ActiveNow::Unknown)
    );
    assert_eq!(
        (parts.sim.rx_bytes, parts.sim.tx_bytes, parts.sim.accuracy),
        (3_000, 1_000, MeterAccuracy::LowerBound)
    );
    assert!(
        parts
            .nodes
            .values()
            .all(|row| row.verdicts.reality.is_none()
                && row.verdicts.hy2.is_none()
                && row.pending_apply_since.is_none())
    );
}

#[test]
fn while_no_ledger_is_pulled_the_usage_view_is_not_pulled_and_no_row_carries_usage() {
    let status = assembled(Ledgers::NotPulled, &BTreeMap::new());
    let parts = status.parts();
    assert_eq!(parts.usage, UsageView::NotPulled);
    assert_eq!(parts.users.len(), 3);
    assert!(
        parts
            .users
            .values()
            .all(|row| row.usage.is_none() && row.quota == QuotaState::NoQuota)
    );
}

/// A paid user's row shows the quota and the expiry their paid order gave
/// (design §9.6); the other users' rows are as before.
#[test]
fn a_paid_users_row_shows_the_paid_policy() {
    use crate::payments::{FeedPage, PaymentLedger};
    use crate::policy::{ExpiryState, paid_quota};

    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let ids: Vec<_> = fixture.deployment.users().keys().cloned().collect();
    let document = serde_json::json!({
        "format": "mooring-portal-entitlements",
        "version": 1,
        "generated_at": at().as_secs(),
        "livemode": true,
        "after": 0,
        "entries": [{
            "seq": 1, "kind": "grant", "order": "aaaaaaaaaaaaaaaaaaaa", "user": ids[0].as_str(),
            "plan": "month-100", "plan_kind": "month", "days": 30, "traffic_bytes": 100_000_000_000_u64,
            "amount": 800, "currency": "gbp", "paid_at": at().as_secs(), "renewal_of": null,
            "amount_refunded": null, "refunded_in_full": null, "amount_disputed": null,
            "recorded_at": at().as_secs()
        }],
        "next": 1,
        "more": false
    });
    let page = FeedPage::decode(&serde_json::to_vec(&document).unwrap(), 0).unwrap();
    let ledger = PaymentLedger::new()
        .apply(&page, fixture.deployment.users(), at(), false)
        .unwrap()
        .ledger;
    let paid = assembled_with(
        Ledgers::NotPulled,
        &BTreeMap::new(),
        &ledger.entitlements(false),
    );
    let plain = assembled(Ledgers::NotPulled, &BTreeMap::new());
    let row = &paid.parts().users[&ids[0]];
    assert_eq!(
        row.quota,
        QuotaState::without_usage(Some(paid_quota(
            std::num::NonZeroU64::new(100_000_000_000).unwrap()
        )))
    );
    assert_eq!(
        row.expiry,
        ExpiryState::Expires {
            at: UnixTime::from_secs(at().as_secs() + 30 * 86_400),
            days_left: 30
        }
    );
    assert_ne!(row, &plain.parts().users[&ids[0]]);
    assert_eq!(paid.parts().users[&ids[1]], plain.parts().users[&ids[1]]);
}

/// A user's row counts a download that was open at the refund in full of
/// a traffic pack (design §9.6): the report that gives the user's use also
/// gives what each node has counted of their REALITY downlink. The user
/// has a paid month of 100 GB and a 50 GB pack refunded in full; the use
/// learned was 120 GB, 30 GB of it REALITY downlink on lon1, so the pack
/// kept 20 GB. lon1 has now counted 40 GB of it: the 10 GB more count as
/// used of the pack, and the quota is 130 GB against 125 GB used.
#[test]
fn a_row_counts_what_a_node_counted_since_a_refunded_packs_use_was_learned() {
    use crate::payments::{FeedPage, PaymentLedger};

    const GB: u64 = 1_000_000_000;
    let deployment = deployment_billed_on(1);
    let user = &user_ids()[0];
    let mut history = CollectedUsage::default();
    let mut lon = NodeUsageHistory::default();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-10",
            at(),
            vec![
                (email(user, Inbound::Reality), traffic(0, 40 * GB)),
                (email(user, Inbound::Hy2), traffic(0, 85 * GB)),
            ],
        ),
        at(),
    )
    .unwrap();
    history.set_node(node("lon1"), lon);
    let mut ams = NodeUsageHistory::default();
    ams.record_month(&node("ams1"), month("2026-10", at(), vec![]), at())
        .unwrap();
    history.set_node(node("ams1"), ams);

    let granted = at().as_secs() - 3 * 3600;
    let refunded = at().as_secs() - 2 * 3600;
    let learned = UnixTime::from_secs(at().as_secs() - 3600);
    let entry = |seq: u64, kind: &str, order: &str, plan_kind: &str, bytes: u64| {
        let refund = kind == "refund";
        serde_json::json!({
            "seq": seq, "kind": kind, "order": order, "user": user.as_str(),
            "plan": "plan", "plan_kind": plan_kind, "days": 30, "traffic_bytes": bytes,
            "amount": 800, "currency": "gbp", "paid_at": granted, "renewal_of": null,
            "amount_refunded": refund.then_some(800), "refunded_in_full": refund.then_some(true),
            "amount_disputed": null,
            "recorded_at": if refund { refunded } else { granted },
        })
    };
    let page = |after: u64, entries: Vec<serde_json::Value>| {
        let next = after + entries.len() as u64;
        let document = serde_json::json!({
            "format": "mooring-portal-entitlements", "version": 1,
            "generated_at": at().as_secs(), "livemode": true,
            "after": after, "entries": entries, "next": next, "more": false,
        });
        FeedPage::decode(&serde_json::to_vec(&document).unwrap(), after).unwrap()
    };
    let grants = page(
        0,
        vec![
            entry(1, "grant", "aaaaaaaaaaaaaaaaaaaa", "month", 100 * GB),
            entry(2, "grant", "bbbbbbbbbbbbbbbbbbbb", "traffic", 50 * GB),
        ],
    );
    let refund = page(
        2,
        vec![entry(
            3,
            "refund",
            "bbbbbbbbbbbbbbbbbbbb",
            "traffic",
            50 * GB,
        )],
    );
    let users = deployment.users();
    let ledger = PaymentLedger::new()
        .apply(&grants, users, UnixTime::from_secs(granted), false)
        .unwrap()
        .ledger
        .apply(&refund, users, UnixTime::from_secs(refunded), false)
        .unwrap()
        .ledger;
    let told = Told {
        served: Some(ServedBefore {
            bytes: 120 * GB,
            reality_downlink: BTreeMap::from([(node("lon1"), 30 * GB), (node("ams1"), 0)]),
        }),
        ..Told::default()
    };
    let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), learned).unwrap();
    let ledger = ledger.settle(learned, cycle, &told).unwrap().ledger;
    let status = assembled_for(
        &deployment,
        Ledgers::Collected(&history),
        &BTreeMap::new(),
        &ledger.entitlements(false),
    );
    assert_eq!(
        status.parts().users[user].quota,
        QuotaState::Warn {
            used_bytes: 125 * GB,
            quota_bytes: 130 * GB,
        }
    );
}
