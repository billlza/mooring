// SPDX-License-Identifier: GPL-3.0-or-later

//! The status line the daemon assembles before it has polled any node
//! (design §15.2): every node row is `NotPolled` unless a poll failed, the
//! usage is unavailable with its reason, or `NotPulled` while the daemon
//! pulls no ledger, rather than zeros, nobody is read as idle, and the SIM
//! figures are the meter's as given.

use std::collections::BTreeMap;

use mooring_model::{NodeId, UnixTime};

use crate::error::UsageErrorKind;
use crate::payments::Entitlements;
use crate::policy::QuotaState;
use crate::router::{RouterReading, RouterUnavailableReason};
use crate::snapshot::{Ledgers, SimTotals, StatusInputs, assemble};
use crate::status::{
    AgentUnreachable, ExitSection, ExitState, MacEngines, MacStatusV2, MeterAccuracy,
    NodeAgentState, PowerSource, PowerStatus, UsageView,
};
use crate::usage::ActiveNow;

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
    assemble(StatusInputs {
        deployment: &fixture.deployment,
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
