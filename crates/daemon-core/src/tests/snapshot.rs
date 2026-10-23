// SPDX-License-Identifier: GPL-3.0-or-later

//! The status line the daemon assembles before it has polled any node
//! (design §15.2): every node row is `NotPolled` unless a poll failed, the
//! usage is unavailable with its reason rather than zeros, nobody is read
//! as idle, and the SIM figures are the meter's as given.

use std::collections::BTreeMap;

use mooring_model::{NodeId, UnixTime};

use crate::error::UsageErrorKind;
use crate::router::{RouterReading, RouterUnavailableReason};
use crate::snapshot::{SimTotals, StatusInputs, assemble};
use crate::status::{
    AgentUnreachable, ExitSection, ExitState, MacEngines, MeterAccuracy, NodeAgentState,
    PowerSource, PowerStatus, UsageView,
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
    }
}

#[test]
fn before_any_poll_nodes_are_not_polled_and_usage_says_why_it_is_missing() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let at = UnixTime::from_secs(mooring_fixtures::FIXTURE_NOW.as_secs() + 3_600);
    let lon1 = NodeId::parse("lon1").unwrap();
    let unreachable = BTreeMap::from([(
        lon1.clone(),
        NodeAgentState::Unreachable {
            since: at,
            cause: AgentUnreachable::Transport,
        },
    )]);
    let status = assemble(StatusInputs {
        deployment: &fixture.deployment,
        at,
        exit: exit(at),
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
        ledgers: &[],
        through: at,
        polls: &BTreeMap::new(),
        unreachable: &unreachable,
        verdicts: &BTreeMap::new(),
        pending_apply: &BTreeMap::new(),
        alerts: Vec::new(),
    })
    .unwrap();
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
