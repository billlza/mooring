// SPDX-License-Identifier: GPL-3.0-or-later

//! Alert conditions and the alert machine.

use std::collections::{BTreeMap, BTreeSet};

use mooring_agent_proto::{Inbound, InboundSet};
use mooring_model::verdict::ViolationKind;
use mooring_model::{NonEmptySet, UnixTime};
use proptest::prelude::*;

use super::support::{date, deployment, node};
use crate::alert::{
    AlertCondition, AlertConditionKind, AlertKey, AlertMachine, AlertNotice, AlertSubject,
    AlertTiming, CriticalThermalLevel, DegradedReasonKind, EngineHost, MacEngine,
    NODE_UNREACHABLE_HOLD_SECS, NodeEngine, NoticeEvent, Severity,
};
use crate::error::{AlertError, AlertErrorKind};
use crate::forecast::SimThreshold;

const MINUTE: u64 = 60;
const HOUR: u64 = 3600;

fn t(secs: u64) -> UnixTime {
    UnixTime::from_secs(1_791_417_600 + secs)
}

fn set<T: Ord>(items: impl IntoIterator<Item = T>) -> NonEmptySet<T> {
    NonEmptySet::try_from(items.into_iter().collect::<BTreeSet<T>>()).unwrap()
}

/// One condition of every kind, named, with its subject.
pub(crate) fn every_condition() -> Vec<(AlertConditionKind, AlertCondition, AlertSubject)> {
    use AlertConditionKind as K;
    let lon1 = || node("lon1");
    let on_lon1 = || AlertSubject::Node { node: lon1() };
    let cycle = date("2026-10-01");
    let sim = AlertSubject::SimCycle { start: cycle };
    vec![
        (
            K::ExitViolation,
            AlertCondition::ExitViolation {
                violations: set([ViolationKind::EgressMismatch]),
            },
            AlertSubject::Exit,
        ),
        (
            K::SimCapReached,
            AlertCondition::SimCapReached { cycle_start: cycle },
            sim.clone(),
        ),
        (
            K::RouterOffloadActive,
            AlertCondition::RouterOffloadActive,
            AlertSubject::Router,
        ),
        (
            K::RouterWifiRadioOn,
            AlertCondition::RouterWifiRadioOn,
            AlertSubject::Router,
        ),
        (
            K::RouterOverheating,
            AlertCondition::RouterOverheating {
                level: CriticalThermalLevel::Level2,
            },
            AlertSubject::Router,
        ),
        (
            K::RouterRestarted,
            AlertCondition::RouterRestarted,
            AlertSubject::Router,
        ),
        (
            K::NodeHalted,
            AlertCondition::NodeHalted { node: lon1() },
            on_lon1(),
        ),
        (
            K::RollbackFailed,
            AlertCondition::RollbackFailed { node: lon1() },
            on_lon1(),
        ),
        (
            K::GateCloseFailed,
            AlertCondition::GateCloseFailed { node: lon1() },
            on_lon1(),
        ),
        (
            K::EngineCrashLoop,
            AlertCondition::EngineCrashLoop {
                host: EngineHost::Node {
                    node: lon1(),
                    engine: NodeEngine::Xray,
                },
            },
            AlertSubject::Engine {
                host: EngineHost::Node {
                    node: lon1(),
                    engine: NodeEngine::Xray,
                },
            },
        ),
        (
            K::HostKeyMismatch,
            AlertCondition::HostKeyMismatch { node: lon1() },
            on_lon1(),
        ),
        (
            K::MacSilent,
            AlertCondition::MacSilent { node: lon1() },
            on_lon1(),
        ),
        (
            K::NodeUnreachable,
            AlertCondition::NodeUnreachable {
                node: lon1(),
                since: t(0),
            },
            on_lon1(),
        ),
        (
            K::NodeDiskLow,
            AlertCondition::NodeDiskLow {
                node: lon1(),
                free_bytes: 700_000_000,
            },
            on_lon1(),
        ),
        (
            K::SimWarn,
            AlertCondition::SimWarn { cycle_start: cycle },
            sim.clone(),
        ),
        (
            K::SimForecastCrossing,
            AlertCondition::SimForecastCrossing {
                cycle_start: cycle,
                threshold: SimThreshold::HardStop,
                on: date("2026-10-27"),
            },
            sim,
        ),
        (
            K::ExitDegraded,
            AlertCondition::ExitDegraded {
                reasons: set(DegradedReasonKind::ALL.iter().copied()),
            },
            AlertSubject::Exit,
        ),
        (
            K::ForeignNetworkAttached,
            AlertCondition::ForeignNetworkAttached { findings: 2 },
            AlertSubject::Exit,
        ),
        (
            K::ReachabilitySuspect,
            AlertCondition::ReachabilitySuspect { node: lon1() },
            on_lon1(),
        ),
        (
            K::TargetDegraded,
            AlertCondition::TargetDegraded { node: lon1() },
            on_lon1(),
        ),
        (
            K::RouterNoService,
            AlertCondition::RouterNoService,
            AlertSubject::Router,
        ),
        (
            K::RouterOnLte,
            AlertCondition::RouterOnLte,
            AlertSubject::Router,
        ),
        (
            K::RouterThermalStepDown,
            AlertCondition::RouterThermalStepDown,
            AlertSubject::Router,
        ),
        (
            K::RouterWeakSignal,
            AlertCondition::RouterWeakSignal {
                rsrp_dbm_x10: -1125,
            },
            AlertSubject::Router,
        ),
        (
            K::RouterFirmwareChanged,
            AlertCondition::RouterFirmwareChanged,
            AlertSubject::Router,
        ),
        (
            K::RouterUnreadSms,
            AlertCondition::RouterUnreadSms { count: 1 },
            AlertSubject::Router,
        ),
        (
            K::RouterCounterMismatch,
            AlertCondition::RouterCounterMismatch { permille: 63 },
            AlertSubject::Router,
        ),
        (
            K::UsersNearQuota,
            AlertCondition::UsersNearQuota { count: 2 },
            AlertSubject::Users,
        ),
        (
            K::UsersOverQuota,
            AlertCondition::UsersOverQuota { count: 1 },
            AlertSubject::Users,
        ),
        (
            K::UsersSuspended,
            AlertCondition::UsersSuspended { count: 1 },
            AlertSubject::Users,
        ),
        (
            K::UsersExpiringSoon,
            AlertCondition::UsersExpiringSoon { count: 3 },
            AlertSubject::Users,
        ),
        (
            K::UsersExpired,
            AlertCondition::UsersExpired { count: 1 },
            AlertSubject::Users,
        ),
        (
            K::CapacitySaturated,
            AlertCondition::CapacitySaturated,
            AlertSubject::Capacity,
        ),
        (
            K::ExitFlowCapHit,
            AlertCondition::ExitFlowCapHit {
                node: lon1(),
                count: 12,
            },
            on_lon1(),
        ),
        (
            K::NodeClockUnsynced,
            AlertCondition::NodeClockUnsynced { node: lon1() },
            on_lon1(),
        ),
        (
            K::NodeRebootPending,
            AlertCondition::NodeRebootPending {
                node: lon1(),
                since: t(0),
            },
            on_lon1(),
        ),
        (
            K::PendingApply,
            AlertCondition::PendingApply {
                node: lon1(),
                since: t(0),
            },
            on_lon1(),
        ),
        (
            K::OperatorHoldLong,
            AlertCondition::OperatorHoldLong {
                node: lon1(),
                since: t(0),
            },
            on_lon1(),
        ),
        (
            K::AccountingCanaryMissing,
            AlertCondition::AccountingCanaryMissing {
                node: lon1(),
                inbounds: InboundSet::of(Inbound::Hy2),
            },
            on_lon1(),
        ),
    ]
}

#[test]
fn every_condition_kind_is_produced_with_its_subject() {
    let conditions = every_condition();
    for (kind, condition, subject) in &conditions {
        assert_eq!(condition.kind(), *kind);
        assert_eq!(condition.subject(), *subject, "{kind}");
        assert_eq!(
            condition.node().is_some(),
            matches!(
                subject,
                AlertSubject::Node { .. }
                    | AlertSubject::Engine {
                        host: EngineHost::Node { .. }
                    }
            ),
            "{kind}"
        );
        assert_eq!(
            condition.key(),
            AlertKey {
                kind: *kind,
                subject: subject.clone()
            }
        );
        assert_eq!(condition.severity(), kind.severity());
        let json = serde_json::to_string(condition).unwrap();
        assert_eq!(
            serde_json::from_str::<AlertCondition>(&json).unwrap(),
            *condition
        );
        assert!(!condition.key().to_string().is_empty());
    }
    assert_eq!(
        conditions
            .iter()
            .map(|(kind, ..)| *kind)
            .collect::<Vec<_>>(),
        AlertConditionKind::ALL
    );
    // A crash loop on the Mac is about that engine on the Mac.
    let probe = EngineHost::Mac {
        engine: MacEngine::Probe,
    };
    let mac = AlertCondition::EngineCrashLoop {
        host: probe.clone(),
    };
    assert_eq!(mac.subject(), AlertSubject::Engine { host: probe });
    assert_eq!(mac.node(), None);
    assert_eq!(
        mac.key().to_string(),
        "EngineCrashLoop of mooring-probe on the Mac"
    );
    assert_eq!(
        AlertCondition::EngineCrashLoop {
            host: EngineHost::Node {
                node: node("lon1"),
                engine: NodeEngine::Hy2,
            },
        }
        .key()
        .to_string(),
        "EngineCrashLoop of mooring-hy2 on lon1"
    );
    // Only the conditions that carry their source's start report one.
    for (kind, condition, _) in &conditions {
        let dated = matches!(
            kind,
            AlertConditionKind::NodeUnreachable
                | AlertConditionKind::NodeRebootPending
                | AlertConditionKind::PendingApply
                | AlertConditionKind::OperatorHoldLong
        );
        assert_eq!(condition.source_since(), dated.then_some(t(0)), "{kind}");
    }
    assert_eq!(
        serde_json::to_string(&AlertConditionKind::MacSilent).unwrap(),
        "\"MacSilent\""
    );
    assert_eq!(
        serde_json::to_string(&AlertCondition::NodeDiskLow {
            node: node("lon1"),
            free_bytes: 1
        })
        .unwrap(),
        r#"{"node_disk_low":{"node":"lon1","free_bytes":1}}"#
    );
    assert!(
        serde_json::from_str::<AlertCondition>(r#"{"mac_silent":{"node":"lon1","user":"x"}}"#)
            .is_err()
    );
}

/// The severity table and holds of console spec B.4.
#[test]
fn severities_and_holds_follow_the_spec() {
    use AlertConditionKind as K;
    let timing = AlertTiming::DEFAULT;
    let critical = [
        K::ExitViolation,
        K::SimCapReached,
        K::RouterOffloadActive,
        K::RouterWifiRadioOn,
        K::RouterOverheating,
        K::RouterRestarted,
        K::NodeHalted,
        K::RollbackFailed,
        K::GateCloseFailed,
        K::EngineCrashLoop,
        K::HostKeyMismatch,
        K::MacSilent,
        K::NodeUnreachable,
        K::NodeDiskLow,
        K::AccountingCanaryMissing,
    ];
    for kind in AlertConditionKind::ALL {
        let expected = if critical.contains(kind) {
            Severity::Critical
        } else {
            Severity::Warning
        };
        assert_eq!(kind.severity(), expected, "{kind}");
        let hold = match kind {
            K::NodeUnreachable => 10 * MINUTE,
            _ if critical.contains(kind) => 0,
            K::RouterOnLte | K::RouterThermalStepDown | K::CapacitySaturated => 30 * MINUTE,
            K::NodeRebootPending | K::OperatorHoldLong => 24 * HOUR,
            K::PendingApply => 48 * HOUR,
            _ => 15 * MINUTE,
        };
        assert_eq!(kind.hold_secs(&timing), hold, "{kind}");
        assert_eq!(kind.once_per_subject(), *kind == K::SimForecastCrossing);
    }
    assert_eq!(timing.reminder_secs.get(), 6 * HOUR);
    assert_eq!(NODE_UNREACHABLE_HOLD_SECS, 10 * MINUTE);
    let names: BTreeSet<&str> = AlertConditionKind::ALL
        .iter()
        .map(|kind| kind.name())
        .collect();
    assert_eq!(names.len(), AlertConditionKind::ALL.len());
    assert_eq!(
        serde_json::to_string(&DegradedReasonKind::OnBattery).unwrap(),
        "\"OnBattery\""
    );
}

/// No condition can carry a user's identity or an address: the fixture
/// users' ids, labels and aliases and any dotted-quad address are absent
/// from every encoded condition and notice.
#[test]
fn alerts_carry_no_user_identity_and_no_address() {
    let deployment = deployment();
    let mut forbidden: Vec<String> = Vec::new();
    for user in deployment.users().values() {
        forbidden.push(user.id.as_str().to_owned());
        forbidden.push(user.label.as_str().to_owned());
        if let Some(alias) = &user.alias {
            forbidden.push(alias.as_str().to_owned());
        }
    }
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let active: Vec<AlertCondition> = every_condition()
        .into_iter()
        .map(|(_, condition, _)| condition)
        .collect();
    let mut texts: Vec<String> = active
        .iter()
        .map(|condition| serde_json::to_string(condition).unwrap())
        .collect();
    for step in [0, 16 * MINUTE, 49 * HOUR] {
        for notice in machine.step(t(step), active.clone()).unwrap() {
            texts.push(serde_json::to_string(&notice).unwrap());
        }
    }
    for notice in machine.step(t(50 * HOUR), Vec::new()).unwrap() {
        texts.push(serde_json::to_string(&notice).unwrap());
    }
    for text in &texts {
        for word in &forbidden {
            assert!(!text.contains(word.as_str()), "{text} names {word}");
        }
        assert!(!has_dotted_quad(text), "{text} holds an address");
    }
}

/// Whether `text` holds four dot-separated decimal numbers.
fn has_dotted_quad(text: &str) -> bool {
    let bytes = text.as_bytes();
    (0..bytes.len()).any(|start| {
        let mut index = start;
        for part in 0..4 {
            let digits = bytes[index..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 {
                return false;
            }
            index += digits;
            if part < 3 {
                if bytes.get(index) != Some(&b'.') {
                    return false;
                }
                index += 1;
            }
        }
        true
    })
}

#[test]
fn the_dotted_quad_scanner_finds_addresses() {
    assert!(has_dotted_quad(r#"{"ip":"31.120.0.7"}"#));
    assert!(!has_dotted_quad(r#"{"on":"2026-10-08","bytes":1.5}"#));
}

fn events(notices: &[AlertNotice]) -> Vec<(NoticeEvent, AlertConditionKind)> {
    notices
        .iter()
        .map(|notice| (notice.event, notice.condition.kind()))
        .collect()
}

#[test]
fn a_critical_alert_is_raised_at_once_reminded_every_six_hours_and_resolved() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let silent = AlertCondition::MacSilent { node: node("lon1") };
    let raised = machine.step(t(0), vec![silent.clone()]).unwrap();
    assert_eq!(
        events(&raised),
        [(NoticeEvent::Raised, AlertConditionKind::MacSilent)]
    );
    assert_eq!(raised[0].severity, Severity::Critical);
    assert_eq!(raised[0].active_since, t(0));
    assert_eq!(
        machine.step(t(6 * HOUR - 1), vec![silent.clone()]).unwrap(),
        Vec::new()
    );
    let reminder = machine.step(t(6 * HOUR), vec![silent.clone()]).unwrap();
    assert_eq!(
        events(&reminder),
        [(NoticeEvent::Reminder, AlertConditionKind::MacSilent)]
    );
    assert_eq!(reminder[0].active_since, t(0));
    assert_eq!(
        machine
            .step(t(12 * HOUR - 1), vec![silent.clone()])
            .unwrap(),
        Vec::new()
    );
    assert_eq!(
        machine
            .step(t(12 * HOUR), vec![silent.clone()])
            .unwrap()
            .len(),
        1
    );
    let open = machine.open();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].raised_at, t(0));
    let resolved = machine.step(t(13 * HOUR), Vec::new()).unwrap();
    assert_eq!(
        events(&resolved),
        [(NoticeEvent::Resolved, AlertConditionKind::MacSilent)]
    );
    assert!(machine.open().is_empty());
    assert_eq!(machine.step(t(14 * HOUR), Vec::new()).unwrap(), Vec::new());
}

#[test]
fn a_warning_waits_for_its_hold_and_is_dropped_if_it_clears_first() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let target = AlertCondition::TargetDegraded { node: node("ams1") };
    assert_eq!(
        machine.step(t(0), vec![target.clone()]).unwrap(),
        Vec::new()
    );
    assert_eq!(
        machine
            .step(t(15 * MINUTE - 1), vec![target.clone()])
            .unwrap(),
        Vec::new()
    );
    assert!(machine.open().is_empty(), "a pending warning is not open");
    // Cleared before the hold: never sent, and nothing to resolve.
    assert_eq!(
        machine.step(t(15 * MINUTE), Vec::new()).unwrap(),
        Vec::new()
    );
    // Back again: the hold restarts.
    assert_eq!(
        machine.step(t(20 * MINUTE), vec![target.clone()]).unwrap(),
        Vec::new()
    );
    assert_eq!(
        machine.step(t(34 * MINUTE), vec![target.clone()]).unwrap(),
        Vec::new()
    );
    let raised = machine.step(t(35 * MINUTE), vec![target.clone()]).unwrap();
    assert_eq!(
        events(&raised),
        [(NoticeEvent::Raised, AlertConditionKind::TargetDegraded)]
    );
    assert_eq!(raised[0].active_since, t(20 * MINUTE));
    // Warnings are not reminded.
    assert_eq!(
        machine.step(t(30 * HOUR), vec![target.clone()]).unwrap(),
        Vec::new()
    );
    let resolved = machine.step(t(31 * HOUR), Vec::new()).unwrap();
    assert_eq!(
        events(&resolved),
        [(NoticeEvent::Resolved, AlertConditionKind::TargetDegraded)]
    );
}

#[test]
fn longer_holds_apply_to_the_kinds_that_name_them() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let reboot = AlertCondition::NodeRebootPending {
        node: node("lon1"),
        since: t(0),
    };
    let lte = AlertCondition::RouterOnLte;
    let apply = AlertCondition::PendingApply {
        node: node("ams1"),
        since: t(0),
    };
    let all = || vec![reboot.clone(), lte.clone(), apply.clone()];
    assert_eq!(machine.step(t(0), all()).unwrap(), Vec::new());
    assert_eq!(machine.step(t(30 * MINUTE - 1), all()).unwrap(), Vec::new());
    assert_eq!(
        events(&machine.step(t(30 * MINUTE), all()).unwrap()),
        [(NoticeEvent::Raised, AlertConditionKind::RouterOnLte)]
    );
    assert_eq!(machine.step(t(24 * HOUR - 1), all()).unwrap(), Vec::new());
    assert_eq!(
        events(&machine.step(t(24 * HOUR), all()).unwrap()),
        [(NoticeEvent::Raised, AlertConditionKind::NodeRebootPending)]
    );
    assert_eq!(machine.step(t(48 * HOUR - 1), all()).unwrap(), Vec::new());
    assert_eq!(
        events(&machine.step(t(48 * HOUR), all()).unwrap()),
        [(NoticeEvent::Raised, AlertConditionKind::PendingApply)]
    );
}

#[test]
fn a_changed_payload_is_the_same_alert() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let disk = |free_bytes| AlertCondition::NodeDiskLow {
        node: node("lon1"),
        free_bytes,
    };
    assert_eq!(machine.step(t(0), vec![disk(900)]).unwrap().len(), 1);
    assert_eq!(
        machine.step(t(MINUTE), vec![disk(800)]).unwrap(),
        Vec::new()
    );
    assert_eq!(machine.open()[0].condition, disk(800));
    let reminder = machine.step(t(6 * HOUR), vec![disk(700)]).unwrap();
    assert_eq!(reminder[0].condition, disk(700));
    assert_eq!(reminder[0].active_since, t(0));
    // Another node is another alert.
    let other = AlertCondition::NodeDiskLow {
        node: node("ams1"),
        free_bytes: 1,
    };
    let raised = machine
        .step(t(6 * HOUR + 1), vec![disk(700), other.clone()])
        .unwrap();
    assert_eq!(raised.len(), 1);
    assert_eq!(raised[0].condition, other);
    let resolved = machine.step(t(7 * HOUR), vec![other]).unwrap();
    assert_eq!(
        resolved[0].condition,
        disk(700),
        "the resolution carries the last payload"
    );
}

#[test]
fn a_forecast_crossing_is_raised_once_per_cycle() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let crossing = |cycle: &str, on: &str| AlertCondition::SimForecastCrossing {
        cycle_start: date(cycle),
        threshold: SimThreshold::Warn,
        on: date(on),
    };
    let october = crossing("2026-10-01", "2026-10-25");
    machine.step(t(0), vec![october.clone()]).unwrap();
    assert_eq!(
        events(&machine.step(t(15 * MINUTE), vec![october.clone()]).unwrap()).len(),
        1
    );
    assert_eq!(
        events(&machine.step(t(HOUR), Vec::new()).unwrap()),
        [(
            NoticeEvent::Resolved,
            AlertConditionKind::SimForecastCrossing
        )]
    );
    // The same cycle again, with another projected day: never re-raised.
    let again = crossing("2026-10-01", "2026-10-26");
    for step in [2 * HOUR, 3 * HOUR, 30 * HOUR] {
        assert_eq!(
            machine.step(t(step), vec![again.clone()]).unwrap(),
            Vec::new()
        );
    }
    assert!(machine.open().is_empty());
    // Clearing a crossing that was never raised sends nothing.
    assert_eq!(machine.step(t(31 * HOUR), Vec::new()).unwrap(), Vec::new());
    // The next cycle is raised again.
    let november = crossing("2026-11-01", "2026-11-20");
    machine.step(t(40 * HOUR), vec![november.clone()]).unwrap();
    assert_eq!(
        machine
            .step(t(40 * HOUR + 15 * MINUTE), vec![november])
            .unwrap()
            .len(),
        1
    );
    // And October stays suppressed only until a newer cycle is remembered.
    let late_october = crossing("2026-10-01", "2026-10-30");
    machine
        .step(t(41 * HOUR), vec![late_october.clone()])
        .unwrap();
    assert_eq!(
        machine
            .step(t(41 * HOUR + 15 * MINUTE), vec![late_october])
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn refused_observations_change_nothing() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    machine
        .step(t(100), vec![AlertCondition::RouterRestarted])
        .unwrap();
    let before = machine.clone();
    assert_eq!(
        machine.step(t(99), Vec::new()),
        Err(AlertError::ClockWentBackwards {
            previous: t(100),
            now: t(99)
        })
    );
    let twice = vec![
        AlertCondition::RouterUnreadSms { count: 1 },
        AlertCondition::RouterUnreadSms { count: 2 },
    ];
    assert_eq!(
        machine.step(t(200), twice),
        Err(AlertError::DuplicateCondition {
            key: AlertKey {
                kind: AlertConditionKind::RouterUnreadSms,
                subject: AlertSubject::Router
            }
        })
    );
    assert_eq!(machine, before);
    // The same instant again is allowed.
    assert_eq!(
        machine
            .step(t(100), vec![AlertCondition::RouterRestarted])
            .unwrap(),
        Vec::new()
    );
}

#[test]
fn every_alert_error_kind_is_named_once() {
    let errors = [
        (
            AlertErrorKind::ClockWentBackwards,
            AlertError::ClockWentBackwards {
                previous: t(1),
                now: t(0),
            },
        ),
        (
            AlertErrorKind::DuplicateCondition,
            AlertError::DuplicateCondition {
                key: AlertKey {
                    kind: AlertConditionKind::CapacitySaturated,
                    subject: AlertSubject::Capacity,
                },
            },
        ),
    ];
    for (kind, error) in &errors {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        AlertErrorKind::ALL
    );
}

/// The conditions the property test draws from: two critical and three
/// warning kinds, one with a longer hold.
fn pool() -> Vec<AlertCondition> {
    vec![
        AlertCondition::MacSilent { node: node("lon1") },
        AlertCondition::RouterRestarted,
        AlertCondition::TargetDegraded { node: node("lon1") },
        AlertCondition::RouterOnLte,
        AlertCondition::UsersNearQuota { count: 1 },
    ]
}

proptest! {
    /// Over any sequence of observations: per key, Raised and Resolved
    /// alternate starting with Raised; a key is raised only after it has
    /// been active continuously for its hold; reminders are only for
    /// critical alerts, at least six hours apart; and the open alerts are
    /// exactly the keys raised and not resolved.
    #[test]
    fn notices_follow_the_rules(steps in proptest::collection::vec((1_u64..4 * HOUR, proptest::collection::vec(any::<bool>(), 5)), 1..80)) {
        let timing = AlertTiming::DEFAULT;
        let mut machine = AlertMachine::new(timing);
        let pool = pool();
        let mut now = 0;
        let mut active_since: BTreeMap<AlertKey, u64> = BTreeMap::new();
        let mut open: BTreeMap<AlertKey, u64> = BTreeMap::new();
        for (gap, on) in steps {
            now += gap;
            let active: Vec<AlertCondition> = pool.iter().zip(&on).filter(|(_, on)| **on).map(|(condition, _)| condition.clone()).collect();
            let keys: BTreeSet<AlertKey> = active.iter().map(AlertCondition::key).collect();
            active_since.retain(|key, _| keys.contains(key));
            for key in &keys {
                active_since.entry(key.clone()).or_insert(now);
            }
            for notice in machine.step(t(now), active).unwrap() {
                let key = notice.condition.key();
                match notice.event {
                    NoticeEvent::Raised => {
                        prop_assert!(!open.contains_key(&key));
                        prop_assert!(now - active_since[&key] >= key.kind.hold_secs(&timing));
                        prop_assert_eq!(notice.active_since, t(active_since[&key]));
                        open.insert(key, now);
                    }
                    NoticeEvent::Reminder => {
                        prop_assert_eq!(notice.severity, Severity::Critical);
                        let last = open[&key];
                        prop_assert!(now - last >= 6 * HOUR);
                        open.insert(key, now);
                    }
                    NoticeEvent::Resolved => {
                        prop_assert!(open.remove(&key).is_some());
                        prop_assert!(!keys.contains(&key));
                    }
                }
            }
            // A critical key active now is open; a warning past its hold is.
            for key in &keys {
                let due = now - active_since[key] >= key.kind.hold_secs(&timing);
                prop_assert_eq!(open.contains_key(key), due, "{}", key);
                if let Some(last) = open.get(key)
                    && key.kind.severity() == Severity::Critical
                {
                    prop_assert!(now - last < 6 * HOUR);
                }
            }
            let listed: BTreeSet<AlertKey> = machine.open().iter().map(|alert| alert.key()).collect();
            prop_assert_eq!(listed, open.keys().cloned().collect::<BTreeSet<_>>());
        }
    }
}

/// Conditions that hold at the same time are distinct alerts or one
/// alert's set, never a refused observation: both canaries of a node
/// (critique C-11's stats policy off), both engines on a node and on the
/// Mac, and two latched violations, beside an unrelated critical condition
/// on another node, are all raised; and one engine recovering resolves
/// only its own alert.
#[test]
fn simultaneous_conditions_never_collide() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let lon1 = node("lon1");
    let engine = |host: EngineHost| AlertCondition::EngineCrashLoop { host };
    let active = vec![
        AlertCondition::AccountingCanaryMissing {
            node: lon1.clone(),
            inbounds: InboundSet::of(Inbound::Reality).with(Inbound::Hy2),
        },
        engine(EngineHost::Node {
            node: lon1.clone(),
            engine: NodeEngine::Xray,
        }),
        engine(EngineHost::Node {
            node: lon1.clone(),
            engine: NodeEngine::Hy2,
        }),
        engine(EngineHost::Mac {
            engine: MacEngine::Exit,
        }),
        engine(EngineHost::Mac {
            engine: MacEngine::Probe,
        }),
        AlertCondition::ExitViolation {
            violations: set([
                ViolationKind::EgressMismatch,
                ViolationKind::EgressIsNodeAddress,
            ]),
        },
        AlertCondition::MacSilent { node: node("ams1") },
    ];
    let keys: BTreeSet<AlertKey> = active.iter().map(AlertCondition::key).collect();
    assert_eq!(keys.len(), active.len(), "every condition is its own alert");
    let raised = machine.step(t(0), active.clone()).unwrap();
    assert_eq!(raised.len(), active.len());
    for notice in &raised {
        assert_eq!(notice.event, NoticeEvent::Raised);
        assert_eq!(notice.severity, Severity::Critical);
    }
    assert_eq!(machine.open().len(), active.len());
    let mut fewer = active.clone();
    let recovered = fewer.remove(1);
    let resolved = machine.step(t(MINUTE), fewer).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].event, NoticeEvent::Resolved);
    assert_eq!(resolved[0].condition, recovered);
}

/// A condition that carries its source's start is held from that start,
/// so a daemon restart (a new machine) does not restart a long hold: a
/// pending apply 47 hours old and an operator hold set just under 24 hours
/// ago are both raised in the second a new machine sees them reach their
/// holds, each reporting its source's start.
#[test]
fn a_dated_condition_is_held_from_its_source_start_across_restarts() {
    let apply = AlertCondition::PendingApply {
        node: node("ams1"),
        since: t(0),
    };
    let hold = AlertCondition::OperatorHoldLong {
        node: node("lon1"),
        since: t(24 * HOUR),
    };
    let mut first = AlertMachine::new(AlertTiming::DEFAULT);
    assert_eq!(
        first.step(t(47 * HOUR), vec![apply.clone()]).unwrap(),
        Vec::new()
    );
    // The daemon restarts: a new machine sees the same conditions.
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let both = || vec![apply.clone(), hold.clone()];
    assert_eq!(machine.step(t(48 * HOUR - 1), both()).unwrap(), Vec::new());
    let raised = machine.step(t(48 * HOUR), both()).unwrap();
    assert_eq!(
        events(&raised),
        [
            (NoticeEvent::Raised, AlertConditionKind::PendingApply),
            (NoticeEvent::Raised, AlertConditionKind::OperatorHoldLong),
        ]
    );
    assert_eq!(raised[0].active_since, t(0));
    assert_eq!(raised[1].active_since, t(24 * HOUR));
    // A source start ahead of the Mac's clock counts as just started.
    let mut skewed = AlertMachine::new(AlertTiming::DEFAULT);
    let ahead = AlertCondition::NodeRebootPending {
        node: node("lon1"),
        since: t(10 * MINUTE),
    };
    assert_eq!(skewed.step(t(0), vec![ahead]).unwrap(), Vec::new());
}

/// One failed poll over the lossy uplink is not an outage: a node that
/// does not answer is raised, as a critical alert, only once it has failed
/// every poll for a whole poll interval from its first failure, and an
/// answer in between raises nothing.
#[test]
fn an_unreachable_node_is_raised_after_one_poll_interval() {
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    let since = t(0);
    let unreachable = AlertCondition::NodeUnreachable {
        node: node("lon1"),
        since,
    };
    assert_eq!(
        machine.step(t(0), vec![unreachable.clone()]).unwrap(),
        Vec::new()
    );
    // The node answered: nothing was raised, so nothing is resolved.
    assert_eq!(machine.step(t(5 * MINUTE), Vec::new()).unwrap(), Vec::new());
    let again = AlertCondition::NodeUnreachable {
        node: node("lon1"),
        since: t(6 * MINUTE),
    };
    assert_eq!(
        machine
            .step(t(16 * MINUTE - 1), vec![again.clone()])
            .unwrap(),
        Vec::new()
    );
    let raised = machine.step(t(16 * MINUTE), vec![again]).unwrap();
    assert_eq!(
        events(&raised),
        [(NoticeEvent::Raised, AlertConditionKind::NodeUnreachable)]
    );
    assert_eq!(raised[0].severity, Severity::Critical);
    assert_eq!(raised[0].active_since, t(6 * MINUTE));
}

/// Each degraded reason names its own kind, and the alerts the exit raises
/// are derived from its state: a degraded exit's alert names exactly the
/// kinds of its reasons, and the latches' alert exactly the kinds of the
/// latched violations, so neither can disagree with what the status shows.
#[test]
fn exit_alerts_are_derived_from_the_exit_state() {
    use std::net::Ipv4Addr;

    use mooring_model::collections::NonEmpty;
    use mooring_model::exit::ProbeProtocol;
    use mooring_model::verdict::Violation;

    use crate::status::{
        DegradedReason, EngineProcess, ExitSection, ExitState, Latch, MacEngines, PowerSource,
        PowerStatus, ProbeStage,
    };

    let reasons = [
        (
            DegradedReason::NodeProbeFailed {
                node: node("lon1"),
                protocol: ProbeProtocol::Reality,
                stage: ProbeStage::Connect,
            },
            DegradedReasonKind::NodeProbeFailed,
        ),
        (
            DegradedReason::ReachabilitySuspect { node: node("lon1") },
            DegradedReasonKind::ReachabilitySuspect,
        ),
        (
            DegradedReason::WatchStale { node: node("ams1") },
            DegradedReasonKind::WatchStale,
        ),
        (DegradedReason::OnBattery, DegradedReasonKind::OnBattery),
        (
            DegradedReason::PowerHelperExited,
            DegradedReasonKind::PowerHelperExited,
        ),
        (
            DegradedReason::OwnNetworksUnreadable {
                input: crate::status::OwnNetworkInput::RouterIdentities,
            },
            DegradedReasonKind::OwnNetworksUnreadable,
        ),
    ];
    for (reason, kind) in &reasons {
        assert_eq!(reason.kind(), *kind);
    }
    assert_eq!(
        reasons.iter().map(|(_, kind)| *kind).collect::<Vec<_>>(),
        DegradedReasonKind::ALL
    );
    let degraded = ExitState::Degraded {
        reasons: NonEmpty::from_parts(
            DegradedReason::WatchStale { node: node("lon1") },
            vec![
                DegradedReason::OnBattery,
                DegradedReason::WatchStale { node: node("ams1") },
            ],
        ),
    };
    assert_eq!(
        degraded.degraded_alert(),
        Some(AlertCondition::ExitDegraded {
            reasons: set([
                DegradedReasonKind::WatchStale,
                DegradedReasonKind::OnBattery
            ]),
        })
    );
    assert_eq!(ExitState::Paused.degraded_alert(), None);

    let process = EngineProcess {
        pid: None,
        restarts: 0,
        last_exit: None,
    };
    let latch = |violation| Latch {
        violation,
        at: t(0),
    };
    let mut exit = ExitSection {
        state: ExitState::Disabled,
        since: t(0),
        latches: Vec::new(),
        egress: None,
        carrier_check: None,
        engines: MacEngines {
            exit: process,
            probe: process,
        },
        power: PowerStatus {
            source: PowerSource::Ac,
            assertions_held: true,
            last_sleep: None,
            last_wake: None,
            last_drain: None,
        },
        foreign_networks: BTreeSet::new(),
        allowed_networks: BTreeSet::new(),
    };
    assert_eq!(exit.violation_alert(), None);
    let on_node = |name: &str| Violation::EgressIsNodeAddress {
        node: node(name),
        ip: Ipv4Addr::new(203, 0, 113, 10),
    };
    exit.latches = vec![
        latch(on_node("lon1")),
        latch(Violation::OutsideCarrierPrefixes {
            ip: Ipv4Addr::new(198, 51, 100, 7),
        }),
        latch(on_node("ams1")),
    ];
    assert_eq!(
        exit.violation_alert(),
        Some(AlertCondition::ExitViolation {
            violations: set([
                ViolationKind::EgressIsNodeAddress,
                ViolationKind::OutsideCarrierPrefixes,
            ]),
        })
    );
}
