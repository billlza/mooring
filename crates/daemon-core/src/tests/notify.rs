// SPDX-License-Identifier: GPL-3.0-or-later

//! The ntfy rendering of alert notices (decision F6): every condition
//! renders for every event within the notice grammar, the urgency follows
//! the severity and the event, and representative texts are pinned.

use std::collections::BTreeSet;

use mooring_agent_proto::{
    Inbound, InboundSet, NoticeBody, NoticeTitle, NtfyMessage, NtfyPriority, NtfyTag,
};
use mooring_model::verdict::ViolationKind;
use mooring_model::{ModelError, NonEmptySet, UnixTime};

use super::alerts::every_condition;
use super::support::{at, date, node};
use crate::alert::{
    AlertCondition, AlertConditionKind, AlertNotice, DegradedReasonKind, EngineHost, MacEngine,
    NoticeEvent, Severity,
};
use crate::error::{NotifyError, NotifyErrorKind};
use crate::forecast::SimThreshold;
use crate::notify::alert_message;

const EVENTS: [NoticeEvent; 3] = [
    NoticeEvent::Raised,
    NoticeEvent::Reminder,
    NoticeEvent::Resolved,
];

fn set<T: Ord>(items: impl IntoIterator<Item = T>) -> NonEmptySet<T> {
    NonEmptySet::try_from(items.into_iter().collect::<BTreeSet<T>>()).unwrap()
}

fn notice(condition: AlertCondition, event: NoticeEvent) -> AlertNotice {
    AlertNotice {
        at: at("2026-10-12", 9 * 3600 + 40 * 60 + 7),
        event,
        severity: condition.severity(),
        condition,
        active_since: at("2026-10-12", 8 * 3600 + 15 * 60 + 59),
    }
}

/// The kinds whose condition carries more than its key, so their body has
/// a payload line.
fn has_payload(kind: AlertConditionKind) -> bool {
    use AlertConditionKind as K;
    matches!(
        kind,
        K::ExitViolation
            | K::ExitDegraded
            | K::SimForecastCrossing
            | K::RouterOverheating
            | K::RouterWeakSignal
            | K::RouterUnreadSms
            | K::UsersNearQuota
            | K::UsersOverQuota
            | K::UsersSuspended
            | K::UsersExpiringSoon
            | K::UsersExpired
            | K::ForeignNetworkAttached
            | K::RouterCounterMismatch
            | K::ExitFlowCapHit
            | K::NodeDiskLow
            | K::NodeUnreachable
            | K::NodeRebootPending
            | K::PendingApply
            | K::OperatorHoldLong
            | K::AccountingCanaryMissing
    )
}

/// Every condition, for every event: the message renders the same each
/// time, decodes back as itself (so its title and body pass the notice
/// grammar on receipt), names its kind in the title and its key on the
/// first line, carries a payload line exactly for the kinds with one, ends
/// with the times, and has the urgency of its severity and event.
#[test]
fn every_condition_renders_for_every_event() {
    let conditions = every_condition();
    assert_eq!(conditions.len(), AlertConditionKind::ALL.len());
    for (kind, condition, _) in conditions {
        for event in EVENTS {
            let notice = notice(condition.clone(), event);
            let message = alert_message(&notice).unwrap();
            assert_eq!(alert_message(&notice).unwrap(), message);
            let json = serde_json::to_string(&message).unwrap();
            assert_eq!(serde_json::from_str::<NtfyMessage>(&json).unwrap(), message);
            let severity = match kind.severity() {
                Severity::Critical => "critical",
                Severity::Warning => "warning",
            };
            let title = match event {
                NoticeEvent::Raised => format!("Mooring {severity} raised: {kind}"),
                NoticeEvent::Reminder => format!("Mooring {severity} reminder: {kind}"),
                NoticeEvent::Resolved => format!("Mooring resolved: {kind}"),
            };
            assert_eq!(message.title.as_str(), title);
            let lines: Vec<&str> = message.body.as_str().lines().collect();
            assert_eq!(lines[0], condition.key().to_string());
            assert_eq!(lines.len(), if has_payload(kind) { 3 } else { 2 }, "{kind}");
            let last = match event {
                NoticeEvent::Raised | NoticeEvent::Reminder => "active since 2026-10-12 08:15 UTC",
                NoticeEvent::Resolved => {
                    "cleared at 2026-10-12 09:40 UTC, active since 2026-10-12 08:15 UTC"
                }
            };
            assert_eq!(lines.last(), Some(&last));
            let urgency = match (kind.severity(), event) {
                (_, NoticeEvent::Resolved) => (NtfyPriority::Low, NtfyTag::WhiteCheckMark),
                (Severity::Critical, NoticeEvent::Raised) => {
                    (NtfyPriority::Max, NtfyTag::RotatingLight)
                }
                (Severity::Critical, NoticeEvent::Reminder) => {
                    (NtfyPriority::High, NtfyTag::RotatingLight)
                }
                (Severity::Warning, _) => (NtfyPriority::Default, NtfyTag::Warning),
            };
            assert_eq!((message.priority, message.tag), urgency, "{kind} {event:?}");
        }
    }
}

fn expect(
    condition: AlertCondition,
    event: NoticeEvent,
    title: &str,
    body: &str,
    priority: NtfyPriority,
    tag: NtfyTag,
) {
    assert_eq!(
        alert_message(&notice(condition, event)),
        Ok(NtfyMessage {
            title: NoticeTitle::new(title).unwrap(),
            body: NoticeBody::new(body).unwrap(),
            priority,
            tag,
        })
    );
}

/// The exact text of representative notices, one per payload shape.
#[test]
fn representative_notices_have_exact_texts() {
    expect(
        AlertCondition::NodeHalted { node: node("lon1") },
        NoticeEvent::Raised,
        "Mooring critical raised: NodeHalted",
        "NodeHalted on lon1\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::Max,
        NtfyTag::RotatingLight,
    );
    expect(
        AlertCondition::ExitViolation {
            violations: set([
                ViolationKind::EgressMismatch,
                ViolationKind::OutsideCarrierPrefixes,
            ]),
        },
        NoticeEvent::Reminder,
        "Mooring critical reminder: ExitViolation",
        "ExitViolation on the exit\nviolations: OutsideCarrierPrefixes, EgressMismatch\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::High,
        NtfyTag::RotatingLight,
    );
    expect(
        AlertCondition::SimForecastCrossing {
            cycle_start: date("2026-10-12"),
            threshold: SimThreshold::HardStop,
            on: date("2026-11-03"),
        },
        NoticeEvent::Raised,
        "Mooring warning raised: SimForecastCrossing",
        "SimForecastCrossing in the cycle from 2026-10-12\nHardStop projected on 2026-11-03\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::Default,
        NtfyTag::Warning,
    );
    expect(
        AlertCondition::RouterWeakSignal {
            rsrp_dbm_x10: -1125,
        },
        NoticeEvent::Resolved,
        "Mooring resolved: RouterWeakSignal",
        "RouterWeakSignal on the router\nRSRP -113 dBm\ncleared at 2026-10-12 09:40 UTC, active since 2026-10-12 08:15 UTC",
        NtfyPriority::Low,
        NtfyTag::WhiteCheckMark,
    );
    expect(
        AlertCondition::NodeDiskLow {
            node: node("ams1"),
            free_bytes: 734_003_200,
        },
        NoticeEvent::Raised,
        "Mooring critical raised: NodeDiskLow",
        "NodeDiskLow on ams1\nfree 734 MB\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::Max,
        NtfyTag::RotatingLight,
    );
    expect(
        AlertCondition::AccountingCanaryMissing {
            node: node("lon1"),
            inbounds: InboundSet::of(Inbound::Reality).with(Inbound::Hy2),
        },
        NoticeEvent::Raised,
        "Mooring critical raised: AccountingCanaryMissing",
        "AccountingCanaryMissing on lon1\ninbounds: reality, hy2\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::Max,
        NtfyTag::RotatingLight,
    );
    expect(
        AlertCondition::ExitDegraded {
            reasons: set([
                DegradedReasonKind::OnBattery,
                DegradedReasonKind::WatchStale,
            ]),
        },
        NoticeEvent::Raised,
        "Mooring warning raised: ExitDegraded",
        "ExitDegraded on the exit\nreasons: WatchStale, OnBattery\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::Default,
        NtfyTag::Warning,
    );
    expect(
        AlertCondition::PendingApply {
            node: node("ams1"),
            since: at("2026-10-10", 9 * 3600 + 5 * 60),
        },
        NoticeEvent::Raised,
        "Mooring warning raised: PendingApply",
        "PendingApply on ams1\nsince 2026-10-10 09:05 UTC\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::Default,
        NtfyTag::Warning,
    );
    expect(
        AlertCondition::EngineCrashLoop {
            host: EngineHost::Mac {
                engine: MacEngine::Exit,
            },
        },
        NoticeEvent::Raised,
        "Mooring critical raised: EngineCrashLoop",
        "EngineCrashLoop of mooring-exit on the Mac\nactive since 2026-10-12 08:15 UTC",
        NtfyPriority::Max,
        NtfyTag::RotatingLight,
    );
}

/// The RSRP of a weak-signal notice is shown in whole dBm rounded down
/// (toward minus infinity), so the figure is never above the reading, and
/// a reading just below the alert's -110 dBm never shows as -110.
#[test]
fn a_weak_signal_shows_its_rsrp_rounded_down() {
    for (tenths, shown) in [
        (-1101, "-111"),
        (-1109, "-111"),
        (-1110, "-111"),
        (-1111, "-112"),
        (-1125, "-113"),
        (-1560, "-156"),
        (-5, "-1"),
        (0, "0"),
    ] {
        let message = alert_message(&notice(
            AlertCondition::RouterWeakSignal {
                rsrp_dbm_x10: tenths,
            },
            NoticeEvent::Raised,
        ))
        .unwrap();
        let payload = message.body.as_str().lines().nth(1).unwrap();
        assert_eq!(payload, format!("RSRP {shown} dBm"), "{tenths}");
    }
}

/// A time past the calendar is refused, not rendered.
#[test]
fn a_time_past_the_calendar_is_refused() {
    let mut late = notice(
        AlertCondition::NodeHalted { node: node("lon1") },
        NoticeEvent::Resolved,
    );
    late.at = UnixTime::from_secs(u64::MAX);
    assert_eq!(
        alert_message(&late),
        Err(NotifyError::Model(ModelError::InvalidDate))
    );
}

#[test]
fn every_notify_error_kind_is_named_once() {
    let errors = [
        (
            NotifyErrorKind::Text,
            NotifyError::Text(mooring_agent_proto::ValueError::NoticeBody),
        ),
        (
            NotifyErrorKind::Model,
            NotifyError::Model(ModelError::InvalidDate),
        ),
    ];
    for (kind, error) in &errors {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        NotifyErrorKind::ALL
    );
}
