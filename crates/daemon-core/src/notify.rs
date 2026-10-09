// SPDX-License-Identifier: GPL-3.0-or-later

//! Push notices (design §15.8, decision F6, 2026-10-08): the ntfy messages
//! the Mac renders for a node to send, one per alert notice and one daily
//! digest.
//!
//! # Level 0 only
//!
//! A message holds node ids, counts, kinds, byte totals, dates and UTC
//! times, nothing else. [`alert_message`] reads an [`AlertNotice`], whose
//! condition has no field for a user, an address or any text
//! ([`crate::alert`]). [`digest_message`] reads a [`MacStatusV1`], which
//! does carry aliases, user ids and addresses, so it reads only
//! aggregates: the exit's phase, the SIM totals, counts of users, alerts and
//! nodes, and the cycle's served total. It names no node and no user. The
//! text must also pass agent-proto's notice grammar (no `.`, `@`, `_` or
//! non-ASCII character), which a renderer bug would break visibly: the
//! result is then an error, never a message.
//!
//! # Times and amounts
//!
//! Times are UTC minutes (`2026-10-12 08:15 UTC`): the core has no
//! time-zone database (see [`crate::period`]). Byte amounts are decimal and
//! rounded down to the largest unit they reach (`42 GB`), so they show one
//! to three digits.

use std::collections::BTreeSet;

use mooring_agent_proto::{NoticeBody, NoticeTitle, NtfyMessage, NtfyPriority, NtfyTag};
use mooring_model::date::SECS_PER_DAY;
use mooring_model::sim::StopPolicy;
use mooring_model::user::UserStatus;
use mooring_model::{CalendarDate, UnixTime};

use crate::alert::{
    AlertCondition, AlertConditionKind, AlertNotice, CriticalThermalLevel, NoticeEvent, Severity,
};
use crate::error::NotifyError;
use crate::forecast::{Crossing, SimThreshold};
use crate::report::exit_phase;
use crate::status::{ForecastView, MacStatusV1, MeterAccuracy, NodeAgentState, UsageView};

/// The ntfy message of one alert notice.
///
/// - Title: `Mooring {critical|warning} {raised|reminder}: {Kind}`, or
///   `Mooring resolved: {Kind}`.
/// - Body: the alert's key (`NodeHalted on lon1`); a line with the
///   condition's payload for the kinds that carry more than their key; and
///   `active since {time}`, or `cleared at {time}, active since {time}`.
/// - Priority and tag: a critical alert is raised at `Max` and reminded at
///   `High` with `RotatingLight`; a warning is `Default` with `Warning`; a
///   resolution is `Low` with `WhiteCheckMark`.
pub fn alert_message(notice: &AlertNotice) -> Result<NtfyMessage, NotifyError> {
    let kind = notice.condition.kind();
    let title = match notice.event {
        NoticeEvent::Resolved => format!("Mooring resolved: {kind}"),
        NoticeEvent::Raised | NoticeEvent::Reminder => {
            format!(
                "Mooring {} {}: {kind}",
                severity_word(notice.severity),
                event_word(notice.event)
            )
        }
    };
    let mut lines = vec![notice.condition.key().to_string()];
    lines.extend(payload(&notice.condition)?);
    let since = utc_minute(notice.active_since)?;
    lines.push(match notice.event {
        NoticeEvent::Raised | NoticeEvent::Reminder => format!("active since {since}"),
        NoticeEvent::Resolved => {
            format!(
                "cleared at {}, active since {since}",
                utc_minute(notice.at)?
            )
        }
    });
    let (priority, tag) = urgency(notice.severity, notice.event);
    message(title, &lines, priority, tag)
}

/// The daily digest of `status` (priority `Low`, tag `BarChart`).
///
/// - Title: `Mooring digest {UTC date of the status}`.
/// - Body, one line each: the exit's phase and since when; the SIM bytes
///   used against the hard stop (or, without one, the fair-use line), the
///   warning and the cycle's first day, marked `lower bound` when the meter
///   may miss bytes; the forecast and the first threshold projected to be
///   crossed; the users by status; the bytes served this cycle; the open
///   alerts by severity and kind; and the nodes behind the current
///   generation or unreachable, by count.
pub fn digest_message(status: &MacStatusV1) -> Result<NtfyMessage, NotifyError> {
    let parts = status.parts();
    let title = format!("Mooring digest {}", CalendarDate::utc_of(parts.at)?);
    let lines = [
        format!(
            "Exit {} since {}",
            exit_phase(&parts.exit.state).name(),
            utc_minute(parts.exit.since)?
        ),
        sim_line(status),
        forecast_line(&parts.sim.forecast),
        users_line(status),
        served_line(status),
        alerts_line(status),
        nodes_line(status),
    ];
    message(title, &lines, NtfyPriority::Low, NtfyTag::BarChart)
}

fn message(
    title: String,
    lines: &[String],
    priority: NtfyPriority,
    tag: NtfyTag,
) -> Result<NtfyMessage, NotifyError> {
    Ok(NtfyMessage {
        title: NoticeTitle::new(title)?,
        body: NoticeBody::new(lines.join("\n"))?,
        priority,
        tag,
    })
}

const fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
    }
}

const fn event_word(event: NoticeEvent) -> &'static str {
    match event {
        NoticeEvent::Raised => "raised",
        NoticeEvent::Reminder => "reminder",
        NoticeEvent::Resolved => "resolved",
    }
}

/// The priority and tag of a notice. The machine never reminds a warning;
/// one would be sent like a raised warning.
const fn urgency(severity: Severity, event: NoticeEvent) -> (NtfyPriority, NtfyTag) {
    match (severity, event) {
        (_, NoticeEvent::Resolved) => (NtfyPriority::Low, NtfyTag::WhiteCheckMark),
        (Severity::Critical, NoticeEvent::Raised) => (NtfyPriority::Max, NtfyTag::RotatingLight),
        (Severity::Critical, NoticeEvent::Reminder) => (NtfyPriority::High, NtfyTag::RotatingLight),
        (Severity::Warning, NoticeEvent::Raised | NoticeEvent::Reminder) => {
            (NtfyPriority::Default, NtfyTag::Warning)
        }
    }
}

/// The line a condition's payload adds to its key, for the kinds that
/// carry more than the key says.
fn payload(condition: &AlertCondition) -> Result<Option<String>, NotifyError> {
    Ok(Some(match condition {
        AlertCondition::ExitViolation { violations } => format!(
            "violations: {}",
            names(violations.iter().map(|kind| kind.name()))
        ),
        AlertCondition::ExitDegraded { reasons } => {
            format!("reasons: {}", names(reasons.iter().map(|kind| kind.name())))
        }
        AlertCondition::SimForecastCrossing { threshold, on, .. } => {
            format!("{} projected on {on}", threshold_name(*threshold))
        }
        AlertCondition::RouterOverheating { level } => format!(
            "thermal level {}",
            match level {
                CriticalThermalLevel::Level2 => 2,
                CriticalThermalLevel::Level3 => 3,
            }
        ),
        // Whole dBm rounded down, never above the reading: the grammar has
        // no `.` for tenths, and truncation would show -110.9 as -110.
        AlertCondition::RouterWeakSignal { rsrp_dbm_x10 } => {
            format!("RSRP {} dBm", rsrp_dbm_x10.div_euclid(10))
        }
        AlertCondition::RouterUnreadSms { count }
        | AlertCondition::UsersNearQuota { count }
        | AlertCondition::UsersOverQuota { count }
        | AlertCondition::UsersSuspended { count }
        | AlertCondition::UsersExpiringSoon { count }
        | AlertCondition::UsersExpired { count } => format!("count: {count}"),
        AlertCondition::ForeignNetworkAttached { findings } => format!("findings: {findings}"),
        AlertCondition::RouterCounterMismatch { permille } => {
            format!("difference {permille} permille")
        }
        AlertCondition::ExitFlowCapHit { count, .. } => format!("flows rejected: {count}"),
        AlertCondition::NodeDiskLow { free_bytes, .. } => {
            format!("free {}", amount(u128::from(*free_bytes)))
        }
        AlertCondition::NodeUnreachable { since, .. }
        | AlertCondition::NodeRebootPending { since, .. }
        | AlertCondition::PendingApply { since, .. }
        | AlertCondition::OperatorHoldLong { since, .. } => {
            format!("since {}", utc_minute(*since)?)
        }
        AlertCondition::AccountingCanaryMissing { inbounds, .. } => {
            format!("inbounds: {inbounds}")
        }
        AlertCondition::SimCapReached { .. }
        | AlertCondition::RouterOffloadActive
        | AlertCondition::RouterWifiRadioOn
        | AlertCondition::RouterRestarted
        | AlertCondition::NodeHalted { .. }
        | AlertCondition::RollbackFailed { .. }
        | AlertCondition::GateCloseFailed { .. }
        | AlertCondition::EngineCrashLoop { .. }
        | AlertCondition::HostKeyMismatch { .. }
        | AlertCondition::MacSilent { .. }
        | AlertCondition::SimWarn { .. }
        | AlertCondition::ReachabilitySuspect { .. }
        | AlertCondition::TargetDegraded { .. }
        | AlertCondition::RouterNoService
        | AlertCondition::RouterOnLte
        | AlertCondition::RouterThermalStepDown
        | AlertCondition::RouterFirmwareChanged
        | AlertCondition::CapacitySaturated
        | AlertCondition::NodeClockUnsynced { .. } => return Ok(None),
    }))
}

const fn threshold_name(threshold: SimThreshold) -> &'static str {
    match threshold {
        SimThreshold::Warn => "Warn",
        SimThreshold::HardStop => "HardStop",
        SimThreshold::FairUse => "FairUse",
        SimThreshold::Allowance => "Allowance",
    }
}

fn names<'a>(names: impl Iterator<Item = &'a str>) -> String {
    names.collect::<Vec<_>>().join(", ")
}

fn sim_line(status: &MacStatusV1) -> String {
    let sim = &status.parts().sim;
    let used = u128::from(sim.rx_bytes) + u128::from(sim.tx_bytes);
    let limit = match sim.thresholds.stop() {
        StopPolicy::HardStop { bytes } => format!("of {}", amount(u128::from(bytes))),
        // Without a hard stop the budget is the fair-use line (the model's
        // `SimThresholds` invariant).
        StopPolicy::AcceptDeprioritisation => format!(
            "with no hard stop, fair-use line {}",
            amount(u128::from(sim.thresholds.budget_bytes()))
        ),
    };
    let mut line = format!(
        "SIM {} used {limit}, warning at {}, cycle from {}",
        amount(used),
        amount(u128::from(sim.thresholds.warn_bytes())),
        sim.cycle.start()
    );
    match sim.accuracy {
        MeterAccuracy::Exact => {}
        MeterAccuracy::LowerBound => line.push_str(", lower bound"),
    }
    line
}

fn forecast_line(forecast: &ForecastView) -> String {
    let ForecastView::Projected(forecast) = forecast else {
        return "Forecast unavailable".to_owned();
    };
    let mut line = format!(
        "Forecast {} by {}",
        amount(u128::from(forecast.projected_bytes)),
        forecast.cycle.next_start()
    );
    let first_projected = forecast
        .crossings
        .iter()
        .find_map(|crossing| match crossing.crossing {
            Crossing::Projected { on } => Some((crossing.threshold, on)),
            Crossing::Reached { .. } | Crossing::NotThisCycle => None,
        });
    if let Some((threshold, on)) = first_projected {
        line.push_str(&format!(
            "; {} projected on {on}",
            threshold_name(threshold)
        ));
    }
    line
}

fn users_line(status: &MacStatusV1) -> String {
    let (mut active, mut suspended, mut revoking) = (0_usize, 0_usize, 0_usize);
    for row in status.parts().users.values() {
        match row.status {
            UserStatus::Active => active += 1,
            UserStatus::Suspended { .. } => suspended += 1,
            UserStatus::RevokePending => revoking += 1,
            UserStatus::Revoked => {}
        }
    }
    format!("Users {active} active, {suspended} suspended, {revoking} revoking")
}

fn served_line(status: &MacStatusV1) -> String {
    let parts = status.parts();
    match parts.usage {
        UsageView::Report { .. } => {
            let served: u128 = parts
                .users
                .values()
                .filter_map(|row| row.usage.as_ref())
                .map(|usage| u128::from(usage.cycle_served_bytes()))
                .sum();
            format!("Served this cycle {}", amount(served))
        }
        UsageView::Unavailable { .. } => "Served this cycle unavailable".to_owned(),
    }
}

fn alerts_line(status: &MacStatusV1) -> String {
    let alerts = &status.parts().alerts;
    let severity = |wanted: Severity| {
        alerts
            .iter()
            .filter(|alert| alert.condition.severity() == wanted)
            .count()
    };
    let mut line = format!(
        "Alerts {} critical, {} warning",
        severity(Severity::Critical),
        severity(Severity::Warning)
    );
    let kinds: BTreeSet<AlertConditionKind> =
        alerts.iter().map(|alert| alert.condition.kind()).collect();
    if !kinds.is_empty() {
        line.push_str(": ");
        line.push_str(&names(kinds.iter().map(|kind| kind.name())));
    }
    line
}

fn nodes_line(status: &MacStatusV1) -> String {
    let nodes = &status.parts().nodes;
    let behind = nodes
        .values()
        .filter(|row| row.pending_apply_since.is_some())
        .count();
    let unreachable = nodes
        .values()
        .filter(|row| matches!(row.agent, NodeAgentState::Unreachable { .. }))
        .count();
    format!(
        "Nodes {}: {behind} behind, {unreachable} unreachable",
        nodes.len()
    )
}

/// `2026-10-12 08:15 UTC`: the UTC minute of `time`, rounded down.
fn utc_minute(time: UnixTime) -> Result<String, NotifyError> {
    let date = CalendarDate::utc_of(time)?;
    let secs = time.as_secs() % SECS_PER_DAY;
    Ok(format!(
        "{date} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    ))
}

/// The decimal units an amount is shown in.
const UNITS: [&str; 7] = ["B", "kB", "MB", "GB", "TB", "PB", "EB"];

/// `bytes` in the largest decimal unit it reaches, rounded down: `0 B`,
/// `999 B`, `1 kB`, `42 GB`. Below 1000 EB that is one to three digits.
fn amount(bytes: u128) -> String {
    let mut unit = 0;
    let mut scale: u128 = 1;
    while unit + 1 < UNITS.len() && bytes >= scale * 1000 {
        scale *= 1000;
        unit += 1;
    }
    format!("{} {}", bytes / scale, UNITS[unit])
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn amounts_round_down_to_the_largest_unit_reached() {
        for (bytes, text) in [
            (0, "0 B"),
            (999, "999 B"),
            (1000, "1 kB"),
            (999_999, "999 kB"),
            (1_000_000, "1 MB"),
            (42_999_999_999, "42 GB"),
            (300_000_000_000, "300 GB"),
            (1_000_000_000_000, "1 TB"),
            (u128::from(u64::MAX), "18 EB"),
            (2 * u128::from(u64::MAX), "36 EB"),
        ] {
            assert_eq!(amount(bytes), text, "{bytes}");
        }
    }

    #[test]
    fn times_are_utc_minutes_rounded_down() {
        let day = CalendarDate::parse("2026-10-12").unwrap().utc_start();
        let at = |secs| UnixTime::from_secs(day.as_secs() + secs);
        assert_eq!(utc_minute(at(0)).unwrap(), "2026-10-12 00:00 UTC");
        assert_eq!(
            utc_minute(at(8 * 3600 + 15 * 60 + 59)).unwrap(),
            "2026-10-12 08:15 UTC"
        );
        assert_eq!(utc_minute(at(86_399)).unwrap(), "2026-10-12 23:59 UTC");
        assert_eq!(
            utc_minute(UnixTime::from_secs(u64::MAX)),
            Err(NotifyError::Model(mooring_model::ModelError::InvalidDate))
        );
    }

    proptest! {
        /// An amount names a unit and one to three digits for any value a
        /// counter can hold, and never more than the bytes.
        #[test]
        fn amounts_have_one_to_three_digits(bytes in any::<u64>()) {
            let text = amount(u128::from(bytes));
            let (number, unit) = text.split_once(' ').unwrap();
            prop_assert!((1..=3).contains(&number.len()), "{text}");
            let index = UNITS.iter().position(|known| *known == unit).unwrap();
            let shown = number.parse::<u128>().unwrap() * 1000_u128.pow(u32::try_from(index).unwrap());
            prop_assert!(shown <= u128::from(bytes));
            prop_assert!(u128::from(bytes) < (number.parse::<u128>().unwrap() + 1) * 1000_u128.pow(u32::try_from(index).unwrap()));
        }
    }
}
