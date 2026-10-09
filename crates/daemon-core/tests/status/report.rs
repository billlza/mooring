// SPDX-License-Identifier: GPL-3.0-or-later

//! The remote viewer's report projected from the scenarios (decision F5):
//! it round-trips, holds only closed names and ids, keeps the allowlisted
//! values (every arm of every mapping, exactly), leaves revoked users out,
//! and carries none of the status's addresses, router identifiers or
//! aliases, not even text shaped to fit the report's own grammars.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

use mooring_agent_proto::{
    ExitPhase, MacReportRule, MacReportV1, NodeName, ReportAccuracy, ReportBand, ReportBandNumber,
    ReportPlanLine, ReportRadio, ReportRadioAccess, ReportRadioSystem, ReportRouter,
    ReportSaturation, ReportSeverity, ReportUsage, ReportUserId, ReportUserStatus, ValueError,
};
use mooring_daemon_core::alert::Severity;
use mooring_daemon_core::capacity::Saturation;
use mooring_daemon_core::notify::digest_message;
use mooring_daemon_core::report::project;
use mooring_daemon_core::router::{
    Band, CarrierName, FirmwareVersion, RadioAccess, RadioState, RouterReading, Rsrp, Rsrq, Rssi,
    Signal, Sinr,
};
use mooring_daemon_core::status::{DegradedReason, DownReason, ExitState, ForecastView, UsageView};
use mooring_daemon_core::{
    ForeignNetworkFinding, MacStatusParts, MacStatusV1, ReportError, ReportErrorKind,
};
use mooring_model::collections::NonEmpty;
use mooring_model::iface::BsdName;
use mooring_model::sim::{PlanLine, PlanLineKind, SimThresholds, StopPolicy};
use mooring_model::user::{SuspendReason, UserStatus};
use mooring_model::{MacAddr, UnixTime, UserId};
use serde_json::Value;

use crate::scenarios;
use crate::support::GRAMMAR_SHAPED_LABEL;

fn scenario(name: &str) -> MacStatusParts {
    scenarios::all()
        .into_iter()
        .find(|(found, _)| *found == name)
        .unwrap()
        .1
        .into_parts()
}

fn report(parts: MacStatusParts) -> MacReportV1 {
    project(&MacStatusV1::new(parts).unwrap()).unwrap()
}

fn secs(time: UnixTime) -> u64 {
    time.as_secs()
}

/// Whether `text` is a closed-enum name as the report spells one: an ASCII
/// capital followed by ASCII letters.
fn is_closed_name(text: &str) -> bool {
    text.starts_with(|c: char| c.is_ascii_uppercase())
        && text.chars().all(|c| c.is_ascii_alphabetic())
}

/// Walks a report's JSON: the keys of `users` are report user ids, every
/// other key is a field name (`[a-z_]+`) or a variant tag, and every string
/// value is a closed name or a node name.
fn walk(value: &Value, in_users: bool, problems: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if !is_closed_name(text) && NodeName::new(text.as_str()).is_err() {
                problems.push(text.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, false, problems);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let key_ok = if in_users {
                    ReportUserId::new(key.as_str()).is_ok()
                } else {
                    is_closed_name(key) || key.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                };
                if !key_ok {
                    problems.push(key.clone());
                }
                walk(item, !in_users && key == "users", problems);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Each scenario projects to a report that decodes back as itself and
/// holds only closed names, report user ids and node names; its encoding
/// has no `.` or `@` at all, so no address or domain.
#[test]
fn every_scenario_projects_to_a_report_of_names_and_ids() {
    for (name, status) in scenarios::all() {
        let report = project(&status).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<MacReportV1>(&json).unwrap(),
            report,
            "{name}"
        );
        let mut problems = Vec::new();
        walk(
            &serde_json::to_value(&report).unwrap(),
            false,
            &mut problems,
        );
        assert_eq!(problems, Vec::<String>::new(), "{name}");
        assert!(!json.contains('.') && !json.contains('@'), "{name}: {json}");
    }
}

/// A serving exit's report keeps the exit, the SIM meter, the radio, the
/// capacity, the usage period and each user's figures, and nothing else of
/// them.
#[test]
fn the_serving_report_keeps_the_allowlisted_values() {
    let status = scenario("serving");
    let parts = report(status.clone()).into_parts();
    assert_eq!(parts.at.as_secs(), secs(status.at));
    assert_eq!(parts.exit.phase, ExitPhase::Serving);
    assert_eq!(parts.exit.since.as_secs(), secs(status.exit.since));

    let sim = &status.sim;
    assert_eq!(
        parts.sim.cycle_starts_at.as_secs(),
        secs(sim.cycle.starts_at())
    );
    assert_eq!(parts.sim.cycle_ends_at.as_secs(), secs(sim.cycle.ends_at()));
    assert_eq!(
        (parts.sim.rx_bytes, parts.sim.tx_bytes),
        (sim.rx_bytes, sim.tx_bytes)
    );
    assert_eq!(parts.sim.accuracy, ReportAccuracy::Exact);
    assert_eq!(parts.sim.warn_bytes, 240_000_000_000);
    assert_eq!(parts.sim.hard_stop_bytes, Some(300_000_000_000));
    // SMARTY's Unlimited plan has no line.
    assert_eq!(parts.sim.line, None);
    let ForecastView::Projected(forecast) = &sim.forecast else {
        panic!("the serving scenario has a forecast");
    };
    let reported = parts.sim.forecast.unwrap();
    assert_eq!(
        (reported.daily_average_bytes, reported.projected_bytes),
        (forecast.daily_average_bytes, forecast.projected_bytes)
    );

    let ReportRouter::Available {
        polled_at,
        radio,
        temperature_c,
    } = parts.router
    else {
        panic!("the serving scenario's router answered");
    };
    assert_eq!(temperature_c, 41);
    let RouterReading::Available(router) = &status.router else {
        panic!("the serving scenario's router answered");
    };
    assert_eq!(polled_at.as_secs(), secs(router.polled_at));
    assert!(polled_at.as_secs() < parts.at.as_secs());
    assert_eq!(
        radio,
        ReportRadio::Attached {
            access: ReportRadioAccess::NrNsa,
            band: ReportBand {
                system: ReportRadioSystem::Nr,
                number: ReportBandNumber::new(78).unwrap()
            },
            rsrp_tenths: Some(-985),
            rsrq_tenths: Some(-105),
            sinr_tenths: Some(124),
            rssi_tenths: None,
        }
    );

    let capacity = status.capacity.unwrap();
    let reported = parts.capacity.unwrap();
    assert_eq!(reported.at.as_secs(), secs(capacity.at));
    assert_eq!(
        (reported.tx_bps, reported.rx_bps),
        (capacity.tx_bps, capacity.rx_bps)
    );
    assert_eq!(reported.saturation, ReportSaturation::Clear);
    assert_eq!(capacity.saturation, Saturation::Clear);

    let UsageView::Report { periods } = status.usage else {
        panic!("the serving scenario has usage");
    };
    assert_eq!(
        parts.usage,
        ReportUsage::Available {
            through: mooring_agent_proto::UnixTime::from_secs(secs(periods.through))
        }
    );
    assert_eq!(parts.users.len(), status.users.len());
    for (id, row) in &status.users {
        let user = &parts.users[&ReportUserId::new(id.as_str()).unwrap()];
        assert_eq!(user.status, ReportUserStatus::Active);
        assert_eq!(user.cycle, Some(row.usage.as_ref().unwrap().cycle()));
        assert_eq!(
            user.last_seen.map(|time| time.as_secs()),
            row.activity.last_seen.map(secs)
        );
    }
    assert!(parts.alerts.is_empty());
}

/// A degraded exit's alerts keep their kind, severity, node and start, in
/// the status's order; a saturated uplink stays saturated since the same
/// time, and the LTE fallback is reported as LTE band 3 with its four
/// readings.
#[test]
fn the_degraded_report_keeps_each_alert() {
    let status = scenario("degraded");
    let parts = report(status.clone()).into_parts();
    assert_eq!(parts.exit.phase, ExitPhase::Degraded);
    let Saturation::Saturated { since } = status.capacity.unwrap().saturation else {
        panic!("the degraded scenario's uplink is saturated");
    };
    assert_eq!(
        parts.capacity.unwrap().saturation,
        ReportSaturation::Saturated {
            since: mooring_agent_proto::UnixTime::from_secs(secs(since))
        }
    );
    let ReportRouter::Available { radio, .. } = parts.router else {
        panic!("the degraded scenario's router answered");
    };
    assert_eq!(
        radio,
        ReportRadio::Attached {
            access: ReportRadioAccess::Lte,
            band: ReportBand {
                system: ReportRadioSystem::Lte,
                number: ReportBandNumber::new(3).unwrap()
            },
            rsrp_tenths: Some(-1125),
            rsrq_tenths: Some(-145),
            sinr_tenths: Some(-15),
            rssi_tenths: Some(-810),
        }
    );
    assert_eq!(parts.alerts.len(), status.alerts.len());
    let mut severities = BTreeSet::new();
    for (reported, open) in parts.alerts.iter().zip(&status.alerts) {
        let kind = open.condition.kind();
        assert_eq!(reported.kind.name(), kind.name());
        let severity = match kind.severity() {
            Severity::Critical => ReportSeverity::Critical,
            Severity::Warning => ReportSeverity::Warning,
        };
        assert_eq!(reported.severity, severity, "{kind}");
        severities.insert(reported.severity);
        assert_eq!(
            reported.node.as_ref().map(NodeName::as_str),
            open.condition.node().map(|node| node.as_str())
        );
        assert_eq!(reported.active_since.as_secs(), secs(open.active_since));
    }
    assert_eq!(
        severities,
        BTreeSet::from([ReportSeverity::Critical, ReportSeverity::Warning])
    );
    // Two suspended users are reported as suspended.
    let suspended = parts
        .users
        .values()
        .filter(|user| user.status == ReportUserStatus::Suspended)
        .count();
    assert_eq!(suspended, 2);
}

/// A down exit with the router unreachable, no capacity sample, no
/// forecast and no usage reports each as absent, never as zero.
#[test]
fn the_down_report_keeps_what_is_unavailable() {
    let status = scenario("down");
    let parts = report(status.clone()).into_parts();
    assert_eq!(parts.exit.phase, ExitPhase::Down);
    assert_eq!(parts.sim.accuracy, ReportAccuracy::LowerBound);
    assert_eq!(parts.sim.forecast, None);
    assert_eq!(parts.capacity, None);
    assert_eq!(parts.usage, ReportUsage::Unavailable);
    assert!(parts.users.values().all(|user| user.cycle.is_none()));
    let ReportRouter::Unavailable { last_polled_at } = parts.router else {
        panic!("the down scenario's router is unreachable");
    };
    let RouterReading::Unavailable {
        last_polled_at: expected,
        ..
    } = status.router
    else {
        panic!("the down scenario's router is unreachable");
    };
    assert_eq!(
        last_polled_at.map(|time| time.as_secs()),
        expected.map(secs)
    );
}

/// Every exit state reports its own phase, which the digest names too;
/// the table covers every phase once.
#[test]
fn every_exit_state_reports_its_own_phase() {
    let serving = scenario("serving");
    let states = [
        (ExitState::Disabled, ExitPhase::Disabled),
        (ExitState::Preflight, ExitPhase::Preflight),
        (ExitState::Starting, ExitPhase::Starting),
        (ExitState::Verifying, ExitPhase::Verifying),
        (
            ExitState::Serving {
                ip: Ipv4Addr::new(198, 51, 100, 17),
                verified_at: serving.at,
            },
            ExitPhase::Serving,
        ),
        (
            ExitState::Degraded {
                reasons: NonEmpty::from_parts(DegradedReason::OnBattery, Vec::new()),
            },
            ExitPhase::Degraded,
        ),
        (
            ExitState::Down {
                reason: DownReason::SecretsUnavailable,
            },
            ExitPhase::Down,
        ),
        (ExitState::Paused, ExitPhase::Paused),
    ];
    let phases: BTreeSet<ExitPhase> = states.iter().map(|(_, phase)| *phase).collect();
    assert_eq!(phases, ExitPhase::ALL.iter().copied().collect());
    for (state, phase) in states {
        let mut status = serving.clone();
        status.exit.state = state;
        let checked = MacStatusV1::new(status).unwrap();
        assert_eq!(project(&checked).unwrap().parts().exit.phase, phase);
        let digest = digest_message(&checked).unwrap();
        let first = digest.body.as_str().lines().next().unwrap();
        assert_eq!(
            first,
            format!("Exit {} since 2026-10-08 06:12 UTC", phase.name())
        );
    }
}

/// The serving status with the router attached as `radio`.
fn with_radio(radio: RadioState) -> MacStatusParts {
    let mut status = scenario("serving");
    let RouterReading::Available(router) = &mut status.router else {
        panic!("the serving scenario's router answered");
    };
    router.radio = radio;
    status
}

/// The serving status's radio attached through `access` on `band`, with
/// the four readings given in tenths.
fn attached(access: RadioAccess, band: &str, readings: [Option<i16>; 4]) -> RadioState {
    RadioState::Attached {
        access,
        band: Band::parse(band).unwrap(),
        carrier: CarrierName::parse("SMARTY").unwrap(),
        signal: Signal {
            rsrp: readings[0].map(|tenths| Rsrp::from_tenths(tenths).unwrap()),
            rsrq: readings[1].map(|tenths| Rsrq::from_tenths(tenths).unwrap()),
            sinr: readings[2].map(|tenths| Sinr::from_tenths(tenths).unwrap()),
            rssi: readings[3].map(|tenths| Rssi::from_tenths(tenths).unwrap()),
        },
    }
}

/// Every radio state, access technology and band system reports exactly:
/// no service; LTE, 5G NSA and 5G SA; an LTE and an NR band with their
/// numbers; each reading in its own slot, and an absent one absent.
#[test]
fn every_radio_reports_exactly() {
    let band = |system, number| ReportBand {
        system,
        number: ReportBandNumber::new(number).unwrap(),
    };
    let cases = [
        (RadioState::NoService, ReportRadio::NoService),
        (
            attached(RadioAccess::Lte, "B20", [Some(-1012), None, Some(31), None]),
            ReportRadio::Attached {
                access: ReportRadioAccess::Lte,
                band: band(ReportRadioSystem::Lte, 20),
                rsrp_tenths: Some(-1012),
                rsrq_tenths: None,
                sinr_tenths: Some(31),
                rssi_tenths: None,
            },
        ),
        (
            attached(
                RadioAccess::NrNsa,
                "B3",
                [None, Some(-118), None, Some(-702)],
            ),
            ReportRadio::Attached {
                access: ReportRadioAccess::NrNsa,
                band: band(ReportRadioSystem::Lte, 3),
                rsrp_tenths: None,
                rsrq_tenths: Some(-118),
                sinr_tenths: None,
                rssi_tenths: Some(-702),
            },
        ),
        (
            attached(
                RadioAccess::NrSa,
                "n78",
                [Some(-934), Some(-97), Some(205), Some(-655)],
            ),
            ReportRadio::Attached {
                access: ReportRadioAccess::NrSa,
                band: band(ReportRadioSystem::Nr, 78),
                rsrp_tenths: Some(-934),
                rsrq_tenths: Some(-97),
                sinr_tenths: Some(205),
                rssi_tenths: Some(-655),
            },
        ),
    ];
    for (radio, expected) in cases {
        let parts = report(with_radio(radio)).into_parts();
        let ReportRouter::Available { radio, .. } = parts.router else {
            panic!("the router answered");
        };
        assert_eq!(radio, expected);
    }
}

/// Every saturation state reports as itself, with the same since time.
#[test]
fn every_saturation_reports_with_its_since() {
    let base = scenario("serving");
    let at = |secs: u64| UnixTime::from_secs(base.at.as_secs() - secs);
    let wire = |time: UnixTime| mooring_agent_proto::UnixTime::from_secs(secs(time));
    for (saturation, expected) in [
        (Saturation::NoEvidence, ReportSaturation::NoEvidence),
        (Saturation::Clear, ReportSaturation::Clear),
        (
            Saturation::Building { since: at(300) },
            ReportSaturation::Building {
                since: wire(at(300)),
            },
        ),
        (
            Saturation::Saturated { since: at(1200) },
            ReportSaturation::Saturated {
                since: wire(at(1200)),
            },
        ),
    ] {
        let mut status = base.clone();
        status.capacity.as_mut().unwrap().saturation = saturation;
        let reported = report(status).into_parts().capacity.unwrap();
        assert_eq!(reported.saturation, expected);
    }
}

/// A plan's line reports with its kind and bytes: a fair-use line as
/// `FairUse`, an allowance as `Allowance`.
#[test]
fn every_plan_line_reports_with_its_kind() {
    let base = scenario("serving");
    let bytes = std::num::NonZeroU64::new(400_000_000_000).unwrap();
    for (kind, expected) in [
        (
            PlanLineKind::FairUse,
            ReportPlanLine::FairUse { bytes: bytes.get() },
        ),
        (
            PlanLineKind::Allowance,
            ReportPlanLine::Allowance { bytes: bytes.get() },
        ),
    ] {
        let mut status = base.clone();
        status.sim.thresholds = SimThresholds::new(
            240_000_000_000,
            StopPolicy::HardStop {
                bytes: 300_000_000_000,
            },
            Some(PlanLine { kind, bytes }),
        )
        .unwrap();
        let sim = report(status).into_parts().sim;
        assert_eq!(sim.line, Some(expected));
        assert_eq!(sim.hard_stop_bytes, Some(300_000_000_000));
    }
}

/// Text that fits the report's own grammars stays out all the same: the
/// projection, not the grammar, keeps it out. A carrier name shaped like
/// both a report user id and a node name, a firmware version shaped like a
/// node name, and an interface name shaped like one are planted in fields
/// the report drops, and none reaches it.
#[test]
fn grammar_shaped_text_in_dropped_fields_stays_out() {
    let (carrier, firmware, interface) = (GRAMMAR_SHAPED_LABEL, "phone", "phone0");
    assert!(ReportUserId::new(carrier).is_ok() && NodeName::new(carrier).is_ok());
    assert!(NodeName::new(firmware).is_ok() && NodeName::new(interface).is_ok());
    let mut status = with_radio(RadioState::NoService);
    let RouterReading::Available(router) = &mut status.router else {
        panic!("the serving scenario's router answered");
    };
    router.radio = attached(RadioAccess::NrNsa, "n78", [Some(-985), None, None, None]);
    let RadioState::Attached { carrier: name, .. } = &mut router.radio else {
        panic!("the radio is attached");
    };
    *name = CarrierName::parse(carrier).unwrap();
    router.firmware = FirmwareVersion::parse(firmware).unwrap();
    status.exit.egress.as_mut().unwrap().interface = BsdName::parse(interface).unwrap();
    let json = serde_json::to_string(&report(status)).unwrap();
    for canary in [carrier, firmware, interface] {
        assert!(
            !json.contains(canary),
            "the report holds {canary:?}: {json}"
        );
    }
}

/// A revoked user is left out; a suspended or revoking one keeps its
/// status.
#[test]
fn revoked_users_are_left_out() {
    let mut status = scenario("serving");
    let ids: Vec<UserId> = status.users.keys().cloned().collect();
    status.users.get_mut(&ids[0]).unwrap().status = UserStatus::Revoked;
    status.users.get_mut(&ids[1]).unwrap().status = UserStatus::Suspended {
        reason: SuspendReason::AbuseReview,
        since: status.at,
    };
    status.users.get_mut(&ids[2]).unwrap().status = UserStatus::RevokePending;
    let parts = report(status).into_parts();
    let reported: Vec<(&str, ReportUserStatus)> = parts
        .users
        .iter()
        .map(|(id, user)| (id.as_str(), user.status))
        .collect();
    assert_eq!(
        reported,
        [
            (ids[1].as_str(), ReportUserStatus::Suspended),
            (ids[2].as_str(), ReportUserStatus::RevokePending),
        ]
    );
}

/// The identifiers a status holds that the report must drop: every IPv4
/// address, link-layer address and interface name in it, the router's
/// carrier name and firmware, and the users' aliases. Labels never reach a
/// `MacStatusV1` (it has no field for one); every label of every fixture
/// deployment, and the grammar-shaped label the degraded scenario gives a
/// user, are scanned for all the same, so a status that ever gained one
/// would be caught leaking it.
fn identifiers(status: &MacStatusV1) -> Vec<String> {
    fn leaves(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::String(text) => found.push(text.clone()),
            Value::Array(items) => items.iter().for_each(|item| leaves(item, found)),
            Value::Object(map) => map.values().for_each(|item| leaves(item, found)),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    let mut strings = Vec::new();
    leaves(&serde_json::to_value(status).unwrap(), &mut strings);
    let mut words: Vec<String> = strings
        .into_iter()
        .filter(|text| Ipv4Addr::from_str(text).is_ok() || MacAddr::parse(text).is_ok())
        .collect();
    let parts = status.parts();
    // Interface names share their grammar with node ids, so they are taken
    // from where the status holds them.
    words.extend(
        parts
            .exit
            .egress
            .iter()
            .map(|egress| egress.interface.as_str().to_owned()),
    );
    for finding in &parts.exit.foreign_networks {
        let (ForeignNetworkFinding::RoutableIpv4 { interface }
        | ForeignNetworkFinding::GlobalIpv6 { interface }
        | ForeignNetworkFinding::DefaultRoute { interface, .. }
        | ForeignNetworkFinding::PersonalHotspot { interface }) = finding;
        words.push(interface.as_str().to_owned());
    }
    if let RouterReading::Available(router) = &parts.router {
        words.push(router.firmware.as_str().to_owned());
        if let RadioState::Attached { carrier, .. } = &router.radio {
            words.push(carrier.as_str().to_owned());
        }
    }
    words.extend(
        parts
            .users
            .values()
            .filter_map(|row| row.alias.as_ref())
            .map(|alias| alias.as_str().to_owned()),
    );
    for fixture in mooring_fixtures::all().unwrap() {
        let deployment = &fixture.deployment;
        words.extend(
            deployment
                .users()
                .values()
                .map(|user| user.label.as_str().to_owned()),
        );
        words.extend(
            deployment
                .viewers()
                .values()
                .map(|viewer| viewer.label.as_str().to_owned()),
        );
    }
    words.push(GRAMMAR_SHAPED_LABEL.to_owned());
    words
}

/// None of the status's addresses, interface names, router identifiers,
/// aliases or the fixtures' labels reaches the report; the statuses hold
/// each kind, so the check is not vacuous.
#[test]
fn no_identifier_of_the_status_reaches_the_report() {
    let mut seen = BTreeSet::new();
    for (name, status) in scenarios::all() {
        let words = identifiers(&status);
        for word in &words {
            if Ipv4Addr::from_str(word).is_ok() {
                seen.insert("ipv4");
            } else if MacAddr::parse(word).is_ok() {
                seen.insert("link-layer");
            }
        }
        if status.parts().exit.egress.is_some() {
            seen.insert("interface");
        }
        if status.parts().users.values().any(|row| row.alias.is_some()) {
            seen.insert("alias");
        }
        let json = serde_json::to_string(&project(&status).unwrap()).unwrap();
        for word in &words {
            assert!(
                !json.contains(word.as_str()),
                "{name}: the report holds {word:?}"
            );
        }
    }
    assert_eq!(
        seen,
        BTreeSet::from(["alias", "interface", "ipv4", "link-layer"])
    );
}

/// A status with more users than a report carries is refused, not
/// truncated.
#[test]
fn a_status_too_large_for_a_report_is_refused() {
    let mut status = scenario("serving");
    let row = status.users.values().next().unwrap().clone();
    status.users = (0..=1024_u64)
        .map(|bits| (UserId::from_low_bits(bits), row.clone()))
        .collect();
    let status = MacStatusV1::new(status).unwrap();
    let error = project(&status).unwrap_err();
    assert_eq!(
        error,
        ReportError::Wire(ValueError::MacReport {
            rule: MacReportRule::TooManyUsers
        })
    );
    assert_eq!(error.kind(), ReportErrorKind::Wire);
    assert!(!error.to_string().is_empty());
    assert_eq!(ReportErrorKind::ALL, [ReportErrorKind::Wire]);
}
