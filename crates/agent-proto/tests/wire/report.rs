// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac report (design §15.9, decision F5): its rules, and that no free
//! text fits it. Every string in it is a closed name, a report user id or
//! a node name, so an address, a domain, a label written with a space or in
//! another script, an IMEI or an ICCID written as text, and an SMS text are
//! refused in every string slot, and a number above 999 in the band slot.
//! A lowercase one-word string and a small number do fit some slots; the
//! projection that builds the report keeps those out, and
//! `mooring-daemon-core`'s report tests check it.

use std::collections::{BTreeMap, BTreeSet};

use mooring_agent_proto::{
    ExitPhase, MAX_REPORT_ALERTS, MAX_REPORT_USERS, MacAlertKind, MacReportParts, MacReportRule,
    MacReportV1, NodeName, ReportAccuracy, ReportAlert, ReportBand, ReportBandNumber,
    ReportCapacity, ReportExit, ReportForecast, ReportPlanLine, ReportRadio, ReportRadioAccess,
    ReportRadioSystem, ReportRouter, ReportSaturation, ReportSeverity, ReportSim, ReportUsage,
    ReportUser, ReportUserId, ReportUserStatus, StoredMacReport, Traffic, UnixTime, ValueError,
};
use proptest::collection::{btree_map, vec};
use proptest::option;
use proptest::prelude::*;
use proptest::sample::select;
use serde_json::Value;

use crate::fixtures;

// ---- strategies ----------------------------------------------------------

fn time() -> impl Strategy<Value = UnixTime> {
    any::<u64>().prop_map(UnixTime::from_secs)
}

fn report_user_id() -> impl Strategy<Value = ReportUserId> {
    "[a-z2-7]{10}".prop_map(|text| ReportUserId::new(text).unwrap())
}

fn node_name() -> impl Strategy<Value = NodeName> {
    "[a-z][a-z0-9]{1,11}".prop_map(|text| NodeName::new(text).unwrap())
}

fn traffic() -> impl Strategy<Value = Traffic> {
    (any::<u64>(), any::<u64>()).prop_map(|(uplink, downlink)| Traffic { uplink, downlink })
}

fn sim() -> impl Strategy<Value = ReportSim> {
    let line = option::of(prop_oneof![
        any::<u64>().prop_map(|bytes| ReportPlanLine::FairUse { bytes }),
        any::<u64>().prop_map(|bytes| ReportPlanLine::Allowance { bytes }),
    ]);
    let forecast = option::of((any::<u64>(), any::<u64>()).prop_map(
        |(daily_average_bytes, projected_bytes)| ReportForecast {
            daily_average_bytes,
            projected_bytes,
        },
    ));
    (
        time(),
        time(),
        any::<u64>(),
        any::<u64>(),
        select(ReportAccuracy::ALL),
        any::<u64>(),
        option::of(any::<u64>()),
        line,
        forecast,
    )
        .prop_map(
            |(
                cycle_starts_at,
                cycle_ends_at,
                rx_bytes,
                tx_bytes,
                accuracy,
                warn_bytes,
                hard_stop_bytes,
                line,
                forecast,
            )| ReportSim {
                cycle_starts_at,
                cycle_ends_at,
                rx_bytes,
                tx_bytes,
                accuracy,
                warn_bytes,
                hard_stop_bytes,
                line,
                forecast,
            },
        )
}

fn router() -> impl Strategy<Value = ReportRouter> {
    let signal = || option::of(any::<i16>());
    let radio = prop_oneof![
        Just(ReportRadio::NoService),
        (
            select(ReportRadioAccess::ALL),
            select(ReportRadioSystem::ALL),
            (1..=ReportBandNumber::MAX).prop_map(|number| ReportBandNumber::new(number).unwrap()),
            (signal(), signal(), signal(), signal()),
        )
            .prop_map(
                |(access, system, number, (rsrp_tenths, rsrq_tenths, sinr_tenths, rssi_tenths))| {
                    ReportRadio::Attached {
                        access,
                        band: ReportBand { system, number },
                        rsrp_tenths,
                        rsrq_tenths,
                        sinr_tenths,
                        rssi_tenths,
                    }
                }
            ),
    ];
    prop_oneof![
        (time(), radio, any::<i16>()).prop_map(|(polled_at, radio, temperature_c)| {
            ReportRouter::Available {
                polled_at,
                radio,
                temperature_c,
            }
        }),
        option::of(time()).prop_map(|last_polled_at| ReportRouter::Unavailable { last_polled_at }),
    ]
}

fn capacity() -> impl Strategy<Value = ReportCapacity> {
    let saturation = prop_oneof![
        Just(ReportSaturation::NoEvidence),
        Just(ReportSaturation::Clear),
        time().prop_map(|since| ReportSaturation::Building { since }),
        time().prop_map(|since| ReportSaturation::Saturated { since }),
    ];
    (time(), any::<u64>(), any::<u64>(), saturation).prop_map(|(at, tx_bps, rx_bps, saturation)| {
        ReportCapacity {
            at,
            tx_bps,
            rx_bps,
            saturation,
        }
    })
}

fn alert() -> impl Strategy<Value = ReportAlert> {
    (
        select(MacAlertKind::ALL),
        select(ReportSeverity::ALL),
        option::of(node_name()),
        time(),
    )
        .prop_map(|(kind, severity, node, active_since)| ReportAlert {
            kind,
            severity,
            node,
            active_since,
        })
}

/// Any report: every shape of every field, users whose usage follows the
/// report's usage view, and alerts that may repeat a kind and node.
pub(crate) fn mac_report() -> impl Strategy<Value = MacReportV1> {
    let usage = prop_oneof![
        time().prop_map(|through| ReportUsage::Available { through }),
        Just(ReportUsage::Unavailable),
    ];
    let users = btree_map(
        report_user_id(),
        (select(ReportUserStatus::ALL), traffic(), option::of(time())),
        0..5,
    );
    (
        time(),
        (select(ExitPhase::ALL), time()),
        sim(),
        router(),
        option::of(capacity()),
        usage,
        users,
        vec(alert(), 0..5),
    )
        .prop_map(
            |(at, (phase, since), sim, router, capacity, usage, users, alerts)| {
                let available = matches!(usage, ReportUsage::Available { .. });
                let users = users
                    .into_iter()
                    .map(|(id, (status, cycle, last_seen))| {
                        let cycle = available.then_some(cycle);
                        (
                            id,
                            ReportUser {
                                status,
                                cycle,
                                last_seen,
                            },
                        )
                    })
                    .collect();
                MacReportV1::new(MacReportParts {
                    at,
                    exit: ReportExit { phase, since },
                    sim,
                    router,
                    capacity,
                    usage,
                    users,
                    alerts,
                })
                .unwrap()
            },
        )
}

// ---- the grammar of every string -----------------------------------------

/// Every field name and every tag of a data-carrying enum in a report or a
/// stored report: the only object keys besides user ids.
const FIELDS: &[&str] = &[
    "received_at",
    "report",
    "at",
    "exit",
    "phase",
    "since",
    "sim",
    "cycle_starts_at",
    "cycle_ends_at",
    "rx_bytes",
    "tx_bytes",
    "accuracy",
    "warn_bytes",
    "hard_stop_bytes",
    "line",
    "FairUse",
    "Allowance",
    "bytes",
    "forecast",
    "daily_average_bytes",
    "projected_bytes",
    "router",
    "Available",
    "polled_at",
    "radio",
    "Attached",
    "access",
    "band",
    "system",
    "number",
    "rsrp_tenths",
    "rsrq_tenths",
    "sinr_tenths",
    "rssi_tenths",
    "temperature_c",
    "Unavailable",
    "last_polled_at",
    "capacity",
    "tx_bps",
    "rx_bps",
    "saturation",
    "Building",
    "Saturated",
    "usage",
    "through",
    "users",
    "status",
    "cycle",
    "uplink",
    "downlink",
    "last_seen",
    "alerts",
    "kind",
    "severity",
    "node",
    "active_since",
];

/// Every name a string value may hold besides a node name: the closed
/// enums' variants and the unit variants of the data-carrying enums.
fn names() -> BTreeSet<&'static str> {
    let mut names: BTreeSet<&'static str> =
        ["NoService", "NoEvidence", "Clear", "Unavailable"].into();
    names.extend(ExitPhase::ALL.iter().map(|value| value.name()));
    names.extend(ReportAccuracy::ALL.iter().map(|value| value.name()));
    names.extend(ReportRadioAccess::ALL.iter().map(|value| value.name()));
    names.extend(ReportRadioSystem::ALL.iter().map(|value| value.name()));
    names.extend(ReportUserStatus::ALL.iter().map(|value| value.name()));
    names.extend(ReportSeverity::ALL.iter().map(|value| value.name()));
    names.extend(MacAlertKind::ALL.iter().map(|value| value.name()));
    names
}

/// Checks every string of `value`: an object key is a field or tag, or,
/// directly under `users`, a report user id; a string value is a node name
/// under `node` and a closed name anywhere else. Returns the strings
/// checked.
fn check_strings(value: &Value, key: Option<&str>, names: &BTreeSet<&str>) -> usize {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(child_key, child)| {
                if key == Some("users") {
                    assert!(
                        ReportUserId::new(child_key.as_str()).is_ok(),
                        "{child_key:?}"
                    );
                } else {
                    assert!(FIELDS.contains(&child_key.as_str()), "{child_key:?}");
                }
                1 + check_strings(child, Some(child_key), names)
            })
            .sum(),
        Value::Array(items) => items
            .iter()
            .map(|item| check_strings(item, key, names))
            .sum(),
        Value::String(text) => {
            if key == Some("node") {
                assert!(NodeName::new(text.as_str()).is_ok(), "{text:?}");
            } else {
                assert!(names.contains(text.as_str()), "{key:?}: {text:?}");
            }
            1
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

/// Text that must never fit a report: a user's address, a destination, an
/// IMEI and an ICCID written as text, labels with a space or in another
/// script, and an SMS text.
const CANARIES: [&str; 7] = [
    "203.0.113.7",
    "example.com",
    "356938035643809",
    "8944100000000000000",
    "Alice Example",
    "张三",
    "Your code is 1234",
];

/// One string slot of a JSON document: a string value or an object key,
/// by its path of keys and indices.
#[derive(Clone, Debug)]
enum Slot {
    Value(Vec<Step>),
    Key(Vec<Step>, String),
}

#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

fn slots(value: &Value, path: &mut Vec<Step>, out: &mut Vec<Slot>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                out.push(Slot::Key(path.clone(), key.clone()));
                path.push(Step::Key(key.clone()));
                slots(child, path, out);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(Step::Index(index));
                slots(item, path, out);
                path.pop();
            }
        }
        Value::String(_) => out.push(Slot::Value(path.clone())),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn at<'a>(value: &'a mut Value, path: &[Step]) -> &'a mut Value {
    path.iter().fold(value, |node, step| match step {
        Step::Key(key) => node.get_mut(key.as_str()).unwrap(),
        Step::Index(index) => node.get_mut(*index).unwrap(),
    })
}

/// `value` with the string in `slot` replaced by `text`.
fn with_text(mut value: Value, slot: &Slot, text: &str) -> Value {
    match slot {
        Slot::Value(path) => *at(&mut value, path) = Value::String(text.to_owned()),
        Slot::Key(path, key) => {
            let map = at(&mut value, path).as_object_mut().unwrap();
            let child = map.remove(key).unwrap();
            map.insert(text.to_owned(), child);
        }
    }
    value
}

/// Every canary in every string slot of `report`'s encoding makes it
/// undecodable; returns the slots tried.
fn assert_no_slot_takes_a_canary(report: &MacReportV1) -> usize {
    let json = serde_json::to_value(report).unwrap();
    let mut found = Vec::new();
    slots(&json, &mut Vec::new(), &mut found);
    for slot in &found {
        for canary in CANARIES {
            let changed = with_text(json.clone(), slot, canary);
            assert!(
                serde_json::from_value::<MacReportV1>(changed.clone()).is_err(),
                "{slot:?} accepted {canary:?}: {changed}"
            );
        }
    }
    found.len()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Every report round-trips, and every string in it is a closed name,
    /// a report user id or a node name.
    #[test]
    fn every_report_round_trips_and_holds_only_names_and_ids(report in mac_report()) {
        let json = serde_json::to_value(&report).unwrap();
        prop_assert_eq!(&serde_json::from_value::<MacReportV1>(json.clone()).unwrap(), &report);
        check_strings(&json, None, &names());
        let stored = StoredMacReport { received_at: UnixTime::from_secs(7), report };
        check_strings(&serde_json::to_value(&stored).unwrap(), None, &names());
    }

    /// No canary fits any string slot of any report.
    #[test]
    fn no_report_slot_takes_a_canary(report in mac_report(), pick in any::<usize>(), canary in select(&CANARIES[..])) {
        let json = serde_json::to_value(&report).unwrap();
        let mut found = Vec::new();
        slots(&json, &mut Vec::new(), &mut found);
        let slot = &found[pick % found.len()];
        let changed = with_text(json, slot, canary);
        prop_assert!(serde_json::from_value::<MacReportV1>(changed.clone()).is_err(), "{:?}: {}", slot, changed);
    }
}

/// The deterministic companions of the properties above, over the fixture
/// reports, which hold every kind of string slot: every closed name, user
/// ids, a node name and every key.
#[test]
fn fixture_reports_hold_only_names_and_ids_and_take_no_canary() {
    let fixture = fixtures::mac_report();
    let json = serde_json::to_value(&fixture).unwrap();
    let strings = check_strings(&json, None, &names());
    assert!(strings > 60, "only {strings} strings were checked");
    let mut other_shapes = fixtures::mac_report_parts();
    other_shapes.router = ReportRouter::Unavailable {
        last_polled_at: None,
    };
    other_shapes.usage = ReportUsage::Unavailable;
    for user in other_shapes.users.values_mut() {
        user.cycle = None;
    }
    for report in [fixture, MacReportV1::new(other_shapes).unwrap()] {
        let tried = assert_no_slot_takes_a_canary(&report);
        assert!(tried > 40, "only {tried} slots were tried");
    }
}

// ---- the rules -----------------------------------------------------------

/// The `index`th report user id.
fn user_id(index: usize) -> ReportUserId {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let text: String = (0..10)
        .map(|digit| char::from(alphabet[(index >> (5 * digit)) % 32]))
        .collect();
    ReportUserId::new(text).unwrap()
}

/// `parts` with `count` users, all active with the fixture's usage view.
fn with_users(mut parts: MacReportParts, count: usize) -> MacReportParts {
    let cycle = matches!(parts.usage, ReportUsage::Available { .. }).then(Traffic::default);
    parts.users = (0..count)
        .map(|index| {
            let user = ReportUser {
                status: ReportUserStatus::Active,
                cycle,
                last_seen: None,
            };
            (user_id(index), user)
        })
        .collect();
    parts
}

/// The decision on `parts`, by the constructor and on receipt, which must
/// agree; the decoder reports the rule as its message.
fn decide(parts: &MacReportParts) -> Result<(), ValueError> {
    let built = MacReportV1::new(parts.clone()).map(drop);
    let json = serde_json::to_string(parts).unwrap();
    match serde_json::from_str::<MacReportV1>(&json) {
        Ok(decoded) => {
            assert_eq!(built, Ok(()));
            assert_eq!(decoded.parts(), parts);
        }
        Err(error) => {
            let expected = built.clone().unwrap_err().to_string();
            assert!(error.to_string().starts_with(&expected), "{error}");
        }
    }
    built
}

#[test]
fn each_rule_is_refused() {
    let refused = |rule| Err(ValueError::MacReport { rule });
    let base = fixtures::mac_report_parts();

    assert_eq!(decide(&with_users(base.clone(), MAX_REPORT_USERS)), Ok(()));
    assert_eq!(
        decide(&with_users(base.clone(), MAX_REPORT_USERS + 1)),
        refused(MacReportRule::TooManyUsers)
    );

    let mut alerts = base.clone();
    let alert = alerts.alerts[1].clone();
    alerts.alerts = vec![alert; MAX_REPORT_ALERTS];
    assert_eq!(decide(&alerts), Ok(()));
    alerts.alerts.push(alerts.alerts[0].clone());
    assert_eq!(decide(&alerts), refused(MacReportRule::TooManyAlerts));

    // Usage for a user while the view is unavailable, and none while it is
    // available, either for every user or for one.
    let mut unavailable = base.clone();
    unavailable.usage = ReportUsage::Unavailable;
    assert_eq!(decide(&unavailable), refused(MacReportRule::UsageMismatch));
    for user in unavailable.users.values_mut() {
        user.cycle = None;
    }
    assert_eq!(decide(&unavailable), Ok(()));
    let first = unavailable.users.keys().next().unwrap().clone();
    unavailable.users.get_mut(&first).unwrap().cycle = Some(Traffic::default());
    assert_eq!(decide(&unavailable), refused(MacReportRule::UsageMismatch));
    let mut missing = base.clone();
    missing.users.get_mut(&first).unwrap().cycle = None;
    assert_eq!(decide(&missing), refused(MacReportRule::UsageMismatch));

    // Rules are checked in declaration order.
    let mut every = with_users(base, MAX_REPORT_USERS + 1);
    every.alerts = vec![every.alerts[0].clone(); MAX_REPORT_ALERTS + 1];
    every.usage = ReportUsage::Unavailable;
    assert_eq!(decide(&every), refused(MacReportRule::TooManyUsers));
    every.users.clear();
    assert_eq!(decide(&every), refused(MacReportRule::TooManyAlerts));
    assert_eq!(
        ValueError::MacReport {
            rule: MacReportRule::UsageMismatch
        }
        .to_string(),
        "the Mac report breaks its rule: every user carries cycle usage exactly when usage is available"
    );
    let rules: BTreeMap<MacReportRule, String> = MacReportRule::ALL
        .iter()
        .map(|rule| (*rule, rule.to_string()))
        .collect();
    assert_eq!(rules[&MacReportRule::TooManyUsers], "at most 1024 users");
    assert_eq!(rules[&MacReportRule::TooManyAlerts], "at most 256 alerts");
}

/// Two alerts may share a kind and node: two engines' crash loops on one
/// node are two alerts on the Mac.
#[test]
fn alerts_may_repeat_a_kind_and_node() {
    let mut parts = fixtures::mac_report_parts();
    let repeated = ReportAlert {
        kind: MacAlertKind::EngineCrashLoop,
        severity: ReportSeverity::Critical,
        node: Some(fixtures::node_name("lon1")),
        active_since: UnixTime::from_secs(1),
    };
    parts.alerts = vec![repeated.clone(), repeated];
    assert_eq!(decide(&parts), Ok(()));
}

/// Each kind travels as its name, the Mac's alert condition kind's name
/// (the list is written out, so `kinds-coverage` sees every variant, and
/// mooring-daemon-core proves the two lists equal).
#[test]
fn mac_alert_kinds_travel_as_their_names() {
    let kinds = [
        (MacAlertKind::ExitViolation, "ExitViolation"),
        (MacAlertKind::SimCapReached, "SimCapReached"),
        (MacAlertKind::RouterOffloadActive, "RouterOffloadActive"),
        (MacAlertKind::RouterWifiRadioOn, "RouterWifiRadioOn"),
        (MacAlertKind::RouterOverheating, "RouterOverheating"),
        (MacAlertKind::RouterRestarted, "RouterRestarted"),
        (MacAlertKind::NodeHalted, "NodeHalted"),
        (MacAlertKind::RollbackFailed, "RollbackFailed"),
        (MacAlertKind::GateCloseFailed, "GateCloseFailed"),
        (MacAlertKind::EngineCrashLoop, "EngineCrashLoop"),
        (MacAlertKind::HostKeyMismatch, "HostKeyMismatch"),
        (MacAlertKind::MacSilent, "MacSilent"),
        (MacAlertKind::NodeUnreachable, "NodeUnreachable"),
        (MacAlertKind::NodeDiskLow, "NodeDiskLow"),
        (MacAlertKind::SimWarn, "SimWarn"),
        (MacAlertKind::SimForecastCrossing, "SimForecastCrossing"),
        (MacAlertKind::ExitDegraded, "ExitDegraded"),
        (
            MacAlertKind::ForeignNetworkAttached,
            "ForeignNetworkAttached",
        ),
        (MacAlertKind::ReachabilitySuspect, "ReachabilitySuspect"),
        (MacAlertKind::TargetDegraded, "TargetDegraded"),
        (MacAlertKind::RouterNoService, "RouterNoService"),
        (MacAlertKind::RouterOnLte, "RouterOnLte"),
        (MacAlertKind::RouterThermalStepDown, "RouterThermalStepDown"),
        (MacAlertKind::RouterWeakSignal, "RouterWeakSignal"),
        (MacAlertKind::RouterFirmwareChanged, "RouterFirmwareChanged"),
        (MacAlertKind::RouterUnreadSms, "RouterUnreadSms"),
        (MacAlertKind::RouterCounterMismatch, "RouterCounterMismatch"),
        (MacAlertKind::UsersNearQuota, "UsersNearQuota"),
        (MacAlertKind::UsersOverQuota, "UsersOverQuota"),
        (MacAlertKind::UsersSuspended, "UsersSuspended"),
        (MacAlertKind::UsersExpiringSoon, "UsersExpiringSoon"),
        (MacAlertKind::UsersExpired, "UsersExpired"),
        (MacAlertKind::CapacitySaturated, "CapacitySaturated"),
        (MacAlertKind::ExitFlowCapHit, "ExitFlowCapHit"),
        (MacAlertKind::NodeClockUnsynced, "NodeClockUnsynced"),
        (MacAlertKind::NodeRebootPending, "NodeRebootPending"),
        (MacAlertKind::PendingApply, "PendingApply"),
        (MacAlertKind::OperatorHoldLong, "OperatorHoldLong"),
        (
            MacAlertKind::AccountingCanaryMissing,
            "AccountingCanaryMissing",
        ),
    ];
    assert_eq!(kinds.map(|(kind, _)| kind), MacAlertKind::ALL);
    for (kind, name) in kinds {
        assert_eq!(kind.name(), name);
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, format!("\"{name}\""));
        assert_eq!(serde_json::from_str::<MacAlertKind>(&json).unwrap(), kind);
    }
    assert!(serde_json::from_str::<MacAlertKind>("\"exitViolation\"").is_err());
}

/// The band number slot takes a band, 1..=999, and nothing larger: not
/// the largest physical cell id (1007), nor a 16-bit tracking-area code.
#[test]
fn the_band_slot_takes_only_a_band_number() {
    let json = serde_json::to_value(fixtures::mac_report()).unwrap();
    let band = |number: Value| {
        let mut changed = json.clone();
        changed["router"]["Available"]["radio"]["Attached"]["band"]["number"] = number;
        serde_json::from_value::<MacReportV1>(changed)
    };
    assert!(json["router"]["Available"]["radio"]["Attached"]["band"]["number"].is_u64());
    for number in [1, 78, 999] {
        assert!(band(number.into()).is_ok(), "{number}");
    }
    for number in [0, 1000, 1007, 25_000, 65_535] {
        assert!(band(number.into()).is_err(), "{number}");
    }
}
