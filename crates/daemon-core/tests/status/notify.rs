// SPDX-License-Identifier: GPL-3.0-or-later

//! The daily digest and the notices of the scenarios' open alerts (decision
//! F6): exact text for a serving exit, the lines that vary with the
//! scenario, and Level 0 throughout: no rendered message holds a label, a
//! user id, an alias, an address, a router identifier or SMS-like digits.

use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::str::FromStr;

use mooring_agent_proto::{NoticeBody, NoticeTitle, NtfyMessage, NtfyPriority, NtfyTag};
use mooring_daemon_core::MacStatusV1;
use mooring_daemon_core::alert::{AlertNotice, NoticeEvent};
use mooring_daemon_core::notify::{alert_message, digest_message};
use mooring_daemon_core::router::{CarrierName, RadioState, RouterReading, RouterStatus};
use mooring_model::MacAddr;
use mooring_model::sim::{PlanLine, PlanLineKind, SimThresholds, StopPolicy};
use serde_json::Value;

use crate::scenarios;
use crate::support::GRAMMAR_SHAPED_LABEL;

fn scenario(name: &str) -> MacStatusV1 {
    scenarios::all()
        .into_iter()
        .find(|(found, _)| *found == name)
        .unwrap()
        .1
}

fn digest_lines(name: &str) -> Vec<String> {
    let message = digest_message(&scenario(name)).unwrap();
    message.body.as_str().lines().map(str::to_owned).collect()
}

#[test]
fn the_serving_digest_has_its_exact_text() {
    assert_eq!(
        digest_message(&scenario("serving")),
        Ok(NtfyMessage {
            title: NoticeTitle::new("Mooring digest 2026-10-08").unwrap(),
            body: NoticeBody::new(
                "Exit Serving since 2026-10-08 06:12 UTC\n\
                 SIM 14 GB used of 300 GB, warning at 240 GB, cycle from 2026-10-01\n\
                 Forecast 60 GB by 2026-11-01\n\
                 Users 3 active, 0 suspended, 0 revoking\n\
                 Served this cycle 6 GB\n\
                 Alerts 0 critical, 0 warning\n\
                 Nodes 2: 0 behind, 0 unreachable"
            )
            .unwrap(),
            priority: NtfyPriority::Low,
            tag: NtfyTag::BarChart,
        })
    );
}

/// A degraded exit's digest: the first threshold projected to be crossed
/// (with its forecast alert open), suspended users, the open alerts by
/// severity and kind, and a node behind and unreachable.
#[test]
fn the_degraded_digest_counts_what_is_wrong() {
    assert_eq!(
        digest_lines("degraded"),
        [
            "Exit Degraded since 2026-10-08 12:34 UTC",
            "SIM 224 GB used of 300 GB, warning at 240 GB, cycle from 2026-10-01",
            "Forecast 921 GB by 2026-11-01; Warn projected on 2026-10-09",
            "Users 18 active, 2 suspended, 0 revoking",
            "Served this cycle 108 GB",
            "Alerts 1 critical, 10 warning: NodeUnreachable, SimForecastCrossing, ExitDegraded, \
             RouterOnLte, RouterWeakSignal, UsersNearQuota, UsersOverQuota, UsersSuspended, \
             UsersExpiringSoon, CapacitySaturated, ExitFlowCapHit",
            "Nodes 2: 1 behind, 1 unreachable",
        ]
    );
}

/// A down exit's digest: a meter that may miss bytes is a lower bound, and
/// a forecast or usage that cannot be computed says so, never zero.
#[test]
fn the_down_digest_marks_a_lower_bound_and_what_is_unavailable() {
    assert_eq!(
        digest_lines("down"),
        [
            "Exit Down since 2026-10-08 16:40 UTC",
            "SIM 18 GB used of 300 GB, warning at 240 GB, cycle from 2026-10-01, lower bound",
            "Forecast unavailable",
            "Users 1 active, 0 suspended, 0 revoking",
            "Served this cycle unavailable",
            "Alerts 1 critical, 0 warning: ExitViolation",
            "Nodes 1: 0 behind, 0 unreachable",
        ]
    );
}

/// Under `AcceptDeprioritisation` there is no hard stop: the digest's SIM
/// line gives the fair-use line the operator accepted running past as the
/// budget instead.
#[test]
fn a_digest_without_a_hard_stop_names_the_fair_use_line() {
    let mut status = scenario("serving").into_parts();
    status.sim.thresholds = SimThresholds::new(
        10_000_000_000,
        StopPolicy::AcceptDeprioritisation,
        Some(PlanLine {
            kind: PlanLineKind::FairUse,
            bytes: NonZeroU64::new(644_245_094_400).unwrap(),
        }),
    )
    .unwrap();
    let digest = digest_message(&MacStatusV1::new(status).unwrap()).unwrap();
    assert_eq!(
        digest.body.as_str().lines().nth(1).unwrap(),
        "SIM 14 GB used with no hard stop, fair-use line 644 GB, warning at 10 GB, \
         cycle from 2026-10-01"
    );
}

/// Every message the scenarios produce: the digest, and each open alert's
/// notice for every event.
fn messages(status: &MacStatusV1) -> Vec<NtfyMessage> {
    let mut messages = vec![digest_message(status).unwrap()];
    for alert in &status.parts().alerts {
        for event in [
            NoticeEvent::Raised,
            NoticeEvent::Reminder,
            NoticeEvent::Resolved,
        ] {
            let notice = AlertNotice {
                at: status.parts().at,
                event,
                severity: alert.severity,
                condition: alert.condition.clone(),
                active_since: alert.active_since,
            };
            messages.push(alert_message(&notice).unwrap());
        }
    }
    messages
}

/// Every string leaf of a JSON document, map keys included.
fn strings(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) => found.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| strings(item, found)),
        Value::Object(map) => {
            for (key, item) in map {
                found.push(key.clone());
                strings(item, found);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The identifiers a status holds that must never reach a notice: user ids,
/// aliases, IPv4 and link-layer addresses, and the router's SIM and network
/// names and its firmware and web app versions. Labels never reach a `MacStatusV1` (it has no field for one);
/// every fixture label and the degraded scenario's grammar-shaped label are
/// scanned for all the same, so a status that ever gained one would be
/// caught leaking it.
fn forbidden(status: &MacStatusV1) -> Vec<String> {
    let parts = status.parts();
    let mut words: Vec<String> = Vec::new();
    for (id, row) in &parts.users {
        words.push(id.as_str().to_owned());
        words.extend(row.alias.iter().map(|alias| alias.as_str().to_owned()));
    }
    let mut leaves = Vec::new();
    strings(&serde_json::to_value(status).unwrap(), &mut leaves);
    words.extend(
        leaves
            .into_iter()
            .filter(|leaf| Ipv4Addr::from_str(leaf).is_ok() || MacAddr::parse(leaf).is_ok()),
    );
    if let RouterReading::Available { status, .. } = &parts.router {
        let router = status.parts();
        words.push(router.firmware.as_str().to_owned());
        words.extend(
            router
                .web_app
                .iter()
                .map(|web_app| web_app.as_str().to_owned()),
        );
        words.extend(router.sim_spn.iter().map(|spn| spn.as_str().to_owned()));
        if let RadioState::Attached(radio) = &router.radio {
            words.push(radio.network.as_str().to_owned());
        }
    }
    words.push(GRAMMAR_SHAPED_LABEL.to_owned());
    for fixture in mooring_fixtures::all().unwrap() {
        let deployment = &fixture.deployment;
        for user in deployment.users().values() {
            words.push(user.id.as_str().to_owned());
            words.push(user.label.as_str().to_owned());
        }
        for viewer in deployment.viewers().values() {
            words.push(viewer.label.as_str().to_owned());
        }
    }
    words
}

/// The longest run of decimal digits in `text`.
fn longest_digit_run(text: &str) -> usize {
    text.split(|c: char| !c.is_ascii_digit())
        .map(str::len)
        .max()
        .unwrap_or(0)
}

/// Level 0 (design §15.5, critique C-12): no message rendered from the
/// scenarios holds any of the status's user ids, aliases or addresses, the
/// router's identifiers, a fixture label, or a run of five or more digits
/// (a phone number, an SMS code, an IMEI or ICCID; a year has four). The
/// statuses do hold every kind of identifier, so the check is not vacuous.
#[test]
fn no_message_holds_a_label_an_id_an_alias_an_address_or_sms_digits() {
    let mut kinds_seen = [false; 4];
    let mut sim_name_seen = false;
    for (name, status) in scenarios::all() {
        let status = with_sim_name(status);
        let words = forbidden(&status);
        sim_name_seen |= words.iter().any(|word| word == SIM_NAME);
        let parts = status.parts();
        kinds_seen[0] |= !parts.users.is_empty();
        kinds_seen[1] |= parts.users.values().any(|row| row.alias.is_some());
        kinds_seen[2] |= words.iter().any(|word| Ipv4Addr::from_str(word).is_ok());
        kinds_seen[3] |= words.iter().any(|word| MacAddr::parse(word).is_ok());
        let messages = messages(&status);
        assert!(messages.len() > 1 || parts.alerts.is_empty(), "{name}");
        for message in &messages {
            for text in [message.title.as_str(), message.body.as_str()] {
                for word in &words {
                    assert!(
                        !text.contains(word.as_str()),
                        "{name}: {text:?} holds {word:?}"
                    );
                }
                assert!(longest_digit_run(text) <= 4, "{name}: {text:?}");
            }
        }
    }
    assert_eq!(
        kinds_seen, [true; 4],
        "the scenarios hold ids, aliases, IPv4 and link-layer addresses"
    );
    assert!(sim_name_seen, "a scenario's router names its SIM");
}

/// A SIM name planted in the scenarios' router readings.
const SIM_NAME: &str = "SPN canary";

/// `status` with its router reading, if it has one, naming the SIM
/// [`SIM_NAME`]: the SMARTY SIM the scenarios carry reports no name
/// (2026-10-16), so the scan would otherwise have no SIM name to look for.
fn with_sim_name(status: MacStatusV1) -> MacStatusV1 {
    let mut parts = status.into_parts();
    if let RouterReading::Available { status: router, .. } = &mut parts.router {
        let mut named = router.as_ref().clone().into_parts();
        named.sim_spn = Some(CarrierName::parse(SIM_NAME).unwrap());
        **router = RouterStatus::new(named).unwrap();
    }
    MacStatusV1::new(parts).unwrap()
}

#[test]
fn the_digit_run_scanner_finds_numbers() {
    assert_eq!(longest_digit_run("Mooring digest 2026-10-08"), 4);
    assert_eq!(longest_digit_run("call 07700900123"), 11);
    assert_eq!(longest_digit_run("no digits"), 0);
}
