// SPDX-License-Identifier: GPL-3.0-or-later

//! The human summary, pinned on the router fixture (the M2a reading).

use mooring_daemon_core::router::netgear::parse_netgear_model_json;
use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};
use mooring_model::iface::BsdName;
use mooring_model::time::UnixTime;

use super::support::{FIXTURE, NOW};
use crate::router::output::{Tenths, json_line, summary};

#[test]
fn the_human_summary_of_the_fixture() {
    let status = parse_netgear_model_json(FIXTURE).unwrap();
    let text = summary(
        &BsdName::parse("en9").unwrap(),
        UnixTime::from_secs(NOW),
        &status,
    )
    .unwrap();
    assert_eq!(
        text,
        "M7 MR7450 on en9, polled 2026-10-13 19:20:00 UTC
firmware NTGX75_10.04.43.01, web app M7_GENERIC_v07.01.81.00; up 4d 03:47:52; 35 °C, thermal Normal
radio connected: Nr5gService, 5GSUB6, band B3; LTE carriers B3 20MHz (primary); secondary carriers 0; session 4d 03:46:57
network CMLink (234-30); SIM CMLink
LTE RSRP -104 dBm, RSRQ -17 dB, SINR 0 dB, RSSI -72 dBm; NR RSRP not reported, RSRQ not reported, SINR not reported
power Online; battery 100 %, Normal, not charging, QuickCharge, 32 °C
counters received 591655199 B, sent 188784597 B
Wi-Fi radio off (main Off, guest Off, aux Off), 0 clients
offload Wi-Fi off, Ethernet off; UPnP off; Analytics off; Insight inactive
unread SMS 0
"
    );
}

#[test]
fn tenths_print_one_decimal_only_when_they_have_one() {
    let status = parse_netgear_model_json(
        &String::from_utf8(FIXTURE.to_vec())
            .unwrap()
            .replace("\"rsrq\":-17", "\"rsrq\":-3")
            .into_bytes(),
    )
    .unwrap();
    let text = summary(
        &BsdName::parse("en9").unwrap(),
        UnixTime::from_secs(59),
        &status,
    )
    .unwrap();
    assert!(text.contains("RSRQ -3 dB"), "{text}");
    assert!(text.starts_with("M7 MR7450 on en9, polled 1970-01-01 00:00:59 UTC\n"));
    assert!(
        summary(
            &BsdName::parse("en9").unwrap(),
            UnixTime::from_secs(u64::MAX),
            &status
        )
        .is_err()
    );
}

#[test]
fn json_lines_are_one_reading_each() {
    let line = json_line(&RouterReading::Unavailable {
        reason: RouterUnavailableReason::NotConfigured,
        last_polled_at: None,
    })
    .unwrap();
    assert_eq!(
        line,
        "{\"unavailable\":{\"reason\":\"not_configured\",\"last_polled_at\":null}}\n"
    );
}

#[test]
fn tenths_are_whole_or_one_decimal() {
    for (tenths, text) in [
        (-1040, "-104"),
        (-1045, "-104.5"),
        (-5, "-0.5"),
        (0, "0"),
        (5, "0.5"),
        (120, "12"),
        (i16::MIN, "-3276.8"),
        (i16::MAX, "3276.7"),
    ] {
        assert_eq!(Tenths(tenths).to_string(), text, "{tenths}");
    }
}
