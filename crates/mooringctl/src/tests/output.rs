// SPDX-License-Identifier: GPL-3.0-or-later

//! The human summary, pinned on the router fixture (the M2a reading).

use mooring_daemon_core::router::netgear::parse_netgear_model_json;
use mooring_daemon_core::router::{
    RadioState, RouterReading, RouterStatus, RouterUnavailableReason,
};
use mooring_model::iface::BsdName;
use mooring_model::time::UnixTime;

use super::support::{FIXTURE, NOW};
use crate::router::output::{Tenths, json_line, summary};

#[test]
fn the_human_summary_of_the_fixture() {
    let status = parse_netgear_model_json(FIXTURE).unwrap();
    let text = summary(
        Some(&BsdName::parse("en9").unwrap()),
        UnixTime::from_secs(NOW),
        &status,
    )
    .unwrap();
    assert_eq!(
        text,
        r#"M7 MR7450 on en9, polled 2026-10-13 19:20:00 UTC
firmware "NTGX75_10.04.43.01", web app "M7_GENERIC_v07.01.81.00"; up 4d 03:47:52; 35 °C, thermal Normal
radio connected: Nr5gService, 5GSUB6, band B3; LTE carriers B3 20MHz (primary); secondary carriers 0; session 4d 03:46:57
network "CMLink" (234-30); SIM "CMLink"
LTE RSRP -104 dBm, RSRQ -17 dB, SINR 0 dB, RSSI -72 dBm; NR RSRP not reported, RSRQ not reported, SINR not reported
power Online; battery 100 %, Normal, not charging, QuickCharge, 32 °C
counters received 591655199 B, sent 188784597 B
Wi-Fi radio off (main Off, guest Off, aux Off), 0 clients
offload Wi-Fi off, Ethernet off; UPnP off; Analytics off; Insight inactive
unread SMS 0
"#
    );
}

/// The settings the exit needs off that are on are named after the
/// settings, in their order; Analytics is shown but never named.
#[test]
fn the_settings_the_exit_needs_off_are_named() {
    let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    let body = serde_json::to_vec(&document).unwrap();
    let text = summary(
        None,
        UnixTime::from_secs(NOW),
        &parse_netgear_model_json(&body).unwrap(),
    )
    .unwrap();
    assert!(!text.contains("needs these off"), "{text}");
    document["router"]["UPNPenabled"] = serde_json::json!(true);
    document["insight"]["active"] = serde_json::json!(true);
    document["ra"]["enabled"] = serde_json::json!(true);
    let body = serde_json::to_vec(&document).unwrap();
    let text = summary(
        None,
        UnixTime::from_secs(NOW),
        &parse_netgear_model_json(&body).unwrap(),
    )
    .unwrap();
    assert!(
        text.contains(
            "offload Wi-Fi off, Ethernet off; UPnP on; Analytics on; Insight active\nthe exit needs these off: UPnP, NETGEAR Insight\nunread SMS 0\n"
        ),
        "{text}"
    );
}

/// Unassigned secondary slots are counted after the carriers, never listed
/// as carriers.
#[test]
fn unassigned_slots_are_counted_in_the_summary() {
    let unassigned = serde_json::json!({
        "band": 0, "channel": "REDACTED", "dlBandwidth": "Unknown", "isPcc": false,
        "phyCid": "REDACTED", "sccId": 0, "sccState": 0, "sccUlBandwidth": "REDACTED",
        "sccUlCaEnabled": "REDACTED", "sccUlChannel": 0
    });
    for (slots, said) in [
        (1, "LTE carriers B3 20MHz (primary), 1 unassigned slot; "),
        (2, "LTE carriers B3 20MHz (primary), 2 unassigned slots; "),
    ] {
        let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        let list = document["wwan"]["lteBandInfo"].as_array_mut().unwrap();
        for _ in 0..slots {
            list.insert(1, unassigned.clone());
        }
        let body = serde_json::to_vec(&document).unwrap();
        let status = parse_netgear_model_json(&body).unwrap();
        let text = summary(None, UnixTime::from_secs(NOW), &status).unwrap();
        assert!(text.contains(said), "{text}");
    }
}

/// What the M7 reports as the empty string reads as not reported, never as
/// an empty name: the SPN and the web app's version, both empty with the
/// SMARTY SIM (2026-10-16).
#[test]
fn the_human_summary_says_what_the_m7_did_not_report() {
    let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    document["sim"]["SPN"] = serde_json::json!("");
    document["general"]["webAppVersion"] = serde_json::json!("");
    let body = serde_json::to_vec(&document).unwrap();
    let text = parse_netgear_model_json(&body).map(|status| {
        summary(
            Some(&BsdName::parse("en9").unwrap()),
            UnixTime::from_secs(NOW),
            &status,
        )
        .unwrap()
    });
    assert_eq!(
        text,
        Ok(r#"M7 MR7450 on en9, polled 2026-10-13 19:20:00 UTC
firmware "NTGX75_10.04.43.01", web app version not reported; up 4d 03:47:52; 35 °C, thermal Normal
radio connected: Nr5gService, 5GSUB6, band B3; LTE carriers B3 20MHz (primary); secondary carriers 0; session 4d 03:46:57
network "CMLink" (234-30); SIM name not reported
LTE RSRP -104 dBm, RSRQ -17 dB, SINR 0 dB, RSSI -72 dBm; NR RSRP not reported, RSRQ not reported, SINR not reported
power Online; battery 100 %, Normal, not charging, QuickCharge, 32 °C
counters received 591655199 B, sent 188784597 B
Wi-Fi radio off (main Off, guest Off, aux Off), 0 clients
offload Wi-Fi off, Ethernet off; UPnP off; Analytics off; Insight inactive
unread SMS 0
"#
        .to_owned())
    );
}

/// Without service the summary still names the SIM, or says that the M7
/// reported no name for it.
#[test]
fn without_service_the_summary_names_the_sim_or_says_it_was_not_reported() {
    let mut parts = parse_netgear_model_json(FIXTURE).unwrap().into_parts();
    parts.radio = RadioState::NoService;
    for (sim_spn, line) in [
        (
            parts.sim_spn.clone(),
            "\nradio no service; SIM \"CMLink\"\n",
        ),
        (None, "\nradio no service; SIM name not reported\n"),
    ] {
        let mut parts = parts.clone();
        parts.sim_spn = sim_spn;
        let text = summary(
            Some(&BsdName::parse("en9").unwrap()),
            UnixTime::from_secs(NOW),
            &RouterStatus::new(parts).unwrap(),
        )
        .unwrap();
        assert!(text.contains(line), "{text}");
        assert!(!text.contains("radio connected"), "{text}");
    }
}

/// Text the M7 reports prints in double quotes, with `"` and `\` escaped,
/// so none of it reads as the summary's own words: a version or a name
/// that spells "not reported" prints unlike one the M7 did not report, and
/// a quote in a name cannot end it early.
#[test]
fn reported_text_is_quoted_so_it_never_reads_as_the_summarys_words() {
    let summary_of = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut document: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        edit(&mut document);
        let body = serde_json::to_vec(&document).unwrap();
        summary(
            Some(&BsdName::parse("en9").unwrap()),
            UnixTime::from_secs(NOW),
            &parse_netgear_model_json(&body).unwrap(),
        )
        .unwrap()
    };
    let spelt = summary_of(&|document| {
        document["general"]["FWversion"] = serde_json::json!("not reported");
        document["general"]["webAppVersion"] = serde_json::json!("version not reported\n");
        document["wwan"]["registerNetworkDisplay"] = serde_json::json!("not reported");
        document["sim"]["SPN"] = serde_json::json!("name not reported");
    });
    for line in [
        "\nfirmware \"not reported\", web app \"version not reported\"; up ",
        "\nnetwork \"not reported\" (234-30); SIM \"name not reported\"\n",
    ] {
        assert!(spelt.contains(line), "{spelt}");
    }
    let absent = summary_of(&|document| {
        document["general"]["webAppVersion"] = serde_json::json!("");
        document["sim"]["SPN"] = serde_json::json!("");
    });
    for line in [
        "\nfirmware \"NTGX75_10.04.43.01\", web app version not reported; up ",
        "\nnetwork \"CMLink\" (234-30); SIM name not reported\n",
    ] {
        assert!(absent.contains(line), "{absent}");
    }
    let quoting = summary_of(&|document| {
        document["sim"]["SPN"] = serde_json::json!(r#"CM" (1-2); SIM "X\Y"#);
    });
    assert!(
        quoting.contains("\nnetwork \"CMLink\" (234-30); SIM \"CM\\\" (1-2); SIM \\\"X\\\\Y\"\n"),
        "{quoting}"
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
        Some(&BsdName::parse("en9").unwrap()),
        UnixTime::from_secs(59),
        &status,
    )
    .unwrap();
    assert!(text.contains("RSRQ -3 dB"), "{text}");
    assert!(text.starts_with("M7 MR7450 on en9, polled 1970-01-01 00:00:59 UTC\n"));
    assert!(
        summary(
            Some(&BsdName::parse("en9").unwrap()),
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
