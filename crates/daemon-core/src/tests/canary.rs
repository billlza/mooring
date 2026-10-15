// SPDX-License-Identifier: GPL-3.0-or-later

//! A canary in every sensitive leaf of the MR7450's `model.json` (the
//! plaintext secrets and identifiers M2a found, design §15.6): none reaches
//! the router status, its `Debug` or JSON encodings, the session's
//! `Debug`, the redactor's capture, or any error.

use mooring_model::UnixTime;
use serde_json::{Value, json};

use crate::error::RouterParseError;
use crate::router::RouterReading;
use crate::router::netgear::{
    parse_netgear_model_json, parse_netgear_session, redact_netgear_model_json,
};
use crate::tests::netgear::fixture;

/// A router parse error is `Copy`, so no variant can own a byte of the
/// answer (nor can a `'static` borrow point into it): the error paths are
/// kept free of input by type, and the checks below show it for each way
/// a document can break.
const _: () = {
    const fn copy<T: Copy>() {}
    copy::<RouterParseError>();
};

/// Every sensitive leaf and its canary: the plaintext secrets and the
/// subscriber, device, cell, location and client identifiers.
const CANARIES: [(&str, &str); 34] = [
    ("/webd/adminPassword", "Pw-canary-admin-1"),
    ("/wifi/passPhrase", "Pw-canary-wifi-2"),
    ("/wifi/guest/passPhrase", "Pw-canary-guest-3"),
    ("/wifi/aux/passPhrase", "Pw-canary-aux-4"),
    ("/cradle/primaryPassphrase", "Pw-canary-cradle-5"),
    ("/cradle/secondaryPassphrase", "Pw-canary-cradle-6"),
    ("/general/IMEI", "356938035643809"),
    ("/general/InstallID", "canary-install-7"),
    ("/general/ESN", "canary-esn-8"),
    ("/general/FSN", "canary-fsn-9"),
    ("/general/MEID", "canary-meid-10"),
    ("/sim/iccid", "8944110068256270054"),
    ("/sim/imsi", "234301234567890"),
    ("/sim/phoneNumber", "+447700900123"),
    ("/sms/msgs/0/text", "canary meet at the dock"),
    ("/sms/msgs/0/sender", "+447700900456"),
    ("/wwan/lteBandInfo/0/phyCid", "canary-pci-11"),
    ("/wwan/lteBandInfo/0/channel", "canary-earfcn-12"),
    ("/lbs/latitude", "51.5007325"),
    ("/lbs/longitude", "-0.1268141"),
    ("/router/clientList/0/IP", "192.168.1.60"),
    ("/router/clientList/0/MAC", "aa:bb:cc:dd:ee:01"),
    ("/router/clientList/0/name", "canary-macbook"),
    ("/ethernet/mac", "aa:bb:cc:dd:ee:02"),
    ("/wifi/MAC", "aa:bb:cc:dd:ee:03"),
    ("/wifi/SSID", "canary-ssid-main"),
    ("/wifi/guest/SSID", "canary-ssid-guest"),
    ("/wwan/IP", "203.0.113.67"),
    ("/wwan/IPv6", "2001:db8:cafe::1"),
    ("/wwan/profileList/0/apn", "canary.apn.example"),
    ("/wwan/profileList/0/username", "canary-apn-user"),
    ("/wwan/profileList/0/password", "Pw-canary-apn-13"),
    ("/session/secToken", "canaryToken0123456789abcdefABCDE"),
    ("/session/clientIP", "192.168.1.61"),
];

/// The cell identifiers, numbers in the M7's answer.
const NUMBER_CANARIES: [(&str, u64); 3] = [
    ("/wwanadv/cellId", 987_123_451),
    ("/wwanadv/LAC", 987_123_452),
    ("/wwanadv/RAC", 987_123_453),
];

/// The fixture with every canary planted.
fn canaried() -> Value {
    let mut value = fixture();
    for (at, canary) in CANARIES {
        *value
            .pointer_mut(at)
            .unwrap_or_else(|| panic!("the fixture has {at}")) = json!(canary);
    }
    for (at, canary) in NUMBER_CANARIES {
        *value
            .pointer_mut(at)
            .unwrap_or_else(|| panic!("the fixture has {at}")) = json!(canary);
    }
    value
}

fn encoded(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

/// Every canary, as text.
fn canaries() -> Vec<String> {
    CANARIES
        .iter()
        .map(|(_, canary)| (*canary).to_owned())
        .chain(NUMBER_CANARIES.iter().map(|(_, canary)| canary.to_string()))
        .collect()
}

fn assert_no_canary(what: &str, text: &str) {
    for canary in canaries() {
        assert!(!text.contains(&canary), "{what} holds {canary:?}");
    }
}

#[test]
fn no_sensitive_leaf_reaches_the_status_its_encodings_the_capture_or_an_error() {
    let document = canaried();
    let body = encoded(&document);
    // The canaries are in the document, so the checks are not vacuous.
    let raw = String::from_utf8(body.clone()).unwrap();
    for canary in canaries() {
        assert!(raw.contains(&canary), "{canary}");
    }

    let status = parse_netgear_model_json(&body).unwrap();
    assert_eq!(status, crate::tests::router::status());
    assert_no_canary("the status's Debug", &format!("{status:?} {status:#?}"));
    assert_no_canary(
        "the status's JSON",
        &serde_json::to_string(&status).unwrap(),
    );
    let reading = RouterReading::Available {
        polled_at: UnixTime::from_secs(1_791_919_200),
        status: Box::new(status),
    };
    assert_no_canary(
        "the reading's JSON",
        &serde_json::to_string(&reading).unwrap(),
    );
    let session = parse_netgear_session(&body).unwrap();
    assert_eq!(
        session.token().expose_str(),
        "canaryToken0123456789abcdefABCDE"
    );
    assert_no_canary("the session's Debug", &format!("{session:?} {session:#?}"));
    let capture = redact_netgear_model_json(&body).unwrap();
    assert_eq!(capture.withheld(), [], "every kept value passes its shape");
    assert_no_canary(
        "the capture",
        std::str::from_utf8(capture.as_bytes()).unwrap(),
    );

    // Every way the document can break, with the canaries still in it.
    let broken = |edit: &dyn Fn(&mut Value)| {
        let mut value = document.clone();
        edit(&mut value);
        encoded(&value)
    };
    let mut bodies = vec![
        broken(&|value| {
            value["sms"].as_object_mut().unwrap().remove("unreadMsgs");
        }),
        broken(&|value| value["wifi"]["enabled"] = json!("yes")),
        broken(&|value| value["wifi"]["status"] = json!("On")),
        broken(&|value| value["session"]["userRole"] = json!("Guest")),
        broken(&|value| value["general"]["model"] = json!("MR6400")),
        broken(&|value| value["sim"]["SPN"] = json!("356938035643809")),
        broken(&|value| value["wwan"]["lteBandInfo"] = json!([value["wwan"]["lteBandInfo"][0]])),
        broken(&|value| value["wwan"]["sessDuration"] = json!(999_999_999)),
        broken(&|value| {
            value
                .as_object_mut()
                .unwrap()
                .insert("aa:bb:cc:dd:ee:01".to_owned(), json!("canary-macbook"));
        }),
    ];
    let mut tail = body.clone();
    tail.extend_from_slice(b"canary meet at the dock");
    bodies.push(tail);
    bodies.push(body[..body.len() / 2].to_vec());
    let duplicate = raw.replacen(
        "\"unreadMsgs\":0",
        "\"unreadMsgs\":0,\"unreadMsgs\":\"canary meet at the dock\"",
        1,
    );
    bodies.push(duplicate.into_bytes());
    for body in &bodies {
        let errors: Vec<RouterParseError> = [
            parse_netgear_model_json(body).err(),
            parse_netgear_session(body).err(),
            redact_netgear_model_json(body).err(),
        ]
        .into_iter()
        .flatten()
        .collect();
        // Each broken document breaks at least one of them.
        assert!(!errors.is_empty());
        for error in errors {
            assert_no_canary("an error", &format!("{error} {error:?} {error:#?}"));
        }
        // What does succeed holds no canary either.
        if let Ok(status) = parse_netgear_model_json(body) {
            assert_no_canary("a status", &format!("{status:?}"));
        }
        if let Ok(session) = parse_netgear_session(body) {
            assert_no_canary("a session", &format!("{session:?}"));
        }
        if let Ok(capture) = redact_netgear_model_json(body) {
            assert_no_canary(
                "a capture",
                std::str::from_utf8(capture.as_bytes()).unwrap(),
            );
            for withheld in capture.withheld() {
                assert_no_canary(
                    "a withheld value's name",
                    &format!("{withheld} {withheld:?}"),
                );
            }
            assert_no_canary("a capture's Debug", &format!("{capture:?}"));
        }
    }
}
