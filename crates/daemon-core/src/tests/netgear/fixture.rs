// SPDX-License-Identifier: GPL-3.0-or-later

//! `contract/router-fixtures/`: the redacted M2a capture carries no
//! identifier, is alone in its directory with its licence, and is named
//! after its model and firmware.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::parse::outside_pointers;
use super::{FIXTURE, fixture, pointer};
use crate::router::netgear::NetgearLeaf;

const FIXTURE_NAME: &str = "mr7450-ntgx75-10.04.43.01.json";

fn directory() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contract/router-fixtures")
}

/// Every run of ASCII digits in `text`.
fn digit_runs(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|run| !run.is_empty())
}

/// Whether `text` holds six pairs of hex digits joined by `:` or `-`.
fn has_mac_shape(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(17).any(|window| {
        let separator = window[2];
        (separator == b':' || separator == b'-')
            && window.chunks(3).all(|chunk| {
                chunk[0].is_ascii_hexdigit()
                    && chunk[1].is_ascii_hexdigit()
                    && chunk.get(2).is_none_or(|byte| *byte == separator)
            })
    })
}

/// Whether `text` holds a word (between characters that are not word
/// characters or dots) of four dot-separated runs of one to three digits.
fn has_ipv4_shape(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .any(|word| {
            let parts: Vec<&str> = word.trim_matches('.').split('.').collect();
            parts.len() == 4
                && parts.iter().all(|part| {
                    (1..=3).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
                })
        })
}

/// Every object key and its value, anywhere in `value`.
fn entries<'v>(value: &'v Value, out: &mut Vec<(&'v str, &'v Value)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                out.push((key, child));
                entries(child, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| entries(item, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The fixture holds no run of twelve digits or more, nothing shaped like
/// a link-layer or IPv4 address, a placeholder in every key that names an
/// identifier or a secret, and real values only in the 48 allowlisted
/// leaves that are not secret.
#[test]
fn the_router_fixture_carries_no_identifiers() {
    let text = std::str::from_utf8(FIXTURE).unwrap();
    assert!(digit_runs(text).all(|run| run.len() < 12));
    assert!(!has_mac_shape(text));
    assert!(!has_ipv4_shape(text));
    // The checks see what they look for.
    assert!(has_mac_shape("x aa:bb:cc:dd:ee:ff y") && has_mac_shape("0A-1B-2C-3D-4E-5F"));
    assert!(has_ipv4_shape("ip 192.168.1.1;") && has_ipv4_shape("\"10.0.0.1.\""));
    assert!(!has_ipv4_shape("NTGX75_10.04.43.01") && !has_ipv4_shape("v07.01.81.00"));
    let value = fixture();
    let mut all = Vec::new();
    entries(&value, &mut all);
    let sensitive = [
        "SSID",
        "primarySSID",
        "secondarySSID",
        "passPhrase",
        "primaryPassphrase",
        "secondaryPassphrase",
        "adminPassword",
        "IMEI",
        "InstallID",
        "ESN",
        "FSN",
        "MEID",
        "iccid",
        "imsi",
        "phoneNumber",
        "IP",
        "IPv6",
        "MAC",
        "mac",
        "secToken",
        "clientIP",
        "latitude",
        "longitude",
        "text",
        "sender",
        "phyCid",
        "apn",
        "username",
        "password",
    ];
    let mut seen = BTreeSet::new();
    for (key, child) in &all {
        if sensitive.contains(key) {
            assert_eq!(*child, &json!("REDACTED"), "{key}");
            seen.insert(*key);
        }
    }
    assert_eq!(seen.len(), sensitive.len(), "{seen:?}");
    for key in ["cellId", "LAC", "RAC", "channel", "chanId", "primScode"] {
        for (found, child) in &all {
            if found == &key {
                assert!(
                    **child == json!(0) || **child == json!("REDACTED"),
                    "{key}: {child}"
                );
            }
        }
    }
    // Real values only in the allowlisted leaves that are not secret.
    let kept: Vec<NetgearLeaf> = NetgearLeaf::ALL
        .iter()
        .copied()
        .filter(|leaf| !leaf.is_secret())
        .collect();
    assert_eq!(kept.len(), 48);
    for leaf in &kept {
        assert!(value.pointer(&pointer(*leaf, 0)).is_some(), "{leaf}");
    }
    for at in outside_pointers() {
        let child = value.pointer(&at).unwrap();
        assert!(
            matches!(child, Value::Null | Value::Bool(false))
                || *child == json!("REDACTED")
                || *child == json!(0)
                || *child == json!({})
                || *child == json!([]),
            "{at}: {child}"
        );
    }
}

/// The directory holds exactly the fixture and its licence sidecar.
#[test]
fn the_router_fixture_directory_holds_exactly_the_fixture() {
    let found: BTreeSet<String> = fs::read_dir(directory())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        found,
        BTreeSet::from([FIXTURE_NAME.to_owned(), format!("{FIXTURE_NAME}.license")])
    );
    assert_eq!(
        fs::read_to_string(directory().join(format!("{FIXTURE_NAME}.license"))).unwrap(),
        "SPDX-License-Identifier: GPL-3.0-or-later\n"
    );
    assert!(fs::read(directory().join(FIXTURE_NAME)).unwrap() == FIXTURE);
}

/// The fixture is named `<general.model>-<general.FWversion>.json` from
/// its own values, in lowercase with `_` written `-`.
#[test]
fn the_fixture_is_named_after_its_model_and_firmware() {
    let value = fixture();
    let text = |leaf: NetgearLeaf| {
        value
            .pointer(&pointer(leaf, 0))
            .and_then(Value::as_str)
            .unwrap()
            .to_owned()
    };
    let name = format!(
        "{}-{}.json",
        text(NetgearLeaf::GeneralModel),
        text(NetgearLeaf::GeneralFirmware)
    )
    .to_lowercase()
    .replace('_', "-");
    assert_eq!(name, FIXTURE_NAME);
}
