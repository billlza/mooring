// SPDX-License-Identifier: GPL-3.0-or-later

//! The redactor: the fixture is its fixed point; it keeps exactly the
//! allowlisted leaves that are not secret, writes placeholders by type in
//! the input's key order, withholds (and names) allowlisted values whose
//! shape is refused, identifier-shaped ones among them, and refuses keys
//! that are data.

use proptest::prelude::*;
use serde_json::{Value, json};

use super::parse::outside_pointers;
use super::{FIXTURE, edited, field, fixture, pointer, with};
use crate::error::{CarrierFaultKind, FieldFaultKind, RouterParseError};
use crate::router::netgear::{NetgearLeaf, redact_netgear_model_json};

/// The redaction of a document whose allowlisted values all pass their
/// shapes (so nothing is withheld), as text.
fn redact(body: &[u8]) -> Result<String, RouterParseError> {
    redact_netgear_model_json(body).map(|redacted| {
        assert_eq!(redacted.withheld(), [], "nothing is withheld");
        String::from_utf8(redacted.as_bytes().to_vec()).unwrap()
    })
}

/// The fixture is what the redactor writes for it, plus one newline: the
/// committed capture holds nothing the shipped redactor would not keep.
#[test]
fn the_fixture_is_a_fixed_point_of_the_redactor() {
    let mut redacted = redact(FIXTURE).unwrap().into_bytes();
    redacted.push(b'\n');
    assert!(redacted == FIXTURE, "the fixture is not a fixed point");
}

/// With a distinct value in every allowlisted leaf, the redactor keeps a
/// leaf's value exactly when it is allowlisted and not secret: the token
/// becomes a placeholder.
#[test]
fn the_redactor_keeps_exactly_the_non_secret_allowlist() {
    let token = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P";
    let body = with(&pointer(NetgearLeaf::SessionToken, 0), json!(token));
    let input: Value = serde_json::from_slice(&body).unwrap();
    let text = redact(&body).unwrap();
    assert!(!text.contains(token));
    let output: Value = serde_json::from_str(&text).unwrap();
    for leaf in NetgearLeaf::ALL.iter().copied() {
        let at = pointer(leaf, 0);
        let kept = output.pointer(&at) == input.pointer(&at);
        assert_eq!(kept, !leaf.is_secret(), "{leaf}");
    }
    assert_eq!(
        output.pointer(&pointer(NetgearLeaf::SessionToken, 0)),
        Some(&json!("REDACTED"))
    );
    // Every leaf that is not allowlisted is a placeholder.
    for at in outside_pointers() {
        let value = output.pointer(&at).unwrap();
        assert!(
            matches!(value, Value::Null | Value::Bool(false))
                || *value == json!("REDACTED")
                || *value == json!(0)
                || *value == json!({})
                || *value == json!([]),
            "{at}: {value}"
        );
    }
}

/// Every value off the allowlisted paths becomes a placeholder of its
/// type; objects keep their keys, arrays their first element, both in
/// turn placeholdered.
#[test]
fn the_redactor_writes_placeholders_by_type() {
    let body = br#"{"a":"text","b":12,"c":-2.5,"d":true,"e":false,"f":null,"g":{},"h":[],
        "i":{"j":["x",2],"k":{"l":1e300}},"m":[{"n":"v"},{"o":1}],"p":"\u0000"}"#;
    assert_eq!(
        redact(body).unwrap(),
        r#"{"a":"REDACTED","b":0,"c":0,"d":false,"e":false,"f":null,"g":{},"h":[],"i":{"j":["REDACTED"],"k":{"l":0}},"m":[{"n":"REDACTED"}],"p":"REDACTED"}"#
    );
    // An allowlisted path whose value is not an object is a placeholder
    // too.
    assert_eq!(
        redact(br#"{"wwan":"x","sms":[{"unreadMsgs":3},{}],"ra":7,"wifi":null,"general":true}"#)
            .unwrap(),
        r#"{"wwan":"REDACTED","sms":[{"unreadMsgs":0}],"ra":0,"wifi":null,"general":false}"#
    );
}

/// Arrays keep only their first element, except the carrier list, which
/// keeps every element (its leaves that are not allowlisted placeholdered).
#[test]
fn arrays_keep_their_first_element_except_the_carriers() {
    let body = br#"{"sms":{"msgs":[{"text":"meet at 9","sender":"+447700900123"},{"text":"second"}],"unreadMsgs":1},
        "wwan":{"lteBandInfo":[{"isPcc":true,"band":3,"dlBandwidth":"20MHz","phyCid":"417","channel":1617},
        {"isPcc":false,"band":20,"dlBandwidth":"10MHz"},{}]}}"#;
    assert_eq!(
        redact(body).unwrap(),
        concat!(
            r#"{"sms":{"msgs":[{"text":"REDACTED","sender":"REDACTED"}],"unreadMsgs":1},"#,
            r#""wwan":{"lteBandInfo":[{"isPcc":true,"band":3,"dlBandwidth":"20MHz","phyCid":"REDACTED","channel":0},"#,
            r#"{"isPcc":false,"band":20,"dlBandwidth":"10MHz"},{}]}}"#
        )
    );
}

/// The redactor writes keys in the answer's order, so a capture reads as
/// the device's document.
#[test]
fn the_redactor_preserves_key_order() {
    assert_eq!(
        redact(
            br#"{"z":1,"a":{"y":"s","b":true},"wifi":{"status":"Off","SSID":"x","enabled":false}}"#
        )
        .unwrap(),
        r#"{"z":0,"a":{"y":"REDACTED","b":false},"wifi":{"status":"Off","SSID":"REDACTED","enabled":false}}"#
    );
    let sorted = redact(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
    let in_order = redact(FIXTURE).unwrap();
    assert_ne!(sorted, in_order);
    assert_eq!(
        serde_json::from_str::<Value>(&sorted).unwrap(),
        serde_json::from_str::<Value>(&in_order).unwrap()
    );
}

/// A kept leaf holding an identifier is withheld: the capture holds a
/// placeholder there, and the leaf is named, never the value.
#[test]
fn the_redactor_withholds_identifier_shaped_kept_values() {
    for (leaf, value) in [
        (NetgearLeaf::SimSpn, json!("356938035643809")),
        (NetgearLeaf::WwanNetworkName, json!("+447700900123")),
        (NetgearLeaf::GeneralFirmware, json!("8944110068256270054")),
        (NetgearLeaf::PlmnMnc, json!("2343012345")),
    ] {
        let at = pointer(leaf, 0);
        let redacted = redact_netgear_model_json(&with(&at, value.clone())).unwrap();
        let expected = field(leaf, None, FieldFaultKind::InvalidText);
        assert_eq!(redacted.withheld(), [expected], "{leaf}");
        let output: Value = serde_json::from_slice(redacted.as_bytes()).unwrap();
        assert_eq!(output.pointer(&at), Some(&json!("REDACTED")), "{leaf}");
        // Everything else is the fixture's redaction.
        let mut baseline = fixture();
        *baseline.pointer_mut(&at).unwrap() = json!("REDACTED");
        assert_eq!(output, baseline, "{leaf}");
        let digits = value.as_str().unwrap().trim_start_matches('+');
        let text = String::from_utf8(redacted.as_bytes().to_vec()).unwrap();
        assert!(!text.contains(digits), "{leaf}");
        assert!(!format!("{redacted:?} {expected}").contains(digits));
    }
}

/// A kept value whose shape is refused, as a state the parser does not
/// know would bring it (an empty or null reading, a number where text
/// belongs, a carrier list that is no longer an array), is withheld by
/// type, the empty string kept as `""`, and named in document order; the
/// capture goes on. The parser refuses each of them.
#[test]
fn the_redactor_withholds_refused_values_by_type() {
    let body = br#"{"sim":{"SPN":""},"wwan":{"registerNetworkDisplay":null,"signalStrength":{"rsrp":null,"rsrq":-17},"lteBandInfo":"","currentPSserviceType":{"k":"v"}},"general":{"devTemperature":35.5,"FWversion":["x"]},"power":{"charging":"yes"},"wifi":{"status":7}}"#;
    let redacted = redact_netgear_model_json(body).unwrap();
    assert_eq!(
        String::from_utf8(redacted.as_bytes().to_vec()).unwrap(),
        r#"{"sim":{"SPN":""},"wwan":{"registerNetworkDisplay":null,"signalStrength":{"rsrp":null,"rsrq":-17},"lteBandInfo":"","currentPSserviceType":{}},"general":{"devTemperature":0,"FWversion":[]},"power":{"charging":"REDACTED"},"wifi":{"status":0}}"#
    );
    assert_eq!(
        redacted.withheld(),
        [
            field(NetgearLeaf::SimSpn, None, FieldFaultKind::InvalidText),
            field(
                NetgearLeaf::WwanNetworkName,
                None,
                FieldFaultKind::WrongType
            ),
            field(NetgearLeaf::SignalRsrp, None, FieldFaultKind::WrongType),
            RouterParseError::Carriers {
                fault: CarrierFaultKind::NotAnArray
            },
            field(
                NetgearLeaf::WwanDataService,
                None,
                FieldFaultKind::WrongType
            ),
            field(
                NetgearLeaf::GeneralTemperature,
                None,
                FieldFaultKind::WrongType
            ),
            field(
                NetgearLeaf::GeneralFirmware,
                None,
                FieldFaultKind::WrongType
            ),
            field(
                NetgearLeaf::BatteryCharging,
                None,
                FieldFaultKind::WrongType
            ),
            field(NetgearLeaf::WifiStatus, None, FieldFaultKind::WrongType),
        ]
    );
    // A carrier that is not an object is withheld in place; the other
    // elements are kept.
    let carriers =
        br#"{"wwan":{"lteBandInfo":[{"isPcc":true,"band":3},"356938035643809",[1],{}]}}"#;
    let redacted = redact_netgear_model_json(carriers).unwrap();
    assert_eq!(
        String::from_utf8(redacted.as_bytes().to_vec()).unwrap(),
        r#"{"wwan":{"lteBandInfo":[{"isPcc":true,"band":3},"REDACTED",[],{}]}}"#
    );
    let element = RouterParseError::Carriers {
        fault: CarrierFaultKind::ElementNotAnObject,
    };
    assert_eq!(redacted.withheld(), [element, element]);
    // The parser refuses what the redactor withholds.
    for edit in [
        (pointer(NetgearLeaf::SimSpn, 0), json!("")),
        (pointer(NetgearLeaf::SignalRsrp, 0), Value::Null),
        (pointer(NetgearLeaf::GeneralTemperature, 0), json!(35.5)),
        ("/wwan/lteBandInfo".to_owned(), json!("")),
    ] {
        let body = with(&edit.0, edit.1.clone());
        assert!(
            crate::router::netgear::parse_netgear_model_json(&body).is_err(),
            "{edit:?}"
        );
        assert_eq!(
            redact_netgear_model_json(&body).unwrap().withheld().len(),
            1,
            "{edit:?}"
        );
    }
}

/// A key that is not a plain name is refused wherever it is, so a key that
/// is data (a link-layer address, a phone number, a long identifier) never
/// reaches a capture.
#[test]
fn the_redactor_refuses_keys_that_are_data() {
    let long = "k".repeat(65);
    for key in [
        "aa:bb:cc:dd:ee:ff",
        "aabbccddeeff",
        "a1b2c3d4e5f6",
        "token_abcdefabcd",
        "447700900123",
        "k1234",
        long.as_str(),
        "",
        "a-b",
        "a b",
        "clé",
    ] {
        let key_json = serde_json::to_string(key).unwrap();
        for body in [
            format!("{{{key_json}:1}}"),
            format!("{{\"wwan\":{{{key_json}:1}}}}"),
            format!("{{\"x\":{{{key_json}:\"v\"}}}}"),
            format!("{{\"x\":[{{{key_json}:\"v\"}},{{}}]}}"),
            format!("{{\"wwan\":{{\"lteBandInfo\":[{{{key_json}:1}},{{}}]}}}}"),
        ] {
            assert_eq!(
                redact(body.as_bytes()),
                Err(RouterParseError::KeyRefused),
                "{body}"
            );
        }
    }
    // A key that is only skipped (after an array's first element) is
    // never written, so it is not checked.
    assert_eq!(
        redact(br#"{"x":[{},{"aa:bb:cc:dd:ee:ff":1}]}"#).unwrap(),
        r#"{"x":[{}]}"#
    );
    let longest = "k".repeat(64);
    for key in [
        "5gMcs160MChanList",
        "lastSucceeded",
        "deadbeef",
        "a_1",
        "ABC123de",
        longest.as_str(),
    ] {
        let body = format!("{{\"{key}\":1}}");
        assert_eq!(redact(body.as_bytes()).unwrap(), format!("{{\"{key}\":0}}"));
    }
    // The parser does not write keys, so it does not refuse them.
    let body = edited(|value| {
        value
            .as_object_mut()
            .unwrap()
            .insert("aa:bb:cc:dd:ee:ff".to_owned(), json!(1));
    });
    assert!(crate::router::netgear::parse_netgear_model_json(&body).is_ok());
}

/// A value of the same JSON type as the one it replaces.
fn same_type(original: &Value) -> BoxedStrategy<Value> {
    match original {
        Value::String(_) => ".{0,24}".prop_map(Value::String).boxed(),
        Value::Number(_) => prop_oneof![
            any::<i64>().prop_map(Value::from),
            any::<u64>().prop_map(Value::from),
            any::<f64>()
                .prop_filter("finite", |value| value.is_finite())
                .prop_map(Value::from),
        ]
        .boxed(),
        Value::Bool(_) => any::<bool>().prop_map(Value::Bool).boxed(),
        Value::Null | Value::Array(_) | Value::Object(_) => Just(original.clone()).boxed(),
    }
}

fn outside_replacement() -> impl Strategy<Value = (String, Value)> {
    let fixture = fixture();
    let pointers = outside_pointers();
    any::<prop::sample::Index>().prop_flat_map(move |index| {
        let at = pointers[index.index(pointers.len())].clone();
        let original = fixture.pointer(&at).unwrap().clone();
        same_type(&original).prop_map(move |value| (at.clone(), value))
    })
}

proptest! {
    /// Replacing a leaf off the allowlisted paths by another value of its
    /// type leaves the capture unchanged: no outside value reaches it.
    #[test]
    fn redaction_does_not_depend_on_outside_values((at, value) in outside_replacement()) {
        let baseline = redact(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        prop_assert_eq!(redact(&with(&at, value)).unwrap(), baseline);
    }
}
