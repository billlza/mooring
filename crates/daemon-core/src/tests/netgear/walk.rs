// SPDX-License-Identifier: GPL-3.0-or-later

//! The walk: shapes, JSON faults and their classification, and documents
//! that are not objects or are deeply nested.

use serde_json::{Value, json};

use super::{FIXTURE, field, pointer, spliced, with};
use crate::error::{FieldFaultKind, RouterParseError};
use crate::router::netgear::{
    NetgearLeaf, parse_netgear_model_json, parse_netgear_session, redact_netgear_model_json,
};
use crate::tests::router;

/// One JSON value of every type, labelled.
fn every_json_type() -> Vec<(&'static str, Value)> {
    vec![
        ("string", json!("x")),
        ("integer", json!(1)),
        ("negative integer", json!(-1)),
        ("float", json!(1.5)),
        ("whole float", json!(1.0)),
        ("true", json!(true)),
        ("false", json!(false)),
        ("null", Value::Null),
        ("empty array", json!([])),
        ("array", json!(["x", 1])),
        ("empty object", json!({})),
        ("object", json!({"a": 1})),
    ]
}

/// The result of reading `leaf` replaced by `value`: through the session
/// parse for the token, the status parse otherwise.
fn read_with(leaf: NetgearLeaf, value: Value) -> Result<(), RouterParseError> {
    let body = with(&pointer(leaf, 0), value);
    if leaf == NetgearLeaf::SessionToken {
        parse_netgear_session(&body).map(|_| ())
    } else {
        parse_netgear_model_json(&body).map(|_| ())
    }
}

/// Each shape accepts its JSON type only: a boolean, an integer (not a
/// float, however whole), or a string; every other type is `WrongType`
/// naming the leaf. Containers are skipped whole.
#[test]
fn shapes_refuse_wrong_json_types() {
    use NetgearLeaf as L;
    let cases: [(NetgearLeaf, &[&str], Value); 6] = [
        (L::WifiEnabled, &["true", "false"], json!(false)),
        (
            L::GeneralUptime,
            &["integer", "negative integer"],
            json!(400_000),
        ),
        (L::SimSpn, &["string"], json!("EE")),
        (L::GeneralWebAppVersion, &["string"], json!("M7\n")),
        (L::WwanRxBytes, &["string"], json!("1")),
        (L::SessionToken, &["string"], json!("token")),
    ];
    for (leaf, accepted, valid) in cases {
        assert_eq!(read_with(leaf, valid), Ok(()), "{leaf}");
        for (label, value) in every_json_type() {
            let read = read_with(leaf, value);
            if accepted.contains(&label) {
                assert_ne!(
                    read,
                    Err(field(leaf, None, FieldFaultKind::WrongType)),
                    "{leaf} {label}"
                );
            } else {
                assert_eq!(
                    read,
                    Err(field(leaf, None, FieldFaultKind::WrongType)),
                    "{leaf} {label}"
                );
            }
        }
    }
}

/// What the redactor writes at `at` in `body`, and what it withheld.
fn redacted_at(body: &[u8], at: &str) -> (Value, Vec<RouterParseError>) {
    let redacted = redact_netgear_model_json(body).unwrap();
    let value: Value = serde_json::from_slice(redacted.as_bytes()).unwrap();
    (
        value.pointer(at).unwrap().clone(),
        redacted.withheld().to_vec(),
    )
}

/// A text leaf is printable ASCII within its length, with no run of
/// digits longer than its limit; the redactor checks the same shape
/// before it writes a value and withholds one that fails it (the empty
/// string as `""`), so an identifier never reaches a capture.
#[test]
fn text_shapes_refuse_control_bytes_and_long_digit_runs() {
    use NetgearLeaf as L;
    let spn = pointer(L::SimSpn, 0);
    let fault = field(L::SimSpn, None, FieldFaultKind::InvalidText);
    for bad in [
        "C\u{7}M",
        "C\tM",
        "C\u{7f}M",
        "CMLïnk",
        "",
        &"C".repeat(33),
        "CM123",
    ] {
        let body = with(&spn, json!(bad));
        assert_eq!(
            parse_netgear_model_json(&body).map(|_| ()),
            Err(fault),
            "{bad:?}"
        );
        let placeholder = if bad.is_empty() { "" } else { "REDACTED" };
        assert_eq!(
            redacted_at(&body, &spn),
            (json!(placeholder), vec![fault]),
            "{bad:?}"
        );
    }
    for good in ["CM12", &"C".repeat(32), "O2 UK"] {
        let body = with(&spn, json!(good));
        assert_eq!(redacted_at(&body, &spn), (json!(good), vec![]), "{good:?}");
    }
    // The role may be empty (an anonymous session's may be).
    let role = with(&pointer(L::SessionUserRole, 0), json!(""));
    assert_eq!(
        parse_netgear_model_json(&role),
        Err(RouterParseError::NotAdmin)
    );
    // Firmware versions allow six digits in a row, not seven.
    let firmware = pointer(L::GeneralFirmware, 0);
    assert_eq!(
        redacted_at(&with(&firmware, json!("A123456")), &firmware),
        (json!("A123456"), vec![])
    );
    assert_eq!(
        redacted_at(&with(&firmware, json!("A1234567")), &firmware),
        (
            json!("REDACTED"),
            vec![field(L::GeneralFirmware, None, FieldFaultKind::InvalidText)]
        )
    );
}

/// The web app version is text followed by exactly one line feed, which
/// the parser removes and the redactor keeps (or withholds, as the parser
/// refuses it).
#[test]
fn line_shape_needs_exactly_one_trailing_newline() {
    let leaf = NetgearLeaf::GeneralWebAppVersion;
    let at = pointer(leaf, 0);
    for bad in ["", "x", "\n", "x\n\n", "x\r\n", "x\ny\n", "\nx"] {
        let body = with(&at, json!(bad));
        let fault = field(leaf, None, FieldFaultKind::InvalidText);
        assert_eq!(
            parse_netgear_model_json(&body).map(|_| ()),
            Err(fault),
            "{bad:?}"
        );
        let placeholder = if bad.is_empty() { "" } else { "REDACTED" };
        assert_eq!(
            redacted_at(&body, &at),
            (json!(placeholder), vec![fault]),
            "{bad:?}"
        );
    }
    let body = with(&at, json!("x\n"));
    let status = parse_netgear_model_json(&body).unwrap();
    assert_eq!(status.parts().web_app.as_str(), "x");
    assert_eq!(redacted_at(&body, &at), (json!("x\n"), vec![]));
}

/// Malformed JSON is `Syntax`, JSON cut short is `Truncated`, and a value
/// that is not an object is `NotAnObject`, whatever the bytes; serde_json's
/// messages, which quote the input, never reach an error.
#[test]
fn json_errors_never_quote_the_input() {
    let canary = "CANARYq7Zx";
    for (body, expected) in [
        (format!("{{\"a\": {canary}}}"), RouterParseError::Syntax),
        (
            format!("{{\"a\":\"{canary}\\q\"}}"),
            RouterParseError::Syntax,
        ),
        (format!("{{\"{canary}\" 1}}"), RouterParseError::Syntax),
        (format!("{{\"a\":\"{canary}"), RouterParseError::Truncated),
        (format!("{{\"{canary}\":"), RouterParseError::Truncated),
        (format!("[\"{canary}\"]"), RouterParseError::NotAnObject),
        (format!("\"{canary}\""), RouterParseError::NotAnObject),
        (format!("{{}} \"{canary}\""), RouterParseError::Syntax),
    ] {
        for result in [
            parse_netgear_model_json(body.as_bytes()).map(|_| ()),
            parse_netgear_session(body.as_bytes()).map(|_| ()),
            redact_netgear_model_json(body.as_bytes()).map(|_| ()),
        ] {
            let error = result.unwrap_err();
            assert_eq!(error, expected, "{body}");
            let text = format!("{error} {error:?}");
            assert!(!text.contains(canary), "{text}");
        }
    }
}

/// The fixture cut anywhere is `Truncated`; bytes after the document are
/// `Syntax`, and trailing whitespace is accepted.
#[test]
fn truncated_json_is_truncated_and_trailing_bytes_are_syntax() {
    for cut in [1, 2, 100, FIXTURE.len() / 2, FIXTURE.len() - 3] {
        assert_eq!(
            parse_netgear_model_json(&FIXTURE[..cut]),
            Err(RouterParseError::Truncated),
            "{cut}"
        );
        assert_eq!(
            redact_netgear_model_json(&FIXTURE[..cut]),
            Err(RouterParseError::Truncated),
            "{cut}"
        );
    }
    assert_eq!(
        parse_netgear_model_json(b""),
        Err(RouterParseError::Truncated)
    );
    for tail in ["x", "{}", "]", "0"] {
        let mut body = FIXTURE.to_vec();
        body.extend_from_slice(tail.as_bytes());
        assert_eq!(
            parse_netgear_model_json(&body),
            Err(RouterParseError::Syntax),
            "{tail}"
        );
        assert_eq!(
            redact_netgear_model_json(&body),
            Err(RouterParseError::Syntax),
            "{tail}"
        );
    }
    let mut padded = FIXTURE.to_vec();
    padded.extend_from_slice(b" \r\n\t");
    assert_eq!(parse_netgear_model_json(&padded), Ok(router::status()));
}

/// A document that is not a JSON object is refused before any leaf is
/// looked for.
#[test]
fn a_top_level_array_is_not_an_object() {
    for body in [
        "[]",
        "[{}]",
        "[{\"session\":{}}]",
        "\"x\"",
        "1",
        "1.5",
        "null",
        "true",
    ] {
        let body = body.as_bytes();
        assert_eq!(
            parse_netgear_model_json(body),
            Err(RouterParseError::NotAnObject)
        );
        assert_eq!(
            parse_netgear_session(body).map(|_| ()),
            Err(RouterParseError::NotAnObject)
        );
        assert_eq!(
            redact_netgear_model_json(body),
            Err(RouterParseError::NotAnObject)
        );
    }
}

/// Deep nesting never crashes the walk. The parser skips a value outside
/// the allowlist with serde_json's iterative skip, so even 100,000 nested
/// arrays leave the status as it is; the redactor descends to write
/// placeholders, and serde_json's recursion limit (128) makes a document
/// nested deeper than that a `Syntax` error, with nothing returned.
#[test]
fn deep_nesting_never_crashes_the_walk() {
    let nested = |depth: usize| {
        spliced(
            "\"unreadMsgs\":0,",
            &format!(
                "\"deep\":{}{},\"unreadMsgs\":0,",
                "[".repeat(depth),
                "]".repeat(depth)
            ),
        )
    };
    for depth in [100_000, 129] {
        let body = nested(depth);
        assert_eq!(parse_netgear_model_json(&body), Ok(router::status()));
        assert_eq!(
            redact_netgear_model_json(&body),
            Err(RouterParseError::Syntax)
        );
    }
    let shallow = redact_netgear_model_json(&nested(100)).unwrap();
    let text = String::from_utf8(shallow.as_bytes().to_vec()).unwrap();
    assert!(text.contains(&format!("\"deep\":{}{},", "[".repeat(100), "]".repeat(100))));
}
