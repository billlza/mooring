// SPDX-License-Identifier: GPL-3.0-or-later

//! The MR7450 allowlist parser and redactor against the M2a fixture,
//! `contract/router-fixtures/mr7450-ntgx75-10.04.43.01.json`.
//!
//! The fixture was captured on 2026-10-13 from the MR7450 (firmware
//! NTGX75_10.04.43.01, web app M7_GENERIC_v07.01.81.00, API 2.0) through
//! `GET /api/model.json?internalapi=1` in the operator's logged-in browser
//! session. An allowlist redactor ran inside the page, so the raw document
//! never left the browser: allowlisted values were kept, every other leaf
//! was replaced by a placeholder of its type (strings `"REDACTED"`,
//! numbers `0`, booleans `false`), and arrays were cut to their first
//! element except `wwan.lteBandInfo`. Placeholders are not readings. The
//! SIM was a CMLink practice SIM on EE's network (MCC 234, MNC 30), not the
//! exit line. On commit the capture was re-redacted with
//! `redact_netgear_model_json`, so the fixture is a fixed point of the
//! shipped redactor (`docs/measurements/M2.md` lists what that replaced).

mod allowlist;
mod fixture;
mod parse;
mod redact;
mod walk;

use serde_json::Value;

use crate::error::{FieldFaultKind, RouterParseError};
use crate::router::netgear::{NetgearLeaf, Segment};

/// The committed fixture.
pub(crate) const FIXTURE: &[u8] =
    include_bytes!("../../../../../contract/router-fixtures/mr7450-ntgx75-10.04.43.01.json");

/// The fixture as a JSON value.
pub(crate) fn fixture() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

/// The JSON pointer of `leaf`, in carrier `element` if it is in the
/// carrier list.
pub(crate) fn pointer(leaf: NetgearLeaf, element: u16) -> String {
    leaf.segments()
        .iter()
        .map(|segment| match segment {
            Segment::Key(key) => format!("/{key}"),
            Segment::Each => format!("/{element}"),
        })
        .collect()
}

/// The element a fixture leaf is in: the first carrier for a carrier leaf.
pub(crate) fn element_of(leaf: NetgearLeaf) -> Option<u16> {
    leaf.segments().contains(&Segment::Each).then_some(0)
}

/// The fixture after `edit`, encoded (keys in sorted order).
pub(crate) fn edited(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value = fixture();
    edit(&mut value);
    serde_json::to_vec(&value).unwrap()
}

/// The fixture with the value at `pointer` replaced.
pub(crate) fn with(pointer: &str, replacement: Value) -> Vec<u8> {
    edited(|value| {
        *value
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("the fixture has {pointer}")) = replacement;
    })
}

/// The fixture without the key at `pointer`.
pub(crate) fn without(pointer: &str) -> Vec<u8> {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    edited(|value| {
        let removed = value
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .and_then(|object| object.remove(key));
        assert!(removed.is_some(), "the fixture has {pointer}");
    })
}

/// The fixture's bytes with `from` replaced by `to` once (for documents a
/// JSON value cannot hold, such as a repeated key).
pub(crate) fn spliced(from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(FIXTURE).unwrap();
    assert_eq!(text.matches(from).count(), 1, "{from}");
    text.replacen(from, to, 1).into_bytes()
}

/// A field error.
pub(crate) const fn field(
    leaf: NetgearLeaf,
    element: Option<u16>,
    fault: FieldFaultKind,
) -> RouterParseError {
    RouterParseError::Field {
        leaf,
        element,
        fault,
    }
}
