// SPDX-License-Identifier: GPL-3.0-or-later

//! The redactor: the walk's other sink. It writes the allowlisted leaves
//! that are not secret as they are (their shapes checked) and every other
//! value as a placeholder of its JSON type, so a capture can hold nothing
//! the parser would not read. An allowlisted value whose shape the walk
//! refuses is withheld (a placeholder) and named, so a capture can record
//! a state whose leaves change form.

use std::fmt;

use serde::Deserializer;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use super::allowlist::{LeafSet, NetgearLeaf};
use super::walk::{Element, Found, KeySeed, LeafValue, Scalar, Sink, walk};
use crate::error::RouterParseError;
use crate::router::digit_runs_within;

/// What a string that is not kept becomes.
const PLACEHOLDER: &[u8] = b"\"REDACTED\"";

/// The longest key written.
const MAX_KEY_BYTES: usize = 64;

/// The longest run of digits in a key written: the M2a capture's longest is
/// three (`5gMcs160MChanList`), and a phone number or an IMEI used as a key
/// has more.
const MAX_KEY_DIGIT_RUN: usize = 3;

/// The longest run of hexadecimal characters (`0-9`, `a-f`, `A-F`) in a key
/// written: the M2a capture's longest is seven (`lastSucceeded`), and a
/// link-layer address without separators (twelve) or a hexadecimal token
/// used as a key has more.
const MAX_KEY_HEX_RUN: usize = 8;

/// A `model.json` answer redacted for a capture by
/// [`redact_netgear_model_json`], the only constructor: a capture written
/// from one holds the redactor's output and nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedModelJson {
    document: Vec<u8>,
    withheld: Vec<RouterParseError>,
}

impl RedactedModelJson {
    /// The redacted document: compact JSON, no trailing newline.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.document
    }

    /// The allowlisted values withheld because the walk refused their
    /// shape, in the document's order: each a
    /// [`RouterParseError::Field`] or [`RouterParseError::Carriers`]
    /// naming the path and the fault, never the value.
    #[must_use]
    pub fn withheld(&self) -> &[RouterParseError] {
        &self.withheld
    }
}

impl fmt::Debug for RedactedModelJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactedModelJson")
            .field("bytes", &self.document.len())
            .field("withheld", &self.withheld)
            .finish()
    }
}

/// Redacts a `model.json` answer for a capture: compact JSON in the
/// answer's key order (no trailing newline) in which
///
/// - every allowlisted leaf that is not secret keeps its value, after the
///   same shape check the parser makes;
/// - the session token, and every value outside the allowlist, becomes a
///   placeholder of its type: a string `"REDACTED"`, a number `0`, a
///   boolean `false`, `null` itself; an object keeps its keys, and an array
///   keeps only its first element, both placeholdered in turn; the carrier
///   list keeps every element;
/// - an allowlisted value whose shape is refused (an empty, null or
///   identifier-shaped text, a number where a string belongs, a carrier
///   list that is not an array, an element of it that is not an object) is
///   withheld: a placeholder of its type as above, an empty string `""`,
///   an array or object `[]` or `{}`; each is named in
///   [`RedactedModelJson::withheld`]. So a capture records a state whose
///   leaves change form (no service, no SIM) instead of failing, and still
///   holds nothing the shape check did not pass.
///
/// Every key written must be a plain name (`[A-Za-z0-9_]`, 1 to 64 bytes,
/// no run of more than three digits or more than eight hexadecimal
/// characters), else `KeyRefused`: a key that is data cannot reach a
/// capture. A repeated allowlisted leaf, a repeated or over-long carrier
/// list and JSON that is not one object are refused as by the parser. On
/// any error nothing is returned.
///
/// The redactor checks no vocabulary, range, role or model, so it can
/// capture an anonymous answer, or a state the parser does not know yet.
pub fn redact_netgear_model_json(body: &[u8]) -> Result<RedactedModelJson, RouterParseError> {
    let mut redactor = Redactor {
        out: Vec::with_capacity(body.len()),
        fault: None,
        withheld: Vec::new(),
    };
    walk(body, LeafSet::Kept, &mut redactor)?;
    Ok(RedactedModelJson {
        document: redactor.out,
        withheld: redactor.withheld,
    })
}

struct Redactor {
    out: Vec<u8>,
    fault: Option<RouterParseError>,
    withheld: Vec<RouterParseError>,
}

impl Redactor {
    /// Writes the comma before a value, unless it is the first of an array
    /// or follows its key.
    fn separate_value(&mut self) {
        if !matches!(self.out.last(), None | Some(b'[' | b':')) {
            self.out.push(b',');
        }
    }

    fn write_key(&mut self, key: &str) -> Result<(), RouterParseError> {
        if !plain_key(key) {
            return Err(RouterParseError::KeyRefused);
        }
        if self.out.last() != Some(&b'{') {
            self.out.push(b',');
        }
        self.out.push(b'"');
        self.out.extend_from_slice(key.as_bytes());
        self.out.extend_from_slice(b"\":");
        Ok(())
    }

    fn write_scalar(&mut self, scalar: Scalar) {
        self.separate_value();
        self.out.extend_from_slice(match scalar {
            Scalar::String => PLACEHOLDER,
            Scalar::Number => b"0",
            Scalar::Bool => b"false",
            Scalar::Null => b"null",
        });
    }

    /// The placeholder of a withheld value: a scalar's, `""` for the empty
    /// string (which holds nothing), an empty array or object.
    fn write_withheld(&mut self, found: Found) {
        match found {
            Found::Scalar(scalar) => self.write_scalar(scalar),
            Found::EmptyString => {
                self.separate_value();
                self.out.extend_from_slice(b"\"\"");
            }
            Found::Array => {
                self.separate_value();
                self.out.extend_from_slice(b"[]");
            }
            Found::Object => {
                self.separate_value();
                self.out.extend_from_slice(b"{}");
            }
        }
    }
}

/// Whether `key` may be written: `[A-Za-z0-9_]`, 1 to 64 bytes, no run of
/// more than three digits or eight hexadecimal characters.
fn plain_key(key: &str) -> bool {
    (1..=MAX_KEY_BYTES).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && digit_runs_within(key, MAX_KEY_DIGIT_RUN)
        && key
            .split(|c: char| !c.is_ascii_hexdigit())
            .all(|run| run.len() <= MAX_KEY_HEX_RUN)
}

/// Writes `text` as a JSON string.
fn write_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            control if u32::from(control) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", u32::from(control)).as_bytes());
            }
            other => {
                let mut buffer = [0; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

impl Sink for Redactor {
    fn leaf(&mut self, _: NetgearLeaf, _: Option<u16>, value: LeafValue) {
        self.separate_value();
        match value {
            LeafValue::Bool(value) => {
                self.out
                    .extend_from_slice(if value { b"true" } else { b"false" })
            }
            LeafValue::Int(value) => self.out.extend_from_slice(value.to_string().as_bytes()),
            LeafValue::Text(text) | LeafValue::Digits(text) => write_string(&mut self.out, &text),
            LeafValue::Line(text) => write_string(&mut self.out, &format!("{text}\n")),
            LeafValue::Secret(_) => self.out.extend_from_slice(PLACEHOLDER),
        }
    }

    /// A refused value is withheld and named; the capture goes on.
    fn refused(&mut self, fault: RouterParseError, found: Found) -> Result<(), RouterParseError> {
        self.write_withheld(found);
        self.withheld.push(fault);
        Ok(())
    }

    fn begin_object(&mut self) {
        self.separate_value();
        self.out.push(b'{');
    }

    fn key(&mut self, key: &str) -> Result<(), RouterParseError> {
        self.write_key(key)
    }

    fn end_object(&mut self) {
        self.out.push(b'}');
    }

    fn begin_carriers(&mut self) {
        self.separate_value();
        self.out.push(b'[');
    }

    fn carrier(&mut self, _: Element) {}

    fn end_carriers(&mut self) {
        self.out.push(b']');
    }

    fn outside<'de, D: Deserializer<'de>>(&mut self, value: D) -> Result<(), D::Error> {
        Placeholder { redactor: self }.deserialize(value)
    }

    fn outside_scalar(&mut self, scalar: Scalar) {
        self.write_scalar(scalar);
    }

    fn outside_seq<'de, A: SeqAccess<'de>>(&mut self, seq: A) -> Result<(), A::Error> {
        Placeholder { redactor: self }.visit_seq(seq)
    }

    fn take_fault(&mut self) -> Option<RouterParseError> {
        self.fault.take()
    }
}

/// Writes a value off the allowlisted paths as a placeholder of its type.
struct Placeholder<'r> {
    redactor: &'r mut Redactor,
}

impl<'de> DeserializeSeed<'de> for Placeholder<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Placeholder<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.redactor.write_scalar(Scalar::Bool);
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.redactor.write_scalar(Scalar::Number);
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.redactor.write_scalar(Scalar::Number);
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.redactor.write_scalar(Scalar::Number);
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        self.redactor.write_scalar(Scalar::String);
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.redactor.write_scalar(Scalar::Null);
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let redactor = self.redactor;
        redactor.separate_value();
        redactor.out.push(b'[');
        if seq
            .next_element_seed(Placeholder {
                redactor: &mut *redactor,
            })?
            .is_some()
        {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
        }
        redactor.out.push(b']');
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let redactor = self.redactor;
        redactor.separate_value();
        redactor.out.push(b'{');
        while let Some(key) = map.next_key_seed(KeySeed)? {
            if let Err(fault) = redactor.write_key(key.as_str()) {
                redactor.fault = Some(fault);
                return Err(de::Error::custom("the router walk stopped"));
            }
            map.next_value_seed(Placeholder {
                redactor: &mut *redactor,
            })?;
        }
        redactor.out.push(b'}');
        Ok(())
    }
}
