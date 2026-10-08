// SPDX-License-Identifier: GPL-3.0-or-later

//! The ordered document tree every emitter renders.
//!
//! Each format writes its proxies as a [`Tree`] whose variable leaves are
//! *slots*. The same tree is rendered three ways, so the structure is written
//! once per format and protocol:
//!
//! - slots resolved to [`Scalar`]s and serialised with serde (sing-box JSON);
//! - slots resolved to [`Scalar`]s and written as block YAML (Clash);
//! - slots replaced by their [`LeafTag`] and written canonically (shapes).

use std::fmt;

use mooring_model::exact::TextSink;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

use crate::text::put_quoted;

/// An ordered tree: mappings keep their key order.
#[derive(Debug)]
pub(crate) enum Tree<S> {
    /// A mapping with fixed keys, in output order.
    Map(Vec<(&'static str, Tree<S>)>),
    /// A sequence.
    List(Vec<Tree<S>>),
    /// A constant fixed by the emitter.
    Lit(Literal),
    /// A variable value.
    Leaf(S),
}

impl<S> Tree<S> {
    /// Replaces every leaf by `f(leaf)`, keeping the structure.
    pub(crate) fn map<T>(self, f: &mut impl FnMut(S) -> T) -> Tree<T> {
        match self {
            Self::Map(entries) => Tree::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, value.map(f)))
                    .collect(),
            ),
            Self::List(items) => Tree::List(items.into_iter().map(|item| item.map(f)).collect()),
            Self::Lit(literal) => Tree::Lit(literal),
            Self::Leaf(slot) => Tree::Leaf(f(slot)),
        }
    }
}

/// A constant written by the emitter itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Literal {
    /// A string.
    Str(&'static str),
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(u16),
}

/// A resolved variable value. Text is held in a zeroizing buffer because
/// some leaves are credentials.
pub(crate) enum Scalar {
    /// A string.
    Text(Zeroizing<String>),
    /// An integer.
    Int(u16),
}

impl Scalar {
    /// Wraps public text.
    pub(crate) fn text(text: impl Into<String>) -> Self {
        Self::Text(Zeroizing::new(text.into()))
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => f.write_str("Text(<redacted>)"),
            Self::Int(value) => write!(f, "Int({value})"),
        }
    }
}

/// The type tag that stands for a variable leaf in a shape: the value
/// domain the emitter guarantees for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum LeafTag {
    /// An [`crate::OutboundTag`].
    OutboundTag,
    /// A `PublicIpv4` in dotted-quad form.
    PublicIpv4,
    /// A Hysteria2 listener port, as an integer.
    Port,
    /// A Hysteria2 client port range `start:end` with `start < end`.
    PortRangeColon,
    /// A Hysteria2 client port range `start-end` with `start < end`.
    PortRangeDash,
    /// A hop interval of 5..=3600 seconds written `<n>s`.
    HopIntervalDuration,
    /// A hop interval of 5..=3600 seconds, as an integer.
    HopIntervalSeconds,
    /// A canonical lowercase hyphenated version 4 UUID.
    Uuid,
    /// A lowercase LDH DNS name.
    DnsName,
    /// An X25519 public key, 43 characters of unpadded base64url.
    X25519PublicKey,
    /// A REALITY short id, 16 lowercase hex characters.
    ShortId,
    /// A 32-byte password, 43 characters of unpadded base64url.
    Password,
    /// A Hysteria2 SNI, `n<16 lowercase hex>.internal`.
    Hy2Sni,
    /// A SHA-256 SPKI pin, 44 characters of padded standard base64.
    SpkiSha256,
    /// A SHA-256 DER pin, 64 lowercase hex characters.
    DerSha256,
}

impl LeafTag {
    /// The stable name written into shapes.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::OutboundTag => "outbound-tag",
            Self::PublicIpv4 => "public-ipv4",
            Self::Port => "port",
            Self::PortRangeColon => "port-range-colon",
            Self::PortRangeDash => "port-range-dash",
            Self::HopIntervalDuration => "hop-interval-duration",
            Self::HopIntervalSeconds => "hop-interval-seconds",
            Self::Uuid => "uuid-v4",
            Self::DnsName => "dns-name",
            Self::X25519PublicKey => "x25519-public-key",
            Self::ShortId => "short-id",
            Self::Password => "password",
            Self::Hy2Sni => "hy2-sni",
            Self::SpkiSha256 => "spki-sha256",
            Self::DerSha256 => "der-sha256",
        }
    }
}

impl Serialize for Literal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match *self {
            Self::Str(text) => serializer.serialize_str(text),
            Self::Bool(value) => serializer.serialize_bool(value),
            Self::Int(value) => serializer.serialize_u16(value),
        }
    }
}

impl Serialize for Scalar {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(text) => serializer.serialize_str(text),
            Self::Int(value) => serializer.serialize_u16(*value),
        }
    }
}

impl<L: Serialize> Serialize for Tree<L> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
            Self::List(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Lit(literal) => literal.serialize(serializer),
            Self::Leaf(leaf) => leaf.serialize(serializer),
        }
    }
}

/// Writes a literal as a JSON (and YAML flow) scalar.
pub(crate) fn put_literal(out: &mut dyn TextSink, literal: Literal) {
    match literal {
        Literal::Str(text) => put_quoted(out, text),
        Literal::Bool(true) => out.put("true"),
        Literal::Bool(false) => out.put("false"),
        Literal::Int(value) => out.put(&value.to_string()),
    }
}

/// Writes a shape tree canonically: JSON syntax without whitespace, with
/// each leaf written as `<tag-name>`. Literals are JSON values and keys are
/// JSON strings, so a tag can never be confused with a literal.
pub(crate) fn put_canonical(out: &mut dyn TextSink, tree: &Tree<LeafTag>) {
    match tree {
        Tree::Map(entries) => {
            out.put("{");
            for (position, (key, value)) in entries.iter().enumerate() {
                if position > 0 {
                    out.put(",");
                }
                put_quoted(out, key);
                out.put(":");
                put_canonical(out, value);
            }
            out.put("}");
        }
        Tree::List(items) => {
            out.put("[");
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.put(",");
                }
                put_canonical(out, item);
            }
            out.put("]");
        }
        Tree::Lit(literal) => put_literal(out, *literal),
        Tree::Leaf(tag) => {
            out.put("<");
            out.put(tag.name());
            out.put(">");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Tree<LeafTag> {
        Tree::Map(vec![
            ("type", Tree::Lit(Literal::Str("vless"))),
            ("server", Tree::Leaf(LeafTag::PublicIpv4)),
            (
                "ports",
                Tree::List(vec![Tree::Leaf(LeafTag::PortRangeColon)]),
            ),
            ("tls", Tree::Lit(Literal::Bool(true))),
            ("port", Tree::Lit(Literal::Int(443))),
            ("empty", Tree::Map(Vec::new())),
        ])
    }

    #[test]
    fn canonical_form_distinguishes_tags_from_literals() {
        let mut out = String::new();
        put_canonical(&mut out, &sample());
        assert_eq!(
            out,
            r#"{"type":"vless","server":<public-ipv4>,"ports":[<port-range-colon>],"tls":true,"port":443,"empty":{}}"#
        );
    }

    #[test]
    fn map_keeps_structure_and_order() {
        let mut count = 0;
        let resolved = sample().map(&mut |tag: LeafTag| {
            count += 1;
            Scalar::text(tag.name())
        });
        assert_eq!(count, 2);
        let json = serde_json::to_string(&resolved).unwrap();
        assert_eq!(
            json,
            r#"{"type":"vless","server":"public-ipv4","ports":["port-range-colon"],"tls":true,"port":443,"empty":{}}"#
        );
        assert_eq!(format!("{:?}", Scalar::text("secret")), "Text(<redacted>)");
        assert_eq!(format!("{:?}", Scalar::Int(7)), "Int(7)");
    }

    #[test]
    fn leaf_tag_names_are_distinct() {
        let tags = [
            LeafTag::OutboundTag,
            LeafTag::PublicIpv4,
            LeafTag::Port,
            LeafTag::PortRangeColon,
            LeafTag::PortRangeDash,
            LeafTag::HopIntervalDuration,
            LeafTag::HopIntervalSeconds,
            LeafTag::Uuid,
            LeafTag::DnsName,
            LeafTag::X25519PublicKey,
            LeafTag::ShortId,
            LeafTag::Password,
            LeafTag::Hy2Sni,
            LeafTag::SpkiSha256,
            LeafTag::DerSha256,
        ];
        let names: std::collections::BTreeSet<_> = tags.iter().map(|tag| tag.name()).collect();
        assert_eq!(names.len(), tags.len());
        assert!(names.iter().all(|name| {
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-' || b.is_ascii_digit())
        }));
    }
}
