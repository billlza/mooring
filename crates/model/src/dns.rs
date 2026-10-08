// SPDX-License-Identifier: GPL-3.0-or-later

//! Lowercase ASCII LDH DNS names.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ModelError;

/// The maximum length of a DNS name in presentation form, without a trailing dot.
pub const MAX_DNS_NAME_LEN: usize = 253;
/// The maximum length of one DNS label.
pub const MAX_DNS_LABEL_LEN: usize = 63;

/// The LDH rule a rejected DNS name breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsNameRule {
    /// The name is empty.
    Empty,
    /// The name is longer than 253 bytes.
    TooLong,
    /// The name ends with a dot; names are written without the root label.
    TrailingDot,
    /// The name has an empty label.
    EmptyLabel,
    /// A label is longer than 63 bytes.
    LabelTooLong,
    /// The name contains an uppercase letter; names are stored in lowercase.
    Uppercase,
    /// The name contains a byte outside `a-z`, `0-9`, `-` and `.`.
    InvalidCharacter,
    /// A label starts or ends with a hyphen.
    HyphenAtLabelEdge,
    /// The last label is all digits, which reads as an IPv4 literal.
    NumericTopLabel,
}

impl fmt::Display for DnsNameRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the name is empty",
            Self::TooLong => "the name is longer than 253 bytes",
            Self::TrailingDot => "the name ends with a dot",
            Self::EmptyLabel => "the name has an empty label",
            Self::LabelTooLong => "a label is longer than 63 bytes",
            Self::Uppercase => "the name contains uppercase letters",
            Self::InvalidCharacter => "the name contains a character outside a-z, 0-9, '-' and '.'",
            Self::HyphenAtLabelEdge => "a label starts or ends with '-'",
            Self::NumericTopLabel => "the last label is all digits",
        })
    }
}

/// A DNS name of lowercase ASCII LDH labels, at most 253 bytes, without a
/// trailing dot, whose last label is not all digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsName(String);

impl DnsName {
    /// Validates `text` as a DNS name.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        check(text).map_err(|rule| ModelError::InvalidDnsName { rule })?;
        Ok(Self(text.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The labels, from leftmost to rightmost.
    pub fn labels(&self) -> std::str::Split<'_, char> {
        self.0.split('.')
    }

    /// The rightmost label, such as `net` in `www.example.net`.
    #[must_use]
    pub fn top_label(&self) -> &str {
        // A single-label name is its own top label.
        self.0.rsplit_once('.').map_or(&self.0, |(_, top)| top)
    }

    /// Whether this name equals `domain` or is a subdomain of it.
    #[must_use]
    pub fn is_within(&self, domain: &str) -> bool {
        match self.0.strip_suffix(domain) {
            Some("") => true,
            Some(prefix) => prefix.ends_with('.'),
            None => false,
        }
    }
}

fn check(text: &str) -> Result<(), DnsNameRule> {
    if text.is_empty() {
        return Err(DnsNameRule::Empty);
    }
    if text.len() > MAX_DNS_NAME_LEN {
        return Err(DnsNameRule::TooLong);
    }
    if text.ends_with('.') {
        return Err(DnsNameRule::TrailingDot);
    }
    let mut last = "";
    for label in text.split('.') {
        check_label(label)?;
        last = label;
    }
    if last.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DnsNameRule::NumericTopLabel);
    }
    Ok(())
}

fn check_label(label: &str) -> Result<(), DnsNameRule> {
    if label.is_empty() {
        return Err(DnsNameRule::EmptyLabel);
    }
    if label.len() > MAX_DNS_LABEL_LEN {
        return Err(DnsNameRule::LabelTooLong);
    }
    for byte in label.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'-' => {}
            b'A'..=b'Z' => return Err(DnsNameRule::Uppercase),
            _ => return Err(DnsNameRule::InvalidCharacter),
        }
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(DnsNameRule::HyphenAtLabelEdge);
    }
    Ok(())
}

impl TryFrom<String> for DnsName {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        check(&text).map_err(|rule| ModelError::InvalidDnsName { rule })?;
        Ok(Self(text))
    }
}

impl From<DnsName> for String {
    fn from(name: DnsName) -> Self {
        name.0
    }
}

impl FromStr for DnsName {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rule(text: &str) -> Option<DnsNameRule> {
        match DnsName::parse(text) {
            Ok(_) => None,
            Err(ModelError::InvalidDnsName { rule }) => Some(rule),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn each_rule_is_enforced() {
        assert_eq!(rule("www.example.net"), None);
        assert_eq!(rule("a"), None);
        assert_eq!(rule("xn--bcher-kva.example"), None);
        assert_eq!(rule(""), Some(DnsNameRule::Empty));
        assert_eq!(rule("example.net."), Some(DnsNameRule::TrailingDot));
        assert_eq!(rule("www..example"), Some(DnsNameRule::EmptyLabel));
        assert_eq!(rule(".example"), Some(DnsNameRule::EmptyLabel));
        assert_eq!(rule("Example.net"), Some(DnsNameRule::Uppercase));
        assert_eq!(rule("ex_ample.net"), Some(DnsNameRule::InvalidCharacter));
        assert_eq!(rule("exämple.net"), Some(DnsNameRule::InvalidCharacter));
        assert_eq!(rule("*.example.net"), Some(DnsNameRule::InvalidCharacter));
        assert_eq!(rule("-a.example"), Some(DnsNameRule::HyphenAtLabelEdge));
        assert_eq!(rule("a-.example"), Some(DnsNameRule::HyphenAtLabelEdge));
        assert_eq!(rule("1.2.3.4"), Some(DnsNameRule::NumericTopLabel));
        assert_eq!(rule("host.123"), Some(DnsNameRule::NumericTopLabel));
        assert_eq!(rule("host.1a"), None);
    }

    #[test]
    fn length_bounds_are_exact() {
        let label63 = "a".repeat(63);
        assert_eq!(rule(&format!("{label63}.net")), None);
        assert_eq!(
            rule(&format!("{}.net", "a".repeat(64))),
            Some(DnsNameRule::LabelTooLong)
        );
        // 4 labels of 61 bytes + 3 dots = 247; add ".abcde" for 253 exactly.
        let base = vec!["b".repeat(61); 4].join(".");
        let at_limit = format!("{base}.abcde");
        assert_eq!(at_limit.len(), 253);
        assert_eq!(rule(&at_limit), None);
        let over = format!("{base}.abcdef");
        assert_eq!(over.len(), 254);
        assert_eq!(rule(&over), Some(DnsNameRule::TooLong));
    }

    #[test]
    fn is_within_matches_whole_labels_only() {
        let name = DnsName::parse("cdn.dl.google.com").unwrap();
        assert!(name.is_within("google.com"));
        assert!(name.is_within("cdn.dl.google.com"));
        assert!(!name.is_within("e.com"));
        assert!(
            !DnsName::parse("notgoogle.com")
                .unwrap()
                .is_within("google.com")
        );
    }

    #[test]
    fn serde_rejects_invalid_names() {
        let name: DnsName = serde_json::from_str("\"target.mooring.test\"").unwrap();
        assert_eq!(
            serde_json::to_string(&name).unwrap(),
            "\"target.mooring.test\""
        );
        assert!(serde_json::from_str::<DnsName>("\"Target.mooring.test\"").is_err());
        assert!(serde_json::from_str::<DnsName>("\"target.mooring.test.\"").is_err());
    }

    proptest! {
        #[test]
        fn generated_ldh_names_are_accepted(
            labels in proptest::collection::vec("[a-z0-9]([a-z0-9-]{0,20}[a-z0-9])?", 1..5),
            top in "[a-z][a-z0-9]{0,9}",
        ) {
            let text = format!("{}.{top}", labels.join("."));
            let name = DnsName::parse(&text).unwrap();
            prop_assert_eq!(name.as_str(), text.as_str());
            prop_assert_eq!(name.labels().count(), labels.len() + 1);
        }

        #[test]
        fn names_with_bytes_outside_ldh_are_rejected(
            prefix in "[a-z]{1,5}",
            bad in "[^a-z0-9.-]",
            suffix in "[a-z]{1,5}",
        ) {
            let name = format!("{prefix}{bad}{suffix}.net");
            prop_assert!(DnsName::parse(&name).is_err());
        }
    }
}
