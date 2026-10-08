// SPDX-License-Identifier: GPL-3.0-or-later

//! Outbound tags: the sing-box `tag` and the Clash `name` of one proxy.

use std::fmt;

use mooring_model::NodeId;
use mooring_model::ports::ListenerIdx;

use crate::error::{ExportError, TagRule};

/// An outbound tag of lowercase ASCII letters, digits and inner hyphens.
///
/// This is a strict subset of what CFM accepts (non-empty, at most 128
/// bytes, no edge whitespace, no control characters; see
/// `docs/cfm-contract.md`), and every such tag is a valid YAML double-quoted
/// scalar without escapes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutboundTag(String);

impl OutboundTag {
    /// The longest accepted tag, in bytes.
    pub const MAX_LEN: usize = 64;

    /// Validates `text` as a tag.
    pub fn parse(text: &str) -> Result<Self, ExportError> {
        check(text).map_err(|rule| ExportError::InvalidTag { rule })?;
        Ok(Self(text.to_owned()))
    }

    /// The tag of a node's VLESS+REALITY outbound: `<node>-reality`.
    #[must_use]
    pub fn reality(node: &NodeId) -> Self {
        Self(format!("{node}-reality"))
    }

    /// The tag of a node's Hysteria2 outbound for one listener: `<node>-hy2`
    /// for listener 0 and `<node>-hy2-<n>` for listener `n`.
    #[must_use]
    pub fn hysteria2(node: &NodeId, listener: ListenerIdx) -> Self {
        if listener == ListenerIdx::FIRST {
            Self(format!("{node}-hy2"))
        } else {
            Self(format!("{node}-hy2-{listener}"))
        }
    }

    /// The tag as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OutboundTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn check(text: &str) -> Result<(), TagRule> {
    if text.is_empty() {
        return Err(TagRule::Empty);
    }
    if text.len() > OutboundTag::MAX_LEN {
        return Err(TagRule::TooLong);
    }
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(TagRule::InvalidCharacter);
    }
    if text.starts_with('-') || text.ends_with('-') {
        return Err(TagRule::HyphenAtEdge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::error::ExportErrorKind;

    fn rule(text: &str) -> TagRule {
        match OutboundTag::parse(text) {
            Err(ExportError::InvalidTag { rule }) => rule,
            other => panic!("{text:?} should be rejected, got {other:?}"),
        }
    }

    #[test]
    fn tag_rules() {
        assert_eq!(rule(""), TagRule::Empty);
        assert_eq!(
            rule(&"a".repeat(OutboundTag::MAX_LEN + 1)),
            TagRule::TooLong
        );
        assert_eq!(rule("Lon1"), TagRule::InvalidCharacter);
        assert_eq!(rule("lon1 reality"), TagRule::InvalidCharacter);
        assert_eq!(rule("lon1_reality"), TagRule::InvalidCharacter);
        assert_eq!(rule("-lon1"), TagRule::HyphenAtEdge);
        assert_eq!(rule("lon1-"), TagRule::HyphenAtEdge);
        let longest = "a".repeat(OutboundTag::MAX_LEN);
        assert_eq!(OutboundTag::parse(&longest).unwrap().as_str(), longest);
        assert_eq!(
            OutboundTag::parse("probe-lon1-reality-out")
                .unwrap()
                .to_string(),
            "probe-lon1-reality-out"
        );
        assert_eq!(
            OutboundTag::parse("").unwrap_err().kind(),
            ExportErrorKind::InvalidTag
        );
    }

    #[test]
    fn node_tags_are_valid_tags() {
        let node = NodeId::parse("abcdefghijkl").unwrap();
        for tag in [
            OutboundTag::reality(&node),
            OutboundTag::hysteria2(&node, ListenerIdx::FIRST),
            OutboundTag::hysteria2(&node, ListenerIdx::new(1)),
            OutboundTag::hysteria2(&node, ListenerIdx::new(u8::MAX)),
        ] {
            assert_eq!(OutboundTag::parse(tag.as_str()).unwrap(), tag);
        }
        let lon1 = NodeId::parse("lon1").unwrap();
        assert_eq!(OutboundTag::reality(&lon1).as_str(), "lon1-reality");
        assert_eq!(
            OutboundTag::hysteria2(&lon1, ListenerIdx::FIRST).as_str(),
            "lon1-hy2"
        );
        assert_eq!(
            OutboundTag::hysteria2(&lon1, ListenerIdx::new(1)).as_str(),
            "lon1-hy2-1"
        );
    }

    proptest! {
        #[test]
        fn accepted_tags_meet_the_cfm_tag_rule(text in "[a-z0-9-]{0,70}") {
            if let Ok(tag) = OutboundTag::parse(&text) {
                // CFM: non-empty, at most 128 bytes, no edge whitespace, no
                // control characters.
                prop_assert!(!tag.as_str().is_empty() && tag.as_str().len() <= 128);
                prop_assert_eq!(tag.as_str().trim(), tag.as_str());
                prop_assert!(!tag.as_str().chars().any(char::is_control));
            }
        }
    }
}
