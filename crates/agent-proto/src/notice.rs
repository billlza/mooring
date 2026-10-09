// SPDX-License-Identifier: GPL-3.0-or-later

//! The push-notice vocabulary (design §15.8, decision F6, 2026-10-08): an
//! ntfy message the Mac renders and a node sends. It lives here so the
//! renderer and the sender share one grammar.
//!
//! Notices are Level 0: node ids, counts, kinds and times only. The text
//! grammar enforces part of that: it has no `.`, `@`, `_`, quote, `#`, `*`
//! or non-ASCII character, so a dotted IPv4 address, a domain name (a
//! destination), an e-mail address or a name in another script cannot be
//! written. A colon is allowed for times, so an IPv6 literal could be; the
//! Mac and the nodes use IPv4 only, and the renderer writes no address.

use serde::{Deserialize, Serialize};

use crate::macros::{closed_enum, text_newtype};

text_newtype!(
    /// A notice title: 1 to [`MAX_NOTICE_TITLE_BYTES`] bytes of ASCII
    /// letters, digits, spaces and `, : ; ( ) / % + < > = -`.
    NoticeTitle,
    NoticeTitle,
    is_notice_title
);

text_newtype!(
    /// A notice body: 1 to [`MAX_NOTICE_BODY_BYTES`] bytes of the title's
    /// characters and line feeds, with no line feed or space at either end
    /// and no empty line.
    NoticeBody,
    NoticeBody,
    is_notice_body
);

/// The longest [`NoticeTitle`], in bytes.
pub const MAX_NOTICE_TITLE_BYTES: usize = 128;

/// The longest [`NoticeBody`], in bytes.
pub const MAX_NOTICE_BODY_BYTES: usize = 2048;

/// The punctuation a notice may hold besides letters, digits and spaces.
const NOTICE_PUNCTUATION: &[u8] = b",:;()/%+<>=-";

const fn is_notice_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b' ' || is_punctuation(byte)
}

const fn is_punctuation(byte: u8) -> bool {
    let mut index = 0;
    while index < NOTICE_PUNCTUATION.len() {
        if NOTICE_PUNCTUATION[index] == byte {
            return true;
        }
        index += 1;
    }
    false
}

fn is_notice_title(text: &str) -> bool {
    (1..=MAX_NOTICE_TITLE_BYTES).contains(&text.len()) && text.bytes().all(is_notice_byte)
}

fn is_notice_body(text: &str) -> bool {
    let bytes = text.as_bytes();
    let at_edge = |byte: &u8| *byte == b'\n' || *byte == b' ';
    (1..=MAX_NOTICE_BODY_BYTES).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| *byte == b'\n' || is_notice_byte(*byte))
        && !bytes.first().is_some_and(at_edge)
        && !bytes.last().is_some_and(at_edge)
        && !text.contains("\n\n")
}

closed_enum! {
    /// An ntfy priority.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum NtfyPriority {
        /// Priority 1.
        Min,
        /// Priority 2.
        Low,
        /// Priority 3.
        Default,
        /// Priority 4.
        High,
        /// Priority 5.
        Max,
    }
}

impl NtfyPriority {
    /// The value of ntfy's `Priority` header: `1` to `5`.
    pub const fn header(self) -> &'static str {
        match self {
            Self::Min => "1",
            Self::Low => "2",
            Self::Default => "3",
            Self::High => "4",
            Self::Max => "5",
        }
    }
}

closed_enum! {
    /// An ntfy tag, shown as an emoji (inference: ntfy's emoji short
    /// codes; checked in M4).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum NtfyTag {
        /// A critical alert.
        RotatingLight,
        /// A warning.
        Warning,
        /// A resolved alert.
        WhiteCheckMark,
        /// The daily digest.
        BarChart,
    }
}

impl NtfyTag {
    /// The value of ntfy's `Tags` header.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RotatingLight => "rotating_light",
            Self::Warning => "warning",
            Self::WhiteCheckMark => "white_check_mark",
            Self::BarChart => "bar_chart",
        }
    }
}

/// One push notice, ready to send to the deployment's ntfy topic. No request
/// carries it yet: the notice transport is M4.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyMessage {
    /// The title.
    pub title: NoticeTitle,
    /// The body.
    pub body: NoticeBody,
    /// The priority.
    pub priority: NtfyPriority,
    /// The tag.
    pub tag: NtfyTag,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValueError;

    /// Every byte of the title alphabet, and nothing else.
    const ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ,:;()/%+<>=-";

    /// Exactly the alphabet's characters pass, alone and among others (and,
    /// in a body, a line feed inside it); every other character of Latin-1,
    /// and two beyond it, is refused in a title and in a body, wherever it
    /// stands.
    #[test]
    fn titles_and_bodies_refuse_dots_ats_and_control() {
        for character in (0..=0xff_u32).filter_map(char::from_u32).chain(['张', '€']) {
            let in_alphabet = ALPHABET.contains(character);
            let in_body = in_alphabet || character == '\n';
            let edge_whitespace = character == ' ' || character == '\n';
            for (text, at_edge) in [
                (format!("{character}"), true),
                (format!("a{character}b"), false),
                (format!("ab{character}"), true),
            ] {
                assert_eq!(
                    NoticeTitle::new(text.clone()).is_ok(),
                    in_alphabet,
                    "title {text:?}"
                );
                assert_eq!(
                    NoticeBody::new(text.clone()).is_ok(),
                    in_body && !(at_edge && edge_whitespace),
                    "body {text:?}"
                );
            }
        }
        for refused in [
            "203.0.113.7",
            "example.com",
            "alice@example.com",
            "user_1",
            "\"quoted\"",
            "#tag",
            "*bold*",
            "Tab\there",
            "line\r\nbreak",
        ] {
            assert_eq!(
                NoticeTitle::new(refused),
                Err(ValueError::NoticeTitle),
                "{refused:?}"
            );
            assert_eq!(
                NoticeBody::new(refused),
                Err(ValueError::NoticeBody),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn titles_and_bodies_have_exact_length_bounds() {
        assert_eq!((MAX_NOTICE_TITLE_BYTES, MAX_NOTICE_BODY_BYTES), (128, 2048));
        assert!(NoticeTitle::new("x".repeat(128)).is_ok());
        assert_eq!(
            NoticeTitle::new("x".repeat(129)),
            Err(ValueError::NoticeTitle)
        );
        assert_eq!(NoticeTitle::new(""), Err(ValueError::NoticeTitle));
        assert!(NoticeBody::new("x".repeat(2048)).is_ok());
        assert_eq!(
            NoticeBody::new("x".repeat(2049)),
            Err(ValueError::NoticeBody)
        );
        assert_eq!(NoticeBody::new(""), Err(ValueError::NoticeBody));
        let lines = format!("{}\n{}", "x".repeat(1000), "y".repeat(1047));
        assert_eq!(lines.len(), 2048);
        assert!(NoticeBody::new(lines).is_ok());
    }

    /// Lines are separated by exactly one line feed, with none at either
    /// end; a space may stand inside a line but not at either end of the
    /// body.
    #[test]
    fn a_body_has_no_empty_line_and_no_edge_whitespace() {
        let ok = "NodeHalted on lon1\nactive since 2026-10-12 08:15 UTC";
        assert_eq!(NoticeBody::new(ok).unwrap().as_str(), ok);
        assert!(NoticeBody::new("a \nb").is_ok());
        assert!(NoticeBody::new("a\n b").is_ok());
        for bad in ["\na", "a\n", "a\n\nb", " a", "a ", "\n", " "] {
            assert_eq!(NoticeBody::new(bad), Err(ValueError::NoticeBody), "{bad:?}");
        }
        assert_eq!(NoticeTitle::new("a\nb"), Err(ValueError::NoticeTitle));
    }

    #[test]
    fn priorities_and_tags_have_their_ntfy_spellings() {
        let headers: Vec<&str> = NtfyPriority::ALL.iter().map(|p| p.header()).collect();
        assert_eq!(headers, ["1", "2", "3", "4", "5"]);
        let tags: Vec<&str> = NtfyTag::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(
            tags,
            ["rotating_light", "warning", "white_check_mark", "bar_chart"]
        );
    }

    #[test]
    fn a_message_has_a_fixed_encoding_and_is_checked_on_receipt() {
        let message = NtfyMessage {
            title: NoticeTitle::new("Mooring critical raised: NodeHalted").unwrap(),
            body: NoticeBody::new("NodeHalted on lon1\nactive since 2026-10-12 08:15 UTC").unwrap(),
            priority: NtfyPriority::Max,
            tag: NtfyTag::RotatingLight,
        };
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(
            json,
            r#"{"title":"Mooring critical raised: NodeHalted","body":"NodeHalted on lon1\nactive since 2026-10-12 08:15 UTC","priority":"Max","tag":"RotatingLight"}"#
        );
        assert_eq!(serde_json::from_str::<NtfyMessage>(&json).unwrap(), message);
        for bad in [
            json.replace("lon1", "lon1.example.com"),
            json.replace("NodeHalted\"", "NodeHalted.\""),
            json.replace(r#""tag":"RotatingLight""#, r#""tag":"Skull""#),
            json.replace(r#""priority":"Max","#, ""),
            json.replacen('{', r#"{"zz_unknown":true,"#, 1),
        ] {
            assert_ne!(bad, json);
            assert!(serde_json::from_str::<NtfyMessage>(&bad).is_err(), "{bad}");
        }
    }
}
