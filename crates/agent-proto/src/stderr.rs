// SPDX-License-Identifier: GPL-3.0-or-later

//! [`StderrTail`]: the bounded, scrubbed and escaped end of a tool's stderr
//! (design §12, "Logs and stderr tails").

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ValueError;

/// The most bytes a [`StderrTail`] may hold.
pub const STDERR_TAIL_MAX_BYTES: usize = 4096;

/// What [`StderrTail::scrubbed`] writes in place of each secret.
pub const REDACTED: &str = "<redacted>";

/// The end of a tool's stderr as it may leave the machine that ran the tool:
/// scrubbed of secrets, at most [`STDERR_TAIL_MAX_BYTES`] bytes and with no
/// control characters.
///
/// The only constructor is [`StderrTail::scrubbed`], so the agent cannot
/// wrap raw output without scrubbing it. The Mac receives tails by
/// deserialisation, which re-checks the size and control-character rules
/// (it cannot re-check the scrubbing, which needs the secrets).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StderrTail(String);

impl StderrTail {
    /// The tail text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Accepts received text that satisfies the size and control-character
    /// rules; the decoding path only.
    fn received(text: String) -> Result<Self, ValueError> {
        if is_stderr_tail(&text) {
            Ok(Self(text))
        } else {
            Err(ValueError::StderrTail)
        }
    }

    /// Turns raw stderr into a tail, deterministically and in this order:
    ///
    /// 1. every exact occurrence of each secret is replaced by [`REDACTED`]
    ///    (longest secrets first, so a secret that contains a shorter one is
    ///    removed whole; empty secrets match nothing);
    /// 2. invalid UTF-8 becomes U+FFFD;
    /// 3. control characters are escaped (`\n`, `\r`, `\t`, otherwise
    ///    `\u{..}`), and `\` itself becomes `\\` so escapes stay unambiguous;
    /// 4. the last whole escaped characters that fit in
    ///    [`STDERR_TAIL_MAX_BYTES`] are kept.
    ///
    /// Scrubbing runs on the complete output before anything is cut, so a
    /// secret is never split across the cut and partly kept.
    pub fn scrubbed(raw: &[u8], secrets: &[&[u8]]) -> Self {
        let scrubbed = scrub(raw, secrets);
        let text = String::from_utf8_lossy(&scrubbed);
        Self(escaped_tail(&text, STDERR_TAIL_MAX_BYTES))
    }
}

impl fmt::Display for StderrTail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for StderrTail {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for StderrTail {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::received(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn is_stderr_tail(text: &str) -> bool {
    text.len() <= STDERR_TAIL_MAX_BYTES && !text.chars().any(char::is_control)
}

fn scrub<'a>(raw: &'a [u8], secrets: &[&[u8]]) -> Cow<'a, [u8]> {
    let mut ordered = secrets.to_vec();
    ordered.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    ordered
        .into_iter()
        .fold(Cow::Borrowed(raw), |text, secret| {
            match replace_all(&text, secret, REDACTED.as_bytes()) {
                Some(replaced) => Cow::Owned(replaced),
                None => text,
            }
        })
}

/// Replaces every non-overlapping occurrence of `needle`, scanning left to
/// right. Returns `None` when there is no occurrence; an empty needle has
/// none.
fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
    if needle.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut found = false;
    let mut rest = haystack;
    while let Some((first, after)) = rest.split_first() {
        if let Some(after_needle) = rest.strip_prefix(needle) {
            out.extend_from_slice(replacement);
            rest = after_needle;
            found = true;
        } else {
            out.push(*first);
            rest = after;
        }
    }
    found.then_some(out)
}

fn escaped_tail(text: &str, max_bytes: usize) -> String {
    let mut units: Vec<Cow<'static, str>> = Vec::new();
    let mut used = 0_usize;
    for character in text.chars().rev() {
        let unit = escape(character);
        if used + unit.len() > max_bytes {
            break;
        }
        used += unit.len();
        units.push(unit);
    }
    units.into_iter().rev().collect()
}

fn escape(character: char) -> Cow<'static, str> {
    match character {
        '\\' => Cow::Borrowed("\\\\"),
        '\n' => Cow::Borrowed("\\n"),
        '\r' => Cow::Borrowed("\\r"),
        '\t' => Cow::Borrowed("\\t"),
        control if control.is_control() => Cow::Owned(format!("\\u{{{:04x}}}", u32::from(control))),
        printable => Cow::Owned(printable.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_replaced_before_anything_else() {
        let raw = b"invalid \"privateKey\": SECRETKEY123 in config\n";
        let tail = StderrTail::scrubbed(raw, &[b"SECRETKEY123"]);
        assert_eq!(
            tail.as_str(),
            "invalid \"privateKey\": <redacted> in config\\n"
        );
    }

    #[test]
    fn longer_secrets_win_over_contained_shorter_ones() {
        let tail = StderrTail::scrubbed(b"x=abcdef y=abc", &[b"abc", b"abcdef", b""]);
        assert_eq!(tail.as_str(), "x=<redacted> y=<redacted>");
    }

    #[test]
    fn control_characters_and_backslashes_are_escaped() {
        let tail = StderrTail::scrubbed(b"a\x1b[31mb\\c\td\re\x7f\xff", &[]);
        assert_eq!(
            tail.as_str(),
            "a\\u{001b}[31mb\\\\c\\td\\re\\u{007f}\u{fffd}"
        );
        assert!(is_stderr_tail(tail.as_str()));
    }

    #[test]
    fn the_tail_keeps_whole_escapes_within_the_limit() {
        let mut raw = vec![b'x'; 10_000];
        raw.extend_from_slice(b"\n\n\nEND");
        let tail = StderrTail::scrubbed(&raw, &[]);
        assert!(tail.as_str().len() <= STDERR_TAIL_MAX_BYTES);
        assert!(tail.as_str().ends_with("\\n\\n\\nEND"));
        assert_eq!(tail.as_str().len(), STDERR_TAIL_MAX_BYTES);

        // A two-byte escape that would straddle the limit is dropped whole.
        let mut raw = b"\n".to_vec();
        raw.extend(std::iter::repeat_n(b'y', STDERR_TAIL_MAX_BYTES - 1));
        let tail = StderrTail::scrubbed(&raw, &[]);
        assert_eq!(tail.as_str(), "y".repeat(STDERR_TAIL_MAX_BYTES - 1));
    }

    #[test]
    fn a_secret_cut_by_the_limit_is_still_removed() {
        // Cutting the raw output to the limit first would start inside the
        // secret, at "K9P"; scrubbing first leaves only part of REDACTED.
        let mut raw = b"Q7XK9P".to_vec();
        raw.extend(std::iter::repeat_n(b'z', STDERR_TAIL_MAX_BYTES - 3));
        let tail = StderrTail::scrubbed(&raw, &[b"Q7XK9P"]);
        assert_eq!(tail.as_str().len(), STDERR_TAIL_MAX_BYTES);
        assert!(tail.as_str().starts_with("ed>z"), "{}", &tail.as_str()[..8]);
        assert!(!tail.as_str().contains("K9P"));
    }

    #[test]
    fn received_tails_are_validated() {
        let decode = |text: String| serde_json::from_value::<StderrTail>(text.into());
        assert_eq!(decode(String::new()).unwrap().as_str(), "");
        let full = "x".repeat(STDERR_TAIL_MAX_BYTES);
        assert_eq!(decode(full.clone()).unwrap().as_str(), full);
        for bad in [
            "x".repeat(STDERR_TAIL_MAX_BYTES + 1),
            "a\nb".to_owned(),
            "\u{9b}".to_owned(),
        ] {
            assert_eq!(
                StderrTail::received(bad.clone()),
                Err(ValueError::StderrTail),
                "{bad:?}"
            );
            let error = decode(bad).unwrap_err();
            assert_eq!(error.to_string(), ValueError::StderrTail.to_string());
        }
        let tail = StderrTail::scrubbed(b"plain", &[]);
        assert_eq!(
            serde_json::from_str::<StderrTail>(&serde_json::to_string(&tail).unwrap()).unwrap(),
            tail
        );
        assert_eq!(tail.to_string(), "plain");
    }
}
