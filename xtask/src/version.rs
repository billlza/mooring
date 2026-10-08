// SPDX-License-Identifier: GPL-3.0-or-later

//! Exact SemVer 2.0 versions as cargo prints them, ordered by precedence:
//! the crate versions `deny-skips` compares, and the plain release versions
//! and release lines `acceptance` reads from the `contract/` files.

use std::cmp::Ordering;
use std::fmt;

use serde::Deserialize;

/// A version such as `0.2.17`, `1.0.0-rc.1` or `0.11.1+wasi-snapshot-preview1`.
///
/// Equality is textual. Ordering is SemVer precedence, with the full text as
/// a tie-breaker so that versions differing only in build metadata still
/// have a total order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<PreRelease>,
    text: String,
}

/// Numeric identifiers sort before alphanumeric ones (SemVer §11.4.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PreRelease {
    Numeric(u64),
    Alphanumeric(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not an exact SemVer version")]
pub(crate) struct VersionError(pub(crate) String);

impl Version {
    pub(crate) fn parse(text: &str) -> Result<Self, VersionError> {
        let invalid = || VersionError(text.to_owned());
        let (core_and_pre, build) = match text.split_once('+') {
            Some((head, build)) => (head, Some(build)),
            None => (text, None),
        };
        if build.is_some_and(|build| !valid_identifiers(build)) {
            return Err(invalid());
        }
        let (core, pre) = match core_and_pre.split_once('-') {
            Some((core, pre)) if valid_identifiers(pre) => (core, Some(pre)),
            Some(_) => return Err(invalid()),
            None => (core_and_pre, None),
        };
        let numbers = core
            .split('.')
            .map(numeric)
            .collect::<Option<Vec<u64>>>()
            .ok_or_else(invalid)?;
        let [major, minor, patch] = numbers.as_slice() else {
            return Err(invalid());
        };
        let pre = pre
            .map(|pre| {
                pre.split('.')
                    .map(|identifier| match numeric(identifier) {
                        Some(number) => PreRelease::Numeric(number),
                        None => PreRelease::Alphanumeric(identifier.to_owned()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            major: *major,
            minor: *minor,
            patch: *patch,
            pre,
            text: text.to_owned(),
        })
    }

    /// Whether this is a plain `major.minor.patch` release, without
    /// pre-release identifiers or build metadata.
    pub(crate) fn is_release(&self) -> bool {
        self.pre.is_empty() && !self.text.contains('+')
    }

    /// The `major.minor` line this version belongs to.
    pub(crate) const fn release_line(&self) -> ReleaseLine {
        ReleaseLine {
            major: self.major,
            minor: self.minor,
        }
    }
}

/// A release line such as `0.4`: the major and minor version every release
/// of the line shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct ReleaseLine {
    major: u64,
    minor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{0}` is not a `major.minor` release line")]
pub(crate) struct ReleaseLineError(String);

impl TryFrom<String> for ReleaseLine {
    type Error = ReleaseLineError;

    fn try_from(text: String) -> Result<Self, ReleaseLineError> {
        let parsed = text
            .split_once('.')
            .and_then(|(major, minor)| Some((numeric(major)?, numeric(minor)?)));
        match parsed {
            Some((major, minor)) => Ok(Self { major, minor }),
            None => Err(ReleaseLineError(text)),
        }
    }
}

impl fmt::Display for ReleaseLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A numeric identifier: ASCII digits without a leading zero.
fn numeric(identifier: &str) -> Option<u64> {
    let digits = !identifier.is_empty() && identifier.bytes().all(|b| b.is_ascii_digit());
    let leading_zero = identifier.len() > 1 && identifier.starts_with('0');
    if digits && !leading_zero {
        identifier.parse().ok()
    } else {
        None
    }
}

/// Dot-separated, non-empty identifiers of `[0-9A-Za-z-]`.
fn valid_identifiers(text: &str) -> bool {
    text.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
            .then_with(|| self.text.cmp(&other.text))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::{ReleaseLine, ReleaseLineError, Version, VersionError};

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn orders_by_semver_precedence() {
        let ascending = [
            "0.2.17",
            "0.3.4",
            "0.4.3",
            "0.10.1",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "2.0.119",
            "3.0.6",
        ];
        for pair in ascending.windows(2) {
            let (lower, higher) = (v(pair[0]), v(pair[1]));
            assert_eq!(
                lower.cmp(&higher),
                Ordering::Less,
                "{} < {}",
                pair[0],
                pair[1]
            );
            assert_eq!(
                higher.cmp(&lower),
                Ordering::Greater,
                "{} > {}",
                pair[1],
                pair[0]
            );
        }
    }

    #[test]
    fn keeps_the_exact_text_including_build_metadata() {
        let version = v("0.11.1+wasi-snapshot-preview1");
        assert_eq!(version.to_string(), "0.11.1+wasi-snapshot-preview1");
        assert_ne!(version, v("0.11.1"));
        assert!(v("0.11.1") < version, "build metadata only breaks ties");
    }

    #[test]
    fn only_plain_versions_are_releases() {
        assert!(v("1.14.2").is_release());
        assert!(v("0.0.0").is_release());
        for text in [
            "1.0.0-rc.1",
            "0.11.1+wasi-snapshot-preview1",
            "1.0.0-alpha+001",
        ] {
            assert!(!v(text).is_release(), "{text}");
        }
    }

    #[test]
    fn a_version_belongs_to_its_major_minor_line() {
        let line = |text: &str| ReleaseLine::try_from(text.to_owned());
        assert_eq!(v("0.4.0").release_line(), line("0.4").unwrap());
        assert_eq!(v("0.4.17").release_line(), line("0.4").unwrap());
        assert_eq!(v("10.20.3-rc.1").release_line(), line("10.20").unwrap());
        assert_ne!(v("0.5.0").release_line(), line("0.4").unwrap());
        assert_ne!(v("1.4.0").release_line(), line("0.4").unwrap());
        assert_eq!(line("0.4").unwrap().to_string(), "0.4");
        for text in ["", "0", "0.", ".4", "0.4.0", "00.4", "0.04", "v0.4", "0.x"] {
            assert_eq!(line(text), Err(ReleaseLineError(text.to_owned())), "{text}");
        }
    }

    #[test]
    fn rejects_requirements_and_malformed_versions() {
        for text in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "^1.2.3",
            "=1.2.3",
            "1.2.x",
            "01.2.3",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3+",
            "1.2.3-é",
        ] {
            assert_eq!(
                Version::parse(text),
                Err(VersionError(text.to_owned())),
                "{text}"
            );
        }
    }
}
