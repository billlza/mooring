// SPDX-License-Identifier: GPL-3.0-or-later

//! Wall-clock instants as values; the model never reads a clock.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Seconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixTime(u64);

impl UnixTime {
    /// The instant `seconds` after the epoch.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Seconds since the epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// `self + seconds`, or `None` on overflow.
    #[must_use]
    pub const fn checked_add_secs(self, seconds: u64) -> Option<Self> {
        match self.0.checked_add(seconds) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// `self - seconds`, or `None` before the epoch.
    #[must_use]
    pub const fn checked_sub_secs(self, seconds: u64) -> Option<Self> {
        match self.0.checked_sub(seconds) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl fmt::Display for UnixTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_arithmetic() {
        let t = UnixTime::from_secs(10);
        assert_eq!(t.checked_add_secs(5), Some(UnixTime::from_secs(15)));
        assert_eq!(t.checked_sub_secs(11), None);
        assert_eq!(UnixTime::from_secs(u64::MAX).checked_add_secs(1), None);
        assert_eq!(serde_json::to_string(&t).unwrap(), "10");
    }
}
