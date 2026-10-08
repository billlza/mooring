// SPDX-License-Identifier: GPL-3.0-or-later

//! Numeric wire scalars: [`Generation`], [`UnixTime`] and [`PortRange`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ValueError;

/// A configuration generation: the Mac's `ConfigGeneration` as the VPS sees
/// it. Generations only grow; an `Apply` must carry one newer than the
/// node's current generation.
///
/// [`Generation::ZERO`] is the generation of a node that has never committed
/// an `Apply`, so the first real generation is at least 1. It is also the
/// generation an agent activation reports while nothing has been applied
/// (activation never changes the configuration generation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Generation(u64);

impl Generation {
    /// The generation of a node that has never committed an `Apply`.
    pub const ZERO: Self = Self(0);

    /// Wraps a generation number.
    pub const fn new(generation: u64) -> Self {
        Self(generation)
    }

    /// The generation number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A point in time: whole seconds since the Unix epoch, UTC. WireGuard's
/// `latest-handshake` uses the same unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixTime(u64);

impl UnixTime {
    /// Wraps a count of seconds since the Unix epoch.
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// Seconds since the Unix epoch.
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Whole seconds from `earlier` to `self`, or `None` when `earlier` is
    /// after `self` (for example after a clock step).
    pub const fn secs_since(self, earlier: Self) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }
}

impl fmt::Display for UnixTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// An inclusive, non-empty range of ports that does not include port 0,
/// such as Linux's `net.ipv4.ip_local_port_range`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawPortRange")]
pub struct PortRange {
    low: u16,
    high: u16,
}

impl PortRange {
    /// Validates `1 <= low <= high`.
    pub const fn new(low: u16, high: u16) -> Result<Self, ValueError> {
        if low >= 1 && low <= high {
            Ok(Self { low, high })
        } else {
            Err(ValueError::PortRange)
        }
    }

    /// The first port of the range.
    pub const fn low(self) -> u16 {
        self.low
    }

    /// The last port of the range.
    pub const fn high(self) -> u16 {
        self.high
    }

    /// Whether `port` lies inside the range.
    pub const fn contains(self, port: u16) -> bool {
        self.low <= port && port <= self.high
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{}", self.low, self.high)
    }
}

/// The unvalidated wire shape of [`PortRange`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPortRange {
    low: u16,
    high: u16,
}

impl TryFrom<RawPortRange> for PortRange {
    type Error = ValueError;

    fn try_from(raw: RawPortRange) -> Result<Self, Self::Error> {
        Self::new(raw.low, raw.high)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_range_requires_a_non_empty_range_above_zero() {
        assert!(PortRange::new(32768, 60999).is_ok());
        assert!(PortRange::new(1, 1).is_ok());
        assert_eq!(PortRange::new(0, 10), Err(ValueError::PortRange));
        assert_eq!(PortRange::new(61000, 60999), Err(ValueError::PortRange));
    }

    #[test]
    fn port_range_deserialisation_validates() {
        let ok: PortRange = serde_json::from_str(r#"{"low":32768,"high":60999}"#).unwrap();
        assert_eq!((ok.low(), ok.high()), (32768, 60999));
        assert!(ok.contains(32768) && ok.contains(60999) && !ok.contains(61000));
        assert!(serde_json::from_str::<PortRange>(r#"{"low":9,"high":8}"#).is_err());
        assert!(serde_json::from_str::<PortRange>(r#"{"low":1,"high":2,"x":3}"#).is_err());
    }

    #[test]
    fn secs_since_is_none_for_a_later_instant() {
        let earlier = UnixTime::from_secs(100);
        let later = UnixTime::from_secs(160);
        assert_eq!(later.secs_since(earlier), Some(60));
        assert_eq!(earlier.secs_since(later), None);
    }
}
