// SPDX-License-Identifier: GPL-3.0-or-later

//! The WireGuard tunnel between a VPS and the Mac.

use std::fmt;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::error::ModelError;
use crate::keys::WgKey;

/// The supernet holding every tunnel /30 (`10.77.0.0/16`).
pub const WG_SUPERNET: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(10, 77, 0, 0), 16);

/// The third octet `k` of a node's tunnel network `10.77.<k>.0/30`, in 1..=255.
///
/// The VPS side is `10.77.<k>.1` and the Mac side `10.77.<k>.2`. Indices are
/// allocated monotonically and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct WgIndex(u8);

impl WgIndex {
    /// The first index ever allocated.
    pub const FIRST: Self = Self(1);

    /// Accepts 1..=255.
    pub fn new(value: u8) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidWgIndex { value })
        } else {
            Ok(Self(value))
        }
    }

    /// The index value `k`.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The next index, or `WgIndexExhausted` after 255.
    pub fn next(self) -> Result<Self, ModelError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ModelError::WgIndexExhausted)
    }

    /// The tunnel network `10.77.<k>.0/30`.
    #[must_use]
    pub const fn network(self) -> Ipv4Net {
        Ipv4Net::new_assert(Ipv4Addr::new(10, 77, self.0, 0), 30)
    }

    /// The VPS tunnel address `10.77.<k>.1`.
    #[must_use]
    pub const fn vps_address(self) -> Ipv4Addr {
        Ipv4Addr::new(10, 77, self.0, 1)
    }

    /// The Mac tunnel address `10.77.<k>.2`.
    #[must_use]
    pub const fn mac_address(self) -> Ipv4Addr {
        Ipv4Addr::new(10, 77, self.0, 2)
    }

    /// The VPS interface address with its prefix, `10.77.<k>.1/30` (wg-quick `Address`).
    #[must_use]
    pub const fn vps_interface(self) -> Ipv4Net {
        Ipv4Net::new_assert(self.vps_address(), 30)
    }

    /// The VPS host route `10.77.<k>.1/32` (the Mac peer's `allowed_ips`).
    #[must_use]
    pub const fn vps_host(self) -> Ipv4Net {
        Ipv4Net::new_assert(self.vps_address(), 32)
    }

    /// The Mac host route `10.77.<k>.2/32` (the Mac endpoint's `address`).
    #[must_use]
    pub const fn mac_host(self) -> Ipv4Net {
        Ipv4Net::new_assert(self.mac_address(), 32)
    }
}

impl TryFrom<u8> for WgIndex {
    type Error = ModelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<WgIndex> for u8 {
    fn from(index: WgIndex) -> Self {
        index.0
    }
}

impl fmt::Display for WgIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The persistent keepalive in seconds, 5..=60.
///
/// The lower bound is design §3; the upper bound keeps three keepalives (the
/// watch's rx-growth window) inside the 180 s handshake freshness limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Keepalive(NonZeroU16);

impl Keepalive {
    /// The v1 default until M2 measures the carrier's UDP NAT timeout: 10 s.
    pub const DEFAULT: Self = Self(NonZeroU16::MIN.saturating_add(9));
    /// The smallest accepted keepalive.
    pub const MIN_SECONDS: u16 = 5;
    /// The largest accepted keepalive.
    pub const MAX_SECONDS: u16 = 60;

    /// Accepts 5..=60 seconds.
    pub fn from_seconds(seconds: u16) -> Result<Self, ModelError> {
        match NonZeroU16::new(seconds) {
            Some(value) if (Self::MIN_SECONDS..=Self::MAX_SECONDS).contains(&seconds) => {
                Ok(Self(value))
            }
            Some(_) | None => Err(ModelError::InvalidKeepalive { seconds }),
        }
    }

    /// The keepalive in seconds.
    #[must_use]
    pub const fn seconds(self) -> u16 {
        self.0.get()
    }

    /// The keepalive as a non-zero number of seconds, the type the agent
    /// protocol's `watch.json` takes, so the conversion cannot fail.
    #[must_use]
    pub const fn non_zero_seconds(self) -> NonZeroU16 {
        self.0
    }
}

impl TryFrom<u16> for Keepalive {
    type Error = ModelError;

    fn try_from(seconds: u16) -> Result<Self, Self::Error> {
        Self::from_seconds(seconds)
    }
}

impl From<Keepalive> for u16 {
    fn from(keepalive: Keepalive) -> Self {
        keepalive.seconds()
    }
}

/// The public half of a node's tunnel; the private keys are secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgLink {
    /// The VPS (`wgexit`) public key.
    pub vps_pub: WgKey,
    /// The Mac endpoint public key.
    pub mac_pub: WgKey,
    /// The Mac's persistent keepalive.
    pub keepalive: Keepalive,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn addressing_helpers() {
        let index = WgIndex::new(7).unwrap();
        assert_eq!(index.network().to_string(), "10.77.7.0/30");
        assert_eq!(index.vps_interface().to_string(), "10.77.7.1/30");
        assert_eq!(index.vps_host().to_string(), "10.77.7.1/32");
        assert_eq!(index.mac_host().to_string(), "10.77.7.2/32");
        assert!(WG_SUPERNET.contains(&index.network()));
        assert!(index.network().contains(&index.vps_address()));
        assert!(index.network().contains(&index.mac_address()));
    }

    #[test]
    fn index_bounds_and_exhaustion() {
        assert_eq!(
            WgIndex::new(0),
            Err(ModelError::InvalidWgIndex { value: 0 })
        );
        assert_eq!(WgIndex::FIRST.next().unwrap().get(), 2);
        assert_eq!(
            WgIndex::new(255).unwrap().next(),
            Err(ModelError::WgIndexExhausted)
        );
        assert!(serde_json::from_str::<WgIndex>("0").is_err());
        assert_eq!(serde_json::from_str::<WgIndex>("3").unwrap().get(), 3);
    }

    #[test]
    fn keepalive_bounds() {
        assert_eq!(Keepalive::from_seconds(10), Ok(Keepalive::DEFAULT));
        for bad in [0, 4, 61] {
            assert_eq!(
                Keepalive::from_seconds(bad),
                Err(ModelError::InvalidKeepalive { seconds: bad })
            );
        }
        assert!(Keepalive::from_seconds(5).is_ok());
        assert!(Keepalive::from_seconds(60).is_ok());
        assert!(serde_json::from_str::<Keepalive>("61").is_err());
        assert_eq!(Keepalive::DEFAULT.seconds(), 10);
        assert_eq!(Keepalive::DEFAULT.non_zero_seconds().get(), 10);
    }

    proptest! {
        #[test]
        fn every_index_has_a_distinct_network(a in 1_u8..=255, b in 1_u8..=255) {
            let (a, b) = (WgIndex::new(a).unwrap(), WgIndex::new(b).unwrap());
            prop_assert_eq!(a.network() == b.network(), a == b);
            prop_assert!(WG_SUPERNET.contains(&a.network()));
        }

        #[test]
        fn keepalive_accepts_exactly_its_range(seconds in any::<u16>()) {
            prop_assert_eq!(Keepalive::from_seconds(seconds).is_ok(), (5..=60).contains(&seconds));
        }
    }
}
