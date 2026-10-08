// SPDX-License-Identifier: GPL-3.0-or-later

//! Special-purpose IPv4 ranges (design §7 `SPECIAL_V4`), public addresses
//! and carrier prefixes.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::error::ModelError;

/// The class of a special-purpose IPv4 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SpecialClass {
    /// 0.0.0.0/8, "this network" (RFC 791).
    ThisNetwork,
    /// 10.0.0.0/8, private use (RFC 1918).
    Private10,
    /// 100.64.0.0/10, shared address space for CGNAT (RFC 6598).
    SharedAddressSpace,
    /// 127.0.0.0/8, loopback (RFC 1122).
    Loopback,
    /// 169.254.0.0/16, link local (RFC 3927).
    LinkLocal,
    /// 172.16.0.0/12, private use (RFC 1918).
    Private172,
    /// 192.0.0.0/24, IETF protocol assignments (RFC 6890).
    IetfProtocolAssignments,
    /// 192.0.2.0/24, documentation TEST-NET-1 (RFC 5737).
    Documentation1,
    /// 192.88.99.0/24, deprecated 6to4 relay anycast (RFC 7526).
    SixToFourRelay,
    /// 192.168.0.0/16, private use (RFC 1918).
    Private192,
    /// 198.18.0.0/15, benchmarking (RFC 2544).
    Benchmarking,
    /// 198.51.100.0/24, documentation TEST-NET-2 (RFC 5737).
    Documentation2,
    /// 203.0.113.0/24, documentation TEST-NET-3 (RFC 5737).
    Documentation3,
    /// 224.0.0.0/4, multicast (RFC 5771).
    Multicast,
    /// 240.0.0.0/4, reserved, including the limited broadcast address (RFC 1112).
    Reserved,
}

impl SpecialClass {
    /// The range this class covers.
    #[must_use]
    pub const fn net(self) -> Ipv4Net {
        match self {
            Self::ThisNetwork => net(0, 0, 0, 0, 8),
            Self::Private10 => net(10, 0, 0, 0, 8),
            Self::SharedAddressSpace => net(100, 64, 0, 0, 10),
            Self::Loopback => net(127, 0, 0, 0, 8),
            Self::LinkLocal => net(169, 254, 0, 0, 16),
            Self::Private172 => net(172, 16, 0, 0, 12),
            Self::IetfProtocolAssignments => net(192, 0, 0, 0, 24),
            Self::Documentation1 => net(192, 0, 2, 0, 24),
            Self::SixToFourRelay => net(192, 88, 99, 0, 24),
            Self::Private192 => net(192, 168, 0, 0, 16),
            Self::Benchmarking => net(198, 18, 0, 0, 15),
            Self::Documentation2 => net(198, 51, 100, 0, 24),
            Self::Documentation3 => net(203, 0, 113, 0, 24),
            Self::Multicast => net(224, 0, 0, 0, 4),
            Self::Reserved => net(240, 0, 0, 0, 4),
        }
    }

    /// A short human-readable description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ThisNetwork => "this network",
            Self::Private10 | Self::Private172 | Self::Private192 => "private use",
            Self::SharedAddressSpace => "shared address space (CGNAT)",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link local",
            Self::IetfProtocolAssignments => "IETF protocol assignments",
            Self::Documentation1 | Self::Documentation2 | Self::Documentation3 => "documentation",
            Self::SixToFourRelay => "6to4 relay anycast",
            Self::Benchmarking => "benchmarking",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
        }
    }
}

impl fmt::Display for SpecialClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.net(), self.description())
    }
}

/// `prefix_len` here is always a literal at most 32, so `new_assert` cannot fail.
const fn net(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(a, b, c, d), prefix_len)
}

/// Every special-purpose IPv4 class, in ascending address order.
///
/// This one list feeds `PublicIpv4`, both renderers' deny rules and the
/// tests. IPv6 is refused entirely in v1.
pub const SPECIAL_V4: [SpecialClass; 15] = [
    SpecialClass::ThisNetwork,
    SpecialClass::Private10,
    SpecialClass::SharedAddressSpace,
    SpecialClass::Loopback,
    SpecialClass::LinkLocal,
    SpecialClass::Private172,
    SpecialClass::IetfProtocolAssignments,
    SpecialClass::Documentation1,
    SpecialClass::SixToFourRelay,
    SpecialClass::Private192,
    SpecialClass::Benchmarking,
    SpecialClass::Documentation2,
    SpecialClass::Documentation3,
    SpecialClass::Multicast,
    SpecialClass::Reserved,
];

/// The special-purpose classes a Mac LAN (the M7's, or the home network of a
/// `Separate` uplink) may be numbered from: private use, shared address space
/// and link local. Each is in [`SPECIAL_V4`], which the Mac exit rejects as a
/// destination of every tunnelled flow (design §8.7), so a LAN numbered from
/// one of them is unreachable through the exit by construction.
pub const LAN_CLASSES: [SpecialClass; 5] = [
    SpecialClass::Private10,
    SpecialClass::SharedAddressSpace,
    SpecialClass::LinkLocal,
    SpecialClass::Private172,
    SpecialClass::Private192,
];

/// The class of [`LAN_CLASSES`] that wholly contains `prefix`, if any.
#[must_use]
pub fn lan_class(prefix: Ipv4Net) -> Option<SpecialClass> {
    LAN_CLASSES
        .into_iter()
        .find(|class| class.net().contains(&prefix))
}

/// The special-purpose class containing `addr`, if any.
#[must_use]
pub fn classify(addr: Ipv4Addr) -> Option<SpecialClass> {
    SPECIAL_V4
        .into_iter()
        .find(|class| class.net().contains(&addr))
}

/// The first special-purpose class that overlaps `prefix`, if any.
#[must_use]
pub fn special_overlap(prefix: Ipv4Net) -> Option<SpecialClass> {
    SPECIAL_V4.into_iter().find(|class| {
        let special = class.net();
        special.contains(&prefix.network()) || prefix.contains(&special.network())
    })
}

/// An IPv4 address outside every `SPECIAL_V4` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "Ipv4Addr", into = "Ipv4Addr")]
pub struct PublicIpv4(Ipv4Addr);

impl PublicIpv4 {
    /// Accepts `addr` unless it lies in a special-purpose range.
    pub fn new(addr: Ipv4Addr) -> Result<Self, ModelError> {
        Self::classified(addr).map_err(|class| ModelError::InvalidAddress { addr, class })
    }

    /// Accepts `addr`, or returns the special-purpose class it lies in.
    pub fn classified(addr: Ipv4Addr) -> Result<Self, SpecialClass> {
        match classify(addr) {
            Some(class) => Err(class),
            None => Ok(Self(addr)),
        }
    }

    /// The address.
    #[must_use]
    pub const fn get(self) -> Ipv4Addr {
        self.0
    }
}

impl TryFrom<Ipv4Addr> for PublicIpv4 {
    type Error = ModelError;

    fn try_from(addr: Ipv4Addr) -> Result<Self, Self::Error> {
        Self::new(addr)
    }
}

impl From<PublicIpv4> for Ipv4Addr {
    fn from(addr: PublicIpv4) -> Self {
        addr.0
    }
}

impl FromStr for PublicIpv4 {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let addr = Ipv4Addr::from_str(text).map_err(|_| ModelError::InvalidIpv4)?;
        Self::new(addr)
    }
}

impl fmt::Display for PublicIpv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Why a prefix was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrefixRule {
    /// Host bits are set; the prefix must be written as its network address.
    NotCanonical,
    /// The prefix overlaps a special-purpose range.
    OverlapsSpecial(SpecialClass),
    /// The prefix is not wholly inside one of [`LAN_CLASSES`].
    NotPrivateLan,
}

impl fmt::Display for PrefixRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCanonical => f.write_str("host bits are set"),
            Self::OverlapsSpecial(class) => write!(f, "overlaps {class}"),
            Self::NotPrivateLan => {
                f.write_str("it is not inside a private-use, shared-address or link-local range")
            }
        }
    }
}

/// Requires `prefix` to be written as its network address.
pub(crate) fn require_canonical(prefix: Ipv4Net) -> Result<Ipv4Net, ModelError> {
    if prefix.addr() == prefix.network() {
        Ok(prefix)
    } else {
        Err(ModelError::InvalidPrefix {
            prefix,
            rule: PrefixRule::NotCanonical,
        })
    }
}

/// A carrier public-pool prefix: canonical and disjoint from `SPECIAL_V4`.
///
/// Observed egress addresses must fall inside one of these (design §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "Ipv4Net", into = "Ipv4Net")]
pub struct CarrierPrefix(Ipv4Net);

impl CarrierPrefix {
    /// Accepts a canonical prefix that overlaps no special-purpose range.
    pub fn new(prefix: Ipv4Net) -> Result<Self, ModelError> {
        let prefix = require_canonical(prefix)?;
        match special_overlap(prefix) {
            Some(class) => Err(ModelError::InvalidPrefix {
                prefix,
                rule: PrefixRule::OverlapsSpecial(class),
            }),
            None => Ok(Self(prefix)),
        }
    }

    /// The prefix.
    #[must_use]
    pub const fn get(self) -> Ipv4Net {
        self.0
    }

    /// Whether `addr` lies inside the prefix.
    #[must_use]
    pub fn contains(self, addr: Ipv4Addr) -> bool {
        self.0.contains(&addr)
    }
}

impl TryFrom<Ipv4Net> for CarrierPrefix {
    type Error = ModelError;

    fn try_from(prefix: Ipv4Net) -> Result<Self, Self::Error> {
        Self::new(prefix)
    }
}

impl From<CarrierPrefix> for Ipv4Net {
    fn from(prefix: CarrierPrefix) -> Self {
        prefix.0
    }
}

/// Parses `a.b.c.d/len` text into a prefix.
pub(crate) fn parse_cidr(text: &str) -> Result<Ipv4Net, ModelError> {
    Ipv4Net::from_str(text).map_err(|_| ModelError::InvalidCidr)
}

impl FromStr for CarrierPrefix {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(parse_cidr(text)?)
    }
}

impl fmt::Display for CarrierPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The design §7 list, verbatim.
    const DESIGN_LIST: &str = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, \
        172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, \
        198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4";

    fn next(addr: Ipv4Addr) -> Option<Ipv4Addr> {
        u32::from(addr).checked_add(1).map(Ipv4Addr::from)
    }

    fn prev(addr: Ipv4Addr) -> Option<Ipv4Addr> {
        u32::from(addr).checked_sub(1).map(Ipv4Addr::from)
    }

    #[test]
    fn special_list_matches_design_exactly() {
        let rendered: Vec<String> = SPECIAL_V4.iter().map(|c| c.net().to_string()).collect();
        assert_eq!(rendered.join(", "), DESIGN_LIST);
    }

    #[test]
    fn special_ranges_are_canonical_sorted_and_disjoint() {
        for class in SPECIAL_V4 {
            assert_eq!(class.net().addr(), class.net().network(), "{class}");
        }
        for pair in SPECIAL_V4.windows(2) {
            assert!(
                pair[0].net().broadcast() < pair[1].net().network(),
                "{} and {} overlap or are unsorted",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn boundaries_of_every_range_are_classified_and_neighbours_are_not() {
        for class in SPECIAL_V4 {
            let first = class.net().network();
            let last = class.net().broadcast();
            assert_eq!(classify(first), Some(class), "first of {class}");
            assert_eq!(classify(last), Some(class), "last of {class}");
            assert_eq!(
                PublicIpv4::new(first),
                Err(ModelError::InvalidAddress { addr: first, class })
            );
            assert_eq!(
                PublicIpv4::new(last),
                Err(ModelError::InvalidAddress { addr: last, class })
            );
            // A neighbour is either public or inside an adjacent special range,
            // never misattributed to this one.
            for neighbour in [prev(first), next(last)].into_iter().flatten() {
                assert_ne!(
                    classify(neighbour),
                    Some(class),
                    "{neighbour} beside {class}"
                );
            }
        }
    }

    #[test]
    fn known_public_neighbours_are_accepted() {
        for text in [
            "1.0.0.0",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "191.255.255.255",
            "192.0.1.0",
            "192.0.3.0",
            "192.88.98.255",
            "192.88.100.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
            "223.255.255.255",
        ] {
            let addr: PublicIpv4 = text.parse().unwrap();
            assert_eq!(addr.to_string(), text);
        }
        assert_eq!(
            "255.255.255.255"
                .parse::<PublicIpv4>()
                .unwrap_err()
                .kind()
                .name(),
            "InvalidAddress"
        );
        assert_eq!("1.2.3".parse::<PublicIpv4>(), Err(ModelError::InvalidIpv4));
        assert_eq!(
            "01.2.3.4".parse::<PublicIpv4>(),
            Err(ModelError::InvalidIpv4)
        );
    }

    #[test]
    fn public_ipv4_serde_rejects_special_addresses() {
        let addr: PublicIpv4 = serde_json::from_str("\"45.67.89.10\"").unwrap();
        assert_eq!(serde_json::to_string(&addr).unwrap(), "\"45.67.89.10\"");
        assert!(serde_json::from_str::<PublicIpv4>("\"100.64.0.1\"").is_err());
        assert!(serde_json::from_str::<PublicIpv4>("\"::1\"").is_err());
    }

    #[test]
    fn carrier_prefix_rules() {
        assert_eq!(
            "31.120.0.0/14"
                .parse::<CarrierPrefix>()
                .unwrap()
                .to_string(),
            "31.120.0.0/14"
        );
        for bad in ["31.120.0.0", "31.120.0.0/33", "31.120.0.0/x", ""] {
            assert_eq!(
                bad.parse::<CarrierPrefix>(),
                Err(ModelError::InvalidCidr),
                "{bad}"
            );
        }
        let ok: Ipv4Net = "31.120.0.0/14".parse().unwrap();
        assert_eq!(CarrierPrefix::new(ok).unwrap().get(), ok);
        let host_bits: Ipv4Net = "31.120.0.1/14".parse().unwrap();
        assert_eq!(
            CarrierPrefix::new(host_bits),
            Err(ModelError::InvalidPrefix {
                prefix: host_bits,
                rule: PrefixRule::NotCanonical
            })
        );
        // A prefix that covers a special range, and one inside a special range.
        for (text, class) in [
            ("96.0.0.0/4", SpecialClass::SharedAddressSpace),
            ("100.64.0.0/24", SpecialClass::SharedAddressSpace),
            ("0.0.0.0/0", SpecialClass::ThisNetwork),
        ] {
            let prefix: Ipv4Net = text.parse().unwrap();
            assert_eq!(
                CarrierPrefix::new(prefix),
                Err(ModelError::InvalidPrefix {
                    prefix,
                    rule: PrefixRule::OverlapsSpecial(class)
                })
            );
        }
        assert!(serde_json::from_str::<CarrierPrefix>("\"10.0.0.0/8\"").is_err());
    }

    proptest! {
        #[test]
        fn public_ipv4_accepts_exactly_the_unclassified(raw in any::<u32>()) {
            let addr = Ipv4Addr::from(raw);
            let in_special = SPECIAL_V4.iter().any(|class| class.net().contains(&addr));
            prop_assert_eq!(PublicIpv4::new(addr).is_ok(), !in_special);
        }

        #[test]
        fn public_ipv4_round_trips_through_json(raw in any::<u32>()) {
            if let Ok(addr) = PublicIpv4::new(Ipv4Addr::from(raw)) {
                let json = serde_json::to_string(&addr).unwrap();
                prop_assert_eq!(serde_json::from_str::<PublicIpv4>(&json).unwrap(), addr);
            }
        }
    }
}
