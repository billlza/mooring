// SPDX-License-Identifier: GPL-3.0-or-later

//! Network interfaces: link-layer addresses, interface names, the Mac's
//! interface selectors and their resolution (design §7, §10.1).

use std::fmt;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::encoding::decode_hex_lower;
use crate::error::ModelError;
use crate::exit::Uplink;
use crate::ipv4::{PrefixRule, lan_class, parse_cidr, require_canonical};
use crate::verdict::UplinkAddress;

/// A unicast Ethernet link-layer address, written `aa:bb:cc:dd:ee:ff` in lowercase.
///
/// All-zero and group (multicast or broadcast) addresses are rejected: an
/// interface or gateway always has a unicast address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Accepts six bytes forming a non-zero unicast address.
    pub fn from_bytes(bytes: [u8; 6]) -> Result<Self, ModelError> {
        if bytes == [0; 6] || bytes[0] & 0x01 == 0x01 {
            Err(ModelError::InvalidMacAddr)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Parses `aa:bb:cc:dd:ee:ff` in lowercase.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() != 6 {
            return Err(ModelError::InvalidMacAddr);
        }
        let mut bytes = [0_u8; 6];
        for (byte, part) in bytes.iter_mut().zip(parts) {
            let [value] = decode_hex_lower::<1>(part).ok_or(ModelError::InvalidMacAddr)?;
            *byte = value;
        }
        Self::from_bytes(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl TryFrom<String> for MacAddr {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<MacAddr> for String {
    fn from(addr: MacAddr) -> Self {
        addr.to_string()
    }
}

impl FromStr for MacAddr {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Which platform's interface naming rule was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceNameKind {
    /// A Linux interface name on a VPS.
    Linux,
    /// A BSD interface name on the Mac.
    Bsd,
}

impl fmt::Display for InterfaceNameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Linux => "Linux",
            Self::Bsd => "BSD",
        })
    }
}

/// The maximum interface name length on Linux and macOS (`IFNAMSIZ - 1`).
pub const MAX_IFNAME_LEN: usize = 15;

/// A Linux interface name as the kernel accepts it (`dev_valid_name`, Linux
/// v6.12 `net/core/dev.c`): 1..=15 bytes, not `.` or `..`, without `/`, `:` or
/// whitespace, restricted to printable ASCII. This is exactly the rule of the
/// agent protocol's `IfName`, so a name `Hello` reports converts both ways.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LinuxIfName(String);

impl LinuxIfName {
    /// Validates `text` as a Linux interface name.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let valid = (1..=MAX_IFNAME_LEN).contains(&text.len())
            && text != "."
            && text != ".."
            && text
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b':');
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidInterfaceName {
                flavor: InterfaceNameKind::Linux,
            })
        }
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A macOS BSD interface name: lowercase letters followed by a unit number,
/// at most 15 bytes, for example `en8` or `bridge100`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BsdName(String);

impl BsdName {
    /// Validates `text` as a BSD interface name.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let letters = text.bytes().take_while(u8::is_ascii_lowercase).count();
        let digits = &text.as_bytes()[letters..];
        let valid = text.len() <= MAX_IFNAME_LEN
            && letters > 0
            && !digits.is_empty()
            && digits.iter().all(u8::is_ascii_digit)
            && (digits.len() == 1 || digits[0] != b'0');
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidInterfaceName {
                flavor: InterfaceNameKind::Bsd,
            })
        }
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! name_conversions {
    ($name:ident) => {
        impl TryFrom<String> for $name {
            type Error = ModelError;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(name: $name) -> Self {
                name.0
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name_conversions!(LinuxIfName);
name_conversions!(BsdName);

/// A non-zero interface index (`if_nametoindex`, `IP_BOUND_IF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct InterfaceIndex(NonZeroU32);

impl InterfaceIndex {
    /// Accepts any index except zero.
    pub fn new(index: u32) -> Result<Self, ModelError> {
        NonZeroU32::new(index)
            .map(Self)
            .ok_or(ModelError::InvalidInterfaceIndex)
    }

    /// The index.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for InterfaceIndex {
    type Error = ModelError;

    fn try_from(index: u32) -> Result<Self, Self::Error> {
        Self::new(index)
    }
}

impl From<InterfaceIndex> for u32 {
    fn from(index: InterfaceIndex) -> Self {
        index.get()
    }
}

impl From<NonZeroU32> for InterfaceIndex {
    fn from(index: NonZeroU32) -> Self {
        Self(index)
    }
}

impl From<InterfaceIndex> for NonZeroU32 {
    fn from(index: InterfaceIndex) -> Self {
        index.0
    }
}

/// The LAN subnet an interface's IPv4 address must lie in, written as its
/// network address (for example the M7's `192.168.1.0/24`).
///
/// Invariant: the subnet lies wholly inside one of [`LAN_CLASSES`](crate::ipv4::LAN_CLASSES), so the
/// Mac exit's `SPECIAL_V4` rejection covers the whole LAN (design §8.7: the
/// M7 admin page and the home LAN are never reachable through the tunnel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "Ipv4Net", into = "Ipv4Net")]
pub struct LanSubnet(Ipv4Net);

impl LanSubnet {
    /// Accepts a canonical prefix inside one of [`LAN_CLASSES`](crate::ipv4::LAN_CLASSES).
    pub fn new(prefix: Ipv4Net) -> Result<Self, ModelError> {
        let prefix = require_canonical(prefix)?;
        match lan_class(prefix) {
            Some(_) => Ok(Self(prefix)),
            None => Err(ModelError::InvalidPrefix {
                prefix,
                rule: PrefixRule::NotPrivateLan,
            }),
        }
    }

    /// The prefix.
    #[must_use]
    pub const fn get(self) -> Ipv4Net {
        self.0
    }

    /// Whether `addr` lies inside the subnet.
    #[must_use]
    pub fn contains(self, addr: Ipv4Addr) -> bool {
        self.0.contains(&addr)
    }
}

impl TryFrom<Ipv4Net> for LanSubnet {
    type Error = ModelError;

    fn try_from(prefix: Ipv4Net) -> Result<Self, Self::Error> {
        Self::new(prefix)
    }
}

impl FromStr for LanSubnet {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(parse_cidr(text)?)
    }
}

impl From<LanSubnet> for Ipv4Net {
    fn from(subnet: LanSubnet) -> Self {
        subnet.0
    }
}

/// How the Mac finds a physical interface; chosen from M2 data. There is
/// never a fallback to another interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InterfaceSelector {
    /// The interface whose own link-layer address is `lladdr`.
    LinkAddr {
        /// The interface's link-layer address.
        lladdr: MacAddr,
        /// The subnet its IPv4 address must lie in.
        subnet: LanSubnet,
    },
    /// The interface whose default gateway has link-layer address `gw_lladdr`.
    GatewayLinkAddr {
        /// The gateway's link-layer address.
        gw_lladdr: MacAddr,
        /// The subnet the interface's IPv4 address must lie in.
        subnet: LanSubnet,
    },
}

impl InterfaceSelector {
    /// The subnet the resolved interface's IPv4 address must lie in.
    #[must_use]
    pub const fn subnet(&self) -> LanSubnet {
        match self {
            Self::LinkAddr { subnet, .. } | Self::GatewayLinkAddr { subnet, .. } => *subnet,
        }
    }
}

/// One interface as resolved on the Mac at run time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedInterface {
    /// The BSD name, used for `bind_interface`.
    pub bsd_name: BsdName,
    /// The interface index, used for `IP_BOUND_IF`.
    pub index: InterfaceIndex,
    /// The interface's link-layer address.
    pub lladdr: MacAddr,
    /// The interface's IPv4 address.
    pub ipv4: Ipv4Addr,
}

impl ResolvedInterface {
    /// Whether this interface is one `selector` can select: its address is in
    /// the selector's subnet and, for a `LinkAddr` selector, its own
    /// link-layer address is the selected one. (A `GatewayLinkAddr`
    /// selector names the gateway's address, which the interface does not
    /// carry; the resolver checks it.)
    #[must_use]
    pub fn matches(&self, selector: &InterfaceSelector) -> bool {
        let lladdr_ok = match selector {
            InterfaceSelector::LinkAddr { lladdr, .. } => *lladdr == self.lladdr,
            InterfaceSelector::GatewayLinkAddr { .. } => true,
        };
        lladdr_ok && selector.subnet().contains(self.ipv4)
    }
}

/// The resolved tunnel uplink.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolvedUplink {
    /// The tunnel uses the egress interface.
    SameAsExit,
    /// The tunnel uses a different interface.
    Separate(ResolvedInterface),
}

impl ResolvedUplink {
    /// The mode, without the interface.
    #[must_use]
    pub const fn mode(&self) -> UplinkMode {
        match self {
            Self::SameAsExit => UplinkMode::SameAsExit,
            Self::Separate(_) => UplinkMode::Separate,
        }
    }
}

/// Whether the tunnel uplink is the egress or a separate interface, without
/// the interface: what a configured and a resolved uplink are compared by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UplinkMode {
    /// The tunnel leaves through the egress interface.
    SameAsExit,
    /// The tunnel leaves through a separate interface.
    Separate,
}

impl fmt::Display for UplinkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SameAsExit => "SameAsExit",
            Self::Separate => "Separate",
        })
    }
}

/// Which of the exit site's interfaces an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceRole {
    /// The egress interface, facing the M7.
    Egress,
    /// The separate tunnel uplink.
    Uplink,
}

impl fmt::Display for InterfaceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Egress => "egress",
            Self::Uplink => "uplink",
        })
    }
}

/// The egress and uplink interfaces resolved for one daemon tick; the
/// renderers bind every Mac socket to these.
///
/// Built only by `ExitSite::resolve`, which checks the interfaces against
/// that site: the egress (and a separate uplink) match their selectors, the
/// uplink mode is the configured one, and a separate uplink is a different
/// interface. The value records the selectors it was resolved for, so it
/// can be tied to the deployment it is used with
/// (`ExitSite::require_resolved`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedInterfaces {
    selector: InterfaceSelector,
    uplink_config: Uplink,
    egress: ResolvedInterface,
    uplink: ResolvedUplink,
}

impl ResolvedInterfaces {
    /// Checks `egress` and `uplink` against the egress `selector` and the
    /// configured `uplink_config`; see [`crate::exit::ExitSite::resolve`].
    pub(crate) fn resolve(
        selector: InterfaceSelector,
        uplink_config: Uplink,
        egress: ResolvedInterface,
        uplink: ResolvedUplink,
    ) -> Result<Self, ModelError> {
        if !egress.matches(&selector) {
            return Err(ModelError::InterfaceNotSelected {
                role: InterfaceRole::Egress,
            });
        }
        match (&uplink_config, &uplink) {
            (Uplink::SameAsExit, ResolvedUplink::SameAsExit) => {}
            (Uplink::Separate(uplink_selector), ResolvedUplink::Separate(separate)) => {
                if separate.bsd_name == egress.bsd_name || separate.index == egress.index {
                    return Err(ModelError::UplinkEqualsEgress);
                }
                if !separate.matches(uplink_selector) {
                    return Err(ModelError::InterfaceNotSelected {
                        role: InterfaceRole::Uplink,
                    });
                }
            }
            (Uplink::SameAsExit | Uplink::Separate(_), _) => {
                return Err(ModelError::UplinkModeMismatch {
                    configured: uplink_config.mode(),
                    resolved: uplink.mode(),
                });
            }
        }
        Ok(Self {
            selector,
            uplink_config,
            egress,
            uplink,
        })
    }

    /// Whether these interfaces were resolved for exactly this egress
    /// selector and uplink configuration.
    pub(crate) fn resolved_for(&self, selector: &InterfaceSelector, uplink: &Uplink) -> bool {
        self.selector == *selector && self.uplink_config == *uplink
    }

    /// The egress interface (facing the M7).
    #[must_use]
    pub const fn egress(&self) -> &ResolvedInterface {
        &self.egress
    }

    /// The uplink as resolved; its mode is the configured one.
    #[must_use]
    pub const fn uplink(&self) -> &ResolvedUplink {
        &self.uplink
    }

    /// The interface the tunnel and probes bind to: the egress for
    /// `SameAsExit`, otherwise the separate uplink.
    #[must_use]
    pub const fn uplink_interface(&self) -> &ResolvedInterface {
        match &self.uplink {
            ResolvedUplink::SameAsExit => &self.egress,
            ResolvedUplink::Separate(separate) => separate,
        }
    }

    /// The uplink address the in-chain verdict compares with (design
    /// §10.2): nothing in `SameAsExit` mode; in `Separate` mode the public
    /// address `observe` (the uplink probe) reports through the separate
    /// interface. `observe` runs only in `Separate` mode, so the address
    /// always matches the mode the site is configured with.
    pub fn uplink_address<E>(
        &self,
        observe: impl FnOnce(&ResolvedInterface) -> Result<Ipv4Addr, E>,
    ) -> Result<UplinkAddress, E> {
        match &self.uplink {
            ResolvedUplink::SameAsExit => Ok(UplinkAddress::same_as_exit()),
            ResolvedUplink::Separate(separate) => observe(separate).map(UplinkAddress::separate),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::ExitSite;
    use proptest::prelude::*;

    #[test]
    fn mac_addr_rules() {
        let addr = MacAddr::parse("02:6d:6f:6f:72:01").unwrap();
        assert_eq!(addr.to_string(), "02:6d:6f:6f:72:01");
        for bad in [
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
            "02:6D:6f:6f:72:01",
            "02-6d-6f-6f-72-01",
            "02:6d:6f:6f:72",
            "02:6d:6f:6f:72:01:00",
            "2:6d:6f:6f:72:01",
        ] {
            assert_eq!(
                MacAddr::parse(bad),
                Err(ModelError::InvalidMacAddr),
                "{bad}"
            );
        }
    }

    #[test]
    fn interface_name_rules() {
        for ok in [
            "eth0",
            "ens3",
            "enp1s0",
            "wg-exit",
            "a",
            "abcdefghijklmno",
            "br+lan",
            "v",
        ] {
            assert!(LinuxIfName::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            "eth/0",
            "eth 0",
            "abcdefghijklmnop",
            "eth:0",
            "eth0\n",
            "ethé",
        ] {
            assert_eq!(
                LinuxIfName::parse(bad),
                Err(ModelError::InvalidInterfaceName {
                    flavor: InterfaceNameKind::Linux
                }),
                "{bad:?}"
            );
        }
        for ok in ["en0", "en8", "bridge100", "utun3"] {
            assert!(BsdName::parse(ok).is_ok(), "{ok}");
        }
        for bad in ["", "en", "0", "En0", "en01", "en-0", "bridge1000000000"] {
            assert_eq!(
                BsdName::parse(bad),
                Err(ModelError::InvalidInterfaceName {
                    flavor: InterfaceNameKind::Bsd
                }),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn lan_subnet_must_be_canonical_and_inside_a_private_lan_class() {
        for ok in [
            "192.168.1.0/24",
            "192.168.64.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "192.168.1.128/25",
        ] {
            assert!(LanSubnet::new(ok.parse().unwrap()).is_ok(), "{ok}");
        }
        assert!(LanSubnet::new("192.168.1.1/24".parse().unwrap()).is_err());
        for public in [
            "81.2.3.0/24",
            "172.32.0.0/16",
            "192.168.0.0/15",
            "127.0.0.0/8",
            "0.0.0.0/0",
        ] {
            let prefix: Ipv4Net = public.parse().unwrap();
            assert_eq!(
                LanSubnet::new(prefix),
                Err(ModelError::InvalidPrefix {
                    prefix,
                    rule: PrefixRule::NotPrivateLan
                }),
                "{public}"
            );
        }
        assert!(serde_json::from_str::<LanSubnet>("\"81.2.3.0/24\"").is_err());
        assert_eq!(
            InterfaceIndex::new(0),
            Err(ModelError::InvalidInterfaceIndex)
        );
        let index = NonZeroU32::new(40).unwrap();
        assert_eq!(
            InterfaceIndex::from(index),
            InterfaceIndex::new(40).unwrap()
        );
        assert_eq!(NonZeroU32::from(InterfaceIndex::from(index)), index);
    }

    /// The egress the testing site selects: `02:6d:6f:6f:72:01` in 192.168.1.0/24.
    fn m7(name: &str, index: u32) -> ResolvedInterface {
        ResolvedInterface {
            bsd_name: BsdName::parse(name).unwrap(),
            index: InterfaceIndex::new(index).unwrap(),
            lladdr: MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
            ipv4: Ipv4Addr::new(192, 168, 1, 20),
        }
    }

    /// A home interface on 10.0.0.0/24 behind gateway `02:68:6f:6d:65:01`.
    fn home(name: &str, index: u32) -> ResolvedInterface {
        ResolvedInterface {
            bsd_name: BsdName::parse(name).unwrap(),
            index: InterfaceIndex::new(index).unwrap(),
            lladdr: MacAddr::parse("02:00:00:00:00:30").unwrap(),
            ipv4: Ipv4Addr::new(10, 0, 0, 30),
        }
    }

    fn separate_site() -> ExitSite {
        let mut site = crate::testing::exit_site();
        site.uplink = Uplink::Separate(InterfaceSelector::GatewayLinkAddr {
            gw_lladdr: MacAddr::parse("02:68:6f:6d:65:01").unwrap(),
            subnet: "10.0.0.0/24".parse().unwrap(),
        });
        site
    }

    #[test]
    fn resolution_follows_the_configured_mode_and_selectors() {
        let same_site = crate::testing::exit_site();
        let same = same_site
            .resolve(m7("en8", 21), ResolvedUplink::SameAsExit)
            .unwrap();
        assert_eq!(same.uplink_interface(), &m7("en8", 21));
        assert_eq!(same.egress(), &m7("en8", 21));
        same_site.require_resolved(&same).unwrap();

        let site = separate_site();
        let separate = site
            .resolve(m7("en8", 21), ResolvedUplink::Separate(home("en0", 4)))
            .unwrap();
        assert_eq!(separate.uplink_interface(), &home("en0", 4));
        site.require_resolved(&separate).unwrap();

        // Each mode refuses the other's resolution, both ways.
        assert_eq!(
            same_site.resolve(m7("en8", 21), ResolvedUplink::Separate(home("en0", 4))),
            Err(ModelError::UplinkModeMismatch {
                configured: UplinkMode::SameAsExit,
                resolved: UplinkMode::Separate
            })
        );
        assert_eq!(
            site.resolve(m7("en8", 21), ResolvedUplink::SameAsExit),
            Err(ModelError::UplinkModeMismatch {
                configured: UplinkMode::Separate,
                resolved: UplinkMode::SameAsExit
            })
        );
        // Interfaces resolved for one site are refused by the other.
        assert_eq!(
            site.require_resolved(&same),
            Err(ModelError::InterfacesForOtherSite)
        );
        assert_eq!(
            same_site.require_resolved(&separate),
            Err(ModelError::InterfacesForOtherSite)
        );
    }

    #[test]
    fn resolved_interfaces_must_match_their_selectors() {
        let site = separate_site();
        let mut wrong_subnet = m7("en8", 21);
        wrong_subnet.ipv4 = Ipv4Addr::new(192, 168, 2, 20);
        let mut wrong_lladdr = m7("en8", 21);
        wrong_lladdr.lladdr = MacAddr::parse("02:00:00:00:00:99").unwrap();
        for egress in [wrong_subnet, wrong_lladdr] {
            assert_eq!(
                site.resolve(egress, ResolvedUplink::Separate(home("en0", 4))),
                Err(ModelError::InterfaceNotSelected {
                    role: InterfaceRole::Egress
                })
            );
        }
        let mut stray_home = home("en0", 4);
        stray_home.ipv4 = Ipv4Addr::new(10, 0, 1, 30);
        assert_eq!(
            site.resolve(m7("en8", 21), ResolvedUplink::Separate(stray_home)),
            Err(ModelError::InterfaceNotSelected {
                role: InterfaceRole::Uplink
            })
        );
    }

    #[test]
    fn a_separate_uplink_must_be_another_interface() {
        let site = separate_site();
        for collapsed in [home("en8", 22), home("en9", 21)] {
            assert_eq!(
                site.resolve(m7("en8", 21), ResolvedUplink::Separate(collapsed)),
                Err(ModelError::UplinkEqualsEgress)
            );
        }
    }

    #[test]
    fn the_uplink_address_follows_the_resolved_mode() {
        let same = crate::testing::exit_site()
            .resolve(m7("en8", 21), ResolvedUplink::SameAsExit)
            .unwrap();
        let address = same
            .uplink_address(|_| Err::<Ipv4Addr, &str>("no uplink probe in SameAsExit mode"))
            .unwrap();
        assert_eq!(address.separate_ip(), None);
        let separate = separate_site()
            .resolve(m7("en8", 21), ResolvedUplink::Separate(home("en0", 4)))
            .unwrap();
        let address = separate
            .uplink_address(|interface| {
                assert_eq!(interface, &home("en0", 4));
                Ok::<_, &str>(Ipv4Addr::new(81, 2, 3, 4))
            })
            .unwrap();
        assert_eq!(address.separate_ip(), Some(Ipv4Addr::new(81, 2, 3, 4)));
        assert_eq!(
            separate.uplink_address(|_| Err("probe failed")),
            Err("probe failed")
        );
    }

    #[test]
    fn selector_serde_is_closed() {
        let selector: InterfaceSelector = serde_json::from_str(
            r#"{"link_addr":{"lladdr":"02:6d:6f:6f:72:01","subnet":"192.168.1.0/24"}}"#,
        )
        .unwrap();
        assert_eq!(selector.subnet().get().to_string(), "192.168.1.0/24");
        assert!(serde_json::from_str::<InterfaceSelector>(
            r#"{"link_addr":{"lladdr":"02:6d:6f:6f:72:01","subnet":"192.168.1.0/24","extra":1}}"#,
        )
        .is_err());
        assert!(
            serde_json::from_str::<InterfaceSelector>(
                r#"{"wifi":{"lladdr":"02:6d:6f:6f:72:01","subnet":"192.168.1.0/24"}}"#,
            )
            .is_err()
        );
    }

    proptest! {
        #[test]
        fn mac_addr_round_trips(bytes in proptest::array::uniform6(any::<u8>())) {
            match MacAddr::from_bytes(bytes) {
                Ok(addr) => prop_assert_eq!(MacAddr::parse(&addr.to_string()).unwrap(), addr),
                Err(_) => prop_assert!(bytes == [0; 6] || bytes[0] & 1 == 1),
            }
        }

        #[test]
        fn bsd_names_from_the_pattern_parse(letters in "[a-z]{1,8}", unit in 0_u32..10_000) {
            let name = format!("{letters}{unit}");
            prop_assert_eq!(BsdName::parse(&name).is_ok(), name.len() <= 15);
        }
    }
}
