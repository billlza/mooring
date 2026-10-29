// SPDX-License-Identifier: GPL-3.0-or-later

//! The network check (console spec P0-2, critique D-11; design §10.2): the
//! exit Mac must not be attached to any network other than the M7's, the
//! separate uplink's, a TUN that CFM numbers in the benchmarking range, or
//! a network the operator declared as their own, because Durham's IT
//! regulations forbid connecting a device that routes traffic for others
//! (§5.1) to the University network, and any socket not bound to the egress
//! would leave through that other network.
//!
//! The check is a pure function over a typed snapshot of the Mac's
//! interfaces, their routers and its default routes (built by `macsys` and
//! `mooringctl`, verified live there). It sorts every interface that is not
//! the egress or the uplink into one of three classes:
//!
//! - **allowed**: CFM's TUN, told by its addresses and never by its name
//!   alone (a `utun*` holding at least one IPv4 address, every IPv4 address
//!   in 198.18.0.0/15 and no global IPv6 address outside 2001:2::/48); or an
//!   interface whose router matches a declared own network and whose DNS
//!   domain is not an institutional one;
//! - **foreign**: any other interface that holds a routable IPv4 address
//!   (anything but loopback and link-local) or a global unicast IPv6
//!   address, one finding per attribute, and every default route through
//!   it;
//! - **nothing**: an interface with no such address (macOS's own
//!   `utun0`–`utun3` with link-local IPv6 only, Wi-Fi off, a bridge on
//!   link-local addresses).
//!
//! The allowed attachments are reported beside the findings, so the status
//! shows what the check let through.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use mooring_model::dns::DnsName;
use mooring_model::iface::{BsdName, RouterIdentity};
use mooring_model::ipv4::{SpecialClass, classify};
use mooring_model::own_network::{OwnNetworkKind, OwnNetworks};
use serde::{Deserialize, Serialize};

/// The domain under which every UK academic network (Janet) names itself.
/// A network whose DNS domain is within it is institutional whatever the
/// operator declares (P0-2). The guard is advisory: a network that publishes
/// no domain, or another one, is not caught by it.
pub const INSTITUTIONAL_DOMAIN: &str = "ac.uk";

/// Whether `domain` is within [`INSTITUTIONAL_DOMAIN`].
#[must_use]
pub fn institutional(domain: &DnsName) -> bool {
    domain.is_within(INSTITUTIONAL_DOMAIN)
}

/// An IP family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// One interface as the Mac sees it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct InterfaceObservation {
    /// Its IPv4 addresses.
    pub ipv4: BTreeSet<Ipv4Addr>,
    /// Its IPv6 addresses.
    pub ipv6: BTreeSet<Ipv6Addr>,
    /// Its IPv4 router as configd resolved it, the gateway's address and
    /// link-layer address: `None` without a router, while the link-layer
    /// address is unresolved or unusable, or when the interface has more
    /// than one IPv4 service with a router.
    pub router: Option<RouterIdentity>,
    /// The DNS domain the network publishes (DHCP option 15), lowercased.
    pub domain: Option<DnsName>,
}

/// The Mac's interfaces and the interfaces its unscoped default routes use.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkSnapshot {
    /// Every interface, by BSD name.
    pub interfaces: BTreeMap<BsdName, InterfaceObservation>,
    /// The unscoped default routes, by family and interface (interface-
    /// scoped defaults are how macOS keeps per-interface routes and are not
    /// listed).
    pub default_routes: BTreeSet<(IpFamily, BsdName)>,
}

/// The interfaces the check does not judge, and the declarations it honours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exemptions<'a> {
    /// The egress facing the M7.
    pub egress: BsdName,
    /// The separate uplink in `Separate` mode: the operator's own line,
    /// named by the deployment.
    pub uplink: Option<BsdName>,
    /// The operator's declared own networks.
    pub own: &'a OwnNetworks,
}

impl Exemptions<'_> {
    fn exempt(&self, name: &BsdName) -> bool {
        *name == self.egress || self.uplink.as_ref() == Some(name)
    }
}

/// One way the Mac is attached to a network other than the M7's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ForeignNetworkFinding {
    /// The interface holds an IPv4 address that is neither loopback nor
    /// link-local.
    RoutableIpv4 {
        /// The interface.
        interface: BsdName,
    },
    /// The interface holds a global unicast IPv6 address (2000::/3).
    GlobalIpv6 {
        /// The interface.
        interface: BsdName,
    },
    /// A default route uses the interface.
    DefaultRoute {
        /// The interface.
        interface: BsdName,
        /// The route's family.
        family: IpFamily,
    },
}

/// An attachment the check allows, reported so the status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AllowedNetwork {
    /// The interface's router matches a network the operator declared as
    /// their own; the exit keeps serving while the Mac is joined to it.
    Own {
        /// The interface.
        interface: BsdName,
        /// The declared kind.
        kind: OwnNetworkKind,
    },
    /// A TUN numbered only in the benchmarking range (198.18.0.0/15 and
    /// 2001:2::/48): CFM's, in its TUN mode, which may hold the default
    /// route; a tunnel is not a network attachment, and the physical
    /// interface it rides is judged on its own.
    BenchmarkingTun {
        /// The interface.
        interface: BsdName,
    },
}

/// What the check found: the foreign attachments, which take the exit
/// down, and the allowed ones.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkCheck {
    /// Every foreign attachment, in order; empty when the Mac is attached to
    /// nothing but the M7, the uplink and the allowed networks.
    pub foreign: BTreeSet<ForeignNetworkFinding>,
    /// Every allowed attachment, in order.
    pub allowed: BTreeSet<AllowedNetwork>,
}

/// Whether an IPv4 address can reach beyond its interface: anything but
/// loopback (127.0.0.0/8), link-local (169.254.0.0/16) and the unspecified
/// address.
fn routable_v4(addr: Ipv4Addr) -> bool {
    !(addr.is_loopback() || addr.is_link_local() || addr.is_unspecified())
}

/// Whether an IPv6 address is global unicast, 2000::/3 (RFC 4291 §2.4 and
/// IANA's allocation). Link-local, unique-local, loopback and multicast
/// addresses are not.
fn global_v6(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xe000 == 0x2000
}

/// Whether an IPv4 address is in the benchmarking range, 198.18.0.0/15
/// (RFC 2544), which CFM numbers its TUN from (198.18.64.1/30 observed).
fn benchmarking_v4(addr: Ipv4Addr) -> bool {
    classify(addr) == Some(SpecialClass::Benchmarking)
}

/// Whether an IPv6 address is in the benchmarking range, 2001:2::/48
/// (RFC 5180), which CFM numbers its TUN from (2001:2:0:64::1/126
/// observed); the range lies inside 2000::/3.
fn benchmarking_v6(addr: Ipv6Addr) -> bool {
    let segments = addr.segments();
    segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0
}

/// Whether the interface is a TUN numbered only in the benchmarking range:
/// named `utun*`, holding at least one IPv4 address, every IPv4 address in
/// 198.18.0.0/15 and every IPv6 address either not global or in
/// 2001:2::/48. An addressless or link-local-only `utun` is not one.
fn benchmarking_tun(name: &BsdName, observed: &InterfaceObservation) -> bool {
    name.as_str().starts_with("utun")
        && !observed.ipv4.is_empty()
        && observed.ipv4.iter().all(|&addr| benchmarking_v4(addr))
        && observed
            .ipv6
            .iter()
            .all(|&addr| !global_v6(addr) || benchmarking_v6(addr))
}

/// How the check sorts one interface.
enum Class {
    /// The egress or the uplink: not judged.
    Exempt,
    /// Allowed, and reported as such.
    Allowed(AllowedNetwork),
    /// Judged by its addresses and routes.
    Foreign,
}

fn class(name: &BsdName, observed: &InterfaceObservation, exemptions: &Exemptions<'_>) -> Class {
    if exemptions.exempt(name) {
        return Class::Exempt;
    }
    if benchmarking_tun(name, observed) {
        return Class::Allowed(AllowedNetwork::BenchmarkingTun {
            interface: name.clone(),
        });
    }
    if let Some(router) = &observed.router
        && let Some((_, network)) = exemptions.own.matching(router)
        && !observed.domain.as_ref().is_some_and(institutional)
    {
        return Class::Allowed(AllowedNetwork::Own {
            interface: name.clone(),
            kind: network.kind,
        });
    }
    Class::Foreign
}

/// Judges `snapshot`: the foreign attachments and the allowed ones. A
/// default route through an interface the snapshot does not list is
/// foreign unless the interface is exempt (fail closed).
#[must_use]
pub fn network_check(snapshot: &NetworkSnapshot, exemptions: &Exemptions<'_>) -> NetworkCheck {
    let mut check = NetworkCheck::default();
    let mut foreign_interfaces: BTreeMap<&BsdName, bool> = BTreeMap::new();
    for (name, observed) in &snapshot.interfaces {
        let foreign = match class(name, observed, exemptions) {
            Class::Exempt => false,
            Class::Allowed(allowed) => {
                check.allowed.insert(allowed);
                false
            }
            Class::Foreign => {
                if observed.ipv4.iter().any(|&addr| routable_v4(addr)) {
                    check.foreign.insert(ForeignNetworkFinding::RoutableIpv4 {
                        interface: name.clone(),
                    });
                }
                if observed.ipv6.iter().any(|&addr| global_v6(addr)) {
                    check.foreign.insert(ForeignNetworkFinding::GlobalIpv6 {
                        interface: name.clone(),
                    });
                }
                true
            }
        };
        foreign_interfaces.insert(name, foreign);
    }
    for (family, name) in &snapshot.default_routes {
        let foreign = foreign_interfaces
            .get(name)
            .copied()
            .unwrap_or_else(|| !exemptions.exempt(name));
        if foreign {
            check.foreign.insert(ForeignNetworkFinding::DefaultRoute {
                interface: name.clone(),
                family: *family,
            });
        }
    }
    check
}

#[cfg(test)]
mod tests {
    use mooring_model::ids::LocalLabel;
    use mooring_model::iface::MacAddr;
    use mooring_model::own_network::OwnNetwork;
    use mooring_model::time::UnixTime;
    use proptest::prelude::*;

    use super::*;

    fn name(text: &str) -> BsdName {
        BsdName::parse(text).unwrap()
    }

    fn v4(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    fn v6(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    fn domain(text: &str) -> DnsName {
        DnsName::parse(text).unwrap()
    }

    /// The iPhone's hotspot router, and the same device on its USB medium.
    const HOTSPOT: &str = "aa:bb:cc:dd:ee:01";
    const HOME: &str = "aa:bb:cc:dd:ee:02";
    const OTHER: &str = "aa:bb:cc:dd:ee:03";

    fn router(addr: &str, lladdr: &str) -> RouterIdentity {
        RouterIdentity::new(v4(addr), MacAddr::parse(lladdr).unwrap()).unwrap()
    }

    fn declared(networks: &[(&str, OwnNetworkKind, RouterIdentity)]) -> OwnNetworks {
        let mut own = OwnNetworks::new();
        for (label, kind, identity) in networks {
            own.insert(
                LocalLabel::parse(label).unwrap(),
                OwnNetwork {
                    kind: *kind,
                    router: *identity,
                    declared_at: UnixTime::from_secs(1_793_300_000),
                },
            );
        }
        own
    }

    fn exemptions(own: &OwnNetworks) -> Exemptions<'_> {
        Exemptions {
            egress: name("en8"),
            uplink: None,
            own,
        }
    }

    fn observed(ipv4: &[&str], ipv6: &[&str]) -> InterfaceObservation {
        InterfaceObservation {
            ipv4: ipv4.iter().map(|text| v4(text)).collect(),
            ipv6: ipv6.iter().map(|text| v6(text)).collect(),
            router: None,
            domain: None,
        }
    }

    /// The exit Mac as designed: the M7 on en8, Wi-Fi off but present,
    /// loopback, CFM's TUN (0.5.1: 198.18.64.1/30 and 2001:2:0:64::1/126)
    /// holding the default route, macOS's own utun with link-local IPv6
    /// only, and a bridge on link-local addresses.
    fn clean() -> NetworkSnapshot {
        NetworkSnapshot {
            interfaces: BTreeMap::from([
                (name("lo0"), observed(&["127.0.0.1"], &["::1", "fe80::1"])),
                (
                    name("en8"),
                    observed(&["192.168.1.20"], &["2a00:23c7:1::20"]),
                ),
                (name("en0"), InterfaceObservation::default()),
                (name("utun0"), observed(&[], &["fe80::ce81:b1c:bd2c:69e"])),
                (
                    name("utun8"),
                    observed(&["198.18.64.1"], &["2001:2:0:64::1"]),
                ),
                (name("bridge0"), observed(&["169.254.10.2"], &["fd00::2"])),
            ]),
            default_routes: BTreeSet::from([
                (IpFamily::V4, name("en8")),
                (IpFamily::V4, name("utun8")),
                (IpFamily::V6, name("en8")),
            ]),
        }
    }

    fn cfm_tun() -> AllowedNetwork {
        AllowedNetwork::BenchmarkingTun {
            interface: name("utun8"),
        }
    }

    #[test]
    fn the_designed_exit_mac_has_no_foreign_network_and_cfm_tun_is_allowed() {
        let none = OwnNetworks::new();
        let check = network_check(&clean(), &exemptions(&none));
        assert!(check.foreign.is_empty(), "{:?}", check.foreign);
        assert_eq!(check.allowed, BTreeSet::from([cfm_tun()]));
    }

    #[test]
    fn cfm_tun_is_told_by_its_addresses_never_by_its_name_alone() {
        let none = OwnNetworks::new();
        let utun8 = name("utun8");
        // Another IPv4 address beside the benchmarking one: not CFM's TUN,
        // so it is judged like any interface, and its benchmarking IPv6
        // address counts as global; its default route is a finding too.
        let mut mixed = clean();
        mixed.interfaces.insert(
            utun8.clone(),
            observed(&["198.18.64.1", "10.0.0.5"], &["2001:2:0:64::1"]),
        );
        assert_eq!(
            network_check(&mixed, &exemptions(&none)),
            NetworkCheck {
                foreign: BTreeSet::from([
                    ForeignNetworkFinding::RoutableIpv4 {
                        interface: utun8.clone()
                    },
                    ForeignNetworkFinding::GlobalIpv6 {
                        interface: utun8.clone()
                    },
                    ForeignNetworkFinding::DefaultRoute {
                        interface: utun8.clone(),
                        family: IpFamily::V4
                    },
                ]),
                allowed: BTreeSet::new(),
            }
        );
        // A global IPv6 address outside 2001:2::/48 is foreign too.
        let mut global = clean();
        global
            .interfaces
            .insert(utun8.clone(), observed(&["198.18.64.1"], &["2001:3::1"]));
        let check = network_check(&global, &exemptions(&none));
        assert!(check.foreign.contains(&ForeignNetworkFinding::GlobalIpv6 {
            interface: utun8.clone()
        }));
        assert!(check.allowed.is_empty());
        // No IPv4 address at all: not CFM's TUN, so its global IPv6 counts.
        let mut six_only = clean();
        six_only
            .interfaces
            .insert(utun8.clone(), observed(&[], &["2001:2:0:64::1"]));
        let check = network_check(&six_only, &exemptions(&none));
        assert_eq!(
            check.foreign,
            BTreeSet::from([
                ForeignNetworkFinding::GlobalIpv6 {
                    interface: utun8.clone()
                },
                ForeignNetworkFinding::DefaultRoute {
                    interface: utun8.clone(),
                    family: IpFamily::V4
                },
            ])
        );
        // The benchmarking address on an interface that is not a utun.
        let mut bridge = clean();
        bridge
            .interfaces
            .insert(name("bridge100"), observed(&["198.18.64.1"], &[]));
        assert!(network_check(&bridge, &exemptions(&none)).foreign.contains(
            &ForeignNetworkFinding::RoutableIpv4 {
                interface: name("bridge100")
            }
        ));
        // Another VPN's utun (Tailscale) is foreign by its CGNAT address.
        let mut tailscale = clean();
        tailscale.interfaces.insert(
            name("utun7"),
            observed(&["100.64.0.3"], &["fd7a:115c:a1e0::1"]),
        );
        let check = network_check(&tailscale, &exemptions(&none));
        assert_eq!(
            check.foreign,
            BTreeSet::from([ForeignNetworkFinding::RoutableIpv4 {
                interface: name("utun7")
            }])
        );
        assert_eq!(check.allowed, BTreeSet::from([cfm_tun()]));
        // An addressless utun, like macOS's link-local-only ones, is nothing.
        let mut idle = clean();
        idle.interfaces
            .insert(name("utun9"), InterfaceObservation::default());
        let check = network_check(&idle, &exemptions(&none));
        assert!(check.foreign.is_empty());
        assert_eq!(check.allowed, BTreeSet::from([cfm_tun()]));
    }

    #[test]
    fn each_way_of_joining_another_network_is_found() {
        let none = OwnNetworks::new();
        let mut snapshot = clean();
        // Wi-Fi joined eduroam: an IPv4 address, a global IPv6 address and
        // a default route.
        let wifi = snapshot.interfaces.get_mut(&name("en0")).unwrap();
        wifi.ipv4.insert(v4("10.240.3.7"));
        wifi.ipv6.insert(v6("2001:630:21:1::7"));
        snapshot.default_routes.insert((IpFamily::V6, name("en0")));
        // The iPhone's hotspot over USB, not declared.
        snapshot
            .interfaces
            .insert(name("en9"), observed(&["172.20.10.2"], &[]));
        // Another VPN's tunnel.
        snapshot
            .interfaces
            .insert(name("utun7"), observed(&["100.64.0.3"], &[]));
        assert_eq!(
            network_check(&snapshot, &exemptions(&none)).foreign,
            BTreeSet::from([
                ForeignNetworkFinding::RoutableIpv4 {
                    interface: name("en0")
                },
                ForeignNetworkFinding::RoutableIpv4 {
                    interface: name("en9")
                },
                ForeignNetworkFinding::RoutableIpv4 {
                    interface: name("utun7")
                },
                ForeignNetworkFinding::GlobalIpv6 {
                    interface: name("en0")
                },
                ForeignNetworkFinding::DefaultRoute {
                    interface: name("en0"),
                    family: IpFamily::V6
                },
            ])
        );
        assert_eq!(
            serde_json::to_string(&ForeignNetworkFinding::DefaultRoute {
                interface: name("en0"),
                family: IpFamily::V4
            })
            .unwrap(),
            r#"{"default_route":{"interface":"en0","family":"v4"}}"#
        );
    }

    #[test]
    fn a_declared_network_is_own_even_when_it_holds_the_default_route() {
        let hotspot = router("172.20.10.1", HOTSPOT);
        let own = declared(&[("my phone", OwnNetworkKind::PersonalHotspot, hotspot)]);
        let none = OwnNetworks::new();
        let en0 = name("en0");
        let joined = |identity: Option<RouterIdentity>, dns: Option<&str>| {
            let mut snapshot = clean();
            snapshot.interfaces.insert(
                en0.clone(),
                InterfaceObservation {
                    ipv4: BTreeSet::from([v4("172.20.10.2")]),
                    ipv6: BTreeSet::new(),
                    router: identity,
                    domain: dns.map(domain),
                },
            );
            snapshot.default_routes.insert((IpFamily::V4, en0.clone()));
            snapshot
        };
        let findings = BTreeSet::from([
            ForeignNetworkFinding::RoutableIpv4 {
                interface: en0.clone(),
            },
            ForeignNetworkFinding::DefaultRoute {
                interface: en0.clone(),
                family: IpFamily::V4,
            },
        ]);
        // Declared: allowed, nothing foreign, the default route included.
        assert_eq!(
            network_check(&joined(Some(hotspot), None), &exemptions(&own)),
            NetworkCheck {
                foreign: BTreeSet::new(),
                allowed: BTreeSet::from([
                    AllowedNetwork::Own {
                        interface: en0.clone(),
                        kind: OwnNetworkKind::PersonalHotspot,
                    },
                    cfm_tun(),
                ]),
            }
        );
        // Not declared: foreign.
        assert_eq!(
            network_check(&joined(Some(hotspot), None), &exemptions(&none)).foreign,
            findings
        );
        // The same router address behind another device, the same device
        // at another address, or no resolved router: foreign.
        for other in [
            Some(router("172.20.10.1", OTHER)),
            Some(router("192.168.0.1", HOTSPOT)),
            None,
        ] {
            let check = network_check(&joined(other, None), &exemptions(&own));
            assert_eq!(check.foreign, findings, "{other:?}");
            assert_eq!(check.allowed, BTreeSet::from([cfm_tun()]));
        }
        // A declared router that now publishes an institutional domain is
        // foreign (P0-2); any other domain leaves it own.
        for institutional in ["dur.ac.uk", "ac.uk", "eduroam.ac.uk"] {
            let check = network_check(
                &joined(Some(hotspot), Some(institutional)),
                &exemptions(&own),
            );
            assert_eq!(check.foreign, findings, "{institutional}");
        }
        for elsewhere in ["example.com", "home.arpa", "myac.uk", "ac.uk.example.net"] {
            let check = network_check(&joined(Some(hotspot), Some(elsewhere)), &exemptions(&own));
            assert!(check.foreign.is_empty(), "{elsewhere}: {:?}", check.foreign);
        }
        // The same device over a second medium: both interfaces are own.
        let mut two = joined(Some(hotspot), None);
        two.interfaces.insert(
            name("en5"),
            InterfaceObservation {
                ipv4: BTreeSet::from([v4("172.20.10.3")]),
                router: Some(hotspot),
                ..InterfaceObservation::default()
            },
        );
        let check = network_check(&two, &exemptions(&own));
        assert!(check.foreign.is_empty());
        assert_eq!(check.allowed.len(), 3);
    }

    #[test]
    fn the_separate_uplink_is_exempt_like_the_egress() {
        let none = OwnNetworks::new();
        let mut snapshot = clean();
        snapshot
            .interfaces
            .insert(name("en7"), observed(&["10.0.0.2"], &[]));
        snapshot.default_routes.insert((IpFamily::V4, name("en7")));
        let with_uplink = Exemptions {
            egress: name("en8"),
            uplink: Some(name("en7")),
            own: &none,
        };
        assert!(network_check(&snapshot, &with_uplink).foreign.is_empty());
        assert_eq!(
            network_check(&snapshot, &exemptions(&none)).foreign.len(),
            2
        );
        // A default route through an interface the snapshot does not list
        // is foreign unless the interface is exempt.
        let mut unlisted = clean();
        unlisted.default_routes.insert((IpFamily::V4, name("en7")));
        assert_eq!(
            network_check(&unlisted, &exemptions(&none)).foreign,
            BTreeSet::from([ForeignNetworkFinding::DefaultRoute {
                interface: name("en7"),
                family: IpFamily::V4
            }])
        );
        assert!(network_check(&unlisted, &with_uplink).foreign.is_empty());
    }

    #[test]
    fn allowed_networks_have_a_fixed_encoding() {
        assert_eq!(
            serde_json::to_string(&AllowedNetwork::Own {
                interface: name("en0"),
                kind: OwnNetworkKind::PersonalHotspot
            })
            .unwrap(),
            r#"{"own":{"interface":"en0","kind":"personal_hotspot"}}"#
        );
        assert_eq!(
            serde_json::to_string(&cfm_tun()).unwrap(),
            r#"{"benchmarking_tun":{"interface":"utun8"}}"#
        );
        assert!(
            serde_json::from_str::<AllowedNetwork>(
                r#"{"own":{"interface":"en0","kind":"personal_hotspot","ssid":"x"}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<AllowedNetwork>(r#"{"personal_hotspot":{"interface":"en0"}}"#)
                .is_err()
        );
    }

    #[test]
    fn address_classes_follow_their_ranges() {
        for routable in [
            "10.0.0.1",
            "172.20.10.2",
            "192.168.1.20",
            "100.64.0.1",
            "8.8.8.8",
            "169.253.255.255",
            "169.255.0.0",
            "198.18.64.1",
        ] {
            assert!(routable_v4(v4(routable)), "{routable}");
        }
        for local in [
            "127.0.0.1",
            "127.255.255.254",
            "169.254.0.1",
            "169.254.255.255",
            "0.0.0.0",
        ] {
            assert!(!routable_v4(v4(local)), "{local}");
        }
        for global in [
            "2000::1",
            "2001:db8::1",
            "2a00:23c7::1",
            "3fff:ffff::1",
            "2001:2:0:64::1",
        ] {
            assert!(global_v6(v6(global)), "{global}");
        }
        for other in [
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fc00::1",
            "ff02::1",
            "4000::1",
            "1fff::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!global_v6(v6(other)), "{other}");
        }
        for inside in ["198.18.0.0", "198.18.64.1", "198.19.255.255"] {
            assert!(benchmarking_v4(v4(inside)), "{inside}");
        }
        for outside in ["198.17.255.255", "198.20.0.0", "198.51.100.1", "10.0.0.1"] {
            assert!(!benchmarking_v4(v4(outside)), "{outside}");
        }
        for inside in [
            "2001:2::",
            "2001:2:0:64::1",
            "2001:2:0:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(benchmarking_v6(v6(inside)), "{inside}");
        }
        for outside in ["2001:2:1::", "2001:1:ffff::", "2001:3::1", "2001:db8::1"] {
            assert!(!benchmarking_v6(v6(outside)), "{outside}");
        }
        for within in ["ac.uk", "dur.ac.uk", "eduroam.dur.ac.uk"] {
            assert!(institutional(&domain(within)), "{within}");
        }
        for elsewhere in [
            "uk",
            "myac.uk",
            "ac.uk.example.net",
            "example.com",
            "ac.ukx",
        ] {
            assert!(!institutional(&domain(elsewhere)), "{elsewhere}");
        }
    }

    fn interface_name() -> impl Strategy<Value = BsdName> {
        prop_oneof![
            Just("en0"),
            Just("en5"),
            Just("en7"),
            Just("en8"),
            Just("utun4"),
            Just("utun7"),
            Just("bridge100")
        ]
        .prop_map(name)
    }

    fn ipv4() -> impl Strategy<Value = Ipv4Addr> {
        prop_oneof![
            any::<u32>().prop_map(Ipv4Addr::from),
            Just(v4("198.18.64.1")),
            Just(v4("198.19.0.7")),
            Just(v4("169.254.3.3")),
            Just(v4("127.0.0.1")),
        ]
    }

    fn ipv6() -> impl Strategy<Value = Ipv6Addr> {
        prop_oneof![
            any::<u128>().prop_map(Ipv6Addr::from),
            Just(v6("2001:2:0:64::1")),
            Just(v6("fe80::1")),
            Just(v6("2001:3::1")),
        ]
    }

    /// Three routers: the hotspot, the home line and a stranger.
    fn routers() -> [RouterIdentity; 3] {
        [
            router("172.20.10.1", HOTSPOT),
            router("192.168.0.1", HOME),
            router("10.0.0.1", OTHER),
        ]
    }

    fn router_identity() -> impl Strategy<Value = Option<RouterIdentity>> {
        prop_oneof![
            Just(None),
            (0_usize..3).prop_map(|index| Some(routers()[index])),
        ]
    }

    fn dns_domain() -> impl Strategy<Value = Option<DnsName>> {
        prop_oneof![
            Just(None),
            Just(Some(domain("dur.ac.uk"))),
            Just(Some(domain("example.com"))),
        ]
    }

    fn observation() -> impl Strategy<Value = InterfaceObservation> {
        (
            proptest::collection::btree_set(ipv4(), 0..3),
            proptest::collection::btree_set(ipv6(), 0..3),
            router_identity(),
            dns_domain(),
        )
            .prop_map(|(ipv4, ipv6, router, domain)| InterfaceObservation {
                ipv4,
                ipv6,
                router,
                domain,
            })
    }

    fn snapshot() -> impl Strategy<Value = NetworkSnapshot> {
        (
            proptest::collection::btree_map(interface_name(), observation(), 0..7),
            proptest::collection::btree_set(
                (
                    prop_oneof![Just(IpFamily::V4), Just(IpFamily::V6)],
                    interface_name(),
                ),
                0..4,
            ),
        )
            .prop_map(|(interfaces, default_routes)| NetworkSnapshot {
                interfaces,
                default_routes,
            })
    }

    /// Any subset of the first two routers declared (the stranger never is).
    fn declarations() -> impl Strategy<Value = OwnNetworks> {
        (any::<bool>(), any::<bool>()).prop_map(|(phone, home)| {
            let [hotspot, broadband, _] = routers();
            let mut networks = Vec::new();
            if phone {
                networks.push(("my phone", OwnNetworkKind::PersonalHotspot, hotspot));
            }
            if home {
                networks.push(("home", OwnNetworkKind::Broadband, broadband));
            }
            declared(&networks)
        })
    }

    fn uplink() -> impl Strategy<Value = Option<BsdName>> {
        prop_oneof![Just(None), Just(Some(name("en7")))]
    }

    fn interface_of(finding: &ForeignNetworkFinding) -> &BsdName {
        match finding {
            ForeignNetworkFinding::RoutableIpv4 { interface }
            | ForeignNetworkFinding::GlobalIpv6 { interface }
            | ForeignNetworkFinding::DefaultRoute { interface, .. } => interface,
        }
    }

    fn interface_of_allowed(allowed: &AllowedNetwork) -> &BsdName {
        match allowed {
            AllowedNetwork::Own { interface, .. }
            | AllowedNetwork::BenchmarkingTun { interface } => interface,
        }
    }

    proptest! {
        /// Every interface is exempt, allowed or judged, never two of them;
        /// a finding exists exactly when a judged interface has the
        /// attribute it names; an allowed interface is exactly one that
        /// passes the TUN rule or matches a declaration off an
        /// institutional domain; and declaring more never adds a finding.
        #[test]
        fn findings_and_allowances_follow_the_rules(snapshot in snapshot(), own in declarations(), uplink in uplink()) {
            let exemptions = Exemptions { egress: name("en8"), uplink, own: &own };
            let check = network_check(&snapshot, &exemptions);
            let foreign_names: BTreeSet<&BsdName> = check.foreign.iter().map(interface_of).collect();
            let allowed_names: BTreeSet<&BsdName> = check.allowed.iter().map(interface_of_allowed).collect();
            prop_assert!(foreign_names.is_disjoint(&allowed_names));
            for named in foreign_names.iter().chain(&allowed_names) {
                prop_assert!(!exemptions.exempt(named));
            }
            for (interface, observed) in &snapshot.interfaces {
                let exempt = exemptions.exempt(interface);
                let tun = benchmarking_tun(interface, observed);
                let matched = observed.router.as_ref().and_then(|router| own.matching(router));
                let off_campus = !observed.domain.as_ref().is_some_and(institutional);
                let allowed = !exempt && (tun || (matched.is_some() && off_campus));
                prop_assert_eq!(allowed_names.contains(interface), allowed, "{}", interface.as_str());
                let judged = !exempt && !allowed;
                prop_assert_eq!(
                    check.foreign.contains(&ForeignNetworkFinding::RoutableIpv4 { interface: interface.clone() }),
                    judged && observed.ipv4.iter().any(|&addr| routable_v4(addr))
                );
                prop_assert_eq!(
                    check.foreign.contains(&ForeignNetworkFinding::GlobalIpv6 { interface: interface.clone() }),
                    judged && observed.ipv6.iter().any(|&addr| global_v6(addr))
                );
                if tun && !exempt {
                    let expected = AllowedNetwork::BenchmarkingTun { interface: interface.clone() };
                    prop_assert!(check.allowed.contains(&expected));
                } else if let Some((_, network)) = matched && off_campus && !exempt {
                    let expected = AllowedNetwork::Own { interface: interface.clone(), kind: network.kind };
                    prop_assert!(check.allowed.contains(&expected));
                }
            }
            for (family, interface) in &snapshot.default_routes {
                let listed = snapshot.interfaces.contains_key(interface);
                let expected = if listed {
                    !exemptions.exempt(interface) && !allowed_names.contains(interface)
                } else {
                    !exemptions.exempt(interface)
                };
                prop_assert_eq!(
                    check.foreign.contains(&ForeignNetworkFinding::DefaultRoute { interface: interface.clone(), family: *family }),
                    expected
                );
            }
            // Declaring nothing finds at least as much as declaring `own`.
            let none = OwnNetworks::new();
            let strict = network_check(&snapshot, &Exemptions { egress: name("en8"), uplink: exemptions.uplink.clone(), own: &none });
            prop_assert!(check.foreign.is_subset(&strict.foreign));
        }
    }
}
