// SPDX-License-Identifier: GPL-3.0-or-later

//! The foreign-network check (console spec P0-2, critique D-11): the exit
//! Mac must not join any network other than the M7's, because Durham's IT
//! regulations forbid connecting a device that routes traffic for others
//! (§5.1), and any socket not bound to the egress would leave through that
//! other network.
//!
//! The check is a pure function over a typed snapshot of the Mac's
//! interfaces and default routes (built by `macsys` in M5, and verified
//! live there in L8/M8). An interface other than the egress and the
//! explicitly exempt tunnels is foreign if it holds a routable IPv4 address
//! (anything but loopback and link-local) or a global unicast IPv6 address,
//! carries a default route, or is joined to a personal hotspot.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use mooring_model::iface::BsdName;
use serde::{Deserialize, Serialize};

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
    /// Whether macOS reports it joined to a personal hotspot (Instant
    /// Hotspot to the operator's iPhone, over Wi-Fi, USB or Bluetooth).
    pub personal_hotspot: bool,
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

/// The interfaces the check ignores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exemptions {
    /// The egress facing the M7.
    pub egress: BsdName,
    /// CFM's TUN interface, which holds a private IPv4 address and may hold
    /// the default route while CFM's TUN mode is on (design §10.4), and in
    /// lab builds the lab bridge. Every other tunnel counts.
    pub tunnels: BTreeSet<BsdName>,
}

impl Exemptions {
    fn exempt(&self, name: &BsdName) -> bool {
        *name == self.egress || self.tunnels.contains(name)
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
    /// The interface is joined to a personal hotspot.
    PersonalHotspot {
        /// The interface.
        interface: BsdName,
    },
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

/// Every foreign attachment in `snapshot`, in order; empty when the Mac is
/// attached to nothing but the M7 and the exempt tunnels.
#[must_use]
pub fn foreign_networks(
    snapshot: &NetworkSnapshot,
    exemptions: &Exemptions,
) -> BTreeSet<ForeignNetworkFinding> {
    let mut findings = BTreeSet::new();
    for (name, observed) in &snapshot.interfaces {
        if exemptions.exempt(name) {
            continue;
        }
        if observed.ipv4.iter().any(|&addr| routable_v4(addr)) {
            findings.insert(ForeignNetworkFinding::RoutableIpv4 {
                interface: name.clone(),
            });
        }
        if observed.ipv6.iter().any(|&addr| global_v6(addr)) {
            findings.insert(ForeignNetworkFinding::GlobalIpv6 {
                interface: name.clone(),
            });
        }
        if observed.personal_hotspot {
            findings.insert(ForeignNetworkFinding::PersonalHotspot {
                interface: name.clone(),
            });
        }
    }
    for (family, name) in &snapshot.default_routes {
        if !exemptions.exempt(name) {
            findings.insert(ForeignNetworkFinding::DefaultRoute {
                interface: name.clone(),
                family: *family,
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn name(text: &str) -> BsdName {
        BsdName::parse(text).unwrap()
    }

    fn exemptions() -> Exemptions {
        Exemptions {
            egress: name("en8"),
            tunnels: BTreeSet::from([name("utun4")]),
        }
    }

    /// The exit Mac as designed: the M7 on en8, Wi-Fi off but present,
    /// loopback, CFM's TUN with the default route, and macOS's own utuns
    /// with only link-local IPv6.
    fn clean() -> NetworkSnapshot {
        let v4 = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        let v6 = |text: &str| text.parse::<Ipv6Addr>().unwrap();
        NetworkSnapshot {
            interfaces: BTreeMap::from([
                (
                    name("lo0"),
                    InterfaceObservation {
                        ipv4: BTreeSet::from([v4("127.0.0.1")]),
                        ipv6: BTreeSet::from([v6("::1"), v6("fe80::1")]),
                        personal_hotspot: false,
                    },
                ),
                (
                    name("en8"),
                    InterfaceObservation {
                        ipv4: BTreeSet::from([v4("192.168.1.20")]),
                        ipv6: BTreeSet::from([v6("2a00:23c7:1::20")]),
                        personal_hotspot: false,
                    },
                ),
                (name("en0"), InterfaceObservation::default()),
                (
                    name("utun0"),
                    InterfaceObservation {
                        ipv6: BTreeSet::from([v6("fe80::ce81:b1c:bd2c:69e")]),
                        ..InterfaceObservation::default()
                    },
                ),
                (
                    name("utun4"),
                    InterfaceObservation {
                        ipv4: BTreeSet::from([v4("198.18.0.1")]),
                        ipv6: BTreeSet::from([v6("fdfe:dcba:9876::1")]),
                        personal_hotspot: false,
                    },
                ),
                (
                    name("bridge0"),
                    InterfaceObservation {
                        ipv4: BTreeSet::from([v4("169.254.10.2")]),
                        ipv6: BTreeSet::from([v6("fd00::2")]),
                        personal_hotspot: false,
                    },
                ),
            ]),
            default_routes: BTreeSet::from([
                (IpFamily::V4, name("en8")),
                (IpFamily::V4, name("utun4")),
                (IpFamily::V6, name("en8")),
            ]),
        }
    }

    #[test]
    fn the_designed_exit_mac_has_no_foreign_network() {
        assert!(foreign_networks(&clean(), &exemptions()).is_empty());
    }

    #[test]
    fn each_way_of_joining_another_network_is_found() {
        let mut snapshot = clean();
        // Wi-Fi joined eduroam: an IPv4 address, a global IPv6 address and
        // a default route.
        let wifi = snapshot.interfaces.get_mut(&name("en0")).unwrap();
        wifi.ipv4.insert("10.240.3.7".parse().unwrap());
        wifi.ipv6.insert("2001:630:21:1::7".parse().unwrap());
        snapshot.default_routes.insert((IpFamily::V6, name("en0")));
        // The iPhone's hotspot over USB.
        snapshot.interfaces.insert(
            name("en9"),
            InterfaceObservation {
                ipv4: BTreeSet::from(["172.20.10.2".parse().unwrap()]),
                personal_hotspot: true,
                ..InterfaceObservation::default()
            },
        );
        // Another VPN's tunnel.
        snapshot.interfaces.insert(
            name("utun7"),
            InterfaceObservation {
                ipv4: BTreeSet::from(["100.64.0.3".parse().unwrap()]),
                ..InterfaceObservation::default()
            },
        );
        assert_eq!(
            foreign_networks(&snapshot, &exemptions()),
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
                ForeignNetworkFinding::PersonalHotspot {
                    interface: name("en9")
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
    fn address_classes_follow_their_ranges() {
        for routable in [
            "10.0.0.1",
            "172.20.10.2",
            "192.168.1.20",
            "100.64.0.1",
            "8.8.8.8",
            "169.253.255.255",
            "169.255.0.0",
        ] {
            assert!(routable_v4(routable.parse().unwrap()), "{routable}");
        }
        for local in [
            "127.0.0.1",
            "127.255.255.254",
            "169.254.0.1",
            "169.254.255.255",
            "0.0.0.0",
        ] {
            assert!(!routable_v4(local.parse().unwrap()), "{local}");
        }
        for global in ["2000::1", "2001:db8::1", "2a00:23c7::1", "3fff:ffff::1"] {
            assert!(global_v6(global.parse().unwrap()), "{global}");
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
            assert!(!global_v6(other.parse().unwrap()), "{other}");
        }
    }

    fn interface_name() -> impl Strategy<Value = BsdName> {
        prop_oneof![
            Just("en0"),
            Just("en8"),
            Just("en9"),
            Just("utun4"),
            Just("utun7"),
            Just("bridge100")
        ]
        .prop_map(name)
    }

    fn observation() -> impl Strategy<Value = InterfaceObservation> {
        (
            proptest::collection::btree_set(any::<u32>().prop_map(Ipv4Addr::from), 0..3),
            proptest::collection::btree_set(any::<u128>().prop_map(Ipv6Addr::from), 0..3),
            any::<bool>(),
        )
            .prop_map(|(ipv4, ipv6, personal_hotspot)| InterfaceObservation {
                ipv4,
                ipv6,
                personal_hotspot,
            })
    }

    fn snapshot() -> impl Strategy<Value = NetworkSnapshot> {
        (
            proptest::collection::btree_map(interface_name(), observation(), 0..6),
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

    proptest! {
        /// A finding names a non-exempt interface and exists exactly when
        /// that interface has the attribute it names.
        #[test]
        fn findings_are_exactly_the_foreign_attachments(snapshot in snapshot()) {
            let exemptions = exemptions();
            let findings = foreign_networks(&snapshot, &exemptions);
            for (interface, observed) in &snapshot.interfaces {
                let foreign = !exemptions.exempt(interface);
                prop_assert_eq!(
                    findings.contains(&ForeignNetworkFinding::RoutableIpv4 { interface: interface.clone() }),
                    foreign && observed.ipv4.iter().any(|&addr| routable_v4(addr))
                );
                prop_assert_eq!(
                    findings.contains(&ForeignNetworkFinding::GlobalIpv6 { interface: interface.clone() }),
                    foreign && observed.ipv6.iter().any(|&addr| global_v6(addr))
                );
                prop_assert_eq!(
                    findings.contains(&ForeignNetworkFinding::PersonalHotspot { interface: interface.clone() }),
                    foreign && observed.personal_hotspot
                );
            }
            for (family, interface) in &snapshot.default_routes {
                prop_assert_eq!(
                    findings.contains(&ForeignNetworkFinding::DefaultRoute { interface: interface.clone(), family: *family }),
                    !exemptions.exempt(interface)
                );
            }
            let named = |finding: &ForeignNetworkFinding| match finding {
                ForeignNetworkFinding::RoutableIpv4 { interface }
                | ForeignNetworkFinding::GlobalIpv6 { interface }
                | ForeignNetworkFinding::DefaultRoute { interface, .. }
                | ForeignNetworkFinding::PersonalHotspot { interface } => interface.clone(),
            };
            for finding in &findings {
                prop_assert!(!exemptions.exempt(&named(finding)));
            }
            // Exempting every interface leaves nothing to find.
            let all = Exemptions {
                egress: name("en8"),
                tunnels: snapshot.interfaces.keys().cloned().chain(snapshot.default_routes.iter().map(|(_, name)| name.clone())).collect(),
            };
            prop_assert!(foreign_networks(&snapshot, &all).is_empty());
        }
    }
}
