// SPDX-License-Identifier: GPL-3.0-or-later

//! The `mooring-exit` config for sing-box 1.14.2 (design §8.7): one
//! userspace WireGuard endpoint per applied node, dialled out over the
//! uplink, and one `direct` outbound bound to the egress interface.
//!
//! The route rules are the Level 2 boundary: they judge the final
//! destination IP of every flow out of a tunnel. Node addresses are
//! reachable only on their reflector port; IPv6, every `SPECIAL_V4` class
//! (including 127/8, where the endpoint rewrites its own address,
//! `protocol/wireguard/endpoint.go:231-240`, and 224/4, which sing's bind
//! control never binds) and, by policy, TCP/25 are rejected.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use mooring_model::ids::NodeId;
use mooring_model::iface::BsdName;
use mooring_model::ipv4::{PublicIpv4, SPECIAL_V4};
use mooring_model::keys::WgKey;
use mooring_model::ports::Port;
use mooring_model::secret::WgPrivateKey;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

use crate::literal::literal;
use crate::reach::NodeReach;
use crate::secret_text::Rendered;
use crate::singbox::{BindInterface, DirectType, Log, RejectAction, RouteAction, Tcp};
use crate::text_value::{TextValueError, display_serde};
use crate::vps::wg::MTU;

/// The `mooring-exit` config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExitDocument {
    pub(crate) log: Log,
    pub(crate) endpoints: Vec<WgEndpoint>,
    pub(crate) outbounds: [EgressOutbound; 1],
    pub(crate) route: ExitRoute,
}

literal!(
    /// The WireGuard endpoint type.
    WireGuardType = "wireguard"
);
literal!(
    /// The tag of the one outbound.
    EgressTag = "egress"
);
literal!(
    /// `udp_timeout` of the endpoint's gVisor UDP NAT (`option/wireguard.go:17`).
    UdpTimeout = "5m"
);

/// The bound on the endpoint's UDP NAT entries
/// (`transport/wireguard/device_stack.go:84-88`).
pub(crate) const UDP_NAT_MAX: u32 = 4096;

/// A node's endpoint tag: `wg-<node>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EndpointTag(pub(crate) NodeId);

const ENDPOINT_PREFIX: &str = "wg-";

impl fmt::Display for EndpointTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ENDPOINT_PREFIX}{}", self.0)
    }
}

impl FromStr for EndpointTag {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.strip_prefix(ENDPOINT_PREFIX)
            .and_then(|node| NodeId::parse(node).ok())
            .map(Self)
            .ok_or(TextValueError("wg-<node>"))
    }
}

display_serde!(EndpointTag);

/// The endpoint's peer: the node (`option/wireguard.go:25-33`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WgPeer {
    pub(crate) address: PublicIpv4,
    pub(crate) port: Port,
    pub(crate) public_key: WgKey,
    /// Only the VPS's tunnel address: an inner packet from any other
    /// source is dropped.
    pub(crate) allowed_ips: [Ipv4Net; 1],
    pub(crate) persistent_keepalive_interval: u16,
}

/// One node's userspace WireGuard endpoint (`option/wireguard.go:9-23`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WgEndpoint {
    #[serde(rename = "type")]
    pub(crate) kind: WireGuardType,
    pub(crate) tag: EndpointTag,
    pub(crate) system: bool,
    pub(crate) mtu: u16,
    pub(crate) address: [Ipv4Net; 1],
    pub(crate) private_key: Rendered<WgPrivateKey>,
    pub(crate) peers: [WgPeer; 1],
    pub(crate) udp_timeout: UdpTimeout,
    pub(crate) udp_nat_max: u32,
    /// The tunnel uplink.
    pub(crate) bind_interface: BindInterface,
}

/// The `direct` outbound every allowed flow leaves through, bound to the
/// egress interface (`option/direct.go:17-25`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressOutbound {
    #[serde(rename = "type")]
    pub(crate) kind: DirectType,
    pub(crate) tag: EgressTag,
    pub(crate) bind_interface: BindInterface,
}

/// `ip_version: 6` (`option/rule.go:142`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Ipv6;

const IPV6: u8 = 6;

impl Serialize for Ipv6 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(IPV6)
    }
}

impl<'de> Deserialize<'de> for Ipv6 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u8::deserialize(deserializer)? {
            IPV6 => Ok(Self),
            other => Err(de::Error::custom(format_args!(
                "ip_version {other} is not 6"
            ))),
        }
    }
}

/// A rule that routes to `egress` (`option/rule.go:140-161`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExitRouteRule {
    pub(crate) inbound: Vec<EndpointTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ip_cidr: Option<Vec<Ipv4Net>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<[Tcp; 1]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<Vec<Port>>,
    pub(crate) action: RouteAction,
    pub(crate) outbound: EgressTag,
}

/// A rule that rejects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExitRejectRule {
    pub(crate) inbound: Vec<EndpointTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ip_version: Option<Ipv6>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ip_cidr: Option<Vec<Ipv4Net>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<[Tcp; 1]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<Vec<Port>>,
    pub(crate) action: RejectAction,
}

/// One route rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum ExitRule {
    Route(ExitRouteRule),
    Reject(ExitRejectRule),
}

/// `route` (`option/route.go:5-24`). Interface auto-detection is off: every
/// socket is bound explicitly, and the default interface is the egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExitRoute {
    pub(crate) rules: Vec<ExitRule>,
    #[serde(rename = "final")]
    pub(crate) final_outbound: EgressTag,
    pub(crate) auto_detect_interface: bool,
    pub(crate) default_interface: BsdName,
}

/// One applied node's tunnel.
#[derive(Debug)]
pub(crate) struct TunnelInput<'a> {
    pub(crate) node: &'a NodeId,
    pub(crate) mac_address: Ipv4Net,
    pub(crate) private_key: &'a WgPrivateKey,
    pub(crate) vps4: PublicIpv4,
    pub(crate) port: Port,
    pub(crate) vps_public: WgKey,
    pub(crate) vps_address: Ipv4Net,
    pub(crate) keepalive: u16,
}

/// What the exit config is rendered from.
#[derive(Debug)]
pub(crate) struct ExitInput<'a> {
    pub(crate) tunnels: Vec<TunnelInput<'a>>,
    pub(crate) uplink: &'a BsdName,
    pub(crate) egress: &'a BsdName,
    pub(crate) reach: &'a NodeReach,
    pub(crate) deny_smtp25: bool,
    pub(crate) smtp: Port,
}

/// Builds the exit config.
pub(crate) fn config(input: &ExitInput<'_>) -> ExitDocument {
    let endpoints = input
        .tunnels
        .iter()
        .map(|tunnel| WgEndpoint {
            kind: WireGuardType::Value,
            tag: EndpointTag(tunnel.node.clone()),
            system: false,
            mtu: MTU,
            address: [tunnel.mac_address],
            private_key: Rendered::new(tunnel.private_key.clone()),
            peers: [WgPeer {
                address: tunnel.vps4,
                port: tunnel.port,
                public_key: tunnel.vps_public,
                allowed_ips: [tunnel.vps_address],
                persistent_keepalive_interval: tunnel.keepalive,
            }],
            udp_timeout: UdpTimeout::Value,
            udp_nat_max: UDP_NAT_MAX,
            bind_interface: BindInterface::new(input.uplink.clone()),
        })
        .collect();
    ExitDocument {
        log: Log::default(),
        endpoints,
        outbounds: [EgressOutbound {
            kind: DirectType::Value,
            tag: EgressTag::Value,
            bind_interface: BindInterface::new(input.egress.clone()),
        }],
        route: ExitRoute {
            rules: rules(input),
            final_outbound: EgressTag::Value,
            auto_detect_interface: false,
            default_interface: input.egress.clone(),
        },
    }
}

fn rules(input: &ExitInput<'_>) -> Vec<ExitRule> {
    let inbound: Vec<EndpointTag> = input
        .tunnels
        .iter()
        .map(|tunnel| EndpointTag(tunnel.node.clone()))
        .collect();
    let reject = || ExitRejectRule {
        inbound: inbound.clone(),
        ip_version: None,
        ip_cidr: None,
        network: None,
        port: None,
        action: RejectAction::Value,
    };
    let hosts = |addresses: &[Ipv4Addr]| {
        addresses
            .iter()
            .copied()
            .map(Ipv4Net::from)
            .collect::<Vec<_>>()
    };
    let mut rules = Vec::new();
    for (port, addresses) in &input.reach.reflectors {
        rules.push(ExitRule::Route(ExitRouteRule {
            inbound: inbound.clone(),
            ip_cidr: Some(hosts(addresses)),
            network: Some([Tcp::Value]),
            port: Some(vec![*port]),
            action: RouteAction::Value,
            outbound: EgressTag::Value,
        }));
    }
    rules.push(ExitRule::Reject(ExitRejectRule {
        ip_cidr: Some(hosts(&input.reach.addresses)),
        ..reject()
    }));
    rules.push(ExitRule::Reject(ExitRejectRule {
        ip_version: Some(Ipv6),
        ..reject()
    }));
    rules.push(ExitRule::Reject(ExitRejectRule {
        ip_cidr: Some(SPECIAL_V4.iter().map(|class| class.net()).collect()),
        ..reject()
    }));
    if input.deny_smtp25 {
        rules.push(ExitRule::Reject(ExitRejectRule {
            network: Some([Tcp::Value]),
            port: Some(vec![input.smtp]),
            ..reject()
        }));
    }
    rules.push(ExitRule::Route(ExitRouteRule {
        inbound,
        ip_cidr: None,
        network: None,
        port: None,
        action: RouteAction::Value,
        outbound: EgressTag::Value,
    }));
    rules
}
