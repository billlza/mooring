// SPDX-License-Identifier: GPL-3.0-or-later

//! The `mooring-probe` config for sing-box 1.14.2 (design §8.8): for each
//! applied node and protocol, a loopback `direct` inbound whose
//! destination is overridden to the node's reflector, routed to the probe
//! identity's exported outbound bound to the uplink.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use mooring_export::SingBoxOutbound;
use mooring_model::exit::ProbeProtocol;
use mooring_model::ids::NodeId;
use mooring_model::iface::BsdName;
use mooring_model::ipv4::PublicIpv4;
use mooring_model::ports::Port;
use serde::{Deserialize, Serialize};

use crate::singbox::{BindInterface, DirectType, Log, RouteAction, Tcp};
use crate::text_value::{TextValueError, display_serde};

/// The `mooring-probe` config, generic over its outbounds: rendering uses
/// [`MacProbeOutbound`], which serialises only (credentials are never read
/// back from text into export types).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProberDocument<O> {
    pub(crate) log: Log,
    pub(crate) inbounds: Vec<ProbeInbound>,
    pub(crate) outbounds: Vec<O>,
    pub(crate) route: ProberRoute,
}

const fn protocol_name(protocol: ProbeProtocol) -> &'static str {
    match protocol {
        ProbeProtocol::Reality => "reality",
        ProbeProtocol::Hy2 => "hy2",
    }
}

/// One probe: a node and a protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Probe {
    pub(crate) node: NodeId,
    pub(crate) protocol: ProbeProtocol,
}

const PROBE_PREFIX: &str = "probe-";
const OUT_SUFFIX: &str = "-out";

impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{PROBE_PREFIX}{}-{}",
            self.node,
            protocol_name(self.protocol)
        )
    }
}

impl FromStr for Probe {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        const WHAT: TextValueError = TextValueError("probe-<node>-<reality|hy2>");
        let rest = text.strip_prefix(PROBE_PREFIX).ok_or(WHAT)?;
        let (node, protocol) = rest.rsplit_once('-').ok_or(WHAT)?;
        let protocol = ProbeProtocol::ALL
            .into_iter()
            .find(|candidate| protocol_name(*candidate) == protocol)
            .ok_or(WHAT)?;
        let node = NodeId::parse(node).map_err(|_| WHAT)?;
        Ok(Self { node, protocol })
    }
}

/// A probe inbound's tag: `probe-<node>-<protocol>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProbeInboundTag(pub(crate) Probe);

impl fmt::Display for ProbeInboundTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ProbeInboundTag {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse().map(Self)
    }
}

display_serde!(ProbeInboundTag);

/// A probe outbound's tag: `probe-<node>-<protocol>-out`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ProbeOutboundTag(pub(crate) Probe);

impl fmt::Display for ProbeOutboundTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{OUT_SUFFIX}", self.0)
    }
}

impl FromStr for ProbeOutboundTag {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.strip_suffix(OUT_SUFFIX)
            .ok_or(TextValueError("probe-<node>-<reality|hy2>-out"))?
            .parse()
            .map(Self)
    }
}

display_serde!(ProbeOutboundTag);

/// A loopback `direct` inbound (`option/direct.go:10-15`,
/// `option/inbound.go:79-81`) that sends every connection to the node's
/// reflector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeInbound {
    #[serde(rename = "type")]
    pub(crate) kind: DirectType,
    pub(crate) tag: ProbeInboundTag,
    pub(crate) listen: Ipv4Addr,
    pub(crate) listen_port: Port,
    pub(crate) network: Tcp,
    pub(crate) override_address: PublicIpv4,
    pub(crate) override_port: Port,
}

/// Routes one probe inbound to its outbound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeRule {
    pub(crate) inbound: [ProbeInboundTag; 1],
    pub(crate) action: RouteAction,
    pub(crate) outbound: ProbeOutboundTag,
}

/// `route`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProberRoute {
    pub(crate) rules: Vec<ProbeRule>,
    pub(crate) auto_detect_interface: bool,
    pub(crate) default_interface: BsdName,
}

/// The single wrapper of a probe outbound (design §8.8): the outbound
/// exactly as the CFM export emitter writes it, plus the Mac-only dial
/// field CFM itself rejects. It flattens to one JSON object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct MacProbeOutbound {
    #[serde(flatten)]
    pub(crate) cfm: SingBoxOutbound,
    pub(crate) bind_interface: BindInterface,
}

/// One probe and the node it reaches.
#[derive(Debug)]
pub(crate) struct ProbeInput {
    pub(crate) probe: Probe,
    pub(crate) listen_port: Port,
    pub(crate) node_address: PublicIpv4,
    pub(crate) reflector: Port,
    pub(crate) outbound: SingBoxOutbound,
}

/// Builds the prober config.
pub(crate) fn config(
    probes: Vec<ProbeInput>,
    uplink: &BsdName,
) -> ProberDocument<MacProbeOutbound> {
    let mut inbounds = Vec::with_capacity(probes.len());
    let mut outbounds = Vec::with_capacity(probes.len());
    let mut rules = Vec::with_capacity(probes.len());
    for probe in probes {
        inbounds.push(ProbeInbound {
            kind: DirectType::Value,
            tag: ProbeInboundTag(probe.probe.clone()),
            listen: Ipv4Addr::LOCALHOST,
            listen_port: probe.listen_port,
            network: Tcp::Value,
            override_address: probe.node_address,
            override_port: probe.reflector,
        });
        rules.push(ProbeRule {
            inbound: [ProbeInboundTag(probe.probe.clone())],
            action: RouteAction::Value,
            outbound: ProbeOutboundTag(probe.probe),
        });
        outbounds.push(MacProbeOutbound {
            cfm: probe.outbound,
            bind_interface: BindInterface::new(uplink.clone()),
        });
    }
    ProberDocument {
        log: Log::default(),
        inbounds,
        outbounds,
        route: ProberRoute {
            rules,
            auto_detect_interface: false,
            default_interface: uplink.clone(),
        },
    }
}
