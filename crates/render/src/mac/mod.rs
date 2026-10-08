// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac side: the `mooring-exit` and `mooring-probe` configs (design
//! §8.7, §8.8), rendered in memory and sent to the engines on stdin.
//!
//! Both cover the applied nodes only: a node gets its tunnel and probes
//! once a transaction has committed, and loses them when it starts
//! retiring.

pub(crate) mod exit;
pub(crate) mod prober;

use mooring_export::{OutboundTag, probe_outbounds};
use mooring_model::exit::ProbeProtocol;
use mooring_model::iface::ResolvedInterfaces;
use mooring_model::node::{Node, NodeAddress, NodeSite};
use mooring_model::ports::Port;
use mooring_model::secret::SecretSnapshot;
use mooring_model::{Deployment, NodeId, Sha256Digest};

use crate::encode;
use crate::error::RenderError;
use crate::reach::NodeReach;
use crate::rendered::RenderedFile;
use crate::system::SMTP_PORT;

/// The applied nodes in id order, with their sites.
fn applied(deployment: &Deployment) -> Result<Vec<(&Node, &NodeSite)>, RenderError> {
    let nodes: Vec<(&Node, &NodeSite)> = deployment
        .nodes()
        .values()
        .filter_map(|node| {
            node.lifecycle.applied()?;
            Some((node, node.lifecycle.site()?))
        })
        .collect();
    if nodes.is_empty() {
        Err(RenderError::NoAppliedNodes)
    } else {
        Ok(nodes)
    }
}

/// The rendered `mooring-exit` config. It holds the Mac's WireGuard
/// private keys, so it lives only in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitConfig {
    file: RenderedFile,
    nodes: Vec<NodeId>,
}

impl ExitConfig {
    /// The JSON config.
    #[must_use]
    pub const fn file(&self) -> &RenderedFile {
        &self.file
    }

    /// The config digest; the engine restarts only when it changes. Users
    /// never appear in this config, so adding one leaves it unchanged.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.file.digest()
    }

    /// The nodes with an endpoint, in id order.
    #[must_use]
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }
}

/// Renders the `mooring-exit` config: a WireGuard endpoint per applied node
/// bound to the uplink, and the bound egress behind the deny rules.
/// `interfaces` must have been resolved for the deployment's exit site
/// (`ExitSite::require_resolved`), so the tunnel never binds to an uplink
/// the site is not configured for.
pub fn exit(
    deployment: &Deployment,
    interfaces: &ResolvedInterfaces,
    secrets: &SecretSnapshot,
) -> Result<ExitConfig, RenderError> {
    deployment.exit().require_resolved(interfaces)?;
    let nodes = applied(deployment)?;
    let tunnels = nodes
        .iter()
        .map(|(node, site)| {
            let NodeAddress::Public(vps4) = site.address;
            Ok(exit::TunnelInput {
                node: &node.id,
                mac_address: node.wg_index.mac_host(),
                private_key: secrets.wg_mac_private(&node.id)?,
                vps4,
                port: node.ports.wg(),
                vps_public: node.wg.vps_pub,
                vps_address: node.wg_index.vps_host(),
                keepalive: node.wg.keepalive.seconds(),
            })
        })
        .collect::<Result<Vec<_>, RenderError>>()?;
    let reach = NodeReach::of(deployment)?;
    let document = exit::config(&exit::ExitInput {
        tunnels,
        uplink: &interfaces.uplink_interface().bsd_name,
        egress: &interfaces.egress().bsd_name,
        reach: &reach,
        deny_smtp25: deployment.policy().deny_smtp25,
        smtp: Port::new(SMTP_PORT)?,
    });
    Ok(ExitConfig {
        file: RenderedFile::new(encode::json(&document)?),
        nodes: nodes.iter().map(|(node, _)| node.id.clone()).collect(),
    })
}

/// Where the daemon connects for one in-chain probe.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeEndpoint {
    /// The node probed.
    pub node: NodeId,
    /// The protocol probed.
    pub protocol: ProbeProtocol,
    /// The loopback port of the probe inbound (`127.0.0.1:<port>`).
    pub port: Port,
}

/// The rendered `mooring-probe` config. It holds the probe credentials, so
/// it lives only in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProberConfig {
    file: RenderedFile,
    probes: Vec<ProbeEndpoint>,
}

impl ProberConfig {
    /// The JSON config.
    #[must_use]
    pub const fn file(&self) -> &RenderedFile {
        &self.file
    }

    /// The config digest; the engine restarts only when it changes.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.file.digest()
    }

    /// Every probe, nodes in id order, REALITY before Hysteria2.
    #[must_use]
    pub fn probes(&self) -> &[ProbeEndpoint] {
        &self.probes
    }
}

/// Renders the `mooring-probe` config: for each applied node, a REALITY and
/// a Hysteria2 probe through the probe identity's exported outbounds, bound
/// to the uplink. Probe ports follow the exit site's probe policy, by the
/// node's position among the applied nodes.
pub fn prober(
    deployment: &Deployment,
    interfaces: &ResolvedInterfaces,
    secrets: &SecretSnapshot,
) -> Result<ProberConfig, RenderError> {
    deployment.exit().require_resolved(interfaces)?;
    let policy = deployment.exit().probe;
    let mut inputs = Vec::new();
    let mut probes = Vec::new();
    for (slot, (node, site)) in applied(deployment)?.into_iter().enumerate() {
        let NodeAddress::Public(node_address) = site.address;
        let outbounds = probe_outbounds(deployment, secrets, &node.id)?;
        for (protocol, outbound) in [
            (ProbeProtocol::Reality, outbounds.reality),
            (ProbeProtocol::Hy2, outbounds.hysteria2),
        ] {
            let probe = prober::Probe {
                node: node.id.clone(),
                protocol,
            };
            let tag = OutboundTag::parse(&prober::ProbeOutboundTag(probe.clone()).to_string())?;
            let listen_port = policy.port_for(slot, protocol)?;
            probes.push(ProbeEndpoint {
                node: node.id.clone(),
                protocol,
                port: listen_port,
            });
            inputs.push(prober::ProbeInput {
                probe,
                listen_port,
                node_address,
                reflector: node.ports.reflector(),
                outbound: outbound.with_tag(tag),
            });
        }
    }
    let document = prober::config(inputs, &interfaces.uplink_interface().bsd_name);
    Ok(ProberConfig {
        file: RenderedFile::new(encode::json(&document)?),
        probes,
    })
}
