// SPDX-License-Identifier: GPL-3.0-or-later

//! VPS nodes (design §7 `Node`).
//!
//! A node's address and host facts are only known from adoption on, so they
//! live in the lifecycle variants that have them rather than in fields that
//! a planned node could not fill.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::cert::CertificatePem;
use crate::counters::ConfigGeneration;
use crate::digest::Sha256Digest;
use crate::error::ModelError;
use crate::ids::{NodeId, ShortId};
use crate::iface::LinuxIfName;
use crate::ipv4::PublicIpv4;
use crate::keys::{Ed25519Pub, X25519Pub};
use crate::kinds;
use crate::ports::{PortPlan, PortRange};
use crate::target::TargetSpec;
use crate::wg::{WgIndex, WgLink};

/// A node's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// The main node users are told to prefer.
    Primary,
    /// The standby on a different ASN.
    Standby,
}

/// A node's public address. Release builds only have `Public`; a lab
/// variant would exist only behind `cfg(feature = "lab")` (design §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeAddress {
    /// A dedicated public IPv4 on the VPS's uplink interface.
    Public(PublicIpv4),
}

impl NodeAddress {
    /// The IPv4 address.
    #[must_use]
    pub const fn ipv4(self) -> Ipv4Addr {
        match self {
            Self::Public(addr) => addr.get(),
        }
    }
}

/// The CPU architecture of a VPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    /// x86-64.
    Amd64,
    /// AArch64.
    Arm64,
}

/// Facts about a VPS recorded from `Hello` at adoption; `Apply` refuses a
/// host whose live facts differ (`HostFactsChanged`).
///
/// Adoption also asserts that the node address is configured on
/// `uplink_interface`; a host where it is not is never adopted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFacts {
    /// The interface holding the node's public address.
    pub uplink_interface: LinuxIfName,
    /// The CPU architecture, which selects the engine binaries.
    pub arch: Arch,
    /// The live `net.ipv4.ip_local_port_range`.
    pub ephemeral_ports: PortRange,
}

/// Where an adopted node lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSite {
    /// The node's public address.
    pub address: NodeAddress,
    /// The host facts recorded at adoption.
    pub host_facts: HostFacts,
}

/// The configuration generation a node last committed and confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedConfig {
    /// The deployment generation that was applied.
    pub config_generation: ConfigGeneration,
    /// The digest of the applied VPS bundle.
    pub digest: Sha256Digest,
}

/// A node's lifecycle (design §7, §13).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeLifecycle {
    /// Secrets generated and user-data written; the VPS is not adopted yet.
    Planned,
    /// Adopted: the agent is installed and the host facts are recorded.
    Adopted {
        /// Where the node lives.
        site: NodeSite,
    },
    /// A generation was committed and confirmed.
    Applied {
        /// Where the node lives.
        site: NodeSite,
        /// The confirmed generation.
        applied: AppliedConfig,
    },
    /// Being shut down; its secrets still exist.
    Retiring {
        /// Where the node lives.
        site: NodeSite,
    },
    /// Shut down and its secrets deleted; the operator must delete the VM.
    RetiredPendingProviderDeletion {
        /// The address the VM still holds.
        address: NodeAddress,
    },
    /// The operator confirmed the VM is deleted.
    Retired,
}

kinds! {
    /// The stage of a [`NodeLifecycle`], without its data.
    pub enum LifecycleStage {
        /// See [`NodeLifecycle::Planned`].
        Planned,
        /// See [`NodeLifecycle::Adopted`].
        Adopted,
        /// See [`NodeLifecycle::Applied`].
        Applied,
        /// See [`NodeLifecycle::Retiring`].
        Retiring,
        /// See [`NodeLifecycle::RetiredPendingProviderDeletion`].
        RetiredPendingProviderDeletion,
        /// See [`NodeLifecycle::Retired`].
        Retired,
    }
}

impl NodeLifecycle {
    /// The stage, without data.
    #[must_use]
    pub const fn stage(&self) -> LifecycleStage {
        match self {
            Self::Planned => LifecycleStage::Planned,
            Self::Adopted { .. } => LifecycleStage::Adopted,
            Self::Applied { .. } => LifecycleStage::Applied,
            Self::Retiring { .. } => LifecycleStage::Retiring,
            Self::RetiredPendingProviderDeletion { .. } => {
                LifecycleStage::RetiredPendingProviderDeletion
            }
            Self::Retired => LifecycleStage::Retired,
        }
    }

    /// Whether the node still holds secrets and counts towards the node limit.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Adopted { .. } | Self::Applied { .. } | Self::Retiring { .. }
        )
    }

    /// The site, for adopted, applied and retiring nodes.
    #[must_use]
    pub const fn site(&self) -> Option<&NodeSite> {
        match self {
            Self::Adopted { site } | Self::Applied { site, .. } | Self::Retiring { site } => {
                Some(site)
            }
            Self::Planned | Self::RetiredPendingProviderDeletion { .. } | Self::Retired => None,
        }
    }

    /// The address a VM still holds: every stage from adoption until the
    /// operator confirms the VM is deleted.
    #[must_use]
    pub const fn address(&self) -> Option<NodeAddress> {
        match self {
            Self::Adopted { site } | Self::Applied { site, .. } | Self::Retiring { site } => {
                Some(site.address)
            }
            Self::RetiredPendingProviderDeletion { address } => Some(*address),
            Self::Planned | Self::Retired => None,
        }
    }

    /// The confirmed generation, for applied nodes.
    #[must_use]
    pub const fn applied(&self) -> Option<&AppliedConfig> {
        match self {
            Self::Applied { applied, .. } => Some(applied),
            Self::Planned
            | Self::Adopted { .. }
            | Self::Retiring { .. }
            | Self::RetiredPendingProviderDeletion { .. }
            | Self::Retired => None,
        }
    }
}

/// The pinned SSH host key of a node: first the one-time key injected via
/// user-data, then the key the VPS generates at Bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshPin {
    /// The Ed25519 host public key.
    pub host_ed25519: Ed25519Pub,
}

/// The public half of a node's REALITY server.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityServer {
    /// The REALITY public key users' clients pin.
    pub public_key: X25519Pub,
    /// The probe identity's short id on this node.
    pub probe_short_id: ShortId,
    /// The qualified target, once `node target set` has run. The key is
    /// required even when the value is `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub target: Option<TargetSpec>,
}

/// The public half of a node's Hysteria2 server; listener ports live in the
/// node's [`PortPlan`].
///
/// Only the certificate is stored: its SNI and pins are derived from it
/// (`mooring-export`'s `certificate_pins`), so they cannot disagree with it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hy2Server {
    /// The self-signed certificate, rendered inline into `hy2.json`.
    pub certificate: CertificatePem,
}

/// One VPS node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// The node id, such as `lon1`.
    pub id: NodeId,
    /// Primary or standby.
    pub role: NodeRole,
    /// Every port the node uses, including the Hysteria2 listeners.
    pub ports: PortPlan,
    /// The tunnel index `k` of `10.77.<k>.0/30`.
    pub wg_index: WgIndex,
    /// The pinned SSH host key.
    pub ssh: SshPin,
    /// The REALITY server.
    pub reality: RealityServer,
    /// The Hysteria2 server.
    pub hy2: Hy2Server,
    /// The tunnel's public keys and keepalive.
    pub wg: WgLink,
    /// Where the node is in its lifecycle.
    pub lifecycle: NodeLifecycle,
}

/// What rendering an Apply for a node needs beyond the node itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyInputs<'a> {
    /// Where the node lives.
    pub site: &'a NodeSite,
    /// The REALITY target.
    pub target: &'a TargetSpec,
}

impl Node {
    /// The site and target an Apply needs; only adopted and applied nodes
    /// with a target qualify.
    pub fn apply_inputs(&self) -> Result<ApplyInputs<'_>, ModelError> {
        let site = match &self.lifecycle {
            NodeLifecycle::Adopted { site } | NodeLifecycle::Applied { site, .. } => site,
            other => {
                return Err(ModelError::NodeNotDeployable {
                    node: self.id.clone(),
                    stage: other.stage(),
                });
            }
        };
        let target = self
            .reality
            .target
            .as_ref()
            .ok_or_else(|| ModelError::TargetNotSet {
                node: self.id.clone(),
            })?;
        Ok(ApplyInputs { site, target })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_queries() {
        let site = NodeSite {
            address: NodeAddress::Public("45.67.89.10".parse().unwrap()),
            host_facts: HostFacts {
                uplink_interface: LinuxIfName::parse("eth0").unwrap(),
                arch: Arch::Amd64,
                ephemeral_ports: crate::ports::DEBIAN_EPHEMERAL_PORTS,
            },
        };
        let applied = AppliedConfig {
            config_generation: ConfigGeneration::INITIAL,
            digest: Sha256Digest::from_bytes([1; 32]),
        };
        let cases = [
            (
                NodeLifecycle::Planned,
                LifecycleStage::Planned,
                true,
                false,
                false,
            ),
            (
                NodeLifecycle::Adopted { site: site.clone() },
                LifecycleStage::Adopted,
                true,
                true,
                true,
            ),
            (
                NodeLifecycle::Applied {
                    site: site.clone(),
                    applied,
                },
                LifecycleStage::Applied,
                true,
                true,
                true,
            ),
            (
                NodeLifecycle::Retiring { site: site.clone() },
                LifecycleStage::Retiring,
                true,
                true,
                true,
            ),
            (
                NodeLifecycle::RetiredPendingProviderDeletion {
                    address: site.address,
                },
                LifecycleStage::RetiredPendingProviderDeletion,
                false,
                false,
                true,
            ),
            (
                NodeLifecycle::Retired,
                LifecycleStage::Retired,
                false,
                false,
                false,
            ),
        ];
        for (lifecycle, stage, active, has_site, has_address) in cases {
            assert_eq!(lifecycle.stage(), stage);
            assert_eq!(lifecycle.is_active(), active, "{stage}");
            assert_eq!(lifecycle.site().is_some(), has_site, "{stage}");
            assert_eq!(lifecycle.address().is_some(), has_address, "{stage}");
            assert_eq!(
                lifecycle.applied().is_some(),
                stage == LifecycleStage::Applied
            );
        }
        assert_eq!(LifecycleStage::ALL.len(), 6);
    }

    #[test]
    fn lifecycle_serde_is_closed() {
        assert_eq!(
            serde_json::to_string(&NodeLifecycle::Planned).unwrap(),
            "\"planned\""
        );
        assert!(serde_json::from_str::<NodeLifecycle>("\"rebooting\"").is_err());
        assert!(serde_json::from_str::<NodeLifecycle>(
            r#"{"retired_pending_provider_deletion":{"address":{"public":"45.67.89.10"},"extra":1}}"#
        )
        .is_err());
        let pending: NodeLifecycle = serde_json::from_str(
            r#"{"retired_pending_provider_deletion":{"address":{"public":"45.67.89.10"}}}"#,
        )
        .unwrap();
        assert_eq!(
            pending.stage(),
            LifecycleStage::RetiredPendingProviderDeletion
        );
        assert!(serde_json::from_str::<NodeAddress>(r#"{"public":"10.0.0.1"}"#).is_err());
        assert!(serde_json::from_str::<NodeAddress>(r#"{"lab":"10.0.0.1"}"#).is_err());
    }

    #[test]
    fn only_adopted_and_applied_nodes_with_a_target_render_an_apply() {
        let site = crate::testing::site([45, 67, 89, 10]);
        let cases = [
            (NodeLifecycle::Planned, LifecycleStage::Planned),
            (
                NodeLifecycle::Adopted { site: site.clone() },
                LifecycleStage::Adopted,
            ),
            (
                crate::testing::applied([45, 67, 89, 10], 1),
                LifecycleStage::Applied,
            ),
            (
                NodeLifecycle::Retiring { site: site.clone() },
                LifecycleStage::Retiring,
            ),
            (
                NodeLifecycle::RetiredPendingProviderDeletion {
                    address: site.address,
                },
                LifecycleStage::RetiredPendingProviderDeletion,
            ),
            (NodeLifecycle::Retired, LifecycleStage::Retired),
        ];
        assert_eq!(cases.len(), LifecycleStage::ALL.len(), "every stage");
        for (lifecycle, stage) in cases {
            let mut node = crate::testing::node("lon1", 1, 10, lifecycle);
            let deployable = matches!(stage, LifecycleStage::Adopted | LifecycleStage::Applied);
            match node.apply_inputs() {
                Ok(inputs) => {
                    assert!(deployable, "{stage} must be refused");
                    assert_eq!(inputs.site, &site);
                    assert_eq!(Some(inputs.target), node.reality.target.as_ref());
                }
                Err(error) => {
                    assert!(!deployable, "{stage} must be accepted: {error}");
                    assert_eq!(
                        error,
                        ModelError::NodeNotDeployable {
                            node: node.id.clone(),
                            stage
                        }
                    );
                }
            }
            node.reality.target = None;
            if deployable {
                assert_eq!(
                    node.apply_inputs(),
                    Err(ModelError::TargetNotSet {
                        node: node.id.clone()
                    })
                );
            }
        }
    }

    #[test]
    fn a_missing_target_key_is_a_decode_error_not_no_target() {
        let with_null = r#"{"public_key":"CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws","probe_short_id":"a00000000000000a","target":null}"#;
        let server: RealityServer = serde_json::from_str(with_null).unwrap();
        assert_eq!(server.target, None);
        let without = with_null.replace(r#","target":null"#, "");
        let error = serde_json::from_str::<RealityServer>(&without).unwrap_err();
        assert!(
            error.to_string().contains("missing field `target`"),
            "{error}"
        );
    }
}
