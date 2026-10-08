// SPDX-License-Identifier: GPL-3.0-or-later

//! The deployment: every node and user, validated as a whole (design §7).

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::counters::ConfigGeneration;
use crate::error::{EntityId, ModelError};
use crate::exit::{ExitSite, TrafficPolicy};
use crate::ids::{NodeId, ShortId, UserId};
use crate::node::{AppliedConfig, Node, NodeAddress, NodeLifecycle};
use crate::ports::PortConflict;
use crate::secret::SecretRef;
use crate::user::{User, UserNodePublic, UserStatus};
use crate::wg::WgIndex;

/// The most nodes that may be active at once in v1: one WireGuard endpoint
/// per node on the Mac, at most two.
pub const MAX_ACTIVE_NODES: usize = 2;

/// A deployment's fields without its invariants: the shape to build or edit
/// a deployment from, and its serialised form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentParts {
    /// Bumped only by changes that alter a rendered VPS or Mac config.
    pub config_generation: ConfigGeneration,
    /// The Mac exit site.
    pub exit: ExitSite,
    /// Destination policy.
    pub policy: TrafficPolicy,
    /// Every node, including retired ones.
    pub nodes: Vec<Node>,
    /// Every user, including revoked ones.
    pub users: Vec<User>,
    /// The next WireGuard index to allocate; indices are never reused.
    pub next_wg_index: WgIndex,
}

/// Every node and user of the one exit, with all cross-entity invariants
/// checked. Built only from [`DeploymentParts`] (also when deserialised):
///
/// - node and user ids are unique;
/// - at most [`MAX_ACTIVE_NODES`] nodes are active;
/// - WireGuard indices are unique and below `next_wg_index`;
/// - live node addresses are unique;
/// - an adopted node's port plan was checked against its host's live range;
/// - an applied node has a target and a generation no newer than the deployment's;
/// - users hold credentials only on active nodes, revoked users on none, and
///   a user pending revocation on at least one (the nodes still to commit);
/// - REALITY short ids are unique per node, probe included.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "DeploymentParts")]
pub struct Deployment {
    config_generation: ConfigGeneration,
    exit: ExitSite,
    policy: TrafficPolicy,
    nodes: BTreeMap<NodeId, Node>,
    users: BTreeMap<UserId, User>,
    next_wg_index: WgIndex,
}

impl Deployment {
    /// A fresh deployment with no nodes or users.
    #[must_use]
    pub fn new(exit: ExitSite, policy: TrafficPolicy) -> Self {
        Self {
            config_generation: ConfigGeneration::INITIAL,
            exit,
            policy,
            nodes: BTreeMap::new(),
            users: BTreeMap::new(),
            next_wg_index: WgIndex::FIRST,
        }
    }

    /// The configuration generation.
    #[must_use]
    pub const fn config_generation(&self) -> ConfigGeneration {
        self.config_generation
    }

    /// The Mac exit site.
    #[must_use]
    pub const fn exit(&self) -> &ExitSite {
        &self.exit
    }

    /// The destination policy.
    #[must_use]
    pub const fn policy(&self) -> &TrafficPolicy {
        &self.policy
    }

    /// Every node by id, including retired ones.
    #[must_use]
    pub const fn nodes(&self) -> &BTreeMap<NodeId, Node> {
        &self.nodes
    }

    /// Every user by id, including revoked ones.
    #[must_use]
    pub const fn users(&self) -> &BTreeMap<UserId, User> {
        &self.users
    }

    /// The next WireGuard index to allocate.
    #[must_use]
    pub const fn next_wg_index(&self) -> WgIndex {
        self.next_wg_index
    }

    /// The node with id `id`.
    pub fn node(&self, id: &NodeId) -> Result<&Node, ModelError> {
        self.nodes
            .get(id)
            .ok_or_else(|| ModelError::UnknownNode { id: id.clone() })
    }

    /// The user with id `id`.
    pub fn user(&self, id: &UserId) -> Result<&User, ModelError> {
        self.users
            .get(id)
            .ok_or_else(|| ModelError::UnknownUser { id: id.clone() })
    }

    /// The nodes that are active (planned to retiring), in id order.
    pub fn active_nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes
            .values()
            .filter(|node| node.lifecycle.is_active())
    }

    /// The address of every node whose VM still exists; the renderers deny
    /// these to every identity except the probe.
    #[must_use]
    pub fn node_addresses(&self) -> BTreeMap<NodeId, NodeAddress> {
        self.nodes
            .values()
            .filter_map(|node| Some((node.id.clone(), node.lifecycle.address()?)))
            .collect()
    }

    /// The users served on `node` with their public per-node data, in id order.
    pub fn served_users<'a>(
        &'a self,
        node: &'a NodeId,
    ) -> impl Iterator<Item = (&'a User, &'a UserNodePublic)> {
        self.users.values().filter_map(move |user| {
            let public = user.per_node.get(node)?;
            user.is_served_on(node).then_some((user, public))
        })
    }

    /// Every secret the deployment references; anything else in the
    /// keychain is orphaned.
    #[must_use]
    pub fn required_secrets(&self) -> BTreeSet<SecretRef> {
        let mut refs = BTreeSet::new();
        for node in self.active_nodes() {
            let id = &node.id;
            refs.insert(SecretRef::NodeRealityPrivate(id.clone()));
            refs.insert(SecretRef::NodeWgVpsPrivate(id.clone()));
            refs.insert(SecretRef::NodeWgMacPrivate(id.clone()));
            refs.insert(SecretRef::NodeHy2Key(id.clone()));
            for (listener, _) in node.ports.hy2_listeners() {
                refs.insert(SecretRef::NodeHy2Obfs(id.clone(), listener));
            }
            refs.insert(SecretRef::ProbeVlessUuid(id.clone()));
            refs.insert(SecretRef::ProbeHy2Password(id.clone()));
            refs.insert(SecretRef::ProbeLoopUuid(id.clone()));
            if node.lifecycle == NodeLifecycle::Planned {
                refs.insert(SecretRef::NodeSshBootstrapPrivate(id.clone()));
            }
        }
        for user in self.users.values() {
            for node in user.per_node.keys() {
                refs.insert(SecretRef::UserVlessUuid(user.id.clone(), node.clone()));
                refs.insert(SecretRef::UserHy2Password(user.id.clone(), node.clone()));
                refs.insert(SecretRef::UserLoopUuid(user.id.clone(), node.clone()));
            }
        }
        refs
    }

    /// The deployment's fields, for editing; rebuild with `Deployment::try_from`.
    #[must_use]
    pub fn into_parts(self) -> DeploymentParts {
        DeploymentParts {
            config_generation: self.config_generation,
            exit: self.exit,
            policy: self.policy,
            nodes: self.nodes.into_values().collect(),
            users: self.users.into_values().collect(),
            next_wg_index: self.next_wg_index,
        }
    }

    fn check_nodes(&self) -> Result<(), ModelError> {
        let active = self.active_nodes().count();
        if active > MAX_ACTIVE_NODES {
            return Err(ModelError::TooManyNodes {
                max: MAX_ACTIVE_NODES,
            });
        }
        let mut indices = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for node in self.nodes.values() {
            if node.wg_index >= self.next_wg_index {
                return Err(ModelError::WgIndexNotAllocated {
                    index: node.wg_index,
                    next: self.next_wg_index,
                });
            }
            if !indices.insert(node.wg_index) {
                return Err(ModelError::DuplicateWgIndex {
                    index: node.wg_index,
                });
            }
            if let Some(address) = node.lifecycle.address()
                && !addresses.insert(address.ipv4())
            {
                return Err(ModelError::DuplicateNodeAddress {
                    addr: address.ipv4(),
                });
            }
            self.check_node(node)?;
        }
        Ok(())
    }

    fn check_node(&self, node: &Node) -> Result<(), ModelError> {
        if let Some(site) = node.lifecycle.site()
            && site.host_facts.ephemeral_ports != node.ports.ephemeral()
        {
            return Err(ModelError::PortPlanConflict {
                conflict: PortConflict::EphemeralRangeChanged {
                    planned: node.ports.ephemeral(),
                    live: site.host_facts.ephemeral_ports,
                },
            });
        }
        if let Some(applied) = node.lifecycle.applied() {
            if node.reality.target.is_none() {
                return Err(ModelError::TargetNotSet {
                    node: node.id.clone(),
                });
            }
            if applied.config_generation > self.config_generation {
                return Err(ModelError::GenerationAhead {
                    node: node.id.clone(),
                    applied: applied.config_generation,
                    current: self.config_generation,
                });
            }
        }
        Ok(())
    }

    fn check_users(&self) -> Result<(), ModelError> {
        let mut short_ids: BTreeMap<&NodeId, BTreeSet<ShortId>> = self
            .nodes
            .values()
            .map(|node| (&node.id, BTreeSet::from([node.reality.probe_short_id])))
            .collect();
        for user in self.users.values() {
            for (node_id, public) in &user.per_node {
                let node = self.node(node_id)?;
                if !node.lifecycle.is_active() {
                    return Err(ModelError::CredentialsOnInactiveNode {
                        user: user.id.clone(),
                        node: node_id.clone(),
                    });
                }
                let taken = short_ids.entry(&node.id).or_default();
                if !taken.insert(public.short_id) {
                    return Err(ModelError::DuplicateShortId {
                        node: node_id.clone(),
                    });
                }
            }
            match &user.status {
                UserStatus::Active => {}
                UserStatus::RevokePending => {
                    if user.per_node.is_empty() {
                        return Err(ModelError::RevokePendingWithoutCredentials {
                            user: user.id.clone(),
                        });
                    }
                }
                UserStatus::Revoked => {
                    if !user.per_node.is_empty() {
                        return Err(ModelError::RevokedUserHoldsCredentials {
                            user: user.id.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

/// A record of progress that changes no rendered VPS bundle and no export
/// (design §7): the store commits these, and only these, without bumping
/// `config_generation`. Every other change bumps it, so a node's confirmed
/// generation always tells whether it serves the current configuration.
///
/// Why each keeps every bundle and export unchanged:
///
/// - `Applied` turns an adopted or applied node's lifecycle into `Applied`
///   with the same site; bundles depend on the site, the target and the
///   served users, none of which change. An applied node's confirmed
///   generation never goes back: an older one is refused. The same one is
///   recorded again with the digest the node confirmed: an unchanged
///   re-apply repeats it, and a re-apply after an app upgrade with new
///   engines (design §13.3) replaces it. A record is the only way to set a
///   confirmed generation; the store refuses a configuration change that
///   edits one (`AppliedEdited`). (The Mac configs follow which nodes are
///   applied by design; the daemon restarts an engine only when that
///   engine's rendered digest changes.)
/// - `RevocationCommitted` drops a pending user's credentials on one node;
///   a user pending revocation is served nowhere and exported nowhere.
/// - `RetirementShutDown` moves a retiring node, which no bundle, Mac config
///   or export includes, to `RetiredPendingProviderDeletion` (its address
///   is still denied everywhere) and drops every user's credentials on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bookkeeping {
    /// `node` committed and confirmed `applied` (design §11.2).
    Applied {
        /// The node.
        node: NodeId,
        /// The generation and bundle digest it confirmed.
        applied: AppliedConfig,
    },
    /// `node` committed the generation that stopped serving `user`, who is
    /// pending revocation (design §13.5 step 3); with no node left the user
    /// becomes `Revoked`.
    RevocationCommitted {
        /// The user being revoked.
        user: UserId,
        /// The node that committed.
        node: NodeId,
    },
    /// The retiring `node` was shut down and its Mac endpoint removed
    /// (design §13.4 step 3); a user pending revocation that held
    /// credentials only there becomes `Revoked`.
    RetirementShutDown {
        /// The node.
        node: NodeId,
    },
}

impl Deployment {
    /// Applies a bookkeeping record, keeping `config_generation`; the
    /// result is validated like any deployment.
    pub fn record(self, entry: Bookkeeping) -> Result<Self, ModelError> {
        let mut parts = self.into_parts();
        match entry {
            Bookkeeping::Applied { node, applied } => {
                let node = node_mut(&mut parts, &node)?;
                let site = match &node.lifecycle {
                    NodeLifecycle::Adopted { site } => site.clone(),
                    NodeLifecycle::Applied {
                        site,
                        applied: recorded,
                    } => {
                        if applied.config_generation < recorded.config_generation {
                            return Err(ModelError::GenerationRegressed {
                                node: node.id.clone(),
                                recorded: recorded.config_generation,
                                applied: applied.config_generation,
                            });
                        }
                        site.clone()
                    }
                    other => {
                        return Err(ModelError::NodeNotDeployable {
                            node: node.id.clone(),
                            stage: other.stage(),
                        });
                    }
                };
                node.lifecycle = NodeLifecycle::Applied { site, applied };
            }
            Bookkeeping::RevocationCommitted { user, node } => {
                let user = parts
                    .users
                    .iter_mut()
                    .find(|candidate| candidate.id == user)
                    .ok_or(ModelError::UnknownUser { id: user })?;
                if user.status != UserStatus::RevokePending {
                    return Err(ModelError::NotRevoking {
                        user: user.id.clone(),
                    });
                }
                if user.per_node.remove(&node).is_none() {
                    return Err(ModelError::NoCredentialsOnNode {
                        user: user.id.clone(),
                        node,
                    });
                }
                settle_revocation(user);
            }
            Bookkeeping::RetirementShutDown { node } => {
                let retiring = node_mut(&mut parts, &node)?;
                let NodeLifecycle::Retiring { site } = &retiring.lifecycle else {
                    return Err(ModelError::NodeNotRetiring {
                        node,
                        stage: retiring.lifecycle.stage(),
                    });
                };
                retiring.lifecycle = NodeLifecycle::RetiredPendingProviderDeletion {
                    address: site.address,
                };
                for user in &mut parts.users {
                    user.per_node.remove(&node);
                    settle_revocation(user);
                }
            }
        }
        Self::try_from(parts)
    }
}

fn node_mut<'a>(parts: &'a mut DeploymentParts, id: &NodeId) -> Result<&'a mut Node, ModelError> {
    parts
        .nodes
        .iter_mut()
        .find(|node| node.id == *id)
        .ok_or_else(|| ModelError::UnknownNode { id: id.clone() })
}

/// A user pending revocation with no node left to commit it is revoked.
fn settle_revocation(user: &mut User) {
    if user.status == UserStatus::RevokePending && user.per_node.is_empty() {
        user.status = UserStatus::Revoked;
    }
}

fn index_by_id<K: Ord + Clone, V>(
    items: Vec<V>,
    id: impl Fn(&V) -> &K,
    duplicate: impl Fn(K) -> EntityId,
) -> Result<BTreeMap<K, V>, ModelError> {
    let mut map = BTreeMap::new();
    for item in items {
        match map.entry(id(&item).clone()) {
            Entry::Occupied(slot) => {
                return Err(ModelError::DuplicateId {
                    id: duplicate(slot.key().clone()),
                });
            }
            Entry::Vacant(slot) => {
                slot.insert(item);
            }
        }
    }
    Ok(map)
}

impl TryFrom<DeploymentParts> for Deployment {
    type Error = ModelError;

    fn try_from(parts: DeploymentParts) -> Result<Self, Self::Error> {
        let deployment = Self {
            config_generation: parts.config_generation,
            exit: parts.exit,
            policy: parts.policy,
            nodes: index_by_id(parts.nodes, |node: &Node| &node.id, EntityId::Node)?,
            users: index_by_id(parts.users, |user: &User| &user.id, EntityId::User)?,
            next_wg_index: parts.next_wg_index,
        };
        deployment.check_nodes()?;
        deployment.check_users()?;
        Ok(deployment)
    }
}

impl From<Deployment> for DeploymentParts {
    fn from(deployment: Deployment) -> Self {
        deployment.into_parts()
    }
}

/// Serialises a map's values as a sequence, in key order.
struct Values<'a, K, V>(&'a BTreeMap<K, V>);

impl<K, V: Serialize> Serialize for Values<'_, K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.values())
    }
}

/// Serialises exactly as [`DeploymentParts`], with nodes and users in id order.
impl Serialize for Deployment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Deployment", 6)?;
        state.serialize_field("config_generation", &self.config_generation)?;
        state.serialize_field("exit", &self.exit)?;
        state.serialize_field("policy", &self.policy)?;
        state.serialize_field("nodes", &Values(&self.nodes))?;
        state.serialize_field("users", &Values(&self.users))?;
        state.serialize_field("next_wg_index", &self.next_wg_index)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Sha256Digest;
    use crate::node::LifecycleStage;
    use crate::ports::{DEBIAN_EPHEMERAL_PORTS, PortRange};
    use crate::testing::{applied, exit_site, node, node_id, site, two_node_parts, user, user_id};

    fn build(parts: DeploymentParts) -> Result<Deployment, ModelError> {
        Deployment::try_from(parts)
    }

    #[test]
    fn a_valid_deployment_round_trips() {
        let deployment = build(two_node_parts()).unwrap();
        assert_eq!(deployment.nodes().len(), 2);
        assert_eq!(deployment.users().len(), 2);
        let json = serde_json::to_string(&deployment).unwrap();
        let parts_json = serde_json::to_string(&deployment.clone().into_parts()).unwrap();
        assert_eq!(
            json, parts_json,
            "Deployment serialises exactly as its parts"
        );
        let back: Deployment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, deployment);
        assert_eq!(build(deployment.clone().into_parts()).unwrap(), deployment);
    }

    #[test]
    fn a_fresh_deployment_is_empty_and_valid() {
        let fresh = Deployment::new(exit_site(), TrafficPolicy::default());
        assert_eq!(fresh.config_generation(), ConfigGeneration::INITIAL);
        assert_eq!(fresh.next_wg_index(), WgIndex::FIRST);
        assert!(fresh.required_secrets().is_empty());
        assert_eq!(build(fresh.clone().into_parts()).unwrap(), fresh);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let mut parts = two_node_parts();
        parts
            .nodes
            .push(node("lon1", 2, 30, NodeLifecycle::Retired));
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateId {
                id: EntityId::Node(node_id("lon1"))
            })
        );
        let mut parts = two_node_parts();
        parts.users.push(user(1, &[]));
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateId {
                id: EntityId::User(user_id(1))
            })
        );
    }

    #[test]
    fn duplicate_ids_in_json_are_rejected() {
        let json = serde_json::to_string(&two_node_parts()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let first = value["users"][0].clone();
        value["users"].as_array_mut().unwrap().push(first);
        assert!(serde_json::from_value::<Deployment>(value).is_err());
    }

    #[test]
    fn active_node_limit_ignores_retired_nodes() {
        let mut parts = two_node_parts();
        parts
            .nodes
            .push(node("lon2", 3, 30, NodeLifecycle::Planned));
        parts.next_wg_index = WgIndex::new(4).unwrap();
        assert_eq!(
            build(parts.clone()),
            Err(ModelError::TooManyNodes {
                max: MAX_ACTIVE_NODES
            })
        );
        parts.nodes[2].lifecycle = NodeLifecycle::Retired;
        assert!(build(parts.clone()).is_ok());
        parts.nodes[2].lifecycle = NodeLifecycle::RetiredPendingProviderDeletion {
            address: site([47, 1, 2, 3]).address,
        };
        assert!(build(parts).is_ok());
    }

    #[test]
    fn wg_indices_must_be_allocated_and_unique() {
        let mut parts = two_node_parts();
        parts.next_wg_index = WgIndex::new(2).unwrap();
        assert_eq!(
            build(parts),
            Err(ModelError::WgIndexNotAllocated {
                index: WgIndex::new(2).unwrap(),
                next: WgIndex::new(2).unwrap()
            })
        );
        let mut parts = two_node_parts();
        parts.nodes[1].wg_index = WgIndex::new(1).unwrap();
        // Ordered by id, ams1 comes first, so lon1 is the duplicate.
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateWgIndex {
                index: WgIndex::new(1).unwrap()
            })
        );
    }

    #[test]
    fn node_addresses_must_be_unique() {
        let mut parts = two_node_parts();
        parts.nodes[1].lifecycle = applied([45, 67, 89, 10], 1);
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateNodeAddress {
                addr: std::net::Ipv4Addr::new(45, 67, 89, 10)
            })
        );
    }

    #[test]
    fn port_plan_must_match_the_live_ephemeral_range() {
        let mut parts = two_node_parts();
        let live = PortRange::new(40000, 50000).unwrap();
        if let NodeLifecycle::Applied { site, .. } = &mut parts.nodes[0].lifecycle {
            site.host_facts.ephemeral_ports = live;
        }
        assert_eq!(
            build(parts.clone()),
            Err(ModelError::PortPlanConflict {
                conflict: PortConflict::EphemeralRangeChanged {
                    planned: DEBIAN_EPHEMERAL_PORTS,
                    live
                }
            })
        );
        parts.nodes[0].ports = parts.nodes[0].ports.rebase(live).unwrap();
        assert!(build(parts).is_ok());
    }

    #[test]
    fn applied_nodes_need_a_target_and_a_past_generation() {
        let mut parts = two_node_parts();
        parts.nodes[0].reality.target = None;
        assert_eq!(
            build(parts),
            Err(ModelError::TargetNotSet {
                node: node_id("lon1")
            })
        );
        let mut parts = two_node_parts();
        parts.nodes[0].lifecycle = applied([45, 67, 89, 10], 2);
        assert_eq!(
            build(parts.clone()),
            Err(ModelError::GenerationAhead {
                node: node_id("lon1"),
                applied: ConfigGeneration::new(2).unwrap(),
                current: ConfigGeneration::INITIAL
            })
        );
        parts.config_generation = ConfigGeneration::new(2).unwrap();
        assert!(build(parts).is_ok());
        // A planned node may lack a target.
        let mut parts = two_node_parts();
        parts.nodes[0].lifecycle = NodeLifecycle::Planned;
        parts.nodes[0].reality.target = None;
        assert!(build(parts).is_ok());
    }

    #[test]
    fn user_credentials_must_point_at_active_nodes() {
        let mut parts = two_node_parts();
        parts.users.push(user(3, &[("par1", 1)]));
        assert_eq!(
            build(parts),
            Err(ModelError::UnknownNode {
                id: node_id("par1")
            })
        );
        let mut parts = two_node_parts();
        parts.nodes[1].lifecycle = NodeLifecycle::Retired;
        assert_eq!(
            build(parts),
            Err(ModelError::CredentialsOnInactiveNode {
                user: user_id(1),
                node: node_id("ams1")
            })
        );
    }

    #[test]
    fn short_ids_are_unique_per_node_including_the_probe() {
        let mut parts = two_node_parts();
        parts.users.push(user(3, &[("lon1", 2)]));
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateShortId {
                node: node_id("lon1")
            })
        );
        let mut parts = two_node_parts();
        let probe = parts.nodes[0].reality.probe_short_id;
        parts.users[0]
            .per_node
            .get_mut(&node_id("lon1"))
            .unwrap()
            .short_id = probe;
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateShortId {
                node: node_id("lon1")
            })
        );
        // The same short id on different nodes is fine.
        let mut parts = two_node_parts();
        parts.users.push(user(3, &[("lon1", 9)]));
        parts.users.push(user(4, &[("ams1", 9)]));
        assert!(build(parts).is_ok());
    }

    #[test]
    fn revocation_states_are_consistent() {
        let mut parts = two_node_parts();
        parts.users[0].status = UserStatus::Revoked;
        assert_eq!(
            build(parts.clone()),
            Err(ModelError::RevokedUserHoldsCredentials { user: user_id(1) })
        );
        parts.users[0].per_node.clear();
        assert!(build(parts).is_ok());
        // Pending on both nodes, then on lon1 only after ams1 committed.
        let mut parts = two_node_parts();
        parts.users[0].status = UserStatus::RevokePending;
        let both = build(parts.clone()).unwrap();
        let remaining: Vec<&str> = both.users()[&user_id(1)]
            .revocation_remaining()
            .map(NodeId::as_str)
            .collect();
        assert_eq!(remaining, ["ams1", "lon1"]);
        parts.users[0].per_node.remove(&node_id("ams1"));
        assert!(build(parts.clone()).is_ok());
        // With no node left the user must be Revoked, not pending.
        parts.users[0].per_node.clear();
        assert_eq!(
            build(parts),
            Err(ModelError::RevokePendingWithoutCredentials { user: user_id(1) })
        );
    }

    #[test]
    fn queries() {
        let mut parts = two_node_parts();
        parts.users[1].status = UserStatus::RevokePending;
        let deployment = build(parts).unwrap();
        assert_eq!(
            deployment.node(&node_id("par1")),
            Err(ModelError::UnknownNode {
                id: node_id("par1")
            })
        );
        assert_eq!(
            deployment.user(&user_id(9)),
            Err(ModelError::UnknownUser { id: user_id(9) })
        );
        let served: Vec<UserId> = deployment
            .served_users(&node_id("lon1"))
            .map(|(user, _)| user.id.clone())
            .collect();
        assert_eq!(
            served,
            vec![user_id(1)],
            "a pending revocation is no longer served"
        );
        let addresses = deployment.node_addresses();
        assert_eq!(addresses.len(), 2);
        assert_eq!(
            addresses[&node_id("lon1")].ipv4(),
            std::net::Ipv4Addr::new(45, 67, 89, 10)
        );
    }

    #[test]
    fn node_addresses_follow_the_lifecycle() {
        let mut parts = two_node_parts();
        parts.users.clear();
        parts.nodes[0].lifecycle = NodeLifecycle::Planned;
        parts.nodes[1].lifecycle = NodeLifecycle::RetiredPendingProviderDeletion {
            address: site([46, 78, 90, 12]).address,
        };
        let deployment = build(parts).unwrap();
        let addresses = deployment.node_addresses();
        let names: Vec<&str> = addresses.keys().map(NodeId::as_str).collect();
        assert_eq!(names, vec!["ams1"]);
    }

    #[test]
    fn required_secrets_follow_lifecycle_and_status() {
        let mut parts = two_node_parts();
        parts.nodes[1].lifecycle = NodeLifecycle::Planned;
        parts.users[1].per_node.clear();
        parts.users[1].status = UserStatus::Revoked;
        let deployment = build(parts).unwrap();
        let refs: Vec<String> = deployment
            .required_secrets()
            .iter()
            .map(ToString::to_string)
            .collect();
        let user1 = user_id(1);
        let mut expected: Vec<String> = Vec::new();
        for node in ["lon1", "ams1"] {
            for item in [
                "reality-private",
                "wg-vps-private",
                "wg-mac-private",
                "hy2-key",
                "hy2-obfs/0",
            ] {
                expected.push(format!("node/{node}/{item}"));
            }
            for item in ["vless-uuid", "hy2-password", "loop-uuid"] {
                expected.push(format!("probe/{node}/{item}"));
                expected.push(format!("user/{user1}/{node}/{item}"));
            }
        }
        expected.push("node/ams1/ssh-bootstrap-private".to_owned());
        let mut expected_sorted: Vec<SecretRef> =
            expected.iter().map(|text| text.parse().unwrap()).collect();
        expected_sorted.sort();
        let expected: Vec<String> = expected_sorted.iter().map(ToString::to_string).collect();
        assert_eq!(refs, expected);
    }

    fn applied_config(generation: u64) -> AppliedConfig {
        AppliedConfig {
            config_generation: ConfigGeneration::new(generation).unwrap(),
            digest: Sha256Digest::from_bytes([0xd2; 32]),
        }
    }

    #[test]
    fn recording_an_apply_keeps_the_generation() {
        let mut parts = two_node_parts();
        parts.config_generation = ConfigGeneration::new(2).unwrap();
        parts.nodes[0].lifecycle = NodeLifecycle::Adopted {
            site: site([45, 67, 89, 10]),
        };
        let deployment = build(parts).unwrap();
        let recorded = deployment
            .clone()
            .record(Bookkeeping::Applied {
                node: node_id("lon1"),
                applied: applied_config(2),
            })
            .unwrap();
        assert_eq!(recorded.config_generation(), deployment.config_generation());
        let lon1 = recorded.node(&node_id("lon1")).unwrap();
        assert_eq!(lon1.lifecycle.applied(), Some(&applied_config(2)));
        assert_eq!(
            lon1.lifecycle.site(),
            deployment.node(&node_id("lon1")).unwrap().lifecycle.site()
        );
        // A generation the deployment has not reached is refused.
        assert_eq!(
            deployment.clone().record(Bookkeeping::Applied {
                node: node_id("lon1"),
                applied: applied_config(3),
            }),
            Err(ModelError::GenerationAhead {
                node: node_id("lon1"),
                applied: ConfigGeneration::new(3).unwrap(),
                current: ConfigGeneration::new(2).unwrap(),
            })
        );
        assert_eq!(
            deployment.record(Bookkeeping::Applied {
                node: node_id("par1"),
                applied: applied_config(1),
            }),
            Err(ModelError::UnknownNode {
                id: node_id("par1")
            })
        );
    }

    #[test]
    fn a_recorded_generation_never_goes_back() {
        let mut parts = two_node_parts();
        parts.config_generation = ConfigGeneration::new(3).unwrap();
        // The fixture's lon1 confirmed generation 2 with digest d1.
        parts.nodes[0].lifecycle = applied([45, 67, 89, 10], 2);
        let deployment = build(parts).unwrap();
        let fixture_digest = Sha256Digest::from_bytes([0xd1; 32]);
        let record = |deployment: Deployment, applied: AppliedConfig| {
            deployment.record(Bookkeeping::Applied {
                node: node_id("lon1"),
                applied,
            })
        };
        let confirmed = |deployment: &Deployment| {
            deployment
                .node(&node_id("lon1"))
                .unwrap()
                .lifecycle
                .applied()
                .copied()
        };
        assert_eq!(
            record(deployment.clone(), applied_config(1)),
            Err(ModelError::GenerationRegressed {
                node: node_id("lon1"),
                recorded: ConfigGeneration::new(2).unwrap(),
                applied: ConfigGeneration::new(1).unwrap(),
            })
        );
        // An unchanged re-apply confirms the same generation and digest again ...
        let unchanged = AppliedConfig {
            config_generation: ConfigGeneration::new(2).unwrap(),
            digest: fixture_digest,
        };
        let same = record(deployment, unchanged).unwrap();
        assert_eq!(confirmed(&same), Some(unchanged));
        // ... and a re-apply of the same generation with new engines (an app
        // upgrade, design §13.3) confirms a new digest, which is recorded.
        let upgraded = record(same, applied_config(2)).unwrap();
        assert_eq!(confirmed(&upgraded), Some(applied_config(2)));
        assert_ne!(applied_config(2).digest, fixture_digest);
        // A newer generation is recorded too, after which the older is refused.
        let newer = record(upgraded, applied_config(3)).unwrap();
        assert_eq!(confirmed(&newer), Some(applied_config(3)));
        assert_eq!(
            record(newer, applied_config(2)),
            Err(ModelError::GenerationRegressed {
                node: node_id("lon1"),
                recorded: ConfigGeneration::new(3).unwrap(),
                applied: ConfigGeneration::new(2).unwrap(),
            })
        );
    }

    #[test]
    fn only_adopted_and_applied_nodes_record_an_apply() {
        for (lifecycle, stage) in [
            (NodeLifecycle::Planned, LifecycleStage::Planned),
            (
                NodeLifecycle::Retiring {
                    site: site([45, 67, 89, 10]),
                },
                LifecycleStage::Retiring,
            ),
        ] {
            let mut parts = two_node_parts();
            parts.users.clear();
            parts.nodes[0].lifecycle = lifecycle;
            assert_eq!(
                build(parts).unwrap().record(Bookkeeping::Applied {
                    node: node_id("lon1"),
                    applied: applied_config(1),
                }),
                Err(ModelError::NodeNotDeployable {
                    node: node_id("lon1"),
                    stage
                })
            );
        }
    }

    #[test]
    fn committed_revocations_drop_credentials_until_the_user_is_revoked() {
        let mut parts = two_node_parts();
        parts.users[0].status = UserStatus::RevokePending;
        let deployment = build(parts).unwrap();
        let generation = deployment.config_generation();
        let commit = |deployment: Deployment, node: &str| {
            deployment.record(Bookkeeping::RevocationCommitted {
                user: user_id(1),
                node: node_id(node),
            })
        };
        let one_left = commit(deployment, "ams1").unwrap();
        let user = &one_left.users()[&user_id(1)];
        assert_eq!(user.status, UserStatus::RevokePending);
        let remaining: Vec<&str> = user.revocation_remaining().map(NodeId::as_str).collect();
        assert_eq!(remaining, ["lon1"]);
        assert_eq!(
            commit(one_left.clone(), "ams1"),
            Err(ModelError::NoCredentialsOnNode {
                user: user_id(1),
                node: node_id("ams1")
            })
        );
        let revoked = commit(one_left, "lon1").unwrap();
        let user = &revoked.users()[&user_id(1)];
        assert_eq!(user.status, UserStatus::Revoked);
        assert!(user.per_node.is_empty());
        assert_eq!(revoked.config_generation(), generation);
        // An active user is not being revoked.
        assert_eq!(
            revoked.record(Bookkeeping::RevocationCommitted {
                user: user_id(2),
                node: node_id("lon1"),
            }),
            Err(ModelError::NotRevoking { user: user_id(2) })
        );
    }

    #[test]
    fn a_shut_down_retirement_drops_the_node_and_its_credentials() {
        let mut parts = two_node_parts();
        parts.nodes[0].lifecycle = NodeLifecycle::Retiring {
            site: site([45, 67, 89, 10]),
        };
        parts.users[1].per_node.remove(&node_id("ams1"));
        parts.users[1].status = UserStatus::RevokePending;
        let deployment = build(parts).unwrap();
        let retired = deployment
            .clone()
            .record(Bookkeeping::RetirementShutDown {
                node: node_id("lon1"),
            })
            .unwrap();
        assert_eq!(retired.config_generation(), deployment.config_generation());
        assert_eq!(
            retired.node(&node_id("lon1")).unwrap().lifecycle,
            NodeLifecycle::RetiredPendingProviderDeletion {
                address: site([45, 67, 89, 10]).address
            }
        );
        // The address stays denied until the operator confirms the VM is gone.
        assert!(retired.node_addresses().contains_key(&node_id("lon1")));
        let held: Vec<&str> = retired.users()[&user_id(1)]
            .per_node
            .keys()
            .map(NodeId::as_str)
            .collect();
        assert_eq!(held, ["ams1"]);
        assert_eq!(retired.users()[&user_id(2)].status, UserStatus::Revoked);
        assert!(
            retired
                .required_secrets()
                .iter()
                .all(|secret_ref| secret_ref.node().as_str() == "ams1")
        );
        assert_eq!(
            retired.record(Bookkeeping::RetirementShutDown {
                node: node_id("ams1"),
            }),
            Err(ModelError::NodeNotRetiring {
                node: node_id("ams1"),
                stage: LifecycleStage::Applied
            })
        );
    }

    #[test]
    fn retired_nodes_require_no_secrets() {
        let mut parts = two_node_parts();
        parts.users.clear();
        parts.nodes[0].lifecycle = NodeLifecycle::Retired;
        let deployment = build(parts).unwrap();
        assert!(
            deployment
                .required_secrets()
                .iter()
                .all(|r| r.node().as_str() == "ams1")
        );
    }
}
