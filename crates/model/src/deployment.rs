// SPDX-License-Identifier: GPL-3.0-or-later

//! The deployment: every node, user and viewer, validated as a whole
//! (design §7).

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::alerting::AlertSettings;
use crate::counters::ConfigGeneration;
use crate::error::{EntityId, ModelError};
use crate::exit::{ExitSite, TrafficPolicy};
use crate::ids::{NodeId, PublicAlias, ShortId, UserId};
use crate::keys::Ed25519Pub;
use crate::node::{AppliedConfig, Node, NodeAddress, NodeLifecycle};
use crate::ports::PortConflict;
use crate::quota::AutoQuotaPolicy;
use crate::secret::SecretRef;
use crate::user::{AgreementRecord, User, UserNodePublic, UserStatus};
use crate::viewer::Viewer;
use crate::wg::WgIndex;

/// The most nodes that may be active at once in v1: one WireGuard endpoint
/// per node on the Mac, at most two.
pub const MAX_ACTIVE_NODES: usize = 2;

/// The cap on active users the pilot runs with, 5: decisions F3 and D-1,
/// 2026-10-08, a pilot of at most 5 active users, and the value `exit init`
/// records ([`CapacityPolicy::PILOT`]).
pub const PILOT_MAX_ACTIVE_USERS: NonZeroU16 = match NonZeroU16::new(5) {
    Some(users) => users,
    None => panic!("the pilot's cap is not zero"),
};

/// Admission control: how many users may be active at once. Suspended,
/// revoking and revoked users never count. A fresh deployment records its
/// cap explicitly ([`DeploymentInit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityPolicy {
    /// The most users that may be `Active` at once, if capped. The key is
    /// required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub max_active_users: Option<NonZeroU16>,
}

impl CapacityPolicy {
    /// No cap on active users: what a version-1 document lifts to.
    pub const UNLIMITED: Self = Self {
        max_active_users: None,
    };

    /// The pilot's cap, [`PILOT_MAX_ACTIVE_USERS`] (decisions F3 and D-1).
    pub const PILOT: Self = Self {
        max_active_users: Some(PILOT_MAX_ACTIVE_USERS),
    };
}

/// Everything a fresh deployment records. `exit init` fills every field,
/// so nothing has a hidden default: the pilot records the SMARTY plan with
/// the F2 thresholds, [`CapacityPolicy::PILOT`],
/// `Some(AutoQuotaPolicy::PILOT)` and `Some(AlertSettings::pilot())`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentInit {
    /// The Mac exit site; its SIM plan must be recorded.
    pub exit: ExitSite,
    /// Destination policy.
    pub policy: TrafficPolicy,
    /// Admission control.
    pub capacity: CapacityPolicy,
    /// Automatic per-user quotas, if on.
    pub auto_quota: Option<AutoQuotaPolicy>,
    /// The alert channels, if set up; a fresh deployment has no node, so no
    /// channel node.
    pub alerting: Option<AlertSettings>,
}

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
    /// Admission control.
    pub capacity: CapacityPolicy,
    /// Automatic per-user quotas (decision F4), if on. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub auto_quota: Option<AutoQuotaPolicy>,
    /// The alert channels (decision F6), if set up. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub alerting: Option<AlertSettings>,
    /// Every remote viewer (decision F5).
    pub viewers: Vec<Viewer>,
    /// Every node, including retired ones.
    pub nodes: Vec<Node>,
    /// Every user, including revoked ones.
    pub users: Vec<User>,
    /// The next WireGuard index to allocate; indices are never reused.
    pub next_wg_index: WgIndex,
}

/// Every node, user and viewer of the one exit, with all cross-entity
/// invariants checked. Built only from [`DeploymentParts`] (also when
/// deserialised), or fresh by [`Deployment::new`]:
///
/// - node and user ids and viewer keys are unique;
/// - at most [`MAX_ACTIVE_NODES`] nodes are active;
/// - WireGuard indices are unique and below `next_wg_index`;
/// - live node addresses are unique;
/// - an adopted node's port plan was checked against its host's live range;
/// - an applied node has a target and a generation no newer than the deployment's;
/// - users hold credentials only on active nodes, revoked users on none, and
///   a user pending revocation on at least one (the nodes still to commit);
/// - REALITY short ids are unique per node, probe included;
/// - public aliases are unique among users;
/// - at most `capacity.max_active_users` users are active;
/// - the digest goes out no earlier than its zone's earliest daily time
///   (02:00 in Europe/London), and alert channels are set up only for
///   active nodes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "DeploymentParts")]
pub struct Deployment {
    config_generation: ConfigGeneration,
    exit: ExitSite,
    policy: TrafficPolicy,
    capacity: CapacityPolicy,
    auto_quota: Option<AutoQuotaPolicy>,
    alerting: Option<AlertSettings>,
    viewers: BTreeMap<Ed25519Pub, Viewer>,
    nodes: BTreeMap<NodeId, Node>,
    users: BTreeMap<UserId, User>,
    next_wg_index: WgIndex,
}

impl Deployment {
    /// A fresh deployment of `init`, with no nodes, users or viewers, at
    /// the initial generation. `PlanNotRecorded` unless the exit's SIM plan
    /// is recorded (a policy lifted from version 1 has none); every other
    /// invariant as for any deployment (an alert channel naming a node is
    /// `UnknownNode`, because there is none yet).
    pub fn new(init: DeploymentInit) -> Result<Self, ModelError> {
        if init.exit.sim.plan().is_none() {
            return Err(ModelError::PlanNotRecorded);
        }
        Self::try_from(DeploymentParts {
            config_generation: ConfigGeneration::INITIAL,
            exit: init.exit,
            policy: init.policy,
            capacity: init.capacity,
            auto_quota: init.auto_quota,
            alerting: init.alerting,
            viewers: Vec::new(),
            nodes: Vec::new(),
            users: Vec::new(),
            next_wg_index: WgIndex::FIRST,
        })
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

    /// Admission control.
    #[must_use]
    pub const fn capacity(&self) -> CapacityPolicy {
        self.capacity
    }

    /// Automatic per-user quotas, if on.
    #[must_use]
    pub const fn auto_quota(&self) -> Option<AutoQuotaPolicy> {
        self.auto_quota
    }

    /// The alert channels, if set up.
    #[must_use]
    pub const fn alerting(&self) -> Option<&AlertSettings> {
        self.alerting.as_ref()
    }

    /// Every remote viewer, by key.
    #[must_use]
    pub const fn viewers(&self) -> &BTreeMap<Ed25519Pub, Viewer> {
        &self.viewers
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
    /// keychain is orphaned, except the M7's admin password
    /// ([`SecretRef::RouterAdmin`]), which no deployment references and
    /// this set never contains. While at least one node has its alert
    /// channels set up, the deployment references its one ntfy topic
    /// ([`SecretRef::AlertTopic`]), which every channel node sends to, and
    /// each channel node its own two Healthchecks checks.
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
        if let Some(alerting) = &self.alerting {
            if !alerting.channels.is_empty() {
                refs.insert(SecretRef::AlertTopic);
            }
            for node in &alerting.channels {
                refs.insert(SecretRef::NodeDeadManCheck(node.clone()));
                refs.insert(SecretRef::NodeMacAliveCheck(node.clone()));
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
            capacity: self.capacity,
            auto_quota: self.auto_quota,
            alerting: self.alerting,
            viewers: self.viewers.into_values().collect(),
            nodes: self.nodes.into_values().collect(),
            users: self.users.into_values().collect(),
            next_wg_index: self.next_wg_index,
        }
    }
}

/// The indexed entities every cross-entity invariant is checked over. The
/// exit site takes no part in them.
///
/// The invariants come in two sets. [`Entities::check_version_1`] holds
/// exactly the rules version 1 had, and a version-1 document
/// (`crate::v1`) is checked with those alone, so its decoding never
/// changes. [`Entities::check`] adds the rules of later versions. A new
/// invariant therefore goes into `check`, never into the version-1 set: a
/// version-1 document that breaks it then fails its migration step
/// (`MigrationFailed`, with the document untouched) rather than reading as
/// corrupt.
#[derive(Debug)]
pub(crate) struct Entities<'a> {
    pub(crate) config_generation: ConfigGeneration,
    pub(crate) nodes: &'a BTreeMap<NodeId, Node>,
    pub(crate) users: &'a BTreeMap<UserId, User>,
    pub(crate) next_wg_index: WgIndex,
    pub(crate) capacity: CapacityPolicy,
    pub(crate) alerting: Option<&'a AlertSettings>,
}

impl Entities<'_> {
    /// Checks every invariant listed on [`Deployment`] after unique ids:
    /// the version-1 rules, then unique public aliases, the cap on active
    /// users, the digest time and the alert channels' nodes (version 2).
    pub(crate) fn check(&self) -> Result<(), ModelError> {
        self.check_version_1()?;
        self.check_aliases()?;
        self.check_capacity()?;
        self.check_digest_time()?;
        self.check_alert_channels()
    }

    /// Checks the cross-entity rules of version 1, and only those: the
    /// active-node cap, WireGuard indices, node addresses, port plans,
    /// applied targets and generations, where users hold credentials,
    /// short ids, and the revocation states. Frozen: see the type.
    pub(crate) fn check_version_1(&self) -> Result<(), ModelError> {
        self.check_nodes()?;
        self.check_credentials()
    }

    fn check_nodes(&self) -> Result<(), ModelError> {
        let active = self
            .nodes
            .values()
            .filter(|node| node.lifecycle.is_active())
            .count();
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

    fn check_credentials(&self) -> Result<(), ModelError> {
        let mut short_ids: BTreeMap<&NodeId, BTreeSet<ShortId>> = self
            .nodes
            .values()
            .map(|node| (&node.id, BTreeSet::from([node.reality.probe_short_id])))
            .collect();
        for user in self.users.values() {
            for (node_id, public) in &user.per_node {
                let node = self
                    .nodes
                    .get(node_id)
                    .ok_or_else(|| ModelError::UnknownNode {
                        id: node_id.clone(),
                    })?;
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
                // A suspended user keeps its credentials, or holds none
                // after the nodes it held them on were retired.
                UserStatus::Active | UserStatus::Suspended { .. } => {}
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

    fn check_aliases(&self) -> Result<(), ModelError> {
        let mut aliases: BTreeSet<&PublicAlias> = BTreeSet::new();
        for alias in self.users.values().filter_map(|user| user.alias.as_ref()) {
            if !aliases.insert(alias) {
                return Err(ModelError::DuplicateAlias {
                    alias: alias.clone(),
                });
            }
        }
        Ok(())
    }

    fn check_capacity(&self) -> Result<(), ModelError> {
        let Some(max) = self.capacity.max_active_users else {
            return Ok(());
        };
        let active = self
            .users
            .values()
            .filter(|user| user.status == UserStatus::Active)
            .count();
        if active > usize::from(max.get()) {
            return Err(ModelError::TooManyActiveUsers { max, active });
        }
        Ok(())
    }

    /// The digest goes out no earlier than its zone's earliest daily time.
    fn check_digest_time(&self) -> Result<(), ModelError> {
        let Some(alerting) = self.alerting else {
            return Ok(());
        };
        let earliest = alerting.digest_zone.earliest_daily_time();
        if alerting.digest_at < earliest {
            return Err(ModelError::DigestTimeTooEarly {
                at: alerting.digest_at,
                earliest,
            });
        }
        Ok(())
    }

    /// Every alert channel node exists and is active: an inactive node's
    /// secrets are deleted, its channels with them.
    fn check_alert_channels(&self) -> Result<(), ModelError> {
        for id in self.alerting.iter().flat_map(|alerting| &alerting.channels) {
            let node = self
                .nodes
                .get(id)
                .ok_or_else(|| ModelError::UnknownNode { id: id.clone() })?;
            if !node.lifecycle.is_active() {
                return Err(ModelError::AlertChannelsOnInactiveNode { node: id.clone() });
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
///   is still denied everywhere), and drops every user's credentials on it
///   and its alert channels: a retired node renders nothing, so no bundle
///   carries them any more.
/// - `AgreementRecorded` records which revision of the user agreement a user
///   accepted. It is Mac-only and is never rendered, sent or exported; it
///   decides only whether `user export` refuses the user (decision F9,
///   design §9.2), so a recorded agreement needs no `node apply`.
///
/// Suspending or resuming a user ([`User::suspend`], [`User::resume`]) is
/// never bookkeeping: it changes which users every node serves, so it is
/// a configuration change and bumps the generation. Starting a revocation
/// ([`User::revoke`]) is one too, for the same reason.
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
    /// credentials only there becomes `Revoked`, and the node's alert
    /// channels are dropped.
    RetirementShutDown {
        /// The node.
        node: NodeId,
    },
    /// `user` accepted the agreement revision in `record` (`user agree`,
    /// design §7). A user pending revocation or revoked is refused
    /// (`RevocationAlreadyStarted`), and so is a revision older than the
    /// one recorded (`AgreementRegressed`). The same revision keeps the
    /// record as it is, so its day stays the day of the first acceptance.
    AgreementRecorded {
        /// The user.
        user: UserId,
        /// The revision accepted and the day.
        record: AgreementRecord,
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
                if let Some(alerting) = &mut parts.alerting {
                    alerting.channels.remove(&node);
                }
            }
            Bookkeeping::AgreementRecorded { user, record } => {
                let user = parts
                    .users
                    .iter_mut()
                    .find(|candidate| candidate.id == user)
                    .ok_or(ModelError::UnknownUser { id: user })?;
                if matches!(user.status, UserStatus::RevokePending | UserStatus::Revoked) {
                    return Err(ModelError::RevocationAlreadyStarted {
                        user: user.id.clone(),
                    });
                }
                match user.agreement {
                    Some(recorded) if record.version < recorded.version => {
                        return Err(ModelError::AgreementRegressed {
                            user: user.id.clone(),
                            recorded: recorded.version,
                            offered: record.version,
                        });
                    }
                    Some(recorded) if record.version == recorded.version => {}
                    Some(_) | None => user.agreement = Some(record),
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

/// Indexes `items` by id, refusing a duplicate (`DuplicateId`).
pub(crate) fn index_by_id<K: Ord + Clone, V>(
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
            capacity: parts.capacity,
            auto_quota: parts.auto_quota,
            alerting: parts.alerting,
            viewers: index_by_id(
                parts.viewers,
                |viewer: &Viewer| &viewer.key,
                EntityId::Viewer,
            )?,
            nodes: index_by_id(parts.nodes, |node: &Node| &node.id, EntityId::Node)?,
            users: index_by_id(parts.users, |user: &User| &user.id, EntityId::User)?,
            next_wg_index: parts.next_wg_index,
        };
        Entities {
            config_generation: deployment.config_generation,
            nodes: &deployment.nodes,
            users: &deployment.users,
            next_wg_index: deployment.next_wg_index,
            capacity: deployment.capacity,
            alerting: deployment.alerting.as_ref(),
        }
        .check()?;
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

/// Serialises exactly as [`DeploymentParts`], with viewers in key order and
/// nodes and users in id order.
impl Serialize for Deployment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Deployment", 10)?;
        state.serialize_field("config_generation", &self.config_generation)?;
        state.serialize_field("exit", &self.exit)?;
        state.serialize_field("policy", &self.policy)?;
        state.serialize_field("capacity", &self.capacity)?;
        state.serialize_field("auto_quota", &self.auto_quota)?;
        state.serialize_field("alerting", &self.alerting)?;
        state.serialize_field("viewers", &Values(&self.viewers))?;
        state.serialize_field("nodes", &Values(&self.nodes))?;
        state.serialize_field("users", &Values(&self.users))?;
        state.serialize_field("next_wg_index", &self.next_wg_index)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::{AlertSettings, WallClockTime, WallClockZone};
    use crate::date::CalendarDate;
    use crate::digest::Sha256Digest;
    use crate::ids::LocalLabel;
    use crate::node::LifecycleStage;
    use crate::ports::{DEBIAN_EPHEMERAL_PORTS, PortRange};
    use crate::secret::SecretKind;
    use crate::sim::SimPolicy;
    use crate::testing::{applied, exit_site, node, node_id, site, two_node_parts, user, user_id};
    use crate::user::{AgreementVersion, SuspendReason};

    fn build(parts: DeploymentParts) -> Result<Deployment, ModelError> {
        Deployment::try_from(parts)
    }

    /// What `exit init` records for the pilot, on the test exit site.
    fn pilot_init() -> DeploymentInit {
        DeploymentInit {
            exit: exit_site(),
            policy: TrafficPolicy::default(),
            capacity: CapacityPolicy::PILOT,
            auto_quota: Some(AutoQuotaPolicy::PILOT),
            alerting: Some(AlertSettings::pilot()),
        }
    }

    fn viewer(byte: u8, label: &str) -> Viewer {
        Viewer {
            key: Ed25519Pub::from_bytes([byte; 32]).unwrap(),
            label: LocalLabel::parse(label).unwrap(),
            added_on: CalendarDate::parse("2026-10-08").unwrap(),
        }
    }

    fn channels(nodes: &[&str]) -> Option<AlertSettings> {
        Some(AlertSettings {
            channels: nodes.iter().map(|id| node_id(id)).collect(),
            ..AlertSettings::pilot()
        })
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
        let fresh = Deployment::new(pilot_init()).unwrap();
        assert_eq!(fresh.config_generation(), ConfigGeneration::INITIAL);
        assert_eq!(fresh.next_wg_index(), WgIndex::FIRST);
        assert!(fresh.nodes().is_empty() && fresh.users().is_empty());
        assert!(fresh.viewers().is_empty());
        assert!(fresh.required_secrets().is_empty());
        // Every record is what the init gave, with nothing defaulted.
        assert_eq!(fresh.exit(), &exit_site());
        assert_eq!(fresh.capacity(), CapacityPolicy::PILOT);
        assert_eq!(fresh.auto_quota(), Some(AutoQuotaPolicy::PILOT));
        assert_eq!(fresh.alerting(), Some(&AlertSettings::pilot()));
        assert_eq!(build(fresh.clone().into_parts()).unwrap(), fresh);
        let bare = Deployment::new(DeploymentInit {
            capacity: CapacityPolicy::UNLIMITED,
            auto_quota: None,
            alerting: None,
            ..pilot_init()
        })
        .unwrap();
        assert_eq!(bare.capacity(), CapacityPolicy::UNLIMITED);
        assert_eq!((bare.auto_quota(), bare.alerting()), (None, None));
    }

    /// P0-1: a fresh deployment records the plan. Only a policy lifted from
    /// version 1 has none, and the only ways to hold one are decoding it
    /// and cloning a lifted state's exit site.
    #[test]
    fn a_fresh_deployment_needs_a_recorded_plan() {
        let lifted: SimPolicy = serde_json::from_str(
            r#"{"bill_day":1,"plan":null,"warn_bytes":240000000000,"stop":{"hard_stop":{"bytes":300000000000}}}"#,
        )
        .unwrap();
        assert_eq!(lifted.plan(), None);
        let mut init = pilot_init();
        init.exit.sim = lifted;
        assert_eq!(Deployment::new(init), Err(ModelError::PlanNotRecorded));
        assert!(Deployment::new(pilot_init()).is_ok());
        // A channel needs a node, and a fresh deployment has none.
        assert_eq!(
            Deployment::new(DeploymentInit {
                alerting: channels(&["lon1"]),
                ..pilot_init()
            }),
            Err(ModelError::UnknownNode {
                id: node_id("lon1")
            })
        );
    }

    /// Decisions F3 and D-1: the pilot admits at most five active users.
    #[test]
    fn the_pilot_cap_is_five() {
        assert_eq!(PILOT_MAX_ACTIVE_USERS.get(), 5);
        assert_eq!(
            CapacityPolicy::PILOT.max_active_users,
            Some(PILOT_MAX_ACTIVE_USERS)
        );
        let mut parts = two_node_parts();
        parts.capacity = CapacityPolicy::PILOT;
        for n in 3..=5 {
            parts
                .users
                .push(user(n, &[("lon1", 10 + u8::try_from(n).unwrap())]));
        }
        assert!(build(parts.clone()).is_ok(), "five active users");
        parts.users.push(user(6, &[("lon1", 16)]));
        assert_eq!(
            build(parts),
            Err(ModelError::TooManyActiveUsers {
                max: PILOT_MAX_ACTIVE_USERS,
                active: 6
            })
        );
    }

    /// Alert channels exist only for active nodes, planned to retiring.
    #[test]
    fn alert_channels_need_an_active_node() {
        let mut parts = two_node_parts();
        parts.alerting = channels(&["lon1", "par1"]);
        assert_eq!(
            build(parts),
            Err(ModelError::UnknownNode {
                id: node_id("par1")
            })
        );
        for lifecycle in [
            NodeLifecycle::Retired,
            NodeLifecycle::RetiredPendingProviderDeletion {
                address: site([45, 67, 89, 10]).address,
            },
        ] {
            let mut parts = two_node_parts();
            parts.users.clear();
            parts.nodes[0].lifecycle = lifecycle;
            parts.alerting = channels(&["lon1"]);
            assert_eq!(
                build(parts.clone()),
                Err(ModelError::AlertChannelsOnInactiveNode {
                    node: node_id("lon1")
                })
            );
            parts.alerting = channels(&["ams1"]);
            assert!(build(parts).is_ok());
        }
        for lifecycle in [
            NodeLifecycle::Planned,
            NodeLifecycle::Adopted {
                site: site([45, 67, 89, 10]),
            },
            NodeLifecycle::Retiring {
                site: site([45, 67, 89, 10]),
            },
        ] {
            let mut parts = two_node_parts();
            parts.nodes[0].lifecycle = lifecycle;
            parts.alerting = channels(&["lon1", "ams1"]);
            assert!(build(parts).is_ok());
        }
        // Settings without channels name no node.
        let mut parts = two_node_parts();
        parts.alerting = channels(&[]);
        assert!(build(parts).is_ok());
    }

    /// The digest goes out from 02:00 to 23:59 London time, every minute
    /// checked: an earlier time is skipped or repeated when the UK's clocks
    /// change, or falls on the previous UTC date. Decoding checks it too.
    #[test]
    fn the_digest_goes_out_from_two_oclock() {
        let earliest = WallClockTime::parse("02:00").unwrap();
        let mut accepted = 0;
        for minutes in 0..24 * 60_u16 {
            let at = WallClockTime::new(
                u8::try_from(minutes / 60).unwrap(),
                u8::try_from(minutes % 60).unwrap(),
            )
            .unwrap();
            let mut parts = two_node_parts();
            parts.alerting = Some(AlertSettings {
                digest_at: at,
                ..AlertSettings::pilot()
            });
            let built = build(parts.clone());
            if minutes >= 120 {
                accepted += 1;
                assert!(built.is_ok(), "{at}");
            } else {
                assert_eq!(
                    built,
                    Err(ModelError::DigestTimeTooEarly { at, earliest }),
                    "{at}"
                );
                let json = serde_json::to_string(&parts).unwrap();
                assert!(serde_json::from_str::<Deployment>(&json).is_err(), "{at}");
            }
        }
        assert_eq!(accepted, 22 * 60);
    }

    /// The two Healthchecks checks of one channel node.
    fn checks_of(id: &str) -> [SecretRef; 2] {
        [
            SecretRef::NodeDeadManCheck(node_id(id)),
            SecretRef::NodeMacAliveCheck(node_id(id)),
        ]
    }

    /// The deployment's one ntfy topic is required exactly while some node
    /// has its channels set up, once however many do; each channel node
    /// adds its own two checks. Without channels nothing is added.
    #[test]
    fn the_alert_topic_is_required_iff_a_channel_node_exists() {
        let without = build(two_node_parts()).unwrap().required_secrets();
        assert!(!without.contains(&SecretRef::AlertTopic));
        for alerting in [None, channels(&[])] {
            let mut parts = two_node_parts();
            parts.alerting = alerting;
            assert_eq!(build(parts).unwrap().required_secrets(), without);
        }
        for (nodes, expected) in [
            (&["lon1"][..], vec![checks_of("lon1")]),
            (&["ams1"][..], vec![checks_of("ams1")]),
            (
                &["lon1", "ams1"][..],
                vec![checks_of("lon1"), checks_of("ams1")],
            ),
        ] {
            let mut parts = two_node_parts();
            parts.alerting = channels(nodes);
            let with = build(parts).unwrap().required_secrets();
            assert!(without.is_subset(&with));
            let added: BTreeSet<SecretRef> = with.difference(&without).cloned().collect();
            let mut want: BTreeSet<SecretRef> = expected.into_iter().flatten().collect();
            want.insert(SecretRef::AlertTopic);
            assert_eq!(added, want, "{nodes:?}");
            let without_node: Vec<&SecretRef> = added
                .iter()
                .filter(|secret_ref| secret_ref.node().is_none())
                .collect();
            assert_eq!(without_node, [&SecretRef::AlertTopic], "{nodes:?}");
        }
    }

    /// No deployment references the M7's admin password: it is set by
    /// `mooringctl router set-password`, so the store's ordered secret
    /// updates never plan to write or delete it, and it is never orphaned.
    #[test]
    fn deployments_never_require_the_router_password() {
        let mut planned = two_node_parts();
        planned.nodes[1].lifecycle = NodeLifecycle::Planned;
        let mut with_channels = two_node_parts();
        with_channels.alerting = channels(&["lon1", "ams1"]);
        let mut without_users = two_node_parts();
        without_users.users.clear();
        for parts in [two_node_parts(), planned, with_channels, without_users] {
            let required = build(parts).unwrap().required_secrets();
            assert!(!required.is_empty());
            assert!(!required.contains(&SecretRef::RouterAdmin));
            assert!(
                required
                    .iter()
                    .all(|secret_ref| secret_ref.kind() != SecretKind::RouterAdminPassword)
            );
        }
    }

    /// Shutting a retiring node down drops its alert channels and with them
    /// its two checks, as it drops the users' credentials there; the topic
    /// stays while another node has channels, and goes with the last one.
    #[test]
    fn a_shut_down_retirement_drops_the_nodes_alert_channels() {
        let mut parts = two_node_parts();
        parts.nodes[0].lifecycle = NodeLifecycle::Retiring {
            site: site([45, 67, 89, 10]),
        };
        parts.alerting = channels(&["lon1", "ams1"]);
        let deployment = build(parts).unwrap();
        let retired = deployment
            .clone()
            .record(Bookkeeping::RetirementShutDown {
                node: node_id("lon1"),
            })
            .unwrap();
        assert_eq!(retired.config_generation(), deployment.config_generation());
        assert_eq!(retired.alerting(), channels(&["ams1"]).as_ref());
        let refs = retired.required_secrets();
        for secret_ref in checks_of("lon1") {
            assert!(deployment.required_secrets().contains(&secret_ref));
            assert!(!refs.contains(&secret_ref), "{secret_ref}");
        }
        for secret_ref in checks_of("ams1") {
            assert!(refs.contains(&secret_ref), "{secret_ref}");
        }
        assert!(
            deployment
                .required_secrets()
                .contains(&SecretRef::AlertTopic)
        );
        assert!(refs.contains(&SecretRef::AlertTopic));
        // With lon1 the only channel node, its retirement drops the topic.
        let mut parts = deployment.clone().into_parts();
        parts.alerting = channels(&["lon1"]);
        let alone = build(parts)
            .unwrap()
            .record(Bookkeeping::RetirementShutDown {
                node: node_id("lon1"),
            })
            .unwrap();
        assert_eq!(alone.alerting(), channels(&[]).as_ref());
        let mut expected = retired.required_secrets();
        expected.remove(&SecretRef::AlertTopic);
        for secret_ref in checks_of("ams1") {
            expected.remove(&secret_ref);
        }
        assert_eq!(alone.required_secrets(), expected);
        // The digest time and zone stay.
        let alerting = retired.alerting().unwrap();
        assert_eq!(alerting.digest_zone, WallClockZone::EuropeLondon);
        assert_eq!(alerting.digest_at, AlertSettings::pilot().digest_at);
    }

    /// Viewers are unique by key, built or decoded; labels may repeat.
    #[test]
    fn viewer_keys_are_unique() {
        let mut parts = two_node_parts();
        parts.viewers = vec![viewer(0x22, "phone"), viewer(0x11, "phone")];
        let deployment = build(parts.clone()).unwrap();
        let keys: Vec<&Ed25519Pub> = deployment.viewers().keys().collect();
        assert_eq!(keys, [&viewer(0x11, "x").key, &viewer(0x22, "x").key]);
        // Viewers reference no secret: only the public half is imported.
        assert_eq!(
            deployment.required_secrets(),
            build(two_node_parts()).unwrap().required_secrets()
        );
        parts.viewers.push(viewer(0x22, "tablet"));
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateId {
                id: EntityId::Viewer(viewer(0x22, "x").key)
            })
        );
        let mut value = serde_json::to_value(&deployment).unwrap();
        let first = value["viewers"][0].clone();
        value["viewers"].as_array_mut().unwrap().push(first);
        assert!(serde_json::from_value::<Deployment>(value).is_err());
        assert_eq!(
            ModelError::DuplicateId {
                id: EntityId::Viewer(viewer(0x7e, "x").key)
            }
            .to_string(),
            "duplicate viewer fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4="
        );
    }

    /// The version-2 records sit between the cap and the nodes, and each
    /// key is required.
    #[test]
    fn the_new_records_are_required_keys() {
        let mut parts = two_node_parts();
        parts.auto_quota = Some(AutoQuotaPolicy::PILOT);
        parts.alerting = channels(&["lon1"]);
        parts.viewers = vec![viewer(0x7e, "phone")];
        let deployment = build(parts).unwrap();
        let json = serde_json::to_string(&deployment).unwrap();
        let records = r#""capacity":{"max_active_users":null},"auto_quota":{"from_active_users":6,"budget_percent":80,"sim_factor":2100,"warn_percent":80,"action":"suspend"},"alerting":{"digest_at":"09:00","digest_zone":"europe_london","channels":["lon1"]},"viewers":[{"key":"fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4=","label":"phone","added_on":"2026-10-08"}],"nodes":["#;
        assert!(json.contains(records), "{json}");
        assert_eq!(
            serde_json::from_str::<Deployment>(&json).unwrap(),
            deployment
        );
        let fresh = serde_json::to_string(&build(two_node_parts()).unwrap()).unwrap();
        assert!(
            fresh.contains(r#""auto_quota":null,"alerting":null,"viewers":[],"nodes":["#),
            "{fresh}"
        );
        for (document, key) in [
            (
                &json,
                r#""auto_quota":{"from_active_users":6,"budget_percent":80,"sim_factor":2100,"warn_percent":80,"action":"suspend"},"#,
            ),
            (
                &json,
                r#""alerting":{"digest_at":"09:00","digest_zone":"europe_london","channels":["lon1"]},"#,
            ),
            (
                &json,
                r#""viewers":[{"key":"fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn4=","label":"phone","added_on":"2026-10-08"}],"#,
            ),
            (&fresh, r#""auto_quota":null,"#),
            (&fresh, r#""alerting":null,"#),
            (&fresh, r#""viewers":[],"#),
        ] {
            let missing = document.replacen(key, "", 1);
            assert_ne!(&missing, document);
            assert!(
                serde_json::from_str::<Deployment>(&missing).is_err(),
                "{missing}"
            );
        }
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

    fn agreement(revision: u16, day: &str) -> AgreementRecord {
        AgreementRecord {
            version: AgreementVersion::new(NonZeroU16::new(revision).unwrap()),
            accepted_on: CalendarDate::parse(day).unwrap(),
        }
    }

    fn agree(deployment: Deployment, record: AgreementRecord) -> Result<Deployment, ModelError> {
        deployment.record(Bookkeeping::AgreementRecorded {
            user: user_id(1),
            record,
        })
    }

    #[test]
    fn a_recorded_agreement_keeps_the_generation_and_a_newer_revision_replaces_it() {
        let deployment = build(two_node_parts()).unwrap();
        let generation = deployment.config_generation();
        assert_eq!(deployment.users()[&user_id(1)].agreement, None);
        let agreed = agree(deployment, agreement(1, "2026-10-18")).unwrap();
        assert_eq!(agreed.config_generation(), generation);
        assert_eq!(
            agreed.users()[&user_id(1)].agreement,
            Some(agreement(1, "2026-10-18"))
        );
        assert_eq!(agreed.users()[&user_id(2)].agreement, None);
        let newer = agree(agreed, agreement(2, "2026-11-02")).unwrap();
        assert_eq!(
            newer.users()[&user_id(1)].agreement,
            Some(agreement(2, "2026-11-02"))
        );
        assert_eq!(newer.config_generation(), generation);
    }

    /// The same revision recorded again keeps the first record's day: the
    /// record says when the user first accepted that text.
    #[test]
    fn the_same_agreement_revision_keeps_the_record_as_it_is() {
        let agreed = agree(build(two_node_parts()).unwrap(), agreement(1, "2026-10-18")).unwrap();
        let again = agree(agreed.clone(), agreement(1, "2026-12-01")).unwrap();
        assert_eq!(again, agreed);
    }

    #[test]
    fn an_older_agreement_revision_is_refused() {
        let agreed = agree(build(two_node_parts()).unwrap(), agreement(2, "2026-11-02")).unwrap();
        assert_eq!(
            agree(agreed, agreement(1, "2026-11-03")),
            Err(ModelError::AgreementRegressed {
                user: user_id(1),
                recorded: AgreementVersion::new(NonZeroU16::new(2).unwrap()),
                offered: AgreementVersion::CURRENT,
            })
        );
    }

    /// A suspended user may record an agreement (it changes no export until
    /// the user is resumed); a revoking or revoked user may not, and an
    /// unknown user is refused.
    #[test]
    fn only_active_and_suspended_users_record_an_agreement() {
        let mut suspended = two_node_parts();
        suspended.users[0]
            .suspend(SuspendReason::Operator, crate::time::UnixTime::from_secs(0))
            .unwrap();
        let recorded = agree(build(suspended).unwrap(), agreement(1, "2026-10-18")).unwrap();
        assert_eq!(
            recorded.users()[&user_id(1)].agreement,
            Some(agreement(1, "2026-10-18"))
        );
        let mut revoking = two_node_parts();
        revoking.users[0].status = UserStatus::RevokePending;
        let mut revoked = two_node_parts();
        revoked.users[0].status = UserStatus::Revoked;
        revoked.users[0].per_node.clear();
        for parts in [revoking, revoked] {
            assert_eq!(
                agree(build(parts).unwrap(), agreement(1, "2026-10-18")),
                Err(ModelError::RevocationAlreadyStarted { user: user_id(1) })
            );
        }
        assert_eq!(
            build(two_node_parts())
                .unwrap()
                .record(Bookkeeping::AgreementRecorded {
                    user: user_id(9),
                    record: agreement(1, "2026-10-18"),
                }),
            Err(ModelError::UnknownUser { id: user_id(9) })
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
                .all(|secret_ref| secret_ref.node().map(NodeId::as_str) == Some("ams1"))
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
                .all(|r| r.node().map(NodeId::as_str) == Some("ams1"))
        );
    }

    fn suspended(reason: SuspendReason) -> UserStatus {
        UserStatus::Suspended {
            reason,
            since: crate::time::UnixTime::from_secs(1_791_417_600),
        }
    }

    /// A suspended user is served nowhere but keeps its credentials, so
    /// every one of its secrets stays referenced.
    #[test]
    fn suspended_users_are_not_served_and_keep_their_secrets() {
        let active = build(two_node_parts()).unwrap();
        let mut parts = two_node_parts();
        parts.users[0].status = suspended(SuspendReason::Operator);
        let deployment = build(parts).unwrap();
        for node in ["lon1", "ams1"] {
            let served: Vec<UserId> = deployment
                .served_users(&node_id(node))
                .map(|(user, _)| user.id.clone())
                .collect();
            assert_eq!(served, vec![user_id(2)], "{node}");
        }
        assert_eq!(deployment.required_secrets(), active.required_secrets());
        assert!(
            deployment
                .required_secrets()
                .contains(&SecretRef::UserVlessUuid(user_id(1), node_id("lon1")))
        );
    }

    /// Only active users count against the cap.
    #[test]
    fn the_active_user_cap_counts_active_users_only() {
        let cap = |max: u16| CapacityPolicy {
            max_active_users: Some(NonZeroU16::new(max).unwrap()),
        };
        let mut parts = two_node_parts();
        parts.capacity = cap(2);
        assert!(build(parts.clone()).is_ok());
        parts.capacity = cap(1);
        assert_eq!(
            build(parts.clone()),
            Err(ModelError::TooManyActiveUsers {
                max: NonZeroU16::new(1).unwrap(),
                active: 2
            })
        );
        for status in [
            suspended(SuspendReason::QuotaExceeded {
                cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
            }),
            suspended(SuspendReason::Expired),
            suspended(SuspendReason::AbuseReview),
            UserStatus::RevokePending,
        ] {
            let mut capped = parts.clone();
            capped.users[1].status = status;
            assert!(build(capped).is_ok(), "{status:?}");
        }
        let mut revoked = parts.clone();
        revoked.users[1].status = UserStatus::Revoked;
        revoked.users[1].per_node.clear();
        assert!(build(revoked).is_ok());
        // Resuming past the cap is refused when the deployment is rebuilt.
        let mut over = parts;
        over.users[1].status = suspended(SuspendReason::Operator);
        let at_cap = build(over).unwrap();
        let mut resumed = at_cap.into_parts();
        resumed.users[1].resume().unwrap();
        assert_eq!(
            build(resumed),
            Err(ModelError::TooManyActiveUsers {
                max: NonZeroU16::new(1).unwrap(),
                active: 2
            })
        );
        // A fresh deployment records the cap it is given, and the key is
        // required.
        let fresh = Deployment::new(DeploymentInit {
            capacity: CapacityPolicy::UNLIMITED,
            ..pilot_init()
        })
        .unwrap();
        assert_eq!(fresh.capacity(), CapacityPolicy::UNLIMITED);
        let json = serde_json::to_string(&fresh).unwrap();
        assert!(
            json.contains(r#""capacity":{"max_active_users":null}"#),
            "{json}"
        );
        let missing = json.replace(r#""capacity":{"max_active_users":null},"#, "");
        assert!(serde_json::from_str::<Deployment>(&missing).is_err());
        let missing_cap = json.replace(r#""max_active_users":null"#, "");
        assert!(missing_cap.contains(r#""capacity":{}"#));
        assert!(serde_json::from_str::<Deployment>(&missing_cap).is_err());
        let zero = json.replace(r#""max_active_users":null"#, r#""max_active_users":0"#);
        assert!(serde_json::from_str::<Deployment>(&zero).is_err());
    }

    #[test]
    fn public_aliases_are_unique() {
        let alias = PublicAlias::parse("k7qd-m2xa").unwrap();
        let mut parts = two_node_parts();
        parts.users[0].alias = Some(alias.clone());
        assert!(build(parts.clone()).is_ok());
        parts.users[1].alias = Some(PublicAlias::parse("k7qd-m2xb").unwrap());
        assert!(build(parts.clone()).is_ok());
        parts.users[1].alias = Some(alias.clone());
        assert_eq!(build(parts), Err(ModelError::DuplicateAlias { alias }));
    }

    /// Suspension is not revocation: no bookkeeping commits it, and a
    /// suspended user can be revoked and committed like an active one.
    #[test]
    fn a_suspended_user_can_be_revoked() {
        let mut parts = two_node_parts();
        parts.users[0].status = suspended(SuspendReason::AbuseReview);
        let deployment = build(parts.clone()).unwrap();
        assert_eq!(
            deployment.clone().record(Bookkeeping::RevocationCommitted {
                user: user_id(1),
                node: node_id("lon1"),
            }),
            Err(ModelError::NotRevoking { user: user_id(1) })
        );
        parts.users[0].revoke().unwrap();
        let revoking = build(parts).unwrap();
        let revoked = ["lon1", "ams1"]
            .into_iter()
            .fold(revoking, |deployment, node| {
                deployment
                    .record(Bookkeeping::RevocationCommitted {
                        user: user_id(1),
                        node: node_id(node),
                    })
                    .unwrap()
            });
        assert_eq!(revoked.users()[&user_id(1)].status, UserStatus::Revoked);
        assert_eq!(revoked.config_generation(), deployment.config_generation());
    }

    /// Retiring the only node a suspended user holds credentials on leaves
    /// it suspended with none, which is valid.
    #[test]
    fn a_retirement_drops_a_suspended_users_credentials() {
        let mut parts = two_node_parts();
        parts.nodes[0].lifecycle = NodeLifecycle::Retiring {
            site: site([45, 67, 89, 10]),
        };
        parts.users[0].per_node.remove(&node_id("ams1"));
        parts.users[0].status = suspended(SuspendReason::Operator);
        let retired = build(parts)
            .unwrap()
            .record(Bookkeeping::RetirementShutDown {
                node: node_id("lon1"),
            })
            .unwrap();
        let user = &retired.users()[&user_id(1)];
        assert!(user.per_node.is_empty());
        assert_eq!(user.status, suspended(SuspendReason::Operator));
    }
}
