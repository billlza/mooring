// SPDX-License-Identifier: GPL-3.0-or-later

//! The frozen version-1 state schema (design §7), and its lift to the
//! current version.
//!
//! Version 1 is read, never written. A version-1 `state.json` decodes into
//! these types, which check the version-1 invariants exactly as version 1
//! did, so a corrupt document is still a decode error. The store's
//! migration chain then lifts it with the conversions at the end of this
//! module, which the version-1 goldens pin. Only a decode bug may change
//! these types.
//!
//! The lift adds what version 1 could not say, without inventing anything:
//!
//! - the SIM cycle day becomes the same bill day, and the hard stop becomes
//!   [`StopPolicy::HardStop`] at the same byte count;
//! - the line's plan is unrecorded (`plan: None`): version 1 kept no plan
//!   record, and the operator records it explicitly;
//! - every explicit version-1 hard stop is kept, at any value, and only a
//!   missing one is refused (`StopPolicyUnchosen`): running past a line is
//!   now the explicit [`StopPolicy::AcceptDeprioritisation`], which needs a
//!   recorded plan with a fair-use line, and version 1's `null` was chosen
//!   before the plan was known, so it cannot stand for that choice
//!   (critique C-10). With the plan unrecorded there is no line to check a
//!   stop against;
//! - users get no expiry, quota, alias or agreement record; the deployment
//!   gets no cap on active users, no automatic quotas, no alert channels
//!   and no viewers; the uplink has no baseline.
//!
//! The version-1 format was never released (design §22, "Format note"), so
//! no version-1 document exists outside the goldens, and Mooring ships no
//! tool to repair one that does not lift. A refused lift leaves the file as
//! it was (`MigrationFailed`).
//!
//! A version-1 deployment is checked with the version-1 cross-entity rules
//! only (`Entities::check_version_1`); the rules later versions add are
//! checked by the lift, so a document that breaks one fails its migration
//! rather than its decoding.

use std::collections::BTreeMap;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::counters::ConfigGeneration;
use crate::deployment::{CapacityPolicy, Deployment, DeploymentParts, Entities, index_by_id};
use crate::error::{EntityId, ModelError};
use crate::exit::{EgressCheck, ExitSite, FlowCap, ProbePolicy, TrafficPolicy, Uplink};
use crate::ids::{LocalLabel, NodeId, UserId};
use crate::iface::InterfaceSelector;
use crate::node::Node;
use crate::sim::{BillDay, CycleRule, SimPolicy, StopPolicy};
use crate::state::{RuntimeIntent, StateV2};
use crate::user::{ClientProfile, User, UserNodePublic, UserPolicy, UserStatus};
use crate::wg::WgIndex;

/// The version-1 SIM billing cycle start day, 1..=28 so that it exists in
/// every month.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct CycleDay(u8);

impl CycleDay {
    /// Accepts 1..=28.
    pub fn new(day: u8) -> Result<Self, ModelError> {
        if (1..=28).contains(&day) {
            Ok(Self(day))
        } else {
            Err(ModelError::InvalidCycleDay { day })
        }
    }

    /// The day of the month.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for CycleDay {
    type Error = ModelError;

    fn try_from(day: u8) -> Result<Self, Self::Error> {
        Self::new(day)
    }
}

impl From<CycleDay> for u8 {
    fn from(day: CycleDay) -> Self {
        day.0
    }
}

/// Version-1 SIM volume accounting.
///
/// Invariant: `warn_bytes > 0` and, with a hard stop, `warn_bytes < hard_stop_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SimPolicyV1Repr", into = "SimPolicyV1Repr")]
pub struct SimPolicyV1 {
    cycle_day: CycleDay,
    warn_bytes: u64,
    hard_stop_bytes: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimPolicyV1Repr {
    cycle_day: CycleDay,
    warn_bytes: u64,
    // Required even when null: a lost key must not silently disable the hard stop.
    #[serde(deserialize_with = "Option::deserialize")]
    hard_stop_bytes: Option<u64>,
}

impl SimPolicyV1 {
    /// Accepts positive thresholds with the warning below any hard stop.
    pub fn new(
        cycle_day: CycleDay,
        warn_bytes: u64,
        hard_stop_bytes: Option<u64>,
    ) -> Result<Self, ModelError> {
        let ordered = hard_stop_bytes.is_none_or(|stop| warn_bytes < stop);
        if warn_bytes == 0 || !ordered {
            return Err(ModelError::InvalidSimThresholds {
                warn_bytes,
                hard_stop_bytes,
            });
        }
        Ok(Self {
            cycle_day,
            warn_bytes,
            hard_stop_bytes,
        })
    }

    /// The billing cycle start day.
    #[must_use]
    pub const fn cycle_day(&self) -> CycleDay {
        self.cycle_day
    }

    /// The usage at which the operator is warned.
    #[must_use]
    pub const fn warn_bytes(&self) -> u64 {
        self.warn_bytes
    }

    /// The usage at which the exit stops until the cycle resets, if any.
    #[must_use]
    pub const fn hard_stop_bytes(&self) -> Option<u64> {
        self.hard_stop_bytes
    }
}

impl TryFrom<SimPolicyV1Repr> for SimPolicyV1 {
    type Error = ModelError;

    fn try_from(repr: SimPolicyV1Repr) -> Result<Self, Self::Error> {
        Self::new(repr.cycle_day, repr.warn_bytes, repr.hard_stop_bytes)
    }
}

impl From<SimPolicyV1> for SimPolicyV1Repr {
    fn from(policy: SimPolicyV1) -> Self {
        Self {
            cycle_day: policy.cycle_day,
            warn_bytes: policy.warn_bytes,
            hard_stop_bytes: policy.hard_stop_bytes,
        }
    }
}

/// The version-1 Mac side of the exit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitSiteV1 {
    /// The wired interface facing the M7.
    pub egress: InterfaceSelector,
    /// The tunnel uplink.
    pub uplink: Uplink,
    /// The carrier check.
    pub egress_check: EgressCheck,
    /// SIM accounting.
    pub sim: SimPolicyV1,
    /// Probe cadence and ports.
    pub probe: ProbePolicy,
    /// The node-wide new-flow cap.
    pub flow_cap: FlowCap,
}

/// A version-1 user's revocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatusV1 {
    /// The user is served.
    Active,
    /// Being revoked on the nodes in `per_node`.
    RevokePending,
    /// Revoked on every node.
    Revoked,
}

/// A version-1 user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserV1 {
    /// The opaque id.
    pub id: UserId,
    /// The Mac-only label.
    pub label: LocalLabel,
    /// The user's client.
    pub client: ClientProfile,
    /// Revocation state.
    pub status: UserStatusV1,
    /// The nodes the user holds credentials on.
    pub per_node: BTreeMap<NodeId, UserNodePublic>,
}

/// A version-1 deployment's fields, as serialised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentV1Parts {
    /// The configuration generation.
    pub config_generation: ConfigGeneration,
    /// The Mac exit site.
    pub exit: ExitSiteV1,
    /// Destination policy.
    pub policy: TrafficPolicy,
    /// Every node, including retired ones.
    pub nodes: Vec<Node>,
    /// Every user, including revoked ones.
    pub users: Vec<UserV1>,
    /// The next WireGuard index to allocate.
    pub next_wg_index: WgIndex,
}

/// A version-1 deployment that satisfies every version-1 invariant: the
/// version-1 cross-entity rules a current [`Deployment`] also runs, and no
/// others (version 1 had no aliases and no cap on active users).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DeploymentV1Parts", into = "DeploymentV1Parts")]
pub struct DeploymentV1(DeploymentV1Parts);

impl DeploymentV1 {
    /// The deployment's fields.
    #[must_use]
    pub const fn parts(&self) -> &DeploymentV1Parts {
        &self.0
    }

    /// The deployment's fields, for editing; rebuild with `DeploymentV1::try_from`.
    #[must_use]
    pub fn into_parts(self) -> DeploymentV1Parts {
        self.0
    }
}

impl TryFrom<DeploymentV1Parts> for DeploymentV1 {
    type Error = ModelError;

    fn try_from(parts: DeploymentV1Parts) -> Result<Self, Self::Error> {
        let nodes = index_by_id(parts.nodes.clone(), |node: &Node| &node.id, EntityId::Node)?;
        let users = index_by_id(
            parts.users.iter().cloned().map(User::from).collect(),
            |user: &User| &user.id,
            EntityId::User,
        )?;
        Entities {
            config_generation: parts.config_generation,
            nodes: &nodes,
            users: &users,
            next_wg_index: parts.next_wg_index,
            capacity: CapacityPolicy::UNLIMITED,
            alerting: None,
        }
        .check_version_1()?;
        Ok(Self(parts))
    }
}

impl From<DeploymentV1> for DeploymentV1Parts {
    fn from(deployment: DeploymentV1) -> Self {
        deployment.0
    }
}

/// Version 1 of the state document, serialised as
/// `{"version": 1, "deployment": …, "runtime": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "StateV1Repr")]
pub struct StateV1 {
    /// Every node and user.
    pub deployment: DeploymentV1,
    /// Mac-only runtime intent.
    pub runtime: RuntimeIntent,
}

impl StateV1 {
    /// The schema version this type reads.
    pub const VERSION: u32 = 1;

    /// Accepts only this type's version.
    pub(crate) fn require_version(found: u32) -> Result<(), ModelError> {
        if found == Self::VERSION {
            Ok(())
        } else {
            Err(ModelError::StateVersionMismatch {
                expected: Self::VERSION,
                found,
            })
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV1Repr {
    version: u32,
    deployment: DeploymentV1,
    runtime: RuntimeIntent,
}

impl TryFrom<StateV1Repr> for StateV1 {
    type Error = ModelError;

    fn try_from(repr: StateV1Repr) -> Result<Self, Self::Error> {
        Self::require_version(repr.version)?;
        Ok(Self {
            deployment: repr.deployment,
            runtime: repr.runtime,
        })
    }
}

/// Writes exactly the version-1 encoding, so the version-1 goldens pin it
/// by round trip; the store never writes version 1.
impl Serialize for StateV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StateV1", 3)?;
        state.serialize_field("version", &Self::VERSION)?;
        state.serialize_field("deployment", &self.deployment)?;
        state.serialize_field("runtime", &self.runtime)?;
        state.end()
    }
}

// The lift to version 2.

impl From<UserStatusV1> for UserStatus {
    fn from(status: UserStatusV1) -> Self {
        match status {
            UserStatusV1::Active => Self::Active,
            UserStatusV1::RevokePending => Self::RevokePending,
            UserStatusV1::Revoked => Self::Revoked,
        }
    }
}

impl From<UserV1> for User {
    fn from(user: UserV1) -> Self {
        Self {
            id: user.id,
            label: user.label,
            client: user.client,
            status: user.status.into(),
            per_node: user.per_node,
            policy: UserPolicy::NONE,
            alias: None,
            agreement: None,
        }
    }
}

/// The bill day is the cycle day (every 1..=28 day is a 1..=31 bill day
/// that exists in every month, so the clamp never applies to it) and the
/// hard stop stays, at any value; the plan is unrecorded. A policy without
/// a hard stop is refused (`StopPolicyUnchosen`): see the module
/// documentation.
impl TryFrom<SimPolicyV1> for SimPolicy {
    type Error = ModelError;

    fn try_from(policy: SimPolicyV1) -> Result<Self, Self::Error> {
        let bytes = policy
            .hard_stop_bytes
            .ok_or(ModelError::StopPolicyUnchosen)?;
        Self::unrecorded(
            CycleRule::Monthly {
                bill_day: BillDay::new(policy.cycle_day.get())?,
            },
            policy.warn_bytes,
            StopPolicy::HardStop { bytes },
        )
    }
}

impl TryFrom<ExitSiteV1> for ExitSite {
    type Error = ModelError;

    fn try_from(site: ExitSiteV1) -> Result<Self, Self::Error> {
        Ok(Self {
            egress: site.egress,
            uplink: site.uplink,
            egress_check: site.egress_check,
            sim: site.sim.try_into()?,
            probe: site.probe,
            flow_cap: site.flow_cap,
            uplink_baseline: None,
        })
    }
}

impl TryFrom<DeploymentV1> for Deployment {
    type Error = ModelError;

    fn try_from(deployment: DeploymentV1) -> Result<Self, Self::Error> {
        let parts = deployment.0;
        Self::try_from(DeploymentParts {
            config_generation: parts.config_generation,
            exit: parts.exit.try_into()?,
            policy: parts.policy,
            capacity: CapacityPolicy::UNLIMITED,
            auto_quota: None,
            alerting: None,
            viewers: Vec::new(),
            nodes: parts.nodes,
            users: parts.users.into_iter().map(User::from).collect(),
            next_wg_index: parts.next_wg_index,
        })
    }
}

impl TryFrom<StateV1> for StateV2 {
    type Error = ModelError;

    fn try_from(state: StateV1) -> Result<Self, Self::Error> {
        Ok(Self {
            deployment: state.deployment.try_into()?,
            runtime: state.runtime,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::testing::{TEST_FAIR_USE_BYTES, exit_site, two_node_parts};
    use proptest::prelude::*;

    /// The warning threshold of the version-1 goldens, 450e9 bytes.
    const V1_GOLDEN_WARN_BYTES: u64 = 450_000_000_000;
    /// The hard stop of the version-1 goldens, 560e9 bytes.
    const V1_GOLDEN_HARD_STOP_BYTES: u64 = 560_000_000_000;

    /// The version-1 form of `two_node_parts`, with the version-1 goldens'
    /// SIM policy on cycle day 1.
    fn v1_parts() -> DeploymentV1Parts {
        let parts = two_node_parts();
        let site = parts.exit;
        DeploymentV1Parts {
            config_generation: parts.config_generation,
            exit: ExitSiteV1 {
                egress: site.egress,
                uplink: site.uplink,
                egress_check: site.egress_check,
                sim: SimPolicyV1::new(
                    CycleDay::new(1).unwrap(),
                    V1_GOLDEN_WARN_BYTES,
                    Some(V1_GOLDEN_HARD_STOP_BYTES),
                )
                .unwrap(),
                probe: site.probe,
                flow_cap: site.flow_cap,
            },
            policy: parts.policy,
            nodes: parts.nodes,
            users: parts
                .users
                .into_iter()
                .map(|user| UserV1 {
                    id: user.id,
                    label: user.label,
                    client: user.client,
                    status: UserStatusV1::Active,
                    per_node: user.per_node,
                })
                .collect(),
            next_wg_index: parts.next_wg_index,
        }
    }

    fn v1_state() -> StateV1 {
        StateV1 {
            deployment: DeploymentV1::try_from(v1_parts()).unwrap(),
            runtime: RuntimeIntent::new(),
        }
    }

    #[test]
    fn version_one_round_trips_with_its_own_encoding() {
        let state = v1_state();
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.starts_with(r#"{"version":1,"deployment":{"config_generation":1,"#));
        assert!(json.contains(
            r#""sim":{"cycle_day":1,"warn_bytes":450000000000,"hard_stop_bytes":560000000000}"#
        ));
        assert!(json.contains(r#""status":"active","per_node":"#));
        assert_eq!(serde_json::from_str::<StateV1>(&json).unwrap(), state);
        // Version 2 fields are unknown to version 1.
        for extra in [
            json.replacen(
                r#""flow_cap":4096"#,
                r#""flow_cap":4096,"uplink_baseline":null"#,
                1,
            ),
            json.replacen(
                r#""policy":{"#,
                r#""capacity":{"max_active_users":null},"policy":{"#,
                1,
            ),
            json.replacen(
                r#""status":"active""#,
                r#""status":"active","alias":null"#,
                1,
            ),
            json.replacen(r#""cycle_day":1"#, r#""bill_day":1"#, 1),
        ] {
            assert!(serde_json::from_str::<StateV1>(&extra).is_err(), "{extra}");
        }
        let suspended = json.replacen(
            r#""status":"active""#,
            r#""status":{"suspended":{"reason":"operator","since":1}}"#,
            1,
        );
        assert!(serde_json::from_str::<StateV1>(&suspended).is_err());
    }

    #[test]
    fn version_one_keeps_its_invariants_and_version() {
        let json = serde_json::to_string(&v1_state()).unwrap();
        for found in [0, 2] {
            let other = json.replacen("\"version\":1", &format!("\"version\":{found}"), 1);
            let error = serde_json::from_str::<StateV1>(&other)
                .unwrap_err()
                .to_string();
            let expected = ModelError::StateVersionMismatch { expected: 1, found }.to_string();
            assert!(error.contains(&expected), "{error}");
        }
        let missing = json.replacen(r#","hard_stop_bytes":560000000000"#, "", 1);
        assert!(serde_json::from_str::<StateV1>(&missing).is_err());
        for bad in [0, 29] {
            assert_eq!(
                CycleDay::new(bad),
                Err(ModelError::InvalidCycleDay { day: bad })
            );
        }
        // The cross-entity invariants are those of version 1.
        let mut parts = v1_parts();
        parts.users.push(parts.users[0].clone());
        assert_eq!(
            DeploymentV1::try_from(parts),
            Err(ModelError::DuplicateId {
                id: EntityId::User(parts_user_id(0))
            })
        );
        let mut parts = v1_parts();
        parts.users[0].status = UserStatusV1::Revoked;
        assert_eq!(
            DeploymentV1::try_from(parts),
            Err(ModelError::RevokedUserHoldsCredentials {
                user: parts_user_id(0)
            })
        );
        let mut parts = v1_parts();
        parts.users[0].per_node.clear();
        parts.users[0].status = UserStatusV1::RevokePending;
        assert_eq!(
            DeploymentV1::try_from(parts),
            Err(ModelError::RevokePendingWithoutCredentials {
                user: parts_user_id(0)
            })
        );
    }

    fn parts_user_id(index: usize) -> UserId {
        v1_parts().users[index].id.clone()
    }

    #[test]
    fn the_lift_keeps_every_version_one_value() {
        let mut parts = v1_parts();
        parts.users[1].status = UserStatusV1::RevokePending;
        let source = DeploymentV1::try_from(parts.clone()).unwrap();
        let lifted = StateV2::try_from(StateV1 {
            deployment: source.clone(),
            runtime: RuntimeIntent::new(),
        })
        .unwrap();
        let deployment = &lifted.deployment;
        assert_eq!(deployment.config_generation(), parts.config_generation);
        assert_eq!(deployment.policy(), &parts.policy);
        assert_eq!(deployment.capacity(), CapacityPolicy::UNLIMITED);
        assert_eq!(deployment.auto_quota(), None);
        assert_eq!(deployment.alerting(), None);
        assert!(deployment.viewers().is_empty());
        assert_eq!(deployment.next_wg_index(), parts.next_wg_index);
        let nodes: Vec<&Node> = deployment.nodes().values().collect();
        let mut expected_nodes = parts.nodes.clone();
        expected_nodes.sort_by(|left, right| left.id.cmp(&right.id));
        assert_eq!(nodes, expected_nodes.iter().collect::<Vec<_>>());
        let exit = deployment.exit();
        assert_eq!(exit.egress, parts.exit.egress);
        assert_eq!(exit.uplink, parts.exit.uplink);
        assert_eq!(exit.egress_check, parts.exit.egress_check);
        assert_eq!(exit.probe, parts.exit.probe);
        assert_eq!(exit.flow_cap, parts.exit.flow_cap);
        assert_eq!(exit.uplink_baseline, None);
        assert_eq!(
            exit.sim.cycle(),
            CycleRule::Monthly {
                bill_day: BillDay::new(1).unwrap()
            }
        );
        assert_eq!(exit.sim.plan(), None);
        assert_eq!(exit.sim.warn_bytes(), V1_GOLDEN_WARN_BYTES);
        assert_eq!(
            exit.sim.stop(),
            StopPolicy::HardStop {
                bytes: V1_GOLDEN_HARD_STOP_BYTES
            }
        );
        assert_eq!(
            deployment.users().keys().cloned().collect::<BTreeSet<_>>(),
            source
                .parts()
                .users
                .iter()
                .map(|user| user.id.clone())
                .collect::<BTreeSet<_>>()
        );
        for old in &parts.users {
            let user = &deployment.users()[&old.id];
            assert_eq!(user.label, old.label);
            assert_eq!(user.client, old.client);
            assert_eq!(user.per_node, old.per_node);
            assert_eq!(user.status, UserStatus::from(old.status));
            assert_eq!(user.policy, UserPolicy::NONE);
            assert_eq!((user.alias.as_ref(), user.agreement.as_ref()), (None, None));
        }
        assert_eq!(
            UserStatus::from(UserStatusV1::RevokePending),
            UserStatus::RevokePending
        );
        assert_eq!(UserStatus::from(UserStatusV1::Revoked), UserStatus::Revoked);
        assert_eq!(lifted.runtime, RuntimeIntent::new());
        // The lifted deployment equals the same deployment built in version 2.
        let mut v2 = two_node_parts();
        v2.exit = exit_site();
        v2.exit.sim = SimPolicy::unrecorded(
            CycleRule::Monthly {
                bill_day: BillDay::new(1).unwrap(),
            },
            V1_GOLDEN_WARN_BYTES,
            StopPolicy::HardStop {
                bytes: V1_GOLDEN_HARD_STOP_BYTES,
            },
        )
        .unwrap();
        v2.users[1].status = UserStatus::RevokePending;
        assert_eq!(lifted.deployment, Deployment::try_from(v2).unwrap());
    }

    /// Version 1's `hard_stop_bytes: null` was chosen before the plan's line
    /// was recorded, so it cannot stand for the explicit choice to accept
    /// deprioritisation: the lift refuses it and the operator chooses.
    #[test]
    fn a_policy_without_a_hard_stop_does_not_lift() {
        let no_stop = SimPolicyV1::new(CycleDay::new(15).unwrap(), 1_000_000, None).unwrap();
        assert_eq!(
            SimPolicy::try_from(no_stop),
            Err(ModelError::StopPolicyUnchosen)
        );
        let mut parts = v1_parts();
        parts.exit.sim = no_stop;
        let deployment = DeploymentV1::try_from(parts).unwrap();
        assert_eq!(
            StateV2::try_from(StateV1 {
                deployment,
                runtime: RuntimeIntent::new(),
            }),
            Err(ModelError::StopPolicyUnchosen)
        );
        let with_stop =
            SimPolicyV1::new(CycleDay::new(15).unwrap(), 1_000_000, Some(2_000_000)).unwrap();
        let lifted = SimPolicy::try_from(with_stop).unwrap();
        assert_eq!(
            lifted.cycle(),
            CycleRule::Monthly {
                bill_day: BillDay::new(15).unwrap()
            }
        );
        assert_eq!(lifted.stop(), StopPolicy::HardStop { bytes: 2_000_000 });
    }

    /// Every explicit version-1 hard stop lifts as it is, at any value: the
    /// plan is unrecorded, so there is no line to check it against, and the
    /// operator records the plan afterwards.
    #[test]
    fn every_explicit_version_one_stop_lifts_unchanged() {
        for (warn, stop) in [
            (1, 2),
            (V1_GOLDEN_WARN_BYTES, V1_GOLDEN_HARD_STOP_BYTES),
            (1, TEST_FAIR_USE_BYTES.get()),
            (1, u64::MAX),
            (u64::MAX - 1, u64::MAX),
        ] {
            let v1 = SimPolicyV1::new(CycleDay::new(28).unwrap(), warn, Some(stop)).unwrap();
            let lifted = SimPolicy::try_from(v1).unwrap();
            assert_eq!(
                lifted.cycle(),
                CycleRule::Monthly {
                    bill_day: BillDay::new(28).unwrap()
                }
            );
            assert_eq!(lifted.plan(), None);
            assert_eq!(lifted.warn_bytes(), warn);
            assert_eq!(lifted.stop(), StopPolicy::HardStop { bytes: stop });
            assert_eq!(lifted.thresholds().budget_bytes(), stop);
            let mut parts = v1_parts();
            parts.exit.sim = v1;
            let deployment = DeploymentV1::try_from(parts).unwrap();
            let state = StateV2::try_from(StateV1 {
                deployment,
                runtime: RuntimeIntent::new(),
            })
            .unwrap();
            assert_eq!(state.deployment.exit().sim, lifted);
        }
    }

    proptest! {
        #[test]
        fn cycle_day_bounds(day in any::<u8>()) {
            prop_assert_eq!(CycleDay::new(day).is_ok(), (1..=28).contains(&day));
        }

        /// Every valid version-1 SIM policy with a hard stop lifts to the
        /// same days and thresholds, whatever the stop.
        #[test]
        fn every_hard_stop_lifts_unchanged(day in 1_u8..=28, warn in 1_u64..u64::MAX, gap in 1_u64..=u64::MAX) {
            // warn < u64::MAX, so the saturated stop still lies above it.
            let stop = warn.saturating_add(gap);
            let v1 = SimPolicyV1::new(CycleDay::new(day).unwrap(), warn, Some(stop)).unwrap();
            let lifted = SimPolicy::try_from(v1).unwrap();
            prop_assert_eq!(
                lifted.cycle(),
                CycleRule::Monthly {
                    bill_day: BillDay::new(day).unwrap()
                }
            );
            prop_assert_eq!(lifted.warn_bytes(), warn);
            prop_assert_eq!(lifted.stop(), StopPolicy::HardStop { bytes: stop });
            prop_assert_eq!(lifted.plan(), None);
        }
    }
}
