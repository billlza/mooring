// SPDX-License-Identifier: GPL-3.0-or-later

//! The frozen version-2 state schema (design §7), and its lift to the
//! current version.
//!
//! Version 2 is read, never written, since version 3 (2026-11-11, M5) gave
//! a revoked user the time it was revoked ([`UserStatus::Revoked`]'s
//! `since`), from which its records are removed 13 months later (§15.7),
//! and the deployment the bare ids of removed users that a node's records
//! may still name ([`Deployment::forgotten`]). Everything else version 2
//! holds is the current version's, so these types freeze only what
//! differs: a user's status, and with it the user and the deployment's
//! fields. A version-2 `state.json` decodes into them, is checked with
//! every version-2 rule (the current rules over its lift, which add none),
//! and re-encodes byte for byte, which the version-2 goldens pin.
//!
//! The lift ([`StateV2::lift`]) sets a revoked user's `since` to the lift's
//! time, which the caller gives: it can only delay the user's removal, and
//! no real user is revoked before the pilot. It keeps no forgotten id:
//! version 2 removed no user that a node could still name. Every other
//! field is kept as it is.

use std::collections::BTreeMap;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::alerting::AlertSettings;
use crate::counters::ConfigGeneration;
use crate::deployment::{CapacityPolicy, Deployment, DeploymentParts};
use crate::error::ModelError;
use crate::exit::{ExitSite, TrafficPolicy};
use crate::ids::{LocalLabel, NodeId, PublicAlias, UserId};
use crate::node::Node;
use crate::quota::AutoQuotaPolicy;
use crate::state::{RuntimeIntent, StateV3};
use crate::time::UnixTime;
use crate::user::{
    AgreementRecord, ClientProfile, SuspendReason, User, UserNodePublic, UserPolicy, UserStatus,
};
use crate::viewer::Viewer;
use crate::wg::WgIndex;

/// The revocation time a version-1 or version-2 shape is checked with
/// before it is lifted. No invariant reads a revocation's time, so any time
/// checks the same rules; the lift then sets the real one.
pub(crate) const CHECKED_WITH: UnixTime = UnixTime::from_secs(0);

/// A version-2 user's lifecycle state: [`UserStatus`] whose `Revoked`
/// carried no time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UserStatusV2 {
    /// The user is served.
    Active,
    /// Served nowhere, holding its credentials.
    Suspended {
        /// Why.
        reason: SuspendReason,
        /// When the user was suspended.
        since: UnixTime,
    },
    /// Being revoked on the nodes in `per_node`.
    RevokePending,
    /// Revoked on every node.
    Revoked,
}

impl UserStatusV2 {
    /// The current status, a revoked user's revoked since `revoked_since`.
    #[must_use]
    pub const fn lift(self, revoked_since: UnixTime) -> UserStatus {
        match self {
            Self::Active => UserStatus::Active,
            Self::Suspended { reason, since } => UserStatus::Suspended { reason, since },
            Self::RevokePending => UserStatus::RevokePending,
            Self::Revoked => UserStatus::Revoked {
                since: revoked_since,
            },
        }
    }
}

/// A version-2 user: [`User`] with [`UserStatusV2`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserV2 {
    /// The opaque id.
    pub id: UserId,
    /// The Mac-only label.
    pub label: LocalLabel,
    /// The user's client.
    pub client: ClientProfile,
    /// Lifecycle state.
    pub status: UserStatusV2,
    /// The nodes the user holds credentials on.
    pub per_node: BTreeMap<NodeId, UserNodePublic>,
    /// Expiry and quota.
    pub policy: UserPolicy,
    /// The public alias. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub alias: Option<PublicAlias>,
    /// The agreement revision accepted. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub agreement: Option<AgreementRecord>,
}

impl UserV2 {
    /// The current user, revoked since `revoked_since` if it is revoked.
    #[must_use]
    pub fn lift(self, revoked_since: UnixTime) -> User {
        User {
            id: self.id,
            label: self.label,
            client: self.client,
            status: self.status.lift(revoked_since),
            per_node: self.per_node,
            policy: self.policy,
            alias: self.alias,
            agreement: self.agreement,
        }
    }
}

/// A version-2 deployment's fields, as serialised: [`DeploymentParts`]
/// with [`UserV2`] and no forgotten ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentV2Parts {
    /// The configuration generation.
    pub config_generation: ConfigGeneration,
    /// The Mac exit site.
    pub exit: ExitSite,
    /// Destination policy.
    pub policy: TrafficPolicy,
    /// Admission control.
    pub capacity: CapacityPolicy,
    /// Automatic per-user quotas. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub auto_quota: Option<AutoQuotaPolicy>,
    /// The alert channels. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub alerting: Option<AlertSettings>,
    /// Every remote viewer.
    pub viewers: Vec<Viewer>,
    /// Every node, including retired ones.
    pub nodes: Vec<Node>,
    /// Every user, including revoked ones.
    pub users: Vec<UserV2>,
    /// The next WireGuard index to allocate.
    pub next_wg_index: WgIndex,
}

impl DeploymentV2Parts {
    /// The current deployment, every revoked user revoked since
    /// `revoked_since`, with no forgotten id; every invariant checked.
    fn lift(self, revoked_since: UnixTime) -> Result<Deployment, ModelError> {
        Deployment::try_from(DeploymentParts {
            config_generation: self.config_generation,
            exit: self.exit,
            policy: self.policy,
            capacity: self.capacity,
            auto_quota: self.auto_quota,
            alerting: self.alerting,
            viewers: self.viewers,
            nodes: self.nodes,
            users: self
                .users
                .into_iter()
                .map(|user| user.lift(revoked_since))
                .collect(),
            forgotten: Vec::new(),
            next_wg_index: self.next_wg_index,
        })
    }
}

/// A version-2 deployment that satisfies every version-2 invariant: those
/// of its lift, since version 3 adds none a lifted document can break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DeploymentV2Parts", into = "DeploymentV2Parts")]
pub struct DeploymentV2(DeploymentV2Parts);

impl DeploymentV2 {
    /// The deployment's fields.
    #[must_use]
    pub const fn parts(&self) -> &DeploymentV2Parts {
        &self.0
    }
}

impl TryFrom<DeploymentV2Parts> for DeploymentV2 {
    type Error = ModelError;

    fn try_from(parts: DeploymentV2Parts) -> Result<Self, Self::Error> {
        parts.clone().lift(CHECKED_WITH)?;
        Ok(Self(parts))
    }
}

impl From<DeploymentV2> for DeploymentV2Parts {
    fn from(deployment: DeploymentV2) -> Self {
        deployment.0
    }
}

/// Version 2 of the state document, serialised as
/// `{"version": 2, "deployment": …, "runtime": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "StateV2Repr")]
pub struct StateV2 {
    /// Every node and user.
    pub deployment: DeploymentV2,
    /// Mac-only runtime intent.
    pub runtime: RuntimeIntent,
}

impl StateV2 {
    /// The schema version this type reads.
    pub const VERSION: u32 = 2;

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

    /// The current state: every field as version 2 holds it, a revoked
    /// user revoked since `revoked_since` (the lift's time), and no
    /// forgotten id.
    pub fn lift(self, revoked_since: UnixTime) -> Result<StateV3, ModelError> {
        Ok(StateV3 {
            deployment: self.deployment.0.lift(revoked_since)?,
            runtime: self.runtime,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV2Repr {
    version: u32,
    deployment: DeploymentV2,
    runtime: RuntimeIntent,
}

impl TryFrom<StateV2Repr> for StateV2 {
    type Error = ModelError;

    fn try_from(repr: StateV2Repr) -> Result<Self, Self::Error> {
        Self::require_version(repr.version)?;
        Ok(Self {
            deployment: repr.deployment,
            runtime: repr.runtime,
        })
    }
}

/// Writes exactly the version-2 encoding, so the version-2 goldens pin it
/// by round trip; the store never writes version 2.
impl Serialize for StateV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StateV2", 3)?;
        state.serialize_field("version", &Self::VERSION)?;
        state.serialize_field("deployment", &self.deployment)?;
        state.serialize_field("runtime", &self.runtime)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{two_node_parts, user_id};

    /// The version-2 form of `two_node_parts`, user 2 revoked.
    fn v2_parts() -> DeploymentV2Parts {
        let parts = two_node_parts();
        DeploymentV2Parts {
            config_generation: parts.config_generation,
            exit: parts.exit,
            policy: parts.policy,
            capacity: parts.capacity,
            auto_quota: parts.auto_quota,
            alerting: parts.alerting,
            viewers: parts.viewers,
            nodes: parts.nodes,
            users: parts
                .users
                .into_iter()
                .map(|user| {
                    let revoked = user.id == user_id(2);
                    UserV2 {
                        per_node: if revoked {
                            BTreeMap::new()
                        } else {
                            user.per_node
                        },
                        id: user.id,
                        label: user.label,
                        client: user.client,
                        status: if revoked {
                            UserStatusV2::Revoked
                        } else {
                            UserStatusV2::Active
                        },
                        policy: user.policy,
                        alias: user.alias,
                        agreement: user.agreement,
                    }
                })
                .collect(),
            next_wg_index: parts.next_wg_index,
        }
    }

    fn state() -> StateV2 {
        StateV2 {
            deployment: DeploymentV2::try_from(v2_parts()).unwrap(),
            runtime: RuntimeIntent::new(),
        }
    }

    /// Version 2 round-trips in its own encoding, a revoked user with no
    /// time and no forgotten ids; the current version's forms of either
    /// are refused.
    #[test]
    fn version_two_round_trips_with_its_own_encoding() {
        let state = state();
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.starts_with(r#"{"version":2,"deployment":{"config_generation":1,"#));
        assert!(
            json.contains(r#""status":"revoked","per_node":{}"#),
            "{json}"
        );
        assert!(!json.contains("forgotten"));
        assert_eq!(serde_json::from_str::<StateV2>(&json).unwrap(), state);
        for refused in [
            json.replacen(
                r#""status":"revoked""#,
                r#""status":{"revoked":{"since":1}}"#,
                1,
            ),
            json.replacen(r#""users":["#, r#""forgotten":[],"users":["#, 1),
            json.replacen(r#""version":2"#, r#""version":3"#, 1),
        ] {
            assert_ne!(refused, json);
            assert!(
                serde_json::from_str::<StateV2>(&refused).is_err(),
                "{refused}"
            );
        }
    }

    /// The lift keeps every field and gives a revoked user the lift's
    /// time; any other status is as it was.
    #[test]
    fn the_lift_dates_a_revocation_at_the_lift() {
        let at = UnixTime::from_secs(1_794_441_600);
        let lifted = state().lift(at).unwrap();
        let parts = two_node_parts();
        assert_eq!(
            lifted.deployment.users()[&user_id(2)].status,
            UserStatus::Revoked { since: at }
        );
        assert_eq!(
            lifted.deployment.users()[&user_id(1)].status,
            UserStatus::Active
        );
        assert!(lifted.deployment.forgotten().is_empty());
        assert_eq!(lifted.deployment.exit(), &parts.exit);
        assert_eq!(lifted.deployment.nodes().len(), parts.nodes.len());
        assert_eq!(lifted.runtime, RuntimeIntent::new());
        for (status, lifted) in [
            (UserStatusV2::Active, UserStatus::Active),
            (UserStatusV2::RevokePending, UserStatus::RevokePending),
            (UserStatusV2::Revoked, UserStatus::Revoked { since: at }),
            (
                UserStatusV2::Suspended {
                    reason: SuspendReason::AbuseReview,
                    since: CHECKED_WITH,
                },
                UserStatus::Suspended {
                    reason: SuspendReason::AbuseReview,
                    since: CHECKED_WITH,
                },
            ),
        ] {
            assert_eq!(status.lift(at), lifted);
        }
    }

    /// A version-2 document that breaks a version-2 rule is a decode error,
    /// as its decoding then was: here a revoked user holding credentials.
    #[test]
    fn a_version_two_document_is_checked_with_the_version_two_rules() {
        let mut parts = v2_parts();
        parts.users[1].per_node = two_node_parts().users[1].per_node.clone();
        assert_eq!(
            DeploymentV2::try_from(parts),
            Err(ModelError::RevokedUserHoldsCredentials { user: user_id(2) })
        );
        assert_eq!(StateV2::require_version(2), Ok(()));
        assert_eq!(
            StateV2::require_version(3),
            Err(ModelError::StateVersionMismatch {
                expected: 2,
                found: 3
            })
        );
    }
}
