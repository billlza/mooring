// SPDX-License-Identifier: GPL-3.0-or-later

//! The frozen version-3 state schema (design §7), and its lift to the
//! current version.
//!
//! Version 3 is read, never written, since version 4 (2026-11-14) gave the
//! deployment its spare users ([`Deployment::spares`], design §13.6).
//! Everything else version 3 holds is the current version's, so these types
//! freeze only what differs: the deployment's fields. A version-3
//! `state.json` decodes into them, is checked with every version-3 rule
//! (the current rules over its lift, which add none a document without
//! spare users can break), and re-encodes byte for byte, which the
//! version-3 goldens pin.
//!
//! The lift ([`StateV3::lift`]) keeps every field and adds no spare user:
//! the nightly apply job draws them inside its window, where the restart
//! their first apply needs is expected.

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::alerting::AlertSettings;
use crate::counters::ConfigGeneration;
use crate::deployment::{CapacityPolicy, Deployment, DeploymentParts};
use crate::error::ModelError;
use crate::exit::{ExitSite, TrafficPolicy};
use crate::node::Node;
use crate::quota::AutoQuotaPolicy;
use crate::removal::ForgottenUser;
use crate::state::{RuntimeIntent, StateV4};
use crate::user::User;
use crate::viewer::Viewer;
use crate::wg::WgIndex;

/// A version-3 deployment's fields, as serialised: [`DeploymentParts`]
/// without spare users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentV3Parts {
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
    pub users: Vec<User>,
    /// The bare ids of removed users that a node's records may still name.
    pub forgotten: Vec<ForgottenUser>,
    /// The next WireGuard index to allocate.
    pub next_wg_index: WgIndex,
}

impl DeploymentV3Parts {
    /// The current deployment, with no spare user; every invariant checked.
    fn lift(self) -> Result<Deployment, ModelError> {
        Deployment::try_from(DeploymentParts {
            config_generation: self.config_generation,
            exit: self.exit,
            policy: self.policy,
            capacity: self.capacity,
            auto_quota: self.auto_quota,
            alerting: self.alerting,
            viewers: self.viewers,
            nodes: self.nodes,
            users: self.users,
            spares: Vec::new(),
            forgotten: self.forgotten,
            next_wg_index: self.next_wg_index,
        })
    }
}

/// A version-3 deployment that satisfies every version-3 invariant: those
/// of its lift, since version 4 adds none a document without spare users
/// can break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DeploymentV3Parts", into = "DeploymentV3Parts")]
pub struct DeploymentV3(DeploymentV3Parts);

impl TryFrom<DeploymentV3Parts> for DeploymentV3 {
    type Error = ModelError;

    fn try_from(parts: DeploymentV3Parts) -> Result<Self, Self::Error> {
        parts.clone().lift()?;
        Ok(Self(parts))
    }
}

impl From<DeploymentV3> for DeploymentV3Parts {
    fn from(deployment: DeploymentV3) -> Self {
        deployment.0
    }
}

/// Version 3 of the state document, serialised as
/// `{"version": 3, "deployment": …, "runtime": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "StateV3Repr")]
pub struct StateV3 {
    /// Every node and user.
    pub deployment: DeploymentV3,
    /// Mac-only runtime intent.
    pub runtime: RuntimeIntent,
}

impl StateV3 {
    /// The schema version this type reads.
    pub const VERSION: u32 = 3;

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

    /// The current state: every field as version 3 holds it, and no spare
    /// user.
    pub fn lift(self) -> Result<StateV4, ModelError> {
        Ok(StateV4 {
            deployment: self.deployment.0.lift()?,
            runtime: self.runtime,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV3Repr {
    version: u32,
    deployment: DeploymentV3,
    runtime: RuntimeIntent,
}

impl TryFrom<StateV3Repr> for StateV3 {
    type Error = ModelError;

    fn try_from(repr: StateV3Repr) -> Result<Self, Self::Error> {
        Self::require_version(repr.version)?;
        Ok(Self {
            deployment: repr.deployment,
            runtime: repr.runtime,
        })
    }
}

/// Writes exactly the version-3 encoding, so the version-3 goldens pin it
/// by round trip; the store never writes version 3.
impl Serialize for StateV3 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StateV3", 3)?;
        state.serialize_field("version", &Self::VERSION)?;
        state.serialize_field("deployment", &self.deployment)?;
        state.serialize_field("runtime", &self.runtime)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::two_node_parts;

    /// The version-3 form of `two_node_parts`.
    fn v3_parts() -> DeploymentV3Parts {
        let parts = two_node_parts();
        DeploymentV3Parts {
            config_generation: parts.config_generation,
            exit: parts.exit,
            policy: parts.policy,
            capacity: parts.capacity,
            auto_quota: parts.auto_quota,
            alerting: parts.alerting,
            viewers: parts.viewers,
            nodes: parts.nodes,
            users: parts.users,
            forgotten: parts.forgotten,
            next_wg_index: parts.next_wg_index,
        }
    }

    fn state() -> StateV3 {
        StateV3 {
            deployment: DeploymentV3::try_from(v3_parts()).unwrap(),
            runtime: RuntimeIntent::new(),
        }
    }

    /// Version 3 round-trips in its own encoding, with no spare users; the
    /// current version's form is refused.
    #[test]
    fn version_three_round_trips_with_its_own_encoding() {
        let state = state();
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.starts_with(r#"{"version":3,"deployment":{"config_generation":1,"#));
        assert!(json.contains(r#""forgotten":[],"next_wg_index""#), "{json}");
        assert!(!json.contains("spares"));
        assert_eq!(serde_json::from_str::<StateV3>(&json).unwrap(), state);
        for refused in [
            json.replacen(r#""forgotten":[]"#, r#""spares":[],"forgotten":[]"#, 1),
            json.replacen(r#""version":3"#, r#""version":4"#, 1),
        ] {
            assert_ne!(refused, json);
            assert!(
                serde_json::from_str::<StateV3>(&refused).is_err(),
                "{refused}"
            );
        }
    }

    /// The lift keeps every field and adds no spare user.
    #[test]
    fn the_lift_keeps_everything_and_adds_no_spare() {
        let lifted = state().lift().unwrap();
        let current = Deployment::try_from(two_node_parts()).unwrap();
        assert_eq!(lifted.deployment, current);
        assert!(lifted.deployment.spares().is_empty());
        assert_eq!(lifted.runtime, RuntimeIntent::new());
    }

    /// A version-3 document that breaks a version-3 rule is a decode error,
    /// as its decoding then was: here a duplicate short id.
    #[test]
    fn a_version_three_document_is_checked_with_the_version_three_rules() {
        let mut parts = v3_parts();
        let taken = parts.users[0].per_node.values().next().unwrap().short_id;
        let node = parts.users[1].per_node.keys().next().unwrap().clone();
        parts.users[1].per_node.get_mut(&node).unwrap().short_id = taken;
        assert_eq!(
            DeploymentV3::try_from(parts),
            Err(ModelError::DuplicateShortId { node })
        );
        assert_eq!(StateV3::require_version(3), Ok(()));
        assert_eq!(
            StateV3::require_version(4),
            Err(ModelError::StateVersionMismatch {
                expected: 3,
                found: 4
            })
        );
    }
}
