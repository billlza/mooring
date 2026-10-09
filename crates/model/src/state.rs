// SPDX-License-Identifier: GPL-3.0-or-later

//! The non-secret state document, `state.json` (design §7).
//!
//! No state type can hold a secret: every one derives `Serialize`, and
//! `Secret<T>` does not implement it.

use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::counters::RuntimeRevision;
use crate::deployment::Deployment;
use crate::error::ModelError;
use crate::v1::StateV1;

/// Mac-only runtime intent; it never affects VPS digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIntent {
    /// Whether the operator wants the exit serving.
    pub exit_enabled: bool,
    /// Bumped by every change to this intent.
    pub revision: RuntimeRevision,
}

impl RuntimeIntent {
    /// A fresh intent: exit disabled, initial revision.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            exit_enabled: false,
            revision: RuntimeRevision::INITIAL,
        }
    }
}

impl Default for RuntimeIntent {
    fn default() -> Self {
        Self::new()
    }
}

/// Version 2 of the state document, the version this build writes,
/// serialised as `{"version": 2, "deployment": …, "runtime": …}`.
///
/// Version 2 adds the SIM plan record, bill day and stop policy, the
/// uplink baseline, user suspension, policy, alias and agreement records,
/// the cap on active users, automatic quotas (decision F4), the alert
/// channels (F6) and the remote viewers (F5) ([`crate::v1`] lists how
/// version 1 lifts).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "StateV2Repr")]
pub struct StateV2 {
    /// Every node and user.
    pub deployment: Deployment,
    /// Mac-only runtime intent.
    pub runtime: RuntimeIntent,
}

impl StateV2 {
    /// The schema version this type reads and writes.
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV2Repr {
    version: u32,
    deployment: Deployment,
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

impl Serialize for StateV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StateV2", 3)?;
        state.serialize_field("version", &Self::VERSION)?;
        state.serialize_field("deployment", &self.deployment)?;
        state.serialize_field("runtime", &self.runtime)?;
        state.end()
    }
}

/// A state document version this build reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StateVersion {
    /// Version 1, read only to be lifted.
    V1,
    /// Version 2, the version this build writes.
    V2,
}

impl StateVersion {
    /// The version's number, as `state.json` carries it.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::V1 => StateV1::VERSION,
            Self::V2 => StateV2::VERSION,
        }
    }
}

/// `UnknownStateVersion` for a number this build does not read.
impl TryFrom<u32> for StateVersion {
    type Error = ModelError;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        match found {
            StateV1::VERSION => Ok(Self::V1),
            StateV2::VERSION => Ok(Self::V2),
            found => Err(ModelError::UnknownStateVersion { found }),
        }
    }
}

/// Every state document version this build reads. The store's migration
/// chain lifts older versions to the newest before use.
///
/// A document is decoded in two steps, because its version decides its
/// schema: [`StateHeader`] reads the version alone, and
/// [`StateFile::deserialize_version`] decodes the document as that version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateFile {
    /// Version 1, read only to be lifted.
    V1(StateV1),
    /// Version 2.
    V2(StateV2),
}

impl StateFile {
    /// The newest version this build writes.
    pub const CURRENT_VERSION: u32 = StateV2::VERSION;

    /// This document's schema version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self {
            Self::V1(_) => StateV1::VERSION,
            Self::V2(_) => StateV2::VERSION,
        }
    }

    /// Decodes a document whose header announced `version` with that
    /// version's schema.
    pub fn deserialize_version<'de, D: Deserializer<'de>>(
        version: StateVersion,
        deserializer: D,
    ) -> Result<Self, D::Error> {
        match version {
            StateVersion::V1 => StateV1::deserialize(deserializer).map(Self::V1),
            StateVersion::V2 => StateV2::deserialize(deserializer).map(Self::V2),
        }
    }
}

impl Serialize for StateFile {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::V1(state) => state.serialize(serializer),
            Self::V2(state) => state.serialize(serializer),
        }
    }
}

/// Reads only the `version` of a state document of any version, ignoring
/// every other field, so the store can pick a parser or refuse a newer
/// document (`DowngradeRefused`) before parsing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct StateHeader {
    /// The document's schema version.
    pub version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::two_node_parts;

    fn state() -> StateV2 {
        StateV2 {
            deployment: Deployment::try_from(two_node_parts()).unwrap(),
            runtime: RuntimeIntent::new(),
        }
    }

    /// Decodes `json` the way the store does: header first, then the
    /// announced version.
    fn decode(json: &str) -> Result<StateFile, serde_json::Error> {
        let header: StateHeader = serde_json::from_str(json)?;
        let version = StateVersion::try_from(header.version).map_err(serde::de::Error::custom)?;
        let mut deserializer = serde_json::Deserializer::from_str(json);
        let file = StateFile::deserialize_version(version, &mut deserializer)?;
        deserializer.end()?;
        Ok(file)
    }

    #[test]
    fn state_round_trips_with_a_leading_version() {
        let file = StateFile::V2(state());
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.starts_with(r#"{"version":2,"deployment":{"config_generation":1,"#));
        assert!(json.ends_with(r#""runtime":{"exit_enabled":false,"revision":1}}"#));
        let back = decode(&json).unwrap();
        assert_eq!(back, file);
        assert_eq!(back.version(), StateFile::CURRENT_VERSION);
        assert_eq!(serde_json::from_str::<StateV2>(&json).unwrap(), state());
        let header: StateHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(header.version, 2);
    }

    #[test]
    fn other_versions_and_unknown_fields_are_refused() {
        let json = serde_json::to_string(&StateFile::V2(state())).unwrap();
        for found in [0, 1, 3] {
            let other = json.replacen("\"version\":2", &format!("\"version\":{found}"), 1);
            let err = serde_json::from_str::<StateV2>(&other)
                .unwrap_err()
                .to_string();
            let expected = ModelError::StateVersionMismatch { expected: 2, found }.to_string();
            assert!(err.contains(&expected), "{err}");
            // The header still reads a newer document's version for DowngradeRefused.
            assert_eq!(
                serde_json::from_str::<StateHeader>(&other).unwrap().version,
                found
            );
        }
        // A version-2 document announced as version 1 fails version 1's schema.
        let as_v1 = json.replacen("\"version\":2", "\"version\":1", 1);
        assert!(decode(&as_v1).is_err());
        for found in [0, 3] {
            let other = json.replacen("\"version\":2", &format!("\"version\":{found}"), 1);
            let err = decode(&other).unwrap_err().to_string();
            let expected = ModelError::UnknownStateVersion { found }.to_string();
            assert!(err.contains(&expected), "{err}");
        }
        let quoted = json.replacen("\"version\":2", "\"version\":\"2\"", 1);
        assert!(serde_json::from_str::<StateV2>(&quoted).is_err());
        assert!(decode(&quoted).is_err());
        let extra = json.replacen("\"version\":2", "\"version\":2,\"secrets\":{}", 1);
        assert!(serde_json::from_str::<StateV2>(&extra).is_err());
        assert!(decode(&extra).is_err());
        let missing = json.replacen("\"version\":2,", "", 1);
        assert!(serde_json::from_str::<StateV2>(&missing).is_err());
        assert!(decode(&missing).is_err());
    }

    #[test]
    fn only_known_versions_select_a_schema() {
        for version in [StateVersion::V1, StateVersion::V2] {
            assert_eq!(StateVersion::try_from(version.number()), Ok(version));
        }
        assert_eq!(StateVersion::V1.number(), 1);
        assert_eq!(StateVersion::V2.number(), StateFile::CURRENT_VERSION);
        for found in [0, 3, u32::MAX] {
            assert_eq!(
                StateVersion::try_from(found),
                Err(ModelError::UnknownStateVersion { found })
            );
        }
    }

    #[test]
    fn invalid_deployments_inside_state_are_refused() {
        let json = serde_json::to_string(&StateFile::V2(state())).unwrap();
        // Retiring ams1 while users still hold credentials on it breaks an invariant.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["deployment"]["nodes"][0]["lifecycle"] = serde_json::json!("retired");
        assert!(serde_json::from_value::<StateV2>(value.clone()).is_err());
        assert!(decode(&value.to_string()).is_err());
    }
}
