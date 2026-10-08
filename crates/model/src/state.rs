// SPDX-License-Identifier: GPL-3.0-or-later

//! The non-secret state document, `state.json` (design §7).
//!
//! No state type can hold a secret: every one derives `Serialize`, and
//! `Secret<T>` does not implement it.

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};

use crate::counters::RuntimeRevision;
use crate::deployment::Deployment;
use crate::error::ModelError;

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

/// Version 1 of the state document, serialised as
/// `{"version": 1, "deployment": …, "runtime": …}`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "StateV1Repr")]
pub struct StateV1 {
    /// Every node and user.
    pub deployment: Deployment,
    /// Mac-only runtime intent.
    pub runtime: RuntimeIntent,
}

impl StateV1 {
    /// The schema version this type reads and writes.
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
    deployment: Deployment,
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

impl Serialize for StateV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("StateV1", 3)?;
        state.serialize_field("version", &Self::VERSION)?;
        state.serialize_field("deployment", &self.deployment)?;
        state.serialize_field("runtime", &self.runtime)?;
        state.end()
    }
}

/// Every state document version this build can read. The store's migration
/// chain lifts older versions to the newest before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateFile {
    /// Version 1.
    V1(StateV1),
}

impl StateFile {
    /// The newest version this build writes.
    pub const CURRENT_VERSION: u32 = StateV1::VERSION;

    /// This document's schema version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self {
            Self::V1(_) => StateV1::VERSION,
        }
    }
}

impl Serialize for StateFile {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::V1(state) => state.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for StateFile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        StateV1::deserialize(deserializer).map(Self::V1)
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

    fn state() -> StateV1 {
        StateV1 {
            deployment: Deployment::try_from(two_node_parts()).unwrap(),
            runtime: RuntimeIntent::new(),
        }
    }

    #[test]
    fn state_round_trips_with_a_leading_version() {
        let file = StateFile::V1(state());
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.starts_with(r#"{"version":1,"deployment":{"config_generation":1,"#));
        assert!(json.ends_with(r#""runtime":{"exit_enabled":false,"revision":1}}"#));
        let back: StateFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, file);
        assert_eq!(back.version(), StateFile::CURRENT_VERSION);
        let header: StateHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(header.version, 1);
    }

    #[test]
    fn other_versions_and_unknown_fields_are_refused() {
        let json = serde_json::to_string(&StateFile::V1(state())).unwrap();
        for found in [0, 2] {
            let other = json.replacen("\"version\":1", &format!("\"version\":{found}"), 1);
            let err = serde_json::from_str::<StateFile>(&other)
                .unwrap_err()
                .to_string();
            let expected = ModelError::StateVersionMismatch { expected: 1, found }.to_string();
            assert!(err.contains(&expected), "{err}");
            // The header still reads a newer document's version for DowngradeRefused.
            assert_eq!(
                serde_json::from_str::<StateHeader>(&other).unwrap().version,
                found
            );
        }
        let quoted = json.replacen("\"version\":1", "\"version\":\"1\"", 1);
        assert!(serde_json::from_str::<StateFile>(&quoted).is_err());
        let extra = json.replacen("\"version\":1", "\"version\":1,\"secrets\":{}", 1);
        assert!(serde_json::from_str::<StateFile>(&extra).is_err());
        let missing = json.replacen("\"version\":1,", "", 1);
        assert!(serde_json::from_str::<StateFile>(&missing).is_err());
    }

    #[test]
    fn invalid_deployments_inside_state_are_refused() {
        let json = serde_json::to_string(&StateFile::V1(state())).unwrap();
        // Retiring ams1 while users still hold credentials on it breaks an invariant.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["deployment"]["nodes"][0]["lifecycle"] = serde_json::json!("retired");
        assert!(serde_json::from_value::<StateFile>(value).is_err());
    }
}
