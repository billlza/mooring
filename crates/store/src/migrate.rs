// SPDX-License-Identifier: GPL-3.0-or-later

//! The migration chain (design §7): every state version this build reads
//! is lifted to the newest one by a chain of pure functions.
//!
//! The store reads the version first ([`StateHeader`]), refuses a newer
//! document (`DowngradeRefused`), parses the document with its own
//! version's schema, and lifts an older one in memory. A lifted document
//! reaches disk only through a write, which first backs up the original
//! bytes to `state.json.bak-<from>-<to>`.

use std::path::Path;

use mooring_model::state::{StateFile, StateHeader, StateV4, StateVersion};
use mooring_model::time::UnixTime;
use mooring_model::v1::StateV1;
use mooring_model::v2::StateV2;
use mooring_model::v3::StateV3;

use crate::error::StoreError;

/// Lifts a state document of any version this build reads to the newest
/// version, `lifted_at` being the lift's time.
///
/// The chain's steps, whose conversions the model's `v1`, `v2` and `v3`
/// modules document:
///
/// - `V1 → V2`: the cycle day becomes the bill day, the hard stop becomes
///   `StopPolicy::HardStop`, the plan stays unrecorded, and every other
///   version-2 field starts empty. It fails with `MigrationFailed` only for
///   a version-1 SIM policy without a hard stop (`StopPolicyUnchosen`):
///   running past the plan's line is now an explicit choice that version 1
///   could not express; and for a document that breaks a rule version 2
///   added (a cap, a unique alias).
/// - `V2 → V4`: a revoked user is revoked since `lifted_at`, which version
///   2 kept no time for: it can only delay the user's removal 13 months on
///   (design §15.7). No id of a removed user is kept, as version 2 removed
///   none a node could still name, and no spare user is added. (Version 3
///   is version 2's lift with those two records, so version 2 lifts to the
///   newest version in one step.)
/// - `V3 → V4`: every field is kept, and no spare user is added: the
///   nightly apply job draws them inside its window (design §13.6).
pub fn migrate(file: StateFile, lifted_at: UnixTime) -> Result<StateV4, StoreError> {
    match file {
        StateFile::V1(state) => v2_to_v4(v1_to_v2(state)?, lifted_at),
        StateFile::V2(state) => v2_to_v4(state, lifted_at),
        StateFile::V3(state) => v3_to_v4(state),
        StateFile::V4(state) => Ok(state),
    }
}

/// The step `V1 → V2`.
fn v1_to_v2(state: StateV1) -> Result<StateV2, StoreError> {
    StateV2::try_from(state).map_err(|source| StoreError::MigrationFailed {
        from: StateV1::VERSION,
        to: StateV2::VERSION,
        source,
    })
}

/// The step `V2 → V4`, at `lifted_at`.
fn v2_to_v4(state: StateV2, lifted_at: UnixTime) -> Result<StateV4, StoreError> {
    state
        .lift(lifted_at)
        .map_err(|source| StoreError::MigrationFailed {
            from: StateV2::VERSION,
            to: StateV4::VERSION,
            source,
        })
}

/// The step `V3 → V4`.
fn v3_to_v4(state: StateV3) -> Result<StateV4, StoreError> {
    state.lift().map_err(|source| StoreError::MigrationFailed {
        from: StateV3::VERSION,
        to: StateV4::VERSION,
        source,
    })
}

/// A state document lifted to the newest version.
#[derive(Debug)]
pub(crate) struct Decoded {
    /// The lifted state.
    pub(crate) state: StateV4,
    /// The version the document had on disk.
    pub(crate) from: u32,
}

/// Parses a state document of any version this build reads with that
/// version's schema, without lifting it.
pub(crate) fn parse(bytes: &[u8]) -> Result<StateFile, serde_json::Error> {
    let header: StateHeader = serde_json::from_slice(bytes)?;
    let version = StateVersion::try_from(header.version).map_err(serde::de::Error::custom)?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let file = StateFile::deserialize_version(version, &mut deserializer)?;
    deserializer.end()?;
    Ok(file)
}

/// Decodes the bytes of the state file at `path`: refuses a newer version
/// before parsing it, then parses the document and lifts it, at the time
/// `lifted_at` gives, which only a version-1 or version-2 document asks.
pub(crate) fn decode(
    path: &Path,
    bytes: &[u8],
    lifted_at: impl FnOnce() -> Result<UnixTime, StoreError>,
) -> Result<Decoded, StoreError> {
    let corrupt = |source| StoreError::StateCorrupt {
        path: path.to_path_buf(),
        source,
    };
    let header: StateHeader = serde_json::from_slice(bytes).map_err(corrupt)?;
    if header.version > StateFile::CURRENT_VERSION {
        return Err(StoreError::DowngradeRefused {
            found: header.version,
            newest: StateFile::CURRENT_VERSION,
        });
    }
    let file = parse(bytes).map_err(corrupt)?;
    let from = file.version();
    let state = match file {
        StateFile::V4(state) => state,
        // Only versions 1 and 2 lift with a time, so only they read it.
        StateFile::V3(state) => v3_to_v4(state)?,
        older => migrate(older, lifted_at()?)?,
    };
    Ok(Decoded { state, from })
}
