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

use mooring_model::state::{StateFile, StateHeader, StateV2, StateVersion};
use mooring_model::v1::StateV1;

use crate::error::StoreError;

/// Lifts a state document of any version this build reads to the newest
/// version.
///
/// The chain has one step, `V1 → V2`, whose conversions
/// `mooring_model::v1` documents: the cycle day becomes the bill day, the
/// hard stop becomes `StopPolicy::HardStop`, the plan stays unrecorded, and
/// every other version-2 field starts empty. It fails with
/// `MigrationFailed` only for a version-1 SIM policy without a hard stop
/// (`StopPolicyUnchosen`): running past the plan's line is now an explicit
/// choice that version 1 could not express.
pub fn migrate(file: StateFile) -> Result<StateV2, StoreError> {
    match file {
        StateFile::V1(state) => v1_to_v2(state),
        StateFile::V2(state) => Ok(state),
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

/// A state document lifted to the newest version.
#[derive(Debug)]
pub(crate) struct Decoded {
    /// The lifted state.
    pub(crate) state: StateV2,
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
/// before parsing it, then parses the document and lifts it.
pub(crate) fn decode(path: &Path, bytes: &[u8]) -> Result<Decoded, StoreError> {
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
    Ok(Decoded {
        state: migrate(file)?,
        from,
    })
}
