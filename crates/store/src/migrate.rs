// SPDX-License-Identifier: GPL-3.0-or-later

//! The migration chain (design §7): every state version this build reads
//! is lifted to the newest one by a chain of pure functions.
//!
//! The store reads the version first ([`StateHeader`]), refuses a newer
//! document (`DowngradeRefused`), and lifts an older one in memory. A
//! lifted document reaches disk only through a write, which first backs up
//! the original bytes to `state.json.bak-<from>-<to>`.

use std::path::Path;

use mooring_model::state::{StateFile, StateHeader, StateV1};

use crate::error::StoreError;

/// Lifts a state document of any version this build reads to the newest
/// version.
///
/// Each future version adds one pure step (`V1 → V2 → …`) here. Version 1
/// is the newest today, so the chain has no steps yet, and no step can fail
/// (`StoreError::MigrationFailed` is reserved for the first fallible one).
#[must_use]
pub fn migrate(file: StateFile) -> StateV1 {
    match file {
        StateFile::V1(state) => state,
    }
}

/// A state document lifted to the newest version.
#[derive(Debug)]
pub(crate) struct Decoded {
    /// The lifted state.
    pub(crate) state: StateV1,
    /// The version the document had on disk.
    pub(crate) from: u32,
}

/// The versions a build reads and how it lifts them. Production code uses
/// [`Chain::CURRENT`]; tests substitute chains with older test versions so
/// the backup path runs before a real second version exists.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Chain {
    /// The newest version, which is the version every write produces.
    pub(crate) newest: u32,
    /// Parses a document of version at most `newest` and lifts it.
    pub(crate) lift: fn(&[u8]) -> Result<StateV1, serde_json::Error>,
}

impl Chain {
    /// This build's chain.
    pub(crate) const CURRENT: Self = Self {
        newest: StateFile::CURRENT_VERSION,
        lift: lift_state_file,
    };

    /// Decodes the bytes of the state file at `path`: refuses a newer
    /// version before parsing it, then lifts the document.
    pub(crate) fn decode(&self, path: &Path, bytes: &[u8]) -> Result<Decoded, StoreError> {
        let corrupt = |source| StoreError::StateCorrupt {
            path: path.to_path_buf(),
            source,
        };
        let header: StateHeader = serde_json::from_slice(bytes).map_err(corrupt)?;
        if header.version > self.newest {
            return Err(StoreError::DowngradeRefused {
                found: header.version,
                newest: self.newest,
            });
        }
        let state = (self.lift)(bytes).map_err(corrupt)?;
        Ok(Decoded {
            state,
            from: header.version,
        })
    }
}

/// Parses any [`StateFile`] version and lifts it with [`migrate`].
pub(crate) fn lift_state_file(bytes: &[u8]) -> Result<StateV1, serde_json::Error> {
    serde_json::from_slice::<StateFile>(bytes).map(migrate)
}
