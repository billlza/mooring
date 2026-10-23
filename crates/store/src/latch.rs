// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit's latch (design §10.2, "After a violation"): the model's
//! [`LatchRecord`], kept in `run/latch.json` so that it outlives the
//! daemon, a crash and a reboot. The daemon's state machine decides when it
//! is set and cleared; this module reads, writes and removes the file.
//!
//! Only the daemon writes it, and only one daemon runs at a time (it holds
//! its instance lock), so the write takes no state lock. The CLI's
//! `exit retry` asks the daemon to clear it.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use mooring_model::verdict::LatchRecord;
use serde::{Deserialize, Serialize};

use crate::durable::{remove_durably, write_durably};
use crate::error::{IoOp, StoreError};

/// The latch's file name, in the daemon's run directory.
pub const LATCH_FILE: &str = "latch.json";

/// The largest latch file read, in bytes.
const MAX_LATCH_BYTES: usize = 64 * 1024;

/// The latch document's version.
const LATCH_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LatchDocument {
    version: u32,
    latch: LatchRecord,
}

/// The latch in `run_dir`, or `None` when there is none. A file that is not
/// a version-1 latch is `LatchCorrupt`: the daemon then keeps the exit down
/// rather than read it as no latch.
pub fn read_latch(run_dir: &Path) -> Result<Option<LatchRecord>, StoreError> {
    let path = run_dir.join(LATCH_FILE);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreError::Io {
                op: IoOp::ReadLatch,
                path,
                source,
            });
        }
    };
    let mut bytes = Vec::with_capacity(MAX_LATCH_BYTES + 1);
    file.take(MAX_LATCH_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            op: IoOp::ReadLatch,
            path: path.clone(),
            source,
        })?;
    if bytes.len() > MAX_LATCH_BYTES {
        return Err(StoreError::LatchCorrupt { path });
    }
    match serde_json::from_slice::<LatchDocument>(&bytes) {
        Ok(document) if document.version == LATCH_VERSION => Ok(Some(document.latch)),
        Ok(_) | Err(_) => Err(StoreError::LatchCorrupt { path }),
    }
}

/// Writes `latch` to `run_dir/latch.json` with the store's durable write
/// (mode 0600), replacing any earlier latch.
pub fn write_latch(run_dir: &Path, latch: &LatchRecord) -> Result<(), StoreError> {
    let mut bytes = serde_json::to_vec_pretty(&LatchDocument {
        version: LATCH_VERSION,
        latch: latch.clone(),
    })
    .map_err(|source| StoreError::Encode { source })?;
    bytes.push(b'\n');
    write_durably(run_dir, LATCH_FILE, &bytes)
}

/// Removes the latch, durably; no latch is fine.
pub fn clear_latch(run_dir: &Path) -> Result<(), StoreError> {
    remove_durably(run_dir, LATCH_FILE)
}
