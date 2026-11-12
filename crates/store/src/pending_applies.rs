// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of pending applies (design §13.6, §15.3):
//! `run/pending-applies.json`, since when each node has been behind the
//! deployment's configuration generation, kept so that a restart of the
//! daemon does not restart a wait. `daemon-core`'s `PendingApplies`
//! encodes and decodes it; this module keeps the file.
//!
//! Only the daemon writes it, and only one daemon runs at a time (it holds
//! its instance lock), so the write takes no state lock. The read is
//! bounded by the caller and opens only a regular file: anything else where
//! the record belongs, a link included, is `NotRegularFile`, and nothing is
//! read through it. A missing file is none.

use std::path::Path;

use crate::durable::{read_limited, write_durably};
use crate::error::{IoOp, StoreError};

/// The record's file name, in the daemon's run directory.
pub const PENDING_APPLIES_FILE: &str = "pending-applies.json";

/// The record in `run_dir`, at most `limit` bytes of it (a longer file
/// reads as its first `limit` bytes, which the decoder then refuses), or
/// `None` when there is none.
pub fn read_pending_applies(run_dir: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    read_limited(
        &run_dir.join(PENDING_APPLIES_FILE),
        limit,
        IoOp::ReadPendingApplies,
    )
}

/// Replaces the record in `run_dir` with `bytes` (the store's durable
/// write, mode 0600). The daemon makes `run_dir` before it writes.
pub fn write_pending_applies(run_dir: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_durably(run_dir, PENDING_APPLIES_FILE, bytes)
}
