// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's status snapshot (design §10.1, "Latches and status"):
//! `status.json` beside `state.json`, a copy of the latest console status
//! kept for diagnosis. It is not state: nothing reads it to decide
//! anything, and the console reads the daemon, never this file.
//!
//! Only the daemon writes it, and only one daemon runs at a time (it holds
//! its instance lock), so the write takes no state lock.

use std::path::Path;

use crate::durable::write_durably;
use crate::error::StoreError;

/// The snapshot's file name.
pub const STATUS_SNAPSHOT_FILE: &str = "status.json";

/// Replaces `dir/status.json` with `bytes` with the store's durable write
/// (temporary file, fsync, rename, directory fsync; mode 0600), so a crash
/// leaves the previous snapshot or the new one, never a mix. The directory
/// must exist: the store never creates it.
pub fn write_status_snapshot(dir: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_durably(dir, STATUS_SNAPSHOT_FILE, bytes)
}
