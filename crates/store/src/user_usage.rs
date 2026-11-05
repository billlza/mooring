// SPDX-License-Identifier: GPL-3.0-or-later

//! Durable daemon-owned user accounting. Encoding and validation belong
//! to daemon-core; this boundary owns the fixed path and private file.

use crate::error::{IoOp, StoreError};
use crate::sim_meter::{read_usage_document, write_usage_document};
use std::path::Path;

/// The aggregate document in the private usage directory.
pub const USER_USAGE_FILE: &str = "users.json";

/// A bounded regular-file read. Missing is uninitialized; links, devices,
/// unreadable files and malformed data are never an empty history.
pub fn read_user_usage(support: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    read_usage_document(support, USER_USAGE_FILE, limit, IoOp::ReadUserUsage)
}

/// Atomic, fsynced replacement. Only the daemon holding its instance lock
/// writes this file; the SIM meter uses a different document.
pub fn write_user_usage(support: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_usage_document(support, USER_USAGE_FILE, bytes)
}
