// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter's document (design §10.1 step 5): `usage/sim-meter.json`
//! in the support directory, the line's bytes per UTC day. `daemon-core`'s
//! `SimMeter` encodes and decodes it; this module keeps the file: the
//! `usage/` directory (mode 0700, created by the write when missing, and
//! refused by the write and the read alike when anything else is there, a
//! link included), the durable write, and a read bounded by the caller,
//! which refuses anything but a regular file where the meter belongs, a
//! link included (`NotRegularFile`), so that a meter is never read through
//! a link nor a link to nothing read as no meter.
//!
//! Only the daemon writes it, and only one daemon runs at a time (it holds
//! its instance lock), so the write takes no state lock.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use crate::durable::{
    RegularFile, existing_private_dir, existing_regular_file, private_dir, write_durably,
};
use crate::error::{IoOp, StoreError};

/// The usage directory's name, in the support directory.
pub const USAGE_DIRECTORY: &str = "usage";

/// The meter's file name, in the usage directory.
pub const SIM_METER_FILE: &str = "sim-meter.json";

/// The meter document in `support_dir`, at most `limit` bytes of it (a
/// longer file reads as its first `limit` bytes, which the decoder then
/// refuses), or `None` when there is none (or no usage directory at all).
/// A usage path that is not a directory (a link included) is
/// `DirNotDirectory`, as for the write, and nothing is read through it;
/// anything but a regular file where the meter belongs, a link included,
/// is `NotRegularFile`, and nothing is read through it either.
pub fn read_sim_meter(support_dir: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    read_usage_document(support_dir, SIM_METER_FILE, limit, IoOp::ReadSimMeter)
}

/// A fixed-name usage document, through the same regular-file boundary.
pub(crate) fn read_usage_document(
    support_dir: &Path,
    name: &str,
    limit: usize,
    op: IoOp,
) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(dir) = existing_private_dir(support_dir, USAGE_DIRECTORY, op)? else {
        return Ok(None);
    };
    let path = dir.join(name);
    let Some(RegularFile { file, .. }) =
        existing_regular_file(&path, OpenOptions::new().read(true), op)?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io { op, path, source })?;
    Ok(Some(bytes))
}

/// Replaces the meter document with `bytes` (the store's durable write,
/// mode 0600), creating the usage directory first if it is missing; a
/// usage path that is not a directory (a link included) is
/// `DirNotDirectory`.
pub fn write_sim_meter(support_dir: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    write_usage_document(support_dir, SIM_METER_FILE, bytes)
}

/// Durably replaces a fixed-name usage document with mode 0600.
pub(crate) fn write_usage_document(
    support_dir: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), StoreError> {
    let dir = private_dir(support_dir, USAGE_DIRECTORY, IoOp::CreateUsageDir)?;
    write_durably(&dir, name, bytes)
}
