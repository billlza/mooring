// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's copy of the nodes' abuse records (design §11.8):
//! `abuse/records.json` in the support directory, kept 13 months from each
//! record, while a node keeps its own 30 days. The CLI's `abuse records`
//! writes it, merging each page it pulls; `daemon-core` encodes, merges and
//! prunes it, and this module keeps the file: the `abuse/` directory (mode
//! 0700, created by the update when missing, refused when anything else is
//! there, a link included), a lock of its own for the read-modify-write
//! (two commands may run at once), the durable write, and a read bounded by
//! the caller that refuses anything but a regular file.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use crate::durable::{
    LockMode, RegularFile, StateLock, existing_private_dir, existing_regular_file, private_dir,
    write_durably,
};
use crate::error::{IoOp, StoreError};

/// The abuse directory's name, in the support directory.
pub const ABUSE_DIRECTORY: &str = "abuse";

/// The records' file name, in the abuse directory.
pub const ABUSE_RECORDS_FILE: &str = "records.json";

/// The lock the update holds, in the abuse directory.
const LOCK_FILE: &str = "records.lock";

/// The records document, at most `limit` bytes of it, or `None` when there
/// is none (or no abuse directory at all).
pub fn read_abuse_records(support_dir: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(dir) = existing_private_dir(support_dir, ABUSE_DIRECTORY, IoOp::ReadAbuseRecords)?
    else {
        return Ok(None);
    };
    read_in(&dir, limit)
}

/// Replaces the records document with what `change` makes of the one there
/// (at most `limit` bytes of it, `None` when there is none), holding the
/// abuse directory's exclusive lock from the read to the durable write. A
/// refusal from `change` writes nothing and comes back as `Ok(Err(_))`.
pub fn update_abuse_records<E>(
    support_dir: &Path,
    limit: usize,
    change: impl FnOnce(Option<Vec<u8>>) -> Result<Vec<u8>, E>,
) -> Result<Result<(), E>, StoreError> {
    let dir = private_dir(support_dir, ABUSE_DIRECTORY, IoOp::CreateAbuseDir)?;
    let _lock = StateLock::acquire(&dir.join(LOCK_FILE), LockMode::Exclusive)?;
    let bytes = match change(read_in(&dir, limit)?) {
        Ok(bytes) => bytes,
        Err(refused) => return Ok(Err(refused)),
    };
    write_durably(&dir, ABUSE_RECORDS_FILE, &bytes)?;
    Ok(Ok(()))
}

fn read_in(dir: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    let path = dir.join(ABUSE_RECORDS_FILE);
    let op = IoOp::ReadAbuseRecords;
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
