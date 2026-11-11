// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull's files (design §9.6). `daemon-core`'s `payments`
//! encodes and decodes both; this module keeps them:
//!
//! - the payment ledger, `payments/ledger.json`: the daemon's alone, which
//!   holds its instance lock, so the write takes no state lock. The
//!   `payments/` directory is the owner's alone (mode 0700), made by the
//!   first write, and refused by the write and the read alike when anything
//!   else is there, a link included (`DirNotDirectory`).
//! - the pull's settings, `payment-pull.json`, beside `state.json`: the
//!   CLI's, each change one read-modify-write under the store's exclusive
//!   lock, so two commands cannot lose each other's change; the daemon reads
//!   without the lock, as the durable write replaces the file atomically.
//!
//! Every read is bounded by the caller and opens only a regular file:
//! anything else where a file belongs, a link included, is
//! `NotRegularFile`, and nothing is read through it. A missing file is
//! none: no pull was ever set up, or none has been recorded.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use crate::durable::{
    LockMode, RegularFile, StateLock, existing_private_dir, existing_regular_file, private_dir,
    write_durably,
};
use crate::error::{ChangeError, IoOp, StoreError};
use crate::store::LOCK_FILE;

/// The payment ledger's directory, in the support directory.
pub const PAYMENTS_DIRECTORY: &str = "payments";

/// The payment ledger's file name, in its directory.
pub const PAYMENT_LEDGER_FILE: &str = "ledger.json";

/// The pull's settings file, in the support directory.
pub const PAYMENT_PULL_FILE: &str = "payment-pull.json";

/// The payment ledger in `support`, at most `limit` bytes of it (a longer
/// file reads as its first `limit` bytes, which the decoder then refuses),
/// or `None` when there is none (or no `payments/` directory at all).
pub fn read_payment_ledger(support: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(dir) = existing_private_dir(support, PAYMENTS_DIRECTORY, IoOp::ReadPaymentLedger)?
    else {
        return Ok(None);
    };
    read_limited(
        &dir.join(PAYMENT_LEDGER_FILE),
        limit,
        IoOp::ReadPaymentLedger,
    )
}

/// Replaces the payment ledger with `bytes` (the store's durable write,
/// mode 0600), making the `payments/` directory first if it is missing.
/// Only the daemon writes it.
pub fn write_payment_ledger(support: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = private_dir(support, PAYMENTS_DIRECTORY, IoOp::CreatePaymentsDir)?;
    write_durably(&dir, PAYMENT_LEDGER_FILE, bytes)
}

/// The pull's settings in `support`, at most `limit` bytes of them, or
/// `None` when there are none. Read without the lock.
pub fn read_payment_pull(support: &Path, limit: usize) -> Result<Option<Vec<u8>>, StoreError> {
    read_limited(
        &support.join(PAYMENT_PULL_FILE),
        limit,
        IoOp::ReadPaymentPull,
    )
}

/// Changes the pull's settings under the store's exclusive lock: `change`
/// gets the current file (at most `limit` bytes of it, or `None`) and
/// returns the new one, which is written durably (mode 0600), or `None`
/// to leave the file as it is. A refusal writes nothing. Returns the bytes
/// written, if any. `support` must exist: the store never creates it.
pub fn update_payment_pull<E>(
    support: &Path,
    limit: usize,
    change: impl FnOnce(Option<&[u8]>) -> Result<Option<Vec<u8>>, E>,
) -> Result<Option<Vec<u8>>, ChangeError<E>> {
    let _lock = StateLock::acquire(&support.join(LOCK_FILE), LockMode::Exclusive)?;
    let current = read_payment_pull(support, limit)?;
    let Some(bytes) = change(current.as_deref()).map_err(ChangeError::Refused)? else {
        return Ok(None);
    };
    write_durably(support, PAYMENT_PULL_FILE, &bytes)?;
    Ok(Some(bytes))
}

/// The regular file at `path`, at most `limit` bytes of it, or `None` when
/// there is none.
fn read_limited(path: &Path, limit: usize, op: IoOp) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(RegularFile { file, .. }) =
        existing_regular_file(path, OpenOptions::new().read(true), op)?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            op,
            path: path.to_path_buf(),
            source,
        })?;
    Ok(Some(bytes))
}
