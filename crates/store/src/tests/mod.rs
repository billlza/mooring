// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the store: CAS, locking, durability, decoding, migrations,
//! secret stores, the secret ordering rules, the router identity file and
//! the radio history's day files (design §7, §15.6, §16 L1).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::store::Store;

mod allowed_networks;
mod builders;
mod cas;
mod concurrency;
mod decode;
mod durability;
mod latch;
mod migration;
mod ordering;
mod properties;
mod radio_history;
mod router_pin;
mod secrets;
mod sim_meter;
mod status_snapshot;
mod taxonomy;

/// The raw bytes of `state.json`.
fn state_bytes(store: &Store) -> Vec<u8> {
    fs::read(store.state_path()).unwrap()
}

/// The permission bits of `path`.
fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// `error` is the failure of `op` on `path` with the operating system's
/// error of kind `cause`: it names the operation and the path, and keeps
/// the system's error as its source.
fn assert_io_error(
    error: &crate::error::StoreError,
    op: crate::error::IoOp,
    path: &Path,
    cause: std::io::ErrorKind,
) {
    assert!(
        matches!(error, crate::error::StoreError::Io { op: found, path: at, source }
            if *found == op && at == path && source.kind() == cause),
        "{error:?}"
    );
    assert_eq!(error.kind(), crate::error::StoreErrorKind::Io);
    assert_eq!(
        error.to_string(),
        format!("failed to {op} at {}", path.display())
    );
}

/// The store error inside `error`; fails the test on a refused change.
fn store_error<E: std::fmt::Debug>(
    error: crate::error::ChangeError<E>,
) -> crate::error::StoreError {
    match error {
        crate::error::ChangeError::Store(error) => error,
        crate::error::ChangeError::Refused(refusal) => {
            panic!("expected a store error, got the refusal {refusal:?}")
        }
    }
}
