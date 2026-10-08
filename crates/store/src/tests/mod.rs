// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests of the store: CAS, locking, durability, decoding, migrations,
//! secret stores and the secret ordering rules (design §7, §16 L1).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::store::Store;

mod builders;
mod cas;
mod concurrency;
mod decode;
mod durability;
mod migration;
mod ordering;
mod properties;
mod secrets;
mod taxonomy;

/// The raw bytes of `state.json`.
fn state_bytes(store: &Store) -> Vec<u8> {
    fs::read(store.state_path()).unwrap()
}

/// The permission bits of `path`.
fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
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
