// SPDX-License-Identifier: GPL-3.0-or-later

//! The error taxonomy (design §14): complete kind lists, and the kinds no
//! public operation of this build can produce.

use std::collections::BTreeSet;
use std::fmt::Display;

use mooring_model::counters::{ConfigGeneration, CounterKind};
use mooring_model::error::ModelError;

use crate::error::{ChangeErrorKind, StoreError, StoreErrorKind};
use crate::secrets::{SecretOp, SecretStoreError, SecretStoreErrorKind};

/// `ALL` lists each kind once, and each kind's name is its Display text.
fn assert_complete<K: Copy + Ord + Display>(
    all: &[K],
    name: impl Fn(K) -> &'static str,
    len: usize,
) {
    assert_eq!(all.len(), len);
    let distinct: BTreeSet<K> = all.iter().copied().collect();
    assert_eq!(distinct.len(), len);
    let names: BTreeSet<&str> = all.iter().map(|kind| name(*kind)).collect();
    assert_eq!(names.len(), len);
    for kind in all {
        assert_eq!(kind.to_string(), name(*kind));
    }
}

#[test]
fn kind_lists_are_complete() {
    assert_complete(StoreErrorKind::ALL, StoreErrorKind::name, 19);
    assert_complete(SecretStoreErrorKind::ALL, SecretStoreErrorKind::name, 2);
    assert_complete(ChangeErrorKind::ALL, ChangeErrorKind::name, 2);
    assert_eq!(
        StoreErrorKind::GenerationConflict.name(),
        "GenerationConflict"
    );
}

/// `MigrationFailed` is the contract for the first fallible migration step
/// and `Encode` guards serde_json's fallible API; neither can occur in this
/// build, so their mapping is checked on constructed values.
#[test]
fn kinds_without_a_reachable_path_still_map() {
    let migration = StoreError::MigrationFailed {
        from: 1,
        to: 2,
        source: ModelError::CounterOverflow {
            counter: CounterKind::ConfigGeneration,
        },
    };
    assert_eq!(migration.kind(), StoreErrorKind::MigrationFailed);
    assert_eq!(
        migration.to_string(),
        "migrating the state from version 1 to 2 failed"
    );

    let encode = StoreError::Encode {
        source: serde_json::from_str::<u8>("x").unwrap_err(),
    };
    assert_eq!(encode.kind(), StoreErrorKind::Encode);
}

#[test]
fn messages_name_the_counters_and_the_operation() {
    let conflict = StoreError::GenerationConflict {
        expected: ConfigGeneration::new(3).unwrap(),
        found: ConfigGeneration::new(5).unwrap(),
    };
    assert_eq!(
        conflict.to_string(),
        "config generation is 5, expected 3; re-read the state and retry"
    );
    let keychain = SecretStoreError::Keychain {
        op: SecretOp::Delete,
        status: -25_300,
    };
    assert_eq!(
        keychain.to_string(),
        "keychain delete failed with OSStatus -25300"
    );
}
