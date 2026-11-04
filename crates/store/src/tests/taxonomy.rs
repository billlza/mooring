// SPDX-License-Identifier: GPL-3.0-or-later

//! The error taxonomy (design §14): complete kind lists, and the kinds no
//! public operation of this build can produce.

use std::collections::BTreeSet;
use std::fmt::Display;
use std::io;
use std::path::PathBuf;

use mooring_model::collections::NonEmpty;
use mooring_model::counters::ConfigGeneration;
use mooring_model::ids::NodeId;
use mooring_model::secret::SecretRef;

use crate::error::{ChangeErrorKind, CleanupFailure, IoOp, StoreError, StoreErrorKind};
use crate::secrets::{SecretOp, SecretStoreError, SecretStoreErrorKind, SnapshotReadErrorKind};

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
    assert_complete(StoreErrorKind::ALL, StoreErrorKind::name, 26);
    assert_complete(SecretStoreErrorKind::ALL, SecretStoreErrorKind::name, 3);
    assert_complete(SnapshotReadErrorKind::ALL, SnapshotReadErrorKind::name, 2);
    assert_complete(ChangeErrorKind::ALL, ChangeErrorKind::name, 2);
    assert_eq!(
        StoreErrorKind::GenerationConflict.name(),
        "GenerationConflict"
    );
}

/// `Encode` guards serde_json's fallible API and cannot occur in this build,
/// and `Lock` needs `flock(2)` to fail on a regular file, which no test can
/// make it do (since 2026-11-03 a FIFO, which macOS refuses to lock, is
/// refused before any lock is tried, as `NotRegularFile`), so their
/// mappings are checked on constructed values. (`MigrationFailed` has a
/// real path: `tests::migration`.)
#[test]
fn kinds_without_a_reachable_path_still_map() {
    let encode = StoreError::Encode {
        source: serde_json::from_str::<u8>("x").unwrap_err(),
    };
    assert_eq!(encode.kind(), StoreErrorKind::Encode);
    let lock = StoreError::Lock {
        path: PathBuf::from("/x/state.lock"),
        source: io::Error::from_raw_os_error(libc::ENOLCK),
    };
    assert_eq!(lock.kind(), StoreErrorKind::Lock);
    assert_eq!(lock.to_string(), "failed to lock /x/state.lock");
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
    assert_eq!(keychain.kind(), SecretStoreErrorKind::Keychain);
}

/// `ItemInvalid` is produced by a Keychain implementation (`mooringctl`'s
/// login keychain) when an item is not text of its reference's kind; it
/// names the reference and kind, never the item.
#[test]
fn an_invalid_item_names_its_reference_and_kind_only() {
    let invalid = SecretStoreError::ItemInvalid {
        secret_ref: SecretRef::RouterAdmin,
    };
    assert_eq!(invalid.kind(), SecretStoreErrorKind::ItemInvalid);
    assert_eq!(
        invalid.to_string(),
        "the item stored as router/admin is not valid RouterAdminPassword material"
    );
    let missing = SecretStoreError::SecretMissing {
        secret_ref: SecretRef::RouterAdmin,
    };
    assert_eq!(missing.kind(), SecretStoreErrorKind::SecretMissing);
    assert_eq!(missing.to_string(), "secret router/admin is missing");
}

/// Each filesystem operation has a description of its own, a lowercase
/// verb phrase that `Io`'s message reads as "failed to …", so the message
/// says which operation failed. `IoOp::ALL` comes from the list that
/// declares the operations, so an operation added there is checked here.
#[test]
fn every_filesystem_operation_has_its_own_description() {
    let descriptions: BTreeSet<String> = IoOp::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(descriptions.len(), IoOp::ALL.len());
    for description in &descriptions {
        assert!(
            description.starts_with(|first: char| first.is_ascii_lowercase())
                && !description.ends_with('.'),
            "{description}"
        );
    }
    assert_eq!(IoOp::ReadSimMeter.to_string(), "read the SIM meter");
}

/// The secret store's operations name themselves as its methods.
#[test]
fn secret_operations_are_named_as_their_calls() {
    let names: Vec<String> = [SecretOp::Get, SecretOp::Put, SecretOp::Delete]
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(names, ["get", "put", "delete"]);
}

/// A message about several secrets names every one, in order, and an empty
/// list as such; a cleanup failure gives each secret with its own error.
#[test]
fn messages_name_every_secret_they_concern() {
    let changed = StoreError::SecretRefsChanged {
        added: BTreeSet::from([SecretRef::RouterAdmin, SecretRef::AlertTopic]),
        removed: BTreeSet::new(),
    };
    assert_eq!(
        changed.to_string(),
        "the change adds secrets [alert/topic, router/admin] and removes secrets []; \
         use the ordered secret update"
    );
    let mismatch = StoreError::SecretPlanMismatch {
        missing: BTreeSet::from([SecretRef::AlertTopic]),
        unreferenced: BTreeSet::from([
            SecretRef::NodeHy2Key(NodeId::parse("lon1").unwrap()),
            SecretRef::RouterAdmin,
        ]),
    };
    assert_eq!(
        mismatch.to_string(),
        "the change needs new secrets [alert/topic] that were not supplied, \
         and was given [router/admin, node/lon1/hy2-key] that it does not reference"
    );
    let cleanup = StoreError::SecretCleanup {
        committed: ConfigGeneration::new(4).unwrap(),
        failures: NonEmpty::from_parts(
            CleanupFailure {
                secret_ref: SecretRef::AlertTopic,
                error: SecretStoreError::Keychain {
                    op: SecretOp::Delete,
                    status: -25_308,
                },
            },
            vec![CleanupFailure {
                secret_ref: SecretRef::RouterAdmin,
                error: SecretStoreError::SecretMissing {
                    secret_ref: SecretRef::RouterAdmin,
                },
            }],
        ),
    };
    assert_eq!(
        cleanup.to_string(),
        "state committed at config generation 4, but deleting secrets failed: \
         alert/topic: keychain delete failed with OSStatus -25308; \
         router/admin: secret router/admin is missing"
    );
}
