// SPDX-License-Identifier: GPL-3.0-or-later

//! The secret store contract and the in-memory implementation.

use std::collections::BTreeSet;

use mooring_model::secret::{SecretEntry, SecretMaterial, SecretRef};

use super::builders::{material_for, node_id};
use crate::secrets::{
    InMemorySecretStore, SecretStore, SecretStoreError, SecretStoreErrorKind, SnapshotReadError,
    SnapshotReadErrorKind, read_snapshot,
};

fn reality_ref() -> SecretRef {
    SecretRef::NodeRealityPrivate(node_id("lon1"))
}

/// The material inside `entry`.
fn material_of(entry: &SecretEntry) -> SecretMaterial {
    entry.clone().into_parts().1
}

#[test]
fn the_in_memory_store_gets_puts_replaces_and_deletes() {
    let mut store = InMemorySecretStore::new();
    let secret_ref = reality_ref();
    let missing = SecretStoreError::SecretMissing {
        secret_ref: secret_ref.clone(),
    };
    assert!(store.is_empty());
    assert_eq!(store.get(&secret_ref).unwrap_err(), missing);
    assert_eq!(missing.kind(), SecretStoreErrorKind::SecretMissing);

    let first = SecretEntry::new(secret_ref.clone(), material_for(&secret_ref, 1)).unwrap();
    store.put(first.clone()).unwrap();
    assert_eq!(&store.get(&secret_ref).unwrap(), &material_of(&first));
    assert_eq!(store.len(), 1);

    let second = SecretEntry::new(secret_ref.clone(), material_for(&secret_ref, 2)).unwrap();
    assert_ne!(&material_of(&first), &material_of(&second));
    store.put(second.clone()).unwrap();
    assert_eq!(
        &store.get(&secret_ref).unwrap(),
        &material_of(&second),
        "put replaces"
    );
    assert_eq!(store.refs(), BTreeSet::from([secret_ref.clone()]));

    store.delete(&secret_ref).unwrap();
    assert!(store.is_empty());
    assert_eq!(store.delete(&secret_ref).unwrap_err(), missing);
    assert_eq!(store.get(&secret_ref).unwrap_err(), missing);
}

#[test]
fn debug_output_never_shows_material() {
    let mut store = InMemorySecretStore::new();
    let secret_ref = reality_ref();
    let material = material_for(&secret_ref, 7);
    let text = material.encode();
    let entry = SecretEntry::new(secret_ref, material).unwrap();
    let entry_debug = format!("{entry:?}");
    store.put(entry).unwrap();
    let store_debug = format!("{store:?}");
    for debug in [&entry_debug, &store_debug] {
        assert!(!debug.contains(text.as_str()), "{debug}");
    }
    assert!(store_debug.contains("NodeRealityPrivate"), "{store_debug}");
    assert!(
        !store_debug.contains("redacted"),
        "only references are listed: {store_debug}"
    );
}

/// Three references of different kinds, with distinct material each.
fn three_refs() -> Vec<SecretRef> {
    vec![
        reality_ref(),
        SecretRef::NodeHy2Obfs(node_id("lon1"), mooring_model::ports::ListenerIdx::FIRST),
        SecretRef::ProbeVlessUuid(node_id("lon1")),
    ]
}

fn holding(refs: &[SecretRef]) -> InMemorySecretStore {
    let mut store = InMemorySecretStore::new();
    for (index, secret_ref) in refs.iter().enumerate() {
        let byte = u8::try_from(index + 1).unwrap();
        store
            .put(SecretEntry::new(secret_ref.clone(), material_for(secret_ref, byte)).unwrap())
            .unwrap();
    }
    store
}

/// `read_snapshot` reads exactly the listed references, each with the
/// material the store holds, and nothing else the store holds.
#[test]
fn a_snapshot_holds_exactly_the_listed_references() {
    let all = three_refs();
    let store = holding(&all);
    let wanted: BTreeSet<SecretRef> = all[..2].iter().cloned().collect();
    let snapshot = read_snapshot(&store, &wanted).unwrap();
    assert_eq!(snapshot.refs(), wanted.iter().cloned().collect::<Vec<_>>());
    for secret_ref in &wanted {
        assert_eq!(
            snapshot.material(secret_ref).unwrap(),
            store.get(secret_ref).unwrap()
        );
    }
    assert!(
        read_snapshot(&store, &BTreeSet::new())
            .unwrap()
            .refs()
            .is_empty()
    );
}

/// A missing item is the store's own `SecretMissing`, naming it.
#[test]
fn a_missing_item_fails_the_snapshot() {
    let all = three_refs();
    let store = holding(&all[..1]);
    let wanted: BTreeSet<SecretRef> = all.iter().cloned().collect();
    let missing = all.iter().skip(1).min().unwrap().clone();
    match read_snapshot(&store, &wanted) {
        Err(SnapshotReadError::Store(SecretStoreError::SecretMissing { secret_ref })) => {
            assert_eq!(secret_ref, missing);
        }
        other => panic!("{other:?}"),
    }
}

/// A store answering with material of another kind than the reference
/// names: the item is invalid for that reference.
#[derive(Debug)]
struct WrongKind;

impl SecretStore for WrongKind {
    fn get(&self, secret_ref: &SecretRef) -> Result<SecretMaterial, SecretStoreError> {
        let other =
            SecretRef::NodeHy2Obfs(node_id("lon1"), mooring_model::ports::ListenerIdx::FIRST);
        assert_ne!(other.kind(), secret_ref.kind());
        Ok(material_for(&other, 7))
    }

    fn put(&mut self, _entry: SecretEntry) -> Result<(), SecretStoreError> {
        unreachable!("read only")
    }

    fn delete(&mut self, _secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        unreachable!("read only")
    }
}

#[test]
fn material_of_another_kind_is_an_invalid_item() {
    let wanted = BTreeSet::from([reality_ref()]);
    let error = read_snapshot(&WrongKind, &wanted).unwrap_err();
    assert_eq!(error.kind(), SnapshotReadErrorKind::Store);
    match error {
        SnapshotReadError::Store(SecretStoreError::ItemInvalid { secret_ref }) => {
            assert_eq!(secret_ref, reality_ref());
        }
        other => panic!("{other:?}"),
    }
}

/// `Snapshot` guards the snapshot's fallible insertion, which a set of
/// distinct references never trips; its mapping is checked on a
/// constructed value.
#[test]
fn a_snapshot_error_keeps_its_kind_and_message() {
    let error =
        SnapshotReadError::Snapshot(mooring_model::secret::SecretSnapshotError::Duplicate {
            secret_ref: reality_ref(),
        });
    assert_eq!(error.kind(), SnapshotReadErrorKind::Snapshot);
    assert_eq!(
        error.to_string(),
        format!("secret {} is already present", reality_ref())
    );
}
