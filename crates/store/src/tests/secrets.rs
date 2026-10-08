// SPDX-License-Identifier: GPL-3.0-or-later

//! The secret store contract and the in-memory implementation.

use std::collections::BTreeSet;

use mooring_model::secret::{SecretEntry, SecretMaterial, SecretRef};

use super::builders::{material_for, node_id};
use crate::secrets::{InMemorySecretStore, SecretStore, SecretStoreError, SecretStoreErrorKind};

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
