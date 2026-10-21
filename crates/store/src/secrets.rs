// SPDX-License-Identifier: GPL-3.0-or-later

//! The secret store abstraction (design §7, §12): one item per
//! [`SecretRef`], holding typed [`SecretMaterial`].
//!
//! The shipped implementation is the macOS data-protection Keychain
//! (milestone M5). Until then `mooringctl` keeps the M7's admin password
//! in the legacy login keychain (revision 7); development and test lanes
//! use [`InMemorySecretStore`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mooring_model::secret::{
    SecretEntry, SecretMaterial, SecretRef, SecretSnapshot, SecretSnapshotError,
};

use mooring_model::kinds;

/// The secret store operation that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretOp {
    /// [`SecretStore::get`].
    Get,
    /// [`SecretStore::put`].
    Put,
    /// [`SecretStore::delete`].
    Delete,
}

impl fmt::Display for SecretOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Get => "get",
            Self::Put => "put",
            Self::Delete => "delete",
        })
    }
}

/// A secret store operation failed. Errors never carry secret material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretStoreError {
    /// No item exists for the reference.
    #[error("secret {secret_ref} is missing")]
    SecretMissing {
        /// The missing reference.
        secret_ref: SecretRef,
    },
    /// The Keychain refused the operation.
    #[error("keychain {op} failed with OSStatus {status}")]
    Keychain {
        /// The operation.
        op: SecretOp,
        /// The `OSStatus` the Security framework returned.
        status: i32,
    },
    /// The item stored under the reference is not valid UTF-8 text of
    /// the material its reference names; the text is never echoed.
    #[error("the item stored as {secret_ref} is not valid {} material", secret_ref.kind())]
    ItemInvalid {
        /// The reference whose item is invalid.
        secret_ref: SecretRef,
    },
}

kinds! {
    /// The kind of a [`SecretStoreError`], without its details.
    pub enum SecretStoreErrorKind {
        /// See [`SecretStoreError::SecretMissing`].
        SecretMissing,
        /// See [`SecretStoreError::Keychain`].
        Keychain,
        /// See [`SecretStoreError::ItemInvalid`].
        ItemInvalid,
    }
}

impl SecretStoreError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> SecretStoreErrorKind {
        match self {
            Self::SecretMissing { .. } => SecretStoreErrorKind::SecretMissing,
            Self::Keychain { .. } => SecretStoreErrorKind::Keychain,
            Self::ItemInvalid { .. } => SecretStoreErrorKind::ItemInvalid,
        }
    }
}

/// Stores secret material by [`SecretRef`].
///
/// Callers never order secret and state writes by hand:
/// [`crate::update_config_with_secrets`] writes new secrets before the
/// state that references them and deletes secrets only after the state
/// stops referencing them.
pub trait SecretStore {
    /// The material stored under `secret_ref`; `SecretMissing` if there is none.
    fn get(&self, secret_ref: &SecretRef) -> Result<SecretMaterial, SecretStoreError>;

    /// Stores `entry`, replacing any item already stored under its reference.
    fn put(&mut self, entry: SecretEntry) -> Result<(), SecretStoreError>;

    /// Deletes the item stored under `secret_ref`; `SecretMissing` if there is none.
    fn delete(&mut self, secret_ref: &SecretRef) -> Result<(), SecretStoreError>;
}

/// Reading a [`SecretSnapshot`] from a [`SecretStore`] failed.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotReadError {
    /// The store could not supply an item: it is missing, the Keychain
    /// refused, or its material is not of the kind its reference names
    /// (`ItemInvalid`).
    #[error(transparent)]
    Store(#[from] SecretStoreError),
    /// The snapshot refused an item. Distinct references never trip this;
    /// it is kept as a typed error rather than assumed away.
    #[error(transparent)]
    Snapshot(#[from] SecretSnapshotError),
}

kinds! {
    /// The kind of a [`SnapshotReadError`], without its details.
    pub enum SnapshotReadErrorKind {
        /// See [`SnapshotReadError::Store`].
        Store,
        /// See [`SnapshotReadError::Snapshot`].
        Snapshot,
    }
}

impl SnapshotReadError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> SnapshotReadErrorKind {
        match self {
            Self::Store(_) => SnapshotReadErrorKind::Store,
            Self::Snapshot(_) => SnapshotReadErrorKind::Snapshot,
        }
    }
}

/// Reads exactly `refs` from `store` into a snapshot, in ascending order,
/// stopping at the first failure; nothing else the store holds is read.
/// (For a user export, `refs` is what `mooring_export::export_secret_refs`
/// lists, so only the secrets the file needs are read.)
pub fn read_snapshot(
    store: &dyn SecretStore,
    refs: &BTreeSet<SecretRef>,
) -> Result<SecretSnapshot, SnapshotReadError> {
    let mut snapshot = SecretSnapshot::new();
    for secret_ref in refs {
        let material = store.get(secret_ref)?;
        let entry = SecretEntry::new(secret_ref.clone(), material).map_err(|_| {
            SecretStoreError::ItemInvalid {
                secret_ref: secret_ref.clone(),
            }
        })?;
        snapshot.insert(entry)?;
    }
    Ok(snapshot)
}

/// A [`SecretStore`] held in process memory, for development and test lanes.
/// Its materials are zeroized when they are replaced, deleted or dropped.
#[derive(Default)]
pub struct InMemorySecretStore {
    items: BTreeMap<SecretRef, SecretMaterial>,
}

impl InMemorySecretStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every reference held, in ascending order.
    #[must_use]
    pub fn refs(&self) -> BTreeSet<SecretRef> {
        self.items.keys().cloned().collect()
    }

    /// The number of items held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the store holds no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Lists the references only; materials never reach `Debug` output.
impl fmt::Debug for InMemorySecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemorySecretStore")
            .field("refs", &self.items.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SecretStore for InMemorySecretStore {
    fn get(&self, secret_ref: &SecretRef) -> Result<SecretMaterial, SecretStoreError> {
        self.items
            .get(secret_ref)
            .cloned()
            .ok_or_else(|| SecretStoreError::SecretMissing {
                secret_ref: secret_ref.clone(),
            })
    }

    fn put(&mut self, entry: SecretEntry) -> Result<(), SecretStoreError> {
        let (secret_ref, material) = entry.into_parts();
        self.items.insert(secret_ref, material);
        Ok(())
    }

    fn delete(&mut self, secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        match self.items.remove(secret_ref) {
            // The removed material is zeroized when it drops here.
            Some(_material) => Ok(()),
            None => Err(SecretStoreError::SecretMissing {
                secret_ref: secret_ref.clone(),
            }),
        }
    }
}
