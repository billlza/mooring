// SPDX-License-Identifier: GPL-3.0-or-later

//! The store's typed error taxonomy (design §14, domain `store`).

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::PathBuf;

use mooring_model::collections::NonEmpty;
use mooring_model::counters::{ConfigGeneration, RuntimeRevision};
use mooring_model::error::ModelError;
use mooring_model::ids::{NodeId, UserId};
use mooring_model::secret::SecretRef;
use mooring_model::user::UserStatus;

use crate::secrets::SecretStoreError;
use mooring_model::kinds;

/// The filesystem operation that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoOp {
    /// Opening or creating `state.lock`.
    OpenLock,
    /// Checking whether `state.json` exists.
    InspectState,
    /// Reading `state.json`.
    ReadState,
    /// Removing a temporary file left behind by an interrupted write.
    RemoveStaleTemp,
    /// Creating a temporary file.
    CreateTemp,
    /// Writing a temporary file.
    WriteTemp,
    /// Flushing a temporary file to stable storage.
    SyncTemp,
    /// Renaming a temporary file over its target.
    Rename,
    /// Opening the store directory.
    OpenDir,
    /// Flushing the store directory to stable storage.
    SyncDir,
}

impl fmt::Display for IoOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenLock => "open the lock file",
            Self::InspectState => "inspect the state file",
            Self::ReadState => "read the state file",
            Self::RemoveStaleTemp => "remove a stale temporary file",
            Self::CreateTemp => "create a temporary file",
            Self::WriteTemp => "write a temporary file",
            Self::SyncTemp => "sync a temporary file",
            Self::Rename => "rename a temporary file into place",
            Self::OpenDir => "open the store directory",
            Self::SyncDir => "sync the store directory",
        })
    }
}

/// A secret that could not be deleted after the state stopped referencing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupFailure {
    /// The secret that is now orphaned.
    pub secret_ref: SecretRef,
    /// Why deleting it failed.
    pub error: SecretStoreError,
}

/// A state or secret store operation failed.
///
/// Unless a variant says otherwise, nothing was committed: `state.json` is
/// unchanged. Errors never carry secret material; the state holds none.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("failed to {op} at {}", path.display())]
    Io {
        /// The operation.
        op: IoOp,
        /// The file or directory it acted on.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// The exclusive or shared lock on `state.lock` could not be taken.
    #[error("failed to lock {}", path.display())]
    Lock {
        /// The lock file.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// `state.json` does not exist yet.
    #[error("no state at {}; initialise the store first", path.display())]
    NotInitialized {
        /// The missing state file.
        path: PathBuf,
    },
    /// `state.json` already exists, so the store cannot be initialised again.
    #[error("state already exists at {}", path.display())]
    AlreadyInitialized {
        /// The existing state file.
        path: PathBuf,
    },
    /// `state.json` is not a valid state document of a version this build reads.
    #[error("state file {} is corrupt", path.display())]
    StateCorrupt {
        /// The state file.
        path: PathBuf,
        /// Why parsing or validation failed.
        #[source]
        source: serde_json::Error,
    },
    /// `state.json` was written by a newer build; it is never downgraded.
    #[error("state version {found} is newer than version {newest}, the newest this build reads")]
    DowngradeRefused {
        /// The version found on disk.
        found: u32,
        /// The newest version this build reads and writes.
        newest: u32,
    },
    /// A migration step could not lift the state to the next version; the
    /// document on disk is valid for its own version and unchanged.
    ///
    /// In this build only `V1 → V2` can fail, with `StopPolicyUnchosen`: a
    /// version-1 SIM policy without a hard stop, which the lifted policy
    /// cannot keep (`mooring_model::v1`). Every explicit hard stop lifts.
    #[error("migrating the state from version {from} to {to} failed")]
    MigrationFailed {
        /// The version the step started from.
        from: u32,
        /// The version the step targets.
        to: u32,
        /// Why the step failed.
        #[source]
        source: ModelError,
    },
    /// The state could not be serialised.
    #[error("failed to encode the state")]
    Encode {
        /// The serialiser's error.
        #[source]
        source: serde_json::Error,
    },
    /// The configuration generation changed since the caller read the state.
    #[error("config generation is {found}, expected {expected}; re-read the state and retry")]
    GenerationConflict {
        /// The generation the caller read.
        expected: ConfigGeneration,
        /// The generation on disk.
        found: ConfigGeneration,
    },
    /// The runtime revision changed since the caller read the state.
    #[error("runtime revision is {found}, expected {expected}; re-read the state and retry")]
    RevisionConflict {
        /// The revision the caller read.
        expected: RuntimeRevision,
        /// The revision on disk.
        found: RuntimeRevision,
    },
    /// A counter cannot be bumped any further.
    #[error("a state counter cannot be bumped")]
    CounterOverflow {
        /// The counter's overflow error.
        #[source]
        source: ModelError,
    },
    /// The change edited the configuration generation, which only the store sets.
    #[error("the change set config generation {returned}; only the store bumps it from {received}")]
    GenerationEdited {
        /// The generation the change received.
        received: ConfigGeneration,
        /// The generation the change returned.
        returned: ConfigGeneration,
    },
    /// The change set, replaced or lowered a node's confirmed generation,
    /// which only a `Bookkeeping::Applied` record sets (design §7). Moving
    /// a node out of `Applied` is not such an edit.
    #[error(
        "the change edited node {node}'s confirmed generation; only a Bookkeeping::Applied record sets it"
    )]
    AppliedEdited {
        /// The node whose confirmed generation the change edited.
        node: NodeId,
    },
    /// The change moved a user's status outside the user transitions
    /// (`User::suspend`, `resume`, `revoke`; design §7), or removed a user
    /// who still holds credentials or is pending revocation: a revocation
    /// in progress settles only through `Bookkeeping` and never goes back.
    /// `to` is `None` when the change removed the user.
    #[error(
        "the change moved user {user} from {from:?} to {to:?}; a status changes only by suspend, resume and revoke, a revocation settles only through Bookkeeping, and only a revoked user may be removed"
    )]
    UserStatusEdited {
        /// The user.
        user: UserId,
        /// The user's status before the change.
        from: UserStatus,
        /// The status the change left; `None` if it removed the user.
        to: Option<UserStatus>,
    },
    /// A change, or the initial deployment ([`crate::Store::init`]), breaks
    /// a model invariant.
    #[error("the new or changed deployment is invalid")]
    InvalidChange {
        /// The invariant that failed.
        #[source]
        source: ModelError,
    },
    /// A change that adds or removes secret references went through a write
    /// that cannot order secret writes; use
    /// [`update_config_with_secrets`](crate::update_config_with_secrets).
    #[error(
        "the change adds secrets [{}] and removes secrets [{}]; use the ordered secret update",
        RefList(added),
        RefList(removed)
    )]
    SecretRefsChanged {
        /// References the new state adds.
        added: BTreeSet<SecretRef>,
        /// References the new state drops.
        removed: BTreeSet<SecretRef>,
    },
    /// The secrets supplied are not exactly those the change newly references.
    #[error(
        "the change needs new secrets [{}] that were not supplied, and was given [{}] that it does not reference",
        RefList(missing),
        RefList(unreferenced)
    )]
    SecretPlanMismatch {
        /// Newly referenced secrets without supplied material.
        missing: BTreeSet<SecretRef>,
        /// Supplied secrets the new state does not newly reference.
        unreferenced: BTreeSet<SecretRef>,
    },
    /// The same secret was supplied twice.
    #[error("secret {secret_ref} was supplied twice")]
    DuplicateSecret {
        /// The duplicated reference.
        secret_ref: SecretRef,
    },
    /// Writing a new secret failed, so the state was not written. Secrets
    /// written earlier in the same update are orphaned (`doctor` lists them).
    #[error("writing secret {secret_ref} failed; the state is unchanged")]
    SecretWrite {
        /// The secret being written.
        secret_ref: SecretRef,
        /// The secret store's error.
        #[source]
        source: SecretStoreError,
    },
    /// The state **was committed**, but deleting secrets it no longer
    /// references failed; those secrets are orphaned (`doctor` lists them).
    #[error(
        "state committed at config generation {committed}, but deleting secrets failed: {}",
        FailureList(failures)
    )]
    SecretCleanup {
        /// The generation that was committed.
        committed: ConfigGeneration,
        /// Every deletion that failed.
        failures: NonEmpty<CleanupFailure>,
    },
}

kinds! {
    /// The kind of a [`StoreError`], without its details.
    pub enum StoreErrorKind {
        /// See [`StoreError::Io`].
        Io,
        /// See [`StoreError::Lock`].
        Lock,
        /// See [`StoreError::NotInitialized`].
        NotInitialized,
        /// See [`StoreError::AlreadyInitialized`].
        AlreadyInitialized,
        /// See [`StoreError::StateCorrupt`].
        StateCorrupt,
        /// See [`StoreError::DowngradeRefused`].
        DowngradeRefused,
        /// See [`StoreError::MigrationFailed`].
        MigrationFailed,
        /// See [`StoreError::Encode`].
        Encode,
        /// See [`StoreError::GenerationConflict`].
        GenerationConflict,
        /// See [`StoreError::RevisionConflict`].
        RevisionConflict,
        /// See [`StoreError::CounterOverflow`].
        CounterOverflow,
        /// See [`StoreError::GenerationEdited`].
        GenerationEdited,
        /// See [`StoreError::AppliedEdited`].
        AppliedEdited,
        /// See [`StoreError::UserStatusEdited`].
        UserStatusEdited,
        /// See [`StoreError::InvalidChange`].
        InvalidChange,
        /// See [`StoreError::SecretRefsChanged`].
        SecretRefsChanged,
        /// See [`StoreError::SecretPlanMismatch`].
        SecretPlanMismatch,
        /// See [`StoreError::DuplicateSecret`].
        DuplicateSecret,
        /// See [`StoreError::SecretWrite`].
        SecretWrite,
        /// See [`StoreError::SecretCleanup`].
        SecretCleanup,
    }
}

impl StoreError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> StoreErrorKind {
        match self {
            Self::Io { .. } => StoreErrorKind::Io,
            Self::Lock { .. } => StoreErrorKind::Lock,
            Self::NotInitialized { .. } => StoreErrorKind::NotInitialized,
            Self::AlreadyInitialized { .. } => StoreErrorKind::AlreadyInitialized,
            Self::StateCorrupt { .. } => StoreErrorKind::StateCorrupt,
            Self::DowngradeRefused { .. } => StoreErrorKind::DowngradeRefused,
            Self::MigrationFailed { .. } => StoreErrorKind::MigrationFailed,
            Self::Encode { .. } => StoreErrorKind::Encode,
            Self::GenerationConflict { .. } => StoreErrorKind::GenerationConflict,
            Self::RevisionConflict { .. } => StoreErrorKind::RevisionConflict,
            Self::CounterOverflow { .. } => StoreErrorKind::CounterOverflow,
            Self::GenerationEdited { .. } => StoreErrorKind::GenerationEdited,
            Self::AppliedEdited { .. } => StoreErrorKind::AppliedEdited,
            Self::UserStatusEdited { .. } => StoreErrorKind::UserStatusEdited,
            Self::InvalidChange { .. } => StoreErrorKind::InvalidChange,
            Self::SecretRefsChanged { .. } => StoreErrorKind::SecretRefsChanged,
            Self::SecretPlanMismatch { .. } => StoreErrorKind::SecretPlanMismatch,
            Self::DuplicateSecret { .. } => StoreErrorKind::DuplicateSecret,
            Self::SecretWrite { .. } => StoreErrorKind::SecretWrite,
            Self::SecretCleanup { .. } => StoreErrorKind::SecretCleanup,
        }
    }
}

/// A change to the state failed, either in the store or in the caller's
/// change function.
#[derive(Debug, thiserror::Error)]
pub enum ChangeError<E> {
    /// The store refused or failed the write; see [`StoreError`] for what
    /// was committed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The caller's change function refused the change; nothing was written.
    #[error("the change was refused")]
    Refused(#[source] E),
}

kinds! {
    /// The kind of a [`ChangeError`], without its details.
    pub enum ChangeErrorKind {
        /// See [`ChangeError::Store`].
        Store,
        /// See [`ChangeError::Refused`].
        Refused,
    }
}

impl<E> ChangeError<E> {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> ChangeErrorKind {
        match self {
            Self::Store(_) => ChangeErrorKind::Store,
            Self::Refused(_) => ChangeErrorKind::Refused,
        }
    }
}

/// Displays secret references as a comma-separated list.
struct RefList<'a>(&'a BTreeSet<SecretRef>);

impl fmt::Display for RefList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, secret_ref) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{secret_ref}")?;
        }
        Ok(())
    }
}

/// Displays cleanup failures as a semicolon-separated list.
struct FailureList<'a>(&'a NonEmpty<CleanupFailure>);

impl fmt::Display for FailureList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, failure) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{}: {}", failure.secret_ref, failure.error)?;
        }
        Ok(())
    }
}
