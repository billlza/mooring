// SPDX-License-Identifier: GPL-3.0-or-later

//! Mooring's persistent state and the secret store abstraction (design §7).
//!
//! # State
//!
//! [`Store`] keeps the non-secret state, `state.json`, in a directory the
//! caller passes in. Writes follow four rules:
//!
//! - an exclusive lock is taken on `state.lock` (`std::fs::File::lock`) for
//!   the whole read-modify-write;
//! - compare-and-swap on a counter: [`Store::update_config`] checks and
//!   bumps the `ConfigGeneration`, [`Store::set_exit_enabled`] the
//!   `RuntimeRevision` only, so enabling the exit never makes a node look
//!   stale; [`Store::record`] and [`record_with_secrets`] check the
//!   generation without bumping it, and accept only the model's typed
//!   `Bookkeeping` records, which change no rendered bundle or export, so
//!   every other change bumps it (design §7). Only a `Bookkeeping::Applied`
//!   record sets a node's confirmed generation: a configuration change
//!   that edits one is refused (`AppliedEdited`);
//! - each write goes temp file → fsync → rename → directory fsync, with
//!   mode 0600, so `state.json` is never partially written;
//! - the CLI is the only writer.
//!
//! # Migrations
//!
//! `state.json` carries `{"version": N, …}`. A newer version is refused
//! (`DowngradeRefused`); an older one is lifted by [`migrate`], a chain of
//! pure functions, and the first write after lifting backs up the original
//! document to `state.json.bak-<from>-<to>` (fsynced) before writing the
//! new version.
//!
//! # Secrets
//!
//! The state holds no secrets. They live in a [`SecretStore`]; the
//! Keychain implementation is part of milestone M5, and
//! [`InMemorySecretStore`] serves development and test lanes. The state
//! writes above refuse any change to the set of referenced secrets; such
//! changes go through [`update_config_with_secrets`], which writes new
//! secrets before the state that references them and deletes dropped ones
//! only after the state stops referencing them.

#![deny(missing_docs)]

mod durable;
mod error;
mod migrate;
mod ordered;
mod secrets;
mod store;
#[cfg(test)]
mod tests;

pub use error::{ChangeError, ChangeErrorKind, CleanupFailure, IoOp, StoreError, StoreErrorKind};
pub use migrate::migrate;
pub use ordered::{record_with_secrets, update_config_with_secrets};
pub use secrets::{
    InMemorySecretStore, SecretOp, SecretStore, SecretStoreError, SecretStoreErrorKind,
};
pub use store::{LOCK_FILE, STATE_FILE, Store};
