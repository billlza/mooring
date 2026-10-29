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
//! `state.json` carries `{"version": N, …}`; this build writes version 2
//! and reads versions 1 and 2. A newer version is refused
//! (`DowngradeRefused`); an older one is lifted by [`migrate`], a chain of
//! pure functions (`V1 → V2`), and the first write after lifting backs up
//! the original document to `state.json.bak-<from>-<to>` (fsynced) before
//! writing the new version. A document the chain cannot lift is refused
//! (`MigrationFailed`) and left as it is.
//!
//! # The router identity
//!
//! Beside the state, [`write_router_pin`] records the M7 gateway's
//! link-layer address and the Mac's interface to it as
//! `router-identity.json` (same durable write, mode 0600, under the same
//! lock), and [`read_router_pin`] reads it back, a version-1 file without
//! the interface too (design §15.6 rule 4, §5.1).
//!
//! # The own networks
//!
//! Beside the state too, [`declare_allowed_network`] and
//! [`revoke_allowed_network`] keep the operator's own-network declarations
//! (design §10.2, P0-2) in `allowed-networks.json`, each a read-modify-write
//! under the same lock with the same durable write, and
//! [`read_allowed_networks`] reads them back without the lock, as the daemon
//! does every tick; an absent file is no declaration.
//!
//! # The status snapshot
//!
//! [`write_status_snapshot`] replaces `status.json`, the daemon's copy of
//! its latest console status for diagnosis, with the same durable write
//! (design §10.1).
//!
//! # The SIM meter
//!
//! [`write_sim_meter`] replaces `usage/sim-meter.json`, the line's bytes per
//! UTC day, and [`read_sim_meter`] reads it back with a bound; the daemon
//! encodes and decodes it (design §10.1).
//!
//! # Secrets
//!
//! The state holds no secrets. They live in a [`SecretStore`]; the
//! data-protection Keychain implementation is part of milestone M5 (until
//! then `mooringctl` implements it over the legacy login keychain for the
//! M7's admin password), and [`InMemorySecretStore`] serves development and
//! test lanes. The state
//! writes above refuse any change to the set of referenced secrets; such
//! changes go through [`update_config_with_secrets`], which writes new
//! secrets before the state that references them and deletes dropped ones
//! only after the state stops referencing them.

#![deny(missing_docs)]

mod allowed_networks;
mod durable;
mod error;
mod latch;
mod migrate;
mod ordered;
mod router_pin;
mod secrets;
mod sim_meter;
mod status_snapshot;
mod store;
#[cfg(test)]
mod tests;

pub use allowed_networks::{
    ALLOWED_NETWORKS_FILE, AllowedNetworksFault, Declaration, MAX_ALLOWED_NETWORKS_BYTES,
    declare_allowed_network, read_allowed_networks, revoke_allowed_network,
};
pub use error::{ChangeError, ChangeErrorKind, CleanupFailure, IoOp, StoreError, StoreErrorKind};
pub use latch::{LATCH_FILE, clear_latch, read_latch, write_latch};
pub use migrate::migrate;
pub use ordered::{record_with_secrets, update_config_with_secrets};
pub use router_pin::{
    MAX_ROUTER_PIN_BYTES, ROUTER_PIN_FILE, RouterPin, RouterPinFault, StoredPin, read_router_pin,
    write_router_pin,
};
pub use secrets::{
    InMemorySecretStore, SecretOp, SecretStore, SecretStoreError, SecretStoreErrorKind,
    SnapshotReadError, SnapshotReadErrorKind, read_snapshot,
};
pub use sim_meter::{SIM_METER_FILE, USAGE_DIRECTORY, read_sim_meter, write_sim_meter};
pub use status_snapshot::{STATUS_SNAPSHOT_FILE, write_status_snapshot};
pub use store::{LOCK_FILE, STATE_FILE, Store};
