// SPDX-License-Identifier: GPL-3.0-or-later

//! Ordered state and secret writes (design §7): secrets are written before
//! any state that references them, and on deletion the state is updated
//! before the secrets are removed.
//!
//! A failure therefore never leaves the state referencing a missing secret;
//! at worst it leaves orphaned secrets, which `mooringctl doctor` lists.

use std::collections::BTreeSet;

use mooring_model::collections::NonEmpty;
use mooring_model::counters::ConfigGeneration;
use mooring_model::deployment::{Bookkeeping, DeploymentParts};
use mooring_model::secret::SecretRef;
use mooring_model::state::StateV1;

use crate::error::{ChangeError, CleanupFailure, StoreError};
use mooring_model::secret::SecretEntry;

use crate::secrets::SecretStore;
use crate::store::{Store, change_config, record_entry};

/// Applies a configuration change that may add or remove secret
/// references, ordering the secret writes around the state write.
///
/// Under the exclusive state lock, if the configuration generation is still
/// `expected`:
///
/// 1. `change` produces the new deployment (generation `expected + 1`),
///    with the rules of [`Store::update_config`] except that the referenced
///    secrets may change;
/// 2. `new_secrets` must hold exactly the secrets the new state references
///    and the current one does not (`SecretPlanMismatch` otherwise), each
///    once (`DuplicateSecret`); nothing has been written yet;
/// 3. every new secret is written to `secrets` (replacing an orphaned item
///    with the same reference, which nothing references);
/// 4. the state is written durably;
/// 5. every secret the current state references and the new one does not
///    is deleted from `secrets`, before the lock is released, so no other
///    update can reuse a reference in between.
///
/// `secrets` must not call back into `store`: it runs under the lock.
///
/// If step 3 fails, the state is unchanged and the secrets written so far
/// are orphaned (`SecretWrite`). If step 5 fails for some secrets, the
/// state **is committed**, the rest are still deleted, and the failures are
/// reported as `SecretCleanup`.
pub fn update_config_with_secrets<S, E, F>(
    store: &Store,
    secrets: &mut S,
    expected: ConfigGeneration,
    new_secrets: Vec<SecretEntry>,
    change: F,
) -> Result<StateV1, ChangeError<E>>
where
    S: SecretStore + ?Sized,
    F: FnOnce(DeploymentParts) -> Result<DeploymentParts, E>,
{
    let (txn, current) = store.begin()?;
    let old_refs = current.deployment.required_secrets();
    let next = change_config(current, expected, change)?;
    let SecretPlan { new, dropped } =
        SecretPlan::new(&old_refs, &next.deployment.required_secrets(), new_secrets)?;
    write_new(secrets, new)?;
    let lock = txn.commit(&next)?;
    let cleanup = delete_dropped(secrets, &dropped);
    drop(lock);
    cleanup.map_err(|failures| StoreError::SecretCleanup {
        committed: next.deployment.config_generation(),
        failures,
    })?;
    Ok(next)
}

/// Records progress that changes no rendered bundle and no export
/// ([`Bookkeeping`], design §7), keeping the configuration generation, and
/// deletes the secrets it stops referencing: a revoked user's credentials
/// on a node that committed the revocation (§13.5 step 3), or a retired
/// node's and its users' secrets (§13.4 step 3).
///
/// Under the exclusive state lock, if the generation is still `expected`:
/// the record is applied (it never adds a secret reference; one that did
/// would be refused with `SecretPlanMismatch`), the state is written
/// durably, and every secret it no longer references is deleted before the
/// lock is released. If a deletion fails the state **is committed** and
/// the failures are reported as `SecretCleanup`, as for
/// [`update_config_with_secrets`].
pub fn record_with_secrets<S>(
    store: &Store,
    secrets: &mut S,
    expected: ConfigGeneration,
    entry: Bookkeeping,
) -> Result<StateV1, StoreError>
where
    S: SecretStore + ?Sized,
{
    let (txn, current) = store.begin()?;
    let old_refs = current.deployment.required_secrets();
    let next = record_entry(current, expected, entry)?;
    let SecretPlan { dropped, .. } =
        SecretPlan::new(&old_refs, &next.deployment.required_secrets(), Vec::new())?;
    let lock = txn.commit(&next)?;
    let cleanup = delete_dropped(secrets, &dropped);
    drop(lock);
    cleanup.map_err(|failures| StoreError::SecretCleanup {
        committed: next.deployment.config_generation(),
        failures,
    })?;
    Ok(next)
}

/// The secret writes one update performs, checked before any of them.
struct SecretPlan {
    /// Secrets the new state references and the current one does not.
    new: Vec<SecretEntry>,
    /// Secrets the current state references and the new one does not.
    dropped: BTreeSet<SecretRef>,
}

impl SecretPlan {
    fn new(
        old: &BTreeSet<SecretRef>,
        new: &BTreeSet<SecretRef>,
        supplied: Vec<SecretEntry>,
    ) -> Result<Self, StoreError> {
        let mut supplied_refs = BTreeSet::new();
        for entry in &supplied {
            if !supplied_refs.insert(entry.secret_ref()) {
                return Err(StoreError::DuplicateSecret {
                    secret_ref: entry.secret_ref(),
                });
            }
        }
        let added: BTreeSet<SecretRef> = new.difference(old).cloned().collect();
        if supplied_refs != added {
            return Err(StoreError::SecretPlanMismatch {
                missing: added.difference(&supplied_refs).cloned().collect(),
                unreferenced: supplied_refs.difference(&added).cloned().collect(),
            });
        }
        Ok(Self {
            new: supplied,
            dropped: old.difference(new).cloned().collect(),
        })
    }
}

/// Writes every new secret, stopping at the first failure.
fn write_new<S: SecretStore + ?Sized>(
    secrets: &mut S,
    new: Vec<SecretEntry>,
) -> Result<(), StoreError> {
    for entry in new {
        let secret_ref = entry.secret_ref();
        secrets
            .put(entry)
            .map_err(|source| StoreError::SecretWrite { secret_ref, source })?;
    }
    Ok(())
}

/// Deletes every dropped secret, continuing past failures so as few
/// orphans as possible remain, and reports every failure.
fn delete_dropped<S: SecretStore + ?Sized>(
    secrets: &mut S,
    dropped: &BTreeSet<SecretRef>,
) -> Result<(), NonEmpty<CleanupFailure>> {
    let mut failures = Vec::new();
    for secret_ref in dropped {
        if let Err(error) = secrets.delete(secret_ref) {
            failures.push(CleanupFailure {
                secret_ref: secret_ref.clone(),
                error,
            });
        }
    }
    let mut failures = failures.into_iter();
    match failures.next() {
        None => Ok(()),
        Some(first) => Err(NonEmpty::from_parts(first, failures.collect())),
    }
}
