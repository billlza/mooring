// SPDX-License-Identifier: GPL-3.0-or-later

//! The state store (design §7): `state.json` under an exclusive lock, with
//! compare-and-swap on the state counters and durable atomic writes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use mooring_model::counters::{ConfigGeneration, RuntimeRevision};
use mooring_model::deployment::{Bookkeeping, Deployment, DeploymentInit, DeploymentParts};
use mooring_model::error::ModelError;
use mooring_model::ids::{NodeId, UserId};
use mooring_model::node::AppliedConfig;
use mooring_model::secret::SecretRef;
use mooring_model::sim::SimPolicy;
use mooring_model::state::{RuntimeIntent, StateFile, StateV2};
use mooring_model::user::UserStatus;

use crate::durable::{self, LockMode, StateLock};
use crate::error::{ChangeError, StoreError};
use crate::migrate;

/// The state document's file name.
pub const STATE_FILE: &str = "state.json";

/// The lock file's file name. It is created on first use and never removed.
pub const LOCK_FILE: &str = "state.lock";

/// The non-secret state of one Mooring installation, kept in one directory
/// as `state.json`, guarded by `state.lock`.
///
/// Every write takes the exclusive lock for the whole read-modify-write,
/// checks the counter the caller read (compare-and-swap), bumps the counter
/// the change belongs to, and replaces `state.json` durably and atomically
/// (mode 0600). Reads take the shared lock, so they only ever see durable
/// states. A document of an older version is lifted in memory on read and
/// written back, after a backup, by the next write.
///
/// The store never reads `HOME`: callers pass the directory, which must
/// already exist (for example `~/Library/Application Support/Mooring`).
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// A store rooted at `dir`. No I/O happens until the first operation.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory the store lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path of `state.json`.
    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }

    /// The path of `state.lock`.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join(LOCK_FILE)
    }

    /// The path of the backup written before a document of version `from`
    /// is first written back as version `to`: `state.json.bak-<from>-<to>`.
    #[must_use]
    pub fn backup_path(&self, from: u32, to: u32) -> PathBuf {
        self.dir.join(backup_name(from, to))
    }

    /// Creates `state.json` holding a fresh deployment of `init` (no nodes,
    /// users or viewers; every record as `init` gives it) and a disabled
    /// exit. It references no secrets. `InvalidChange` if `init` breaks a
    /// model invariant (`PlanNotRecorded` unless the exit's SIM plan is
    /// recorded), checked before anything is read or written.
    pub fn init(&self, init: DeploymentInit) -> Result<StateV2, StoreError> {
        let deployment =
            Deployment::new(init).map_err(|source| StoreError::InvalidChange { source })?;
        let _lock = StateLock::acquire(&self.lock_path(), LockMode::Exclusive)?;
        let path = self.state_path();
        if durable::state_exists(&path)? {
            return Err(StoreError::AlreadyInitialized { path });
        }
        let state = StateV2 {
            deployment,
            runtime: RuntimeIntent::new(),
        };
        durable::write_durably(&self.dir, STATE_FILE, &encode(&state)?)?;
        Ok(state)
    }

    /// Reads the state, lifted to the newest version. Nothing is written,
    /// even when the document on disk is older.
    pub fn load(&self) -> Result<StateV2, StoreError> {
        let _lock = StateLock::acquire(&self.lock_path(), LockMode::Shared)?;
        let path = self.state_path();
        let bytes = durable::read_state(&path)?;
        Ok(migrate::decode(&path, &bytes)?.state)
    }

    /// Applies a change to the deployment, if the configuration generation
    /// is still `expected`; the new state has generation `expected + 1` and
    /// the same runtime intent. Every change made through a closure bumps
    /// the generation: only the typed [`Bookkeeping`] records of
    /// [`Store::record`] keep it, because only they are known to change no
    /// rendered bundle and no export (design §7).
    ///
    /// `change` receives the current deployment's parts under the exclusive
    /// lock and returns the new parts. Keep it quick and free of I/O, and
    /// never call back into the store from it: that would wait forever for
    /// the lock it runs under. It must leave `config_generation` as
    /// received, because only the store sets it (`GenerationEdited`). It
    /// must not set, replace or lower any node's confirmed generation
    /// (`AppliedEdited`), because only a node's own confirmation, recorded
    /// as `Bookkeeping::Applied`, sets it; moving a node out of `Applied` is
    /// allowed. It may change a user's status only along the user
    /// transitions, and remove only a revoked user (`UserStatusEdited`):
    /// a revocation settles only through `Bookkeeping`. It may edit the
    /// exit's SIM policy only to one whose plan is recorded
    /// (`InvalidChange{PlanNotRecorded}`, P0-1). And it must not
    /// change which secrets the state references:
    /// such changes go through [`crate::update_config_with_secrets`], which
    /// orders the secret writes.
    pub fn update_config<E, F>(
        &self,
        expected: ConfigGeneration,
        change: F,
    ) -> Result<StateV2, ChangeError<E>>
    where
        F: FnOnce(DeploymentParts) -> Result<DeploymentParts, E>,
    {
        let (txn, current) = self.begin()?;
        let old_refs = current.deployment.required_secrets();
        let next = change_config(current, expected, change)?;
        require_same_refs(&old_refs, &next.deployment.required_secrets())?;
        txn.commit(&next)?;
        Ok(next)
    }

    /// Records progress that changes no rendered bundle and no export (a
    /// node confirmed a generation; design §7), if the configuration
    /// generation is still `expected`; the generation is checked and kept.
    ///
    /// A record that drops secret references (a committed revocation, a
    /// shut-down retirement) is refused with `SecretRefsChanged`: it goes
    /// through [`crate::record_with_secrets`], which deletes the dropped
    /// secrets after the state stops referencing them.
    pub fn record(
        &self,
        expected: ConfigGeneration,
        entry: Bookkeeping,
    ) -> Result<StateV2, StoreError> {
        let (txn, current) = self.begin()?;
        let old_refs = current.deployment.required_secrets();
        let next = record_entry(current, expected, entry)?;
        require_same_refs(&old_refs, &next.deployment.required_secrets())?;
        txn.commit(&next)?;
        Ok(next)
    }

    /// Enables or disables the exit, if the runtime revision is still
    /// `expected`; the new state has revision `expected + 1` and the same
    /// deployment, so its configuration generation does not change.
    pub fn set_exit_enabled(
        &self,
        expected: RuntimeRevision,
        exit_enabled: bool,
    ) -> Result<StateV2, StoreError> {
        let (txn, current) = self.begin()?;
        let found = current.runtime.revision;
        if found != expected {
            return Err(StoreError::RevisionConflict { expected, found });
        }
        let revision = expected.next().map_err(counter_overflow)?;
        let next = StateV2 {
            deployment: current.deployment,
            runtime: RuntimeIntent {
                exit_enabled,
                revision,
            },
        };
        txn.commit(&next)?;
        Ok(next)
    }

    /// Takes the exclusive lock and reads the current state for one
    /// read-modify-write.
    pub(crate) fn begin(&self) -> Result<(Txn<'_>, StateV2), StoreError> {
        let lock = StateLock::acquire(&self.lock_path(), LockMode::Exclusive)?;
        let path = self.state_path();
        let bytes = durable::read_state(&path)?;
        let decoded = migrate::decode(&path, &bytes)?;
        let backup = (decoded.from != StateFile::CURRENT_VERSION).then_some(PendingBackup {
            from: decoded.from,
            original: bytes,
        });
        let txn = Txn {
            store: self,
            lock,
            backup,
        };
        Ok((txn, decoded.state))
    }
}

/// The original bytes of a document that was lifted from an older version.
#[derive(Debug)]
struct PendingBackup {
    from: u32,
    original: Vec<u8>,
}

/// One read-modify-write holding the exclusive lock.
#[derive(Debug)]
pub(crate) struct Txn<'a> {
    store: &'a Store,
    lock: StateLock,
    backup: Option<PendingBackup>,
}

impl Txn<'_> {
    /// Writes `state` durably. If the document on disk was lifted from an
    /// older version, its original bytes are first written durably to
    /// `state.json.bak-<from>-<to>`. Returns the lock, so the caller can
    /// finish work that must precede any other writer before releasing it.
    pub(crate) fn commit(self, state: &StateV2) -> Result<StateLock, StoreError> {
        let bytes = encode(state)?;
        let dir = &self.store.dir;
        if let Some(backup) = &self.backup {
            let name = backup_name(backup.from, StateFile::CURRENT_VERSION);
            durable::write_durably(dir, &name, &backup.original)?;
        }
        durable::write_durably(dir, STATE_FILE, &bytes)?;
        Ok(self.lock)
    }
}

/// Requires the generation on disk to be `expected`.
fn require_generation(current: &StateV2, expected: ConfigGeneration) -> Result<(), StoreError> {
    let found = current.deployment.config_generation();
    if found == expected {
        Ok(())
    } else {
        Err(StoreError::GenerationConflict { expected, found })
    }
}

/// Checks the generation, applies `change` and stamps the next generation;
/// the result is a validated state with the same runtime intent, in which
/// every node's confirmed generation is the one it had before.
pub(crate) fn change_config<E, F>(
    current: StateV2,
    expected: ConfigGeneration,
    change: F,
) -> Result<StateV2, ChangeError<E>>
where
    F: FnOnce(DeploymentParts) -> Result<DeploymentParts, E>,
{
    require_generation(&current, expected)?;
    let stamped = expected.next().map_err(counter_overflow)?;
    let confirmed = confirmed_generations(&current.deployment);
    let statuses = user_statuses(&current.deployment);
    let sim = current.deployment.exit().sim.clone();
    let parts = change(current.deployment.into_parts()).map_err(ChangeError::Refused)?;
    if parts.config_generation != expected {
        return Err(StoreError::GenerationEdited {
            received: expected,
            returned: parts.config_generation,
        }
        .into());
    }
    let deployment = Deployment::try_from(DeploymentParts {
        config_generation: stamped,
        ..parts
    })
    .map_err(|source| StoreError::InvalidChange { source })?;
    require_confirmations_kept(&confirmed, &deployment)?;
    require_user_transitions(&statuses, &deployment)?;
    require_recorded_plan_if_edited(&sim, &deployment)?;
    Ok(StateV2 {
        deployment,
        runtime: current.runtime,
    })
}

/// The generation and digest each applied node confirmed.
fn confirmed_generations(deployment: &Deployment) -> BTreeMap<NodeId, AppliedConfig> {
    deployment
        .nodes()
        .iter()
        .filter_map(|(id, node)| Some((id.clone(), *node.lifecycle.applied()?)))
        .collect()
}

/// Refuses a change that leaves any node with a confirmed generation it did
/// not have before: only a node's confirmation (`Bookkeeping::Applied`)
/// records one, so a closure can never make a node look as if it serves a
/// configuration it never applied (design §7).
fn require_confirmations_kept(
    before: &BTreeMap<NodeId, AppliedConfig>,
    after: &Deployment,
) -> Result<(), StoreError> {
    for (id, node) in after.nodes() {
        if let Some(applied) = node.lifecycle.applied()
            && before.get(id) != Some(applied)
        {
            return Err(StoreError::AppliedEdited { node: id.clone() });
        }
    }
    Ok(())
}

/// Every user's status.
fn user_statuses(deployment: &Deployment) -> BTreeMap<UserId, UserStatus> {
    deployment
        .users()
        .iter()
        .map(|(id, user)| (id.clone(), user.status))
        .collect()
}

/// Refuses a change that moves a user's status other than by the user
/// transitions, or removes a user who is not revoked
/// (`UserStatus::may_change_to`, `may_be_removed`): the model documents
/// the transitions, and this is where a closure could otherwise skip them,
/// as it could forge a confirmation (design §7). A new user may start in
/// any status the model accepts.
fn require_user_transitions(
    before: &BTreeMap<UserId, UserStatus>,
    after: &Deployment,
) -> Result<(), StoreError> {
    for (id, &from) in before {
        let to = after.users().get(id).map(|user| user.status);
        let allowed = match to {
            Some(to) => from.may_change_to(to),
            None => from.may_be_removed(),
        };
        if !allowed {
            return Err(StoreError::UserStatusEdited {
                user: id.clone(),
                from,
                to,
            });
        }
    }
    Ok(())
}

/// Refuses a change that edits the exit's SIM policy and leaves its plan
/// unrecorded (P0-1, design §7): `InvalidChange{PlanNotRecorded}`, as for
/// [`Store::init`]. The public API builds only recorded policies, but a
/// policy decoded from a document may hold `"plan": null`, and a closure
/// could otherwise swap one in, un-recording a recorded plan or retuning a
/// lifted policy without recording its plan. A lifted state whose policy
/// the change leaves as it is takes every other change.
fn require_recorded_plan_if_edited(
    before: &SimPolicy,
    after: &Deployment,
) -> Result<(), StoreError> {
    let sim = &after.exit().sim;
    if sim != before && sim.plan().is_none() {
        return Err(StoreError::InvalidChange {
            source: ModelError::PlanNotRecorded,
        });
    }
    Ok(())
}

/// Checks the generation and applies a bookkeeping record, which keeps it;
/// the result is a validated state with the same runtime intent.
pub(crate) fn record_entry(
    current: StateV2,
    expected: ConfigGeneration,
    entry: Bookkeeping,
) -> Result<StateV2, StoreError> {
    require_generation(&current, expected)?;
    let deployment = current
        .deployment
        .record(entry)
        .map_err(|source| StoreError::InvalidChange { source })?;
    Ok(StateV2 {
        deployment,
        runtime: current.runtime,
    })
}

/// Refuses a change to the set of referenced secrets.
fn require_same_refs(
    old: &BTreeSet<SecretRef>,
    new: &BTreeSet<SecretRef>,
) -> Result<(), StoreError> {
    if old == new {
        Ok(())
    } else {
        Err(StoreError::SecretRefsChanged {
            added: new.difference(old).cloned().collect(),
            removed: old.difference(new).cloned().collect(),
        })
    }
}

fn counter_overflow(source: ModelError) -> StoreError {
    StoreError::CounterOverflow { source }
}

fn backup_name(from: u32, to: u32) -> String {
    format!("{STATE_FILE}.bak-{from}-{to}")
}

/// The on-disk form: pretty-printed JSON with a trailing newline.
fn encode(state: &StateV2) -> Result<Vec<u8>, StoreError> {
    let mut bytes =
        serde_json::to_vec_pretty(state).map_err(|source| StoreError::Encode { source })?;
    bytes.push(b'\n');
    Ok(bytes)
}
