// SPDX-License-Identifier: GPL-3.0-or-later

//! `state.json` for the commands that read or change the deployment: the
//! load that tells a Mac without a deployment apart, and the error
//! mappings they share.

use std::convert::Infallible;
use std::io;

use mooring_model::deployment::Bookkeeping;
use mooring_model::{Deployment, StateV3};
use mooring_store::{ChangeError, Store, StoreError};

use crate::error::{CommandError, LocalError};

pub(crate) fn state_read(error: StoreError) -> LocalError {
    LocalError::StateRead(Box::new(error))
}

/// The state, or `NoState` when this Mac has no deployment yet: no support
/// directory (the store would fail to open its lock there) or no
/// `state.json` in it.
pub(crate) fn load(store: &Store) -> Result<StateV3, LocalError> {
    if !store.dir().is_dir() {
        return Err(LocalError::NoState {
            path: store.state_path(),
        });
    }
    store.load().map_err(|error| match error {
        StoreError::NotInitialized { path } => LocalError::NoState { path },
        other => state_read(other),
    })
}

pub(crate) fn output(error: io::Error) -> CommandError {
    CommandError::Local(LocalError::Output(error))
}

/// A store failure of a change: `StateCommitted` when the change is
/// committed and only deleting the secrets it stopped referencing failed
/// (`SecretCleanup`), `StateChange` for a refusal or a failed write. (A
/// write that fails after its rename, when the directory cannot be
/// synced, has replaced the state all the same; the store does not tell
/// that failure apart.)
pub(crate) fn store_failure(error: StoreError) -> LocalError {
    match error {
        StoreError::SecretCleanup { .. } => LocalError::StateCommitted(Box::new(error)),
        other => LocalError::StateChange(Box::new(other)),
    }
}

/// What the bookkeeping record `entry` makes of `deployment`, with
/// nothing written: what a command shows before it asks. A record the
/// model refuses is the refusal the store would give for it
/// (`InvalidChange`).
pub(crate) fn recorded(
    deployment: &Deployment,
    entry: Bookkeeping,
) -> Result<Deployment, LocalError> {
    deployment
        .clone()
        .record(entry)
        .map_err(|source| store_failure(StoreError::InvalidChange { source }))
}

/// Reads the state again and requires its deployment to be `read`, the one
/// a command described before it asked. The answer may have waited. A
/// record another command wrote meanwhile keeps the generation, so the
/// compare-and-swap of the write that follows would not notice it, and no
/// write at all guards what a command does outside the state: a node's
/// files, or a VPS. Only mooringctl writes the state, so a difference is
/// another command's doing (`StateChangedSinceRead`).
///
/// This shortens the time in which another command can slip in unnoticed
/// from the wait for an answer to the instant between this read and the
/// write or the action that follows; it does not close it.
pub(crate) fn unchanged(store: &Store, read: &Deployment) -> Result<(), LocalError> {
    if load(store)?.deployment == *read {
        Ok(())
    } else {
        Err(LocalError::StateChangedSinceRead)
    }
}

/// A change whose closure cannot refuse: only the store can fail it.
pub(crate) fn state_change(error: ChangeError<Infallible>) -> LocalError {
    match error {
        ChangeError::Store(error) => store_failure(error),
        ChangeError::Refused(never) => match never {},
    }
}

/// A change whose closure refuses with a [`LocalError`]: that refusal, or
/// the store's failure.
pub(crate) fn refused_change(error: ChangeError<LocalError>) -> LocalError {
    match error {
        ChangeError::Store(error) => store_failure(error),
        ChangeError::Refused(refusal) => refusal,
    }
}
