// SPDX-License-Identifier: GPL-3.0-or-later

//! `state.json` for the commands that read or change the deployment: the
//! load that tells a Mac without a deployment apart, and the error
//! mappings they share.

use std::convert::Infallible;
use std::io;

use mooring_model::StateV2;
use mooring_store::{ChangeError, Store, StoreError};

use crate::error::{CommandError, LocalError};

pub(crate) fn state_read(error: StoreError) -> LocalError {
    LocalError::StateRead(Box::new(error))
}

/// The state, or `NoState` when this Mac has no deployment yet: no support
/// directory (the store would fail to open its lock there) or no
/// `state.json` in it.
pub(crate) fn load(store: &Store) -> Result<StateV2, LocalError> {
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

/// A change whose closure cannot refuse: only the store can fail it.
pub(crate) fn state_change(error: ChangeError<Infallible>) -> LocalError {
    match error {
        ChangeError::Store(error) => LocalError::StateChange(Box::new(error)),
        ChangeError::Refused(never) => match never {},
    }
}
