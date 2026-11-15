// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's spare users (design §13.6): inside the window only,
//! after the removals and before the node applies, so that those applies
//! carry the spares in the night, when their restart is expected. Each
//! spare is given credentials on every node planned, adopted or applied
//! that it lacks them on, and new spares are drawn until
//! [`SPARE_USERS`](mooring_model::SPARE_USERS) are ready, in one
//! configuration change, with the credentials written to the keychain
//! before the state that references them. A run outside the window, which
//! only the operator's `apply --now` makes, leaves them, so that it
//! restarts no engine for them by day; a run with nothing to do changes
//! nothing. A step that fails changes nothing either: the report gives its
//! error, and the log only which part failed ([`SparesFailure`]), since the
//! error may name a spare.

use std::convert::Infallible;

use mooring_daemon_core::apply::in_window;
use mooring_model::UnixTime;
use mooring_store::{SecretStore, Store, update_config_with_secrets};

use super::report::{Spares, SparesDone, SparesFailure};
use crate::daemon::chain;
use crate::state::state_change;
use crate::user_spares::top_up;

/// The step at `now`, writing credentials to `secrets`.
pub(super) fn step(store: &Store, secrets: &mut dyn SecretStore, now: UnixTime) -> Spares {
    if !in_window(now) {
        return Spares::OutsideWindow;
    }
    let state = match store.load() {
        Ok(state) => state,
        Err(error) => return failed(SparesFailure::State, &error),
    };
    let deployment = state.deployment;
    let ready = deployment.spares().len();
    let top_up = match top_up(&deployment) {
        Ok(Some(top_up)) => top_up,
        Ok(None) => {
            return Spares::Done(SparesDone {
                drawn: 0,
                credentials: 0,
                ready,
            });
        }
        Err(error) => return failed(SparesFailure::Credentials, &error),
    };
    let done = SparesDone {
        drawn: top_up.drawn,
        credentials: top_up.credentials,
        ready: top_up.spares.len(),
    };
    let spares = top_up.spares;
    match update_config_with_secrets(
        store,
        secrets,
        deployment.config_generation(),
        top_up.secrets,
        |mut parts| {
            parts.spares = spares;
            Ok::<_, Infallible>(parts)
        },
    ) {
        Ok(_) => Spares::Done(done),
        Err(error) => failed(SparesFailure::Change, &state_change(error)),
    }
}

fn failed(kind: SparesFailure, error: &dyn std::error::Error) -> Spares {
    Spares::Failed {
        kind,
        error: chain(error),
    }
}
