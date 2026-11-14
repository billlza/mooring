// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's render drift (design §13.6): inside the window only,
//! after the spare users and before the node applies. A node that
//! confirmed the deployment's generation, but not the bundle this build
//! renders for it now, last applied another build's files, engines or
//! host profile; the agent refuses that bundle at the same generation.
//! So the deployment is given a new generation, in one configuration
//! change that changes nothing else, and the node applies that follow
//! carry this build's render to it in the night, where its restart is
//! expected, rather than with the next change by day. Every applied node
//! is then behind and is applied: one that confirmed this build's bundle
//! is answered `Unchanged` and restarts nothing.
//!
//! A run outside the window, which only the operator's `apply --now`
//! makes, leaves them, so that it restarts no engine for them by day; so
//! does a run in which every node at the generation confirmed this build's
//! bundle, or none is at it. The bundles are rendered only when a node is
//! at the generation, and as `node apply` renders them, from the keychain
//! and the engines in the support directory. A step that fails changes
//! nothing: the report gives its error, and the log only which part failed
//! ([`DriftFailure`]), since a rendering error may name a user.

use std::convert::Infallible;
use std::path::Path;

use mooring_daemon_core::apply::in_window;
use mooring_model::UnixTime;
use mooring_store::Store;

use super::nodes::at_generation;
use super::report::{Drift, DriftFailure, Regenerated};
use crate::app::Env;
use crate::daemon::chain;
use crate::node::rendered::{Renders, Unreadable};
use crate::state::state_change;

/// The step at `now`, rendering with the engines in `support`.
pub(super) fn step(env: &Env<'_>, store: &Store, support: &Path, now: UnixTime) -> Drift {
    if !in_window(now) {
        return Drift::OutsideWindow;
    }
    let deployment = match store.load() {
        Ok(state) => state.deployment,
        Err(error) => return failed(DriftFailure::State, &error),
    };
    let nodes = at_generation(&deployment);
    if nodes.is_empty() {
        return Drift::NoneFound;
    }
    let renders = match Renders::read(env, support, &deployment) {
        Ok(renders) => renders,
        Err(Unreadable::Secrets(error)) => return failed(DriftFailure::Secrets, &error),
        Err(Unreadable::Engines(error)) => return failed(DriftFailure::Engines, &error),
    };
    let mut drifted = Vec::new();
    for (node, applied) in nodes {
        match renders.confirmed(&deployment, node, applied) {
            Ok(true) => {}
            Ok(false) => drifted.push(node.clone()),
            Err(error) => {
                return Drift::Failed {
                    kind: DriftFailure::Render,
                    error: format!("{node}: {}", chain(&error)),
                };
            }
        }
    }
    if drifted.is_empty() {
        return Drift::NoneFound;
    }
    match store.update_config(deployment.config_generation(), Ok::<_, Infallible>) {
        Ok(state) => Drift::Regenerated(Regenerated {
            nodes: drifted,
            generation: state.deployment.config_generation(),
        }),
        Err(error) => failed(DriftFailure::Change, &state_change(error)),
    }
}

fn failed(kind: DriftFailure, error: &dyn std::error::Error) -> Drift {
    Drift::Failed {
        kind,
        error: chain(error),
    }
}
