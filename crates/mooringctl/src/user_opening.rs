// SPDX-License-Identifier: GPL-3.0-or-later

//! What each node's next apply does for the user `user add` adds (design
//! §13.6), decided before the add, from the deployment it is made to.
//!
//! Only the user's two Xray clients are new on a node when the user holds
//! the spare's credentials there and the node runs what this build renders
//! for that deployment: it confirmed the deployment's generation, and the
//! bundle it confirmed is the one rendered now, with the engines this build
//! pins. Its next apply then adds the user to the running Xray. Fresh
//! credentials change what its engines read at start; a node behind the
//! deployment, or one whose last apply was of another build's files or
//! engines, carries those changes too.
//!
//! A restart is made only by an apply that allows it (design §13.6):
//! `node apply` with `--restart`, or the night's run in its window. What
//! runs on the node is not read here: a node whose Xray is not running, or
//! whose running generation serves no `HandlerService` yet, needs a
//! restart too, which its apply then names.

use std::path::Path;

use mooring_model::secret::SecretSnapshot;
use mooring_model::{Deployment, NodeId, Sha256Digest};
use mooring_render::EngineCatalog;
use mooring_render::vps::bundle;
use mooring_store::read_snapshot;

use crate::app::Env;
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::LocalError;
use crate::node::engines::pinned_catalog;
use crate::user_spares::NewUser;

/// What a node's next apply does for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextApply {
    /// It adds the user's clients to the running Xray.
    AddsLive,
    /// The user's credentials there are new.
    Fresh,
    /// The node confirmed an older generation.
    Behind,
    /// The bundle the node confirmed is not the one this build renders.
    OtherRender,
}

impl NextApply {
    const fn words(self) -> &'static str {
        match self {
            Self::AddsLive => "adds the user to the running Xray, with no restart",
            Self::Fresh => {
                "needs a restart, since the user's credentials there are new: `node apply` makes it only with `--restart`, the night's run in its window"
            }
            Self::Behind => {
                "also carries changes it has not applied yet: if any needs a restart, `node apply` makes it only with `--restart`, the night's run in its window"
            }
            Self::OtherRender => {
                "also carries what this build renders differently from what it last applied: if any of that needs a restart, `node apply` makes it only with `--restart`, the night's run in its window"
            }
        }
    }
}

/// The line of each node `new` holds credentials on that confirmed a
/// generation of `deployment`, the deployment before the add, in node
/// order. A node not yet applied has none: it serves the user from its
/// first apply. The secrets are read, from the keychain, only for a node
/// that would add the user live; the engines are named by this build's
/// pins (`env.engine_pins`), for the engine directory in `support`, as the
/// apply job applies a node. A node that cannot be rendered refuses the
/// add.
pub(crate) fn lines(
    env: &Env<'_>,
    support: &Path,
    deployment: &Deployment,
    new: &NewUser,
) -> Result<Vec<String>, LocalError> {
    let mut renders: Option<Renders> = None;
    let mut lines = Vec::new();
    for node in new.per_node.keys() {
        let Some(applied) = deployment
            .nodes()
            .get(node)
            .and_then(|record| record.lifecycle.applied())
        else {
            continue;
        };
        let next = if new.fresh.contains(node) {
            NextApply::Fresh
        } else if applied.config_generation < deployment.config_generation() {
            NextApply::Behind
        } else {
            let renders = match &mut renders {
                Some(renders) => renders,
                None => renders.insert(Renders::read(env, support, deployment, node)?),
            };
            if renders.digest(deployment, node)? == applied.digest {
                NextApply::AddsLive
            } else {
                NextApply::OtherRender
            }
        };
        lines.push(format!("{node}: its next apply {}", next.words()));
    }
    Ok(lines)
}

/// What a node's bundle is rendered from: the deployment's secrets and the
/// engines this build pins, as `node apply` and the apply job render it.
struct Renders {
    secrets: SecretSnapshot,
    engines: EngineCatalog,
}

impl Renders {
    /// Reads them for the first node to render, `node`.
    fn read(
        env: &Env<'_>,
        support: &Path,
        deployment: &Deployment,
        node: &NodeId,
    ) -> Result<Self, LocalError> {
        let secrets = read_snapshot(&*env.secrets, &deployment.required_secrets())
            .map_err(|error| LocalError::OpeningSecrets(Box::new(error)))?;
        let engines = pinned_catalog(&support.join(ENGINES_DIRECTORY), env.engine_pins)
            .map_err(|error| unrendered(node, error))?;
        Ok(Self { secrets, engines })
    }

    /// The digest of `node`'s bundle, as `node apply` would confirm it.
    fn digest(&self, deployment: &Deployment, node: &NodeId) -> Result<Sha256Digest, LocalError> {
        bundle(deployment, node, &self.secrets, &self.engines)
            .map(|bundle| bundle.digest())
            .map_err(|error| unrendered(node, LocalError::Render(error)))
    }
}

/// `node`'s bundle could not be rendered, for `source`.
fn unrendered(node: &NodeId, source: LocalError) -> LocalError {
    LocalError::OpeningRender {
        node: node.clone(),
        source: Box::new(source),
    }
}
