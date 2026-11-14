// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the bundle a node confirmed is the one this build renders for
//! it now (design §13.6), as the agent compares them: by digest. The
//! bundles are rendered from the deployment's secrets and the engines this
//! build pins, as `node apply` and the apply job render them. `user add`
//! asks it to tell which nodes add a user to the running Xray; the apply
//! job, to find the nodes whose last apply was of another build's files,
//! engines or host profile.

use std::path::Path;

use mooring_model::node::AppliedConfig;
use mooring_model::secret::SecretSnapshot;
use mooring_model::{Deployment, NodeId};
use mooring_render::vps::bundle;
use mooring_render::{EngineCatalog, RenderError};
use mooring_store::{SnapshotReadError, read_snapshot};

use crate::app::Env;
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::LocalError;
use crate::node::engines::pinned_catalog;

/// What the bundles are rendered from: the deployment's secrets and the
/// engines this build pins.
pub(crate) struct Renders {
    secrets: SecretSnapshot,
    engines: EngineCatalog,
}

/// Why [`Renders::read`] could not read them.
#[derive(Debug)]
pub(crate) enum Unreadable {
    /// The deployment's secrets, from the keychain.
    Secrets(SnapshotReadError),
    /// The engines this build pins, in the support directory.
    Engines(LocalError),
}

impl Renders {
    /// Reads them: the secrets `deployment` references, from the keychain,
    /// and the engines this build pins (`env.engine_pins`) in the engine
    /// directory of `support`.
    pub(crate) fn read(
        env: &Env<'_>,
        support: &Path,
        deployment: &Deployment,
    ) -> Result<Self, Unreadable> {
        let secrets = read_snapshot(&*env.secrets, &deployment.required_secrets())
            .map_err(Unreadable::Secrets)?;
        let engines = pinned_catalog(&support.join(ENGINES_DIRECTORY), env.engine_pins)
            .map_err(Unreadable::Engines)?;
        Ok(Self { secrets, engines })
    }

    /// Whether `applied`, what `node` confirmed, is the bundle this build
    /// renders for it from `deployment`: one with the same digest, which
    /// the agent answers `Unchanged`. The digest leaves the configuration
    /// generation out, so a bundle a node confirmed at an older generation
    /// is this one when nothing it renders has changed since.
    pub(crate) fn confirmed(
        &self,
        deployment: &Deployment,
        node: &NodeId,
        applied: &AppliedConfig,
    ) -> Result<bool, RenderError> {
        bundle(deployment, node, &self.secrets, &self.engines)
            .map(|bundle| bundle.digest() == applied.digest)
    }
}
