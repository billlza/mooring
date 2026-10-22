// SPDX-License-Identifier: GPL-3.0-or-later

//! [`ConsoleStatus`]: one line of `mooringctl status [--follow] --json`,
//! and the daemon's snapshot in `status.json` (design §15.1, §15.2).
//!
//! The daemon starts at login whether or not `exit init` has created a
//! deployment. Without one there is no exit, SIM meter, user or node to
//! report, but the router adapter needs none of them: its identity pin
//! and admin password live outside the state (design §15.6 rule 4). So the
//! console's document is the deployment's [`MacStatusV1`] once there is a
//! deployment, and until then [`UndeployedStatus`], which carries the
//! router panel alone and says that nothing else exists yet, rather than
//! zeros or defaults for a deployment that does not exist.

use serde::{Deserialize, Serialize};

use mooring_model::UnixTime;

use crate::error::ConsoleError;
use crate::router::{RouterAdvisory, RouterReading};
use crate::status::MacStatusV1;

/// The version [`UndeployedStatus`] documents carry.
pub const UNDEPLOYED_STATUS_VERSION: u32 = 1;

/// What the console shows: the deployment's status, or, before there is a
/// deployment, the router alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsoleStatus {
    /// No deployment exists on this Mac yet (`exit init` creates it).
    NoDeployment(UndeployedStatus),
    /// The deployment's status (boxed: it is far larger than the other
    /// variant).
    Deployed(Box<MacStatusV1>),
}

impl ConsoleStatus {
    /// The router panel, which both documents carry.
    #[must_use]
    pub fn router(&self) -> &RouterReading {
        match self {
            Self::NoDeployment(status) => status.router(),
            Self::Deployed(status) => &status.parts().router,
        }
    }

    /// When the daemon produced the document.
    #[must_use]
    pub fn at(&self) -> UnixTime {
        match self {
            Self::NoDeployment(status) => status.at(),
            Self::Deployed(status) => status.parts().at,
        }
    }
}

/// The status before a deployment exists: when the daemon produced it, the
/// router panel, and the settings the exit needs off that the panel shows
/// on ([`RouterStatus::advisories`](crate::router::RouterStatus::advisories)),
/// so the app shows them without a rule of its own. On the wire it carries
/// its version, which must be [`UNDEPLOYED_STATUS_VERSION`], refuses an
/// unknown key, and refuses advisories that do not follow from its panel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "UndeployedRepr", into = "UndeployedRepr")]
pub struct UndeployedStatus {
    at: UnixTime,
    router: RouterReading,
    advisories: Vec<RouterAdvisory>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UndeployedRepr {
    version: u32,
    at: UnixTime,
    router: RouterReading,
    advisories: Vec<RouterAdvisory>,
}

/// The advisories of a router panel: the status's, or none without one.
fn advisories_of(router: &RouterReading) -> Vec<RouterAdvisory> {
    match router {
        RouterReading::Available { status, .. } => status.advisories(),
        RouterReading::Unavailable { .. } => Vec::new(),
    }
}

impl UndeployedStatus {
    /// The status the daemon produced at `at` with `router`.
    #[must_use]
    pub fn new(at: UnixTime, router: RouterReading) -> Self {
        let advisories = advisories_of(&router);
        Self {
            at,
            router,
            advisories,
        }
    }

    /// When the daemon produced it.
    #[must_use]
    pub const fn at(&self) -> UnixTime {
        self.at
    }

    /// The router panel.
    #[must_use]
    pub const fn router(&self) -> &RouterReading {
        &self.router
    }

    /// The settings the exit needs off that the panel shows on.
    #[must_use]
    pub fn advisories(&self) -> &[RouterAdvisory] {
        &self.advisories
    }
}

impl TryFrom<UndeployedRepr> for UndeployedStatus {
    type Error = ConsoleError;

    fn try_from(repr: UndeployedRepr) -> Result<Self, Self::Error> {
        if repr.version != UNDEPLOYED_STATUS_VERSION {
            return Err(ConsoleError::UnsupportedVersion {
                found: repr.version,
            });
        }
        let status = Self::new(repr.at, repr.router);
        if status.advisories != repr.advisories {
            return Err(ConsoleError::AdvisoriesMismatch);
        }
        Ok(status)
    }
}

impl From<UndeployedStatus> for UndeployedRepr {
    fn from(status: UndeployedStatus) -> Self {
        Self {
            version: UNDEPLOYED_STATUS_VERSION,
            at: status.at,
            router: status.router,
            advisories: status.advisories,
        }
    }
}
