// SPDX-License-Identifier: GPL-3.0-or-later

//! Pending applies (design §13.6, §15.3): since when each node has been
//! behind the deployment's configuration generation. The console shows each
//! with how long it has waited, and the alert machine holds `PendingApply`
//! from that date (§15.8).
//!
//! The state records no time for a configuration change, so the daemon
//! dates each wait itself: a node is behind when the generation it
//! confirmed (`Applied`) is older than the deployment's, and its wait
//! starts at the first tick that sees it so. The record keeps the
//! generation the node had confirmed then, so a node that applied between
//! two sightings, and is behind again or still, is dated anew. The daemon
//! keeps the record in `run/pending-applies.json`, so a restart does not
//! restart a wait. A wait is a lower bound: a change made while the daemon
//! was not running is dated when it next runs, and so is every wait when
//! the record cannot be read.
//!
//! A node not yet applied (`Planned`, `Adopted`: the operator's first
//! `node apply` bootstraps it) or leaving (`Retiring` and on) is never
//! behind; neither does the apply job apply one.

use std::collections::BTreeMap;

use mooring_model::node::NodeLifecycle;
use mooring_model::{ConfigGeneration, Deployment, NodeId, UnixTime};
use serde::{Deserialize, Serialize};

/// The record's document version.
pub const PENDING_APPLIES_VERSION: u32 = 1;

/// The largest record read, in bytes.
pub const MAX_PENDING_APPLIES_BYTES: usize = 64 * 1024;

/// A node's wait, as the daemon first saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Behind {
    /// The generation the node had confirmed then.
    pub applied: ConfigGeneration,
    /// When.
    pub since: UnixTime,
}

/// The record is not a version-1 record of pending applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the record of pending applies is corrupt")]
pub struct PendingAppliesCorrupt;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    nodes: BTreeMap<NodeId, Behind>,
}

/// Every node's pending apply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingApplies {
    nodes: BTreeMap<NodeId, Behind>,
}

impl PendingApplies {
    /// The record with no node behind.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a record the daemon wrote.
    pub fn decode(bytes: &[u8]) -> Result<Self, PendingAppliesCorrupt> {
        if bytes.len() > MAX_PENDING_APPLIES_BYTES {
            return Err(PendingAppliesCorrupt);
        }
        let document: Document =
            serde_json::from_slice(bytes).map_err(|_| PendingAppliesCorrupt)?;
        if document.version != PENDING_APPLIES_VERSION {
            return Err(PendingAppliesCorrupt);
        }
        Ok(Self {
            nodes: document.nodes,
        })
    }

    /// The record as the daemon writes it.
    pub fn encode(&self) -> Result<Vec<u8>, PendingAppliesCorrupt> {
        let mut bytes = serde_json::to_vec_pretty(&Document {
            version: PENDING_APPLIES_VERSION,
            nodes: self.nodes.clone(),
        })
        .map_err(|_| PendingAppliesCorrupt)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// The record at `now` for `deployment`: every applied node whose
    /// confirmed generation is older than the deployment's, dated as this
    /// record dates it while the node has confirmed nothing since (never
    /// after `now`, so that a clock that stepped back makes no wait
    /// negative), and at `now` otherwise.
    #[must_use]
    pub fn tracked(&self, deployment: &Deployment, now: UnixTime) -> Self {
        let current = deployment.config_generation();
        let nodes = deployment
            .nodes()
            .iter()
            .filter_map(|(id, node)| {
                let NodeLifecycle::Applied { applied, .. } = &node.lifecycle else {
                    return None;
                };
                let confirmed = applied.config_generation;
                if confirmed >= current {
                    return None;
                }
                let since = self
                    .nodes
                    .get(id)
                    .filter(|seen| seen.applied == confirmed)
                    .map_or(now, |seen| seen.since.min(now));
                Some((
                    id.clone(),
                    Behind {
                        applied: confirmed,
                        since,
                    },
                ))
            })
            .collect();
        Self { nodes }
    }

    /// Since when each node behind has been behind, for the status.
    #[must_use]
    pub fn since(&self) -> BTreeMap<NodeId, UnixTime> {
        self.nodes
            .iter()
            .map(|(id, behind)| (id.clone(), behind.since))
            .collect()
    }
}
