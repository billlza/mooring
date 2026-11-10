// SPDX-License-Identifier: GPL-3.0-or-later

//! A planned node as the commands that act on one find it: `node adopt`,
//! `node repin` and `node cancel` (design §13.2).
//!
//! A cancel keeps the configuration generation (it is a record, since a
//! planned node renders nothing), so a command that loaded the node before
//! a cancel still passes the store's compare-and-swap. Every closure that
//! edits a planned node therefore finds it again under the lock, with
//! [`planned_mut`], and refuses when it is gone or past `Planned` instead
//! of changing nothing.

use mooring_model::counters::ConfigGeneration;
use mooring_model::deployment::DeploymentParts;
use mooring_model::node::{Node, NodeLifecycle, SshPin};
use mooring_model::{Deployment, Ed25519Pub, NodeId};
use mooring_store::Store;

use crate::error::LocalError;
use crate::state::refused_change;

/// What a command does to a planned node, which the refusal of a node past
/// `Planned` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlannedAction {
    /// `node adopt`.
    Adopted,
    /// `node repin`.
    Repinned,
    /// `node cancel`.
    Cancelled,
}

impl PlannedAction {
    /// The past participle the refusal names: "only a planned node is …".
    pub(crate) const fn past(self) -> &'static str {
        match self {
            Self::Adopted => "adopted",
            Self::Repinned => "re-pinned",
            Self::Cancelled => "cancelled",
        }
    }
}

/// `id`'s node in `deployment`: `UnknownNode` if there is none,
/// `NodeNotPlanned` if it is past `Planned`.
pub(crate) fn planned<'d>(
    deployment: &'d Deployment,
    id: &NodeId,
    action: PlannedAction,
) -> Result<&'d Node, LocalError> {
    let node = deployment
        .nodes()
        .get(id)
        .ok_or_else(|| LocalError::UnknownNode { node: id.clone() })?;
    require_planned(node, action)?;
    Ok(node)
}

/// [`planned`] in a change's parts, which the closure receives under the
/// store's lock.
pub(crate) fn planned_mut<'p>(
    parts: &'p mut DeploymentParts,
    id: &NodeId,
    action: PlannedAction,
) -> Result<&'p mut Node, LocalError> {
    let node = parts
        .nodes
        .iter_mut()
        .find(|candidate| candidate.id == *id)
        .ok_or_else(|| LocalError::UnknownNode { node: id.clone() })?;
    require_planned(node, action)?;
    Ok(node)
}

fn require_planned(node: &Node, action: PlannedAction) -> Result<(), LocalError> {
    if node.lifecycle == NodeLifecycle::Planned {
        Ok(())
    } else {
        Err(LocalError::NodeNotPlanned {
            node: node.id.clone(),
            stage: node.lifecycle.stage(),
            action,
        })
    }
}

/// Records `host` as the planned node's pinned host key, the key its VPS
/// holds from now on. A configuration change, so a command that loaded the
/// deployment before it fails its next write; returns the new generation.
pub(crate) fn pin_in_state(
    store: &Store,
    id: &NodeId,
    generation: ConfigGeneration,
    host: Ed25519Pub,
    action: PlannedAction,
) -> Result<ConfigGeneration, LocalError> {
    let state = store
        .update_config(generation, |mut parts| {
            planned_mut(&mut parts, id, action)?.ssh = SshPin { host_ed25519: host };
            Ok(parts)
        })
        .map_err(refused_change)?;
    Ok(state.deployment.config_generation())
}
