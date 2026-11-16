// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's node applies (design §13.6): every node that confirmed
//! a generation older than the deployment's, by id, each as `node apply`
//! does it (`node::apply::transact`), through the exit's egress as the
//! daemon resolves it (`exit_interfaces`) and with the engines in the
//! support directory, as the daemon runs them. The revocations the
//! confirmations settle are recorded after the last, for every node at
//! once (`revocation::commit`). A node not yet applied, or leaving, is not
//! applied: its first apply is the operator's (design §13.2). A node that
//! cannot be reached, or whose apply fails, is reported, and the next one
//! runs; an egress that does not resolve fails each node without dialling.

use std::io::Write;
use std::path::Path;

use mooring_model::node::NodeLifecycle;
use mooring_model::{Deployment, NodeId, UnixTime};
use mooring_store::Store;

use super::report::{NodeOutcome, NodeResult};
use crate::app::Env;
use crate::daemon::chain;
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::{CommandError, LocalError};
use crate::runtime::resolve::exit_interfaces;
use crate::state::load;

/// The nodes of `deployment` behind its generation, in id order.
pub(super) fn behind(deployment: &Deployment) -> Vec<NodeId> {
    let current = deployment.config_generation();
    deployment
        .nodes()
        .iter()
        .filter(|(_, node)| {
            matches!(&node.lifecycle, NodeLifecycle::Applied { applied, .. }
                if applied.config_generation < current)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// Applies every node behind the state's generation as it is now, writing
/// each apply's progress to `progress` and handing each outcome, with the
/// time it ended, to `done`.
pub(super) fn apply_behind(
    env: &mut Env<'_>,
    progress: &mut dyn Write,
    store: &Store,
    support: &Path,
    done: &mut dyn FnMut(&NodeOutcome, UnixTime) -> Result<(), CommandError>,
) -> Result<Vec<NodeOutcome>, CommandError> {
    let deployment = load(store)?.deployment;
    let behind = behind(&deployment);
    if behind.is_empty() {
        return Ok(Vec::new());
    }
    let egress = match exit_interfaces(env.router.link, deployment.exit()) {
        Ok(Ok(egress)) => Ok(egress.interfaces.egress().bsd_name.clone()),
        Ok(Err(fault)) => Err(chain(&LocalError::NodeUnreachableWithoutEgress { fault })),
        Err(error) => Err(chain(&error)),
    };
    let engines = support.join(ENGINES_DIRECTORY);
    let mut outcomes = Vec::new();
    for node in behind {
        let result = match &egress {
            Ok(interface) => {
                match crate::node::apply::transact(env, progress, &node, interface, &engines) {
                    Ok(()) => NodeResult::Applied,
                    Err(error) => NodeResult::Failed {
                        error: chain(&error),
                    },
                }
            }
            Err(error) => NodeResult::Failed {
                error: error.clone(),
            },
        };
        let outcome = NodeOutcome { node, result };
        done(&outcome, (env.clock)()?)?;
        outcomes.push(outcome);
    }
    Ok(outcomes)
}
