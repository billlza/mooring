// SPDX-License-Identifier: GPL-3.0-or-later

//! Settling revocations (design §13.5). A user being revoked is served by
//! no node from the generation its revocation made on, so a node applied
//! at the deployment's generation has committed the revocation of every
//! user pending revocation that holds credentials on it
//! (`Deployment::revocations_confirmed`). For each, the state records
//! `RevocationCommitted{user, node, at}`, and the store deletes the user's
//! credentials on that node from the keychain only after that record is
//! committed (`record_with_secrets`). With no node left, the user is
//! revoked.
//!
//! `node apply` commits the revocations its node confirms, once it has
//! recorded the node's confirmation; the apply job commits those of every
//! node after its node applies, which also records one that a node
//! confirmed earlier and a stopped run did not get to record. Neither the
//! daemon, which never writes `state.json`, nor any other command records
//! one.
//!
//! What waits ([`pending`]) is read from the state: each user still being
//! revoked and, for each node it still holds credentials on, what settles
//! it there. A node that cannot be reached keeps the user pending, and the
//! report says so.

use std::fmt;

use mooring_model::node::NodeLifecycle;
use mooring_model::{Bookkeeping, Deployment, NodeId, UnixTime, UserId, UserStatus};
use mooring_store::{SecretStore, Store, StoreError, record_with_secrets};
use serde::Serialize;

use crate::daemon::chain;
use crate::error::LocalError;
use crate::state::{load, store_failure};

/// A revocation recorded on a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Committed {
    /// The user being revoked.
    pub(crate) user: UserId,
    /// The node that committed it.
    pub(crate) node: NodeId,
    /// Whether the user is revoked now: no node holds its credentials.
    pub(crate) revoked: bool,
}

/// A revocation a node confirmed that was not recorded, or whose keychain
/// items were not all deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FailedCommit {
    /// The user being revoked.
    pub(crate) user: UserId,
    /// The node.
    pub(crate) node: NodeId,
    /// Whether the record was committed all the same, so that only the
    /// deletion of keychain items failed: nothing uses those any more.
    pub(crate) recorded: bool,
    /// Why, naming the user by id at most.
    pub(crate) error: String,
}

/// What one pass of [`commit`] recorded, and what still waits after it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Commits {
    /// The revocations recorded, in user, then node order.
    pub(crate) committed: Vec<Committed>,
    /// Those that failed.
    pub(crate) failed: Vec<FailedCommit>,
    /// The users still being revoked once the pass is done, in id order,
    /// with what each waits on ([`pending`]).
    pub(crate) pending: Vec<Pending>,
}

/// What settles a pending revocation on a node, read from its stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WaitsFor {
    /// An applied node behind the generation: its next apply.
    Apply,
    /// An applied node at the generation whose revocation is not recorded
    /// yet (its record failed, or `node apply` of another node left it):
    /// the next `node apply` of it, or the next run of the apply job.
    Record,
    /// An adopted node: its first `node apply`, the operator's.
    FirstApply,
    /// A retiring node: its shutdown.
    Shutdown,
    /// A planned node: `node cancel`, or its adoption and first apply.
    Plan,
}

impl WaitsFor {
    /// What settles a revocation waiting on `node` of `deployment`.
    fn of(deployment: &Deployment, node: &NodeId) -> Self {
        let generation = deployment.config_generation();
        match deployment.nodes().get(node).map(|found| &found.lifecycle) {
            Some(NodeLifecycle::Applied { applied, .. })
                if applied.config_generation == generation =>
            {
                Self::Record
            }
            Some(NodeLifecycle::Applied { .. }) => Self::Apply,
            Some(NodeLifecycle::Adopted { .. }) => Self::FirstApply,
            Some(NodeLifecycle::Retiring { .. }) => Self::Shutdown,
            // Only active nodes hold credentials (the model's invariant),
            // so a node waited on is planned if it is none of the above.
            Some(
                NodeLifecycle::Planned
                | NodeLifecycle::RetiredPendingProviderDeletion { .. }
                | NodeLifecycle::Retired,
            )
            | None => Self::Plan,
        }
    }
}

impl fmt::Display for WaitsFor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Apply => "behind; its next apply commits it",
            Self::Record => {
                "applied, not recorded yet; its next `node apply` or the apply job's next run records it"
            }
            Self::FirstApply => "adopted; its first `node apply` commits it",
            Self::Shutdown => "retiring; its shutdown settles it",
            Self::Plan => "planned; `node cancel` settles it, or its first apply",
        })
    }
}

/// One node a pending revocation waits on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Waiting {
    /// The node, which still holds the user's credentials.
    pub(crate) node: NodeId,
    /// What settles it there.
    pub(crate) waits_for: WaitsFor,
}

/// A user still being revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Pending {
    /// The user.
    pub(crate) user: UserId,
    /// The nodes it waits on, in id order.
    pub(crate) nodes: Vec<Waiting>,
}

impl Pending {
    /// The nodes and what settles each, in words.
    pub(crate) fn nodes_text(&self) -> String {
        self.nodes
            .iter()
            .map(|waiting| format!("{} ({})", waiting.node, waiting.waits_for))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Every user of `deployment` being revoked, in id order, with the nodes
/// it waits on.
pub(crate) fn pending(deployment: &Deployment) -> Vec<Pending> {
    deployment
        .users()
        .values()
        .filter(|user| user.status == UserStatus::RevokePending)
        .map(|user| Pending {
            user: user.id.clone(),
            nodes: user
                .revocation_remaining()
                .map(|node| Waiting {
                    node: node.clone(),
                    waits_for: WaitsFor::of(deployment, node),
                })
                .collect(),
        })
        .collect()
}

/// What waits in the state as it is now ([`pending`]), recording nothing.
pub(crate) fn waiting(store: &Store) -> Result<Vec<Pending>, LocalError> {
    Ok(pending(&load(store)?.deployment))
}

/// Records, in the state as it is now, every revocation that `only` (one
/// node), or every node, has confirmed, at `at`, each a record of its own;
/// one that fails is kept and the next is recorded. Then what still waits,
/// in the state as the pass left it. A state that cannot be read records
/// nothing and is the error.
pub(crate) fn commit(
    store: &Store,
    secrets: &mut dyn SecretStore,
    at: UnixTime,
    only: Option<&NodeId>,
) -> Result<Commits, LocalError> {
    let mut working = load(store)?.deployment;
    let generation = working.config_generation();
    let confirmed: Vec<(UserId, NodeId)> = working
        .revocations_confirmed()
        .filter(|(_, node)| only.is_none_or(|only| *node == only))
        .map(|(user, node)| (user.clone(), node.clone()))
        .collect();
    let mut commits = Commits::default();
    for (user, node) in confirmed {
        let entry = Bookkeeping::RevocationCommitted {
            user: user.clone(),
            node: node.clone(),
            at,
        };
        // What the record makes of the state as this pass has left it: the
        // store commits it there unless another command wrote meanwhile,
        // which its compare-and-swap or the model then refuses.
        let after = working.clone().record(entry.clone());
        match record_with_secrets(store, secrets, generation, entry) {
            Ok(next) => {
                working = next.deployment;
                commits.committed.push(Committed {
                    revoked: is_revoked(&working, &user),
                    user,
                    node,
                });
            }
            Err(error @ StoreError::SecretCleanup { .. }) => {
                // Committed: the state no longer references what was left.
                if let Ok(after) = after {
                    working = after;
                }
                commits.committed.push(Committed {
                    revoked: is_revoked(&working, &user),
                    user: user.clone(),
                    node: node.clone(),
                });
                commits.failed.push(FailedCommit {
                    user,
                    node,
                    recorded: true,
                    error: chain(&store_failure(error)),
                });
            }
            Err(error) => commits.failed.push(FailedCommit {
                user,
                node,
                recorded: false,
                error: chain(&store_failure(error)),
            }),
        }
    }
    commits.pending = pending(&working);
    Ok(commits)
}

/// Whether `user` is revoked in `deployment`.
fn is_revoked(deployment: &Deployment, user: &UserId) -> bool {
    deployment
        .users()
        .get(user)
        .is_some_and(|found| found.status.is_revoked())
}

impl Commits {
    /// The report's lines, which name users by id: each revocation
    /// recorded, then each failure.
    pub(crate) fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for committed in &self.committed {
            let left = self
                .pending
                .iter()
                .find(|waiting| waiting.user == committed.user)
                .map(Pending::nodes_text);
            lines.push(match (committed.revoked, left) {
                (true, _) => format!(
                    "revocation committed on {}: {}, now revoked; its credentials there are deleted from the keychain",
                    committed.node, committed.user
                ),
                (false, Some(left)) => format!(
                    "revocation committed on {}: {}, which still waits on {left}",
                    committed.node, committed.user
                ),
                (false, None) => format!(
                    "revocation committed on {}: {}",
                    committed.node, committed.user
                ),
            });
        }
        for failed in &self.failed {
            lines.push(if failed.recorded {
                format!(
                    "revocation committed on {}: {}, but deleting its keychain items failed: {}",
                    failed.node, failed.user, failed.error
                )
            } else {
                format!(
                    "recording the revocation of {} on {} failed: {}",
                    failed.user, failed.node, failed.error
                )
            });
        }
        lines
    }
}
