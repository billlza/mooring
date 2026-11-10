// SPDX-License-Identifier: GPL-3.0-or-later

//! `node cancel <id> [--yes]` (design §13.2): gives a planned node up, as
//! when its VPS is gone, was planned by mistake, or is replaced by another.
//!
//! The record `Bookkeeping::PlanCancelled` removes the node from the state
//! with every user's credentials on it and its alert channels. A planned
//! node renders nothing, so the record keeps the configuration generation
//! and makes no node stale. The store deletes the keychain items the state
//! no longer references after the commit, under its lock; then this command
//! removes the node's ssh directory, which it inspected before asking, so
//! the files go only once the state no longer names the node. No VPS is
//! contacted. The id may be planned again; its tunnel index is not reused.

use std::io::{self, Write};

use mooring_keys::SshPublicKey;
use mooring_model::deployment::Bookkeeping;
use mooring_model::node::Node;
use mooring_model::{Deployment, NodeId, UserStatus};
use mooring_store::{Store, record_with_secrets};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::node::files::{NodeDirListing, NodeFiles};
use crate::node::planned::{PlannedAction, planned};
use crate::state::{load, output, store_failure};

/// `node cancel`. It reads and checks everything before the question and
/// writes nothing before it: the node must be planned, and its ssh
/// directory must hold only Mooring's own files.
pub(crate) fn cancel(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    id: &NodeId,
    yes: bool,
) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let store = Store::new(support.clone());
    let state = load(&store)?;
    let deployment = &state.deployment;
    let node = planned(deployment, id, PlannedAction::Cancelled)?;
    let files = NodeFiles::of(&support, id);
    let found = files.inspect()?;
    describe(out, deployment, node, found.as_ref()).map_err(output)?;
    confirm(env, yes, "Cancel this planned node?")?;
    let generation = deployment.config_generation();
    let cleanup = match record_with_secrets(
        &store,
        env.secrets,
        generation,
        Bookkeeping::PlanCancelled { node: id.clone() },
    )
    .map_err(store_failure)
    {
        Ok(_) => None,
        Err(committed @ LocalError::StateCommitted(_)) => Some(committed),
        Err(error) => return Err(error.into()),
    };
    let removed = found.map_or(Ok(()), NodeDirListing::remove);
    writeln!(
        out,
        "cancelled node {id}: the configuration generation stays {}, so the cancel needs no `node apply`, and the id may be planned again",
        generation.get()
    )
    .map_err(output)?;
    let behind: Vec<&str> = deployment
        .nodes()
        .values()
        .filter(|other| {
            other
                .lifecycle
                .applied()
                .is_some_and(|applied| applied.config_generation < generation)
        })
        .map(|other| other.id.as_str())
        .collect();
    if !behind.is_empty() {
        writeln!(
            out,
            "applied nodes behind generation {} since an earlier change: {}; `node apply` them before exporting users",
            generation.get(),
            behind.join(", ")
        )
        .map_err(output)?;
    }
    match (cleanup, removed) {
        (None, Ok(())) => Ok(()),
        (None, Err(source)) => Err(LocalError::NodeFilesLeft {
            node: id.clone(),
            dir: files.dir().to_path_buf(),
            source,
        }
        .into()),
        (Some(committed), removed) => {
            if let Err(source) = removed {
                writeln!(
                    out,
                    "{} could not be removed ({source}); remove it by hand, or `node new {id}` refuses",
                    files.dir().display()
                )
                .map_err(output)?;
            }
            Err(committed.into())
        }
    }
}

/// What the cancel removes, and what it leaves on a VPS an adoption may
/// have touched.
fn describe(
    out: &mut dyn Write,
    deployment: &Deployment,
    node: &Node,
    found: Option<&NodeDirListing>,
) -> io::Result<()> {
    let id = &node.id;
    let holders: Vec<&str> = deployment
        .users()
        .values()
        .filter(|user| user.per_node.contains_key(id))
        .map(|user| user.id.as_str())
        .collect();
    writeln!(
        out,
        "node {id}: planned, tunnel 10.77.{}.0/30, host key {} pinned; users with credentials on it: {}",
        node.wg_index.get(),
        SshPublicKey::from(node.ssh.host_ed25519).fingerprint(),
        if holders.is_empty() {
            "none".to_owned()
        } else {
            holders.join(", ")
        }
    )?;
    let settled: Vec<&str> = deployment
        .users()
        .values()
        .filter(|user| {
            user.status == UserStatus::RevokePending && user.per_node.keys().all(|held| held == id)
        })
        .map(|user| user.id.as_str())
        .collect();
    if !settled.is_empty() {
        writeln!(
            out,
            "revoked once it is gone, since their revocation waits only on it: {}",
            settled.join(", ")
        )?;
    }
    if deployment
        .alerting()
        .is_some_and(|alerting| alerting.channels.contains(id))
    {
        writeln!(out, "its alert channels go with it")?;
    }
    writeln!(
        out,
        "cancelling removes it from the state and deletes its keys, and those users' credentials on it, from the keychain{}; no VPS is contacted",
        found.map_or_else(String::new, |listing| format!(
            ", then {}",
            listing.dir().display()
        ))
    )?;
    if found.is_some() {
        writeln!(
            out,
            "`node adopt {id}` ran on this Mac: if its Bootstrap ran, the VPS lets in only the Mooring keys this deletes, not your own root key, so reinstall it or delete it from the provider's console"
        )?;
    }
    Ok(())
}
