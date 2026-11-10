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
//!
//! What the command says before it asks is read from the record applied to
//! the deployment it loaded (`state::recorded`): it names what the model
//! does, not a second reading of the model's rules. The answer may wait,
//! and a record another command writes meanwhile keeps the generation, so
//! the state is read again when the answer comes and must be the one
//! described (`state::unchanged`).
//!
//! A cancel that stopped after its commit (the process ended there, or the
//! write failed late) leaves the ssh directory, and `node new` refuses to
//! plan over it. Run for an id the state does not hold, the command
//! removes that directory, after the same inspection, a question and the
//! same second reading of the state: no write guards that removal, and a
//! node planned under the id meanwhile would own whatever its adoption has
//! put at the path since.

use std::io::{self, Write};

use mooring_keys::SshPublicKey;
use mooring_model::deployment::Bookkeeping;
use mooring_model::node::Node;
use mooring_model::secret::SecretRef;
use mooring_model::{Deployment, NodeId, User, UserStatus};
use mooring_store::{Store, record_with_secrets};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::node::files::{NodeDirListing, NodeFiles};
use crate::node::planned::{PlannedAction, planned};
use crate::state::{load, output, recorded, store_failure, unchanged};

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
    let files = NodeFiles::of(&support, id);
    let state = load(&store)?;
    let deployment = &state.deployment;
    let node = match planned(deployment, id, PlannedAction::Cancelled) {
        Ok(node) => node,
        Err(LocalError::UnknownNode { .. }) => {
            return remove_leftover(env, out, &store, deployment, &files, id, yes);
        }
        Err(refusal) => return Err(refusal.into()),
    };
    let found = files.inspect()?;
    let entry = Bookkeeping::PlanCancelled { node: id.clone() };
    let after = recorded(deployment, entry.clone())?;
    describe(out, deployment, &after, node, found.as_ref()).map_err(output)?;
    confirm(env, yes, "Cancel this planned node?")?;
    unchanged(&store, deployment)?;
    let generation = deployment.config_generation();
    let cleanup =
        match record_with_secrets(&store, env.secrets, generation, entry).map_err(store_failure) {
            Ok(_) => None,
            Err(LocalError::StateCommitted(failure)) => Some(failure),
            Err(error) => return Err(error.into()),
        };
    // A directory that was not there before the question may be there now,
    // made by an adoption started meanwhile: the removal fails on it, so
    // `removed` says that nothing is at the path, not that nothing was.
    let removed = found.unwrap_or_else(|| files.absent()).remove();
    // The cancel is committed. What it left behind is the failure to
    // report, whatever becomes of the lines that say it is done.
    let written = summarize(out, deployment, id, removed.is_ok()).map_err(output);
    let dir = files.dir().to_path_buf();
    match (cleanup, removed) {
        (None, Ok(())) => written,
        (None, Err(source)) => Err(LocalError::NodeFilesLeft {
            node: id.clone(),
            dir,
            source,
        }
        .into()),
        (Some(failure), Ok(())) => Err(LocalError::StateCommitted(failure).into()),
        (Some(source), Err(removal)) => Err(LocalError::NodeFilesAndSecretsLeft {
            node: id.clone(),
            dir,
            removal,
            source,
        }
        .into()),
    }
}

/// `node cancel` for an id the state does not hold. If Mooring's ssh files
/// for the id are still there, a cancel committed and did not get to
/// remove them: they are removed now, after a question, so that the id can
/// be planned again. With no directory the node is unknown.
///
/// The question may wait, and nothing holds the directory meanwhile: once
/// it is gone, by another run of this command or by hand, the id can be
/// planned and adopted again, and the files at the path are then that
/// node's. So the state is read again when the answer comes, and must be
/// `read`, the state that held no node of the id.
fn remove_leftover(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    store: &Store,
    read: &Deployment,
    files: &NodeFiles,
    id: &NodeId,
    yes: bool,
) -> Result<(), CommandError> {
    let Some(found) = files.inspect()? else {
        return Err(LocalError::UnknownNode { node: id.clone() }.into());
    };
    writeln!(
        out,
        "node {id} is not in the state, but {} still holds the ssh files Mooring kept for a node of that id: a cancel committed and did not get to remove them\nremoving them lets the id be planned again; the state is not changed, no VPS is contacted, and keychain items that cancel did not get to delete stay, which nothing uses",
        found.dir().display()
    )
    .map_err(output)?;
    stranded_note(out, id).map_err(output)?;
    confirm(env, yes, "Remove these files?")?;
    unchanged(store, read)?;
    let dir = found.dir().to_path_buf();
    found.remove().map_err(|source| LocalError::NodeFilesLeft {
        node: id.clone(),
        dir: dir.clone(),
        source,
    })?;
    writeln!(
        out,
        "removed {}: the id may be planned again",
        dir.display()
    )
    .map_err(output)
}

/// What the cancel removes, read from the deployment before it and after
/// it, and what it leaves on a VPS an adoption may have touched.
fn describe(
    out: &mut dyn Write,
    before: &Deployment,
    after: &Deployment,
    node: &Node,
    found: Option<&NodeDirListing>,
) -> io::Result<()> {
    let id = &node.id;
    let left = |user: &User| after.users().get(&user.id);
    let holders: Vec<&str> = before
        .users()
        .values()
        .filter(|user| {
            user.per_node.contains_key(id)
                && left(user).is_some_and(|left| !left.per_node.contains_key(id))
        })
        .map(|user| user.id.as_str())
        .collect();
    writeln!(
        out,
        "node {id}: planned, tunnel {}, host key {} pinned; users with credentials on it: {}",
        node.wg_index.network(),
        SshPublicKey::from(node.ssh.host_ed25519).fingerprint(),
        if holders.is_empty() {
            "none".to_owned()
        } else {
            holders.join(", ")
        }
    )?;
    let settled: Vec<&str> = before
        .users()
        .values()
        .filter(|user| {
            user.status == UserStatus::RevokePending
                && left(user).is_some_and(|left| left.status == UserStatus::Revoked)
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
    let has_channels = |deployment: &Deployment| {
        deployment
            .alerting()
            .is_some_and(|alerting| alerting.channels.contains(id))
    };
    if has_channels(before) && !has_channels(after) {
        let topic = SecretRef::AlertTopic;
        let topic_goes = before.required_secrets().contains(&topic)
            && !after.required_secrets().contains(&topic);
        writeln!(
            out,
            "its alert channels go with it{}",
            if topic_goes {
                ", and the alert topic with them, as no other node has channels"
            } else {
                ""
            }
        )?;
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
        stranded_note(out, id)?;
    }
    Ok(())
}

/// What deleting the node's keys means for a VPS an adoption on this Mac
/// may have handed to them.
fn stranded_note(out: &mut dyn Write, id: &NodeId) -> io::Result<()> {
    writeln!(
        out,
        "`node adopt {id}` ran on this Mac: if its Bootstrap ran, the VPS lets in only the Mooring keys this deletes, not your own root key, so reinstall it or delete it from the provider's console"
    )
}

/// What the committed cancel means for the commands after it: no apply for
/// its own sake, the id free again once its files are gone, and the nodes
/// an earlier change left behind the generation.
fn summarize(
    out: &mut dyn Write,
    deployment: &Deployment,
    id: &NodeId,
    files_gone: bool,
) -> io::Result<()> {
    let generation = deployment.config_generation();
    writeln!(
        out,
        "cancelled node {id}: the configuration generation stays {}, so the cancel needs no `node apply`{}",
        generation.get(),
        if files_gone {
            ", and the id may be planned again"
        } else {
            ""
        }
    )?;
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
        )?;
    }
    Ok(())
}
