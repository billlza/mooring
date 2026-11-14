// SPDX-License-Identifier: GPL-3.0-or-later

//! Spare users on the Mac (design §13.6): user ids drawn ahead of need,
//! each with its credentials on the nodes, so that `user add` changes
//! nothing a node's engines read only at their start. `user add` takes the
//! spare with the lowest id ([`new_user`]); the nightly apply job keeps
//! [`SPARE_USERS`] ready, inside its window ([`top_up`]), where the restart
//! their first apply needs is expected.

use std::collections::{BTreeMap, BTreeSet};

use mooring_keys::credentials;
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::SecretEntry;
use mooring_model::{Deployment, NodeId, SPARE_USERS, SpareUser, UserId, UserNodePublic};

use crate::error::LocalError;

/// The nodes a new identity gets credentials on: every node planned,
/// adopted or applied, none retiring. `user add` has always given a user
/// credentials on exactly these, so that the user holds every node it can
/// be served by.
pub(crate) fn eligible(deployment: &Deployment) -> impl Iterator<Item = &NodeId> {
    deployment
        .nodes()
        .values()
        .filter(|node| {
            matches!(
                node.lifecycle,
                NodeLifecycle::Planned
                    | NodeLifecycle::Adopted { .. }
                    | NodeLifecycle::Applied { .. }
            )
        })
        .map(|node| &node.id)
}

/// Fresh credentials for identity `id` on `node`, kept under `id`: a short
/// id, a VLESS UUID, a Hysteria 2 password and a loopback UUID.
fn mint(id: &UserId, node: &NodeId) -> Result<(UserNodePublic, [SecretEntry; 3]), LocalError> {
    let public = UserNodePublic {
        short_id: credentials::short_id().map_err(LocalError::Keys)?,
    };
    let secrets = [
        SecretEntry::UserVlessUuid(
            id.clone(),
            node.clone(),
            credentials::credential_uuid().map_err(LocalError::Keys)?,
        ),
        SecretEntry::UserHy2Password(
            id.clone(),
            node.clone(),
            credentials::password().map_err(LocalError::Keys)?,
        ),
        SecretEntry::UserLoopUuid(
            id.clone(),
            node.clone(),
            credentials::credential_uuid().map_err(LocalError::Keys)?,
        ),
    ];
    Ok((public, secrets))
}

/// A new user's id and credentials, before it is added.
#[derive(Debug)]
pub(crate) struct NewUser {
    /// Its id: the spare's it takes, or a fresh one.
    pub(crate) id: UserId,
    /// Whether it takes the spare with its id.
    pub(crate) takes_spare: bool,
    /// Its credentials on each eligible node.
    pub(crate) per_node: BTreeMap<NodeId, UserNodePublic>,
    /// The secrets minted for it: on every node without a spare, else on
    /// the nodes the spare held none on.
    pub(crate) secrets: Vec<SecretEntry>,
    /// The nodes it holds fresh credentials on.
    pub(crate) fresh: BTreeSet<NodeId>,
}

/// The user `user add` adds to `deployment`: the spare with the lowest id,
/// with its credentials on each eligible node and fresh ones on any it
/// lacks (a node planned since the spare was drawn), or, with no spare
/// ready, a fresh id with fresh credentials on every eligible node. The
/// spare's credentials on a node no longer eligible (one retiring) are left
/// out, so the store deletes them.
pub(crate) fn new_user(deployment: &Deployment) -> Result<NewUser, LocalError> {
    let spare = deployment.spares().values().next();
    let id = match spare {
        Some(spare) => spare.id.clone(),
        None => credentials::user_id().map_err(LocalError::Keys)?,
    };
    let mut new = NewUser {
        id,
        takes_spare: spare.is_some(),
        per_node: BTreeMap::new(),
        secrets: Vec::new(),
        fresh: BTreeSet::new(),
    };
    for node in eligible(deployment) {
        let held = spare.and_then(|spare| spare.per_node.get(node));
        let public = match held {
            Some(public) => *public,
            None => {
                let (public, secrets) = mint(&new.id, node)?;
                new.secrets.extend(secrets);
                new.fresh.insert(node.clone());
                public
            }
        };
        new.per_node.insert(node.clone(), public);
    }
    Ok(new)
}

/// The nightly top-up of a deployment's spare users.
#[derive(Debug)]
pub(crate) struct TopUp {
    /// Every spare user, as the top-up leaves them.
    pub(crate) spares: Vec<SpareUser>,
    /// The secrets minted.
    pub(crate) secrets: Vec<SecretEntry>,
    /// How many spare users it draws.
    pub(crate) drawn: usize,
    /// How many credentials it gives spares already drawn, one per spare
    /// and node.
    pub(crate) credentials: usize,
}

/// The top-up of `deployment`: each spare given credentials on every
/// eligible node it lacks them on, then new spares drawn, with credentials
/// on every eligible node, until [`SPARE_USERS`] are ready. `None` when
/// there is nothing to do, so that a run that changes nothing leaves the
/// generation as it is. A spare's credentials on a node no longer eligible
/// stay until the node is released.
pub(crate) fn top_up(deployment: &Deployment) -> Result<Option<TopUp>, LocalError> {
    let nodes: Vec<&NodeId> = eligible(deployment).collect();
    let mut secrets = Vec::new();
    let mut give = |spare: &mut SpareUser| -> Result<usize, LocalError> {
        let mut given = 0;
        for node in &nodes {
            if !spare.per_node.contains_key(*node) {
                let (public, minted) = mint(&spare.id, node)?;
                spare.per_node.insert((*node).clone(), public);
                secrets.extend(minted);
                given += 1;
            }
        }
        Ok(given)
    };
    let mut spares = Vec::new();
    let mut credentials_given = 0;
    for spare in deployment.spares().values() {
        let mut spare = spare.clone();
        credentials_given += give(&mut spare)?;
        spares.push(spare);
    }
    let mut drawn = 0;
    while spares.len() < SPARE_USERS {
        let mut spare = SpareUser {
            id: credentials::user_id().map_err(LocalError::Keys)?,
            per_node: BTreeMap::new(),
        };
        give(&mut spare)?;
        spares.push(spare);
        drawn += 1;
    }
    Ok((drawn > 0 || credentials_given > 0).then_some(TopUp {
        spares,
        secrets,
        drawn,
        credentials: credentials_given,
    }))
}
