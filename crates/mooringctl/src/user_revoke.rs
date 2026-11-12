// SPDX-License-Identifier: GPL-3.0-or-later

//! `user revoke <uid> [--yes]` (design §13.5, §15.3; the agreement's
//! clause 6): ends an active or suspended user's service for good, as when
//! the user leaves, a device of theirs was taken, or they were banned.
//!
//! It is a configuration change (`User::revoke`), so it bumps the
//! generation: a user holding credentials on some node becomes
//! `RevokePending`, served by no node from that generation on and exported
//! nowhere; one holding none is `Revoked` at once. Each node then commits
//! the revocation when it applies a configuration without the user, which
//! `node apply` and the apply job record (`RevocationCommitted`), and only
//! once that record is committed are the user's credentials on that node
//! deleted from the keychain ([`crate::revocation`]). Nothing is applied
//! here: the nightly job applies the nodes behind at 19:20 UTC, or
//! `mooringctl apply --now` at once.
//!
//! A revocation cannot be undone, so the command says first what it does,
//! read from the change applied to the deployment it loaded, and asks; the
//! state is read again when the answer comes and must be the one described
//! (`state::unchanged`). A user unknown, being revoked or revoked is
//! refused before anything is asked.
//!
//! The operator's other steps for a user who leaves (Stripe's auto-renewal
//! and saved card, the portal account) are in `docs/runbooks/revoke.md`,
//! section 3: Mooring reaches neither.

use std::io::{self, Write};

use mooring_model::removal::removal_due;
use mooring_model::user::SuspendReason;
use mooring_model::{Deployment, ModelError, UnixTime, UserId, UserStatus};
use mooring_store::{Store, StoreError};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::payments::notes::stamp;
use crate::revocation::{Pending, pending};
use crate::state::{load, output, refused_change, store_failure, unchanged};

/// `user revoke`.
pub(crate) fn revoke(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    id: &UserId,
    yes: bool,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let deployment = &state.deployment;
    let at = (env.clock)()?;
    let after = revoked(deployment, id, at)?;
    let removal = removal(&after, id)?;
    describe(out, deployment, &after, id, removal).map_err(output)?;
    confirm(env, yes, "Revoke this user?")?;
    unchanged(&store, deployment)?;
    let next = store
        .update_config(deployment.config_generation(), |mut parts| {
            let user = parts
                .users
                .iter_mut()
                .find(|candidate| candidate.id == *id)
                .ok_or_else(|| LocalError::UnknownUser { user: id.clone() })?;
            user.revoke(at).map_err(invalid)?;
            Ok(parts)
        })
        .map_err(refused_change)?;
    summarize(out, &next.deployment, id, removal).map_err(output)
}

/// The refusal a model error is for the change: what the store would give
/// for it (`InvalidChange`).
fn invalid(source: ModelError) -> LocalError {
    store_failure(StoreError::InvalidChange { source })
}

/// What the revocation makes of `deployment`, with nothing written: the
/// user `id` revoked at `at`, at the generation the change will have. An
/// unknown user is `UnknownUser`, and one being revoked or revoked the
/// model's `RevocationAlreadyStarted`.
fn revoked(deployment: &Deployment, id: &UserId, at: UnixTime) -> Result<Deployment, LocalError> {
    let mut parts = deployment.clone().into_parts();
    parts.config_generation = parts.config_generation.next().map_err(invalid)?;
    let user = parts
        .users
        .iter_mut()
        .find(|candidate| candidate.id == *id)
        .ok_or_else(|| LocalError::UnknownUser { user: id.clone() })?;
    user.revoke(at).map_err(invalid)?;
    Deployment::try_from(parts).map_err(invalid)
}

/// When the records of `id` go if `after` revokes it at once: 13 months
/// after its revocation. `None` while it waits on a node.
fn removal(after: &Deployment, id: &UserId) -> Result<Option<UnixTime>, LocalError> {
    match after.users().get(id).map(|user| user.status) {
        Some(UserStatus::Revoked { since }) => Ok(Some(removal_due(since).map_err(invalid)?)),
        Some(_) | None => Ok(None),
    }
}

/// What revoking `id` does, read from `after`, the deployment with it
/// made, whose records go at `removal` if it is revoked at once.
fn describe(
    out: &mut dyn Write,
    before: &Deployment,
    after: &Deployment,
    id: &UserId,
    removal: Option<UnixTime>,
) -> io::Result<()> {
    let user = &before.users()[id];
    let alias = user
        .alias
        .as_ref()
        .map_or_else(String::new, |alias| format!(" (alias {alias})"));
    let held: Vec<&str> = user.per_node.keys().map(|node| node.as_str()).collect();
    writeln!(
        out,
        "user {id}{alias}: {}; credentials on {}",
        status_text(user.status),
        if held.is_empty() {
            "no node".to_owned()
        } else {
            held.join(", ")
        }
    )?;
    writeln!(
        out,
        "revoking it ends its service for good: no node serves it from the configuration this makes, and no file or portal profile is made for it again"
    )?;
    match waiting(after, id) {
        None => writeln!(
            out,
            "it holds credentials on no node, so it is revoked at once{}",
            removal_text(removal, id)
        )?,
        Some(pending) => writeln!(
            out,
            "it waits on {}: each node commits the revocation once it applies a configuration without the user, and then its credentials there are deleted from the keychain; with none left it is revoked, and its records here go 13 months later, or at once with `mooringctl user forget {id}`",
            pending.nodes_text()
        )?,
    }
    writeln!(
        out,
        "this cannot be undone; the Stripe and portal steps that follow it are in docs/runbooks/revoke.md, section 3"
    )
}

/// What the committed revocation means for the commands after it.
fn summarize(
    out: &mut dyn Write,
    deployment: &Deployment,
    id: &UserId,
    removal: Option<UnixTime>,
) -> io::Result<()> {
    let generation = deployment.config_generation().get();
    match waiting(deployment, id) {
        None => writeln!(
            out,
            "revoked {id} (configuration generation {generation}){}",
            removal_text(removal, id)
        ),
        Some(pending) => writeln!(
            out,
            "revocation started for {id} (configuration generation {generation}): it waits on {}\nnext: `mooringctl apply --now` applies every applied node behind now, or the nightly apply job does at 19:20 UTC; it records each node's commit",
            pending.nodes_text()
        ),
    }
}

/// The revocation of `id` still pending in `deployment`, if it is.
fn waiting(deployment: &Deployment, id: &UserId) -> Option<Pending> {
    pending(deployment)
        .into_iter()
        .find(|pending| pending.user == *id)
}

/// When a revoked user's records go, as words to follow its revocation.
fn removal_text(removal: Option<UnixTime>, id: &UserId) -> String {
    removal.map_or_else(String::new, |due| {
        format!(
            ": its records here go 13 months later, on {}, or at once with `mooringctl user forget {id}`",
            stamp(due)
        )
    })
}

/// A status the command describes, in words.
fn status_text(status: UserStatus) -> String {
    match status {
        UserStatus::Active => "active".to_owned(),
        UserStatus::Suspended { reason, since } => {
            let why = match reason {
                SuspendReason::Operator => "by the operator".to_owned(),
                SuspendReason::QuotaExceeded { cycle_start } => {
                    format!("for quota in the billing cycle from {cycle_start}")
                }
                SuspendReason::Expired => "at expiry".to_owned(),
                SuspendReason::AbuseReview => "for an abuse review".to_owned(),
            };
            format!("suspended {why} since {}", stamp(since))
        }
        UserStatus::RevokePending => "being revoked".to_owned(),
        UserStatus::Revoked { since } => format!("revoked since {}", stamp(since)),
    }
}
