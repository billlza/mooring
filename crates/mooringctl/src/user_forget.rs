// SPDX-License-Identifier: GPL-3.0-or-later

//! `user forget <uid> [--yes]` (design §15.3, §15.7; the agreement's
//! clause 4): removes a revoked user at once, on the user's request,
//! instead of 13 months after the revocation, as the bookkeeping record
//! `RevokedUserRemoved`. The user's label, alias and agreement record leave
//! `state.json` with it; the daemon deletes what it keeps of the user (the
//! usage history and lifetime totals, and the payment ledger's orders) on
//! its next tick, since it alone writes those files and holds them in
//! memory.
//!
//! The nodes' records of the user expire on their own schedule (§11.5), so
//! the bare opaque id stays in the state until the last of them has
//! expired, and nothing else of the user; a node's late reply naming it is
//! then dropped, not stored again. The apply job drops the id after that
//! (`ForgottenExpired`).
//!
//! Only a revoked user is removed: one that is active, suspended or being
//! revoked still holds credentials on a node, or soon did. What the command
//! says before it asks is read from the record applied to the deployment
//! it loaded (`state::recorded`), and the state is read again when the
//! answer comes and must be the one described (`state::unchanged`).

use std::io::Write;

use mooring_model::{Bookkeeping, Deployment, UserId, UserStatus};
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::error::CommandError;
use crate::exit::confirm;
use crate::payments::notes::stamp;
use crate::state::{load, output, recorded, store_failure, unchanged};

/// `user forget`.
pub(crate) fn forget(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    id: &UserId,
    yes: bool,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    let deployment = &state.deployment;
    let entry = Bookkeeping::RevokedUserRemoved {
        user: id.clone(),
        at: (env.clock)()?,
    };
    let after = recorded(deployment, entry.clone())?;
    describe(out, deployment, &after, id).map_err(output)?;
    confirm(env, yes, "Remove this user now?")?;
    unchanged(&store, deployment)?;
    store
        .record(deployment.config_generation(), entry)
        .map_err(store_failure)?;
    writeln!(
        out,
        "removed {id}: the daemon deletes its usage history and payment orders at its next tick, or when it next starts"
    )
    .map_err(output)
}

/// What the removal of `id` does, read from `after`, the deployment with
/// it recorded.
fn describe(
    out: &mut dyn Write,
    before: &Deployment,
    after: &Deployment,
    id: &UserId,
) -> std::io::Result<()> {
    let user = &before.users()[id];
    let alias = user
        .alias
        .as_ref()
        .map_or_else(String::new, |alias| format!(" (alias {alias})"));
    // `recorded` refused every other status before this is said.
    let since = match user.status {
        UserStatus::Revoked { since } => format!(", revoked since {}", stamp(since)),
        UserStatus::Active | UserStatus::Suspended { .. } | UserStatus::RevokePending => {
            String::new()
        }
    };
    writeln!(
        out,
        "user {id}{alias}{since}: its label, alias and agreement record leave state.json now, and the daemon then deletes its usage history and its payment orders"
    )?;
    match after.forgotten().get(id) {
        Some(until) => writeln!(
            out,
            "its bare id stays until {}, while a node may still name it, so that a node's late reply is dropped, not stored again",
            stamp(*until)
        )?,
        None => writeln!(out, "no id is kept: the nodes' records of it have expired")?,
    }
    writeln!(out, "this cannot be undone")
}
