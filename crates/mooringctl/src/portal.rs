// SPDX-License-Identifier: GPL-3.0-or-later

//! `portal export` (design §9.5): the user portal's snapshot of the users
//! the operator names, from `state.json` and the usage the daemon collected
//! in `usage/users.json`, written as an export's file is.

use std::io::Write;
use std::path::Path;

use mooring_daemon_core::portal::snapshot;
use mooring_model::UserId;
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::collected_usage::{Usage, usage};
use crate::error::{CommandError, LocalError};
use crate::export_file;
use crate::payments::command::entitlements;
use crate::state::{load, output};

/// `portal export --user <uid>... --out <path>`: writes the snapshot of
/// `users` to a new file with mode 0600, never overwriting one.
///
/// Refused first while the agreement this build ships does not cover the
/// portal; then when the daemon's collected usage cannot be read or is
/// inconsistent (`PortalUsage`); then when the payment ledger or the
/// pull's settings cannot be read (`PaymentFiles`): each user's quota and
/// expiry include what their paid orders gave (design §9.6), and a ledger
/// that cannot be read is never read as no payment; then for anything
/// `mooring-daemon-core`
/// refuses (an unknown user, one without an acceptance of the required
/// revision, a user named twice, a record dated after now). Only then are
/// the file and its folder checked, as for `user export`.
///
/// The usage is the daemon's collected usage aggregated at now, as the
/// status line aggregates it. When the collection is behind, so that there
/// is no report (a serving node the daemon has not collected yet, or not
/// within the last three minutes, as when it is stopped), the snapshot says
/// so: every figure is `null`, the portal shows each user's usage as
/// unknown, and the reason is warned about on `err`.
pub(crate) fn export(
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    users: &[UserId],
    path: &Path,
) -> Result<(), CommandError> {
    env.portal_agreement
        .required()
        .map_err(LocalError::PortalNotCovered)?;
    let support = support_dir(env)?;
    let state = load(&Store::new(&support))?;
    let now = (env.clock)()?;
    let usage = usage(&support, &state.deployment, now)
        .map_err(|fault| LocalError::PortalUsage(Box::new(fault)))?;
    let report = match &usage {
        Usage::Report(report) => Some(report),
        Usage::Behind(_) => None,
    };
    let paid = entitlements(&support).map_err(|error| LocalError::PaymentFiles(Box::new(error)))?;
    let made = snapshot(
        &state.deployment,
        report,
        &paid,
        users,
        now,
        env.portal_agreement,
    )
    .map_err(|error| LocalError::PortalSnapshotRefused(Box::new(error)))?;
    export_file::prepare(env, err, path)?;
    if let Usage::Behind(reason) = &usage {
        err.write_all(
            format!(
                "mooringctl: warning: the snapshot holds no usage figures ({reason}); the portal shows each user's usage as unknown\n"
            )
            .as_bytes(),
        )
        .map_err(output)?;
    }
    export_file::write_new(path, made.bytes())?;
    let counted = match made.counted_through() {
        Some(through) => format!("usage counted through {through}"),
        None => "no usage figures".to_owned(),
    };
    out.write_all(
        format!(
            "wrote {}: portal snapshot of {} user(s), mode 0600\n{counted}, billing cycle {} to {}\nimport it with `mooring-portal import` on the portal host, then delete it\n",
            path.display(),
            made.users(),
            made.cycle().start(),
            made.cycle().next_start(),
        )
        .as_bytes(),
    )
    .map_err(output)
}
