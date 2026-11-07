// SPDX-License-Identifier: GPL-3.0-or-later

//! `user usage <uid> [--json | --out <path>] [--bins-only]` (design §15.3):
//! what this Mac holds about one user's traffic, as the daemon would keep
//! it now (`mooring-daemon-core`'s `CollectedUsage::user_history`), from
//! `state.json` and the usage the daemon collected in `usage/users.json`.
//!
//! The command reads and never writes either: the state under the shared
//! lock every reader takes, the collected usage as `portal export` reads
//! it, with no lock (the daemon replaces it whole). It names the user by id
//! and alias, never by label, which stays on this Mac. Only `--out`
//! writes: a new file, as an export's file is written.

mod text;

use std::io::{self, Write};
use std::path::Path;

use mooring_daemon_core::usage::history::{UsageScope, UserUsageHistory};
use mooring_model::UserId;
use mooring_store::{Store, USAGE_DIRECTORY, USER_USAGE_FILE};

use crate::app::{Env, support_dir};
use crate::daemon::usage::{UsageFault, read_collected_document};
use crate::error::{CommandError, LocalError};
use crate::export_file;
use crate::router::output::json_line;
use crate::state::{load, output};

/// `user usage`: prints `user`'s history as a summary, or as one JSON line
/// with `json`, or writes it pretty-printed to the new file `path` (mode
/// 0600, never overwriting one, its folder warned about as for an
/// export's). `json` and `path` never come together: clap refuses them.
///
/// Refused, with nothing printed, in this order: no state (`NoState`); an
/// id the deployment does not hold (`UnknownUser`), before the collected
/// usage is opened; no collected usage (`NoCollectedUsage`); collected
/// usage that cannot be read or is inconsistent (`UserUsage`, with the
/// core's reason); and, with `path`, a file that exists or cannot be
/// written. A summary that cannot be made, which only a time in the state
/// past the year 9999 could cause, is an output error.
pub(crate) fn usage(
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    user: &UserId,
    json: bool,
    scope: UsageScope,
    path: Option<&Path>,
) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let state = load(&Store::new(&support))?;
    if !state.deployment.users().contains_key(user) {
        return Err(LocalError::UnknownUser { user: user.clone() }.into());
    }
    let collected = read_collected_document(&support)
        .map_err(|error| LocalError::UserUsage(Box::new(UsageFault::Read(error))))?
        .ok_or_else(|| LocalError::NoCollectedUsage {
            path: support.join(USAGE_DIRECTORY).join(USER_USAGE_FILE),
        })?;
    // Read once the document is: a month the daemon received just before
    // is then never after now.
    let now = (env.clock)()?;
    let history = collected
        .user_history(&state.deployment, user, now, scope)
        .map_err(|error| LocalError::UserUsage(Box::new(UsageFault::Inconsistent(error))))?;
    let text = match path {
        Some(path) => return write(env, out, err, path, &history),
        None if json => json_line(&history)
            .map_err(io::Error::other)
            .map_err(output)?,
        None => text::summary(&history)
            .map_err(io::Error::other)
            .map_err(output)?,
    };
    out.write_all(text.as_bytes()).map_err(output)
}

/// Writes `history` as the core encodes it for a file to the new file
/// `path`, through the export file's checks, and says so.
fn write(
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    path: &Path,
    history: &UserUsageHistory,
) -> Result<(), CommandError> {
    let bytes = history.pretty().map_err(io::Error::other).map_err(output)?;
    export_file::prepare(env, err, path)?;
    export_file::write_new(path, &bytes)?;
    out.write_all(
        format!(
            "wrote {}: the usage history of user {}, mode 0600; it names the user by id and alias, never by label\n",
            path.display(),
            history.user()
        )
        .as_bytes(),
    )
    .map_err(output)
}
