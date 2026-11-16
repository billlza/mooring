// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl apply --pending | --now [--json]` (design §13.6, §15.3,
//! §15.7): the nightly apply job. launchd runs `apply --pending` every
//! hour at minute 20 of the Mac's local time
//! (`com.bill.mooring.apply.plist`); it runs only between 19:15 and 19:45
//! UTC (`daemon-core`'s `apply::in_window`), so one firing a day runs, in
//! BST and GMT alike, and a firing outside that window, as launchd delivers
//! one late after a sleep, does nothing. The operator's `apply --now` runs
//! at once.
//!
//! A run takes `run/apply.lock`, so two never overlap, and then, in this
//! order, makes each change on its own, so that none blocks another:
//! 1. **The policy step** ([`policy::step`]): `daemon-core`'s
//!    `plan_policy` at the run's `now`, from the state, what the users'
//!    paid orders gave (the payment ledger) and the cycle's usage the
//!    daemon collected; its suspensions, each recorded at that `now`, then
//!    its resumes, one configuration change each. A payment ledger or pull
//!    settings that cannot be read refuse the step, since a paid user
//!    would be read as unpaid; so do collected usage that cannot be read
//!    or is inconsistent, and a suspension for quota dated after `now` (a
//!    clock that stepped back). Usage that is behind (the daemon stopped,
//!    or a node it cannot reach) leaves the quotas unchecked, and the rest
//!    of the step runs. Last, the users suspended at expiry whose service
//!    was not renewed in three months are revoked, one change each, if the
//!    agreement they accepted provides for it (`Env::expiry_revocation`);
//!    the others are reported.
//! 2. **Removals** ([`policy::remove`]): each user revoked 13 months ago
//!    (`RevokedUserRemoved`), then the kept ids whose records have expired
//!    (`ForgottenExpired`); skipped when the clock stepped back. The daemon
//!    deletes what it keeps of a removed user (its usage history and its
//!    payment orders) on its next tick.
//! 3. **Node applies** ([`nodes::apply_behind`]): every applied node whose
//!    confirmed generation is older than the deployment's, by id, through
//!    the exit's egress as the daemon resolves it, with the engines in the
//!    support directory; one that fails is reported, and the next one runs.
//! 4. **Revocations** (`revocation::commit`): every revocation a node
//!    applied at the deployment's generation settles, whether this run or
//!    an earlier one applied it, each a bookkeeping record of its own,
//!    after which the user's credentials on that node are deleted from the
//!    keychain; then each user still pending, with what it waits on. A node
//!    that cannot be reached keeps its users pending. Skipped when the clock
//!    stepped back, as the removals are, since a record dates the
//!    revocation by it; what waits is still reported.
//!
//! The report names users by id, on standard output; the log,
//! `~/Library/Logs/Mooring/apply.log`, counts them and names none, since a
//! log line can outlive the 13 months the agreement keeps a user's records
//! (§15.7). `--pending` points standard error at the log, as the daemon
//! does, since launchd keeps no output of an agent. The run fails (exit 1)
//! when any part of it failed; a user the cap holds back, a lapsed
//! suspension kept, and quotas left unchecked are reported, and are no
//! failure.

mod nodes;
pub(crate) mod policy;
pub(crate) mod report;

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::os::fd::BorrowedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use mooring_daemon_core::apply::in_window;
use mooring_macsys::MacsysError;
use mooring_store::Store;

use self::report::{Outcome, Revocations};
use crate::app::{Env, support_dir};
use crate::daemon::chain;
use crate::daemon::log::{APPLY_LOG, ROTATE_AT_BYTES, RedirectStderr, RotatingLog, log_dir};
use crate::daemon::{prepare_run_dir, say_as};
use crate::error::{CommandError, LocalError};
use crate::revocation;
use crate::state::load;

/// The job's lock, in the daemon's run directory: one run at a time.
pub(crate) const APPLY_LOCK_FILE: &str = "apply.lock";

/// Which form of the job runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum When {
    /// launchd's hourly firing: it runs only within the window.
    Pending,
    /// The operator's: it runs at once.
    Now,
}

impl When {
    /// The flag that names it.
    const fn flag(self) -> &'static str {
        match self {
            Self::Pending => "--pending",
            Self::Now => "--now",
        }
    }
}

/// Leaves standard error where it is: `--now` runs at the operator's
/// terminal.
fn keep_stderr(_: BorrowedFd<'_>) -> Result<(), MacsysError> {
    Ok(())
}

/// `apply --pending | --now [--json]`.
pub(crate) fn apply(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    when: When,
    json: bool,
) -> Result<(), CommandError> {
    let now = (env.clock)()?;
    if when == When::Pending && !in_window(now) {
        return report::outside_window(out, now, json);
    }
    let support = support_dir(env)?;
    let run = prepare_run_dir(&support)?;
    let _lock = lock(&run.dir.join(APPLY_LOCK_FILE))?;
    let redirect: &RedirectStderr<'_> = match when {
        When::Pending => env.redirect_stderr,
        When::Now => &keep_stderr,
    };
    let mut log = RotatingLog::open(
        &log_dir(env.home.clone())?,
        APPLY_LOG,
        ROTATE_AT_BYTES,
        redirect,
    )?;
    let restored: Vec<String> = log.restored().iter().map(|mode| mode.line()).collect();
    for line in restored {
        say_as(&mut log, now, "apply", &line)?;
    }
    say_as(&mut log, now, "apply", &format!("run ({})", when.flag()))?;
    let store = Store::new(&support);
    let deployment = load(&store)?.deployment;
    let policy = policy::step(&store, &support, &deployment, now, env.expiry_revocation);
    say_as(&mut log, (env.clock)()?, "apply", &policy.log_line())?;
    let removals = policy::remove(&store, now, policy.clock_stepped_back());
    say_as(&mut log, (env.clock)()?, "apply", &removals.log_line())?;
    if !json {
        report::write_lines(out, &policy.lines(), &removals.lines())?;
    }
    let mut progress = Vec::new();
    let sink: &mut dyn Write = if json { &mut progress } else { out };
    let nodes = nodes::apply_behind(env, sink, &store, &support, &mut |node, at| {
        say_as(&mut log, at, "apply", &node.log_line())
    })?;
    let at = (env.clock)()?;
    let revocations = if policy.clock_stepped_back() {
        match revocation::waiting(&store) {
            Ok(pending) => Revocations::Skipped { pending },
            Err(error) => Revocations::Unread {
                error: chain(&error),
            },
        }
    } else {
        match revocation::commit(&store, env.secrets, at, None) {
            Ok(commits) => Revocations::Done(commits),
            Err(error) => Revocations::Unread {
                error: chain(&error),
            },
        }
    };
    if let Some(line) = revocations.log_line() {
        say_as(&mut log, at, "apply", &line)?;
    }
    let outcome = Outcome {
        at: now,
        policy,
        removals,
        nodes,
        revocations,
    };
    let failures = outcome.failures();
    say_as(
        &mut log,
        (env.clock)()?,
        "apply",
        &format!("done: {failures} failure(s)"),
    )?;
    outcome.finish(out, json)?;
    if failures == 0 {
        Ok(())
    } else {
        Err(LocalError::ApplyFailed { failures }.into())
    }
}

/// Takes the job's lock at `path` (made with mode 0600): a run that holds
/// it already is `ApplyAlreadyRunning`.
fn lock(path: &Path) -> Result<File, LocalError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|source| LocalError::ApplyLock {
            path: path.to_path_buf(),
            source,
        })?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(LocalError::ApplyAlreadyRunning {
            path: path.to_path_buf(),
        }),
        Err(TryLockError::Error(source)) => Err(LocalError::ApplyLock {
            path: path.to_path_buf(),
            source,
        }),
    }
}
