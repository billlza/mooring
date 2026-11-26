// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl apply --pending | --now [--json]` (design §13.6, §15.3,
//! §15.7): the nightly apply job. launchd runs `apply --pending` every
//! hour at minute 20 of the Mac's local time
//! (`com.bill.mooring.apply.plist`); the whole job runs only between 19:15
//! and 19:45 UTC (`daemon-core`'s `apply::in_window`), so one firing a day
//! runs it, in BST and GMT alike. Every other firing, one launchd delivers
//! late after a sleep included, only resumes the users whose suspension at
//! expiry a payment has lifted, and then applies the nodes behind, so that
//! a user who pays is served within the hour (the operator's decision of
//! 2026-11-14); one that finds no such user ([`policy::nothing_to_resume`])
//! does nothing, and takes no lock and writes no log. The operator's
//! `apply --now` runs the whole job at once.
//!
//! A run takes `run/apply.lock`, so two never overlap, and then, in this
//! order, makes each change on its own, so that none blocks another (an
//! hourly firing outside the window makes the first step as
//! `plan_expiry_resumes` plans it, no removals, and the node applies, with
//! the records of the revocations they settle, only when it resumed a
//! user):
//! 1. **The policy step** ([`policy::step`]): `daemon-core`'s
//!    `plan_policy` at the run's `now`, from the state, what the users'
//!    paid orders gave (the payment ledger) and the cycle's usage the
//!    daemon collected; its suspensions, each recorded at that `now`, then
//!    its resumes, one configuration change each. A payment ledger or pull
//!    settings that cannot be read refuse the step, since a paid user
//!    would be read as unpaid; so do collected usage that cannot be read
//!    or is inconsistent, and an expiry or quota suspension dated after
//!    `now` (a clock that stepped back). While usage is behind because the
//!    daemon stopped or a node is unreachable, the rest of the step runs
//!    with quotas unchecked. Last, in the whole job only, the users
//!    suspended at expiry whose service was not renewed in three months
//!    are revoked, one change each, if the agreement they accepted provides
//!    for it (`Env::expiry_revocation`); the others are reported. An hourly
//!    firing revokes no one: a revocation cannot be undone, so it waits for
//!    the night's run, as the suspensions do.
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

use self::policy::Plan;
use self::report::{Applies, Form, NodeOutcome, Outcome, Revocations};
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
    /// launchd's hourly firing runs the full job in the window and checks
    /// for expiry resumes outside it.
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
    let support = support_dir(env)?;
    let store = Store::new(&support);
    let plan = match when {
        When::Now => Plan::Full,
        When::Pending if in_window(now) => Plan::Full,
        When::Pending if policy::nothing_to_resume(&store, &support, now) => {
            return report::outside_window(out, now, json);
        }
        When::Pending => Plan::ExpiryResumes,
    };
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
    let started = match plan {
        Plan::Full => format!("run ({})", when.flag()),
        Plan::ExpiryResumes => format!(
            "run ({}, outside the window: resumes at expiry only)",
            when.flag()
        ),
    };
    say_as(&mut log, now, "apply", &started)?;
    let deployment = load(&store)?.deployment;
    let policy = policy::step(
        &store,
        &support,
        &deployment,
        now,
        plan,
        env.expiry_revocation,
    );
    say_as(&mut log, (env.clock)()?, "apply", &policy.log_line())?;
    let skip_records = policy.clock_stepped_back();
    let form = match plan {
        Plan::Full => {
            let removals = policy::remove(&store, now, skip_records);
            say_as(&mut log, (env.clock)()?, "apply", &removals.log_line())?;
            if !json {
                report::write_lines(out, &policy.lines(), &removals.lines())?;
            }
            let applies =
                apply_and_record(env, out, json, &store, &support, &mut log, skip_records)?;
            Form::Full { removals, applies }
        }
        Plan::ExpiryResumes => {
            if !json {
                report::write_lines(out, &policy.lines(), &[])?;
            }
            // A node's engines restart during the day only for a user just
            // resumed: a node left behind otherwise waits for the night, and
            // so does the record of a revocation no apply of this firing
            // settled.
            let applies = if policy.resumed_any() {
                Some(apply_and_record(
                    env,
                    out,
                    json,
                    &store,
                    &support,
                    &mut log,
                    skip_records,
                )?)
            } else {
                None
            };
            Form::ExpiryResumes { applies }
        }
    };
    let outcome = Outcome {
        at: now,
        policy,
        form,
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

/// Applies every node behind ([`apply_nodes`]), then records the
/// revocations those applies, or earlier ones, settled
/// ([`record_revocations`]).
fn apply_and_record(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    json: bool,
    store: &Store,
    support: &Path,
    log: &mut RotatingLog,
    skip_records: bool,
) -> Result<Applies, CommandError> {
    let nodes = apply_nodes(env, out, json, store, support, log)?;
    let revocations = record_revocations(env, store, log, skip_records)?;
    Ok(Applies { nodes, revocations })
}

/// Records every revocation the nodes settled (`revocation::commit`),
/// logging the counts; with `skip_records`, since the run takes its clock
/// for one that stepped back, records none and only reads who still waits,
/// as no removal is made then: a record dates the revocation, and its
/// removal 13 months later, by that clock.
fn record_revocations(
    env: &mut Env<'_>,
    store: &Store,
    log: &mut RotatingLog,
    skip_records: bool,
) -> Result<Revocations, CommandError> {
    let at = (env.clock)()?;
    let revocations = if skip_records {
        match revocation::waiting(store) {
            Ok(pending) => Revocations::Skipped { pending },
            Err(error) => Revocations::Unread {
                error: chain(&error),
            },
        }
    } else {
        match revocation::commit(store, env.secrets, at, None) {
            Ok(commits) => Revocations::Done(commits),
            Err(error) => Revocations::Unread {
                error: chain(&error),
            },
        }
    };
    if let Some(line) = revocations.log_line() {
        say_as(log, at, "apply", &line)?;
    }
    Ok(revocations)
}

/// Applies every node behind, logging each outcome; with `json` the
/// applies' progress is not written, as the outcome is one JSON line.
fn apply_nodes(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    json: bool,
    store: &Store,
    support: &Path,
    log: &mut RotatingLog,
) -> Result<Vec<NodeOutcome>, CommandError> {
    let mut progress = Vec::new();
    let sink: &mut dyn Write = if json { &mut progress } else { out };
    nodes::apply_behind(env, sink, store, support, &mut |node, at| {
        say_as(log, at, "apply", &node.log_line())
    })
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
