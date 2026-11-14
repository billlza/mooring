// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's policy step and removals (design §13.6, §15.7).
//!
//! The step plans at the run's `now` from the deployment the run read,
//! what the users' paid orders gave and the cycle's usage, and carries the
//! plan out one configuration change each: every suspension, at that
//! `now`, then every resume, earliest suspension first. Each change reads
//! the state again and edits the user under the store's lock, so a user
//! the operator changed meanwhile is left alone: a suspension only of a
//! user still active, a resume only of a user still under the suspension
//! the plan resumes. A change that fails is reported and the next one is
//! made. The night's run plans the whole step ([`Plan::Full`]); an hourly
//! firing outside the window plans only the resumes at expiry that a
//! payment has lifted ([`Plan::ExpiryResumes`]), and runs at all only when
//! [`nothing_to_resume`] does not hold.
//!
//! The removals follow, in the night's run only: each user whose
//! revocation is 13 months old, then the kept ids whose records have
//! expired, each a bookkeeping record of its own, at the run's `now`.

use std::path::Path;

use mooring_daemon_core::apply::{
    PolicyPlan, expiry_resumes_due, forgotten_expired, plan_expiry_resumes, plan_policy,
    removals_due,
};
use mooring_daemon_core::error::PolicyErrorKind;
use mooring_daemon_core::policy::{PolicyAction, PolicyWarning};
use mooring_model::{Bookkeeping, Deployment, ModelError, UnixTime, User, UserId, UserStatus};
use mooring_store::Store;

use super::report::{
    Change, FailedChange, FailedRemoval, PolicyDone, PolicyOutcome, Refusal, RefusalKind, Removals,
    RemovalsDone,
};
use crate::collected_usage::{Usage, usage};
use crate::daemon::chain;
use crate::payments::command::entitlements;

/// Why the store refused one of the step's changes.
#[derive(Debug, thiserror::Error)]
enum Moved {
    /// The user has left the deployment since the plan.
    #[error("the user is no longer in the deployment")]
    Gone,
    /// The user's suspension is not the one the plan resumes.
    #[error("the user's status changed since the run planned this")]
    Changed,
    /// The model refused the transition.
    #[error(transparent)]
    Model(#[from] ModelError),
}

/// Which plan the policy step carries out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Plan {
    /// The whole step (`plan_policy`): the night's run, and `--now`.
    Full,
    /// Only the resumes at expiry that a payment has lifted
    /// (`plan_expiry_resumes`): an hourly firing outside the window.
    ExpiryResumes,
}

/// Whether an hourly firing outside the window at `now` finds no
/// suspension at expiry that a payment has lifted, and so has nothing to
/// do. A state, payment ledger or pull settings that cannot be read, and a
/// plan refused, are no such finding: the firing runs, and its report and
/// log say what failed.
pub(super) fn nothing_to_resume(store: &Store, support: &Path, now: UnixTime) -> bool {
    let Ok(state) = store.load() else {
        return false;
    };
    let Ok(paid) = entitlements(support) else {
        return false;
    };
    expiry_resumes_due(&state.deployment, &paid, now).is_ok_and(|due| due.is_empty())
}

/// Plans the policy step at `now` for `deployment`, as `plan` says, and
/// carries it out.
pub(super) fn step(
    store: &Store,
    support: &Path,
    deployment: &Deployment,
    now: UnixTime,
    plan: Plan,
) -> PolicyOutcome {
    let paid = match entitlements(support) {
        Ok(paid) => paid,
        Err(error) => return refused(RefusalKind::PaymentFiles, &error),
    };
    let usage = match usage(support, deployment, now) {
        Ok(usage) => usage,
        Err(fault) => return refused(RefusalKind::Usage, &fault),
    };
    let (cycle, behind) = match &usage {
        Usage::Report(report) => (Some(report.cycle_usage()), None),
        Usage::Behind(error) => (None, Some(chain(error))),
    };
    let planned = match plan {
        Plan::Full => plan_policy(deployment, &paid, cycle.as_ref(), now),
        Plan::ExpiryResumes => plan_expiry_resumes(deployment, &paid, cycle.as_ref(), now),
    };
    match planned {
        Ok(plan) => PolicyOutcome::CarriedOut(Box::new(carry_out(store, &plan, behind))),
        Err(error) => {
            let kind = match error.kind() {
                PolicyErrorKind::QuotaSuspensionAfterNow => RefusalKind::ClockSteppedBack,
                _ => RefusalKind::Policy,
            };
            refused(kind, &error)
        }
    }
}

/// Carries `plan` out on the state as it is now, one change each, and
/// reports it; `behind` says why no usage report could be made, if none
/// could.
pub(crate) fn carry_out(store: &Store, plan: &PolicyPlan, behind: Option<String>) -> PolicyDone {
    let mut done = PolicyDone {
        usage_behind: behind,
        quotas_unchecked: plan
            .warnings
            .iter()
            .filter(|warning| {
                matches!(
                    warning.action,
                    PolicyAction::Warn(PolicyWarning::QuotaUnchecked { .. })
                )
            })
            .map(|warning| warning.user.clone())
            .collect(),
        held_back: plan.held_back.clone(),
        kept: plan.kept.clone(),
        ..PolicyDone::default()
    };
    for suspension in &plan.suspensions {
        match change(store, &suspension.user, |user| {
            Ok(user.suspend(suspension.reason, plan.now)?)
        }) {
            Ok(()) => done.suspended.push(suspension.clone()),
            Err(error) => done.failed.push(FailedChange {
                user: suspension.user.clone(),
                change: Change::Suspend,
                error,
            }),
        }
    }
    for lapsed in &plan.resumes {
        let planned = UserStatus::Suspended {
            reason: lapsed.reason,
            since: lapsed.since,
        };
        match change(store, &lapsed.user, |user| {
            if user.status != planned {
                return Err(Moved::Changed);
            }
            Ok(user.resume()?)
        }) {
            Ok(()) => done.resumed.push(lapsed.clone()),
            Err(error) => done.failed.push(FailedChange {
                user: lapsed.user.clone(),
                change: Change::Resume,
                error,
            }),
        }
    }
    done
}

fn refused(kind: RefusalKind, error: &dyn std::error::Error) -> PolicyOutcome {
    PolicyOutcome::Refused(Refusal {
        kind,
        error: chain(error),
    })
}

/// One configuration change: `edit` applied to `user` in the state as it
/// is now. The error, which names nothing but the user's id, if that.
fn change(
    store: &Store,
    user: &UserId,
    edit: impl FnOnce(&mut User) -> Result<(), Moved>,
) -> Result<(), String> {
    let state = store.load().map_err(|error| chain(&error))?;
    store
        .update_config::<Moved, _>(state.deployment.config_generation(), |mut parts| {
            let found = parts
                .users
                .iter_mut()
                .find(|candidate| candidate.id == *user)
                .ok_or(Moved::Gone)?;
            edit(found)?;
            Ok(parts)
        })
        .map(drop)
        .map_err(|error| chain(&error))
}

/// The removals at `now`: each user revoked 13 months ago, then the kept
/// ids whose records have expired; none when the clock stepped back.
pub(super) fn remove(store: &Store, now: UnixTime, clock_stepped_back: bool) -> Removals {
    if clock_stepped_back {
        return Removals::Skipped;
    }
    let mut done = RemovalsDone::default();
    let due = match store.load() {
        Ok(state) => removals_due(&state.deployment, now).map_err(|error| chain(&error)),
        Err(error) => Err(chain(&error)),
    };
    let due = match due {
        Ok(due) => due,
        Err(error) => {
            done.failed.push(FailedRemoval { user: None, error });
            return Removals::Done(done);
        }
    };
    for user in due {
        match record(
            store,
            Bookkeeping::RevokedUserRemoved {
                user: user.clone(),
                at: now,
            },
        ) {
            Ok(()) => done.removed.push(user),
            Err(error) => done.failed.push(FailedRemoval {
                user: Some(user),
                error,
            }),
        }
    }
    let expired = store
        .load()
        .map(|state| forgotten_expired(&state.deployment, now))
        .map_err(|error| chain(&error));
    match expired {
        Ok(false) => {}
        Ok(true) => match record(store, Bookkeeping::ForgottenExpired { at: now }) {
            Ok(()) => done.kept_ids_dropped = true,
            Err(error) => done.failed.push(FailedRemoval { user: None, error }),
        },
        Err(error) => done.failed.push(FailedRemoval { user: None, error }),
    }
    Removals::Done(done)
}

/// Records `entry` on the state as it is now.
fn record(store: &Store, entry: Bookkeeping) -> Result<(), String> {
    let state = store.load().map_err(|error| chain(&error))?;
    store
        .record(state.deployment.config_generation(), entry)
        .map(drop)
        .map_err(|error| chain(&error))
}
