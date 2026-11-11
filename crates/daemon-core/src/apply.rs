// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's decisions (design §13.6, §15.7): when a launchd firing
//! runs, what its policy step carries out, and which revoked users are due
//! for removal. Nothing here reads a clock or does I/O: `mooringctl apply`
//! reads the state, the payment ledger and the usage store, passes the time,
//! and carries the decisions out, one change each, then applies the nodes.
//!
//! - **When** ([`in_window`]). launchd fires the job every hour at minute
//!   20 of the Mac's local time; it runs only between 19:15 and 19:45 UTC
//!   (03:15 to 03:45 Beijing time), so in BST and GMT alike exactly one
//!   firing a day runs, at 19:20 UTC, before the nodes' 20:00 UTC reboot. A
//!   firing launchd delivers late, after a sleep, outside that span does
//!   nothing.
//! - **The policy step** ([`plan_policy`]). The suspensions `evaluate`
//!   proposes at the run's `now`, each recorded at that `now`; and the
//!   resumes of suspensions whose cause has gone: a suspension for quota
//!   made before the current billing cycle (`quota_suspension_holds_at`
//!   does not hold it), and a suspension at expiry once the user's paid time
//!   or own record runs past `now` again (design §9.6; the agreement's
//!   clause 1: service resumes once the user has paid). A suspension by the
//!   operator or for an abuse review is never resumed here: only the
//!   operator lifts it. Resumes go earliest suspension first, then by id,
//!   while fewer users are active than the cap allows, counting the users
//!   active when the run began: a place the run's own suspensions free is
//!   filled at the next run. A user the cap holds back is reported, not a
//!   failure. A user who would be suspended again at once (an expiry past,
//!   or a quota already used up) stays suspended and is reported. A
//!   suspension for quota made after `now` (a clock that stepped back, or
//!   a corrupt record) fails the step as a whole: none of its suspensions
//!   and resumes is carried out.
//! - **Removals** ([`removals_due`]). A user revoked 13 months ago is
//!   removed with every record the Mac holds of it (`RevokedUserRemoved`),
//!   and the kept ids of removed users whose nodes' records have expired go
//!   (`ForgottenExpired`).

use std::num::NonZeroU16;

use mooring_model::removal::removal_due;
use mooring_model::user::SuspendReason;
use mooring_model::{Deployment, ModelError, UnixTime, UserId, UserStatus};
use serde::Serialize;

use crate::error::PolicyError;
use crate::payments::Entitlements;
use crate::period::BillingCycle;
use crate::policy::{
    ExpiryState, PolicyAction, UserAction, automatic_quota, effective_policy, evaluate,
    quota_suspension_holds_at,
};
use crate::usage::CycleUsage;

/// Seconds after UTC midnight at which the window the job runs in opens:
/// 19:15 UTC, 03:15 in Beijing (UTC+8, no daylight saving time).
pub const WINDOW_OPENS_SECS: u64 = (19 * 60 + 15) * 60;

/// Seconds after UTC midnight at which the window closes: 19:45 UTC, which
/// leaves the job's node applies time to finish before the nodes'
/// unattended-upgrades reboot at 20:00 UTC (design §5.2).
pub const WINDOW_CLOSES_SECS: u64 = (19 * 60 + 45) * 60;

/// Whether a firing at `now` runs the job: from 19:15:00 UTC up to, and
/// not including, 19:45:00 UTC on any day.
#[must_use]
pub const fn in_window(now: UnixTime) -> bool {
    let secs = now.as_secs() % 86_400;
    secs >= WINDOW_OPENS_SECS && secs < WINDOW_CLOSES_SECS
}

/// A suspension the policy step carries out at the run's `now`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suspension {
    /// The user, active when the run began.
    pub user: UserId,
    /// Why, as `evaluate` proposed it.
    pub reason: SuspendReason,
}

/// A suspension whose cause has gone, which the policy step resumes, or
/// reports when it cannot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lapsed {
    /// The suspended user.
    pub user: UserId,
    /// The suspension's reason, as recorded.
    pub reason: SuspendReason,
    /// When the user was suspended.
    pub since: UnixTime,
}

/// A lapsed suspension the policy step does not resume, because the user
/// would be suspended again at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Kept {
    /// The lapsed suspension.
    pub lapsed: Lapsed,
    /// The suspension `evaluate` would propose for the user once active.
    pub again: SuspendReason,
}

/// What the policy step carries out at `now`, and what it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlan {
    /// The run's time: every suspension is recorded at it.
    pub now: UnixTime,
    /// The suspensions, in user order.
    pub suspensions: Vec<Suspension>,
    /// The resumes, one configuration change each, in this order.
    pub resumes: Vec<Lapsed>,
    /// The lapsed suspensions the cap holds back, in the order they wait.
    pub held_back: Vec<Lapsed>,
    /// The lapsed suspensions kept, because the user would be suspended
    /// again at once.
    pub kept: Vec<Kept>,
    /// The evaluation's warnings, in user order.
    pub warnings: Vec<UserAction>,
}

/// The policy step at `now` for `deployment`, with what the users' paid
/// orders gave (`paid`) and the cycle's `usage` (`None` when no usage
/// report could be made).
///
/// The lapsed suspensions are listed first, so that a suspension for quota
/// after `now` refuses the step before anything is proposed, whether or not
/// automatic quotas are on; then `evaluate` gives the run's suspensions and
/// warnings. Each lapsed suspension, in order, is resumed while the users
/// active when the run began, with the resumes before it, are fewer than
/// the cap; a resume is tried on a copy of the deployment and kept only if
/// `evaluate` there proposes no suspension for the user.
pub fn plan_policy(
    deployment: &Deployment,
    paid: &Entitlements,
    usage: Option<&CycleUsage>,
    now: UnixTime,
) -> Result<PolicyPlan, PolicyError> {
    let lapsed = lapsed_suspensions(deployment, paid, now)?;
    let mut suspensions = Vec::new();
    let mut warnings = Vec::new();
    for action in evaluate(deployment, paid, usage, now)? {
        match action.action {
            PolicyAction::Suspend(reason) => suspensions.push(Suspension {
                user: action.user,
                reason,
            }),
            PolicyAction::Warn(_) => warnings.push(action),
        }
    }
    let cap = deployment.capacity().max_active_users;
    let mut working = deployment.clone();
    let mut resumes = Vec::new();
    let mut held_back = Vec::new();
    let mut kept = Vec::new();
    for candidate in lapsed {
        if !room_for_one(&working, cap) {
            held_back.push(candidate);
            continue;
        }
        let trial = resumed(&working, &candidate.user)?;
        match suspended_again(&trial, paid, usage, now, &candidate.user)? {
            Some(again) => kept.push(Kept {
                lapsed: candidate,
                again,
            }),
            None => {
                working = trial;
                resumes.push(candidate);
            }
        }
    }
    Ok(PolicyPlan {
        now,
        suspensions,
        resumes,
        held_back,
        kept,
        warnings,
    })
}

/// Every suspension of `deployment` whose cause has gone at `now`, earliest
/// first and then by id: one for quota made before the current cycle, one
/// at expiry whose user's expiry (`effective_policy`, with what their paid
/// orders gave) is no longer past. One by the operator or for an abuse
/// review never lapses here. A suspension for quota after `now` is
/// `QuotaSuspensionAfterNow`.
fn lapsed_suspensions(
    deployment: &Deployment,
    paid: &Entitlements,
    now: UnixTime,
) -> Result<Vec<Lapsed>, PolicyError> {
    let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), now)?;
    let automatic = automatic_quota(deployment, now)?;
    let mut lapsed = Vec::new();
    for (id, user) in deployment.users() {
        let UserStatus::Suspended { reason, since } = user.status else {
            continue;
        };
        let gone = match reason {
            SuspendReason::QuotaExceeded { .. } => {
                !quota_suspension_holds_at(deployment, id, since, now)?
            }
            SuspendReason::Expired => {
                let policy = effective_policy(user, automatic, paid, cycle, now);
                !matches!(
                    ExpiryState::of(policy.expires_at, now),
                    ExpiryState::Expired { .. }
                )
            }
            SuspendReason::Operator | SuspendReason::AbuseReview => false,
        };
        if gone {
            lapsed.push(Lapsed {
                user: id.clone(),
                reason,
                since,
            });
        }
    }
    lapsed.sort_by(|left, right| (left.since, &left.user).cmp(&(right.since, &right.user)));
    Ok(lapsed)
}

/// Whether one more user may be active in `deployment` under `cap`.
fn room_for_one(deployment: &Deployment, cap: Option<NonZeroU16>) -> bool {
    cap.is_none_or(|cap| {
        let active = deployment
            .users()
            .values()
            .filter(|user| user.status == UserStatus::Active)
            .count();
        active < usize::from(cap.get())
    })
}

/// `deployment` with the suspended `user` active again.
fn resumed(deployment: &Deployment, user: &UserId) -> Result<Deployment, PolicyError> {
    let mut parts = deployment.clone().into_parts();
    for candidate in &mut parts.users {
        if candidate.id == *user {
            candidate.resume()?;
        }
    }
    Ok(Deployment::try_from(parts)?)
}

/// The suspension `evaluate` proposes for `user` in `deployment` at `now`,
/// if any.
fn suspended_again(
    deployment: &Deployment,
    paid: &Entitlements,
    usage: Option<&CycleUsage>,
    now: UnixTime,
    user: &UserId,
) -> Result<Option<SuspendReason>, PolicyError> {
    Ok(evaluate(deployment, paid, usage, now)?
        .into_iter()
        .find_map(|action| match action.action {
            PolicyAction::Suspend(reason) if action.user == *user => Some(reason),
            PolicyAction::Suspend(_) | PolicyAction::Warn(_) => None,
        }))
}

/// The revoked users of `deployment` due for removal at `now`, 13 calendar
/// months after their revocation ([`removal_due`]), in id order.
pub fn removals_due(deployment: &Deployment, now: UnixTime) -> Result<Vec<UserId>, ModelError> {
    let mut due = Vec::new();
    for (id, user) in deployment.users() {
        if let UserStatus::Revoked { since } = user.status
            && removal_due(since)? <= now
        {
            due.push(id.clone());
        }
    }
    Ok(due)
}

/// Whether a removed user's kept id has records that expired by `now`, so
/// that `ForgottenExpired` would drop it.
#[must_use]
pub fn forgotten_expired(deployment: &Deployment, now: UnixTime) -> bool {
    deployment.forgotten().values().any(|until| *until <= now)
}
