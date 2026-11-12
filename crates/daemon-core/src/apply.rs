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
//!   does not hold it); one made in the current cycle once the user is no
//!   longer over quota by the cycle's usage as reported then, because a
//!   pack, a paid period or a raised quota covers what they used (the
//!   agreement's revision 2: service paused for quota resumes once a pack
//!   is bought), never while the usage is behind; and a suspension at
//!   expiry once the user's paid time or own record runs past `now` again
//!   (design §9.6; the agreement's clause 1: service resumes once the user
//!   has paid). A suspension by the
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
//! - **Revocations at expiry** ([`unrenewed`], 2026-11-12). A user
//!   suspended at expiry whose service, as paid time extends it, expired
//!   three calendar months before the run and was not renewed is revoked
//!   (the agreement's clause 6 from revision 2), each a configuration
//!   change of its own after the step's resumes; one whose accepted
//!   revision does not provide for it is reported to the operator instead,
//!   and so is one whose revocation waits for a payment pull that succeeded
//!   since it fell due ([`PaymentsKnown`]).
//!   Computed only once [`plan_policy`] has planned the step, so a clock
//!   that stepped back revokes no one either.
//! - **Removals** ([`removals_due`]). A user revoked 13 months ago is
//!   removed with every record the Mac holds of it (`RevokedUserRemoved`),
//!   and the kept ids of removed users whose nodes' records have expired go
//!   (`ForgottenExpired`).

use std::num::NonZeroU16;

use mooring_model::removal::removal_due;
use mooring_model::revocation::{ExpiryRevocation, revocation_due};
use mooring_model::user::SuspendReason;
use mooring_model::{Deployment, ModelError, UnixTime, UserId, UserStatus};
use serde::Serialize;

use crate::error::PolicyError;
use crate::payments::Entitlements;
use crate::period::BillingCycle;
use crate::policy::{
    ExpiryState, PolicyAction, UserAction, automatic_quota, effective_policy, evaluate,
    quota_suspension_holds_at, suspension_due,
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

/// Why the policy step tries to lift a suspension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lapse {
    /// A suspension for quota made before the current billing cycle.
    CycleEnded,
    /// A suspension for quota made in the current cycle whose user is no
    /// longer over quota with the cycle's usage as reported now: a pack, a
    /// paid period or a raised quota covers what they used.
    NoLongerOverQuota,
    /// A suspension for quota made in the current cycle after which the
    /// user was granted a pack or a paid period, which leaves them to be
    /// suspended again at once: reported, never lifted.
    PaidSince,
    /// A suspension at expiry whose expiry is no longer past.
    NoLongerExpired,
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
    /// Why it is tried.
    pub why: Lapse,
}

/// A suspension the policy step tried to lift and does not resume, because
/// the user would be suspended again at once: a lapsed one, or one for
/// quota in the current cycle that a pack or a paid period granted since
/// does not lift (`Lapse::PaidSince`).
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
/// `evaluate` there proposes no suspension for the user. A user resumed
/// from a suspension for quota of the current cycle shared the cycle's
/// automatic quota while suspended, so the resume changes no one's share.
pub fn plan_policy(
    deployment: &Deployment,
    paid: &Entitlements,
    usage: Option<&CycleUsage>,
    now: UnixTime,
) -> Result<PolicyPlan, PolicyError> {
    let (lapsed, paid_short) = lapsed_suspensions(deployment, paid, usage, now)?;
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
    let mut kept = paid_short;
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
    kept.sort_by(|left, right| {
        (left.lapsed.since, &left.lapsed.user).cmp(&(right.lapsed.since, &right.lapsed.user))
    });
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
/// first and then by id, and the suspensions for quota that a grant since
/// left in force, to report:
/// - one for quota made before the current cycle (`CycleEnded`);
/// - one for quota made in the current cycle whose user `evaluate` would no
///   longer suspend with the cycle's `usage` (`NoLongerOverQuota`): a pack,
///   a paid period covering `now` or a raised quota covers what they used.
///   Only with the user's usage reported, as a suspension for quota needs
///   it; with the usage behind, a suspension for quota lasts until its
///   cycle ends. One that `evaluate` would still suspend is reported as
///   kept when a pack or a period was granted since it (`PaidSince`), and
///   is otherwise left in force unreported;
/// - one at expiry whose user's expiry (`effective_policy`, with what their
///   paid orders gave) is no longer past (`NoLongerExpired`).
///
/// One by the operator or for an abuse review never lapses here. A
/// suspension for quota after `now` is `QuotaSuspensionAfterNow`.
fn lapsed_suspensions(
    deployment: &Deployment,
    paid: &Entitlements,
    usage: Option<&CycleUsage>,
    now: UnixTime,
) -> Result<(Vec<Lapsed>, Vec<Kept>), PolicyError> {
    let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), now)?;
    let automatic = automatic_quota(deployment, now)?;
    let mut lapsed = Vec::new();
    let mut paid_short = Vec::new();
    for (id, user) in deployment.users() {
        let UserStatus::Suspended { reason, since } = user.status else {
            continue;
        };
        let why = match reason {
            SuspendReason::QuotaExceeded { .. } => {
                if !quota_suspension_holds_at(deployment, id, since, now)? {
                    Some(Lapse::CycleEnded)
                } else if usage_reported(usage, id) {
                    match suspension_due(deployment, paid, usage, now, id)? {
                        None => Some(Lapse::NoLongerOverQuota),
                        Some(again) => {
                            if granted_since(paid, id, since, cycle, now) {
                                paid_short.push(Kept {
                                    lapsed: Lapsed {
                                        user: id.clone(),
                                        reason,
                                        since,
                                        why: Lapse::PaidSince,
                                    },
                                    again,
                                });
                            }
                            None
                        }
                    }
                } else {
                    None
                }
            }
            SuspendReason::Expired => {
                let policy = effective_policy(user, automatic, paid, cycle, now);
                (!matches!(
                    ExpiryState::of(policy.expires_at, now),
                    ExpiryState::Expired { .. }
                ))
                .then_some(Lapse::NoLongerExpired)
            }
            SuspendReason::Operator | SuspendReason::AbuseReview => None,
        };
        if let Some(why) = why {
            lapsed.push(Lapsed {
                user: id.clone(),
                reason,
                since,
                why,
            });
        }
    }
    lapsed.sort_by(|left, right| (left.since, &left.user).cmp(&(right.since, &right.user)));
    Ok((lapsed, paid_short))
}

/// Whether the cycle's `usage` reports `user`'s own: a report, and a
/// figure for the user in it.
fn usage_reported(usage: Option<&CycleUsage>, user: &UserId) -> bool {
    usage.is_some_and(|usage| usage.served.get(user).is_some_and(Option::is_some))
}

/// Whether `user`'s paid orders gave, after `since`, a pack counted in
/// `cycle` and not refunded in full by `now`, or a period covering `now`.
fn granted_since(
    paid: &Entitlements,
    user: &UserId,
    since: UnixTime,
    cycle: BillingCycle,
    now: UnixTime,
) -> bool {
    paid.user(user).is_some_and(|orders| {
        orders.packs().iter().any(|pack| {
            pack.granted_at > since
                && cycle.contains(pack.granted_at)
                && pack.refund.is_none_or(|refund| refund.at > now)
        }) || orders
            .period_at(now)
            .is_some_and(|period| period.from > since)
    })
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

/// A user suspended at expiry whose service has not been renewed three
/// calendar months after it expired ([`unrenewed`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unrenewed {
    /// The user, suspended at expiry.
    pub user: UserId,
    /// When the user's service expired: its effective expiry, with the time
    /// its paid orders gave (`effective_policy`).
    pub expired_at: UnixTime,
    /// When the revocation fell due: three calendar months after
    /// `expired_at` ([`revocation_due`]).
    pub due: UnixTime,
    /// When the user was suspended at expiry.
    pub since: UnixTime,
}

/// How far the payments Mooring holds are known to reach, which a
/// revocation, never undone, waits on ([`unrenewed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentsKnown {
    /// No payment pull is set up, so no payment reaches Mooring: the
    /// records held decide.
    NoPull,
    /// The payment pull is set up, and its last pull that succeeded was at
    /// this instant, or none has: a payment made since may not be known.
    Pulled(Option<UnixTime>),
}

impl PaymentsKnown {
    /// Whether every payment made before `instant` is known: without a
    /// pull, at once; with one, once a pull succeeded at or after it.
    fn covers(self, instant: UnixTime) -> bool {
        match self {
            Self::NoPull => true,
            Self::Pulled(at) => at.is_some_and(|at| at >= instant),
        }
    }
}

/// The revocations at expiry of the policy step, and the users reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnrenewedPlan {
    /// The users to revoke, each a configuration change of its own, in id
    /// order.
    pub revoke: Vec<Unrenewed>,
    /// The users due whose revocation waits for a payment pull that
    /// succeeded at or after it fell due, in id order: reported, and
    /// revoked by a later run once one has.
    pub awaiting_pull: Vec<Unrenewed>,
    /// The users as long unrenewed whose acceptance of the agreement does
    /// not provide for revoking them, in id order: reported, and the
    /// operator decides.
    pub not_covered: Vec<Unrenewed>,
}

/// The users of `deployment` suspended at expiry whose service expired
/// three calendar months or more before `now` ([`revocation_due`] of their
/// effective expiry, with what their paid orders gave: `paid`), and was not
/// renewed since: those whose accepted agreement provides for it (`gate`,
/// [`ExpiryRevocation::covers`]) to revoke, the others to report (the
/// agreement's clause 6 from revision 2: 「服务到期 3 个月后仍未续费，运营者会
/// 作废你的账户」).
///
/// A revocation is never undone, so while a payment pull is set up it
/// waits for a pull that succeeded at or after the instant it fell due
/// (`known`): until then a renewal paid in time may not have reached
/// Mooring, and the user is reported as waiting instead. A payment made
/// after that instant is late by the agreement, whether a pull took it or
/// not; the ledger holds it, not granted, for a revoked user.
///
/// Only a suspension at expiry ends so: a suspension by the operator, for
/// an abuse review or for quota is never revoked here, whatever the user's
/// expiry, and an active user whose expiry passed is suspended by the
/// step first. A user whose effective expiry is no longer past is resumed
/// by the step instead ([`Lapse::NoLongerExpired`]), so no user is both.
/// The step plans this only once [`plan_policy`] has planned the rest, so a
/// suspension for quota after `now`, a clock that stepped back, revokes no
/// one; a clock behind can only delay a revocation, since the expiry is
/// compared with `now`, while a clock ahead cannot be told from the true
/// time.
pub fn unrenewed(
    deployment: &Deployment,
    paid: &Entitlements,
    known: PaymentsKnown,
    now: UnixTime,
    gate: ExpiryRevocation,
) -> Result<UnrenewedPlan, PolicyError> {
    let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), now)?;
    let automatic = automatic_quota(deployment, now)?;
    let mut plan = UnrenewedPlan::default();
    for (id, user) in deployment.users() {
        let UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since,
        } = user.status
        else {
            continue;
        };
        let Some(expired_at) = effective_policy(user, automatic, paid, cycle, now).expires_at
        else {
            continue;
        };
        let falls_due = revocation_due(expired_at)?;
        if falls_due > now {
            continue;
        }
        let due = Unrenewed {
            user: id.clone(),
            expired_at,
            due: falls_due,
            since,
        };
        if !gate.covers(user) {
            plan.not_covered.push(due);
        } else if known.covers(falls_due) {
            plan.revoke.push(due);
        } else {
            plan.awaiting_pull.push(due);
        }
    }
    Ok(plan)
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
