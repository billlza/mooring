// SPDX-License-Identifier: GPL-3.0-or-later

//! The job's hourly firings outside the window (design §13.6): each lifts
//! the suspensions at expiry that a payment has lifted, as the night's run
//! lifts them, within the cap and never for a user who would be suspended
//! again at once; it suspends no one and lifts no other suspension.

use mooring_model::user::{SuspendReason, UserPolicy};
use mooring_model::{Deployment, UnixTime, User, UserId, UserStatus};

use super::super::payments::{Terms, live};
use super::super::support::{at, date};
use super::{GB, active, holding, id, now, over_quota, quota, suspended, usage, user};
use crate::apply::{
    Kept, Lapse, Lapsed, Suspension, expiry_resumes_due, plan_expiry_resumes, plan_policy,
};
use crate::error::PolicyError;
use crate::payments::{Entitlements, PaymentLedger};

/// The user who pays.
const PAID: &str = "paidmonthx";

/// The user who has not paid.
const UNPAID: &str = "unpaidyetx";

/// A firing two hours after the night's run, outside the window.
fn later() -> UnixTime {
    UnixTime::from_secs(now().as_secs() + 2 * 3600)
}

/// When the users were added: a day before the night's run.
fn added() -> UnixTime {
    UnixTime::from_secs(now().as_secs() - 86_400)
}

/// The user `text` as `user add --unpaid` added it at `added()`: suspended
/// at expiry, its expiry the time it was added.
fn added_unpaid(text: &str) -> User {
    let mut new = user(
        0,
        UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: added(),
        },
        UserPolicy {
            expires_at: Some(added()),
            quota: None,
        },
    );
    new.id = UserId::parse(text).unwrap();
    new
}

/// What `PAID`'s month of 30 days and 100 GB, granted an hour before
/// `later()`, gives in `deployment`.
fn paid(deployment: &Deployment) -> Entitlements {
    PaymentLedger::new()
        .apply(
            &live(0, vec![Terms::month("aaaaaaaaaaaaaaaaaaaa", PAID).grant(1)]),
            deployment.users(),
            UnixTime::from_secs(later().as_secs() - 3600),
            false,
        )
        .unwrap()
        .ledger
        .entitlements(false)
}

/// `PAID`'s suspension, lifted once its expiry is no longer past.
fn paid_lapsed() -> Lapsed {
    Lapsed {
        user: UserId::parse(PAID).unwrap(),
        reason: SuspendReason::Expired,
        since: added(),
        why: Lapse::NoLongerExpired,
    }
}

/// Only a suspension at expiry that a payment has lifted is tried. Not an
/// unpaid one; not one for quota whose cycle has ended, which the night's
/// run lifts; not the operator's or an abuse review's. An active user whose
/// expiry has passed is not suspended. The night's plan, at the same time,
/// does both.
#[test]
fn an_hourly_firing_tries_only_suspensions_at_expiry_a_payment_lifted() {
    let deployment = holding(
        vec![
            added_unpaid(PAID),
            added_unpaid(UNPAID),
            over_quota(3, "2026-10-01", at("2026-10-20", 0)),
            suspended(4, SuspendReason::Operator, added()),
            suspended(5, SuspendReason::AbuseReview, added()),
            user(
                6,
                UserStatus::Active,
                UserPolicy {
                    expires_at: Some(added()),
                    quota: None,
                },
            ),
        ],
        None,
    );
    let paid = paid(&deployment);
    assert_eq!(
        expiry_resumes_due(&deployment, &paid, later()).unwrap(),
        [paid_lapsed()]
    );
    assert_eq!(
        expiry_resumes_due(&deployment, &Entitlements::none(), later()).unwrap(),
        []
    );
    let usage = usage(&deployment, later(), &[]);
    let plan = plan_expiry_resumes(&deployment, &paid, Some(&usage), later()).unwrap();
    assert_eq!(plan.now, later());
    assert_eq!(plan.resumes, [paid_lapsed()]);
    assert_eq!(plan.suspensions, []);
    assert_eq!(plan.held_back, []);
    assert_eq!(plan.kept, []);
    assert_eq!(plan.warnings, []);
    let unpaid =
        plan_expiry_resumes(&deployment, &Entitlements::none(), Some(&usage), later()).unwrap();
    assert_eq!(unpaid.resumes, []);
    let night = plan_policy(&deployment, &paid, Some(&usage), later()).unwrap();
    let resumed: Vec<&str> = night
        .resumes
        .iter()
        .map(|lapsed| lapsed.user.as_str())
        .collect();
    assert_eq!(resumed, [id(3).as_str(), PAID]);
    assert_eq!(
        night.suspensions,
        [Suspension {
            user: id(6),
            reason: SuspendReason::Expired,
        }]
    );
}

/// The cap holds an hourly resume back as it holds the night's, counting
/// the users active when the firing began; and a paid user whose own quota
/// this cycle is already used stays suspended and is reported.
#[test]
fn the_cap_and_a_quota_already_used_bound_an_hourly_resume() {
    let full = holding(vec![active(7), added_unpaid(PAID)], Some(1));
    let plan = plan_expiry_resumes(&full, &paid(&full), None, later()).unwrap();
    assert_eq!(plan.resumes, []);
    assert_eq!(plan.held_back, [paid_lapsed()]);
    assert_eq!(plan.kept, []);
    let room = holding(vec![active(7), added_unpaid(PAID)], Some(2));
    let plan = plan_expiry_resumes(&room, &paid(&room), None, later()).unwrap();
    assert_eq!(plan.resumes, [paid_lapsed()]);
    let mut over = added_unpaid(PAID);
    over.policy.quota = Some(quota(GB));
    let deployment = holding(vec![over], None);
    let mut used = usage(&deployment, later(), &[]);
    used.served
        .insert(UserId::parse(PAID).unwrap(), Some(2 * GB));
    let plan = plan_expiry_resumes(&deployment, &paid(&deployment), Some(&used), later()).unwrap();
    assert_eq!(plan.resumes, []);
    assert_eq!(
        plan.kept,
        [Kept {
            lapsed: paid_lapsed(),
            again: SuspendReason::QuotaExceeded {
                cycle_start: date("2026-11-01"),
            },
        }]
    );
}

/// A suspension for quota dated after the firing refuses it, as it refuses
/// the night's run: the clock stepped back, and nothing is tried.
#[test]
fn a_suspension_for_quota_after_the_firing_refuses_it() {
    let ahead = UnixTime::from_secs(later().as_secs() + 60);
    let deployment = holding(
        vec![added_unpaid(PAID), over_quota(3, "2026-11-01", ahead)],
        None,
    );
    let paid = paid(&deployment);
    let refusal = PolicyError::QuotaSuspensionAfterNow {
        user: id(3),
        since: ahead,
        now: later(),
    };
    assert_eq!(
        expiry_resumes_due(&deployment, &paid, later()),
        Err(refusal.clone())
    );
    assert_eq!(
        plan_expiry_resumes(&deployment, &paid, None, later()),
        Err(refusal)
    );
}
