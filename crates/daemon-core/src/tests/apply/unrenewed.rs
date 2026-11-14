// SPDX-License-Identifier: GPL-3.0-or-later

//! The revocations of the policy step (design §13.6; the agreement's clause
//! 6 from revision 2): a user suspended at expiry whose service, as paid
//! time extends it, expired three calendar months before the run is due,
//! to the second; no other suspension, and no active user, is; and a user
//! whose accepted agreement does not provide for it is reported instead.

use mooring_model::revocation::{ExpiryRevocation, revocation_due};
use mooring_model::user::{SuspendReason, UserPolicy};
use mooring_model::{AgreementVersion, UnixTime, UserId, UserStatus};

use super::super::payments::{Terms, live};
use super::super::support::{at, date};
use super::{holding, id, now, user};
use crate::apply::{PaymentsKnown, Unrenewed, UnrenewedPlan, unrenewed};
use crate::payments::{Entitlements, PaymentLedger};
use crate::period::BillingCycle;
use crate::policy::effective_policy;

/// The gate as a build whose agreement provides for the revocation has it:
/// every fixture user accepted the current revision.
fn open() -> ExpiryRevocation {
    ExpiryRevocation::since(Some(AgreementVersion::CURRENT))
}

fn secs(at: UnixTime, delta: i64) -> UnixTime {
    UnixTime::from_secs(at.as_secs().checked_add_signed(delta).unwrap())
}

/// User `n` suspended at expiry `since`, whose own expiry is `expires_at`.
fn expired(n: u64, expires_at: UnixTime, since: UnixTime) -> mooring_model::User {
    user(
        n,
        UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since,
        },
        UserPolicy {
            expires_at: Some(expires_at),
            quota: None,
        },
    )
}

/// Three calendar months before the run (2026-11-02 19:20 UTC): 2026-08-02
/// 19:20 UTC.
fn three_months_before() -> UnixTime {
    at("2026-08-02", (19 * 60 + 20) * 60)
}

/// A service that expired three calendar months before the run is due at
/// that instant, and one that expired a second later is not; the plan
/// names each with its expiry and the suspension's time, in id order.
#[test]
fn a_service_expired_three_months_before_is_due_to_the_second() {
    let expiry = three_months_before();
    assert_eq!(revocation_due(expiry).unwrap(), now());
    let since = secs(expiry, 3600);
    let deployment = holding(
        vec![
            expired(3, expiry, since),
            expired(1, at("2026-05-01", 0), at("2026-05-01", 1)),
            expired(2, secs(expiry, 1), since),
        ],
        None,
    );
    let plan = unrenewed(
        &deployment,
        &Entitlements::none(),
        PaymentsKnown::NoPull,
        now(),
        open(),
    )
    .unwrap();
    assert_eq!(
        plan,
        UnrenewedPlan {
            revoke: vec![
                Unrenewed {
                    user: id(1),
                    expired_at: at("2026-05-01", 0),
                    due: at("2026-08-01", 0),
                    since: at("2026-05-01", 1),
                },
                Unrenewed {
                    user: id(3),
                    expired_at: expiry,
                    due: now(),
                    since,
                },
            ],
            awaiting_pull: Vec::new(),
            not_covered: Vec::new(),
        }
    );
    // A second later the second user is due too.
    let later = unrenewed(
        &deployment,
        &Entitlements::none(),
        PaymentsKnown::NoPull,
        secs(now(), 1),
        open(),
    )
    .unwrap();
    let users: Vec<&UserId> = later.revoke.iter().map(|due| &due.user).collect();
    assert_eq!(users, [&id(1), &id(2), &id(3)]);
}

/// Only a suspension at expiry ends in revocation: a user suspended by the
/// operator, for an abuse review or for quota, whose expiry is as long
/// past, is not; nor is an active one, whom the step suspends first, nor a
/// user being revoked or revoked. A user suspended at expiry without an
/// expiry any more (the record cleared) is not due either: the step resumes
/// them.
#[test]
fn only_a_suspension_at_expiry_ends_in_revocation() {
    let long_ago = at("2026-03-01", 0);
    let policy = UserPolicy {
        expires_at: Some(long_ago),
        quota: None,
    };
    let suspended = |n: u64, reason: SuspendReason| {
        user(
            n,
            UserStatus::Suspended {
                reason,
                since: long_ago,
            },
            policy,
        )
    };
    let mut revoked = user(6, UserStatus::Revoked { since: long_ago }, policy);
    revoked.per_node.clear();
    let mut cleared = expired(7, long_ago, long_ago);
    cleared.policy.expires_at = None;
    let deployment = holding(
        vec![
            suspended(1, SuspendReason::Operator),
            suspended(2, SuspendReason::AbuseReview),
            suspended(
                3,
                SuspendReason::QuotaExceeded {
                    cycle_start: date("2026-02-01"),
                },
            ),
            user(4, UserStatus::Active, policy),
            revoked,
            cleared,
        ],
        None,
    );
    let plan = unrenewed(
        &deployment,
        &Entitlements::none(),
        PaymentsKnown::NoPull,
        now(),
        open(),
    )
    .unwrap();
    assert_eq!(plan, UnrenewedPlan::default());
}

/// The three months run from the effective expiry, paid time included: a
/// month paid after the user's own expiry moves it, so the user who would
/// be due by the record alone is not.
#[test]
fn paid_time_moves_the_expiry_the_three_months_run_from() {
    let own = at("2026-07-01", 0);
    let mut paying = expired(1, own, secs(own, 60));
    paying.id = UserId::parse("expiredone").unwrap();
    let deployment = holding(vec![paying.clone()], None);
    let unpaid = unrenewed(
        &deployment,
        &Entitlements::none(),
        PaymentsKnown::NoPull,
        now(),
        open(),
    )
    .unwrap();
    assert_eq!(unpaid.revoke.len(), 1, "{unpaid:?}");
    let ledger = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![Terms::month("aaaaaaaaaaaaaaaaaaaa", "expiredone").grant(1)],
            ),
            deployment.users(),
            at("2026-08-10", 0),
            false,
        )
        .unwrap()
        .ledger;
    let paid = ledger.entitlements(false);
    let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), now()).unwrap();
    let extended = effective_policy(&paying, None, &paid, cycle, now(), None)
        .expires_at
        .unwrap();
    assert!(revocation_due(extended).unwrap() > now(), "{extended:?}");
    let plan = unrenewed(&deployment, &paid, PaymentsKnown::NoPull, now(), open()).unwrap();
    assert_eq!(plan, UnrenewedPlan::default());
    // Once the paid time is three months past too, the user is due, dated
    // at the paid time's end.
    let then = revocation_due(extended).unwrap();
    let plan = unrenewed(&deployment, &paid, PaymentsKnown::NoPull, then, open()).unwrap();
    assert_eq!(
        plan.revoke,
        [Unrenewed {
            user: paying.id,
            expired_at: extended,
            due: then,
            since: secs(own, 60),
        }]
    );
}

/// A user whose recorded acceptance is not of a revision providing for the
/// revocation, or who has none, is reported and not revoked; while no
/// revision provides for it (a closed gate), every user due is.
#[test]
fn a_user_the_agreement_does_not_cover_is_reported_instead() {
    let expiry = at("2026-06-01", 0);
    let mut unrecorded = expired(2, expiry, expiry);
    unrecorded.agreement = None;
    let deployment = holding(vec![expired(1, expiry, expiry), unrecorded], None);
    let plan = unrenewed(
        &deployment,
        &Entitlements::none(),
        PaymentsKnown::NoPull,
        now(),
        open(),
    )
    .unwrap();
    let names =
        |list: &[Unrenewed]| -> Vec<UserId> { list.iter().map(|due| due.user.clone()).collect() };
    assert_eq!(names(&plan.revoke), [id(1)]);
    assert_eq!(names(&plan.not_covered), [id(2)]);
    let closed = unrenewed(
        &deployment,
        &Entitlements::none(),
        PaymentsKnown::NoPull,
        now(),
        ExpiryRevocation::since(None),
    )
    .unwrap();
    assert!(closed.revoke.is_empty());
    assert_eq!(names(&closed.not_covered), [id(1), id(2)]);
}

/// While a payment pull is set up, a revocation, never undone, waits for a
/// pull that succeeded at or after the instant it fell due, since a renewal
/// paid before then may not be known yet: the user is reported instead.
/// Without a pull no payment reaches Mooring, so the records decide. A user
/// the agreement does not cover is reported as such, pulled or not.
#[test]
fn a_revocation_waits_for_a_payment_pull_since_it_fell_due() {
    let expiry = three_months_before();
    let due = revocation_due(expiry).unwrap();
    let mut unrecorded = expired(2, expiry, expiry);
    unrecorded.agreement = None;
    let deployment = holding(vec![expired(1, expiry, expiry), unrecorded], None);
    let plan = |known| unrenewed(&deployment, &Entitlements::none(), known, now(), open()).unwrap();
    let names =
        |list: &[Unrenewed]| -> Vec<UserId> { list.iter().map(|due| due.user.clone()).collect() };
    for known in [
        PaymentsKnown::Pulled(None),
        PaymentsKnown::Pulled(Some(secs(due, -1))),
    ] {
        let waiting = plan(known);
        assert!(waiting.revoke.is_empty(), "{known:?}");
        assert_eq!(names(&waiting.awaiting_pull), [id(1)], "{known:?}");
        assert_eq!(names(&waiting.not_covered), [id(2)], "{known:?}");
    }
    for known in [PaymentsKnown::Pulled(Some(due)), PaymentsKnown::NoPull] {
        let ready = plan(known);
        assert_eq!(names(&ready.revoke), [id(1)], "{known:?}");
        assert!(ready.awaiting_pull.is_empty(), "{known:?}");
        assert_eq!(names(&ready.not_covered), [id(2)], "{known:?}");
    }
    // A run an hour later needs a pull since the instant it fell due, not
    // since the run.
    let later = |known| {
        unrenewed(
            &deployment,
            &Entitlements::none(),
            known,
            secs(now(), 3600),
            open(),
        )
        .unwrap()
    };
    assert_eq!(
        names(&later(PaymentsKnown::Pulled(Some(due))).revoke),
        [id(1)]
    );
    assert_eq!(
        names(&later(PaymentsKnown::Pulled(Some(secs(due, -1)))).awaiting_pull),
        [id(1)]
    );
}
