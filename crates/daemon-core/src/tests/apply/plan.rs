// SPDX-License-Identifier: GPL-3.0-or-later

//! The policy step (design §13.6): the suspensions `evaluate` proposes,
//! each at the run's time; the resumes of lapsed suspensions, earliest
//! first and within the cap; and the whole step refused when a suspension
//! for quota lies after `now`.

use mooring_model::user::{SuspendReason, UserPolicy};
use mooring_model::{UnixTime, UserId, UserStatus};

use super::super::payments::{Terms, live};
use super::super::support::{at, date};
use super::{
    GB, active, holding, id, now, over_quota, quota, suspended, usage, user, with_auto_quota,
};
use crate::apply::{Kept, Lapse, Lapsed, Suspension, plan_policy};
use crate::error::PolicyError;
use crate::payments::{Entitlements, PaymentLedger};
use crate::policy::{PolicyAction, PolicyWarning, UserAction};

/// `user` with a 1 GB quota of its own, which the tests' 2 GB of use
/// leaves it over: a suspension for quota of the run's cycle holds.
fn still_over(mut user: mooring_model::User) -> mooring_model::User {
    user.policy.quota = Some(quota(GB));
    user
}

fn november() -> SuspendReason {
    SuspendReason::QuotaExceeded {
        cycle_start: date("2026-11-01"),
    }
}

/// A lapsed suspension of user `n`, lapsed as its reason lapses at the
/// cycle's turn or once its expiry is no longer past.
fn lapsed(n: u64, reason: SuspendReason, since: UnixTime) -> Lapsed {
    Lapsed {
        user: id(n),
        reason,
        since,
        why: match reason {
            SuspendReason::Expired => Lapse::NoLongerExpired,
            _ => Lapse::CycleEnded,
        },
    }
}

/// An expired user and one over a suspending quota are suspended, each at
/// the run's time and in user order; a user within the cycle stays.
#[test]
fn the_runs_suspensions_are_those_evaluate_proposes_at_its_now() {
    let past = UnixTime::from_secs(now().as_secs() - 1);
    let deployment = holding(
        vec![
            user(
                1,
                UserStatus::Active,
                UserPolicy {
                    expires_at: Some(past),
                    quota: None,
                },
            ),
            user(
                2,
                UserStatus::Active,
                UserPolicy {
                    expires_at: None,
                    quota: Some(quota(10 * GB)),
                },
            ),
            active(3),
        ],
        None,
    );
    let usage = usage(&deployment, now(), &[(2, 10 * GB), (3, 99 * GB)]);
    let plan = plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert_eq!(plan.now, now());
    assert_eq!(
        plan.suspensions,
        [
            Suspension {
                user: id(1),
                reason: SuspendReason::Expired
            },
            Suspension {
                user: id(2),
                reason: november()
            },
        ]
    );
    assert!(plan.resumes.is_empty() && plan.held_back.is_empty() && plan.kept.is_empty());
}

/// Under the pilot's cap, with five users active and one suspended for
/// quota in the cycle before, the run resumes nobody and reports the user
/// it holds back, and still carries out its own suspensions. The place an
/// expiry tonight frees is filled at the next run.
#[test]
fn the_cap_holds_back_a_lapsed_suspension_and_the_runs_suspensions_still_go() {
    let past = UnixTime::from_secs(now().as_secs() - 1);
    let october = at("2026-10-20", 0);
    let mut users: Vec<_> = (1..=5).map(active).collect();
    users[0].policy.expires_at = Some(past);
    users.push(over_quota(6, "2026-10-01", october));
    let deployment = holding(users, Some(5));
    let usage = usage(&deployment, now(), &[]);
    let plan = plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert_eq!(
        plan.suspensions,
        [Suspension {
            user: id(1),
            reason: SuspendReason::Expired
        }]
    );
    assert!(plan.resumes.is_empty(), "{:?}", plan.resumes);
    assert_eq!(
        plan.held_back,
        [lapsed(
            6,
            SuspendReason::QuotaExceeded {
                cycle_start: date("2026-10-01")
            },
            october
        )]
    );
}

/// With places free, the earliest suspension resumes first, then by id at
/// the same instant, one each while a place is left; the rest wait.
#[test]
fn with_places_free_the_earliest_lapsed_suspension_resumes_first() {
    let early = at("2026-10-05", 0);
    let late = at("2026-10-25", 0);
    let deployment = holding(
        vec![
            active(1),
            active(2),
            active(3),
            over_quota(4, "2026-10-01", late),
            over_quota(5, "2026-10-01", early),
            over_quota(6, "2026-10-01", early),
            suspended(7, SuspendReason::Expired, late),
        ],
        Some(5),
    );
    let usage = usage(&deployment, now(), &[]);
    let october = SuspendReason::QuotaExceeded {
        cycle_start: date("2026-10-01"),
    };
    let plan = plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert_eq!(
        plan.resumes,
        [lapsed(5, october, early), lapsed(6, october, early)]
    );
    assert_eq!(
        plan.held_back,
        [
            lapsed(4, october, late),
            lapsed(7, SuspendReason::Expired, late)
        ]
    );
    // Without a cap, every one resumes, in the same order.
    let uncapped = holding(deployment.users().values().cloned().collect(), None);
    let plan = plan_policy(&uncapped, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert_eq!(
        plan.resumes,
        [
            lapsed(5, october, early),
            lapsed(6, october, early),
            lapsed(4, october, late),
            lapsed(7, SuspendReason::Expired, late),
        ]
    );
    assert!(plan.held_back.is_empty());
}

/// A suspension for quota made at or after the current cycle's start holds
/// while the user is still over quota; one made a second before it has
/// lapsed, whatever start it records.
#[test]
fn only_a_suspension_for_quota_from_before_the_cycle_lapses() {
    let start = at("2026-11-01", 0);
    let before = UnixTime::from_secs(start.as_secs() - 1);
    let deployment = holding(
        vec![
            still_over(over_quota(1, "2026-11-01", start)),
            over_quota(2, "2026-10-01", before),
            // A bill day moved forward: the record names this cycle, but
            // the suspension was made before it.
            over_quota(3, "2026-11-01", before),
            // A bill day moved back: the record names the cycle before, but
            // the suspension was made in this one.
            still_over(over_quota(4, "2026-10-01", start)),
        ],
        None,
    );
    let plan = plan_policy(
        &deployment,
        &Entitlements::none(),
        Some(&usage(&deployment, now(), &[(1, 2 * GB), (4, 2 * GB)])),
        now(),
    )
    .unwrap();
    let resumed: Vec<&UserId> = plan.resumes.iter().map(|lapsed| &lapsed.user).collect();
    assert_eq!(resumed, [&id(2), &id(3)]);
}

/// A suspension for quota made after the run's time, which only a clock
/// that stepped back or a corrupt record can leave, refuses the whole step,
/// with or without automatic quotas: none of its suspensions (an expiry
/// here) and none of its resumes is carried out.
#[test]
fn a_suspension_for_quota_after_now_refuses_the_whole_step() {
    let past = UnixTime::from_secs(now().as_secs() - 1);
    let ahead = UnixTime::from_secs(now().as_secs() + 1);
    let deployment = holding(
        vec![
            user(
                1,
                UserStatus::Active,
                UserPolicy {
                    expires_at: Some(past),
                    quota: None,
                },
            ),
            over_quota(2, "2026-10-01", at("2026-10-20", 0)),
            still_over(over_quota(3, "2026-11-01", ahead)),
        ],
        None,
    );
    for deployment in [deployment.clone(), with_auto_quota(&deployment)] {
        let usage = usage(&deployment, now(), &[]);
        assert_eq!(
            plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()),
            Err(PolicyError::QuotaSuspensionAfterNow {
                user: id(3),
                since: ahead,
                now: now(),
            })
        );
        assert!(matches!(
            plan_policy(&deployment, &Entitlements::none(), None, now()),
            Err(PolicyError::QuotaSuspensionAfterNow { .. })
        ));
    }
    // Once the clock passes that instant, the step goes ahead; the user
    // suspended then is still over quota, and stays suspended.
    let later = UnixTime::from_secs(ahead.as_secs() + 1);
    let plan = plan_policy(
        &deployment,
        &Entitlements::none(),
        Some(&usage(&deployment, later, &[(3, 2 * GB)])),
        later,
    )
    .unwrap();
    assert_eq!(plan.suspensions.len(), 1);
    assert_eq!(plan.resumes.len(), 1);
}

/// A suspension by the operator or for an abuse review is never resumed
/// here, however long ago it was made, with places free or not.
#[test]
fn an_operators_suspension_and_an_abuse_review_are_never_resumed() {
    let long_ago = at("2026-01-02", 0);
    let deployment = holding(
        vec![
            suspended(1, SuspendReason::Operator, long_ago),
            suspended(2, SuspendReason::AbuseReview, long_ago),
            active(3),
        ],
        None,
    );
    let plan = plan_policy(
        &deployment,
        &Entitlements::none(),
        Some(&usage(&deployment, now(), &[])),
        now(),
    )
    .unwrap();
    assert!(plan.resumes.is_empty() && plan.held_back.is_empty() && plan.kept.is_empty());
    assert!(plan.suspensions.is_empty());
}

/// A suspension at expiry resumes once the user's expiry runs past the
/// run's time again: by the user's own record, or by a paid period; while
/// it is still past, the user stays suspended.
#[test]
fn a_suspension_at_expiry_resumes_once_the_expiry_runs_past_now() {
    let october = at("2026-10-20", 0);
    let future = UnixTime::from_secs(now().as_secs() + 86_400);
    let past = UnixTime::from_secs(now().as_secs() - 86_400);
    let expired = |n: u64, expires_at: Option<UnixTime>| {
        user(
            n,
            UserStatus::Suspended {
                reason: SuspendReason::Expired,
                since: october,
            },
            UserPolicy {
                expires_at,
                quota: None,
            },
        )
    };
    let deployment = holding(
        vec![
            expired(1, Some(future)),
            expired(2, Some(past)),
            expired(3, None),
        ],
        None,
    );
    let plan = plan_policy(
        &deployment,
        &Entitlements::none(),
        Some(&usage(&deployment, now(), &[])),
        now(),
    )
    .unwrap();
    let resumed: Vec<&UserId> = plan.resumes.iter().map(|lapsed| &lapsed.user).collect();
    assert_eq!(resumed, [&id(1), &id(3)]);
    // A month paid after the expiry gives the user time again.
    let mut paying = expired(4, Some(past));
    paying.id = UserId::parse("expiredone").unwrap();
    let deployment = holding(vec![paying.clone()], None);
    let ledger = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![Terms::month("aaaaaaaaaaaaaaaaaaaa", "expiredone").grant(1)],
            ),
            deployment.users(),
            UnixTime::from_secs(now().as_secs() - 3600),
            false,
            None,
        )
        .unwrap()
        .ledger;
    let usage = usage(&deployment, now(), &[]);
    let unpaid = plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert!(unpaid.resumes.is_empty());
    let paid = plan_policy(
        &deployment,
        &ledger.entitlements(false),
        Some(&usage),
        now(),
    )
    .unwrap();
    assert_eq!(
        paid.resumes,
        [Lapsed {
            user: paying.id,
            reason: SuspendReason::Expired,
            since: october,
            why: Lapse::NoLongerExpired,
        }]
    );
}

/// A lapsed user who would be suspended again at once stays suspended and
/// is reported: a suspension for quota from the cycle before with the
/// expiry now past, and a paid-up expiry with the cycle's quota already
/// used. Neither takes a place.
#[test]
fn a_user_who_would_be_suspended_again_at_once_stays_suspended() {
    let october = at("2026-10-20", 0);
    let past = UnixTime::from_secs(now().as_secs() - 1);
    let future = UnixTime::from_secs(now().as_secs() + 86_400);
    let deployment = holding(
        vec![
            user(
                1,
                UserStatus::Suspended {
                    reason: SuspendReason::QuotaExceeded {
                        cycle_start: date("2026-10-01"),
                    },
                    since: october,
                },
                UserPolicy {
                    expires_at: Some(past),
                    quota: None,
                },
            ),
            user(
                2,
                UserStatus::Suspended {
                    reason: SuspendReason::Expired,
                    since: october,
                },
                UserPolicy {
                    expires_at: Some(future),
                    quota: Some(quota(10 * GB)),
                },
            ),
            over_quota(3, "2026-10-01", october),
            active(4),
        ],
        Some(2),
    );
    let usage = usage(&deployment, now(), &[(2, 10 * GB)]);
    let plan = plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert_eq!(
        plan.kept,
        [
            Kept {
                lapsed: lapsed(
                    1,
                    SuspendReason::QuotaExceeded {
                        cycle_start: date("2026-10-01")
                    },
                    october
                ),
                again: SuspendReason::Expired,
            },
            Kept {
                lapsed: lapsed(2, SuspendReason::Expired, october),
                again: november(),
            },
        ]
    );
    // The one place left goes to the user who can be served.
    assert_eq!(
        plan.resumes,
        [lapsed(
            3,
            SuspendReason::QuotaExceeded {
                cycle_start: date("2026-10-01")
            },
            october
        )]
    );
    assert!(plan.held_back.is_empty());
}

/// Without a usage report (a node the Mac cannot reach), the step still
/// suspends at expiry and resumes lapsed suspensions; a quota it cannot
/// check suspends nobody and is reported.
#[test]
fn without_usage_expiries_and_resumes_still_go_and_quotas_are_unchecked() {
    let past = UnixTime::from_secs(now().as_secs() - 1);
    let deployment = holding(
        vec![
            user(
                1,
                UserStatus::Active,
                UserPolicy {
                    expires_at: Some(past),
                    quota: None,
                },
            ),
            user(
                2,
                UserStatus::Active,
                UserPolicy {
                    expires_at: None,
                    quota: Some(quota(10 * GB)),
                },
            ),
            over_quota(3, "2026-10-01", at("2026-10-20", 0)),
        ],
        None,
    );
    let plan = plan_policy(&deployment, &Entitlements::none(), None, now()).unwrap();
    assert_eq!(
        plan.suspensions,
        [Suspension {
            user: id(1),
            reason: SuspendReason::Expired
        }]
    );
    assert_eq!(plan.resumes.len(), 1);
    assert_eq!(plan.resumes[0].user, id(3));
    assert_eq!(
        plan.warnings,
        [UserAction {
            user: id(2),
            action: PolicyAction::Warn(PolicyWarning::QuotaUnchecked {
                quota_bytes: 10 * GB
            }),
        }]
    );
}
