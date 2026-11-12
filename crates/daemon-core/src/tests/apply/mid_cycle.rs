// SPDX-License-Identifier: GPL-3.0-or-later

//! A suspension for quota lifted within its billing cycle (design §13.6,
//! §9.6; the agreement's revision 2: service paused when the quota runs
//! out resumes once a traffic pack is bought): once a pack, a paid period
//! or a raised quota takes the user back under their quota, with the
//! cycle's usage reported as current, the next run resumes the user,
//! within the cap and earliest suspension first. A grant that does not is
//! reported; without one the suspension stands, unreported; a suspension
//! by the operator or for an abuse review is never lifted; and with the
//! usage behind nothing is lifted within the cycle.

use mooring_model::user::{SuspendReason, UserPolicy};
use mooring_model::{Deployment, UnixTime, User, UserId, UserStatus};

use super::super::payments::{Terms, live};
use super::super::support::{at, date};
use super::{GB, active, holding, now, quota, usage, user};
use crate::apply::{Kept, Lapse, Lapsed, plan_policy};
use crate::payments::{Entitlements, PaymentLedger};
use crate::usage::CycleUsage;

/// The suspension for quota of the run's cycle, from 2026-11-01.
fn november() -> SuspendReason {
    SuspendReason::QuotaExceeded {
        cycle_start: date("2026-11-01"),
    }
}

/// When the users below were suspended: in the run's cycle, before the
/// packs were bought.
fn suspended_at() -> UnixTime {
    at("2026-11-02", 0)
}

/// User `text`, in `status`, with an own quota of `quota_gb` GB that
/// suspends.
fn named(text: &str, status: UserStatus, quota_gb: u64) -> User {
    let mut user = user(
        0,
        status,
        UserPolicy {
            expires_at: None,
            quota: Some(quota(quota_gb * GB)),
        },
    );
    user.id = UserId::parse(text).unwrap();
    user
}

/// User `text` suspended for quota in the run's cycle, with a quota of
/// `quota_gb` GB.
fn over(text: &str, quota_gb: u64) -> User {
    named(
        text,
        UserStatus::Suspended {
            reason: november(),
            since: suspended_at(),
        },
        quota_gb,
    )
}

fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

/// What a 50 GB pack each, bought an hour before the run, gives `buyers`
/// of `deployment`.
fn packs(deployment: &Deployment, buyers: &[&'static str]) -> Entitlements {
    const ORDERS: [&str; 4] = [
        "aaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbb",
        "cccccccccccccccccccc",
        "dddddddddddddddddddd",
    ];
    let entries = buyers
        .iter()
        .zip(ORDERS)
        .zip(1..)
        .map(|((buyer, order), seq)| Terms::pack(order, buyer).grant(seq))
        .collect();
    PaymentLedger::new()
        .apply(
            &live(0, entries),
            deployment.users(),
            UnixTime::from_secs(now().as_secs() - 3600),
            false,
            None,
        )
        .unwrap()
        .ledger
        .entitlements(false)
}

/// The cycle's usage of `deployment`: `served` GB for the users named,
/// zero for every other.
fn used(deployment: &Deployment, served: &[(&str, u64)]) -> CycleUsage {
    let mut usage = usage(deployment, now(), &[]);
    for (user, gigabytes) in served {
        usage.served.insert(id(user), Some(gigabytes * GB));
    }
    usage
}

fn lapsed(text: &str, why: Lapse) -> Lapsed {
    Lapsed {
        user: id(text),
        reason: november(),
        since: suspended_at(),
        why,
    }
}

/// A pack that covers what the user used this cycle (100 GB and 50 GB
/// against 120 GB) resumes the user at the next run; one that does not
/// (against 160 GB) is reported as kept, the user still over quota; a
/// user with no pack stays suspended and is not reported.
#[test]
fn a_pack_that_covers_the_cycles_use_resumes_the_user() {
    let deployment = holding(
        vec![
            over("packbuyera", 100),
            over("packbuyerb", 100),
            over("packbuyerc", 100),
        ],
        None,
    );
    let paid = packs(&deployment, &["packbuyera", "packbuyerb"]);
    let usage = used(
        &deployment,
        &[
            ("packbuyera", 120),
            ("packbuyerb", 160),
            ("packbuyerc", 120),
        ],
    );
    let plan = plan_policy(&deployment, &paid, Some(&usage), now()).unwrap();
    assert_eq!(
        plan.resumes,
        [lapsed("packbuyera", Lapse::NoLongerOverQuota)]
    );
    assert_eq!(
        plan.kept,
        [Kept {
            lapsed: lapsed("packbuyerb", Lapse::PaidSince),
            again: november(),
        }]
    );
    assert!(plan.held_back.is_empty());
    assert!(plan.suspensions.is_empty());
    // Without the pack, nothing is lifted, and nothing is reported.
    let plan = plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert!(plan.resumes.is_empty() && plan.kept.is_empty() && plan.held_back.is_empty());
}

/// A pack refunded in full is taken back: with the user's use not known
/// when Mooring applied the refund, all of it. The user, still over quota,
/// stays suspended, and the run does not report a pack bought since, as it
/// would for one not refunded that falls short.
#[test]
fn a_pack_refunded_in_full_lifts_nothing_and_is_not_reported() {
    let deployment = holding(vec![over("packbuyera", 100)], None);
    let pack = Terms::pack("aaaaaaaaaaaaaaaaaaaa", "packbuyera");
    let mut refund = pack.refund(2, 800, true);
    refund["recorded_at"] = serde_json::json!(now().as_secs() - 1800);
    let paid = PaymentLedger::new()
        .apply(
            &live(0, vec![pack.grant(1), refund]),
            deployment.users(),
            UnixTime::from_secs(now().as_secs() - 3600),
            false,
            None,
        )
        .unwrap()
        .ledger
        .entitlements(false);
    // 120 GB used: the pack would have lifted the suspension, and at 160 GB
    // it would have been reported as falling short.
    for gigabytes in [120, 160] {
        let usage = used(&deployment, &[("packbuyera", gigabytes)]);
        let plan = plan_policy(&deployment, &paid, Some(&usage), now()).unwrap();
        assert!(plan.resumes.is_empty(), "{gigabytes}");
        assert!(plan.kept.is_empty(), "{gigabytes}");
        assert!(plan.held_back.is_empty(), "{gigabytes}");
    }
}

/// A quota the operator raised above what the user used lifts the
/// suspension too, with no pack.
#[test]
fn a_raised_quota_that_covers_the_use_resumes_the_user() {
    let deployment = holding(vec![over("raisedquot", 130)], None);
    let usage = used(&deployment, &[("raisedquot", 120)]);
    let plan = plan_policy(&deployment, &Entitlements::none(), Some(&usage), now()).unwrap();
    assert_eq!(
        plan.resumes,
        [Lapsed {
            user: id("raisedquot"),
            reason: november(),
            since: suspended_at(),
            why: Lapse::NoLongerOverQuota,
        }]
    );
}

/// Such a resume is bounded by the cap as any other: with the one place
/// taken, the user is held back and reported; and it comes after a
/// suspension from the cycle before, which is earlier.
#[test]
fn the_cap_holds_back_a_resume_a_pack_allows() {
    let october = SuspendReason::QuotaExceeded {
        cycle_start: date("2026-10-01"),
    };
    let earlier = at("2026-10-20", 0);
    let mut lapsed_before = user(
        0,
        UserStatus::Suspended {
            reason: october,
            since: earlier,
        },
        UserPolicy::NONE,
    );
    lapsed_before.id = id("lastcycleu");
    let full = holding(vec![active(1), over("packbuyera", 100)], Some(1));
    let paid = packs(&full, &["packbuyera"]);
    let usage = used(&full, &[("packbuyera", 120)]);
    let plan = plan_policy(&full, &paid, Some(&usage), now()).unwrap();
    assert!(plan.resumes.is_empty());
    assert_eq!(
        plan.held_back,
        [lapsed("packbuyera", Lapse::NoLongerOverQuota)]
    );
    // With one place, the suspension from the cycle before goes first.
    let one_place = holding(vec![lapsed_before, over("packbuyera", 100)], Some(1));
    let paid = packs(&one_place, &["packbuyera"]);
    let usage = used(&one_place, &[("packbuyera", 120)]);
    let plan = plan_policy(&one_place, &paid, Some(&usage), now()).unwrap();
    assert_eq!(
        plan.resumes,
        [Lapsed {
            user: id("lastcycleu"),
            reason: october,
            since: earlier,
            why: Lapse::CycleEnded,
        }]
    );
    assert_eq!(
        plan.held_back,
        [lapsed("packbuyera", Lapse::NoLongerOverQuota)]
    );
}

/// A suspension by the operator or for an abuse review is never lifted by
/// a pack, however much it covers.
#[test]
fn a_pack_never_lifts_an_operators_or_an_abuse_review_suspension() {
    let deployment = holding(
        vec![
            named(
                "operatorsu",
                UserStatus::Suspended {
                    reason: SuspendReason::Operator,
                    since: suspended_at(),
                },
                100,
            ),
            named(
                "abusereviw",
                UserStatus::Suspended {
                    reason: SuspendReason::AbuseReview,
                    since: suspended_at(),
                },
                100,
            ),
        ],
        None,
    );
    let paid = packs(&deployment, &["operatorsu", "abusereviw"]);
    let usage = used(&deployment, &[]);
    let plan = plan_policy(&deployment, &paid, Some(&usage), now()).unwrap();
    assert!(plan.resumes.is_empty() && plan.kept.is_empty() && plan.held_back.is_empty());
}

/// With the cycle's usage behind (no report, or the user's own usage
/// unknown), nothing is lifted within the cycle, pack or not; a
/// suspension from the cycle before still resumes.
#[test]
fn with_the_usage_behind_nothing_is_lifted_within_the_cycle() {
    let october = SuspendReason::QuotaExceeded {
        cycle_start: date("2026-10-01"),
    };
    let mut lapsed_before = user(
        0,
        UserStatus::Suspended {
            reason: october,
            since: at("2026-10-20", 0),
        },
        UserPolicy::NONE,
    );
    lapsed_before.id = id("lastcycleu");
    let deployment = holding(vec![lapsed_before, over("packbuyera", 100)], None);
    let paid = packs(&deployment, &["packbuyera"]);
    let plan = plan_policy(&deployment, &paid, None, now()).unwrap();
    let resumed: Vec<&UserId> = plan.resumes.iter().map(|lapsed| &lapsed.user).collect();
    assert_eq!(resumed, [&id("lastcycleu")]);
    assert!(plan.kept.is_empty() && plan.held_back.is_empty());
    let mut unknown = used(&deployment, &[]);
    unknown.served.insert(id("packbuyera"), None);
    let plan = plan_policy(&deployment, &paid, Some(&unknown), now()).unwrap();
    let resumed: Vec<&UserId> = plan.resumes.iter().map(|lapsed| &lapsed.user).collect();
    assert_eq!(resumed, [&id("lastcycleu")]);
}

/// A month bought since the suspension counts as paid since: its quota
/// (100 GB, where the user has none of their own) lifts the suspension when
/// it covers what they used (50 GB), and is reported when it does not
/// (120 GB).
#[test]
fn a_month_bought_since_lifts_or_is_reported_as_a_pack_is() {
    let no_quota = |text: &str| {
        let mut user = over(text, 1);
        user.policy.quota = None;
        user
    };
    let deployment = holding(vec![no_quota("monthbuyra"), no_quota("monthbuyrb")], None);
    let paid = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    Terms::month("aaaaaaaaaaaaaaaaaaaa", "monthbuyra").grant(1),
                    Terms::month("bbbbbbbbbbbbbbbbbbbb", "monthbuyrb").grant(2),
                ],
            ),
            deployment.users(),
            UnixTime::from_secs(now().as_secs() - 3600),
            false,
            None,
        )
        .unwrap()
        .ledger
        .entitlements(false);
    let usage = used(&deployment, &[("monthbuyra", 50), ("monthbuyrb", 120)]);
    let plan = plan_policy(&deployment, &paid, Some(&usage), now()).unwrap();
    assert_eq!(
        plan.resumes,
        [lapsed("monthbuyra", Lapse::NoLongerOverQuota)]
    );
    assert_eq!(
        plan.kept,
        [Kept {
            lapsed: lapsed("monthbuyrb", Lapse::PaidSince),
            again: november(),
        }]
    );
}

/// `suspension_due` reads the usage as `evaluate` does: usage of another
/// cycle, or running past `now`, is refused; an id the deployment does not
/// hold is the model's `UnknownUser`.
#[test]
fn suspension_due_refuses_usage_evaluate_refuses() {
    use crate::error::PolicyError;
    use crate::policy::suspension_due;

    let deployment = holding(vec![over("packbuyera", 100)], None);
    let mut other_cycle = used(&deployment, &[("packbuyera", 120)]);
    other_cycle.cycle =
        crate::period::BillingCycle::of_instant(deployment.exit().sim.cycle(), at("2026-10-15", 0))
            .unwrap();
    assert!(matches!(
        suspension_due(
            &deployment,
            &Entitlements::none(),
            Some(&other_cycle),
            now(),
            &id("packbuyera")
        ),
        Err(PolicyError::UsageForOtherCycle { .. })
    ));
    let mut ahead = used(&deployment, &[("packbuyera", 120)]);
    ahead.through = UnixTime::from_secs(now().as_secs() + 1);
    assert!(matches!(
        suspension_due(
            &deployment,
            &Entitlements::none(),
            Some(&ahead),
            now(),
            &id("packbuyera")
        ),
        Err(PolicyError::UsageAfterNow { .. })
    ));
    assert!(matches!(
        suspension_due(
            &deployment,
            &Entitlements::none(),
            None,
            now(),
            &id("strangerxx")
        ),
        Err(PolicyError::Model(
            mooring_model::ModelError::UnknownUser { .. }
        ))
    ));
    let usage = used(&deployment, &[("packbuyera", 120)]);
    assert_eq!(
        suspension_due(
            &deployment,
            &Entitlements::none(),
            Some(&usage),
            now(),
            &id("packbuyera")
        ),
        Ok(Some(november()))
    );
}
