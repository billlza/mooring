// SPDX-License-Identifier: GPL-3.0-or-later

//! Quota and expiry evaluation, with the automatic quota (decision F4).

use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU64};

use mooring_model::deployment::CapacityPolicy;
use mooring_model::quota::{AutoQuotaPolicy, BudgetPercent, SimFactor};
use mooring_model::sim::{EvidenceRef, FairUseWindow, PlanKind, SimPlan};
use mooring_model::target::EvidenceUrl;
use mooring_model::user::{
    QuotaAction, SuspendReason, UserPolicy, UserQuota, UserStatus, WarnPercent,
};
use mooring_model::{
    BillDay, Carrier, CycleRule, Deployment, ModelError, SimPolicy, StopPolicy, UnixTime, User,
    UserId,
};
use proptest::prelude::*;

use super::support::{at, date, edited, user_ids, users};
use crate::alert::AlertCondition;
use crate::error::{PolicyError, PolicyErrorKind};
use crate::period::BillingCycle;
use crate::policy::{
    EXPIRY_WARNING_SECS, ExpiryState, PolicyAction, PolicyWarning, QuotaState, UserAction,
    automatic_quota, effective_quota, evaluate, user_alerts,
};
use crate::usage::CycleUsage;

const GB: u64 = 1_000_000_000;

fn quota(bytes: u64, warn: u8, action: QuotaAction) -> UserQuota {
    UserQuota {
        cycle_served_bytes: NonZeroU64::new(bytes).unwrap(),
        warn_percent: WarnPercent::new(warn).unwrap(),
        action,
    }
}

fn policy(expires_at: Option<UnixTime>, quota: Option<UserQuota>) -> UserPolicy {
    UserPolicy { expires_at, quota }
}

fn set(users: &mut BTreeMap<UserId, User>, user: &UserId, value: UserPolicy) {
    users.get_mut(user).unwrap().policy = value;
}

fn bill_day() -> CycleRule {
    CycleRule::Monthly {
        bill_day: BillDay::new(1).unwrap(),
    }
}

/// The three-user fixture deployment (billed on day 1, no automatic
/// quotas) holding `users`.
fn holding(users: &BTreeMap<UserId, User>) -> Deployment {
    edited(|parts| parts.users = users.values().cloned().collect())
}

/// The usage of October's cycle through `through`.
fn usage(through: UnixTime, served: &[(UserId, u64)]) -> CycleUsage {
    CycleUsage {
        cycle: BillingCycle::of_instant(bill_day(), through).unwrap(),
        through,
        served: served.iter().cloned().collect(),
    }
}

#[test]
fn quota_states_turn_at_the_warning_share_and_at_the_quota() {
    let limited = policy(None, Some(quota(100 * GB, 80, QuotaAction::Suspend)));
    let state = |used| QuotaState::of(limited.quota, used);
    assert_eq!(
        state(0),
        QuotaState::Within {
            used_bytes: 0,
            quota_bytes: 100 * GB
        }
    );
    assert_eq!(
        state(80 * GB - 1),
        QuotaState::Within {
            used_bytes: 80 * GB - 1,
            quota_bytes: 100 * GB
        }
    );
    assert_eq!(
        state(80 * GB),
        QuotaState::Warn {
            used_bytes: 80 * GB,
            quota_bytes: 100 * GB
        }
    );
    assert_eq!(
        state(100 * GB - 1),
        QuotaState::Warn {
            used_bytes: 100 * GB - 1,
            quota_bytes: 100 * GB
        }
    );
    assert_eq!(
        state(100 * GB),
        QuotaState::Over {
            used_bytes: 100 * GB,
            quota_bytes: 100 * GB
        }
    );
    assert_eq!(
        QuotaState::of(UserPolicy::NONE.quota, u64::MAX),
        QuotaState::NoQuota
    );
    // A quota near u64::MAX does not overflow the share.
    let huge = policy(None, Some(quota(u64::MAX, 99, QuotaAction::Warn)));
    assert!(matches!(
        QuotaState::of(huge.quota, u64::MAX - 1),
        QuotaState::Warn { .. }
    ));
    assert_eq!(
        QuotaState::without_usage(limited.quota),
        QuotaState::UsageUnavailable {
            quota_bytes: 100 * GB
        }
    );
    assert_eq!(
        QuotaState::without_usage(UserPolicy::NONE.quota),
        QuotaState::NoQuota
    );
    assert_eq!(
        serde_json::to_string(&state(80 * GB)).unwrap(),
        r#"{"warn":{"used_bytes":80000000000,"quota_bytes":100000000000}}"#
    );
}

#[test]
fn expiry_counts_whole_days_up_and_expires_at_its_instant() {
    let now = at("2026-10-08", 0);
    let expiring = |secs| policy(Some(UnixTime::from_secs(now.as_secs() + secs)), None);
    assert_eq!(
        ExpiryState::of(&UserPolicy::NONE, now),
        ExpiryState::NoExpiry
    );
    assert_eq!(
        ExpiryState::of(&expiring(1), now),
        ExpiryState::Expires {
            at: UnixTime::from_secs(now.as_secs() + 1),
            days_left: 1
        }
    );
    assert_eq!(
        ExpiryState::of(&expiring(86_400), now),
        ExpiryState::Expires {
            at: at("2026-10-09", 0),
            days_left: 1
        }
    );
    assert_eq!(
        ExpiryState::of(&expiring(86_401), now),
        ExpiryState::Expires {
            at: at("2026-10-09", 1),
            days_left: 2
        }
    );
    assert_eq!(
        ExpiryState::of(&policy(Some(now), None), now),
        ExpiryState::Expired { at: now }
    );
}

#[test]
fn evaluation_proposes_suspensions_and_warnings_by_precedence() {
    let ids = user_ids();
    let now = at("2026-10-08", 12 * 3600);
    let mut users = users();

    // User 1: expired, and over a suspending quota: the expiry wins.
    set(
        &mut users,
        &ids[0],
        policy(
            Some(at("2026-10-08", 0)),
            Some(quota(10 * GB, 80, QuotaAction::Suspend)),
        ),
    );
    // User 2: over a suspending quota.
    set(
        &mut users,
        &ids[1],
        policy(None, Some(quota(10 * GB, 80, QuotaAction::Suspend))),
    );
    // User 3: over a warning quota and expiring in exactly three days.
    set(
        &mut users,
        &ids[2],
        policy(
            Some(UnixTime::from_secs(now.as_secs() + EXPIRY_WARNING_SECS)),
            Some(quota(10 * GB, 80, QuotaAction::Warn)),
        ),
    );
    let served = [
        (ids[0].clone(), 20 * GB),
        (ids[1].clone(), 10 * GB),
        (ids[2].clone(), 11 * GB),
    ];
    let actions = evaluate(&holding(&users), &usage(now, &served), now).unwrap();
    assert_eq!(
        actions,
        vec![
            UserAction {
                user: ids[0].clone(),
                action: PolicyAction::Suspend(SuspendReason::Expired)
            },
            UserAction {
                user: ids[1].clone(),
                action: PolicyAction::Suspend(SuspendReason::QuotaExceeded {
                    cycle_start: date("2026-10-01")
                })
            },
            UserAction {
                user: ids[2].clone(),
                action: PolicyAction::Warn(PolicyWarning::QuotaReached {
                    used_bytes: 11 * GB,
                    quota_bytes: 10 * GB
                })
            },
            UserAction {
                user: ids[2].clone(),
                action: PolicyAction::Warn(PolicyWarning::ExpiresSoon {
                    at: UnixTime::from_secs(now.as_secs() + EXPIRY_WARNING_SECS)
                })
            },
        ]
    );
    assert_eq!(
        user_alerts(&users, &actions),
        vec![
            AlertCondition::UsersOverQuota { count: 2 },
            AlertCondition::UsersExpiringSoon { count: 1 },
            AlertCondition::UsersExpired { count: 1 },
        ]
    );
    // One second more than three days is not yet "soon"; near the quota is.
    set(
        &mut users,
        &ids[2],
        policy(
            Some(UnixTime::from_secs(now.as_secs() + EXPIRY_WARNING_SECS + 1)),
            Some(quota(10 * GB, 80, QuotaAction::Warn)),
        ),
    );
    let served = [
        (ids[0].clone(), 0),
        (ids[1].clone(), 0),
        (ids[2].clone(), 8 * GB),
    ];
    let actions = evaluate(&holding(&users), &usage(now, &served), now).unwrap();
    assert_eq!(
        actions.last(),
        Some(&UserAction {
            user: ids[2].clone(),
            action: PolicyAction::Warn(PolicyWarning::QuotaNear {
                used_bytes: 8 * GB,
                quota_bytes: 10 * GB
            })
        })
    );
    assert_eq!(
        actions.len(),
        2,
        "user 1 is still expired; user 2 is within its quota"
    );
}

#[test]
fn only_active_users_are_evaluated_and_no_policy_proposes_nothing() {
    let ids = user_ids();
    let now = at("2026-10-08", 0);
    let mut users = users();
    assert_eq!(
        evaluate(&holding(&users), &usage(now, &[]), now),
        Ok(Vec::new())
    );
    for user in users.values_mut() {
        user.policy = policy(
            Some(at("2026-10-01", 0)),
            Some(quota(1, 80, QuotaAction::Suspend)),
        );
    }
    users
        .get_mut(&ids[0])
        .unwrap()
        .suspend(SuspendReason::Operator, now)
        .unwrap();
    users.get_mut(&ids[1]).unwrap().revoke().unwrap();
    users.get_mut(&ids[2]).unwrap().status = UserStatus::Revoked;
    users.get_mut(&ids[2]).unwrap().per_node.clear();
    // Inactive users need no usage either.
    assert_eq!(
        evaluate(&holding(&users), &usage(now, &[]), now),
        Ok(Vec::new())
    );
    assert_eq!(
        user_alerts(&users, &[]),
        vec![AlertCondition::UsersSuspended { count: 1 }]
    );
    assert_eq!(user_alerts(&super::support::users(), &[]), Vec::new());
}

#[test]
fn evaluation_refuses_usage_it_cannot_rely_on() {
    let ids = user_ids();
    let now = at("2026-10-08", 0);
    let mut users = users();
    users.get_mut(&ids[1]).unwrap().policy = policy(None, Some(quota(GB, 80, QuotaAction::Warn)));
    let last_cycle = usage(at("2026-09-30", 0), &[(ids[1].clone(), 1)]);
    assert_eq!(
        evaluate(&holding(&users), &last_cycle, now),
        Err(PolicyError::UsageForOtherCycle {
            usage_cycle: date("2026-09-01"),
            current_cycle: date("2026-10-01")
        })
    );
    let ahead = usage(at("2026-10-08", 1), &[(ids[1].clone(), 1)]);
    assert_eq!(
        evaluate(&holding(&users), &ahead, now),
        Err(PolicyError::UsageAfterNow {
            through: at("2026-10-08", 1),
            now
        })
    );
    assert_eq!(
        evaluate(&holding(&users), &usage(now, &[(ids[0].clone(), 1)]), now),
        Err(PolicyError::UsageMissing {
            user: ids[1].clone()
        })
    );
    let billed_on_20 = with_bill_day(holding(&users), 20);
    assert_eq!(
        evaluate(&billed_on_20, &usage(now, &[]), UnixTime::from_secs(86_400)),
        Err(PolicyError::Model(ModelError::InvalidDate))
    );
}

#[test]
fn every_policy_error_kind_is_named_once() {
    let ids = user_ids();
    let errors = [
        (
            PolicyErrorKind::UsageForOtherCycle,
            PolicyError::UsageForOtherCycle {
                usage_cycle: date("2026-09-01"),
                current_cycle: date("2026-10-01"),
            },
        ),
        (
            PolicyErrorKind::UsageAfterNow,
            PolicyError::UsageAfterNow {
                through: at("2026-10-08", 1),
                now: at("2026-10-08", 0),
            },
        ),
        (
            PolicyErrorKind::UsageMissing,
            PolicyError::UsageMissing {
                user: ids[0].clone(),
            },
        ),
        (
            PolicyErrorKind::AutomaticQuotaZero,
            PolicyError::AutomaticQuotaZero {
                budget_bytes: 15,
                sharing: 6,
            },
        ),
        (
            PolicyErrorKind::QuotaSuspensionAfterNow,
            PolicyError::QuotaSuspensionAfterNow {
                user: ids[0].clone(),
                since: at("2026-10-08", 1),
                now: at("2026-10-08", 0),
            },
        ),
        (
            PolicyErrorKind::Model,
            PolicyError::Model(ModelError::InvalidDate),
        ),
    ];
    for (kind, error) in &errors {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        PolicyErrorKind::ALL
    );
}

fn arbitrary_policy() -> impl Strategy<Value = UserPolicy> {
    (
        proptest::option::of(0_u64..10 * 86_400),
        proptest::option::of((1_u64..100, 1_u8..=99, any::<bool>())),
    )
        .prop_map(|(expiry, quota_parts)| UserPolicy {
            expires_at: expiry
                .map(|offset| UnixTime::from_secs(at("2026-10-03", 0).as_secs() + offset)),
            quota: quota_parts.map(|(gb, warn, suspend)| {
                quota(
                    gb * GB,
                    warn,
                    if suspend {
                        QuotaAction::Suspend
                    } else {
                        QuotaAction::Warn
                    },
                )
            }),
        })
}

fn arbitrary_status() -> impl Strategy<Value = Option<SuspendReason>> {
    // `None` keeps the user active.
    proptest::option::weighted(0.3, Just(SuspendReason::AbuseReview))
}

proptest! {
    /// For any policies, statuses and usage: only active users get actions;
    /// a user gets at most one suspension and then no warning; and each
    /// action holds exactly when its rule says so.
    #[test]
    fn actions_follow_the_rules(
        policies in proptest::collection::vec(arbitrary_policy(), 3),
        suspended in proptest::collection::vec(arbitrary_status(), 3),
        served in proptest::collection::vec(0_u64..120 * GB, 3),
    ) {
        let ids = user_ids();
        let now = at("2026-10-08", 0);
        let mut users: BTreeMap<UserId, User> = users();
        for (index, id) in ids.iter().enumerate() {
            let user = users.get_mut(id).unwrap();
            user.policy = policies[index];
            if let Some(reason) = suspended[index] {
                user.suspend(reason, now).unwrap();
            }
        }
        let usage = usage(now, &ids.iter().cloned().zip(served.iter().copied()).collect::<Vec<_>>());
        let actions = evaluate(&holding(&users), &usage, now).unwrap();
        for (index, id) in ids.iter().enumerate() {
            let mine: Vec<PolicyAction> = actions.iter().filter(|action| &action.user == id).map(|action| action.action).collect();
            if suspended[index].is_some() {
                prop_assert!(mine.is_empty());
                continue;
            }
            let policy = policies[index];
            let expired = policy.expires_at.is_some_and(|at| at <= now);
            let over = policy.quota.is_some_and(|quota| served[index] >= quota.cycle_served_bytes.get());
            let near = policy.quota.is_some_and(|quota| {
                u128::from(served[index]) * 100 >= u128::from(quota.cycle_served_bytes.get()) * u128::from(quota.warn_percent.get())
            });
            let suspends_on_quota = policy.quota.is_some_and(|quota| quota.action == QuotaAction::Suspend);
            let soon = policy.expires_at.is_some_and(|at| at > now && at.as_secs() - now.as_secs() <= EXPIRY_WARNING_SECS);
            let expected: Vec<PolicyAction> = if expired {
                vec![PolicyAction::Suspend(SuspendReason::Expired)]
            } else if over && suspends_on_quota {
                vec![PolicyAction::Suspend(SuspendReason::QuotaExceeded { cycle_start: date("2026-10-01") })]
            } else {
                let quota_bytes = policy.quota.map_or(0, |quota| quota.cycle_served_bytes.get());
                let mut warnings = Vec::new();
                if over {
                    warnings.push(PolicyAction::Warn(PolicyWarning::QuotaReached { used_bytes: served[index], quota_bytes }));
                } else if near {
                    warnings.push(PolicyAction::Warn(PolicyWarning::QuotaNear { used_bytes: served[index], quota_bytes }));
                }
                if soon {
                    warnings.push(PolicyAction::Warn(PolicyWarning::ExpiresSoon { at: policy.expires_at.unwrap() }));
                }
                warnings
            };
            prop_assert_eq!(mine, expected);
        }
        // The alerts count the same users, never naming any.
        let alerts = user_alerts(&users, &actions);
        let count = |pick: fn(&PolicyAction) -> bool| actions.iter().filter(|action| pick(&action.action)).count() as u64;
        for alert in &alerts {
            match alert {
                AlertCondition::UsersNearQuota { count: n } => prop_assert_eq!(*n, count(|a| matches!(a, PolicyAction::Warn(PolicyWarning::QuotaNear { .. })))),
                AlertCondition::UsersOverQuota { count: n } => prop_assert_eq!(*n, count(|a| matches!(a, PolicyAction::Warn(PolicyWarning::QuotaReached { .. }) | PolicyAction::Suspend(SuspendReason::QuotaExceeded { .. })))),
                AlertCondition::UsersExpiringSoon { count: n } => prop_assert_eq!(*n, count(|a| matches!(a, PolicyAction::Warn(PolicyWarning::ExpiresSoon { .. })))),
                AlertCondition::UsersExpired { count: n } => prop_assert_eq!(*n, count(|a| matches!(a, PolicyAction::Suspend(SuspendReason::Expired)))),
                AlertCondition::UsersSuspended { count: n } => prop_assert_eq!(*n, suspended.iter().flatten().count() as u64),
                other => prop_assert!(false, "unexpected {other:?}"),
            }
            let text = serde_json::to_string(alert).unwrap();
            for id in &ids {
                prop_assert!(!text.contains(id.as_str()));
            }
        }
    }
}

// The automatic quota (decision F4).

/// The pilot's automatic quota with six users sharing the budget: 300e9
/// SIM bytes × 1000 / 2100 ‰ × 80 % / 6, rounded down.
const PILOT_QUOTA_AT_SIX: u64 = 19_047_619_047;

/// The pilot's automatic quota with seven users sharing the budget.
const PILOT_QUOTA_AT_SEVEN: u64 = 16_326_530_612;

/// An instant in October's billing cycle (the fixture bills on day 1).
fn october() -> UnixTime {
    at("2026-10-08", 0)
}

/// A suspension for quota in the cycle that starts on `cycle_start`.
fn over_quota(cycle_start: &str) -> SuspendReason {
    SuspendReason::QuotaExceeded {
        cycle_start: date(cycle_start),
    }
}

/// The twenty-user fixture deployment (SMARTY, 300e9 hard stop, no cap)
/// with `auto` recorded and every user after the first `active` suspended
/// by the operator.
fn twenty(active: usize, auto: Option<AutoQuotaPolicy>) -> Deployment {
    let mut parts = mooring_fixtures::two_nodes_twenty_users()
        .unwrap()
        .deployment
        .into_parts();
    parts.auto_quota = auto;
    for user in parts.users.iter_mut().skip(active) {
        user.suspend(SuspendReason::Operator, at("2026-10-02", 0))
            .unwrap();
    }
    Deployment::try_from(parts).unwrap()
}

/// `deployment` with its SIM policy replaced by one billed on day 1 with
/// `plan`, `warn` and `stop`.
fn with_sim(deployment: Deployment, plan: SimPlan, warn: u64, stop: StopPolicy) -> Deployment {
    let mut parts = deployment.into_parts();
    parts.exit.sim = SimPolicy::new(bill_day(), plan, warn, stop).unwrap();
    Deployment::try_from(parts).unwrap()
}

/// `deployment` billed on `day` instead, its plan, warning and stop kept.
fn with_bill_day(deployment: Deployment, day: u8) -> Deployment {
    let mut parts = deployment.into_parts();
    let sim = &parts.exit.sim;
    parts.exit.sim = SimPolicy::new(
        CycleRule::Monthly {
            bill_day: BillDay::new(day).unwrap(),
        },
        sim.plan().unwrap().clone(),
        sim.warn_bytes(),
        sim.stop(),
    )
    .unwrap();
    Deployment::try_from(parts).unwrap()
}

fn smarty() -> SimPlan {
    SimPlan {
        carrier: Carrier::Smarty,
        kind: PlanKind::Unlimited,
        speed_cap_mbps: None,
        terms: EvidenceRef {
            url: EvidenceUrl::parse("https://evidence.mooring.test/sim-plan").unwrap(),
            dated: date("2026-08-25"),
        },
    }
}

const fn pilot_quota(bytes: u64) -> Option<UserQuota> {
    Some(UserQuota {
        cycle_served_bytes: match NonZeroU64::new(bytes) {
            Some(bytes) => bytes,
            None => panic!("a test quota is not zero"),
        },
        warn_percent: AutoQuotaPolicy::PILOT.warn_percent,
        action: AutoQuotaPolicy::PILOT.action,
    })
}

fn active_ids(deployment: &Deployment) -> Vec<UserId> {
    deployment
        .users()
        .iter()
        .filter(|(_, user)| user.status == UserStatus::Active)
        .map(|(id, _)| id.clone())
        .collect()
}

/// Five active users leave the automatic quota off; the sixth turns it on,
/// and more users share the budget more thinly. Without a policy it never
/// applies.
#[test]
fn dormant_below_the_threshold() {
    let pilot = Some(AutoQuotaPolicy::PILOT);
    let now = october();
    assert_eq!(automatic_quota(&twenty(5, pilot), now), Ok(None));
    assert_eq!(
        automatic_quota(&twenty(6, pilot), now),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    assert_eq!(
        automatic_quota(&twenty(20, pilot), now),
        Ok(pilot_quota(5_714_285_714))
    );
    assert_eq!(automatic_quota(&twenty(20, None), now), Ok(None));
    assert_eq!(automatic_quota(&twenty(0, pilot), now), Ok(None));
}

/// Revoking and revoked users share nothing, and admitting one more active
/// user lowers every share at once (F4's "÷ N").
#[test]
fn revoking_users_share_nothing_and_admission_lowers_every_share() {
    let mut parts = twenty(6, Some(AutoQuotaPolicy::PILOT)).into_parts();
    // Of the fourteen suspended users, one is revoking and one revoked.
    parts.users[10].resume().unwrap();
    parts.users[10].revoke().unwrap();
    parts.users[11].resume().unwrap();
    parts.users[11].status = UserStatus::Revoked;
    parts.users[11].per_node.clear();
    let deployment = Deployment::try_from(parts.clone()).unwrap();
    assert_eq!(active_ids(&deployment).len(), 6);
    assert_eq!(
        automatic_quota(&deployment, october()),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    parts.users[12].resume().unwrap();
    let seven = Deployment::try_from(parts).unwrap();
    assert_eq!(
        automatic_quota(&seven, october()),
        Ok(pilot_quota(PILOT_QUOTA_AT_SEVEN))
    );
}

/// The quota is latched per cycle (design §15.3, §20 F4, decided
/// 2026-10-09): with six active users, suspending one for quota leaves
/// every remaining user the N = 6 share, never no quota, and the next user
/// who reaches it is suspended in turn.
#[test]
fn a_quota_suspension_keeps_every_share_for_the_cycle() {
    let mut parts = twenty(6, Some(AutoQuotaPolicy::PILOT)).into_parts();
    let now = october();
    assert_eq!(
        automatic_quota(&Deployment::try_from(parts.clone()).unwrap(), now),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    parts.users[0]
        .suspend(over_quota("2026-10-01"), at("2026-10-05", 0))
        .unwrap();
    let after = Deployment::try_from(parts).unwrap();
    let ids = active_ids(&after);
    assert_eq!(ids.len(), 5);
    let automatic = automatic_quota(&after, now).unwrap();
    assert_eq!(automatic, pilot_quota(PILOT_QUOTA_AT_SIX));
    for id in &ids {
        assert_eq!(effective_quota(&after.users()[id], automatic), automatic);
    }
    let mut served: Vec<(UserId, u64)> = ids.iter().map(|id| (id.clone(), 0)).collect();
    served[0].1 = PILOT_QUOTA_AT_SIX;
    served[1].1 = PILOT_QUOTA_AT_SIX - 1;
    assert_eq!(
        evaluate(&after, &usage(now, &served), now),
        Ok(vec![
            UserAction {
                user: ids[0].clone(),
                action: PolicyAction::Suspend(over_quota("2026-10-01"))
            },
            UserAction {
                user: ids[1].clone(),
                action: PolicyAction::Warn(PolicyWarning::QuotaNear {
                    used_bytes: PILOT_QUOTA_AT_SIX - 1,
                    quota_bytes: PILOT_QUOTA_AT_SIX
                })
            },
        ])
    );
}

/// A suspension for quota stops counting once the cycle it was made in has
/// ended: in October a September suspension is not among the users sharing
/// the budget (the apply resumes it at the boundary, M5), and the
/// evaluation proposes nothing for it, whatever its usage; in September it
/// counts.
#[test]
fn a_quota_suspension_from_an_earlier_cycle_does_not_count() {
    let mut parts = twenty(7, Some(AutoQuotaPolicy::PILOT)).into_parts();
    parts.users[0]
        .suspend(over_quota("2026-09-01"), at("2026-09-20", 0))
        .unwrap();
    let six_and_september = Deployment::try_from(parts.clone()).unwrap();
    assert_eq!(active_ids(&six_and_september).len(), 6);
    let now = october();
    assert_eq!(
        automatic_quota(&six_and_september, now),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    assert_eq!(
        automatic_quota(&six_and_september, at("2026-09-25", 0)),
        Ok(pilot_quota(PILOT_QUOTA_AT_SEVEN))
    );
    let september_user = parts.users[0].id.clone();
    let mut served: Vec<(UserId, u64)> = active_ids(&six_and_september)
        .into_iter()
        .map(|id| (id, 0))
        .collect();
    served.push((september_user, u64::MAX));
    assert_eq!(
        evaluate(&six_and_september, &usage(now, &served), now),
        Ok(Vec::new())
    );
    parts.users[1]
        .suspend(SuspendReason::Operator, at("2026-10-02", 0))
        .unwrap();
    let five_and_september = Deployment::try_from(parts).unwrap();
    assert_eq!(automatic_quota(&five_and_september, now), Ok(None));
}

/// An edit of the bill day can move the current cycle's start back past a
/// suspension's recorded `cycle_start` (design §7, `BillDay`): from 1 to
/// 28 on 10 October, the cycle runs from 28 September, and a suspension
/// recorded for 1 October was made inside it. It still counts, so the
/// others keep the N = 6 share for the rest of that cycle, and it lapses
/// when the cycle ends.
#[test]
fn a_quota_suspension_counts_after_the_bill_day_moves_the_cycle_start_back() {
    let mut parts = twenty(6, Some(AutoQuotaPolicy::PILOT)).into_parts();
    parts.users[0]
        .suspend(over_quota("2026-10-01"), at("2026-10-05", 0))
        .unwrap();
    let billed_on_1 = Deployment::try_from(parts).unwrap();
    let now = at("2026-10-10", 0);
    assert_eq!(
        automatic_quota(&billed_on_1, now),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    let billed_on_28 = with_bill_day(billed_on_1, 28);
    for during in [now, at("2026-10-27", 86_399)] {
        assert_eq!(
            automatic_quota(&billed_on_28, during),
            Ok(pilot_quota(PILOT_QUOTA_AT_SIX)),
            "{during:?}"
        );
    }
    assert_eq!(
        automatic_quota(&billed_on_28, at("2026-10-28", 0)),
        Ok(None)
    );
}

/// A renewal taken late moves the cycle's start forward to the day payment
/// was taken, and the operator records the new bill day (design §7,
/// `BillDay`): billed on day 5, a user suspended for quota on 9 October is
/// recorded for the cycle from 5 October; with the bill day recorded as 8
/// the cycle runs from 8 October, and the suspension was made inside it.
/// It still counts, so the others keep the N = 6 share for the rest of that
/// cycle, and it lapses when the cycle ends.
#[test]
fn a_quota_suspension_counts_after_the_bill_day_moves_the_cycle_start_forward() {
    let mut parts = with_bill_day(twenty(6, Some(AutoQuotaPolicy::PILOT)), 5).into_parts();
    parts.users[0]
        .suspend(over_quota("2026-10-05"), at("2026-10-09", 0))
        .unwrap();
    let billed_on_5 = Deployment::try_from(parts).unwrap();
    let now = at("2026-10-10", 0);
    assert_eq!(
        automatic_quota(&billed_on_5, now),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    let billed_on_8 = with_bill_day(billed_on_5, 8);
    for during in [now, at("2026-11-07", 86_399)] {
        assert_eq!(
            automatic_quota(&billed_on_8, during),
            Ok(pilot_quota(PILOT_QUOTA_AT_SIX)),
            "{during:?}"
        );
    }
    assert_eq!(automatic_quota(&billed_on_8, at("2026-11-08", 0)), Ok(None));
}

/// The same forward move from bill day 28 to 1: a user suspended for quota
/// on 5 October, recorded for the cycle from 28 September, still counts in
/// the cycle from 1 October, so the evaluation suspends a remaining user
/// over the N = 6 share and warns one at 80 % of it, rather than leaving
/// them without a quota.
#[test]
fn a_forward_edit_of_the_bill_day_keeps_the_share_enforced() {
    let mut parts = with_bill_day(twenty(6, Some(AutoQuotaPolicy::PILOT)), 28).into_parts();
    parts.users[0]
        .suspend(over_quota("2026-09-28"), at("2026-10-05", 0))
        .unwrap();
    let billed_on_1 = with_bill_day(Deployment::try_from(parts).unwrap(), 1);
    let now = at("2026-10-10", 0);
    assert_eq!(
        automatic_quota(&billed_on_1, now),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    let ids = active_ids(&billed_on_1);
    assert_eq!(ids.len(), 5);
    let mut served: Vec<(UserId, u64)> = ids.iter().map(|id| (id.clone(), 0)).collect();
    served[0].1 = 100 * GB;
    // 80 % of the N = 6 share, rounded up.
    served[1].1 = 15_238_095_238;
    assert_eq!(
        evaluate(&billed_on_1, &usage(now, &served), now),
        Ok(vec![
            UserAction {
                user: ids[0].clone(),
                action: PolicyAction::Suspend(over_quota("2026-10-01"))
            },
            UserAction {
                user: ids[1].clone(),
                action: PolicyAction::Warn(PolicyWarning::QuotaNear {
                    used_bytes: 15_238_095_238,
                    quota_bytes: PILOT_QUOTA_AT_SIX
                })
            },
        ])
    );
}

/// A suspension for quota made after `now` cannot come from a clock that
/// kept time, so it is an error from the quota and from the evaluation,
/// whether its instant falls later in the current cycle or in a later one:
/// never held until its own cycle ends, and never lapsed. One made at `now`
/// holds. Only the instants of suspensions for quota are read, and only
/// with an automatic quota policy.
#[test]
fn a_quota_suspension_after_now_is_an_error() {
    let now = october();
    for since in [
        UnixTime::from_secs(now.as_secs() + 1),
        at("2026-11-01", 0),
        at("2027-06-01", 0),
    ] {
        let mut parts = twenty(6, Some(AutoQuotaPolicy::PILOT)).into_parts();
        parts.users[0]
            .suspend(over_quota("2026-10-01"), since)
            .unwrap();
        let error = PolicyError::QuotaSuspensionAfterNow {
            user: parts.users[0].id.clone(),
            since,
            now,
        };
        let deployment = Deployment::try_from(parts.clone()).unwrap();
        let served: Vec<(UserId, u64)> = active_ids(&deployment)
            .into_iter()
            .map(|id| (id, 0))
            .collect();
        assert_eq!(
            automatic_quota(&deployment, now),
            Err(error.clone()),
            "{since:?}"
        );
        assert_eq!(
            evaluate(&deployment, &usage(now, &served), now),
            Err(error),
            "{since:?}"
        );
        parts.auto_quota = None;
        let off = Deployment::try_from(parts).unwrap();
        assert_eq!(automatic_quota(&off, now), Ok(None), "{since:?}");
        assert_eq!(
            evaluate(&off, &usage(now, &served), now),
            Ok(Vec::new()),
            "{since:?}"
        );
    }
    let mut parts = twenty(6, Some(AutoQuotaPolicy::PILOT)).into_parts();
    parts.users[0]
        .suspend(over_quota("2026-10-01"), now)
        .unwrap();
    assert_eq!(
        automatic_quota(&Deployment::try_from(parts).unwrap(), now),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    // The fourteen users the operator suspended on 2 October are not read
    // on 1 October.
    assert_eq!(
        automatic_quota(
            &twenty(6, Some(AutoQuotaPolicy::PILOT)),
            at("2026-10-01", 0)
        ),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
}

/// A time whose billing cycle would start before the calendar's first day
/// is an error, never "no automatic quota", with or without an automatic
/// quota policy.
#[test]
fn the_automatic_quota_refuses_a_cycle_outside_the_calendar() {
    for auto in [Some(AutoQuotaPolicy::PILOT), None] {
        let billed_on_20 = with_bill_day(twenty(6, auto), 20);
        assert_eq!(
            automatic_quota(&billed_on_20, UnixTime::from_secs(86_400)),
            Err(PolicyError::Model(ModelError::InvalidDate)),
            "{auto:?}"
        );
    }
}

/// A suspension by the operator, at expiry or for an abuse review is not
/// among the users sharing the budget: with five users active it leaves
/// the quota off, and with six it leaves N at six.
#[test]
fn other_suspensions_do_not_count() {
    let now = october();
    for reason in [
        SuspendReason::Operator,
        SuspendReason::Expired,
        SuspendReason::AbuseReview,
    ] {
        let mut parts = twenty(6, Some(AutoQuotaPolicy::PILOT)).into_parts();
        parts.users[0].suspend(reason, at("2026-10-05", 0)).unwrap();
        let five = Deployment::try_from(parts.clone()).unwrap();
        assert_eq!(active_ids(&five).len(), 5);
        assert_eq!(automatic_quota(&five, now), Ok(None), "{reason:?}");
        parts.users[6].resume().unwrap();
        let six = Deployment::try_from(parts).unwrap();
        assert_eq!(active_ids(&six).len(), 6);
        assert_eq!(
            automatic_quota(&six, now),
            Ok(pilot_quota(PILOT_QUOTA_AT_SIX)),
            "{reason:?}"
        );
    }
}

/// Under the pilot's cap, five active users and one suspended this cycle
/// for their own quota share the budget as six, so the automatic quota
/// applies to the five; in the next cycle that suspension no longer
/// counts and the quota is off again.
#[test]
fn five_active_and_one_suspended_for_quota_this_cycle_share_as_six() {
    let mut parts = twenty(5, Some(AutoQuotaPolicy::PILOT)).into_parts();
    parts.capacity = CapacityPolicy::PILOT;
    parts.users[5].resume().unwrap();
    parts.users[5].policy.quota = Some(quota(GB, 80, QuotaAction::Suspend));
    parts.users[5]
        .suspend(over_quota("2026-10-01"), at("2026-10-03", 0))
        .unwrap();
    let deployment = Deployment::try_from(parts).unwrap();
    assert_eq!(active_ids(&deployment).len(), 5);
    assert_eq!(
        automatic_quota(&deployment, october()),
        Ok(pilot_quota(PILOT_QUOTA_AT_SIX))
    );
    assert_eq!(automatic_quota(&deployment, at("2026-11-02", 0)), Ok(None));
}

/// A user's own quota overrides the automatic one, whether larger or
/// smaller, and still counts the user among the active.
#[test]
fn an_override_wins() {
    let mut parts = twenty(6, Some(AutoQuotaPolicy::PILOT)).into_parts();
    let larger = quota(50 * GB, 80, QuotaAction::Suspend);
    let smaller = quota(GB, 90, QuotaAction::Warn);
    parts.users[0].policy.quota = Some(larger);
    parts.users[1].policy.quota = Some(smaller);
    let deployment = Deployment::try_from(parts).unwrap();
    let automatic = automatic_quota(&deployment, october()).unwrap();
    assert_eq!(automatic, pilot_quota(PILOT_QUOTA_AT_SIX));
    let ids = active_ids(&deployment);
    let user = |index: usize| &deployment.users()[&ids[index]];
    assert_eq!(effective_quota(user(0), automatic), Some(larger));
    assert_eq!(effective_quota(user(1), automatic), Some(smaller));
    assert_eq!(effective_quota(user(2), automatic), automatic);
    assert_eq!(effective_quota(user(0), None), Some(larger));
    assert_eq!(effective_quota(user(2), None), None);

    // 25 GB is over the automatic quota but within the larger override;
    // 2 GB is within the automatic quota but over the smaller one.
    let now = at("2026-10-08", 0);
    let mut served: Vec<(UserId, u64)> = ids.iter().map(|id| (id.clone(), 0)).collect();
    served[0].1 = 25 * GB;
    served[1].1 = 2 * GB;
    served[2].1 = PILOT_QUOTA_AT_SIX;
    assert_eq!(
        evaluate(&deployment, &usage(now, &served), now),
        Ok(vec![
            UserAction {
                user: ids[1].clone(),
                action: PolicyAction::Warn(PolicyWarning::QuotaReached {
                    used_bytes: 2 * GB,
                    quota_bytes: GB
                })
            },
            UserAction {
                user: ids[2].clone(),
                action: PolicyAction::Suspend(SuspendReason::QuotaExceeded {
                    cycle_start: date("2026-10-01")
                })
            },
        ])
    );
}

/// The automatic quota warns at 80 % and suspends at 100 %; with automatic
/// quotas on, every active user needs usage, and with them off the same
/// usage proposes nothing.
#[test]
fn evaluate_suspends_and_warns_on_the_automatic_quota() {
    let deployment = twenty(6, Some(AutoQuotaPolicy::PILOT));
    let ids = active_ids(&deployment);
    let now = at("2026-10-08", 12 * 3600);
    let mut served: Vec<(UserId, u64)> = ids.iter().map(|id| (id.clone(), 0)).collect();
    served[0].1 = PILOT_QUOTA_AT_SIX;
    // 80 % of the quota is 15,238,095,237.6 bytes.
    served[1].1 = 15_238_095_238;
    served[2].1 = 15_238_095_237;
    served[3].1 = PILOT_QUOTA_AT_SIX - 1;
    let actions = evaluate(&deployment, &usage(now, &served), now).unwrap();
    assert_eq!(
        actions,
        vec![
            UserAction {
                user: ids[0].clone(),
                action: PolicyAction::Suspend(SuspendReason::QuotaExceeded {
                    cycle_start: date("2026-10-01")
                })
            },
            UserAction {
                user: ids[1].clone(),
                action: PolicyAction::Warn(PolicyWarning::QuotaNear {
                    used_bytes: 15_238_095_238,
                    quota_bytes: PILOT_QUOTA_AT_SIX
                })
            },
            UserAction {
                user: ids[3].clone(),
                action: PolicyAction::Warn(PolicyWarning::QuotaNear {
                    used_bytes: PILOT_QUOTA_AT_SIX - 1,
                    quota_bytes: PILOT_QUOTA_AT_SIX
                })
            },
        ]
    );
    assert_eq!(
        user_alerts(deployment.users(), &actions),
        vec![
            AlertCondition::UsersNearQuota { count: 2 },
            AlertCondition::UsersOverQuota { count: 1 },
            AlertCondition::UsersSuspended { count: 14 },
        ]
    );
    let missing: Vec<(UserId, u64)> = served[..5].to_vec();
    assert_eq!(
        evaluate(&deployment, &usage(now, &missing), now),
        Err(PolicyError::UsageMissing {
            user: ids[5].clone()
        })
    );
    let off = twenty(6, None);
    assert_eq!(evaluate(&off, &usage(now, &served), now), Ok(Vec::new()));
    assert_eq!(evaluate(&off, &usage(now, &missing), now), Ok(Vec::new()));
}

/// A share that rounds down to zero is an error, from the quota and from
/// the evaluation, never "no quota".
#[test]
fn a_zero_quota_is_an_error() {
    let pilot = twenty(6, Some(AutoQuotaPolicy::PILOT));
    let tiny = |stop| {
        with_sim(
            pilot.clone(),
            smarty(),
            1,
            StopPolicy::HardStop { bytes: stop },
        )
    };
    let zero = PolicyError::AutomaticQuotaZero {
        budget_bytes: 15,
        sharing: 6,
    };
    let now = october();
    assert_eq!(automatic_quota(&tiny(15), now), Err(zero.clone()));
    assert_eq!(evaluate(&tiny(15), &usage(now, &[]), now), Err(zero));
    // 16 bytes is the smallest budget that leaves six users a byte each.
    assert_eq!(automatic_quota(&tiny(16), now), Ok(pilot_quota(1)));
}

/// The budget is the hard stop, or under `AcceptDeprioritisation` the
/// fair-use line; never the warning.
#[test]
fn the_budget_follows_the_stop() {
    let pilot = twenty(6, Some(AutoQuotaPolicy::PILOT));
    let halved = with_sim(
        pilot.clone(),
        smarty(),
        100 * GB,
        StopPolicy::HardStop { bytes: 150 * GB },
    );
    assert_eq!(
        automatic_quota(&halved, october()),
        Ok(pilot_quota(9_523_809_523))
    );
    let fair_use = SimPlan {
        kind: PlanKind::UnlimitedFairUse {
            fair_use_bytes: NonZeroU64::new(600 << 30).unwrap(),
            window: FairUseWindow::BillingCycle,
        },
        ..smarty()
    };
    let accepting = with_sim(
        pilot,
        fair_use,
        240 * GB,
        StopPolicy::AcceptDeprioritisation,
    );
    // 644,245,094,400 bytes × 1000 / 2100 × 80 % / 6.
    assert_eq!(
        automatic_quota(&accepting, october()),
        Ok(pilot_quota(40_904_450_438))
    );
}

/// The instants users are suspended at in the property below, around the
/// start of October's cycle and `october()`, each with whether a
/// suspension for quota made then holds in October: made at or after the
/// cycle's start (UTC midnight of 1 October), and not after `october()`.
const SUSPENDED_AT: [((&str, u64), bool); 5] = [
    (("2026-09-20", 0), false),
    (("2026-09-30", 86_399), false),
    (("2026-10-01", 0), true),
    (("2026-10-05", 0), true),
    (("2026-10-08", 0), true),
];

/// The cycle starts a suspension for quota records in the property below:
/// none of them decides whether it holds.
const RECORDED_STARTS: [&str; 3] = ["2026-09-01", "2026-10-01", "2026-11-01"];

/// The policy with the given values and the pilot's warning and action.
fn auto_policy(from: u16, percent: u8, permille: u16) -> AutoQuotaPolicy {
    AutoQuotaPolicy {
        from_active_users: NonZeroU16::new(from).unwrap(),
        budget_percent: BudgetPercent::new(percent).unwrap(),
        sim_factor: SimFactor::new(permille).unwrap(),
        ..AutoQuotaPolicy::PILOT
    }
}

proptest! {
    /// For any budget, share, factor and number of active users, the quota
    /// is the formula rounded down: N quotas never exceed the share of the
    /// served budget, and one byte more each would. A share that rounds to
    /// zero is refused.
    #[test]
    fn the_quota_is_floored(
        stop in 2_u64..=u64::MAX,
        active in 1_usize..=20,
        percent in 1_u8..=100,
        permille in 1000_u16..=u16::MAX,
    ) {
        let policy = auto_policy(1, percent, permille);
        let deployment = with_sim(
            twenty(active, Some(policy)),
            smarty(),
            1,
            StopPolicy::HardStop { bytes: stop },
        );
        let share = u128::from(stop) * 1000 * u128::from(percent);
        let per_user = u128::from(permille) * 100 * active as u128;
        match automatic_quota(&deployment, october()) {
            Ok(Some(quota)) => {
                let bytes = u128::from(quota.cycle_served_bytes.get());
                prop_assert!(bytes * per_user <= share);
                prop_assert!(share < (bytes + 1) * per_user);
                prop_assert!(bytes <= u128::from(stop));
                prop_assert_eq!(quota.warn_percent, policy.warn_percent);
                prop_assert_eq!(quota.action, policy.action);
            }
            Ok(None) => prop_assert!(false, "{active} active users reach a threshold of 1"),
            Err(error) => {
                prop_assert_eq!(error, PolicyError::AutomaticQuotaZero { budget_bytes: stop, sharing: active });
                prop_assert!(share < per_user);
            }
        }
    }

    /// The users sharing the budget are exactly those active now and those
    /// suspended for quota during the current cycle, at or after its start,
    /// whatever cycle start the suspension records; a suspension for quota
    /// made before that start, or a suspension for any other reason, does
    /// not count. The pilot's cap of five admits only five active users, so
    /// under it the automatic quota (from six) applies only through
    /// suspensions for quota this cycle, and never without one.
    #[test]
    fn the_budget_is_shared_by_the_active_and_this_cycles_quota_suspensions(
        users in proptest::collection::vec(
            (0_u8..5, 0..SUSPENDED_AT.len(), 0..RECORDED_STARTS.len()),
            20,
        ),
    ) {
        let mut parts = twenty(20, Some(AutoQuotaPolicy::PILOT)).into_parts();
        for (user, &(state, when, recorded)) in parts.users.iter_mut().zip(&users) {
            let reason = match state {
                0 => continue,
                1 => over_quota(RECORDED_STARTS[recorded]),
                2 => SuspendReason::Operator,
                3 => SuspendReason::Expired,
                _ => SuspendReason::AbuseReview,
            };
            let ((day, secs), _) = SUSPENDED_AT[when];
            user.suspend(reason, at(day, secs)).unwrap();
        }
        let active = users.iter().filter(|&&(state, ..)| state == 0).count();
        let latched = users
            .iter()
            .filter(|&&(state, when, _)| state == 1 && SUSPENDED_AT[when].1)
            .count();
        let sharing = active + latched;
        let expected = (sharing >= 6).then(|| {
            // 300e9 × 1000 × 80 / (2100 × 100 × N), rounded down.
            let bytes = 300_000_000_000_u128 * 1000 * 80 / (2100 * 100 * sharing as u128);
            u64::try_from(bytes).unwrap()
        });
        let uncapped = Deployment::try_from(parts.clone()).unwrap();
        let found = automatic_quota(&uncapped, october())
            .unwrap()
            .map(|quota| quota.cycle_served_bytes.get());
        prop_assert_eq!(found, expected);
        parts.capacity = CapacityPolicy::PILOT;
        match Deployment::try_from(parts) {
            Ok(capped) => {
                prop_assert!(active <= 5);
                let applies = automatic_quota(&capped, october()).unwrap().is_some();
                prop_assert_eq!(applies, sharing >= 6);
                prop_assert!(!applies || latched > 0);
            }
            Err(error) => {
                prop_assert!(active >= 6);
                prop_assert!(
                    matches!(error, ModelError::TooManyActiveUsers { active: found, .. } if found == active),
                    "{error:?}"
                );
            }
        }
    }
}
