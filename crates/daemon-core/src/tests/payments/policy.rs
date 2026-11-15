// SPDX-License-Identifier: GPL-3.0-or-later

//! What paid orders give users (design §9.6): the effective quota and
//! expiry, and their readers: `evaluate` and the portal snapshot.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use mooring_model::{
    AgreementVersion, BillDay, CycleRule, PortalAgreement, QuotaAction, UnixTime, User, UserId,
    UserQuota, UserStatus, WarnPercent,
};
use serde_json::Value;

use super::{DAY, NOW, Terms, by_id, id, live, order, secs, user};
use crate::payments::{Entitlements, LedgerEvent, PaymentLedger};
use crate::period::BillingCycle;
use crate::policy::{
    EffectivePolicy, ExpiryState, PolicyAction, PolicyWarning, UserAction, effective_policy,
    evaluate, paid_quota,
};
use crate::portal::snapshot;
use crate::usage::CycleUsage;

const GB: u64 = 1_000_000_000;

/// The billing cycle `at` is in, on monthly cycles from the 1st.
fn cycle(at: UnixTime) -> BillingCycle {
    BillingCycle::of_instant(
        CycleRule::Monthly {
            bill_day: BillDay::new(1).unwrap(),
        },
        at,
    )
    .unwrap()
}

fn quota(bytes: u64, warn: u8, action: QuotaAction) -> UserQuota {
    UserQuota {
        cycle_served_bytes: NonZeroU64::new(bytes).unwrap(),
        warn_percent: WarnPercent::new(warn).unwrap(),
        action,
    }
}

/// The ledger after applying `entries` live at `at` for `users`.
fn granted(users: &BTreeMap<UserId, User>, entries: Vec<Value>, at: UnixTime) -> PaymentLedger {
    PaymentLedger::new()
        .apply(&live(0, entries), users, at, false)
        .unwrap()
        .ledger
}

fn policy_of(
    user: &User,
    automatic: Option<UserQuota>,
    paid: &Entitlements,
    at: UnixTime,
) -> EffectivePolicy {
    effective_policy(user, automatic, paid, cycle(at), at, None)
}

/// A paid period's quota is the order's bytes, with the pilot's automatic
/// quota's warning and action: a warning at 80 % and a suspension at all of
/// it.
#[test]
fn a_paid_quota_warns_at_80_and_suspends() {
    assert_eq!(
        paid_quota(NonZeroU64::new(100 * GB).unwrap()),
        quota(100 * GB, 80, QuotaAction::Suspend)
    );
}

/// Without a paid order a user is as their own record says: their own
/// quota, or the automatic one, and their own expiry.
#[test]
fn without_payments_the_users_own_record_holds() {
    let automatic = Some(quota(19 * GB, 80, QuotaAction::Suspend));
    let mut own = user("pilotusera", UserStatus::Active, Some(NOW.as_secs() + DAY));
    let none = Entitlements::none();
    assert_eq!(
        policy_of(&own, automatic, &none, NOW),
        EffectivePolicy {
            quota: automatic,
            expires_at: Some(secs(NOW.as_secs() + DAY)),
        }
    );
    own.policy.quota = Some(quota(GB, 90, QuotaAction::Warn));
    assert_eq!(
        policy_of(&own, automatic, &none, NOW).quota,
        Some(quota(GB, 90, QuotaAction::Warn))
    );
    let plain = user("pilotuserb", UserStatus::Active, None);
    assert_eq!(
        policy_of(&plain, None, &none, NOW),
        EffectivePolicy {
            quota: None,
            expires_at: None
        }
    );
}

/// A paid period gives its quota where the user has none of their own, in
/// place of the automatic one, while it covers the instant; its end is the
/// expiry, unless the user's own expiry is later.
#[test]
fn a_paid_period_gives_its_quota_and_its_end() {
    let now = NOW.as_secs();
    let users = by_id(vec![
        user("pilotusera", UserStatus::Active, None),
        user("pilotuserb", UserStatus::Active, Some(now + 100 * DAY)),
    ]);
    let ledger = granted(
        &users,
        vec![
            Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
            Terms::month("bbbbbbbbbbbbbbbbbbbb", "pilotuserb").grant(2),
        ],
        NOW,
    );
    let paid = ledger.entitlements(false);
    let automatic = Some(quota(19 * GB, 80, QuotaAction::Suspend));
    let a = &users[&id("pilotusera")];
    // A user who had no expiry and paid expires when the paid time ends.
    assert_eq!(
        policy_of(a, automatic, &paid, NOW),
        EffectivePolicy {
            quota: Some(paid_quota(NonZeroU64::new(100 * GB).unwrap())),
            expires_at: Some(secs(now + 30 * DAY)),
        }
    );
    // The period started at their own later expiry, so it covers no
    // instant before it: until then the automatic quota applies.
    let b = &users[&id("pilotuserb")];
    assert_eq!(
        policy_of(b, automatic, &paid, NOW),
        EffectivePolicy {
            quota: automatic,
            expires_at: Some(secs(now + 130 * DAY)),
        }
    );
    let inside = secs(now + 110 * DAY);
    assert_eq!(
        policy_of(b, automatic, &paid, inside).quota,
        Some(paid_quota(NonZeroU64::new(100 * GB).unwrap()))
    );
    // Past the end the period gives no quota, and its end stays the
    // expiry.
    let after = secs(now + 31 * DAY);
    assert_eq!(
        policy_of(a, automatic, &paid, after),
        EffectivePolicy {
            quota: automatic,
            expires_at: Some(secs(now + 30 * DAY)),
        }
    );
    assert_eq!(
        ExpiryState::of(policy_of(a, automatic, &paid, after).expires_at, after),
        ExpiryState::Expired {
            at: secs(now + 30 * DAY)
        }
    );
    // An own expiry later than the paid time is kept.
    let mut later = a.clone();
    later.policy.expires_at = Some(secs(now + 45 * DAY));
    assert_eq!(
        policy_of(&later, automatic, &paid, NOW).expires_at,
        Some(secs(now + 45 * DAY))
    );
}

/// While a paid period covers the instant, the user's own quota counts only
/// where it allows more than the period's (the operator's decision of
/// 2026-11-15): a payment is never given less than it bought, and the
/// operator's own quota only adds. A quota that only warns allows any use,
/// so it wins over the period's whatever its bytes; of two that suspend,
/// the one of more bytes wins, and the user's own a tie, its warning share
/// included. Outside the period the user's own quota holds again, in place
/// of the automatic one, and the cycle's packs add to whichever applies.
#[test]
fn a_paid_period_and_the_users_own_quota_give_the_larger() {
    let users = by_id(vec![user("pilotusera", UserStatus::Active, None)]);
    let with_own = |own: UserQuota| {
        let mut user = users[&id("pilotusera")].clone();
        user.policy.quota = Some(own);
        user
    };
    let month = granted(
        &users,
        vec![Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1)],
        NOW,
    )
    .entitlements(false);
    let automatic = Some(quota(19 * GB, 80, QuotaAction::Suspend));
    let paid = paid_quota(NonZeroU64::new(100 * GB).unwrap());
    let less = quota(50 * GB, 80, QuotaAction::Suspend);
    let just_less = quota(100 * GB - 1, 99, QuotaAction::Suspend);
    let as_much = quota(100 * GB, 90, QuotaAction::Suspend);
    let more = quota(150 * GB, 70, QuotaAction::Suspend);
    let warns_only = quota(GB, 90, QuotaAction::Warn);
    for (own, expected) in [
        (less, paid),
        (just_less, paid),
        (as_much, as_much),
        (more, more),
        (warns_only, warns_only),
    ] {
        assert_eq!(
            policy_of(&with_own(own), automatic, &month, NOW).quota,
            Some(expected),
            "{own:?}"
        );
    }
    // Past the period's end the user's own quota holds, not the automatic
    // one, and the period's end is still the expiry.
    let after = secs(NOW.as_secs() + 31 * DAY);
    assert_eq!(
        policy_of(&with_own(less), automatic, &month, after),
        EffectivePolicy {
            quota: Some(less),
            expires_at: Some(secs(NOW.as_secs() + 30 * DAY)),
        }
    );
    // A 50 GB pack adds to the period's quota where that is the larger,
    // and to the user's own where that is.
    let with_pack = granted(
        &users,
        vec![
            Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
            Terms::pack("bbbbbbbbbbbbbbbbbbbb", "pilotusera").grant(2),
        ],
        NOW,
    )
    .entitlements(false);
    assert_eq!(
        policy_of(&with_own(less), automatic, &with_pack, NOW).quota,
        Some(quota(150 * GB, 80, QuotaAction::Suspend))
    );
    assert_eq!(
        policy_of(&with_own(more), automatic, &with_pack, NOW).quota,
        Some(quota(200 * GB, 70, QuotaAction::Suspend))
    );
}

/// The apply job's evaluation reads the larger quota: a user whose own
/// quota is 50 GB and whose paid month gives 100 GB is not suspended at
/// 60 GB, and is at 100 GB.
#[test]
fn evaluate_suspends_at_the_larger_of_the_own_and_the_paid_quota() {
    let mut parts = super::super::support::deployment().into_parts();
    parts.users[0].policy.quota = Some(quota(50 * GB, 80, QuotaAction::Suspend));
    let deployment = mooring_model::Deployment::try_from(parts).unwrap();
    let ids: Vec<UserId> = deployment.users().keys().cloned().collect();
    let mut terms = Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera");
    terms.user = Box::leak(ids[0].as_str().to_owned().into_boxed_str());
    let paid = granted(deployment.users(), vec![terms.grant(1)], NOW).entitlements(false);
    let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), NOW).unwrap();
    let usage = |served: u64| CycleUsage {
        cycle,
        through: NOW,
        served: ids.iter().map(|id| (id.clone(), Some(served))).collect(),
        reality_downlink: BTreeMap::new(),
    };
    let suspended = UserAction {
        user: ids[0].clone(),
        action: PolicyAction::Suspend(mooring_model::SuspendReason::QuotaExceeded {
            cycle_start: cycle.start(),
        }),
    };
    let within = evaluate(&deployment, &paid, Some(&usage(60 * GB)), NOW).unwrap();
    assert!(
        !within.iter().any(|action| action.user == ids[0]),
        "{within:?}"
    );
    let over = evaluate(&deployment, &paid, Some(&usage(100 * GB)), NOW).unwrap();
    assert!(over.contains(&suspended), "{over:?}");
}

/// A pack adds its bytes to the quota that applies, in the billing cycle
/// it was granted in and in no other; a user with no quota keeps none.
#[test]
fn a_pack_raises_the_quota_of_its_cycle_only() {
    let users = by_id(vec![user("pilotusera", UserStatus::Active, None)]);
    let ledger = granted(
        &users,
        vec![
            Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
            Terms::pack("bbbbbbbbbbbbbbbbbbbb", "pilotusera").grant(2),
            Terms::pack("cccccccccccccccccccc", "pilotusera").grant(3),
        ],
        NOW,
    );
    let paid = ledger.entitlements(false);
    let a = &users[&id("pilotusera")];
    let mut with_packs = paid_quota(NonZeroU64::new(100 * GB).unwrap());
    with_packs.cycle_served_bytes = NonZeroU64::new(200 * GB).unwrap();
    assert_eq!(policy_of(a, None, &paid, NOW).quota, Some(with_packs));
    let entitlements = paid.user(&id("pilotusera")).unwrap();
    assert_eq!(entitlements.packs().len(), 2);
    assert_eq!(
        entitlements.pack_bytes_in(cycle(NOW), NOW, 0, None),
        100 * GB
    );
    let next_cycle = cycle(NOW).ends_at();
    assert_eq!(
        entitlements.pack_bytes_in(cycle(next_cycle), next_cycle, 0, None),
        0
    );
    assert_eq!(
        policy_of(a, None, &paid, next_cycle).quota,
        Some(paid_quota(NonZeroU64::new(100 * GB).unwrap()))
    );
    // Packs alone, with the automatic quota, or with none.
    let packs_only = granted(
        &users,
        vec![Terms::pack("dddddddddddddddddddd", "pilotusera").grant(1)],
        NOW,
    )
    .entitlements(false);
    let automatic = quota(19 * GB, 80, QuotaAction::Suspend);
    let mut raised = automatic;
    raised.cycle_served_bytes = NonZeroU64::new(69 * GB).unwrap();
    assert_eq!(
        policy_of(a, Some(automatic), &packs_only, NOW),
        EffectivePolicy {
            quota: Some(raised),
            expires_at: None,
        }
    );
    assert_eq!(policy_of(a, None, &packs_only, NOW).quota, None);
}

/// `evaluate`, which the apply job will run, reads the effective policy: a
/// paid user past their paid time is due a suspension for expiry, one about
/// to reach it a warning, and one inside it with usage over the paid quota a
/// suspension for quota.
#[test]
fn evaluate_reads_the_paid_policy() {
    let deployment = super::super::support::deployment();
    let ids: Vec<UserId> = deployment.users().keys().cloned().collect();
    let now = NOW.as_secs();
    let users = deployment.users().clone();
    let terms = |order: &'static str, index: usize| {
        let mut terms = Terms::month(order, "pilotusera");
        terms.user = Box::leak(ids[index].as_str().to_owned().into_boxed_str());
        terms
    };
    let first = terms("aaaaaaaaaaaaaaaaaaaa", 0);
    let second = terms("bbbbbbbbbbbbbbbbbbbb", 1);
    let mut short = terms("cccccccccccccccccccc", 2);
    short.days = 1;
    let ledger = granted(
        &users,
        vec![first.grant(1), second.grant(2), short.grant(3)],
        secs(now - 31 * DAY),
    );
    // At now, the first two periods (30 days from 31 days ago) are over and
    // the third ended 30 days ago; give the second user a fresh period.
    let ledger = ledger
        .apply(
            &live(3, vec![terms("dddddddddddddddddddd", 1).grant(4)]),
            &users,
            secs(now - DAY),
            false,
        )
        .unwrap()
        .ledger;
    let paid = ledger.entitlements(false);
    let usage = |served: u64| CycleUsage {
        cycle: BillingCycle::of_instant(deployment.exit().sim.cycle(), NOW).unwrap(),
        through: NOW,
        served: ids.iter().map(|id| (id.clone(), Some(served))).collect(),
        reality_downlink: BTreeMap::new(),
    };
    let actions = evaluate(&deployment, &paid, Some(&usage(0)), NOW).unwrap();
    let expected_first = UserAction {
        user: ids[0].clone(),
        action: PolicyAction::Suspend(mooring_model::SuspendReason::Expired),
    };
    assert!(actions.contains(&expected_first), "{actions:?}");
    assert!(
        !actions.iter().any(|action| action.user == ids[1]),
        "{actions:?}"
    );
    let over = evaluate(&deployment, &paid, Some(&usage(100 * GB)), NOW).unwrap();
    assert!(
        over.contains(&UserAction {
            user: ids[1].clone(),
            action: PolicyAction::Suspend(mooring_model::SuspendReason::QuotaExceeded {
                cycle_start: BillingCycle::of_instant(deployment.exit().sim.cycle(), NOW)
                    .unwrap()
                    .start(),
            }),
        })
    );
    let near = evaluate(&deployment, &paid, Some(&usage(80 * GB)), NOW).unwrap();
    assert!(near.contains(&UserAction {
        user: ids[1].clone(),
        action: PolicyAction::Warn(PolicyWarning::QuotaNear {
            used_bytes: 80 * GB,
            quota_bytes: 100 * GB
        }),
    }));
    // Two days before the second user's paid time ends, the expiry warns.
    let soon = secs(now + 27 * DAY);
    let soon_usage = CycleUsage {
        cycle: BillingCycle::of_instant(deployment.exit().sim.cycle(), soon).unwrap(),
        through: soon,
        served: ids.iter().map(|id| (id.clone(), Some(0))).collect(),
        reality_downlink: BTreeMap::new(),
    };
    let warned = evaluate(&deployment, &paid, Some(&soon_usage), soon).unwrap();
    assert!(warned.contains(&UserAction {
        user: ids[1].clone(),
        action: PolicyAction::Warn(PolicyWarning::ExpiresSoon {
            at: secs(now - DAY + 30 * DAY)
        }),
    }));
}

/// A dispute never suspends the user, nor takes back their paid time or
/// quota (the operator's decision of 2026-11-11, design §9.6): two days
/// after their month is disputed, the user has what the month gave and is
/// due no action.
#[test]
fn a_dispute_never_suspends_the_user() {
    let deployment = super::super::support::deployment();
    let ids: Vec<UserId> = deployment.users().keys().cloned().collect();
    let users = deployment.users().clone();
    let mut terms = Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera");
    terms.user = Box::leak(ids[0].as_str().to_owned().into_boxed_str());
    let paid = granted(&users, vec![terms.grant(1)], NOW);
    let disputed = paid
        .apply(&live(1, vec![terms.dispute(2, 800)]), &users, NOW, false)
        .unwrap();
    assert_eq!(
        disputed.events,
        [LedgerEvent::Disputed {
            order: order("aaaaaaaaaaaaaaaaaaaa"),
            user: ids[0].clone(),
            amount_disputed: 800,
            granted: true,
        }]
    );
    let after = disputed.ledger.entitlements(false);
    assert_eq!(after, paid.entitlements(false));
    let two_days_on = secs(NOW.as_secs() + 2 * DAY);
    assert_eq!(
        policy_of(&users[&ids[0]], None, &after, two_days_on),
        EffectivePolicy {
            quota: Some(paid_quota(NonZeroU64::new(100 * GB).unwrap())),
            expires_at: Some(secs(NOW.as_secs() + 30 * DAY)),
        }
    );
    let usage = CycleUsage {
        cycle: BillingCycle::of_instant(deployment.exit().sim.cycle(), two_days_on).unwrap(),
        through: two_days_on,
        served: ids.iter().map(|id| (id.clone(), Some(0))).collect(),
        reality_downlink: BTreeMap::new(),
    };
    let actions = evaluate(&deployment, &after, Some(&usage), two_days_on).unwrap();
    assert!(
        !actions.iter().any(|action| action.user == ids[0]),
        "{actions:?}"
    );
}

/// The portal snapshot shows a paid user their paid quota and the end of
/// their paid time.
#[test]
fn the_portal_snapshot_shows_the_paid_policy() {
    let deployment = super::super::support::deployment();
    let ids: Vec<UserId> = deployment.users().keys().cloned().collect();
    let mut terms = Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera");
    terms.user = Box::leak(ids[0].as_str().to_owned().into_boxed_str());
    let at = mooring_fixtures::FIXTURE_NOW;
    let ledger = granted(deployment.users(), vec![terms.grant(1)], at);
    let open = PortalAgreement::since(Some(AgreementVersion::CURRENT));
    let made = snapshot(
        &deployment,
        None,
        &ledger.entitlements(false),
        &ids,
        at,
        open,
    )
    .unwrap();
    let document: Value = serde_json::from_slice(made.bytes()).unwrap();
    let first = &document["users"][0];
    assert_eq!(first["user"], ids[0].as_str());
    assert_eq!(
        first["quota"],
        serde_json::json!({"cycle_served_bytes": 100_000_000_000_u64, "warn_percent": 80, "action": "suspend"})
    );
    assert_eq!(first["expires_at"], at.as_secs() + 30 * DAY);
    let without = snapshot(&deployment, None, &Entitlements::none(), &ids, at, open).unwrap();
    let plain: Value = serde_json::from_slice(without.bytes()).unwrap();
    assert_eq!(plain["users"][1], document["users"][1]);
    assert_ne!(plain["users"][0], document["users"][0]);
}
