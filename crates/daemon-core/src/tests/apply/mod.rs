// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's decisions (design §13.6, §15.7): its window, its policy
//! step and its removals, against deployments of users in every status.

mod evaluate;
mod mid_cycle;
mod plan;
mod removals;
mod window;

use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU64};

use mooring_model::deployment::CapacityPolicy;
use mooring_model::quota::AutoQuotaPolicy;
use mooring_model::user::{QuotaAction, SuspendReason, UserPolicy, UserQuota, WarnPercent};
use mooring_model::{Deployment, UnixTime, User, UserId, UserStatus};

use super::support::{at, deployment_billed_on, users};
use crate::period::BillingCycle;
use crate::usage::CycleUsage;

pub(super) const GB: u64 = 1_000_000_000;

/// The run's time: 19:20 UTC on 2026-11-02, in the cycle from
/// 2026-11-01 (bill day 1).
pub(super) fn now() -> UnixTime {
    at("2026-11-02", (19 * 60 + 20) * 60)
}

/// User `n`: the fixture's first user with id `n`, holding no
/// credentials, in `status`, with `policy`.
pub(super) fn user(n: u64, status: UserStatus, policy: UserPolicy) -> User {
    let mut user = users().into_values().next().unwrap();
    user.id = UserId::from_low_bits(n);
    user.per_node.clear();
    user.alias = None;
    user.status = status;
    user.policy = policy;
    user
}

pub(super) fn id(n: u64) -> UserId {
    UserId::from_low_bits(n)
}

/// Active user `n` without a policy.
pub(super) fn active(n: u64) -> User {
    user(n, UserStatus::Active, UserPolicy::NONE)
}

/// User `n` suspended for `reason` at `since`, without a policy.
pub(super) fn suspended(n: u64, reason: SuspendReason, since: UnixTime) -> User {
    user(n, UserStatus::Suspended { reason, since }, UserPolicy::NONE)
}

/// User `n` suspended for its quota at `since`, in the cycle from
/// `cycle_start`.
pub(super) fn over_quota(n: u64, cycle_start: &str, since: UnixTime) -> User {
    suspended(
        n,
        SuspendReason::QuotaExceeded {
            cycle_start: super::support::date(cycle_start),
        },
        since,
    )
}

pub(super) fn quota(bytes: u64) -> UserQuota {
    UserQuota {
        cycle_served_bytes: NonZeroU64::new(bytes).unwrap(),
        warn_percent: WarnPercent::new(80).unwrap(),
        action: QuotaAction::Suspend,
    }
}

/// The fixture deployment billed on day 1, holding `users`, capped at
/// `cap` active users (none: no cap), without automatic quotas.
pub(super) fn holding(users: Vec<User>, cap: Option<u16>) -> Deployment {
    let mut parts = deployment_billed_on(1).into_parts();
    parts.users = users;
    parts.capacity = CapacityPolicy {
        max_active_users: cap.map(|cap| NonZeroU16::new(cap).unwrap()),
    };
    parts.auto_quota = None;
    Deployment::try_from(parts).unwrap()
}

/// `deployment` with the pilot's automatic quotas on.
pub(super) fn with_auto_quota(deployment: &Deployment) -> Deployment {
    let mut parts = deployment.clone().into_parts();
    parts.auto_quota = Some(AutoQuotaPolicy::PILOT);
    Deployment::try_from(parts).unwrap()
}

/// The cycle's usage through `now`: `served` bytes for the users named,
/// zero for every other user of `deployment`.
pub(super) fn usage(deployment: &Deployment, now: UnixTime, served: &[(u64, u64)]) -> CycleUsage {
    let given: BTreeMap<UserId, u64> = served.iter().map(|(n, bytes)| (id(*n), *bytes)).collect();
    CycleUsage {
        cycle: BillingCycle::of_instant(deployment.exit().sim.cycle(), now).unwrap(),
        through: now,
        served: deployment
            .users()
            .keys()
            .map(|user| (user.clone(), Some(given.get(user).copied().unwrap_or(0))))
            .collect(),
    }
}
