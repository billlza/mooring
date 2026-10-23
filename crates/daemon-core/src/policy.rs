// SPDX-License-Identifier: GPL-3.0-or-later

//! Quota and expiry evaluation (console spec P1-1): from each user's
//! [`UserPolicy`], the deployment's automatic quotas, the cycle's usage and
//! the time, the actions the daemon would apply in the next apply window.
//! Nothing here applies anything: suspending a user is an explicit state
//! change made elsewhere, and the model's renderers and export look only at
//! `UserStatus`.
//!
//! # Quotas (decision F4, 2026-10-08)
//!
//! A user's quota is their own `UserPolicy::quota` when the operator set
//! one (an override), and otherwise the deployment's automatic quota
//! ([`automatic_quota`]) when it applies, and otherwise none
//! ([`effective_quota`]). The automatic quota applies while at least
//! `AutoQuotaPolicy::from_active_users` users (F4: 6) share the cycle's
//! budget: the users `Active` now and those suspended for quota during the
//! current cycle, so a suspension for quota never switches the quota off
//! or changes anyone's share within the cycle (latched per cycle, decided
//! 2026-10-09). Any other departure, a suspension for another reason or a
//! revocation, still lowers the count. Each user's share is
//! `budget_percent` of the cycle's served budget divided by those users,
//! the served budget being the SIM budget (the hard stop, or under
//! `AcceptDeprioritisation` the fair-use line) divided by the recorded SIM
//! factor. Under the pilot's cap of 5 active users the automatic quota
//! applies only once users suspended for their own quota this cycle bring
//! the users sharing the budget to six. Expiries stay a per-user record;
//! their default is a pending operator decision.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use mooring_model::quota::{BudgetPercent, SimFactor};
use mooring_model::user::{QuotaAction, SuspendReason, UserPolicy, UserQuota, UserStatus};
use mooring_model::{Deployment, UnixTime, User, UserId};
use serde::{Deserialize, Serialize};

use crate::alert::AlertCondition;
use crate::error::PolicyError;
use crate::period::{BillingCycle, days_until};
use crate::usage::CycleUsage;

/// How long before an expiry the operator is warned (console spec B.4).
pub const EXPIRY_WARNING_SECS: u64 = 3 * 86_400;

/// A user's quota against the cycle's served bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QuotaState {
    /// The user has no quota.
    NoQuota,
    /// Below the warning share.
    Within {
        /// Bytes served this cycle.
        used_bytes: u64,
        /// The quota.
        quota_bytes: u64,
    },
    /// At or above the warning share, below the quota.
    Warn {
        /// Bytes served this cycle.
        used_bytes: u64,
        /// The quota.
        quota_bytes: u64,
    },
    /// At or above the quota.
    Over {
        /// Bytes served this cycle.
        used_bytes: u64,
        /// The quota.
        quota_bytes: u64,
    },
    /// The user has a quota, but the cycle's usage is unavailable, so the
    /// state is unknown (never assumed to be within the quota).
    UsageUnavailable {
        /// The quota.
        quota_bytes: u64,
    },
}

impl QuotaState {
    /// The state of a user's quota ([`effective_quota`]) when the cycle's
    /// usage is unavailable: [`QuotaState::NoQuota`] or
    /// [`QuotaState::UsageUnavailable`].
    #[must_use]
    pub const fn without_usage(quota: Option<UserQuota>) -> Self {
        match quota {
            None => Self::NoQuota,
            Some(quota) => Self::UsageUnavailable {
                quota_bytes: quota.cycle_served_bytes.get(),
            },
        }
    }

    /// The state of a user's quota ([`effective_quota`]) with `used_bytes`
    /// served this cycle.
    #[must_use]
    pub fn of(quota: Option<UserQuota>, used_bytes: u64) -> Self {
        let Some(quota) = quota else {
            return Self::NoQuota;
        };
        let quota_bytes = quota.cycle_served_bytes.get();
        if used_bytes >= quota_bytes {
            Self::Over {
                used_bytes,
                quota_bytes,
            }
        } else if u128::from(used_bytes) * 100
            >= u128::from(quota_bytes) * u128::from(quota.warn_percent.get())
        {
            Self::Warn {
                used_bytes,
                quota_bytes,
            }
        } else {
            Self::Within {
                used_bytes,
                quota_bytes,
            }
        }
    }
}

/// A user's expiry at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpiryState {
    /// The user's access does not expire.
    NoExpiry,
    /// The access expires at `at`, in `days_left` days rounded up.
    Expires {
        /// When.
        at: UnixTime,
        /// Whole days left, rounded up; at least 1.
        days_left: u64,
    },
    /// The access expired at `at` (at or before the evaluation time).
    Expired {
        /// When.
        at: UnixTime,
    },
}

impl ExpiryState {
    /// The state of `policy`'s expiry at `now`.
    #[must_use]
    pub fn of(policy: &UserPolicy, now: UnixTime) -> Self {
        match policy.expires_at {
            None => Self::NoExpiry,
            Some(at) if at <= now => Self::Expired { at },
            Some(at) => Self::Expires {
                at,
                days_left: days_until(now, at),
            },
        }
    }
}

/// A warning about a user's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyWarning {
    /// The user reached the warning share of the quota.
    QuotaNear {
        /// Bytes served this cycle.
        used_bytes: u64,
        /// The quota.
        quota_bytes: u64,
    },
    /// The user reached a quota whose action is only to warn.
    QuotaReached {
        /// Bytes served this cycle.
        used_bytes: u64,
        /// The quota.
        quota_bytes: u64,
    },
    /// The user's access expires within [`EXPIRY_WARNING_SECS`].
    ExpiresSoon {
        /// When.
        at: UnixTime,
    },
}

/// What the daemon would do about one user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyAction {
    /// Tell the operator.
    Warn(PolicyWarning),
    /// Suspend the user (reversibly; their credentials are kept).
    Suspend(SuspendReason),
}

/// One action for one user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAction {
    /// The user.
    pub user: UserId,
    /// The action.
    pub action: PolicyAction,
}

/// The automatic quota of the billing cycle `now` is in (decision F4), if
/// it applies: `Some` when `deployment` has an `AutoQuotaPolicy` and at
/// least its `from_active_users` users share the cycle's budget, `None`
/// otherwise. `Model` when the cycle falls outside the calendar; with an
/// `AutoQuotaPolicy`, `QuotaSuspensionAfterNow` when a user's suspension
/// for quota was made after `now`, which the Mac's clock cannot have
/// written unless it stepped back since.
///
/// N, the users sharing the budget, counts the users `Active` now and the
/// users suspended with `SuspendReason::QuotaExceeded` during this cycle:
/// their `UserStatus::Suspended::since` is at or after the cycle's start
/// (UTC midnight of its first day) and not after `now`. The threshold
/// counts the same users. The suspension's instant decides, not the
/// `cycle_start` it records: that names the cycle as it was when the user
/// was suspended, and after an edit of the cycle rule (design §7,
/// `CycleRule`) it can lie on either side of the current cycle's start, whichever side
/// the suspension was made on. The quota is latched per cycle (design
/// §15.3, §20 F4, decided 2026-10-09): suspending a user for quota changes
/// neither N nor anyone's share within the cycle, so it never switches the
/// quota off for the others. Admitting
/// a user mid-cycle still raises N and lowers every share at once (F4's
/// "÷ N"), so a user between the old and the new share is suspended at the
/// next evaluation. A user suspended for any other reason, revoking or
/// revoked does not count, so such a departure lowers N, raising every
/// share, and switches the quota off when N was at the threshold; nor does a
/// suspension for quota made before the cycle's start, which has lapsed
/// (the M5 apply resumes it at the boundary, within the cap); a user with
/// an override does count. Each share is
/// `budget × 1000 × budget_percent / (sim_factor_permille × 100 × N)`
/// served bytes, rounded down, where the budget is the SIM policy's
/// [`SimThresholds::budget_bytes`](mooring_model::sim::SimThresholds::budget_bytes);
/// a share that rounds down to zero is `AutomaticQuotaZero`, never read as
/// no quota. The quota warns at the policy's `warn_percent` and does its
/// `action` at all of it.
pub fn automatic_quota(
    deployment: &Deployment,
    now: UnixTime,
) -> Result<Option<UserQuota>, PolicyError> {
    cycle_quota(deployment, Moment::of(deployment, now)?)
}

/// An evaluation time and the billing cycle it is in, computed together
/// from the deployment's bill day so that the two cannot disagree:
/// `cycle` contains `now`.
#[derive(Debug, Clone, Copy)]
struct Moment {
    now: UnixTime,
    cycle: BillingCycle,
}

impl Moment {
    /// `now` and the billing cycle it is in, on `deployment`'s bill day.
    fn of(deployment: &Deployment, now: UnixTime) -> Result<Self, PolicyError> {
        Ok(Self {
            now,
            cycle: BillingCycle::of_instant(deployment.exit().sim.cycle(), now)?,
        })
    }
}

/// [`automatic_quota`] at `moment`, computed once by the caller.
fn cycle_quota(deployment: &Deployment, moment: Moment) -> Result<Option<UserQuota>, PolicyError> {
    let Some(policy) = deployment.auto_quota() else {
        return Ok(None);
    };
    let mut sharing = 0_usize;
    for (id, user) in deployment.users() {
        if shares_the_budget(id, user, moment)? {
            sharing += 1;
        }
    }
    if sharing < usize::from(policy.from_active_users.get()) {
        return Ok(None);
    }
    let budget_bytes = deployment.exit().sim.thresholds().budget_bytes();
    let cycle_served_bytes = share(
        budget_bytes,
        policy.budget_percent,
        policy.sim_factor,
        sharing,
    )?;
    Ok(Some(UserQuota {
        cycle_served_bytes,
        warn_percent: policy.warn_percent,
        action: policy.action,
    }))
}

/// Whether user `id` is one of the N users sharing the budget of
/// `moment`'s cycle: active now, or suspended for quota by a suspension
/// that still holds ([`quota_suspension_holds`]). Every other status and
/// suspension reason is named, so a new one needs a decision here; their
/// instants are not read.
fn shares_the_budget(id: &UserId, user: &User, moment: Moment) -> Result<bool, PolicyError> {
    match user.status {
        UserStatus::Active => Ok(true),
        UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded { .. },
            since,
        } => quota_suspension_holds(id, since, moment),
        UserStatus::Suspended {
            reason: SuspendReason::Operator | SuspendReason::Expired | SuspendReason::AbuseReview,
            ..
        }
        | UserStatus::RevokePending
        | UserStatus::Revoked => Ok(false),
    }
}

/// Whether user `id`'s suspension for quota, made at `since`, still holds
/// at `moment` (design §15.3, §20 F4): it holds when it was made during
/// `moment`'s cycle, at or after the cycle's start, and has lapsed when it
/// was made before. The instant decides, not the `cycle_start` the
/// suspension records: after an edit of the cycle rule (design §7,
/// `CycleRule`) a recorded start can lie on either side of the current cycle's start,
/// whichever side the suspension was made on. A lapsed suspension shares
/// nothing, and resuming it at the cycle boundary is the apply's step (M5,
/// design §13.6), which is to use this predicate too, so that a suspension
/// for quota is always either held or lapsed.
///
/// A suspension made after `now` is neither: the Mac's clock wrote `since`
/// and gives `now`, so it stepped back since, or the record is corrupt.
/// It is `QuotaSuspensionAfterNow`, like usage that runs past `now`
/// (`UsageAfterNow`), never read as held until its own cycle ends, which
/// would keep the user out of service and in N for up to a cycle more than
/// any real suspension.
fn quota_suspension_holds(
    id: &UserId,
    since: UnixTime,
    moment: Moment,
) -> Result<bool, PolicyError> {
    if since > moment.now {
        return Err(PolicyError::QuotaSuspensionAfterNow {
            user: id.clone(),
            since,
            now: moment.now,
        });
    }
    Ok(since >= moment.cycle.starts_at())
}

/// One user's share of the served budget: `budget_bytes × 1000 × percent /
/// (factor × 100 × sharing)`, rounded down, in one step so that only the
/// final division rounds. `sharing` is at least 1 (the caller has checked
/// it against a non-zero threshold).
fn share(
    budget_bytes: u64,
    percent: BudgetPercent,
    factor: SimFactor,
    sharing: usize,
) -> Result<NonZeroU64, PolicyError> {
    let numerator = u128::from(budget_bytes) * 1000 * u128::from(percent.get());
    // A count of a collection's elements fits a u128 on every target.
    let denominator = u128::from(factor.permille()) * 100 * sharing as u128;
    // The factor is at least 1000 permille and the share at most 100
    // percent, so the quotient is at most `budget_bytes`, a u64: it fits.
    let bytes = (numerator / denominator) as u64;
    NonZeroU64::new(bytes).ok_or(PolicyError::AutomaticQuotaZero {
        budget_bytes,
        sharing,
    })
}

/// A user's quota: their own `UserPolicy::quota` (an override) wins,
/// whether larger or smaller; otherwise the `automatic` one
/// ([`automatic_quota`]), if any.
#[must_use]
pub const fn effective_quota(user: &User, automatic: Option<UserQuota>) -> Option<UserQuota> {
    match user.policy.quota {
        Some(own) => Some(own),
        None => automatic,
    }
}

/// The actions due for `deployment`'s users at `now`, given the cycle's
/// `usage`.
///
/// Only active users are evaluated, each against their
/// [`effective_quota`] (the automatic quota of the cycle `now` is in is
/// computed once, before any action). A suspended user gets no action,
/// including one whose suspension for quota has lapsed: resuming it at the
/// cycle boundary is the apply's step (M5), never this evaluation's.
/// A user gets at most one suspension: an expiry first, then a quota whose
/// action is `Suspend` (`QuotaExceeded{cycle_start}`, the start of the
/// cycle `now` is in). The apply records a proposed suspension with
/// `since` = `now` (design §13.6), so its instant lies in the cycle it
/// names. A user who is not suspended gets every warning that applies,
/// quota before expiry. Actions are in user order.
///
/// `usage` must be for the cycle `now` is in (`UsageForOtherCycle`) and
/// must not run past `now` (`UsageAfterNow`); every active user with a
/// quota, their own or the automatic one, needs a usage entry
/// (`UsageMissing`), and absent usage is never read as zero. With an
/// `AutoQuotaPolicy`, a suspension for quota made after `now` is
/// `QuotaSuspensionAfterNow` ([`automatic_quota`]).
pub fn evaluate(
    deployment: &Deployment,
    usage: &CycleUsage,
    now: UnixTime,
) -> Result<Vec<UserAction>, PolicyError> {
    let moment = Moment::of(deployment, now)?;
    if usage.cycle != moment.cycle {
        return Err(PolicyError::UsageForOtherCycle {
            usage_cycle: usage.cycle.start(),
            current_cycle: moment.cycle.start(),
        });
    }
    if usage.through > now {
        return Err(PolicyError::UsageAfterNow {
            through: usage.through,
            now,
        });
    }
    let automatic = cycle_quota(deployment, moment)?;
    let mut actions = Vec::new();
    for (id, user) in deployment.users() {
        if user.status != UserStatus::Active {
            continue;
        }
        let effective = effective_quota(user, automatic);
        let quota = match effective {
            None => QuotaState::NoQuota,
            Some(_) => {
                let used = *usage
                    .served
                    .get(id)
                    .ok_or_else(|| PolicyError::UsageMissing { user: id.clone() })?;
                QuotaState::of(effective, used)
            }
        };
        let suspend_on_quota = effective.is_some_and(|quota| quota.action == QuotaAction::Suspend);
        let expiry = ExpiryState::of(&user.policy, now);
        let suspension = match (expiry, quota) {
            (ExpiryState::Expired { .. }, _) => Some(SuspendReason::Expired),
            (_, QuotaState::Over { .. }) if suspend_on_quota => {
                Some(SuspendReason::QuotaExceeded {
                    cycle_start: moment.cycle.start(),
                })
            }
            _ => None,
        };
        if let Some(reason) = suspension {
            actions.push(UserAction {
                user: id.clone(),
                action: PolicyAction::Suspend(reason),
            });
            continue;
        }
        let quota_warning = match quota {
            QuotaState::Over {
                used_bytes,
                quota_bytes,
            } => Some(PolicyWarning::QuotaReached {
                used_bytes,
                quota_bytes,
            }),
            QuotaState::Warn {
                used_bytes,
                quota_bytes,
            } => Some(PolicyWarning::QuotaNear {
                used_bytes,
                quota_bytes,
            }),
            QuotaState::NoQuota
            | QuotaState::Within { .. }
            | QuotaState::UsageUnavailable { .. } => None,
        };
        let expiry_warning = match expiry {
            ExpiryState::Expires { at, .. }
                if at.as_secs() - now.as_secs() <= EXPIRY_WARNING_SECS =>
            {
                Some(PolicyWarning::ExpiresSoon { at })
            }
            _ => None,
        };
        for warning in [quota_warning, expiry_warning].into_iter().flatten() {
            actions.push(UserAction {
                user: id.clone(),
                action: PolicyAction::Warn(warning),
            });
        }
    }
    Ok(actions)
}

/// The aggregate user alerts (console spec B.4, critique C-12): counts
/// only, never which users. `actions` is [`evaluate`]'s output for
/// `users`; suspended users are counted from their status. A count of zero
/// raises nothing.
#[must_use]
pub fn user_alerts(users: &BTreeMap<UserId, User>, actions: &[UserAction]) -> Vec<AlertCondition> {
    let mut near = 0_u64;
    let mut over = 0_u64;
    let mut expiring = 0_u64;
    let mut expired = 0_u64;
    for action in actions {
        let counter = match action.action {
            PolicyAction::Warn(PolicyWarning::QuotaNear { .. }) => &mut near,
            PolicyAction::Warn(PolicyWarning::QuotaReached { .. })
            | PolicyAction::Suspend(SuspendReason::QuotaExceeded { .. }) => &mut over,
            PolicyAction::Warn(PolicyWarning::ExpiresSoon { .. }) => &mut expiring,
            PolicyAction::Suspend(SuspendReason::Expired) => &mut expired,
            // `evaluate` never proposes these reasons; they are operator
            // decisions.
            PolicyAction::Suspend(SuspendReason::Operator | SuspendReason::AbuseReview) => continue,
        };
        *counter += 1;
    }
    // A count of a collection's elements fits a u64 on every target.
    let suspended = users
        .values()
        .filter(|user| matches!(user.status, UserStatus::Suspended { .. }))
        .count() as u64;
    [
        (near, AlertCondition::UsersNearQuota { count: near }),
        (over, AlertCondition::UsersOverQuota { count: over }),
        (
            suspended,
            AlertCondition::UsersSuspended { count: suspended },
        ),
        (
            expiring,
            AlertCondition::UsersExpiringSoon { count: expiring },
        ),
        (expired, AlertCondition::UsersExpired { count: expired }),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(_, condition)| condition)
    .collect()
}
