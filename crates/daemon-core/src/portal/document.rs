// SPDX-License-Identifier: GPL-3.0-or-later

//! The snapshot document of contract version 1 (`docs/portal-contract.md`,
//! section 2), exactly as the portal reads it: every key always present,
//! `null` for what is unknown or absent, and no other key. These types are
//! that shape and nothing more. They are built from the model's values by
//! the mappings below, whose matches name every variant, so a new status,
//! reason or action needs a decision here, and the model's own serde
//! format never reaches the portal.

use std::num::NonZeroU64;

use mooring_model::{
    CalendarDate, QuotaAction, SuspendReason, UnixTime, UserId, UserQuota, UserStatus,
};
use serde::Serialize;

/// What the document is, so that no other JSON is imported as a snapshot.
pub(super) const FORMAT: &str = "mooring-portal-snapshot";

/// The contract's version.
pub(super) const VERSION: u32 = 1;

/// The document.
#[derive(Debug, Serialize)]
pub(super) struct SnapshotV1<'a> {
    pub(super) format: &'static str,
    pub(super) version: u32,
    pub(super) generated_at: UnixTime,
    pub(super) cycle: CycleV1,
    pub(super) counted_through: Option<UnixTime>,
    pub(super) users: Vec<UserV1<'a>>,
}

/// The SIM billing cycle on the UTC calendar.
#[derive(Debug, Serialize)]
pub(super) struct CycleV1 {
    pub(super) start: CalendarDate,
    pub(super) next_start: CalendarDate,
}

/// One user's record.
#[derive(Debug, Serialize)]
pub(super) struct UserV1<'a> {
    pub(super) user: &'a UserId,
    pub(super) status: StatusV1,
    pub(super) cycle_served_bytes: Option<u64>,
    pub(super) reality_downlink_counted_at_close: bool,
    pub(super) quota: Option<QuotaV1>,
    pub(super) expires_at: Option<UnixTime>,
}

/// `"active"`, `"revoked"` or `{"suspended": {"reason": …, "since": …}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StatusV1 {
    Active,
    Suspended { reason: ReasonV1, since: UnixTime },
    Revoked,
}

impl StatusV1 {
    /// A user being revoked is no longer served anywhere, so the portal
    /// shows it as revoked, as it shows one whose revocation is complete.
    pub(super) const fn of(status: UserStatus) -> Self {
        match status {
            UserStatus::Active => Self::Active,
            UserStatus::Suspended { reason, since } => Self::Suspended {
                reason: ReasonV1::of(reason),
                since,
            },
            UserStatus::RevokePending | UserStatus::Revoked => Self::Revoked,
        }
    }
}

/// Why a user is suspended. A suspension for quota leaves out the cycle it
/// names: the portal tells whether it holds from `since`, as Mooring does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReasonV1 {
    Operator,
    QuotaExceeded,
    Expired,
    AbuseReview,
}

impl ReasonV1 {
    const fn of(reason: SuspendReason) -> Self {
        match reason {
            SuspendReason::Operator => Self::Operator,
            SuspendReason::QuotaExceeded { .. } => Self::QuotaExceeded,
            SuspendReason::Expired => Self::Expired,
            SuspendReason::AbuseReview => Self::AbuseReview,
        }
    }
}

/// A user's effective quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) struct QuotaV1 {
    cycle_served_bytes: NonZeroU64,
    warn_percent: u8,
    action: ActionV1,
}

impl QuotaV1 {
    pub(super) const fn of(quota: UserQuota) -> Self {
        Self {
            cycle_served_bytes: quota.cycle_served_bytes,
            warn_percent: quota.warn_percent.get(),
            action: ActionV1::of(quota.action),
        }
    }
}

/// What reaching the quota does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ActionV1 {
    Warn,
    Suspend,
}

impl ActionV1 {
    const fn of(action: QuotaAction) -> Self {
        match action {
            QuotaAction::Warn => Self::Warn,
            QuotaAction::Suspend => Self::Suspend,
        }
    }
}
