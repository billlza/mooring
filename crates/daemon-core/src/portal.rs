// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal snapshot (design §9.5; contract `mooring-portal-snapshot`
//! version 1, `docs/portal-contract.md`): for each user the operator
//! names, what the portal shows that user about their service, as the
//! console would show it at the same instant.
//!
//! # What it holds
//!
//! The snapshot's time; the billing cycle; how far the usage was counted;
//! and per user its id, status, bytes served this cycle, whether its
//! REALITY downlink is counted only when connections close, its effective
//! quota and its expiry. The figures come from the same functions the
//! status line uses ([`crate::snapshot::assemble`]): the usage report's
//! [`UserUsage::cycle_served_bytes`](crate::usage::UserUsage::cycle_served_bytes),
//! [`UsageAccuracy::of`], [`effective_quota`] with the automatic quota of
//! the snapshot's time, and the user's `UserPolicy::expires_at`.
//!
//! # What it leaves out
//!
//! Everything else, by construction (the document's types have no field
//! for it): labels, aliases, credentials, short ids, nodes, addresses, the
//! other periods' figures, and the users not named. A usage figure that is
//! unknown is `null`, never 0; without a usage report every figure is
//! `null` and so is `counted_through`.
//!
//! # The agreement
//!
//! A snapshot is made only while the agreement revision the build ships
//! covers the portal ([`PortalAgreement`]), and only of users who accepted
//! that revision; anything else is refused before anything is encoded.

mod document;
mod error;

use std::collections::BTreeMap;
use std::fmt;

use mooring_model::{
    AgreementVersion, CalendarDate, Deployment, PortalAgreement, RecordedAgreement, UnixTime, User,
    UserId, UserStatus,
};

use crate::period::BillingCycle;
use crate::policy::{automatic_quota, effective_quota};
use crate::usage::{UsageAccuracy, UsageReport};

use self::document::{CycleV1, FORMAT, QuotaV1, SnapshotV1, StatusV1, UserV1, VERSION};
pub use self::error::{PortalError, PortalErrorKind};

/// The most bytes of a snapshot the portal reads.
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;

/// An encoded snapshot: pretty-printed JSON ending with one newline. It
/// holds no secret; its `Debug` output gives the size, not the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct PortalSnapshot {
    bytes: Vec<u8>,
    users: usize,
    cycle: BillingCycle,
    counted_through: Option<UnixTime>,
}

impl fmt::Debug for PortalSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortalSnapshot")
            .field("len", &self.bytes.len())
            .field("users", &self.users)
            .field("cycle", &self.cycle)
            .field("counted_through", &self.counted_through)
            .finish()
    }
}

impl PortalSnapshot {
    /// The file's contents.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many users it holds.
    #[must_use]
    pub const fn users(&self) -> usize {
        self.users
    }

    /// The billing cycle its usage belongs to.
    #[must_use]
    pub const fn cycle(&self) -> BillingCycle {
        self.cycle
    }

    /// The end of its usage report's periods, `None` without a report.
    #[must_use]
    pub const fn counted_through(&self) -> Option<UnixTime> {
        self.counted_through
    }
}

/// The snapshot of `users` made at `generated_at`, with `report`'s usage.
///
/// Refused, in this order, while `agreement` does not cover the portal
/// (`NotCovered`); when no user is named; when `generated_at` is past
/// 9999-12-31; when a user is unknown, has not accepted the revision
/// required or is named twice; when the report runs past `generated_at`
/// or ends outside its own cycle; when the automatic quota cannot be
/// evaluated; and for a user suspended after `generated_at`, expiring past
/// 9999-12-31 or missing from the report. The users appear in id order.
///
/// `report` is the deployment's usage report, `None` when Mooring has none
/// (every figure is then `null`). The cycle is the report's, or else the
/// one `generated_at` is in. `counted_through` is the report's
/// `UsagePeriods::through`, the instant its figures are reported as of;
/// each node's figures come from its latest accounting sample, which may
/// be up to the report's freshness bound older.
pub fn snapshot(
    deployment: &Deployment,
    report: Option<&UsageReport>,
    users: &[UserId],
    generated_at: UnixTime,
    agreement: PortalAgreement,
) -> Result<PortalSnapshot, PortalError> {
    bounded(
        deployment,
        report,
        users,
        generated_at,
        agreement,
        MAX_SNAPSHOT_BYTES,
    )
}

/// [`snapshot`] refused past `limit` bytes: one function, so the tests reach
/// the bound on the path every snapshot takes.
fn bounded(
    deployment: &Deployment,
    report: Option<&UsageReport>,
    users: &[UserId],
    generated_at: UnixTime,
    agreement: PortalAgreement,
    limit: usize,
) -> Result<PortalSnapshot, PortalError> {
    let required = agreement.required()?;
    if users.is_empty() {
        return Err(PortalError::NoUsers);
    }
    if CalendarDate::utc_of(generated_at).is_err() {
        return Err(PortalError::GeneratedOutOfRange { at: generated_at });
    }
    let selected = selected(deployment, users, required)?;
    let (cycle, counted_through) = match report {
        Some(report) => {
            let periods = report.periods;
            if periods.through > generated_at {
                return Err(PortalError::ReportAfterGeneration {
                    through: periods.through,
                    generated_at,
                });
            }
            let cycle = periods.cycle;
            if periods.through < cycle.starts_at() || periods.through > cycle.ends_at() {
                return Err(PortalError::ReportOutsideCycle {
                    through: periods.through,
                });
            }
            (cycle, Some(periods.through))
        }
        None => (
            BillingCycle::of_instant(deployment.exit().sim.cycle(), generated_at)
                .map_err(PortalError::Cycle)?,
            None,
        ),
    };
    let automatic = automatic_quota(deployment, generated_at).map_err(PortalError::Quota)?;
    let mut records = Vec::with_capacity(selected.len());
    for (id, user) in selected {
        if let UserStatus::Suspended { since, .. } = user.status
            && since > generated_at
        {
            return Err(PortalError::SuspendedAfterGeneration {
                user: id.clone(),
                since,
                generated_at,
            });
        }
        if let Some(at) = user.policy.expires_at
            && CalendarDate::utc_of(at).is_err()
        {
            return Err(PortalError::ExpiryOutOfRange {
                user: id.clone(),
                at,
            });
        }
        let cycle_served_bytes = match report {
            Some(report) => report
                .users
                .get(id)
                .ok_or_else(|| PortalError::RowMissing { user: id.clone() })?
                .cycle_served_bytes(),
            None => None,
        };
        records.push(UserV1 {
            user: id,
            status: StatusV1::of(user.status),
            cycle_served_bytes,
            reality_downlink_counted_at_close: UsageAccuracy::of(user)
                .reality_downlink_counted_at_close,
            quota: effective_quota(user, automatic).map(QuotaV1::of),
            expires_at: user.policy.expires_at,
        });
    }
    let count = records.len();
    let document = SnapshotV1 {
        format: FORMAT,
        version: VERSION,
        generated_at,
        cycle: CycleV1 {
            start: cycle.start(),
            next_start: cycle.next_start(),
        },
        counted_through,
        users: records,
    };
    let mut bytes = serde_json::to_vec_pretty(&document).map_err(PortalError::Encode)?;
    bytes.push(b'\n');
    fits(bytes.len(), limit)?;
    Ok(PortalSnapshot {
        bytes,
        users: count,
        cycle,
        counted_through,
    })
}

/// The named users, in id order, each known and with an acceptance of
/// `required`, none named twice.
fn selected<'a>(
    deployment: &'a Deployment,
    users: &[UserId],
    required: AgreementVersion,
) -> Result<BTreeMap<&'a UserId, &'a User>, PortalError> {
    let mut selected = BTreeMap::new();
    for id in users {
        let (id, user) = deployment
            .users()
            .get_key_value(id)
            .ok_or_else(|| PortalError::UnknownUser { user: id.clone() })?;
        user.accepted(required)
            .map_err(
                |RecordedAgreement(recorded)| PortalError::AgreementNotAccepted {
                    user: id.clone(),
                    recorded,
                    required,
                },
            )?;
        if selected.insert(id, user).is_some() {
            return Err(PortalError::DuplicateUser { user: id.clone() });
        }
    }
    Ok(selected)
}

/// `TooLarge` when a snapshot of `bytes` is more than `limit`.
const fn fits(bytes: usize, limit: usize) -> Result<(), PortalError> {
    if bytes > limit {
        return Err(PortalError::TooLarge { bytes, limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mooring_fixtures::{FIXTURE_NOW, two_nodes_three_users};
    use mooring_model::{AgreementVersion, PortalAgreement, UserId};

    use super::{MAX_SNAPSHOT_BYTES, PortalError, bounded};

    /// The bound counts every byte written, the last newline included, and
    /// refuses only what is past it.
    #[test]
    fn the_size_bound_counts_every_byte_and_refuses_only_what_is_past_it() {
        let fixture = two_nodes_three_users().unwrap();
        let users: Vec<UserId> = fixture.deployment.users().keys().cloned().collect();
        let open = PortalAgreement::since(Some(AgreementVersion::CURRENT));
        let make = |limit| bounded(&fixture.deployment, None, &users, FIXTURE_NOW, open, limit);
        let len = make(MAX_SNAPSHOT_BYTES).unwrap().bytes().len();
        assert!(make(len).is_ok());
        assert!(
            matches!(make(len - 1), Err(PortalError::TooLarge { bytes, limit }) if bytes == len && limit == len - 1)
        );
    }
}
