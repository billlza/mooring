// SPDX-License-Identifier: GPL-3.0-or-later

//! Removing revoked users (design §15.3, §15.7; the agreement's clause 4).
//!
//! A revoked user's records on the Mac go 13 calendar months after it was
//! revoked ([`removal_due`]), or at once when the user asks (`user
//! forget`). Either way the deployment drops the user by the bookkeeping
//! record `RevokedUserRemoved`, with its label, alias, policy and agreement
//! record, and the daemon then deletes what its own files hold of it (its
//! usage history and payment records).
//!
//! The nodes' records of a user expire on their own schedule (§11.5), and
//! until they have, a node's reply can still name the user. So the
//! deployment keeps the removed user's bare opaque id, and nothing else,
//! until then ([`ForgottenUser`]); the Mac drops a node's entries naming it
//! on receipt instead of refusing them as an unknown user's. A removal 13
//! months on keeps none: by then no node holds anything of the user.

use serde::{Deserialize, Serialize};

use crate::date::{CalendarDate, days_in_month};
use crate::deployment::DeploymentParts;
use crate::error::ModelError;
use crate::ids::UserId;
use crate::time::UnixTime;
use crate::user::UserStatus;

/// How many calendar months after a user's revocation its records on the
/// Mac are removed (decision F7, the agreement's clause 4).
pub const REVOKED_RETENTION_MONTHS: u32 = 13;

/// How many days a node keeps a month's usage totals after the month ends
/// (design §11.5); the Mac asks for the month before during as many days
/// of the next.
pub const NODE_MONTH_TOTALS_DAYS: u32 = 7;

/// The instant `months` calendar months after `at`, at the same time of
/// day: the same day of the month, or the month's last day when it is
/// shorter (31 January and one month is 28 or 29 February). `InvalidDate`
/// past 9999-12-31.
pub fn months_after(at: UnixTime, months: u32) -> Result<UnixTime, ModelError> {
    let date = CalendarDate::utc_of(at)?;
    let ordinal = u32::from(date.year()) * 12 + u32::from(date.month() - 1) + months;
    let year = u16::try_from(ordinal / 12).map_err(|_| ModelError::InvalidDate)?;
    // A remainder of 12 is below 12, so the month fits a u8.
    let month = (ordinal % 12 + 1) as u8;
    let day = date.day().min(days_in_month(year, month));
    let start = CalendarDate::new(year, month, day)?.utc_start();
    start
        .checked_add_secs(at.as_secs() % 86_400)
        .ok_or(ModelError::InvalidDate)
}

/// When a user revoked at `revoked` is due for removal: 13 calendar months
/// later ([`REVOKED_RETENTION_MONTHS`]). A removal is due at that instant,
/// and not a second before.
pub fn removal_due(revoked: UnixTime) -> Result<UnixTime, ModelError> {
    months_after(revoked, REVOKED_RETENTION_MONTHS)
}

/// What the Mac keeps of a user removed from the deployment while a node's
/// records may still name it: the bare opaque id, and nothing else, until
/// those records have expired. Until then the Mac drops a node's entries
/// naming the id on receipt, where an unknown user's are refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgottenUser {
    /// The removed user's opaque id.
    pub user: UserId,
    /// When the nodes' records naming it have expired
    /// ([`ForgottenUser::records_until`]).
    pub until: UnixTime,
}

impl ForgottenUser {
    /// When the records a node may hold of a user revoked at `revoked`
    /// have expired, with a day to spare for a pull in flight: a revoked
    /// user is served by no node, so a node last counted it in the month of
    /// its revocation, or earlier; it keeps its five-minute bins 48 hours
    /// and that month's totals until [`NODE_MONTH_TOTALS_DAYS`] after the
    /// month (design §11.5). So the first instant of the next month, plus
    /// those days and one more. A revocation in the calendar's last month
    /// has no such instant (`InvalidDate`).
    pub fn records_until(revoked: UnixTime) -> Result<UnixTime, ModelError> {
        let date = CalendarDate::utc_of(revoked)?;
        let month_days = days_in_month(date.year(), date.month());
        Ok(date
            .first_of_month()
            .checked_add_days(u32::from(month_days) + NODE_MONTH_TOTALS_DAYS + 1)?
            .utc_start())
    }
}

/// Removes the revoked `user` at `at` (`RevokedUserRemoved`): its bare id
/// stays while a node's records may still name it, and the ids whose
/// records have expired by `at` go. `UnknownUser` for an id the
/// deployment does not hold, `UserNotRevoked` for a user that is not
/// revoked; nothing changes then.
pub(crate) fn remove_revoked(
    parts: &mut DeploymentParts,
    user: &UserId,
    at: UnixTime,
) -> Result<(), ModelError> {
    let index = parts
        .users
        .iter()
        .position(|candidate| candidate.id == *user)
        .ok_or_else(|| ModelError::UnknownUser { id: user.clone() })?;
    let UserStatus::Revoked { since } = parts.users[index].status else {
        return Err(ModelError::UserNotRevoked { user: user.clone() });
    };
    let until = ForgottenUser::records_until(since)?;
    parts.users.remove(index);
    expire_forgotten(parts, at);
    if until > at {
        parts.forgotten.push(ForgottenUser {
            user: user.clone(),
            until,
        });
    }
    Ok(())
}

/// Drops every forgotten id whose nodes' records have expired by `at`
/// (`ForgottenExpired`); the others stay.
pub(crate) fn expire_forgotten(parts: &mut DeploymentParts, at: UnixTime) {
    parts.forgotten.retain(|kept| kept.until > at);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::{Bookkeeping, Deployment};
    use crate::error::EntityId;
    use crate::ids::{LocalLabel, PublicAlias};
    use crate::testing::{two_node_parts, user_id};
    use crate::user::{AgreementRecord, AgreementVersion, SuspendReason};

    fn at(text: &str) -> UnixTime {
        let (date, time) = text.split_once(' ').unwrap();
        let (hours, minutes) = time.split_once(':').unwrap();
        let hours: u64 = hours.parse().unwrap();
        let minutes: u64 = minutes.parse().unwrap();
        UnixTime::from_secs(
            CalendarDate::parse(date).unwrap().utc_start().as_secs() + hours * 3600 + minutes * 60,
        )
    }

    /// Two nodes, user 1 active on both, user 2 revoked at `revoked` with
    /// an alias and an agreement record.
    fn with_revoked(revoked: UnixTime) -> Deployment {
        let mut parts = two_node_parts();
        let user = &mut parts.users[1];
        user.per_node.clear();
        user.status = UserStatus::Revoked { since: revoked };
        user.alias = Some(PublicAlias::parse("k7qd-m2xa").unwrap());
        user.agreement = Some(AgreementRecord {
            version: AgreementVersion::CURRENT,
            accepted_on: CalendarDate::parse("2026-10-08").unwrap(),
        });
        Deployment::try_from(parts).unwrap()
    }

    fn remove(deployment: &Deployment, user: u64, now: UnixTime) -> Result<Deployment, ModelError> {
        deployment.clone().record(Bookkeeping::RevokedUserRemoved {
            user: user_id(user),
            at: now,
        })
    }

    /// Thirteen calendar months, at the same time of day: the boundary is
    /// that instant, and a month without the day ends on its last day.
    #[test]
    fn thirteen_months_after_a_revocation_is_the_same_time_thirteen_months_on() {
        for (revoked, due) in [
            ("2026-10-13 19:20", "2027-11-13 19:20"),
            ("2026-01-31 23:59", "2027-02-28 23:59"),
            ("2027-01-31 08:00", "2028-02-29 08:00"),
            ("2026-12-01 00:00", "2028-01-01 00:00"),
            ("2026-11-30 12:00", "2027-12-30 12:00"),
        ] {
            assert_eq!(removal_due(at(revoked)).unwrap(), at(due), "{revoked}");
        }
        assert_eq!(REVOKED_RETENTION_MONTHS, 13);
        assert_eq!(
            months_after(at("2026-10-13 19:20"), 0).unwrap(),
            at("2026-10-13 19:20")
        );
        assert_eq!(
            months_after(at("9999-01-01 00:00"), 12),
            Err(ModelError::InvalidDate)
        );
        assert_eq!(
            removal_due(at("9998-12-31 00:00")),
            Err(ModelError::InvalidDate)
        );
    }

    /// A node may name a user revoked in a month until 7 days after the
    /// month, and a day more for a pull in flight.
    #[test]
    fn the_nodes_records_of_a_revoked_user_expire_eight_days_into_the_next_month() {
        for (revoked, until) in [
            ("2026-10-31 23:59", "2026-11-09 00:00"),
            ("2026-10-01 00:00", "2026-11-09 00:00"),
            ("2026-12-15 12:00", "2027-01-09 00:00"),
            ("2028-02-29 06:00", "2028-03-09 00:00"),
        ] {
            assert_eq!(
                ForgottenUser::records_until(at(revoked)).unwrap(),
                at(until),
                "{revoked}"
            );
        }
        assert_eq!(
            ForgottenUser::records_until(at("9999-12-01 00:00")),
            Err(ModelError::InvalidDate)
        );
    }

    /// The removal drops the user with every record the state holds of it
    /// and keeps the generation; while a node may still name it, its bare
    /// id stays, and nothing else of it.
    #[test]
    fn a_revoked_user_is_removed_with_its_records_and_its_bare_id_kept() {
        let revoked = at("2026-10-20 10:00");
        let deployment = with_revoked(revoked);
        let removed = remove(&deployment, 2, at("2026-10-21 09:00")).unwrap();
        assert!(!removed.users().contains_key(&user_id(2)));
        assert_eq!(removed.users().len(), 1);
        assert_eq!(
            removed.forgotten(),
            &[(user_id(2), at("2026-11-09 00:00"))].into_iter().collect()
        );
        assert_eq!(removed.config_generation(), deployment.config_generation());
        let json = serde_json::to_string(&removed).unwrap();
        assert!(!json.contains("k7qd-m2xa"), "the alias is gone: {json}");
        assert!(
            !json.contains("2026-10-08"),
            "the agreement record is gone: {json}"
        );
        let kept = format!(
            r#""forgotten":[{{"user":"{}","until":{}}}],"next_wg_index""#,
            user_id(2),
            at("2026-11-09 00:00").as_secs()
        );
        assert!(json.contains(&kept), "{json}");
        assert_eq!(serde_json::from_str::<Deployment>(&json).unwrap(), removed);
        assert_eq!(
            Deployment::try_from(removed.clone().into_parts()).unwrap(),
            removed
        );
        // The label of user 1 stays.
        assert_eq!(
            removed.users()[&user_id(1)].label,
            deployment.users()[&user_id(1)].label
        );
    }

    /// Thirteen months on, no node holds anything of the user, so no id is
    /// kept; at the very instant its records expire, none either.
    #[test]
    fn a_removal_after_the_nodes_records_expired_keeps_no_id() {
        let revoked = at("2026-10-20 10:00");
        let deployment = with_revoked(revoked);
        let late = remove(&deployment, 2, removal_due(revoked).unwrap()).unwrap();
        assert!(late.forgotten().is_empty());
        let edge = remove(&deployment, 2, at("2026-11-09 00:00")).unwrap();
        assert!(edge.forgotten().is_empty(), "records expire at the instant");
        let before = remove(&deployment, 2, at("2026-11-08 23:59")).unwrap();
        assert_eq!(before.forgotten().len(), 1);
    }

    /// Only a revoked user is removed; an unknown id and every other status
    /// are refused, and nothing changes.
    #[test]
    fn only_a_revoked_user_is_removed() {
        let deployment = with_revoked(at("2026-10-20 10:00"));
        let now = at("2026-10-21 09:00");
        assert_eq!(
            remove(&deployment, 1, now),
            Err(ModelError::UserNotRevoked { user: user_id(1) })
        );
        assert_eq!(
            remove(&deployment, 9, now),
            Err(ModelError::UnknownUser { id: user_id(9) })
        );
        for status in [
            UserStatus::Suspended {
                reason: SuspendReason::QuotaExceeded {
                    cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
                },
                since: now,
            },
            UserStatus::Suspended {
                reason: SuspendReason::AbuseReview,
                since: now,
            },
            UserStatus::RevokePending,
        ] {
            let mut parts = deployment.clone().into_parts();
            parts.users[0].status = status;
            let other = Deployment::try_from(parts).unwrap();
            assert_eq!(
                remove(&other, 1, now),
                Err(ModelError::UserNotRevoked { user: user_id(1) }),
                "{status:?}"
            );
        }
        // Removed once, the user is unknown.
        let removed = remove(&deployment, 2, now).unwrap();
        assert_eq!(
            remove(&removed, 2, now),
            Err(ModelError::UnknownUser { id: user_id(2) })
        );
    }

    /// A kept id goes once its records have expired, by the next removal or
    /// by `ForgottenExpired`, at the instant and not before; the others
    /// stay.
    #[test]
    fn a_kept_id_goes_once_the_nodes_records_have_expired() {
        let revoked = at("2026-10-20 10:00");
        let removed = remove(&with_revoked(revoked), 2, at("2026-10-21 09:00")).unwrap();
        let expire = |deployment: &Deployment, now: &str| {
            deployment
                .clone()
                .record(Bookkeeping::ForgottenExpired { at: at(now) })
                .unwrap()
        };
        assert_eq!(expire(&removed, "2026-11-08 23:59").forgotten().len(), 1);
        assert!(expire(&removed, "2026-11-09 00:00").forgotten().is_empty());
        assert_eq!(
            expire(&removed, "2026-11-09 00:00").config_generation(),
            removed.config_generation()
        );
        // Nothing to expire changes nothing.
        let none = expire(&with_revoked(revoked), "2026-11-10 00:00");
        assert_eq!(none, with_revoked(revoked));
        // A later removal drops the expired id and keeps its own.
        let mut parts = removed.clone().into_parts();
        parts.users[0].per_node.clear();
        parts.users[0].status = UserStatus::Revoked {
            since: at("2026-11-08 12:00"),
        };
        let second = Deployment::try_from(parts).unwrap();
        let both = remove(&second, 1, at("2026-11-08 13:00")).unwrap();
        assert_eq!(both.forgotten().len(), 2);
        let next = remove(&second, 1, at("2026-11-09 00:00")).unwrap();
        assert_eq!(
            next.forgotten(),
            &[(user_id(1), at("2026-12-09 00:00"))].into_iter().collect(),
            "the first id's records expired at the removal"
        );
    }

    /// A kept id is never a user's, and each is kept once.
    #[test]
    fn a_kept_id_is_unique_and_never_a_users() {
        let removed = remove(
            &with_revoked(at("2026-10-20 10:00")),
            2,
            at("2026-10-21 09:00"),
        )
        .unwrap();
        let mut parts = removed.clone().into_parts();
        let mut again = two_node_parts().users[1].clone();
        again.label = LocalLabel::parse("Someone").unwrap();
        parts.users.push(again);
        assert_eq!(
            Deployment::try_from(parts),
            Err(ModelError::DuplicateId {
                id: EntityId::User(user_id(2))
            })
        );
        let mut parts = removed.into_parts();
        parts.forgotten.push(parts.forgotten[0].clone());
        assert_eq!(
            Deployment::try_from(parts),
            Err(ModelError::DuplicateId {
                id: EntityId::User(user_id(2))
            })
        );
    }
}
