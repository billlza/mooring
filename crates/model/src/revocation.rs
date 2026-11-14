// SPDX-License-Identifier: GPL-3.0-or-later

//! Revoking a user whose service expired and was not renewed (design
//! §13.6; the agreement's clause 6 from revision 2): a user suspended at
//! expiry is revoked three calendar months after its service expired
//! ([`revocation_due`]), by the apply job, and its records then go 13
//! months later, as every revoked user's do (clause 4, [`crate::removal`]).
//!
//! The rule needs the user's word. Revision 1 of the agreement, which users
//! accepted until revision 2, says that an expired service stays suspended
//! until the operator resumes it, and promises no revocation for it. So the
//! rule waits for a revision whose clause 6 states it
//! ([`EXPIRY_REVOCATION_SINCE`]) and for the user's acceptance of that
//! revision ([`ExpiryRevocation::covers`]); a user it does not cover is
//! reported to the operator instead, who decides.

use crate::error::ModelError;
use crate::removal::months_after;
use crate::time::UnixTime;
use crate::user::{AgreementVersion, User};

/// How many calendar months after a user's service expired, unrenewed, the
/// user is revoked (the agreement's clause 6 from revision 2: 「服务到期 3
/// 个月后仍未续费，运营者会作废你的账户」).
pub const EXPIRED_REVOCATION_MONTHS: u32 = 3;

/// When a user whose service expired at `expired` is due for revocation:
/// three calendar months later ([`EXPIRED_REVOCATION_MONTHS`]), at the same
/// time of day, on the same day of the month or the month's last when it is
/// shorter, as for the 13-month removal ([`months_after`]). Due at that
/// instant, and not a second before. `InvalidDate` past 9999-12-31.
pub fn revocation_due(expired: UnixTime) -> Result<UnixTime, ModelError> {
    months_after(expired, EXPIRED_REVOCATION_MONTHS)
}

/// The first revision of the user agreement whose clause 6 says that a
/// service expired three months before and not renewed ends in revocation.
/// `None` while no revision this build ships says so.
///
/// Writing that revision sets it, in the commit that raises
/// [`AgreementVersion::CURRENT`] and records the text's digest
/// (`crates/export/tests/export/agreement_text.rs`, which also requires the
/// text to state the three months exactly while the gate is open).
pub const EXPIRY_REVOCATION_SINCE: Option<AgreementVersion> = None;

/// Whether this build revokes a user three months after its expiry, and
/// which agreement revision the user must have accepted first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExpiryRevocation {
    since: Option<AgreementVersion>,
}

impl ExpiryRevocation {
    /// This build's gate, from [`EXPIRY_REVOCATION_SINCE`]. Every product
    /// path passes it.
    pub const SHIPPED: Self = Self::since(EXPIRY_REVOCATION_SINCE);

    /// The gate of this build if `since` were the first revision providing
    /// for the revocation. The binary passes [`Self::SHIPPED`]; tests open
    /// the gate with `since(Some(AgreementVersion::CURRENT))`.
    #[must_use]
    pub const fn since(since: Option<AgreementVersion>) -> Self {
        Self { since }
    }

    /// Whether `user` accepted a revision that provides for revoking it
    /// three months after its expiry: one at or after the first that does.
    /// A user with no acceptance recorded, or one of an earlier revision,
    /// is not covered, and neither is anyone while no revision provides for
    /// it.
    #[must_use]
    pub fn covers(self, user: &User) -> bool {
        match (self.since, user.agreement) {
            (Some(since), Some(record)) => record.version >= since,
            (Some(_) | None, _) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;
    use crate::date::CalendarDate;
    use crate::testing::user;
    use crate::user::AgreementRecord;

    fn at(text: &str) -> UnixTime {
        let (date, time) = text.split_once(' ').unwrap();
        let (hours, minutes) = time.split_once(':').unwrap();
        let hours: u64 = hours.parse().unwrap();
        let minutes: u64 = minutes.parse().unwrap();
        UnixTime::from_secs(
            CalendarDate::parse(date).unwrap().utc_start().as_secs() + hours * 3600 + minutes * 60,
        )
    }

    fn revision(number: u16) -> AgreementVersion {
        AgreementVersion::new(NonZeroU16::new(number).unwrap())
    }

    /// Three calendar months, at the same time of day: the boundary is that
    /// instant, and a month without the day ends on its last day.
    #[test]
    fn three_months_after_an_expiry_is_the_same_time_three_months_on() {
        for (expired, due) in [
            ("2026-10-13 19:20", "2027-01-13 19:20"),
            ("2026-11-30 12:00", "2027-02-28 12:00"),
            ("2027-11-30 12:00", "2028-02-29 12:00"),
            ("2026-08-31 23:59", "2026-11-30 23:59"),
            ("2026-12-01 00:00", "2027-03-01 00:00"),
        ] {
            assert_eq!(revocation_due(at(expired)).unwrap(), at(due), "{expired}");
        }
        assert_eq!(EXPIRED_REVOCATION_MONTHS, 3);
        assert_eq!(
            revocation_due(at("9999-10-01 00:00")),
            Err(ModelError::InvalidDate)
        );
    }

    /// The build's gate never names a revision the build does not ship,
    /// and opens only with one.
    #[test]
    fn the_shipped_gate_names_no_revision_the_build_does_not_ship() {
        assert_eq!(
            ExpiryRevocation::SHIPPED,
            ExpiryRevocation::since(EXPIRY_REVOCATION_SINCE)
        );
        assert!(
            EXPIRY_REVOCATION_SINCE.is_none_or(|since| since <= AgreementVersion::CURRENT),
            "{EXPIRY_REVOCATION_SINCE:?}"
        );
    }

    /// A user is covered by an acceptance of the first providing revision
    /// or a later one; no acceptance, an earlier revision, and a closed
    /// gate cover no one.
    #[test]
    fn only_an_acceptance_of_a_providing_revision_covers_a_user() {
        let accepted = |version: Option<u16>| {
            let mut found = user(1, &[]);
            found.agreement = version.map(|number| AgreementRecord {
                version: revision(number),
                accepted_on: CalendarDate::parse("2026-11-12").unwrap(),
            });
            found
        };
        let from_two = ExpiryRevocation::since(Some(revision(2)));
        assert!(!from_two.covers(&accepted(None)));
        assert!(!from_two.covers(&accepted(Some(1))));
        assert!(from_two.covers(&accepted(Some(2))));
        assert!(from_two.covers(&accepted(Some(3))));
        let closed = ExpiryRevocation::since(None);
        for version in [None, Some(1), Some(2), Some(3)] {
            assert!(!closed.covers(&accepted(version)), "{version:?}");
        }
    }
}
