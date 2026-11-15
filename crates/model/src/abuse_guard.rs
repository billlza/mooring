// SPDX-License-Identifier: GPL-3.0-or-later

//! The abuse guard's gate on the user agreement (design §11.8).
//!
//! The guard limits each user's connections on a node, measures them from
//! connection features and cuts the user when they reach a cut level.
//! Revision 1 of the agreement says nothing of it, and a user on revision
//! 1 keeps their service without ever accepting a later one (the
//! operator's decision of 2026-11-15). So the guard covers only the users
//! who accepted a revision that states it, from the first such revision
//! ([`ABUSE_GUARD_SINCE`]) on ([`AbuseGuardAgreement::covers`]); every
//! other user leaves the node as before the guard, where it neither
//! measures, limits nor cuts them.
//!
//! The render takes an [`AbuseGuardAgreement`] and gives only the users it
//! covers their own source address, the one the guard sees. Which users it
//! covers is therefore part of every bundle that serves them, so an
//! acceptance that brings a user under the guard is a configuration change,
//! never bookkeeping (`ModelError::AgreementStartsGuard`). `mooringctl`
//! passes [`AbuseGuardAgreement::SHIPPED`].

use crate::user::{AgreementVersion, User};

/// The first revision of the user agreement whose text states the abuse
/// guard: clause 3 says what it limits, detects and cuts, and clause 4
/// which abuse records it keeps and for how long. `None` while no revision
/// this build ships does.
///
/// Writing that revision sets it, in the commit that raises
/// [`AgreementVersion::CURRENT`] and records the text's digest
/// (`crates/export/tests/export/agreement_text.rs`, which also requires the
/// text of a stating revision to name the abuse records, and only then).
pub const ABUSE_GUARD_SINCE: Option<AgreementVersion> = None;

/// Whether this build's abuse guard covers a user, by the agreement
/// revision the user accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AbuseGuardAgreement {
    since: Option<AgreementVersion>,
}

impl AbuseGuardAgreement {
    /// This build's gate, from [`ABUSE_GUARD_SINCE`]. Every product path
    /// passes it.
    pub const SHIPPED: Self = Self::since(ABUSE_GUARD_SINCE);

    /// The gate of this build if `since` were the first revision stating
    /// the guard. The binary passes [`Self::SHIPPED`]; tests open the gate
    /// with `since(Some(AgreementVersion::CURRENT))`.
    #[must_use]
    pub const fn since(since: Option<AgreementVersion>) -> Self {
        Self { since }
    }

    /// Whether an acceptance of `revision` brings a user under the guard:
    /// one at or after the first revision stating it. No revision does
    /// while none states it.
    #[must_use]
    pub fn covers_revision(self, revision: AgreementVersion) -> bool {
        self.since.is_some_and(|since| revision >= since)
    }

    /// Whether the guard covers `user`: the user's recorded acceptance is
    /// of a revision that brings them under it ([`Self::covers_revision`]).
    /// A user with no acceptance recorded is not covered.
    #[must_use]
    pub fn covers(self, user: &User) -> bool {
        user.agreement
            .is_some_and(|record| self.covers_revision(record.version))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;
    use crate::date::CalendarDate;
    use crate::testing::user;
    use crate::user::AgreementRecord;

    fn revision(number: u16) -> AgreementVersion {
        AgreementVersion::new(NonZeroU16::new(number).unwrap())
    }

    /// The build's gate is the constant's, and the constant never names a
    /// revision the build does not ship.
    #[test]
    fn the_shipped_gate_names_no_revision_the_build_does_not_ship() {
        assert_eq!(
            AbuseGuardAgreement::SHIPPED,
            AbuseGuardAgreement::since(ABUSE_GUARD_SINCE)
        );
        assert!(
            ABUSE_GUARD_SINCE.is_none_or(|since| since <= AgreementVersion::CURRENT),
            "{ABUSE_GUARD_SINCE:?}"
        );
    }

    /// An acceptance of the first stating revision or a later one covers a
    /// user; no acceptance and an earlier revision do not, and a closed
    /// gate covers no one.
    #[test]
    fn only_an_acceptance_of_a_stating_revision_covers_a_user() {
        let accepted = |version: Option<u16>| {
            let mut found = user(1, &[]);
            found.agreement = version.map(|number| AgreementRecord {
                version: revision(number),
                accepted_on: CalendarDate::parse("2026-11-15").unwrap(),
            });
            found
        };
        let from_two = AbuseGuardAgreement::since(Some(revision(2)));
        assert!(!from_two.covers(&accepted(None)));
        assert!(!from_two.covers(&accepted(Some(1))));
        assert!(from_two.covers(&accepted(Some(2))));
        assert!(from_two.covers(&accepted(Some(3))));
        assert!(!from_two.covers_revision(revision(1)));
        assert!(from_two.covers_revision(revision(2)));
        let closed = AbuseGuardAgreement::since(None);
        for version in [None, Some(1), Some(2), Some(3)] {
            assert!(!closed.covers(&accepted(version)), "{version:?}");
        }
        assert!(!closed.covers_revision(revision(1)));
    }
}
