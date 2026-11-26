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
//! acceptance that brings a served user under the guard is a configuration
//! change, never bookkeeping (`ModelError::AgreementStartsGuard`); one by a
//! user served nowhere changes no bundle
//! ([`AbuseGuardAgreement::acceptance_changes_bundles`]). `mooringctl`
//! passes [`AbuseGuardAgreement::SHIPPED`], which is open because
//! [`ABUSE_GUARD_SINCE`] names a revision this build ships.

use std::num::NonZeroU16;

use crate::user::{AgreementVersion, User};

/// The first revision of the user agreement whose text states the abuse
/// guard: clause 3 says what it limits, detects and cuts, and clause 4
/// which abuse records it keeps and for how long. Revision 2, set when the
/// guard was merged with the build that raised [`AgreementVersion::CURRENT`]
/// to it (`crates/export/tests/export/agreement_text.rs` requires the text
/// of a stating revision to name the abuse records, and only then). It
/// stays 2 when later revisions raise `CURRENT`, so a later revision never
/// takes a user who accepted revision 2 out of the guard.
pub const ABUSE_GUARD_SINCE: Option<AgreementVersion> = match NonZeroU16::new(2) {
    Some(revision) => Some(AgreementVersion::new(revision)),
    None => panic!("agreement revisions count from 1"),
};

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
    /// the guard. The binary passes [`Self::SHIPPED`]; tests close the gate
    /// with `since(None)`, as a build whose agreement does not state the
    /// guard has it.
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

    /// Whether recording `user`'s acceptance of `revision` changes a
    /// bundle: it brings under the guard a user whom some node serves, and
    /// the render then gives them their own source address. A user served
    /// nowhere, suspended (one added before their first payment included),
    /// is in no bundle, so their acceptance changes none, and the change
    /// that serves them again covers them. No acceptance takes a user out
    /// from under the guard, since a recorded revision never goes back.
    #[must_use]
    pub fn acceptance_changes_bundles(self, user: &User, revision: AgreementVersion) -> bool {
        user.is_served_anywhere() && !self.covers(user) && self.covers_revision(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::date::CalendarDate;
    use crate::testing::user;
    use crate::time::UnixTime;
    use crate::user::{AgreementRecord, SuspendReason};

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

    /// Revision 2 is the first that states the guard, and stays so: a
    /// later revision raises `CURRENT`, never the revision from which the
    /// guard covers a user. Revision 1 never brings a user under it.
    #[test]
    fn the_guard_covers_from_revision_2() {
        assert_eq!(ABUSE_GUARD_SINCE, Some(revision(2)));
        assert!(AbuseGuardAgreement::SHIPPED.covers_revision(AgreementVersion::CURRENT));
        assert!(!AbuseGuardAgreement::SHIPPED.covers_revision(AgreementVersion::FIRST));
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

    /// An acceptance changes a bundle only when it brings under the guard
    /// a user some node serves: not for a user served nowhere, suspended or
    /// holding no node, not for one covered already, not for a revision
    /// that states nothing, and never with the gate closed.
    #[test]
    fn only_a_served_users_acceptance_into_the_guard_changes_a_bundle() {
        let from_two = AbuseGuardAgreement::since(Some(revision(2)));
        let mut served = user(1, &[("lon1", 1)]);
        assert!(served.is_served_anywhere());
        assert!(from_two.acceptance_changes_bundles(&served, revision(2)));
        assert!(from_two.acceptance_changes_bundles(&served, revision(3)));
        assert!(!from_two.acceptance_changes_bundles(&served, revision(1)));
        assert!(!AbuseGuardAgreement::since(None).acceptance_changes_bundles(&served, revision(2)));
        let mut suspended = served.clone();
        suspended
            .suspend(SuspendReason::Expired, UnixTime::from_secs(0))
            .unwrap();
        assert!(!suspended.is_served_anywhere());
        assert!(!from_two.acceptance_changes_bundles(&suspended, revision(2)));
        let nowhere = user(2, &[]);
        assert!(!nowhere.is_served_anywhere());
        assert!(!from_two.acceptance_changes_bundles(&nowhere, revision(2)));
        served.agreement = Some(AgreementRecord {
            version: revision(2),
            accepted_on: CalendarDate::parse("2026-11-15").unwrap(),
        });
        assert!(!from_two.acceptance_changes_bundles(&served, revision(3)));
    }
}
