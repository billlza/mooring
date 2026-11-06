// SPDX-License-Identifier: GPL-3.0-or-later

//! The user portal's gate on the user agreement (design §9.5).
//!
//! The portal keeps, on a host on the internet, what Mooring exports for
//! it: a snapshot of the status, usage, quota and expiry of the users the
//! operator names, and the CFM file, credentials included, of every user
//! Mooring serves, which the portal hands out by download and by
//! subscription link. The user agreement says where a user's data is kept
//! and how files reach users; revision 1 names neither the portal's host
//! (clause 4) nor a link (clauses 2 and 5). So nothing about a user may go
//! to the portal until a revision that covers it is written and the user
//! has accepted that revision.
//!
//! Both portal exporters take a [`PortalAgreement`] and refuse everything
//! while its [`PortalAgreement::required`] is an error. `mooringctl` passes
//! [`PortalAgreement::SHIPPED`], which opens only once
//! [`PORTAL_AGREEMENT_SINCE`] names a revision this build ships.

use crate::user::AgreementVersion;

/// The first revision of the user agreement whose text covers the portal:
/// clause 4 says what the portal's host keeps, where and for how long, and
/// clauses 2 and 5 how a subscription link is used and kept. `None` while
/// no revision does.
///
/// Writing that revision sets it, in the commit that raises
/// [`AgreementVersion::CURRENT`] and records the text's digest
/// (`crates/export/tests/export/agreement_text.rs`, which also requires the
/// text of a covering revision to name the portal).
pub const PORTAL_AGREEMENT_SINCE: Option<AgreementVersion> = None;

/// Whether this build may send anything about a user to the portal, and
/// which agreement revision the user must have accepted first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortalAgreement {
    since: Option<AgreementVersion>,
}

impl PortalAgreement {
    /// This build's gate: [`AgreementVersion::CURRENT`] against
    /// [`PORTAL_AGREEMENT_SINCE`]. Every product path passes it.
    pub const SHIPPED: Self = Self::since(PORTAL_AGREEMENT_SINCE);

    /// The gate of this build if `since` were the first revision covering
    /// the portal. The binary passes [`Self::SHIPPED`]; tests open the gate
    /// with `since(Some(AgreementVersion::CURRENT))` to run the exporters.
    #[must_use]
    pub const fn since(since: Option<AgreementVersion>) -> Self {
        Self { since }
    }

    /// The revision a user must have accepted before anything about them
    /// goes to the portal: [`AgreementVersion::CURRENT`], as for a user
    /// export (decision F9), once it is at or past the first revision that
    /// covers the portal. `PortalNotCovered` before that.
    pub const fn required(self) -> Result<AgreementVersion, PortalNotCovered> {
        let current = AgreementVersion::CURRENT;
        match self.since {
            Some(since) if since.get() <= current.get() => Ok(current),
            Some(_) | None => Err(PortalNotCovered { current }),
        }
    }
}

/// The agreement revision this build ships does not cover the portal, so
/// no portal export is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error(
    "agreement revision {current}, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links"
)]
pub struct PortalNotCovered {
    /// The revision this build ships.
    pub current: AgreementVersion,
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;

    fn revision(number: u16) -> AgreementVersion {
        AgreementVersion::new(NonZeroU16::new(number).unwrap())
    }

    /// The build's gate is the shipped revision against the constant, and
    /// the constant never names a revision the build does not ship yet.
    #[test]
    fn the_shipped_gate_is_the_current_revision_against_the_constant() {
        assert_eq!(
            PortalAgreement::SHIPPED,
            PortalAgreement::since(PORTAL_AGREEMENT_SINCE)
        );
        // Naming a revision opens the gate: the constant never names one the
        // build does not ship yet.
        assert_eq!(
            PortalAgreement::SHIPPED.required().is_ok(),
            PORTAL_AGREEMENT_SINCE.is_some()
        );
    }

    /// Covered from the first covering revision on, and only then; the
    /// revision required is always the one the build ships.
    #[test]
    fn the_gate_opens_at_the_first_revision_that_covers_the_portal() {
        let current = AgreementVersion::CURRENT;
        let closed = Err(PortalNotCovered { current });
        assert_eq!(PortalAgreement::since(None).required(), closed);
        assert_eq!(
            PortalAgreement::since(Some(current)).required(),
            Ok(current)
        );
        assert_eq!(
            PortalAgreement::since(Some(revision(current.get() + 1))).required(),
            closed
        );
        assert_eq!(PortalAgreement::SHIPPED.required(), closed);
    }

    #[test]
    fn the_refusal_names_the_shipped_revision() {
        assert_eq!(
            PortalNotCovered {
                current: revision(1)
            }
            .to_string(),
            "agreement revision 1, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links"
        );
    }
}
