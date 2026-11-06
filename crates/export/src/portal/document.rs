// SPDX-License-Identifier: GPL-3.0-or-later

//! The bundle's document, contract `mooring-portal-cfm-profiles` version
//! 2: every key always present, in the contract's order, and none other.

use mooring_model::{UnixTime, UserId};
use serde::Serialize;

use super::Withheld;
use crate::tree::{Scalar, Tree};

/// What the document is, so that no other JSON is imported as a bundle.
pub(super) const FORMAT: &str = "mooring-portal-cfm-profiles";

/// The contract's version.
pub(super) const VERSION: u32 = 2;

/// The bundle: the users delivered, then the users withheld.
#[derive(Debug, Serialize)]
pub(super) struct BundleV2<'a> {
    pub(super) format: &'static str,
    pub(super) version: u32,
    pub(super) generated_at: UnixTime,
    pub(super) profiles: Vec<EntryV2<'a>>,
    pub(super) withheld: Vec<WithheldV2<'a>>,
}

/// A delivered user's entry: its id and its file's document.
#[derive(Debug, Serialize)]
pub(super) struct EntryV2<'a> {
    pub(super) user: &'a UserId,
    pub(super) document: Tree<Scalar>,
}

/// A withheld user's entry: its id and why, without a document.
#[derive(Debug, Serialize)]
pub(super) struct WithheldV2<'a> {
    pub(super) user: &'a UserId,
    pub(super) reason: ReasonV2,
}

/// Why a user is withheld, as the contract spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReasonV2 {
    /// Suspended, for whatever reason: the snapshot carries the reason.
    Suspended,
    /// Being revoked or revoked: as in the snapshot, both are `revoked`,
    /// since to the user both mean the service has ended.
    Revoked,
    /// Active, without an acceptance of the revision required.
    AgreementNotAccepted,
}

impl ReasonV2 {
    /// The contract's reason for `why`.
    pub(super) const fn of(why: Withheld) -> Self {
        match why {
            Withheld::Suspended => Self::Suspended,
            Withheld::BeingRevoked | Withheld::Revoked => Self::Revoked,
            Withheld::AgreementNotAccepted { .. } => Self::AgreementNotAccepted,
        }
    }
}

#[cfg(test)]
mod tests {
    use mooring_model::AgreementVersion;

    use super::*;

    /// Each reason is spelt as the contract spells it, and being revoked is
    /// `revoked`.
    #[test]
    fn each_reason_is_spelt_as_the_contract_spells_it() {
        let required = AgreementVersion::CURRENT;
        for (why, spelt) in [
            (Withheld::Suspended, "\"suspended\""),
            (Withheld::BeingRevoked, "\"revoked\""),
            (Withheld::Revoked, "\"revoked\""),
            (
                Withheld::AgreementNotAccepted {
                    recorded: None,
                    required,
                },
                "\"agreement_not_accepted\"",
            ),
            (
                Withheld::AgreementNotAccepted {
                    recorded: Some(required),
                    required,
                },
                "\"agreement_not_accepted\"",
            ),
        ] {
            assert_eq!(
                serde_json::to_string(&ReasonV2::of(why)).unwrap(),
                spelt,
                "{why:?}"
            );
        }
    }
}
