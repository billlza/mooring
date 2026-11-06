// SPDX-License-Identifier: GPL-3.0-or-later

//! Why no portal snapshot was made ([`super::snapshot`]). Each error names
//! users by id only, never by label or alias.

use mooring_model::kinds;
use mooring_model::{
    AgreementVersion, ModelError, PortalNotCovered, RecordedAgreement, UnixTime, UserId,
};

use crate::error::PolicyError;

/// A portal snapshot could not be made; nothing was encoded.
#[derive(Debug, thiserror::Error)]
pub enum PortalError {
    /// The agreement revision this build ships does not cover the portal.
    #[error(transparent)]
    NotCovered(#[from] PortalNotCovered),
    /// No user was named: a snapshot holds only the users the operator
    /// names, never every user by default.
    #[error("no user was named; a snapshot holds only the users named")]
    NoUsers,
    /// A user was named twice.
    #[error("user {user} is named twice")]
    DuplicateUser {
        /// The user.
        user: UserId,
    },
    /// No user has this id.
    #[error("unknown user {user}")]
    UnknownUser {
        /// The id given.
        user: UserId,
    },
    /// The user has not accepted the revision the portal requires.
    #[error(
        "user {user} has not accepted agreement revision {required}: {}",
        RecordedAgreement(*.recorded)
    )]
    AgreementNotAccepted {
        /// The user.
        user: UserId,
        /// The revision the user accepted, if a record exists.
        recorded: Option<AgreementVersion>,
        /// The revision required.
        required: AgreementVersion,
    },
    /// The snapshot's time is past 9999-12-31, where the contract's
    /// instants end.
    #[error("the snapshot's time {at} is past 9999-12-31")]
    GeneratedOutOfRange {
        /// The snapshot's time.
        at: UnixTime,
    },
    /// The user's access expires past 9999-12-31, which the portal does
    /// not accept.
    #[error("user {user}'s access expires at {at}, past 9999-12-31")]
    ExpiryOutOfRange {
        /// The user.
        user: UserId,
        /// The expiry.
        at: UnixTime,
    },
    /// The billing cycle of the snapshot's time could not be computed.
    #[error("the billing cycle could not be computed")]
    Cycle(#[source] ModelError),
    /// The usage report runs past the snapshot's time.
    #[error("the usage report runs to {through}, after the snapshot's time {generated_at}")]
    ReportAfterGeneration {
        /// The report's end.
        through: UnixTime,
        /// The snapshot's time.
        generated_at: UnixTime,
    },
    /// The usage report's end lies outside its own billing cycle.
    #[error("the usage report runs to {through}, outside its own billing cycle")]
    ReportOutsideCycle {
        /// The report's end.
        through: UnixTime,
    },
    /// The automatic quota could not be evaluated.
    #[error("the automatic quota could not be evaluated")]
    Quota(#[source] PolicyError),
    /// The usage report has no row for a named user; a report covers every
    /// user of its deployment, so the report is not this deployment's.
    #[error("the usage report has no row for user {user}")]
    RowMissing {
        /// The user.
        user: UserId,
    },
    /// The user's suspension is dated after the snapshot's time: the Mac's
    /// clock wrote both, so it stepped back since, or the record is
    /// corrupt. The portal refuses such a snapshot.
    #[error("user {user} was suspended at {since}, after the snapshot's time {generated_at}")]
    SuspendedAfterGeneration {
        /// The user.
        user: UserId,
        /// When the suspension says it was made.
        since: UnixTime,
        /// The snapshot's time.
        generated_at: UnixTime,
    },
    /// The encoded snapshot is larger than the portal reads.
    #[error("the snapshot is {bytes} bytes, more than the portal's {limit}")]
    TooLarge {
        /// Its size.
        bytes: usize,
        /// The portal's bound.
        limit: usize,
    },
    /// The JSON encoder failed.
    #[error("the snapshot could not be encoded")]
    Encode(#[source] serde_json::Error),
}

kinds! {
    /// The kind of a [`PortalError`], without its details.
    pub enum PortalErrorKind {
        /// See [`PortalError::NotCovered`].
        NotCovered,
        /// See [`PortalError::NoUsers`].
        NoUsers,
        /// See [`PortalError::DuplicateUser`].
        DuplicateUser,
        /// See [`PortalError::UnknownUser`].
        UnknownUser,
        /// See [`PortalError::AgreementNotAccepted`].
        AgreementNotAccepted,
        /// See [`PortalError::GeneratedOutOfRange`].
        GeneratedOutOfRange,
        /// See [`PortalError::ExpiryOutOfRange`].
        ExpiryOutOfRange,
        /// See [`PortalError::Cycle`].
        Cycle,
        /// See [`PortalError::ReportAfterGeneration`].
        ReportAfterGeneration,
        /// See [`PortalError::ReportOutsideCycle`].
        ReportOutsideCycle,
        /// See [`PortalError::Quota`].
        Quota,
        /// See [`PortalError::RowMissing`].
        RowMissing,
        /// See [`PortalError::SuspendedAfterGeneration`].
        SuspendedAfterGeneration,
        /// See [`PortalError::TooLarge`].
        TooLarge,
        /// See [`PortalError::Encode`].
        Encode,
    }
}

impl PortalError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> PortalErrorKind {
        match self {
            Self::NotCovered(_) => PortalErrorKind::NotCovered,
            Self::NoUsers => PortalErrorKind::NoUsers,
            Self::DuplicateUser { .. } => PortalErrorKind::DuplicateUser,
            Self::UnknownUser { .. } => PortalErrorKind::UnknownUser,
            Self::AgreementNotAccepted { .. } => PortalErrorKind::AgreementNotAccepted,
            Self::GeneratedOutOfRange { .. } => PortalErrorKind::GeneratedOutOfRange,
            Self::ExpiryOutOfRange { .. } => PortalErrorKind::ExpiryOutOfRange,
            Self::Cycle(_) => PortalErrorKind::Cycle,
            Self::ReportAfterGeneration { .. } => PortalErrorKind::ReportAfterGeneration,
            Self::ReportOutsideCycle { .. } => PortalErrorKind::ReportOutsideCycle,
            Self::Quota(_) => PortalErrorKind::Quota,
            Self::RowMissing { .. } => PortalErrorKind::RowMissing,
            Self::SuspendedAfterGeneration { .. } => PortalErrorKind::SuspendedAfterGeneration,
            Self::TooLarge { .. } => PortalErrorKind::TooLarge,
            Self::Encode(_) => PortalErrorKind::Encode,
        }
    }
}
