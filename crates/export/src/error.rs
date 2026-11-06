// SPDX-License-Identifier: GPL-3.0-or-later

//! The export crate's typed error taxonomy (design §14, domain `export`).
//!
//! Errors never carry secret material: they name nodes, users, rules and
//! public certificate data only.

use std::fmt;

use mooring_model::node::LifecycleStage;
use mooring_model::secret::SecretSnapshotError;
use mooring_model::{
    AgreementVersion, Capability, ClientLine, ConfigGeneration, ModelError, NamedUsersError,
    NodeId, PortalNotCovered, RecordedAgreement, UnixTime, UserId,
};

use mooring_model::kinds;

/// Why a node cannot appear in a user export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotApplied {
    /// The node is not in the `Applied` stage.
    Stage(LifecycleStage),
    /// The node last confirmed an older generation than the deployment's, so
    /// it may not serve the credentials, SNI or ports being exported.
    Stale {
        /// The generation the node confirmed.
        applied: ConfigGeneration,
        /// The deployment's generation.
        current: ConfigGeneration,
    },
}

impl fmt::Display for NotApplied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stage(stage) => write!(f, "its stage is {stage}"),
            Self::Stale { applied, current } => {
                write!(
                    f,
                    "it confirmed generation {applied}, the deployment is at {current}"
                )
            }
        }
    }
}

/// The rule an outbound tag breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TagRule {
    /// The tag is empty.
    Empty,
    /// The tag is longer than [`crate::OutboundTag::MAX_LEN`] bytes.
    TooLong,
    /// The tag contains a byte outside `a-z`, `0-9` and `-`.
    InvalidCharacter,
    /// The tag starts or ends with `-`.
    HyphenAtEdge,
}

impl fmt::Display for TagRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the tag is empty",
            Self::TooLong => "the tag is too long",
            Self::InvalidCharacter => "the tag contains a byte outside a-z, 0-9 and '-'",
            Self::HyphenAtEdge => "the tag starts or ends with '-'",
        })
    }
}

/// An export, a probe outbound or a certificate check failed.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// A deployment lookup or lifecycle query failed, such as an unknown
    /// user, or a probe for a node that has no site or target yet.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// The secret snapshot lacks a credential the export needs.
    #[error(transparent)]
    Secret(#[from] SecretSnapshotError),
    /// The user is suspended, being revoked or revoked; only active users
    /// are exported.
    #[error("user {user} is not active")]
    UserNotActive {
        /// The user.
        user: UserId,
    },
    /// The user has not accepted the agreement revision this build ships
    /// (decision F9): no record, or a record of another revision. Checked
    /// after the status and before anything about the file.
    #[error(
        "user {user} has not accepted agreement revision {required}: {}",
        RecordedAgreement(*.recorded)
    )]
    AgreementNotAccepted {
        /// The user.
        user: UserId,
        /// The revision the user accepted, if a record exists.
        recorded: Option<AgreementVersion>,
        /// The revision exports require, [`AgreementVersion::CURRENT`].
        required: AgreementVersion,
    },
    /// The user is active but holds credentials on no node, so the file
    /// would have no outbounds, which CFM rejects.
    #[error("user {user} holds credentials on no node")]
    NothingToExport {
        /// The user.
        user: UserId,
    },
    /// A node the user holds credentials on has not confirmed the current
    /// configuration.
    #[error("node {node} cannot be exported: {reason}")]
    NodeNotApplied {
        /// The node.
        node: NodeId,
        /// Why.
        reason: NotApplied,
    },
    /// The user's CFM line does not accept one of the user's capabilities.
    #[error("CFM line {line:?} does not accept capability {cap:?}")]
    CapabilityUnsupported {
        /// The user's client line.
        line: ClientLine,
        /// The capability it does not accept.
        cap: Capability,
    },
    /// The stored Hysteria2 certificate is not one X.509 certificate.
    #[error("node {node}: the stored Hysteria2 certificate does not parse as X.509")]
    CertUnparseable {
        /// The node.
        node: NodeId,
    },
    /// The certificate key is not a canonically encoded P-256 key, so the
    /// SPKI pin could differ between CFM's verifier and upstream sing-box.
    #[error("node {node}: the certificate key is not a canonical P-256 public key")]
    CertKeyUnsupported {
        /// The node.
        node: NodeId,
    },
    /// The certificate's validity does not cover `now` with one day of
    /// clock-skew margin on each side.
    #[error(
        "node {node}: the certificate is valid from {not_before} to {not_after} (Unix seconds), \
         which does not cover {now} with one day of margin"
    )]
    CertNotCurrent {
        /// The node.
        node: NodeId,
        /// The time checked.
        now: UnixTime,
        /// The certificate's notBefore, in Unix seconds.
        not_before: i64,
        /// The certificate's notAfter, in Unix seconds.
        not_after: i64,
    },
    /// The certificate's SAN is not exactly one DNS name of the Hysteria2
    /// SNI form `n<16 lowercase hex>.internal`, so no SNI can be derived
    /// that both client pin verifiers accept.
    #[error("node {node}: the certificate SAN is not exactly one n<16 hex>.internal DNS name")]
    CertSanMismatch {
        /// The node.
        node: NodeId,
    },
    /// The certificate has no extended key usage permitting serverAuth.
    #[error("node {node}: the certificate's extended key usage lacks serverAuth")]
    CertEkuMissing {
        /// The node.
        node: NodeId,
    },
    /// An outbound tag breaks a tag rule.
    #[error("invalid outbound tag: {rule}")]
    InvalidTag {
        /// The rule it breaks.
        rule: TagRule,
    },
    /// The sing-box JSON serialiser failed.
    #[error("sing-box JSON could not be encoded")]
    Encode(#[source] serde_json::Error),
}

kinds! {
    /// The kind of an [`ExportError`], without its details.
    pub enum ExportErrorKind {
        /// See [`ExportError::Model`].
        Model,
        /// See [`ExportError::Secret`].
        Secret,
        /// See [`ExportError::UserNotActive`].
        UserNotActive,
        /// See [`ExportError::AgreementNotAccepted`].
        AgreementNotAccepted,
        /// See [`ExportError::NothingToExport`].
        NothingToExport,
        /// See [`ExportError::NodeNotApplied`].
        NodeNotApplied,
        /// See [`ExportError::CapabilityUnsupported`].
        CapabilityUnsupported,
        /// See [`ExportError::CertUnparseable`].
        CertUnparseable,
        /// See [`ExportError::CertKeyUnsupported`].
        CertKeyUnsupported,
        /// See [`ExportError::CertNotCurrent`].
        CertNotCurrent,
        /// See [`ExportError::CertSanMismatch`].
        CertSanMismatch,
        /// See [`ExportError::CertEkuMissing`].
        CertEkuMissing,
        /// See [`ExportError::InvalidTag`].
        InvalidTag,
        /// See [`ExportError::Encode`].
        Encode,
    }
}

impl ExportError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> ExportErrorKind {
        match self {
            Self::Model(_) => ExportErrorKind::Model,
            Self::Secret(_) => ExportErrorKind::Secret,
            Self::UserNotActive { .. } => ExportErrorKind::UserNotActive,
            Self::AgreementNotAccepted { .. } => ExportErrorKind::AgreementNotAccepted,
            Self::NothingToExport { .. } => ExportErrorKind::NothingToExport,
            Self::NodeNotApplied { .. } => ExportErrorKind::NodeNotApplied,
            Self::CapabilityUnsupported { .. } => ExportErrorKind::CapabilityUnsupported,
            Self::CertUnparseable { .. } => ExportErrorKind::CertUnparseable,
            Self::CertKeyUnsupported { .. } => ExportErrorKind::CertKeyUnsupported,
            Self::CertNotCurrent { .. } => ExportErrorKind::CertNotCurrent,
            Self::CertSanMismatch { .. } => ExportErrorKind::CertSanMismatch,
            Self::CertEkuMissing { .. } => ExportErrorKind::CertEkuMissing,
            Self::InvalidTag { .. } => ExportErrorKind::InvalidTag,
            Self::Encode(_) => ExportErrorKind::Encode,
        }
    }
}

/// The portal's profile bundle could not be made ([`crate::export_profiles`]);
/// nothing was encoded, and no part of a bundle is ever returned.
#[derive(Debug, thiserror::Error)]
pub enum ProfilesError {
    /// The agreement revision this build ships does not cover the portal.
    #[error(transparent)]
    NotCovered(#[from] PortalNotCovered),
    /// The users named are not a list of distinct users of the
    /// deployment ([`mooring_model::named_users`]): none, an id no user
    /// has, or one user twice. A bundle holds exactly the users named.
    #[error(transparent)]
    Named(#[from] NamedUsersError),
    /// A user named who is to be delivered cannot have a file. The whole
    /// bundle is refused: withheld, the user would lose their subscription
    /// link at the portal for good, and left out, the portal would refuse
    /// the bundle.
    #[error("user {user}'s file cannot be made")]
    User {
        /// The user.
        user: UserId,
        /// Why.
        #[source]
        source: Box<ExportError>,
    },
    /// A user's document, as it stands in the bundle, is larger than the
    /// portal accepts.
    #[error(
        "user {user}'s document is {bytes} bytes in the bundle, more than the portal's {limit}"
    )]
    DocumentTooLarge {
        /// The user.
        user: UserId,
        /// The document's size in the bundle.
        bytes: usize,
        /// The portal's bound.
        limit: usize,
    },
    /// The bundle is larger than the portal reads.
    #[error("the bundle is {bytes} bytes, more than the portal's {limit}")]
    BundleTooLarge {
        /// Its size.
        bytes: usize,
        /// The portal's bound.
        limit: usize,
    },
    /// The JSON encoder failed.
    #[error("the profile bundle could not be encoded")]
    Encode(#[source] serde_json::Error),
}

kinds! {
    /// The kind of a [`ProfilesError`], without its details.
    pub enum ProfilesErrorKind {
        /// See [`ProfilesError::NotCovered`].
        NotCovered,
        /// See [`ProfilesError::Named`].
        Named,
        /// See [`ProfilesError::User`].
        User,
        /// See [`ProfilesError::DocumentTooLarge`].
        DocumentTooLarge,
        /// See [`ProfilesError::BundleTooLarge`].
        BundleTooLarge,
        /// See [`ProfilesError::Encode`].
        Encode,
    }
}

impl ProfilesError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> ProfilesErrorKind {
        match self {
            Self::NotCovered(_) => ProfilesErrorKind::NotCovered,
            Self::Named(_) => ProfilesErrorKind::Named,
            Self::User { .. } => ProfilesErrorKind::User,
            Self::DocumentTooLarge { .. } => ProfilesErrorKind::DocumentTooLarge,
            Self::BundleTooLarge { .. } => ProfilesErrorKind::BundleTooLarge,
            Self::Encode(_) => ProfilesErrorKind::Encode,
        }
    }
}
