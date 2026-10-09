// SPDX-License-Identifier: GPL-3.0-or-later

//! The export crate's typed error taxonomy (design §14, domain `export`).
//!
//! Errors never carry secret material: they name nodes, users, rules and
//! public certificate data only.

use std::fmt;

use mooring_model::node::LifecycleStage;
use mooring_model::secret::SecretSnapshotError;
use mooring_model::{
    Capability, ClientLine, ConfigGeneration, ModelError, NodeId, UnixTime, UserId,
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
