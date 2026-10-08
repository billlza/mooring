// SPDX-License-Identifier: GPL-3.0-or-later

//! The keys crate's typed errors (design §14, domain `keys`).
//!
//! No variant carries generated material, so an error can be displayed,
//! logged or returned to the CLI without leaking a secret.

use std::fmt;

use mooring_model::{ModelError, UnixTime, kinds};

/// The stage of building the Hysteria2 certificate that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertStep {
    /// Generating the P-256 key pair from `ring`'s system random source.
    KeyGeneration,
    /// Building the certificate parameters (the subject alternative name).
    Parameters,
    /// Self-signing the certificate.
    Signing,
}

impl fmt::Display for CertStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeyGeneration => "key generation",
            Self::Parameters => "parameter construction",
            Self::Signing => "self-signing",
        })
    }
}

/// Generating a key, credential or certificate failed.
///
/// Every variant is fatal for the command that asked for the material; the
/// CLI does not retry (design §14).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeysError {
    /// The operating system's random source failed.
    #[error("the operating system random source failed")]
    Entropy(#[source] getrandom::Error),
    /// A model invariant rejected generated or derived material.
    ///
    /// With a working random source this happens only for an all-zero draw
    /// (at most 2^-64 for a short id), so it means the source is broken.
    #[error("generated key material was rejected")]
    MaterialRejected(#[source] ModelError),
    /// A certificate issued at `now` would have a validity window outside
    /// 1970-01-01T00:00:00Z..=9999-12-31T23:59:59Z, which X.509 cannot encode.
    #[error("a certificate issued at {now} would be valid outside the range X.509 can encode")]
    CertValidity {
        /// The requested issue time.
        now: UnixTime,
    },
    /// `rcgen` failed to build the Hysteria2 certificate.
    #[error("building the Hysteria2 certificate failed during {step}")]
    CertBuild {
        /// The stage that failed.
        step: CertStep,
        /// The `rcgen` error.
        #[source]
        source: rcgen::Error,
    },
    /// The SSH key comment breaks the comment rule.
    #[error(
        "SSH key comment must be at most 64 characters of A-Z, a-z, 0-9, '.', '_', '@', '+' or '-'"
    )]
    InvalidSshComment,
}

kinds! {
    /// The kind of a [`KeysError`], without its details.
    pub enum KeysErrorKind {
        /// See [`KeysError::Entropy`].
        Entropy,
        /// See [`KeysError::MaterialRejected`].
        MaterialRejected,
        /// See [`KeysError::CertValidity`].
        CertValidity,
        /// See [`KeysError::CertBuild`].
        CertBuild,
        /// See [`KeysError::InvalidSshComment`].
        InvalidSshComment,
    }
}

impl KeysError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> KeysErrorKind {
        match self {
            Self::Entropy(_) => KeysErrorKind::Entropy,
            Self::MaterialRejected(_) => KeysErrorKind::MaterialRejected,
            Self::CertValidity { .. } => KeysErrorKind::CertValidity,
            Self::CertBuild { .. } => KeysErrorKind::CertBuild,
            Self::InvalidSshComment => KeysErrorKind::InvalidSshComment,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    /// One error of every variant, built through the variant itself.
    fn one_of_each() -> Vec<KeysError> {
        vec![
            KeysError::Entropy(getrandom::Error::UNSUPPORTED),
            KeysError::MaterialRejected(ModelError::InvalidShortId),
            KeysError::CertValidity {
                now: UnixTime::from_secs(0),
            },
            KeysError::CertBuild {
                step: CertStep::Signing,
                source: rcgen::Error::RingUnspecified,
            },
            KeysError::InvalidSshComment,
        ]
    }

    #[test]
    fn every_kind_is_listed_once_and_reached() {
        let kinds: Vec<KeysErrorKind> = one_of_each().iter().map(KeysError::kind).collect();
        assert_eq!(kinds, KeysErrorKind::ALL);
        assert_eq!(
            KeysErrorKind::ALL,
            [
                KeysErrorKind::Entropy,
                KeysErrorKind::MaterialRejected,
                KeysErrorKind::CertValidity,
                KeysErrorKind::CertBuild,
                KeysErrorKind::InvalidSshComment,
            ]
        );
        let names: Vec<&str> = KeysErrorKind::ALL.iter().map(|kind| kind.name()).collect();
        assert_eq!(
            names,
            [
                "Entropy",
                "MaterialRejected",
                "CertValidity",
                "CertBuild",
                "InvalidSshComment"
            ]
        );
        assert_eq!(KeysErrorKind::CertBuild.to_string(), "CertBuild");
    }

    #[test]
    fn messages_and_sources() {
        let entropy = KeysError::Entropy(getrandom::Error::UNSUPPORTED);
        assert_eq!(
            entropy.to_string(),
            "the operating system random source failed"
        );
        assert_eq!(
            entropy.source().map(ToString::to_string),
            Some(getrandom::Error::UNSUPPORTED.to_string())
        );

        let build = KeysError::CertBuild {
            step: CertStep::KeyGeneration,
            source: rcgen::Error::RingUnspecified,
        };
        assert_eq!(
            build.to_string(),
            "building the Hysteria2 certificate failed during key generation"
        );
        assert!(build.source().is_some());

        let validity = KeysError::CertValidity {
            now: UnixTime::from_secs(5),
        };
        assert_eq!(
            validity.to_string(),
            "a certificate issued at @5 would be valid outside the range X.509 can encode"
        );
        assert!(validity.source().is_none());

        let rejected = KeysError::MaterialRejected(ModelError::InvalidShortId);
        assert_eq!(
            rejected.source().map(ToString::to_string),
            Some(ModelError::InvalidShortId.to_string())
        );
        assert_eq!(CertStep::Parameters.to_string(), "parameter construction");
        assert_eq!(CertStep::Signing.to_string(), "self-signing");
    }
}
