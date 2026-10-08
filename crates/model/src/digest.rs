// SPDX-License-Identifier: GPL-3.0-or-later

//! SHA-256 digests as typed values, and the one SHA-256 helper the
//! workspace's crates share ([`Sha256Digest::of`], [`SpkiSha256::of`]);
//! only `mooring-render` also streams its bundle-digest encoding through
//! `sha2` directly (design §6.3). They detect accidental corruption or the
//! wrong artifact (design §12, Level 1); none of them is a security
//! boundary.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::encoding::{decode_b64std_32, decode_hex_lower, encode_b64std, encode_hex_lower};
use crate::error::ModelError;

/// The text encoding a digest parse error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestEncoding {
    /// 64 lowercase hexadecimal characters.
    LowerHex,
    /// 44 characters of padded standard base64.
    Base64,
}

impl fmt::Display for DigestEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LowerHex => "64 lowercase hex characters",
            Self::Base64 => "44 characters of standard base64",
        })
    }
}

/// A SHA-256 digest written as 64 lowercase hex characters: bundle digests
/// and the certificate DER pin (Clash `fingerprint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps a computed digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The SHA-256 of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Parses 64 lowercase hex characters.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        decode_hex_lower::<32>(text)
            .map(Self)
            .ok_or(ModelError::InvalidDigest {
                encoding: DigestEncoding::LowerHex,
            })
    }

    /// The raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex_lower(&self.0))
    }
}

/// A SHA-256 digest of a certificate's SubjectPublicKeyInfo, written as 44
/// characters of standard base64 (sing-box `certificate_public_key_sha256`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SpkiSha256([u8; 32]);

impl SpkiSha256 {
    /// Wraps a computed digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The SHA-256 of a DER SubjectPublicKeyInfo.
    #[must_use]
    pub fn of(spki_der: &[u8]) -> Self {
        Self(Sha256::digest(spki_der).into())
    }

    /// Parses 44 characters of padded standard base64.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        decode_b64std_32(text)
            .map(|bytes| Self(*bytes))
            .ok_or(ModelError::InvalidDigest {
                encoding: DigestEncoding::Base64,
            })
    }

    /// The raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SpkiSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_b64std(&self.0))
    }
}

macro_rules! digest_text_conversions {
    ($name:ident) => {
        impl TryFrom<String> for $name {
            type Error = ModelError;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(digest: $name) -> Self {
                digest.to_string()
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
    };
}

digest_text_conversions!(Sha256Digest);
digest_text_conversions!(SpkiSha256);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_encodings_and_rejections() {
        // SHA-256 of the empty string.
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let digest = Sha256Digest::parse(hex).unwrap();
        assert_eq!(digest.to_string(), hex);
        let spki = SpkiSha256::from_bytes(*digest.as_bytes());
        assert_eq!(
            spki.to_string(),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        assert_eq!(
            Sha256Digest::parse(&hex.to_uppercase()),
            Err(ModelError::InvalidDigest {
                encoding: DigestEncoding::LowerHex
            })
        );
        assert_eq!(
            SpkiSha256::parse("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"),
            Err(ModelError::InvalidDigest {
                encoding: DigestEncoding::Base64
            })
        );
        assert!(serde_json::from_str::<Sha256Digest>("\"e3b0\"").is_err());
    }

    #[test]
    fn computed_digests_match_the_fips_180_vectors() {
        assert_eq!(
            Sha256Digest::of(b"").to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            Sha256Digest::of(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            SpkiSha256::of(b"").to_string(),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
    }

    proptest! {
        #[test]
        fn digests_round_trip(bytes in proptest::array::uniform32(any::<u8>())) {
            let hex = Sha256Digest::from_bytes(bytes);
            prop_assert_eq!(Sha256Digest::parse(&hex.to_string()).unwrap(), hex);
            let b64 = SpkiSha256::from_bytes(bytes);
            prop_assert_eq!(SpkiSha256::parse(&b64.to_string()).unwrap(), b64);
        }
    }
}
