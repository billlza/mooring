// SPDX-License-Identifier: GPL-3.0-or-later

//! Public keys in their canonical text encodings.
//!
//! All-zero keys are rejected everywhere: an all-zero Curve25519 public key
//! is a low-order point, and CFM rejects all-zero WireGuard keys
//! (`cfw-singbox-config/src/credentials.rs` `valid_wireguard_key`).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::encoding::{decode_b64std_32, decode_b64url_32, encode_b64std, encode_b64url};
use crate::error::ModelError;

/// Which public key type a parse error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyKind {
    /// A REALITY X25519 public key (43 characters of unpadded base64url).
    RealityX25519,
    /// A WireGuard public key (44 characters of padded standard base64).
    WireGuard,
    /// An Ed25519 SSH host key (44 characters of padded standard base64).
    Ed25519,
}

impl fmt::Display for PublicKeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RealityX25519 => "REALITY X25519",
            Self::WireGuard => "WireGuard",
            Self::Ed25519 => "Ed25519",
        })
    }
}

fn non_zero(bytes: [u8; 32], key: PublicKeyKind) -> Result<[u8; 32], ModelError> {
    if bytes == [0; 32] {
        Err(ModelError::InvalidPublicKey { key })
    } else {
        Ok(bytes)
    }
}

/// A REALITY X25519 public key: 32 non-zero bytes, written as 43 characters
/// of unpadded base64url (Xray `base64.RawURLEncoding`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct X25519Pub([u8; 32]);

impl X25519Pub {
    /// Accepts 32 bytes unless they are all zero.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ModelError> {
        non_zero(bytes, PublicKeyKind::RealityX25519).map(Self)
    }

    /// Parses 43 characters of unpadded base64url.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = decode_b64url_32(text).ok_or(ModelError::InvalidPublicKey {
            key: PublicKeyKind::RealityX25519,
        })?;
        Self::from_bytes(*bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for X25519Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_b64url(&self.0))
    }
}

/// A WireGuard public key: 32 non-zero bytes, written as 44 characters of
/// padded standard base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WgKey([u8; 32]);

impl WgKey {
    /// Accepts 32 bytes unless they are all zero.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ModelError> {
        non_zero(bytes, PublicKeyKind::WireGuard).map(Self)
    }

    /// Parses 44 characters of padded standard base64.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = decode_b64std_32(text).ok_or(ModelError::InvalidPublicKey {
            key: PublicKeyKind::WireGuard,
        })?;
        Self::from_bytes(*bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_b64std(&self.0))
    }
}

/// An Ed25519 public key (an SSH host key pin): 32 non-zero bytes, written as
/// 44 characters of padded standard base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ed25519Pub([u8; 32]);

impl Ed25519Pub {
    /// Accepts 32 bytes unless they are all zero.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ModelError> {
        non_zero(bytes, PublicKeyKind::Ed25519).map(Self)
    }

    /// Parses 44 characters of padded standard base64.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = decode_b64std_32(text).ok_or(ModelError::InvalidPublicKey {
            key: PublicKeyKind::Ed25519,
        })?;
        Self::from_bytes(*bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The OpenSSH name of the key type.
    pub const SSH_KEY_TYPE: &str = "ssh-ed25519";

    /// The length of the RFC 8709 public key blob.
    pub const SSH_BLOB_LEN: usize = SSH_BLOB_PREFIX.len() + 32;

    /// The RFC 8709 public key blob: `string "ssh-ed25519"`, `string key[32]`.
    #[must_use]
    pub fn ssh_blob(&self) -> [u8; Self::SSH_BLOB_LEN] {
        let mut blob = [0_u8; Self::SSH_BLOB_LEN];
        let (prefix, key) = blob.split_at_mut(SSH_BLOB_PREFIX.len());
        prefix.copy_from_slice(&SSH_BLOB_PREFIX);
        key.copy_from_slice(&self.0);
        blob
    }

    /// The key in an RFC 8709 public key blob. Any other bytes, or an
    /// all-zero key, are `InvalidPublicKey`.
    pub fn from_ssh_blob(blob: &[u8]) -> Result<Self, ModelError> {
        let key = blob
            .strip_prefix(SSH_BLOB_PREFIX.as_slice())
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
            .ok_or(ModelError::InvalidPublicKey {
                key: PublicKeyKind::Ed25519,
            })?;
        Self::from_bytes(key)
    }

    /// `ssh-ed25519 <base64 blob>`: the `authorized_keys` form without a
    /// comment, which the agent protocol and cloud-init carry.
    #[must_use]
    pub fn ssh_authorized_key(&self) -> String {
        format!(
            "{} {}",
            Self::SSH_KEY_TYPE,
            STANDARD.encode(self.ssh_blob())
        )
    }

    /// Parses the [`ssh_authorized_key`](Self::ssh_authorized_key) form
    /// exactly: no comment, padded standard base64.
    pub fn parse_ssh_authorized_key(text: &str) -> Result<Self, ModelError> {
        let mut blob = [0_u8; Self::SSH_BLOB_LEN];
        let decoded = text
            .strip_prefix(Self::SSH_KEY_TYPE)
            .and_then(|rest| rest.strip_prefix(' '))
            .and_then(|encoded| STANDARD.decode_slice(encoded, &mut blob).ok());
        match decoded {
            Some(Self::SSH_BLOB_LEN) => Self::from_ssh_blob(&blob),
            _ => Err(ModelError::InvalidPublicKey {
                key: PublicKeyKind::Ed25519,
            }),
        }
    }
}

/// The RFC 8709 public key blob up to the key bytes: `string "ssh-ed25519"`
/// and the length prefix of the 32-byte key.
const SSH_BLOB_PREFIX: [u8; 19] = *b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";

impl fmt::Display for Ed25519Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_b64std(&self.0))
    }
}

macro_rules! key_text_conversions {
    ($name:ident) => {
        impl TryFrom<String> for $name {
            type Error = ModelError;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(key: $name) -> Self {
                key.to_string()
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

key_text_conversions!(X25519Pub);
key_text_conversions!(WgKey);
key_text_conversions!(Ed25519Pub);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// RFC 7748 §6.1: Alice's public key.
    const RFC7748_ALICE_PUB: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];

    #[test]
    fn known_encodings() {
        let reality = X25519Pub::from_bytes(RFC7748_ALICE_PUB).unwrap();
        assert_eq!(
            reality.to_string(),
            "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
        );
        let wg = WgKey::from_bytes(RFC7748_ALICE_PUB).unwrap();
        assert_eq!(
            wg.to_string(),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
        assert_eq!(X25519Pub::parse(&reality.to_string()).unwrap(), reality);
        assert_eq!(WgKey::parse(&wg.to_string()).unwrap(), wg);
    }

    #[test]
    fn encodings_are_not_interchangeable() {
        let reality = X25519Pub::from_bytes(RFC7748_ALICE_PUB)
            .unwrap()
            .to_string();
        let wg = WgKey::from_bytes(RFC7748_ALICE_PUB).unwrap().to_string();
        assert!(WgKey::parse(&reality).is_err());
        assert!(X25519Pub::parse(&wg).is_err());
        assert!(Ed25519Pub::parse(&reality).is_err());
    }

    #[test]
    fn all_zero_keys_are_rejected() {
        let zero_url = "A".repeat(43);
        let zero_std = format!("{}=", "A".repeat(43));
        assert_eq!(
            X25519Pub::parse(&zero_url),
            Err(ModelError::InvalidPublicKey {
                key: PublicKeyKind::RealityX25519
            })
        );
        assert_eq!(
            WgKey::parse(&zero_std),
            Err(ModelError::InvalidPublicKey {
                key: PublicKeyKind::WireGuard
            })
        );
        assert_eq!(
            Ed25519Pub::parse(&zero_std),
            Err(ModelError::InvalidPublicKey {
                key: PublicKeyKind::Ed25519
            })
        );
    }

    /// RFC 8032 §7.1 test 1: the public key.
    const RFC8032_TEST1_PUB: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    #[test]
    fn ed25519_openssh_encodings() {
        let key = Ed25519Pub::parse(RFC8032_TEST1_PUB).unwrap();
        let line =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
        assert_eq!(key.ssh_authorized_key(), line);
        assert_eq!(Ed25519Pub::parse_ssh_authorized_key(line), Ok(key));
        let blob = key.ssh_blob();
        assert_eq!(&blob[..4], [0, 0, 0, 11]);
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], [0, 0, 0, 32]);
        assert_eq!(&blob[19..], key.as_bytes());
        assert_eq!(Ed25519Pub::from_ssh_blob(&blob), Ok(key));
    }

    #[test]
    fn ed25519_openssh_encodings_refuse_other_bytes() {
        let invalid = Err(ModelError::InvalidPublicKey {
            key: PublicKeyKind::Ed25519,
        });
        let blob = Ed25519Pub::parse(RFC8032_TEST1_PUB).unwrap().ssh_blob();
        let mut other_type = blob;
        other_type[4] = b'S';
        let mut zero_key = blob;
        zero_key[19..].fill(0);
        let longer = [blob.as_slice(), &[0]].concat();
        for bad in [&blob[..50], &longer, &other_type, &zero_key, &[]] {
            assert_eq!(Ed25519Pub::from_ssh_blob(bad), invalid, "{bad:?}");
        }
        let line =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
        let zero_line = Ed25519Pub::SSH_KEY_TYPE.to_owned() + " " + &STANDARD.encode(zero_key);
        for bad in [
            format!("{line} comment"),
            line.replacen(' ', "  ", 1),
            line.replacen("ssh-ed25519", "ssh-rsa", 1),
            line[..line.len() - 1].to_owned(),
            line.replacen("ssh-ed25519 ", "", 1),
            zero_line,
            String::new(),
        ] {
            assert_eq!(Ed25519Pub::parse_ssh_authorized_key(&bad), invalid, "{bad}");
        }
    }

    #[test]
    fn serde_rejects_wrong_lengths() {
        assert!(
            serde_json::from_str::<X25519Pub>("\"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTm\"")
                .is_err()
        );
        assert!(
            serde_json::from_str::<WgKey>("\"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo\"")
                .is_err()
        );
    }

    proptest! {
        #[test]
        fn x25519_pub_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            match X25519Pub::from_bytes(bytes) {
                Ok(key) => {
                    let text = key.to_string();
                    prop_assert_eq!(text.len(), 43);
                    let json = serde_json::to_string(&key).unwrap();
                    prop_assert_eq!(serde_json::from_str::<X25519Pub>(&json).unwrap(), key);
                }
                Err(_) => prop_assert_eq!(bytes, [0; 32]),
            }
        }

        #[test]
        fn ed25519_openssh_line_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            if let Ok(key) = Ed25519Pub::from_bytes(bytes) {
                let line = key.ssh_authorized_key();
                prop_assert_eq!(line.len(), "ssh-ed25519 ".len() + 68);
                prop_assert_eq!(Ed25519Pub::parse_ssh_authorized_key(&line), Ok(key));
                prop_assert_eq!(Ed25519Pub::from_ssh_blob(&key.ssh_blob()), Ok(key));
            }
        }

        #[test]
        fn wg_key_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            if let Ok(key) = WgKey::from_bytes(bytes) {
                let text = key.to_string();
                prop_assert_eq!(text.len(), 44);
                prop_assert_eq!(WgKey::parse(&text).unwrap(), key);
                let ed25519 = Ed25519Pub::parse(&text).unwrap();
                prop_assert_eq!(ed25519.as_bytes(), key.as_bytes());
            }
        }
    }
}
