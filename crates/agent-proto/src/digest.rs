// SPDX-License-Identifier: GPL-3.0-or-later

//! Content addresses: [`Sha256Hex`] and the bounded blob length [`BlobLen`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ValueError;
use crate::macros::string_serde;

/// The largest blob a single `PutBlob` may carry: 128 MiB (design §11.1).
pub const MAX_BLOB_BYTES: u64 = 128 * 1024 * 1024;

/// A SHA-256 digest. On the wire it is exactly 64 lowercase hexadecimal
/// characters; any other spelling is rejected.
///
/// Blob and engine digests are Level 1 (design §1.1): they detect accidental
/// corruption and the wrong artifact, not deliberate tampering, which SSH
/// already rules out.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Hex([u8; 32]);

impl Sha256Hex {
    /// Wraps a raw digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Hex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(formatter, "{byte:02x}"))
    }
}

impl fmt::Debug for Sha256Hex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sha256Hex({self})")
    }
}

impl FromStr for Sha256Hex {
    type Err = ValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let digits = text.as_bytes();
        if digits.len() != 64 {
            return Err(ValueError::Sha256Hex);
        }
        let (pairs, _) = digits.as_chunks::<2>();
        let mut bytes = [0_u8; 32];
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = (lower_hex_value(*high)? << 4) | lower_hex_value(*low)?;
        }
        Ok(Self(bytes))
    }
}

string_serde!(Sha256Hex);

fn lower_hex_value(digit: u8) -> Result<u8, ValueError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(ValueError::Sha256Hex),
    }
}

/// The length of a blob payload: at most [`MAX_BLOB_BYTES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct BlobLen(u64);

impl BlobLen {
    /// The largest permitted length.
    pub const MAX: Self = Self(MAX_BLOB_BYTES);

    /// Validates `len` against [`MAX_BLOB_BYTES`].
    pub const fn new(len: u64) -> Result<Self, ValueError> {
        if len <= MAX_BLOB_BYTES {
            Ok(Self(len))
        } else {
            Err(ValueError::BlobTooLarge { len })
        }
    }

    /// The length in bytes.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for BlobLen {
    type Error = ValueError;

    fn try_from(len: u64) -> Result<Self, Self::Error> {
        Self::new(len)
    }
}

impl From<BlobLen> for u64 {
    fn from(len: BlobLen) -> Self {
        len.0
    }
}

impl fmt::Display for BlobLen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "00ff10a9b8c7d6e5f4030201abcdef0123456789abcdef0123456789abcdef01";

    #[test]
    fn digest_round_trips_through_lowercase_hex() {
        let digest: Sha256Hex = DIGEST.parse().unwrap();
        assert_eq!(digest.as_bytes()[..3], [0x00, 0xff, 0x10]);
        assert_eq!(digest.to_string(), DIGEST);
        assert_eq!(Sha256Hex::from_bytes(*digest.as_bytes()), digest);
    }

    #[test]
    fn digest_rejects_every_non_canonical_spelling() {
        let upper = DIGEST.to_ascii_uppercase();
        let short = &DIGEST[..63];
        let long = format!("{DIGEST}0");
        let non_hex = DIGEST.replacen('0', "g", 1);
        let multibyte = format!("{}é", &DIGEST[..62]);
        for text in [
            upper.as_str(),
            short,
            long.as_str(),
            non_hex.as_str(),
            multibyte.as_str(),
            "",
        ] {
            assert_eq!(
                text.parse::<Sha256Hex>(),
                Err(ValueError::Sha256Hex),
                "{text:?}"
            );
        }
    }

    #[test]
    fn digest_debug_shows_hex() {
        let digest: Sha256Hex = DIGEST.parse().unwrap();
        assert_eq!(format!("{digest:?}"), format!("Sha256Hex({DIGEST})"));
    }

    #[test]
    fn blob_len_accepts_exactly_the_limit_and_rejects_one_more() {
        assert_eq!(
            BlobLen::new(MAX_BLOB_BYTES).map(BlobLen::get),
            Ok(MAX_BLOB_BYTES)
        );
        assert_eq!(BlobLen::new(0).map(BlobLen::get), Ok(0));
        assert_eq!(
            BlobLen::new(MAX_BLOB_BYTES + 1),
            Err(ValueError::BlobTooLarge {
                len: MAX_BLOB_BYTES + 1
            })
        );
        assert_eq!(BlobLen::MAX.get(), 134_217_728);
    }
}
