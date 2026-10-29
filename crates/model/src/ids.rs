// SPDX-License-Identifier: GPL-3.0-or-later

//! Identifiers: node and user ids, REALITY short ids, credential UUIDs and
//! Mac-local labels.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, de};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::encoding::{decode_hex_lower, encode_hex_lower};
use crate::error::ModelError;

/// A node id matching `^[a-z][a-z0-9]{1,11}$`, for example `lon1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeId(String);

impl NodeId {
    /// Validates `text` as a node id.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = text.as_bytes();
        let valid = (2..=12).contains(&bytes.len())
            && bytes[0].is_ascii_lowercase()
            && bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidNodeId)
        }
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The RFC 4648 base32 alphabet in lowercase.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// The number of characters in a user id.
pub const USER_ID_LEN: usize = 10;

/// An opaque user id of 10 lowercase RFC 4648 base32 characters (50 bits).
///
/// It is the only user identifier ever sent to a VPS.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserId(String);

impl UserId {
    /// Validates `text` as a user id.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let valid =
            text.len() == USER_ID_LEN && text.bytes().all(|byte| BASE32_LOWER.contains(&byte));
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidUserId)
        }
    }

    /// Encodes the low 50 bits of `bits`, most significant first; this is how
    /// a random user id is built from 50 random bits.
    #[must_use]
    pub fn from_low_bits(bits: u64) -> Self {
        let mut text = String::with_capacity(USER_ID_LEN);
        for position in (0..USER_ID_LEN).rev() {
            let index = (bits >> (5 * position)) & 0x1f;
            // `index` is masked to 0..32, so it always indexes the alphabet.
            text.push(char::from(BASE32_LOWER[index as usize]));
        }
        Self(text)
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The number of characters in a public alias, hyphen included.
pub const PUBLIC_ALIAS_LEN: usize = 9;

/// A user's public alias: 40 random bits as two groups of four lowercase
/// RFC 4648 base32 characters joined by a hyphen, for example `k7qd-m2xa`.
///
/// It is never a name: an alias is made only from random bits
/// ([`PublicAlias::from_random_bytes`], which `mooring-keys` feeds from the
/// operating system's random source) or decoded from a stored one. No
/// public conversion turns text into an alias (there is no `FromStr` and
/// no `TryFrom<String>`), so no command can take an alias an operator
/// typed. The user and the operator can quote it (in support messages,
/// say) without naming the user. The hyphen keeps it visibly apart from a
/// [`UserId`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct PublicAlias(String);

impl PublicAlias {
    /// Validates `text` as an alias: only for decoding a stored alias, so
    /// it is not public.
    pub(crate) fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = text.as_bytes();
        let valid = bytes.len() == PUBLIC_ALIAS_LEN
            && bytes.iter().enumerate().all(|(index, byte)| {
                if index == 4 {
                    *byte == b'-'
                } else {
                    BASE32_LOWER.contains(byte)
                }
            });
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidPublicAlias)
        }
    }

    /// Encodes 40 random bits, most significant first. The bytes must come
    /// from a cryptographic random source (`mooring-keys` draws them): any
    /// 40 bits make a valid alias, so only the source keeps it from
    /// spelling a name.
    #[must_use]
    pub fn from_random_bytes(bytes: [u8; 5]) -> Self {
        let bits = bytes
            .iter()
            .fold(0_u64, |bits, &byte| (bits << 8) | u64::from(byte));
        let mut text = String::with_capacity(PUBLIC_ALIAS_LEN);
        for position in (0..8).rev() {
            let index = (bits >> (5 * position)) & 0x1f;
            // `index` is masked to 0..32, so it always indexes the alphabet.
            text.push(char::from(BASE32_LOWER[index as usize]));
            if position == 4 {
                text.push('-');
            }
        }
        Self(text)
    }

    /// The alias as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PublicAlias {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

impl From<PublicAlias> for String {
    fn from(alias: PublicAlias) -> Self {
        alias.0
    }
}

impl fmt::Display for PublicAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A REALITY short id: 8 non-zero bytes written as 16 lowercase hex characters.
///
/// All-zero is rejected because Xray decodes `"0000000000000000"` to the same
/// bytes as the empty short id, which any client matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ShortId([u8; 8]);

impl ShortId {
    /// Accepts 8 bytes unless they are all zero.
    pub fn from_bytes(bytes: [u8; 8]) -> Result<Self, ModelError> {
        if bytes == [0; 8] {
            Err(ModelError::InvalidShortId)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Parses 16 lowercase hex characters.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = decode_hex_lower::<8>(text).ok_or(ModelError::InvalidShortId)?;
        Self::from_bytes(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode_hex_lower(&self.0))
    }
}

impl TryFrom<String> for ShortId {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<ShortId> for String {
    fn from(id: ShortId) -> Self {
        id.to_string()
    }
}

impl FromStr for ShortId {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// The credential-UUID rule a rejected UUID breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UuidRule {
    /// Not the canonical lowercase hyphenated 8-4-4-4-12 form.
    NotCanonical,
    /// The nil UUID.
    Nil,
    /// Not version 4.
    NotVersion4,
    /// Not the RFC 9562 variant.
    NotRfcVariant,
}

impl fmt::Display for UuidRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotCanonical => "not in canonical lowercase hyphenated form",
            Self::Nil => "the nil UUID",
            Self::NotVersion4 => "not version 4",
            Self::NotRfcVariant => "not the RFC 9562 variant",
        })
    }
}

/// The length of a hyphenated UUID.
const UUID_TEXT_LEN: usize = 36;

/// A credential UUID: canonical lowercase, non-nil, version 4, RFC 9562 variant.
///
/// Every UUID in Mooring is a credential, so `Debug` is redacted, and there is
/// neither `Display` nor `Serialize` nor `Deserialize`: no state or wire type
/// can hold one, and the text form is returned only in a zeroizing buffer
/// (the keychain format is `SecretMaterial::encode`). The bytes are zeroized
/// on drop; values held in a `SecretSnapshot` are also wrapped in
/// [`crate::secret::Secret`].
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Parses the canonical lowercase hyphenated form.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let invalid = |rule| ModelError::InvalidUuid { rule };
        if text.len() != UUID_TEXT_LEN {
            return Err(invalid(UuidRule::NotCanonical));
        }
        let parsed = uuid::Uuid::try_parse(text).map_err(|_| invalid(UuidRule::NotCanonical))?;
        let mut canonical = Zeroizing::new([0_u8; UUID_TEXT_LEN]);
        if parsed
            .hyphenated()
            .encode_lower(canonical.as_mut_slice())
            .as_bytes()
            != text.as_bytes()
        {
            return Err(invalid(UuidRule::NotCanonical));
        }
        Self::from_bytes(parsed.into_bytes())
    }

    /// Accepts 16 bytes that form a non-nil version 4 RFC 9562 UUID.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, ModelError> {
        let value = uuid::Uuid::from_bytes(bytes);
        let rule = if value.is_nil() {
            Some(UuidRule::Nil)
        } else if value.get_version() != Some(uuid::Version::Random) {
            Some(UuidRule::NotVersion4)
        } else if value.get_variant() != uuid::Variant::RFC4122 {
            Some(UuidRule::NotRfcVariant)
        } else {
            None
        };
        match rule {
            Some(rule) => Err(ModelError::InvalidUuid { rule }),
            None => Ok(Self(bytes)),
        }
    }

    /// Builds a version 4 UUID from 16 random bytes by setting the version and
    /// variant bits, as RFC 9562 §5.4 prescribes; the result is never nil.
    #[must_use]
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(
            uuid::Builder::from_random_bytes(bytes)
                .into_uuid()
                .into_bytes(),
        )
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The canonical lowercase hyphenated text, in a zeroizing buffer.
    #[must_use]
    pub fn to_hyphenated(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::with_capacity(UUID_TEXT_LEN));
        let mut buffer = Zeroizing::new([0_u8; UUID_TEXT_LEN]);
        text.push_str(
            uuid::Uuid::from_bytes(self.0)
                .hyphenated()
                .encode_lower(buffer.as_mut_slice()),
        );
        text
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Uuid(<redacted>)")
    }
}

impl Zeroize for Uuid {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A credential is wiped when it is dropped, inside or outside a `Secret`.
impl Drop for Uuid {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Uuid {}

/// The maximum number of characters in a local label.
pub const MAX_LABEL_CHARS: usize = 64;

/// A Mac-only human label for a user or an own network; never exported or
/// sent to a VPS.
///
/// 1 to 64 characters, no control characters, no leading or trailing
/// whitespace. Any script is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LocalLabel(String);

impl LocalLabel {
    /// Validates `text` as a label.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let count = text.chars().count();
        let valid = (1..=MAX_LABEL_CHARS).contains(&count)
            && !text.chars().any(char::is_control)
            && text.trim() == text;
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidLabel)
        }
    }

    /// The label as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! string_newtype_conversions {
    ($name:ident) => {
        impl TryFrom<String> for $name {
            type Error = ModelError;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_newtype_conversions!(NodeId);
string_newtype_conversions!(UserId);
string_newtype_conversions!(LocalLabel);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn node_id_bounds() {
        for ok in ["lon1", "ab", "a12345678901", "ams"] {
            assert_eq!(NodeId::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "a",
            "a123456789012",
            "1lon",
            "Lon1",
            "lon-1",
            "lon_1",
            "",
            "lön1",
        ] {
            assert_eq!(NodeId::parse(bad), Err(ModelError::InvalidNodeId), "{bad}");
        }
        assert!(serde_json::from_str::<NodeId>("\"LON1\"").is_err());
    }

    #[test]
    fn user_id_bounds() {
        assert!(UserId::parse("abcdefgh23").is_ok());
        for bad in [
            "abcdefgh2",
            "abcdefgh234",
            "abcdefgh18",
            "Abcdefgh23",
            "abcdefgh==",
        ] {
            assert_eq!(UserId::parse(bad), Err(ModelError::InvalidUserId), "{bad}");
        }
        assert_eq!(UserId::from_low_bits(0).as_str(), "aaaaaaaaaa");
        assert_eq!(UserId::from_low_bits(1).as_str(), "aaaaaaaaab");
        assert_eq!(UserId::from_low_bits(u64::MAX).as_str(), "7777777777");
        // Bits above the low 50 do not change the id.
        assert_eq!(UserId::from_low_bits(1 << 50), UserId::from_low_bits(0));
    }

    /// `Text::<T>::FROM_STR` (`TRY_FROM_STRING`) is true exactly when `T`
    /// implements `FromStr` (`TryFrom<String>`), by the same inherent
    /// constant probe as [`Serde`].
    struct Text<T>(std::marker::PhantomData<T>);

    trait NoText {
        const FROM_STR: bool = false;
        const TRY_FROM_STRING: bool = false;
    }

    impl<T> NoText for Text<T> {}

    impl<T: FromStr> Text<T> {
        const FROM_STR: bool = true;
    }

    impl<T: TryFrom<String>> Text<T> {
        const TRY_FROM_STRING: bool = true;
    }

    #[test]
    fn public_alias_rules() {
        // An alias comes only from random bits (`mooring-keys`) or from
        // decoding a stored one: no public conversion turns text, an
        // operator's say, into an alias, so an alias is never a name
        // someone typed. Checked at compile time; the control is a type
        // with both conversions.
        const {
            assert!(Text::<UserId>::FROM_STR && Text::<UserId>::TRY_FROM_STRING);
            assert!(!Text::<PublicAlias>::FROM_STR, "no FromStr for PublicAlias");
            assert!(
                !Text::<PublicAlias>::TRY_FROM_STRING,
                "no TryFrom<String> for PublicAlias"
            );
        }
        let alias = PublicAlias::from_random_bytes([0x57, 0xe0, 0x36, 0x6a, 0xe0]);
        assert_eq!(alias.as_str(), "k7qd-m2xa");
        assert_eq!(alias.to_string(), "k7qd-m2xa");
        assert_eq!(String::from(alias.clone()), "k7qd-m2xa");
        assert_eq!(serde_json::to_string(&alias).unwrap(), "\"k7qd-m2xa\"");
        assert_eq!(
            serde_json::from_str::<PublicAlias>("\"k7qd-m2xa\"").unwrap(),
            alias
        );
        assert_eq!(PublicAlias::parse("k7qd-m2xa").unwrap(), alias);
        for bad in [
            "k7qdm2xa",
            "k7qd-m2x",
            "k7qd-m2xa2",
            "k7q-dm2xa",
            "K7qd-m2xa",
            "k7qd-m2x1",
            "k7qd_m2xa",
            "abcdefghij",
            "Alice",
            "",
        ] {
            assert_eq!(
                PublicAlias::parse(bad),
                Err(ModelError::InvalidPublicAlias),
                "{bad}"
            );
            let json = serde_json::to_string(bad).unwrap();
            assert!(serde_json::from_str::<PublicAlias>(&json).is_err(), "{bad}");
        }
        let from = PublicAlias::from_random_bytes;
        assert_eq!(from([0; 5]).as_str(), "aaaa-aaaa");
        assert_eq!(from([0, 0, 0, 0, 1]).as_str(), "aaaa-aaab");
        assert_eq!(from([0, 0, 0, 0, 32]).as_str(), "aaaa-aaba");
        assert_eq!(from([0, 0, 0x10, 0, 0]).as_str(), "aaab-aaaa");
        assert_eq!(from([0x80, 0, 0, 0, 0]).as_str(), "qaaa-aaaa");
        assert_eq!(from([0xff; 5]).as_str(), "7777-7777");
    }

    #[test]
    fn short_id_rules() {
        let id = ShortId::parse("5f1e000100000001").unwrap();
        assert_eq!(id.to_string(), "5f1e000100000001");
        for bad in [
            "0000000000000000",
            "5F1E000100000001",
            "5f1e00010000001",
            "5f1e0001000000011",
            "5f1e00010000000g",
        ] {
            assert_eq!(
                ShortId::parse(bad),
                Err(ModelError::InvalidShortId),
                "{bad}"
            );
        }
        assert_eq!(ShortId::from_bytes([0; 8]), Err(ModelError::InvalidShortId));
        assert!(serde_json::from_str::<ShortId>("\"0000000000000000\"").is_err());
    }

    #[test]
    fn uuid_rules() {
        let text = "6d6f6f72-0101-4001-8000-000000010101";
        let uuid = Uuid::parse(text).unwrap();
        assert_eq!(uuid.to_hyphenated().as_str(), text);
        let cases = [
            (
                "6D6F6F72-0101-4001-8000-000000010101",
                UuidRule::NotCanonical,
            ),
            ("6d6f6f72010140018000000000010101", UuidRule::NotCanonical),
            (
                "{6d6f6f72-0101-4001-8000-000000010101}",
                UuidRule::NotCanonical,
            ),
            (
                "urn:uuid:6d6f6f72-0101-4001-8000-000000010101",
                UuidRule::NotCanonical,
            ),
            (
                "6d6f6f72-0101-4001-8000-00000001010",
                UuidRule::NotCanonical,
            ),
            ("00000000-0000-0000-0000-000000000000", UuidRule::Nil),
            (
                "6d6f6f72-0101-1001-8000-000000010101",
                UuidRule::NotVersion4,
            ),
            (
                "6d6f6f72-0101-7001-8000-000000010101",
                UuidRule::NotVersion4,
            ),
            (
                "6d6f6f72-0101-4001-c000-000000010101",
                UuidRule::NotRfcVariant,
            ),
            (
                "6d6f6f72-0101-4001-0000-000000010101",
                UuidRule::NotRfcVariant,
            ),
        ];
        for (text, rule) in cases {
            assert_eq!(
                Uuid::parse(text),
                Err(ModelError::InvalidUuid { rule }),
                "{text}"
            );
        }
    }

    /// `Serde::<T>::SERIALIZE` (`DESERIALIZE`) is true exactly when `T`
    /// implements `Serialize` (`DeserializeOwned`): an inherent constant is
    /// found only when its impl's bound holds, and the trait's `false`
    /// default answers otherwise.
    struct Serde<T: ?Sized>(std::marker::PhantomData<T>);

    trait NoSerde {
        const SERIALIZE: bool = false;
        const DESERIALIZE: bool = false;
    }

    impl<T: ?Sized> NoSerde for Serde<T> {}

    impl<T: ?Sized + Serialize> Serde<T> {
        const SERIALIZE: bool = true;
    }

    impl<T: de::DeserializeOwned> Serde<T> {
        const DESERIALIZE: bool = true;
    }

    #[test]
    fn a_credential_uuid_can_be_neither_serialised_nor_deserialised() {
        // Checked at compile time: re-adding either impl fails the build of
        // the tests. Controls: the probe sees both impls of a serialisable
        // type.
        const {
            assert!(Serde::<NodeId>::SERIALIZE && Serde::<NodeId>::DESERIALIZE);
            assert!(!Serde::<Uuid>::SERIALIZE, "Uuid must not be Serialize");
            assert!(!Serde::<Uuid>::DESERIALIZE, "Uuid must not be Deserialize");
        }
        let uuid = Uuid::from_random_bytes([0x11; 16]);
        assert_eq!(format!("{uuid:?}"), "Uuid(<redacted>)");
    }

    #[test]
    fn local_label_rules() {
        for ok in ["Alice", "王小明", "a", &"x".repeat(64)] {
            assert!(LocalLabel::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            " Alice",
            "Alice ",
            "Al\nice",
            "Al\u{7}ice",
            &"x".repeat(65),
        ] {
            assert_eq!(
                LocalLabel::parse(bad),
                Err(ModelError::InvalidLabel),
                "{bad:?}"
            );
        }
    }

    proptest! {
        #[test]
        fn node_id_accepts_exactly_its_pattern(text in "[a-z0-9A-Z_-]{0,14}") {
            let expected = (2..=12).contains(&text.len())
                && text.as_bytes()[0].is_ascii_lowercase()
                && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
            prop_assert_eq!(NodeId::parse(&text).is_ok(), expected);
        }

        /// Every 40 bits make a distinct alias that decodes to itself.
        #[test]
        fn public_alias_from_bits_always_parses(bytes in proptest::array::uniform5(any::<u8>()), other in proptest::array::uniform5(any::<u8>())) {
            let alias = PublicAlias::from_random_bytes(bytes);
            prop_assert_eq!(PublicAlias::parse(alias.as_str()).unwrap(), alias.clone());
            let json = serde_json::to_string(&alias).unwrap();
            prop_assert_eq!(serde_json::from_str::<PublicAlias>(&json).unwrap(), alias.clone());
            prop_assert_eq!(PublicAlias::from_random_bytes(other) == alias, other == bytes);
        }

        #[test]
        fn user_id_from_bits_always_parses(bits in any::<u64>()) {
            let id = UserId::from_low_bits(bits);
            prop_assert_eq!(UserId::parse(id.as_str()).unwrap(), id);
        }

        #[test]
        fn short_id_round_trips(bytes in proptest::array::uniform8(any::<u8>())) {
            match ShortId::from_bytes(bytes) {
                Ok(id) => {
                    let text = id.to_string();
                    prop_assert_eq!(text.len(), 16);
                    prop_assert_eq!(ShortId::parse(&text).unwrap(), id);
                }
                Err(err) => {
                    prop_assert_eq!(bytes, [0; 8]);
                    prop_assert_eq!(err, ModelError::InvalidShortId);
                }
            }
        }

        #[test]
        fn random_uuids_are_valid_v4(bytes in proptest::array::uniform16(any::<u8>())) {
            let uuid = Uuid::from_random_bytes(bytes);
            prop_assert_eq!(Uuid::parse(&uuid.to_hyphenated()).unwrap(), uuid.clone());
            prop_assert_eq!(Uuid::from_bytes(*uuid.as_bytes()).unwrap(), uuid);
        }

        #[test]
        fn uuid_from_bytes_matches_the_uuid_crate(bytes in proptest::array::uniform16(any::<u8>())) {
            let reference = uuid::Uuid::from_bytes(bytes);
            let expected = !reference.is_nil()
                && reference.get_version_num() == 4
                && reference.get_variant() == uuid::Variant::RFC4122;
            prop_assert_eq!(Uuid::from_bytes(bytes).is_ok(), expected);
        }
    }
}
