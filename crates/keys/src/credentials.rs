// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-user and per-node credentials: UUIDs, REALITY short ids, passwords
//! and opaque user ids (design §7).

use mooring_model::secret::Password;
use mooring_model::{Secret, ShortId, UserId, Uuid};

use crate::error::KeysError;
use crate::random::{OsRandom, RandomSource, draw};

/// A credential UUID (VLESS, loopback or probe): version 4 from 16 random
/// bytes, canonical lowercase when written.
pub fn credential_uuid() -> Result<Secret<Uuid>, KeysError> {
    credential_uuid_from(&mut OsRandom)
}

pub(crate) fn credential_uuid_from(
    source: &mut impl RandomSource,
) -> Result<Secret<Uuid>, KeysError> {
    let bytes = draw::<16>(source)?;
    Ok(Secret::new(Uuid::from_random_bytes(*bytes)))
}

/// A REALITY short id: 8 random bytes, written as 16 lowercase hex characters.
pub fn short_id() -> Result<ShortId, KeysError> {
    short_id_from(&mut OsRandom)
}

pub(crate) fn short_id_from(source: &mut impl RandomSource) -> Result<ShortId, KeysError> {
    let bytes = draw::<8>(source)?;
    ShortId::from_bytes(*bytes).map_err(KeysError::MaterialRejected)
}

/// A Hysteria2 user or probe password, or a salamander obfuscation
/// password: 32 random bytes whose unpadded base64url text (43 characters)
/// is the password.
pub fn password() -> Result<Password, KeysError> {
    password_from(&mut OsRandom)
}

pub(crate) fn password_from(source: &mut impl RandomSource) -> Result<Password, KeysError> {
    let bytes = draw::<32>(source)?;
    Password::from_bytes(*bytes).map_err(KeysError::MaterialRejected)
}

/// An opaque user id: 50 random bits as 10 lowercase base32 characters.
///
/// The caller still checks the new id against the deployment's users, which
/// refuses a duplicate.
pub fn user_id() -> Result<UserId, KeysError> {
    user_id_from(&mut OsRandom)
}

pub(crate) fn user_id_from(source: &mut impl RandomSource) -> Result<UserId, KeysError> {
    let bytes = draw::<8>(source)?;
    Ok(UserId::from_low_bits(u64::from_be_bytes(*bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeysErrorKind;
    use crate::testing::{CountingRandom, FailingRandom, ReplayRandom, ZeroRandom};
    use mooring_model::ModelError;
    use mooring_model::secret::SecretKind;

    #[test]
    fn uuids_are_canonical_version_4() {
        let uuid = credential_uuid_from(&mut ReplayRandom::new(&[0xff; 16])).unwrap();
        // Version nibble 4 and variant bits 10 are forced over the random bytes.
        assert_eq!(
            *uuid.expose_secret().to_hyphenated(),
            "ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
        let uuid = credential_uuid_from(&mut ZeroRandom).unwrap();
        assert_eq!(
            *uuid.expose_secret().to_hyphenated(),
            "00000000-0000-4000-8000-000000000000"
        );

        let generated = credential_uuid().unwrap();
        let text = generated.expose_secret().to_hyphenated();
        let parsed = uuid::Uuid::parse_str(&text).unwrap();
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
        assert_eq!(parsed.hyphenated().to_string(), *text);
        assert_eq!(text.to_lowercase(), *text);
        assert_eq!(Uuid::parse(&text).unwrap(), *generated.expose_secret());
        assert_ne!(credential_uuid().unwrap(), generated);
    }

    #[test]
    fn short_ids_are_16_lowercase_hex() {
        let id = short_id_from(&mut CountingRandom::starting_at(0xa8)).unwrap();
        assert_eq!(id.to_string(), "a8a9aaabacadaeaf");
        let generated = short_id().unwrap();
        let text = generated.to_string();
        assert_eq!(text.len(), 16);
        assert!(
            text.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(short_id().unwrap(), generated);
    }

    #[test]
    fn passwords_are_43_base64url_characters() {
        let fixed = password_from(&mut ReplayRandom::new(&[0xfb; 32])).unwrap();
        assert_eq!(
            *fixed.expose_text(),
            "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s"
        );
        let generated = password().unwrap();
        let text = generated.expose_text();
        assert_eq!(text.len(), 43);
        assert!(
            text.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_ne!(password().unwrap(), generated);
    }

    #[test]
    fn user_ids_take_the_low_50_bits() {
        let id = user_id_from(&mut ReplayRandom::new(&[0xff; 8])).unwrap();
        assert_eq!(id.as_str(), "7777777777");
        // The top 14 bits are discarded: 0x0003_ffff_ffff_ffff has the same
        // low 50 bits as all ones.
        let id = user_id_from(&mut ReplayRandom::new(&[
            0x00, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]))
        .unwrap();
        assert_eq!(id.as_str(), "7777777777");
        let id = user_id_from(&mut ReplayRandom::new(&[0, 0, 0, 0, 0, 0, 0, 33])).unwrap();
        assert_eq!(id.as_str(), "aaaaaaaabb");
        let generated = user_id().unwrap();
        assert!(UserId::parse(generated.as_str()).is_ok());
        assert_ne!(user_id().unwrap(), generated);
    }

    #[test]
    fn an_all_zero_draw_is_rejected_not_used() {
        assert_eq!(
            short_id_from(&mut ZeroRandom),
            Err(KeysError::MaterialRejected(ModelError::InvalidShortId))
        );
        assert_eq!(
            password_from(&mut ZeroRandom),
            Err(KeysError::MaterialRejected(ModelError::InvalidSecret {
                kind: SecretKind::Password
            }))
        );
        assert_eq!(
            short_id_from(&mut ZeroRandom).unwrap_err().kind(),
            KeysErrorKind::MaterialRejected
        );
    }

    #[test]
    fn entropy_failure_is_reported_by_every_generator() {
        let kinds = [
            credential_uuid_from(&mut FailingRandom).unwrap_err().kind(),
            short_id_from(&mut FailingRandom).unwrap_err().kind(),
            password_from(&mut FailingRandom).unwrap_err().kind(),
            user_id_from(&mut FailingRandom).unwrap_err().kind(),
        ];
        assert_eq!(kinds, [KeysErrorKind::Entropy; 4]);
    }
}
