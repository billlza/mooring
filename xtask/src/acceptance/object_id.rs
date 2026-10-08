// SPDX-License-Identifier: GPL-3.0-or-later

//! Git object ids in `contract/cfm-manifest.toml`. Like the manifest's
//! SHA-256 values (`mooring_model::digest::Sha256Digest`), they detect a
//! mistyped or wrong value (design §12, Level 1); none of them is a
//! security boundary.

use std::fmt;

use serde::Deserialize;

/// A git (SHA-1) object id: exactly 40 lowercase hexadecimal characters.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct GitObjectId(String);

/// The length of a git object id in hex characters.
const LENGTH: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a git object id ({LENGTH} lowercase hex characters)")]
pub(crate) struct ObjectIdError(String);

impl TryFrom<String> for GitObjectId {
    type Error = ObjectIdError;

    fn try_from(text: String) -> Result<Self, ObjectIdError> {
        let lower_hex = text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
        if text.len() == LENGTH && lower_hex {
            Ok(Self(text))
        } else {
            Err(ObjectIdError(text))
        }
    }
}

impl GitObjectId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{GitObjectId, ObjectIdError};

    #[test]
    fn accepts_exactly_forty_lowercase_hex_characters() {
        let id = "ac981c3b6c3284824e1018de367335aa6d69433e";
        assert_eq!(GitObjectId::try_from(id.to_owned()).unwrap().as_str(), id);
        for text in [
            "",
            "ac981c3b6c3284824e1018de367335aa6d69433",
            "ac981c3b6c3284824e1018de367335aa6d69433e0",
            "AC981C3B6C3284824E1018DE367335AA6D69433E",
            "ac981c3b6c3284824e1018de367335aa6d69433g",
            " c981c3b6c3284824e1018de367335aa6d69433e",
        ] {
            assert_eq!(
                GitObjectId::try_from(text.to_owned()),
                Err(ObjectIdError(text.to_owned())),
                "{text:?}"
            );
        }
    }
}
