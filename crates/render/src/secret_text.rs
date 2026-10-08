// SPDX-License-Identifier: GPL-3.0-or-later

//! The serde bridge for secret material inside rendered configs.
//!
//! Model secrets have no `Serialize` by design; a rendered config is the one
//! place a secret must become text. [`Rendered`] holds the typed,
//! zeroize-on-drop material, writes its canonical text only while a config
//! is serialised, re-validates it through the model parser when a golden is
//! read back, and prints `<redacted>` under `Debug`.

use std::fmt;

use mooring_model::ModelError;
use mooring_model::ids::Uuid;
use mooring_model::secret::{Password, RealityPrivateKey, Secret, WgPrivateKey};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// A secret material type with one canonical text form.
pub(crate) trait SecretText: Sized {
    /// The canonical text.
    fn text(&self) -> Zeroizing<String>;

    /// Parses the canonical text.
    fn parse_text(text: &str) -> Result<Self, ModelError>;
}

impl SecretText for RealityPrivateKey {
    fn text(&self) -> Zeroizing<String> {
        self.expose_text()
    }

    fn parse_text(text: &str) -> Result<Self, ModelError> {
        Self::parse(text)
    }
}

impl SecretText for WgPrivateKey {
    fn text(&self) -> Zeroizing<String> {
        self.expose_text()
    }

    fn parse_text(text: &str) -> Result<Self, ModelError> {
        Self::parse(text)
    }
}

impl SecretText for Password {
    fn text(&self) -> Zeroizing<String> {
        self.expose_text()
    }

    fn parse_text(text: &str) -> Result<Self, ModelError> {
        Self::parse(text)
    }
}

impl SecretText for Secret<Uuid> {
    fn text(&self) -> Zeroizing<String> {
        self.expose_secret().to_hyphenated()
    }

    fn parse_text(text: &str) -> Result<Self, ModelError> {
        Uuid::parse(text).map(Secret::new)
    }
}

/// Secret material as a string in a rendered config.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Rendered<T>(T);

impl<T> Rendered<T> {
    pub(crate) const fn new(secret: T) -> Self {
        Self(secret)
    }

    #[cfg(test)]
    pub(crate) const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Rendered<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T: SecretText> Serialize for Rendered<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.text())
    }
}

impl<'de, T: SecretText> Deserialize<'de> for Rendered<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        T::parse_text(&text).map(Self).map_err(de::Error::custom)
    }
}

/// Text that is written as its lines, without line endings: sing-box's
/// inline `certificate` and `key` lists (`option/tls.go:22,28`), which
/// sing-box joins with `\n` (`common/tls/std_server.go:406-416`).
pub(crate) trait PemText: Sized {
    /// The PEM text, one block ending with a newline.
    fn pem(&self) -> &str;

    /// Parses one canonical PEM block.
    fn parse_pem(text: &str) -> Result<Self, ModelError>;
}

impl PemText for mooring_model::cert::CertificatePem {
    fn pem(&self) -> &str {
        self.as_str()
    }

    fn parse_pem(text: &str) -> Result<Self, ModelError> {
        Self::parse(text)
    }
}

impl PemText for mooring_model::secret::Hy2KeyPem {
    fn pem(&self) -> &str {
        self.expose_pem()
    }

    fn parse_pem(text: &str) -> Result<Self, ModelError> {
        Self::parse(text)
    }
}

/// A PEM block as the list of its lines. Debug never prints the text, so
/// the same wrapper carries the Hysteria2 key.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PemLines<T>(T);

impl<T> PemLines<T> {
    pub(crate) const fn new(pem: T) -> Self {
        Self(pem)
    }
}

impl<T> fmt::Debug for PemLines<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<pem lines>")
    }
}

impl<T: PemText> Serialize for PemLines<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.pem().lines())
    }
}

impl<'de, T: PemText> Deserialize<'de> for PemLines<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(PemLinesVisitor(std::marker::PhantomData))
    }
}

struct PemLinesVisitor<T>(std::marker::PhantomData<T>);

impl<'de, T: PemText> Visitor<'de> for PemLinesVisitor<T> {
    type Value = PemLines<T>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the lines of one PEM block")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        // Each line moves into a zeroizing buffer without a copy; the joined
        // text is sized once, so no reallocation leaves key bytes behind.
        let mut lines: Vec<Zeroizing<String>> = Vec::new();
        while let Some(line) = seq.next_element::<String>()? {
            lines.push(Zeroizing::new(line));
        }
        let len = lines.iter().map(|line| line.len() + 1).sum();
        let mut text = Zeroizing::new(String::with_capacity(len));
        for line in &lines {
            text.push_str(line);
            text.push('\n');
        }
        T::parse_pem(&text).map(PemLines).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_secrets_round_trip_and_never_debug_print() {
        let password = Password::from_bytes([7; 32]).unwrap();
        let text = password.expose_text();
        let rendered = Rendered::new(password);
        let json = serde_json::to_string(&rendered).unwrap();
        assert_eq!(json, format!("\"{}\"", text.as_str()));
        assert_eq!(format!("{rendered:?}"), "<redacted>");
        let back: Rendered<Password> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rendered);
        assert!(serde_json::from_str::<Rendered<Password>>("\"short\"").is_err());
        let uuid = Rendered::new(Secret::new(Uuid::from_random_bytes([3; 16])));
        let json = serde_json::to_string(&uuid).unwrap();
        let back: Rendered<Secret<Uuid>> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, uuid);
    }
}
