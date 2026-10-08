// SPDX-License-Identifier: GPL-3.0-or-later

//! The Hysteria2 certificate: canonical PEM, its SNI and its pins
//! (design §7 "Hysteria2 certificate").
//!
//! The model cannot parse X.509: `mooring-keys` issues the certificate, and
//! `mooring-export` derives the SNI and pins from it and checks validity,
//! SAN and EKU at run time (design §9.2).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::digest::{Sha256Digest, SpkiSha256};
use crate::encoding::{decode_hex_lower, encode_hex_lower};
use crate::error::ModelError;

/// The label of a PEM block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PemLabel {
    /// `CERTIFICATE`: an X.509 certificate in DER.
    Certificate,
    /// `PRIVATE KEY`: an unencrypted PKCS#8 private key in DER.
    PrivateKey,
}

impl PemLabel {
    /// The label text between `BEGIN`/`END` and the dashes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "CERTIFICATE",
            Self::PrivateKey => "PRIVATE KEY",
        }
    }
}

impl fmt::Display for PemLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The largest PEM block accepted, far above a P-256 certificate or key.
pub const MAX_PEM_BYTES: usize = 16 * 1024;
/// The number of base64 characters per PEM body line.
const PEM_LINE_LEN: usize = 64;

/// Encodes `der` as one canonical PEM block: 64-character lines, LF line
/// endings and a trailing newline, as OpenSSL and rcgen write it.
pub(crate) fn pem_encode(label: PemLabel, der: &[u8]) -> Zeroizing<String> {
    let body = Zeroizing::new(STANDARD.encode(der));
    let mut text = Zeroizing::new(String::with_capacity(
        body.len() + body.len() / PEM_LINE_LEN + 64,
    ));
    text.push_str("-----BEGIN ");
    text.push_str(label.as_str());
    text.push_str("-----\n");
    for (position, symbol) in body.chars().enumerate() {
        if position > 0 && position % PEM_LINE_LEN == 0 {
            text.push('\n');
        }
        text.push(symbol);
    }
    if !body.is_empty() {
        text.push('\n');
    }
    text.push_str("-----END ");
    text.push_str(label.as_str());
    text.push_str("-----\n");
    text
}

/// Decodes one canonical PEM block; any other spelling is rejected.
pub(crate) fn pem_decode(label: PemLabel, text: &str) -> Result<Zeroizing<Vec<u8>>, ModelError> {
    let invalid = ModelError::InvalidPem { label };
    if text.len() > MAX_PEM_BYTES {
        return Err(invalid);
    }
    let begin = format!("-----BEGIN {label}-----\n");
    let end = format!("-----END {label}-----\n");
    let body = text
        .strip_prefix(begin.as_str())
        .and_then(|rest| rest.strip_suffix(end.as_str()))
        .ok_or_else(|| invalid.clone())?;
    let joined = Zeroizing::new(body.split('\n').collect::<String>());
    let der = Zeroizing::new(
        STANDARD
            .decode(joined.as_bytes())
            .map_err(|_| invalid.clone())?,
    );
    if der.is_empty() || pem_encode(label, &der).as_str() != text {
        return Err(invalid);
    }
    Ok(der)
}

/// A self-signed X.509 certificate as one canonical PEM block. Public data.
///
/// The DER bytes are decoded once at construction and kept beside the text.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CertificatePem {
    pem: String,
    der: Vec<u8>,
}

impl CertificatePem {
    /// Accepts one canonical `CERTIFICATE` PEM block.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let der = pem_decode(PemLabel::Certificate, text)?;
        Ok(Self {
            pem: text.to_owned(),
            der: der.to_vec(),
        })
    }

    /// Wraps non-empty DER bytes in a canonical PEM block.
    pub fn from_der(der: &[u8]) -> Result<Self, ModelError> {
        if der.is_empty() {
            return Err(ModelError::InvalidPem {
                label: PemLabel::Certificate,
            });
        }
        Ok(Self {
            pem: pem_encode(PemLabel::Certificate, der).to_string(),
            der: der.to_vec(),
        })
    }

    /// The PEM text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pem
    }

    /// The PEM lines without line endings, as sing-box's `certificate` list takes them.
    pub fn lines(&self) -> std::str::Lines<'_> {
        self.pem.lines()
    }

    /// The DER bytes.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

impl TryFrom<String> for CertificatePem {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let der = pem_decode(PemLabel::Certificate, &text)?;
        Ok(Self {
            pem: text,
            der: der.to_vec(),
        })
    }
}

impl From<CertificatePem> for String {
    fn from(certificate: CertificatePem) -> Self {
        certificate.pem
    }
}

/// The Hysteria2 SNI and certificate SAN: `n<16 lowercase hex>.internal`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Hy2Sni(String);

impl Hy2Sni {
    /// The fixed suffix of every Hysteria2 SNI.
    pub const SUFFIX: &'static str = ".internal";

    /// Builds the SNI for 8 random bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(format!("n{}{}", encode_hex_lower(&bytes), Self::SUFFIX))
    }

    /// Parses `n<16 lowercase hex>.internal`.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let hex = text
            .strip_prefix('n')
            .and_then(|rest| rest.strip_suffix(Self::SUFFIX))
            .ok_or(ModelError::InvalidHy2Sni)?;
        let bytes = decode_hex_lower::<8>(hex).ok_or(ModelError::InvalidHy2Sni)?;
        Ok(Self::from_bytes(bytes))
    }

    /// The SNI as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Hy2Sni {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<Hy2Sni> for String {
    fn from(sni: Hy2Sni) -> Self {
        sni.0
    }
}

impl FromStr for Hy2Sni {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for Hy2Sni {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What clients pin for a node's Hysteria2 certificate: the SNI (the
/// certificate's one DNS SAN), the SPKI pin and the DER pin.
///
/// Pins are a function of the certificate, so they are never stored beside
/// it: `mooring-export` derives them from the stored certificate each time
/// (`certificate_pins`), and a certificate and its pins cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertPins {
    sni: Hy2Sni,
    spki_sha256: SpkiSha256,
    der_sha256: Sha256Digest,
}

impl CertPins {
    /// Collects the SNI and pins derived from one certificate.
    #[must_use]
    pub const fn new(sni: Hy2Sni, spki_sha256: SpkiSha256, der_sha256: Sha256Digest) -> Self {
        Self {
            sni,
            spki_sha256,
            der_sha256,
        }
    }

    /// The SNI, which is also the certificate's only SAN.
    #[must_use]
    pub const fn sni(&self) -> &Hy2Sni {
        &self.sni
    }

    /// SHA-256 of the SubjectPublicKeyInfo (sing-box pin).
    #[must_use]
    pub const fn spki_sha256(&self) -> SpkiSha256 {
        self.spki_sha256
    }

    /// SHA-256 of the certificate DER (Clash `fingerprint`).
    #[must_use]
    pub const fn der_sha256(&self) -> Sha256Digest {
        self.der_sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn pem_round_trip_and_canonical_form() {
        let der: Vec<u8> = (0..=200).collect();
        let pem = CertificatePem::from_der(&der).unwrap();
        assert!(pem.as_str().starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.as_str().ends_with("-----END CERTIFICATE-----\n"));
        assert!(pem.lines().skip(1).take(4).all(|line| line.len() == 64));
        assert_eq!(pem.der(), der.as_slice());
        assert_eq!(CertificatePem::parse(pem.as_str()).unwrap(), pem);
    }

    #[test]
    fn non_canonical_pem_is_rejected() {
        let pem = CertificatePem::from_der(&[7_u8; 100]).unwrap();
        let invalid = Err(ModelError::InvalidPem {
            label: PemLabel::Certificate,
        });
        let text = pem.as_str();
        assert_eq!(CertificatePem::parse(&text.replace('\n', "\r\n")), invalid);
        assert_eq!(CertificatePem::parse(text.trim_end()), invalid);
        assert_eq!(CertificatePem::parse(&format!("{text}{text}")), invalid);
        assert_eq!(
            CertificatePem::parse(&text.replace("CERTIFICATE", "PRIVATE KEY")),
            invalid
        );
        // Re-wrapping at 76 columns is valid base64 but not canonical PEM.
        let body: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let rewrapped = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n{}\n-----END CERTIFICATE-----\n",
            &body[..76],
            &body[76..]
        );
        assert_eq!(CertificatePem::parse(&rewrapped), invalid);
        assert_eq!(
            CertificatePem::parse("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
            invalid
        );
        assert_eq!(CertificatePem::from_der(&[]), invalid);
        assert!(serde_json::from_str::<CertificatePem>("\"not pem\"").is_err());
    }

    #[test]
    fn hy2_sni_rules() {
        let sni = Hy2Sni::parse("n6c6f6e3100000001.internal").unwrap();
        assert_eq!(sni.as_str(), "n6c6f6e3100000001.internal");
        for bad in [
            "n6c6f6e310000001.internal",
            "n6C6f6e3100000001.internal",
            "m6c6f6e3100000001.internal",
            "n6c6f6e3100000001.internal.",
            "n6c6f6e3100000001.local",
        ] {
            assert_eq!(Hy2Sni::parse(bad), Err(ModelError::InvalidHy2Sni), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn pem_round_trips_any_der(der in proptest::collection::vec(any::<u8>(), 1..2048)) {
            let pem = CertificatePem::from_der(&der).unwrap();
            prop_assert_eq!(pem.der(), der.as_slice());
        }

        #[test]
        fn hy2_sni_round_trips(bytes in proptest::array::uniform8(any::<u8>())) {
            let sni = Hy2Sni::from_bytes(bytes);
            prop_assert_eq!(Hy2Sni::parse(sni.as_str()).unwrap(), sni);
        }
    }
}
