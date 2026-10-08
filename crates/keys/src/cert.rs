// SPDX-License-Identifier: GPL-3.0-or-later

//! The per-node Hysteria2 certificate (design §7 "Hysteria2 certificate").
//!
//! The certificate is ECDSA P-256, self-signed, with a critical
//! `basicConstraints` of `CA:FALSE`, a critical `keyUsage` of
//! `digitalSignature`, `extendedKeyUsage` `serverAuth`, subject
//! `CN=<sni>` and the single SAN `DNS:<sni>`. It is valid from one day
//! before the issue time for 3650 days after it, and is never re-issued.
//!
//! The SubjectPublicKeyInfo is written in the canonical form sing-box hashes
//! (`x509.MarshalPKIXPublicKey`, sing-box v1.14.2
//! `common/tls/std_client.go:278-295`). The client pins are a function of
//! the certificate and are derived from it where they are used
//! (`mooring-export`'s `certificate_pins`); nothing here stores them.

use mooring_model::secret::Hy2KeyPem;
use mooring_model::{CertificatePem, Hy2Sni, UnixTime};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use x509_parser::time::ASN1Time;

use crate::error::{CertStep, KeysError};
use crate::random::{OsRandom, RandomSource, draw};

/// How long before the issue time the certificate becomes valid: one day.
const CERT_BACKDATE_SECS: u64 = 86_400;
/// How long after the issue time the certificate stays valid: 3650 days.
const CERT_LIFETIME_SECS: u64 = 3_650 * 86_400;
/// 9999-12-31T23:59:59Z, the last instant an X.509 `GeneralizedTime`
/// (four-digit year) can express.
const X509_MAX_SECS: u64 = 253_402_300_799;

/// A node's Hysteria2 certificate, its private key and the SNI it was issued
/// for (its one SAN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2Certificate {
    certificate: CertificatePem,
    key: Hy2KeyPem,
    sni: Hy2Sni,
}

impl Hy2Certificate {
    /// Issues a new certificate at `now` (the caller's clock; this crate
    /// never reads one). The SNI comes from the operating system's random
    /// source and the P-256 key from `ring`'s system random source.
    pub fn generate(now: UnixTime) -> Result<Self, KeysError> {
        Self::generate_from(&mut OsRandom, now)
    }

    pub(crate) fn generate_from(
        source: &mut impl RandomSource,
        now: UnixTime,
    ) -> Result<Self, KeysError> {
        let validity = Validity::issued_at(now)?;
        let sni = Hy2Sni::from_bytes(*draw::<8>(source)?);
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(cert_build(CertStep::KeyGeneration))?;
        let certificate = certificate_params(&sni, &validity)?
            .self_signed(&key_pair)
            .map_err(cert_build(CertStep::Signing))?;
        Ok(Self {
            certificate: CertificatePem::from_der(certificate.der().as_ref())
                .map_err(KeysError::MaterialRejected)?,
            key: Hy2KeyPem::from_der(key_pair.serialized_der())
                .map_err(KeysError::MaterialRejected)?,
            sni,
        })
    }

    /// The certificate as one canonical PEM block.
    #[must_use]
    pub const fn certificate(&self) -> &CertificatePem {
        &self.certificate
    }

    /// The unencrypted PKCS#8 private key.
    #[must_use]
    pub const fn key(&self) -> &Hy2KeyPem {
        &self.key
    }

    /// The SNI the certificate was issued for: its only SAN and subject CN.
    #[must_use]
    pub const fn sni(&self) -> &Hy2Sni {
        &self.sni
    }

    /// Splits the certificate into its stored part and its secret key.
    #[must_use]
    pub fn into_parts(self) -> (CertificatePem, Hy2KeyPem) {
        (self.certificate, self.key)
    }
}

/// The validity window of a certificate issued at a given time, checked to
/// be encodable in X.509.
#[derive(Debug)]
struct Validity {
    not_before_x509: ASN1Time,
    not_after_x509: ASN1Time,
}

impl Validity {
    fn issued_at(now: UnixTime) -> Result<Self, KeysError> {
        let out_of_range = || KeysError::CertValidity { now };
        let not_before = now
            .checked_sub_secs(CERT_BACKDATE_SECS)
            .ok_or_else(out_of_range)?;
        let not_after = now
            .checked_add_secs(CERT_LIFETIME_SECS)
            .ok_or_else(out_of_range)?;
        Ok(Self {
            not_before_x509: x509_time(not_before).ok_or_else(out_of_range)?,
            not_after_x509: x509_time(not_after).ok_or_else(out_of_range)?,
        })
    }
}

/// Converts Unix seconds into the date-time type `rcgen` takes, or `None`
/// past the last instant X.509 can encode.
///
/// `x509-parser`'s `ASN1Time` gives a fallible conversion into `rcgen`'s
/// `time::OffsetDateTime`, so this crate needs no direct `time` dependency.
/// With `time`'s default range that conversion also fails after year 9999;
/// the explicit bound keeps the X.509 rule independent of that feature set,
/// because `rcgen`'s encoder (`yasna` 0.6 `GeneralizedTime::from_datetime`)
/// asserts a four-digit year and would panic on a later one.
fn x509_time(time: UnixTime) -> Option<ASN1Time> {
    if time.as_secs() > X509_MAX_SECS {
        return None;
    }
    let seconds = i64::try_from(time.as_secs()).ok()?;
    ASN1Time::from_timestamp(seconds).ok()
}

fn certificate_params(sni: &Hy2Sni, validity: &Validity) -> Result<CertificateParams, KeysError> {
    let mut params = CertificateParams::new(vec![sni.as_str().to_owned()])
        .map_err(cert_build(CertStep::Parameters))?;
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, sni.as_str());
    params.distinguished_name = subject;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = validity.not_before_x509.to_datetime();
    params.not_after = validity.not_after_x509.to_datetime();
    Ok(params)
}

fn cert_build(step: CertStep) -> impl FnOnce(rcgen::Error) -> KeysError {
    move |source| KeysError::CertBuild { step, source }
}

#[cfg(test)]
mod tests;
