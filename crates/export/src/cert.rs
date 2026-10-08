// SPDX-License-Identifier: GPL-3.0-or-later

//! A node's Hysteria2 certificate as clients see it (design §9.2): the SNI
//! and pins derived from the stored certificate, and the run-time checks
//! made at `node apply` and at every user export.
//!
//! Only the certificate is stored (`Hy2Server`), so the SNI and pins below
//! are computed from it each time and cannot disagree with it. This module
//! is the one place they are derived.
//!
//! CFM's pin verifier (`common/tls/pinning.go`, added by CFM's
//! `sing-box-v1.14.x-security-dependencies.patch`) still requires the pinned
//! leaf to be within its validity period, to match the configured server
//! name, and to permit server authentication when it lists extended key
//! usages. Each check here is that rule or a stricter one, so a certificate
//! that passes is one CFM accepts:
//!
//! | CFM (`pinning.go`) | Here |
//! |---|---|
//! | `x509.ParseCertificate` succeeds | parses with nothing trailing, else [`ExportError::CertUnparseable`] |
//! | `NotBefore <= now <= NotAfter` | `NotBefore <= now - 1 day` and `now + 1 day <= NotAfter`, else [`ExportError::CertNotCurrent`] |
//! | `VerifyHostname(server_name)` | the SAN is exactly one DNS name of the `n<16 hex>.internal` form, which becomes the SNI clients send, else [`ExportError::CertSanMismatch`] |
//! | EKU absent, or lists serverAuth or any | EKU present and lists serverAuth, else [`ExportError::CertEkuMissing`] |
//! | SHA-256 of the DER or of the raw SPKI equals a pin | both pins are those hashes of this certificate, by construction |
//!
//! The SPKI must also be the canonical uncompressed P-256 encoding, because
//! CFM hashes the raw SPKI while upstream sing-box hashes
//! `x509.MarshalPKIXPublicKey` of the parsed key
//! ([`ExportError::CertKeyUnsupported`]).

use mooring_model::{CertPins, Hy2Sni, Node, NodeId, Sha256Digest, SpkiSha256, UnixTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::error::ExportError;

/// The clock-skew margin required on each side of `now`, in seconds.
pub const CERT_SKEW_MARGIN_SECS: u64 = 86_400;

/// The DER SubjectPublicKeyInfo of an uncompressed P-256 key, up to and
/// including the `04` point-format byte (RFC 5480): SEQUENCE { SEQUENCE {
/// id-ecPublicKey, prime256v1 }, BIT STRING { 0 unused bits, 04 … } }.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
/// The length of that SPKI: the prefix plus the 64-byte point.
const P256_SPKI_LEN: usize = 91;

/// The SNI and both pins of the node's stored certificate, without the
/// time-dependent checks: what the Mac prober needs (design §8.8; the
/// certificate is checked in full at `node apply` and at user exports).
pub fn certificate_pins(node: &Node) -> Result<CertPins, ExportError> {
    let der = node.hy2.certificate.der();
    pins_of(&node.id, der, &parse(&node.id, der)?)
}

/// Checks the node's stored certificate against what CFM's pin verifier
/// enforces at `now`, and returns the SNI and pins clients use.
pub fn check_certificate(node: &Node, now: UnixTime) -> Result<CertPins, ExportError> {
    let id = &node.id;
    let der = node.hy2.certificate.der();
    let certificate = parse(id, der)?;
    let pins = pins_of(id, der, &certificate)?;
    check_validity(id, &certificate, now)?;
    check_eku(id, &certificate)?;
    Ok(pins)
}

/// Parses one DER certificate with nothing after it.
fn parse<'a>(node: &NodeId, der: &'a [u8]) -> Result<X509Certificate<'a>, ExportError> {
    match parse_x509_certificate(der) {
        Ok(([], certificate)) => Ok(certificate),
        Ok(_) | Err(_) => Err(unparseable(node)),
    }
}

fn unparseable(node: &NodeId) -> ExportError {
    ExportError::CertUnparseable { node: node.clone() }
}

/// The SNI (the one SAN) and the pins of `certificate`, whose DER is `der`.
fn pins_of(
    node: &NodeId,
    der: &[u8],
    certificate: &X509Certificate<'_>,
) -> Result<CertPins, ExportError> {
    check_key(node, certificate)?;
    let sni = san_sni(node, certificate)?;
    Ok(CertPins::new(
        sni,
        SpkiSha256::of(certificate.public_key().raw),
        Sha256Digest::of(der),
    ))
}

/// The SPKI must be the canonical P-256 encoding, so its raw bytes equal
/// their re-encoding and both client verifiers compute the same pin.
fn check_key(node: &NodeId, certificate: &X509Certificate<'_>) -> Result<(), ExportError> {
    let spki = certificate.public_key().raw;
    if spki.len() == P256_SPKI_LEN && spki.starts_with(&P256_SPKI_PREFIX) {
        Ok(())
    } else {
        Err(ExportError::CertKeyUnsupported { node: node.clone() })
    }
}

/// Validity must cover `now` with [`CERT_SKEW_MARGIN_SECS`] on each side.
fn check_validity(
    node: &NodeId,
    certificate: &X509Certificate<'_>,
    now: UnixTime,
) -> Result<(), ExportError> {
    let validity = certificate.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let at = i128::from(now.as_secs());
    let margin = i128::from(CERT_SKEW_MARGIN_SECS);
    if i128::from(not_before) <= at - margin && at + margin <= i128::from(not_after) {
        Ok(())
    } else {
        Err(ExportError::CertNotCurrent {
            node: node.clone(),
            now,
            not_before,
            not_after,
        })
    }
}

/// The SAN must be exactly one DNS name, a Hysteria2 SNI; it is the name
/// clients send and verify.
fn san_sni(node: &NodeId, certificate: &X509Certificate<'_>) -> Result<Hy2Sni, ExportError> {
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| unparseable(node))?;
    match san.map(|extension| extension.value.general_names.as_slice()) {
        Some([GeneralName::DNSName(name)]) => Hy2Sni::parse(name).map_err(|_| san_mismatch(node)),
        _ => Err(san_mismatch(node)),
    }
}

fn san_mismatch(node: &NodeId) -> ExportError {
    ExportError::CertSanMismatch { node: node.clone() }
}

/// The EKU must be present and permit serverAuth.
fn check_eku(node: &NodeId, certificate: &X509Certificate<'_>) -> Result<(), ExportError> {
    let eku = certificate
        .extended_key_usage()
        .map_err(|_| unparseable(node))?;
    if eku.is_some_and(|extension| extension.value.server_auth) {
        Ok(())
    } else {
        Err(ExportError::CertEkuMissing { node: node.clone() })
    }
}
