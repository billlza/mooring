// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeSet;

use rcgen::PublicKeyData as _;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256,
    OID_X509_EXT_BASIC_CONSTRAINTS, OID_X509_EXT_EXTENDED_KEY_USAGE, OID_X509_EXT_KEY_USAGE,
    OID_X509_EXT_SUBJECT_ALT_NAME, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};
use x509_parser::prelude::{FromDer as _, GeneralName, X509Certificate, X509Version};

use super::*;
use crate::error::KeysErrorKind;
use crate::testing::{CountingRandom, FailingRandom};

#[cfg(target_os = "macos")]
mod tools;

/// 2026-10-08T00:00:00Z.
const NOW: UnixTime = UnixTime::from_secs(1_791_417_600);

/// The DER prefix of a P-256 SubjectPublicKeyInfo in the canonical form Go's
/// `x509.MarshalPKIXPublicKey` and OpenSSL write: SEQUENCE { SEQUENCE {
/// id-ecPublicKey, prime256v1 }, BIT STRING (65 bytes, uncompressed point) }.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

fn parse(certificate: &Hy2Certificate) -> X509Certificate<'_> {
    let (rest, parsed) = X509Certificate::from_der(certificate.certificate().der()).unwrap();
    assert!(rest.is_empty());
    parsed
}

#[test]
fn every_certificate_property_holds_when_reparsed() {
    let generated = Hy2Certificate::generate(NOW).unwrap();
    let sni = generated.sni().as_str().to_owned();
    let cert = parse(&generated);

    assert_eq!(cert.version(), X509Version::V3);
    assert_eq!(
        cert.signature_algorithm.algorithm,
        OID_SIG_ECDSA_WITH_SHA256
    );
    assert_eq!(
        cert.tbs_certificate.signature.algorithm,
        OID_SIG_ECDSA_WITH_SHA256
    );
    cert.verify_signature(None).unwrap();

    // Self-signed, subject CN=<sni>.
    assert_eq!(cert.subject(), cert.issuer());
    let names: Vec<&str> = cert
        .subject()
        .iter_common_name()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert_eq!(names, [sni.as_str()]);
    assert_eq!(cert.subject().iter().count(), 1);

    // ECDSA P-256 in the canonical SPKI encoding.
    let spki = cert.public_key();
    assert_eq!(spki.algorithm.algorithm, OID_KEY_TYPE_EC_PUBLIC_KEY);
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .unwrap()
        .as_oid()
        .unwrap();
    assert_eq!(curve, OID_EC_P256);
    assert_eq!(spki.raw.len(), 91);
    assert_eq!(&spki.raw[..27], P256_SPKI_PREFIX);

    // CA:FALSE, present and critical.
    let basic = cert.basic_constraints().unwrap().unwrap();
    assert!(basic.critical);
    assert!(!basic.value.ca);
    assert_eq!(basic.value.path_len_constraint, None);
    assert!(!cert.is_ca());

    // keyUsage digitalSignature only, critical.
    let key_usage = cert.key_usage().unwrap().unwrap();
    assert!(key_usage.critical);
    assert!(key_usage.value.digital_signature());
    assert_eq!(key_usage.value.flags, 1);

    // extendedKeyUsage serverAuth only.
    let eku = cert.extended_key_usage().unwrap().unwrap();
    assert!(eku.value.server_auth);
    assert!(
        !(eku.value.any
            || eku.value.client_auth
            || eku.value.code_signing
            || eku.value.email_protection
            || eku.value.time_stamping
            || eku.value.ocsp_signing)
    );
    assert!(eku.value.other.is_empty());

    // Exactly one SAN, DNS:<sni>, which is also the pinned SNI.
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert!(!san.critical);
    assert_eq!(
        san.value.general_names,
        [GeneralName::DNSName(sni.as_str())]
    );
    assert!(sni.starts_with('n') && sni.ends_with(".internal") && sni.len() == 26);

    // No extension beyond the five expected ones.
    let extensions: BTreeSet<String> = cert
        .extensions()
        .iter()
        .map(|extension| extension.oid.to_id_string())
        .collect();
    let expected: BTreeSet<String> = [
        OID_X509_EXT_SUBJECT_ALT_NAME,
        OID_X509_EXT_KEY_USAGE,
        OID_X509_EXT_EXTENDED_KEY_USAGE,
        OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
        OID_X509_EXT_BASIC_CONSTRAINTS,
    ]
    .iter()
    .map(|oid| oid.to_id_string())
    .collect();
    assert_eq!(extensions, expected);

    // notBefore = now - 1 day, notAfter = now + 3650 days.
    let validity = cert.validity();
    assert_eq!(
        validity.not_before.timestamp(),
        i64::try_from(NOW.as_secs() - 86_400).unwrap()
    );
    assert_eq!(
        validity.not_after.timestamp(),
        i64::try_from(NOW.as_secs() + 3_650 * 86_400).unwrap()
    );
}

#[test]
fn key_and_certificate_are_canonical_pem_and_belong_together() {
    let generated = Hy2Certificate::generate(NOW).unwrap();
    let pem = generated.certificate().as_str();
    assert_eq!(
        CertificatePem::parse(pem).unwrap(),
        *generated.certificate()
    );
    let key = generated.key();
    assert_eq!(Hy2KeyPem::parse(key.expose_pem()).unwrap(), *key);

    let reloaded = KeyPair::from_pem(key.expose_pem()).unwrap();
    assert_eq!(
        reloaded.subject_public_key_info(),
        parse(&generated).public_key().raw
    );
    assert!(reloaded.is_compatible(&PKCS_ECDSA_P256_SHA256));

    let (certificate, key) = generated.clone().into_parts();
    assert_eq!(&certificate, generated.certificate());
    assert_eq!(&key, generated.key());
}

#[test]
fn the_sni_comes_from_the_random_source() {
    let generated =
        Hy2Certificate::generate_from(&mut CountingRandom::starting_at(1), NOW).unwrap();
    assert_eq!(generated.sni().as_str(), "n0102030405060708.internal");
}

#[test]
fn every_certificate_is_new() {
    let first = Hy2Certificate::generate(NOW).unwrap();
    let second = Hy2Certificate::generate(NOW).unwrap();
    assert_ne!(first.sni(), second.sni());
    assert_ne!(first.certificate(), second.certificate());
    assert_ne!(
        parse(&first).public_key().raw,
        parse(&second).public_key().raw
    );
    assert_ne!(first.key(), second.key());
}

#[test]
fn the_validity_window_must_fit_x509() {
    let rejected = |now: u64| {
        let now = UnixTime::from_secs(now);
        assert_eq!(
            Hy2Certificate::generate(now),
            Err(KeysError::CertValidity { now }),
            "{now}"
        );
    };
    // notBefore would precede the Unix epoch.
    rejected(0);
    rejected(86_399);
    // notAfter would pass 9999-12-31T23:59:59Z, or overflow.
    let latest = X509_MAX_SECS - CERT_LIFETIME_SECS;
    rejected(latest + 1);
    rejected(u64::MAX);

    let earliest = Hy2Certificate::generate(UnixTime::from_secs(86_400)).unwrap();
    assert_eq!(parse(&earliest).validity().not_before.timestamp(), 0);

    let last = Hy2Certificate::generate(UnixTime::from_secs(latest)).unwrap();
    assert_eq!(
        parse(&last).validity().not_after.timestamp(),
        i64::try_from(X509_MAX_SECS).unwrap()
    );

    assert_eq!(
        Hy2Certificate::generate(UnixTime::from_secs(0))
            .unwrap_err()
            .kind(),
        KeysErrorKind::CertValidity
    );
}

#[test]
fn entropy_failure_is_reported_before_any_key_is_made() {
    assert_eq!(
        Hy2Certificate::generate_from(&mut FailingRandom, NOW),
        Err(KeysError::Entropy(getrandom::Error::UNSUPPORTED))
    );
}

#[test]
fn debug_never_shows_the_private_key() {
    let generated = Hy2Certificate::generate(NOW).unwrap();
    let debug = format!("{generated:?}");
    let body = generated.key().expose_lines().nth(1).unwrap().to_owned();
    assert!(!debug.contains(&body));
    assert!(debug.contains("<redacted>"));
}
