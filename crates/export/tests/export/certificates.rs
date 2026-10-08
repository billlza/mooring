// SPDX-License-Identifier: GPL-3.0-or-later

//! The certificate's derived SNI and pins and the run-time checks (design
//! §9.2), against certificates made by `mooring-keys`, the fixtures'
//! OpenSSL certificates, and certificates with single DER bytes changed to
//! break exactly one property.

use mooring_export::{
    CERT_SKEW_MARGIN_SECS, ExportError, ExportErrorKind, ExportFormat, certificate_pins,
    check_certificate, export_user,
};
use mooring_fixtures::{FIXTURE_NOW, recorded_pins};
use mooring_keys::Hy2Certificate;
use mooring_model::{CertPins, CertificatePem, Hy2Server, Hy2Sni, Node, UnixTime};
use sha2::{Digest as _, Sha256};

use crate::support::{edited, first_user, fixtures, node, two_nodes};

/// A fixture node with its Hysteria2 certificate replaced.
fn with_certificate(certificate: CertificatePem) -> Node {
    let fixture = two_nodes();
    let mut node = fixture.deployment.node(&node("lon1")).unwrap().clone();
    node.hy2 = Hy2Server { certificate };
    node
}

/// A certificate issued by `mooring-keys` at `issued`, with its SNI.
fn generated(issued: UnixTime) -> (CertificatePem, Hy2Sni) {
    let generated = Hy2Certificate::generate(issued).unwrap();
    let sni = generated.sni().clone();
    (generated.into_parts().0, sni)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The pins of `der` computed here, independently of the crate under test.
fn expected_pins(der: &[u8], sni: Hy2Sni) -> CertPins {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).unwrap();
    CertPins::new(
        sni,
        mooring_model::SpkiSha256::from_bytes(sha256(parsed.public_key().raw)),
        mooring_model::Sha256Digest::from_bytes(sha256(der)),
    )
}

/// The validity window of `der` in Unix seconds.
fn validity(der: &[u8]) -> (u64, u64) {
    let (_, parsed) = x509_parser::parse_x509_certificate(der).unwrap();
    let window = parsed.validity();
    (
        u64::try_from(window.not_before.timestamp()).unwrap(),
        u64::try_from(window.not_after.timestamp()).unwrap(),
    )
}

/// `der` with the single occurrence of `from` replaced by `to`.
fn patched(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let positions: Vec<_> = der
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(positions.len(), 1, "exactly one occurrence");
    let mut out = der.to_vec();
    out[positions[0]..positions[0] + to.len()].copy_from_slice(to);
    out
}

/// A generated certificate with one DER change.
fn tampered(from: &[u8], to: &[u8]) -> Node {
    let (certificate, _) = generated(FIXTURE_NOW);
    let der = patched(certificate.der(), from, to);
    with_certificate(CertificatePem::from_der(&der).unwrap())
}

fn kind(node: &Node, now: UnixTime) -> ExportErrorKind {
    check_certificate(node, now).unwrap_err().kind()
}

#[test]
fn fixture_certificates_pass_and_derive_the_pins_openssl_recorded() {
    for fixture in fixtures() {
        for node in fixture.deployment.nodes().values() {
            let recorded = recorded_pins(&node.id).unwrap();
            assert_eq!(certificate_pins(node).unwrap(), recorded, "{}", node.id);
            assert_eq!(
                check_certificate(node, FIXTURE_NOW).unwrap(),
                recorded,
                "{}",
                node.id
            );
        }
    }
}

#[test]
fn the_pins_are_the_hashes_of_the_stored_certificate_and_its_san() {
    for _ in 0..4 {
        let (certificate, sni) = generated(FIXTURE_NOW);
        let node = with_certificate(certificate.clone());
        let expected = expected_pins(certificate.der(), sni);
        assert_eq!(certificate_pins(&node).unwrap(), expected);
        assert_eq!(check_certificate(&node, FIXTURE_NOW).unwrap(), expected);
    }
}

#[test]
fn validity_must_cover_now_with_a_day_of_margin() {
    let issued = FIXTURE_NOW;
    let (certificate, _) = generated(issued);
    let (not_before, not_after) = validity(certificate.der());
    let node = with_certificate(certificate);
    let at = |secs: u64| UnixTime::from_secs(secs);
    // keys issues from issued - 1 day, so the margin is met at once.
    check_certificate(&node, issued).unwrap();
    let last = not_after - CERT_SKEW_MARGIN_SECS;
    check_certificate(&node, at(last)).unwrap();
    for now in [issued.as_secs() - 1, last + 1, 0, u64::MAX] {
        let error = check_certificate(&node, at(now)).unwrap_err();
        assert_eq!(error.kind(), ExportErrorKind::CertNotCurrent, "{now}");
        assert!(matches!(
            error,
            ExportError::CertNotCurrent { not_before: before, not_after: after, .. }
                if u64::try_from(before).unwrap() == not_before
                    && u64::try_from(after).unwrap() == not_after
        ));
    }
    // The pins alone do not depend on the time.
    certificate_pins(&node).unwrap();
}

#[test]
fn the_san_must_be_exactly_one_hysteria2_sni() {
    // subjectAltName (2.5.29.17) renamed to issuerAltName (2.5.29.18).
    let no_san = tampered(
        &[0x06, 0x03, 0x55, 0x1d, 0x11],
        &[0x06, 0x03, 0x55, 0x1d, 0x12],
    );
    assert_eq!(kind(&no_san, FIXTURE_NOW), ExportErrorKind::CertSanMismatch);
    let (certificate, sni) = generated(FIXTURE_NOW);
    let sni = sni.as_str().as_bytes();
    for names in [
        vec![sni, b"extra.internal".as_slice()],
        vec![b"extra.internal".as_slice()],
        vec![b"n6c6f6e3100000001.local".as_slice()],
        vec![],
    ] {
        let der = with_san_dns_names(certificate.der(), &names);
        let node = with_certificate(CertificatePem::from_der(&der).unwrap());
        let error = certificate_pins(&node).unwrap_err();
        assert_eq!(error.kind(), ExportErrorKind::CertSanMismatch, "{names:?}");
        assert!(matches!(error, ExportError::CertSanMismatch { node: ref n } if *n == node.id));
    }
    // The helper itself keeps a valid SAN valid.
    let der = with_san_dns_names(certificate.der(), &[sni]);
    certificate_pins(&with_certificate(CertificatePem::from_der(&der).unwrap())).unwrap();
}

/// A DER element: a tag and either primitive content or child elements.
enum Der {
    Primitive(u8, Vec<u8>),
    Constructed(u8, Vec<Der>),
}

fn der_parse(mut bytes: &[u8]) -> Vec<Der> {
    let mut elements = Vec::new();
    while !bytes.is_empty() {
        let tag = bytes[0];
        let (len, header) = match bytes[1] {
            short @ 0..=0x7f => (usize::from(short), 2),
            long => {
                let count = usize::from(long & 0x7f);
                let len = bytes[2..2 + count]
                    .iter()
                    .fold(0, |acc, byte| (acc << 8) | usize::from(*byte));
                (len, 2 + count)
            }
        };
        let content = &bytes[header..header + len];
        elements.push(if tag & 0x20 == 0 {
            Der::Primitive(tag, content.to_vec())
        } else {
            Der::Constructed(tag, der_parse(content))
        });
        bytes = &bytes[header + len..];
    }
    elements
}

fn der_encode(element: &Der) -> Vec<u8> {
    let (tag, content) = match element {
        Der::Primitive(tag, content) => (*tag, content.clone()),
        Der::Constructed(tag, children) => (*tag, children.iter().flat_map(der_encode).collect()),
    };
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap());
        out.extend(bytes);
    }
    out.extend(content);
    out
}

/// `der` with its subjectAltName set to exactly the dNSNames `names`.
fn with_san_dns_names(der: &[u8], names: &[&[u8]]) -> Vec<u8> {
    const SAN_OID: [u8; 3] = [0x55, 0x1d, 0x11];
    let mut certificate = der_parse(der).remove(0);
    let Der::Constructed(_, parts) = &mut certificate else {
        panic!("a certificate is a SEQUENCE");
    };
    let Der::Constructed(_, tbs) = &mut parts[0] else {
        panic!("tbsCertificate is a SEQUENCE");
    };
    let Some(Der::Constructed(_, wrapper)) = tbs
        .iter_mut()
        .find(|element| matches!(element, Der::Constructed(0xa3, _)))
    else {
        panic!("the certificate has extensions");
    };
    let Der::Constructed(_, extensions) = &mut wrapper[0] else {
        panic!("extensions are a SEQUENCE");
    };
    let san = extensions
        .iter_mut()
        .find_map(|extension| match extension {
            Der::Constructed(_, fields)
                if matches!(&fields[0], Der::Primitive(0x06, oid) if oid[..] == SAN_OID) =>
            {
                Some(fields)
            }
            _ => None,
        })
        .unwrap();
    let Some(Der::Primitive(0x04, value)) = san.last_mut() else {
        panic!("extnValue is an OCTET STRING");
    };
    let general_names = names
        .iter()
        .map(|name| Der::Primitive(0x82, name.to_vec()))
        .collect();
    *value = der_encode(&Der::Constructed(0x30, general_names));
    der_encode(&certificate)
}

#[test]
fn the_eku_must_permit_server_authentication() {
    let server_auth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    let client_auth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    let client_only = tampered(&server_auth, &client_auth);
    assert_eq!(
        kind(&client_only, FIXTURE_NOW),
        ExportErrorKind::CertEkuMissing
    );
    // extKeyUsage (2.5.29.37) renamed to an unassigned 2.5.29.99.
    let no_eku = tampered(
        &[0x06, 0x03, 0x55, 0x1d, 0x25],
        &[0x06, 0x03, 0x55, 0x1d, 0x63],
    );
    assert_eq!(kind(&no_eku, FIXTURE_NOW), ExportErrorKind::CertEkuMissing);
}

#[test]
fn the_key_must_be_canonical_p256() {
    // prime256v1 (1.2.840.10045.3.1.7) renamed to 1.2.840.10045.3.1.6.
    let prime256v1 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let other_curve = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x06];
    let node = tampered(&prime256v1, &other_curve);
    for error in [
        check_certificate(&node, FIXTURE_NOW).unwrap_err(),
        certificate_pins(&node).unwrap_err(),
    ] {
        assert_eq!(error.kind(), ExportErrorKind::CertKeyUnsupported);
        assert!(matches!(error, ExportError::CertKeyUnsupported { node: ref n } if *n == node.id));
    }
}

#[test]
fn the_certificate_must_parse_with_nothing_trailing() {
    let (certificate, _) = generated(FIXTURE_NOW);
    let mut trailing = certificate.der().to_vec();
    trailing.push(0);
    for der in [trailing, vec![0x30, 0x03, 0x02, 0x01, 0x00]] {
        let node = with_certificate(CertificatePem::from_der(&der).unwrap());
        for error in [
            check_certificate(&node, FIXTURE_NOW).unwrap_err(),
            certificate_pins(&node).unwrap_err(),
        ] {
            assert_eq!(error.kind(), ExportErrorKind::CertUnparseable);
            assert!(matches!(error, ExportError::CertUnparseable { node: ref n } if *n == node.id));
        }
    }
}

#[test]
fn exports_run_the_certificate_checks() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let (certificate, _) = generated(FIXTURE_NOW);
    // A certificate issued after now is not yet valid for clients.
    let later = UnixTime::from_secs(FIXTURE_NOW.as_secs() + 1);
    let (future, _) = generated(later);
    for (certificate, expected) in [
        (certificate, None),
        (future, Some(ExportErrorKind::CertNotCurrent)),
    ] {
        let deployment = edited(&fixture.deployment, |parts| {
            let ams1 = parts
                .nodes
                .iter_mut()
                .find(|n| n.id == node("ams1"))
                .unwrap();
            ams1.hy2 = Hy2Server {
                certificate: certificate.clone(),
            };
        });
        let result = export_user(
            &deployment,
            &fixture.secrets,
            &user,
            ExportFormat::SingBoxJson,
            FIXTURE_NOW,
        );
        assert_eq!(result.err().map(|error| error.kind()), expected);
    }
}
