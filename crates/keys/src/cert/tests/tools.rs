// SPDX-License-Identifier: GPL-3.0-or-later

//! Cross-check against `/usr/bin/openssl` (LibreSSL 3.3.6), which design
//! §16 L1 runs on the macOS runner only; the `-text` needles below are
//! that release's spelling.

use super::*;
use crate::testing::tools::{run_tool, run_tool_bytes, write_private_file};

/// `/usr/bin/openssl` reads the same DER, the same SubjectPublicKeyInfo and
/// the same extensions.
#[test]
fn openssl_agrees_with_the_certificate() {
    const OPENSSL: &str = "/usr/bin/openssl";
    let generated = Hy2Certificate::generate(NOW).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    std::fs::write(&cert_path, generated.certificate().as_str()).unwrap();
    let key_path = write_private_file(
        dir.path(),
        "key.pem",
        generated.key().expose_pem().as_bytes(),
    );
    let cert = cert_path.to_str().unwrap();
    let key = key_path.to_str().unwrap();

    let der = run_tool_bytes(OPENSSL, ["x509", "-in", cert, "-outform", "DER"], &[]);
    assert_eq!(der, generated.certificate().der());

    let public_pem = run_tool(OPENSSL, ["x509", "-in", cert, "-noout", "-pubkey"]);
    let spki = run_tool_bytes(
        OPENSSL,
        ["pkey", "-pubin", "-outform", "DER"],
        public_pem.as_bytes(),
    );
    assert_eq!(spki, parse(&generated).public_key().raw);

    // The private key's public half is the certificate's.
    let key_spki = run_tool_bytes(
        OPENSSL,
        ["pkey", "-in", key, "-pubout", "-outform", "DER"],
        &[],
    );
    assert_eq!(key_spki, spki);

    let text = run_tool(OPENSSL, ["x509", "-in", cert, "-noout", "-text"]);
    let sni = generated.sni().as_str();
    for needle in [
        "Version: 3 (0x2)",
        "Signature Algorithm: ecdsa-with-SHA256",
        "Public Key Algorithm: id-ecPublicKey",
        "prime256v1",
        "X509v3 Basic Constraints: critical",
        "CA:FALSE",
        "X509v3 Key Usage: critical",
        "Digital Signature",
        "X509v3 Extended Key Usage:",
        "TLS Web Server Authentication",
        "X509v3 Subject Alternative Name:",
        &format!("DNS:{sni}"),
    ] {
        assert!(text.contains(needle), "missing {needle:?} in\n{text}");
    }
    assert!(!text.contains("CA:TRUE"));
    assert!(!text.contains("TLS Web Client Authentication"));
}
