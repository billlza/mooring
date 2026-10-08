// SPDX-License-Identifier: GPL-3.0-or-later

//! Fixed key material for the fixture nodes. Test material only: none of it
//! may ever protect a real node.
//!
//! # How every value was produced (2026-10-08)
//!
//! X25519 and Ed25519 values come from Homebrew OpenSSL 3.6.4, because the
//! macOS `/usr/bin/openssl` (LibreSSL 3.3.6) has neither algorithm. Each
//! private key is the SHA-256 of a fixed label, clamped per RFC 7748 for
//! X25519 (as `wg genkey` and `xray x25519` do):
//!
//! ```text
//! raw=$(printf '%s' 'mooring-fixture/<node>/<item>' | openssl dgst -sha256 -hex)
//! # items: reality-private, wg-vps-private, wg-mac-private (X25519, clamped),
//! #        ssh-host-ed25519 (Ed25519 seed, unclamped)
//! printf '302e020100300506032b656e04220420%s' "$clamped" | xxd -r -p \
//!   | openssl pkey -inform DER -pubout -outform DER | tail -c 32   # X25519 public
//! printf '302e020100300506032b657004220420%s' "$seed" | xxd -r -p \
//!   | openssl pkey -inform DER -pubout -outform DER | tail -c 32   # Ed25519 public
//! ```
//!
//! The same OpenSSL reproduces RFC 7748 §6.1 (Alice) and RFC 8032 §7.1
//! (test 1) with this procedure.
//!
//! Each Hysteria2 certificate is ECDSA P-256 from `/usr/bin/openssl`
//! (LibreSSL 3.3.6), self-signed with `CA:FALSE`, `keyUsage=digitalSignature`,
//! `extendedKeyUsage=serverAuth`, `subjectAltName=DNS:<sni>`, subject
//! `CN=<sni>`, serial `4D4F4F52494E47<nn>`, notBefore 2026-10-01 00:00:00 UTC
//! and notAfter 2036-09-28 00:00:00 UTC:
//!
//! ```text
//! openssl ecparam -name prime256v1 -genkey -noout -out ec.pem
//! openssl pkcs8 -topk8 -nocrypt -in ec.pem -out key.pem
//! openssl req -new -key key.pem -config ca.cnf -out csr.pem
//! openssl ca -batch -selfsign -notext -config ca.cnf -keyfile key.pem -in csr.pem \
//!   -startdate 261001000000Z -enddate 360928000000Z -out cert.pem
//! ```
//!
//! The pins were computed with the same LibreSSL; later crates that have
//! `sha2` re-verify them against the embedded PEM:
//!
//! ```text
//! openssl x509 -in cert.pem -noout -pubkey | openssl pkey -pubin -outform DER \
//!   | openssl dgst -sha256 -binary | openssl base64 -A          # spki_sha256 (base64)
//! openssl x509 -in cert.pem -outform DER | openssl dgst -sha256 -hex   # der_sha256 (hex)
//! ```
//!
//! The applied bundle digests are placeholders, the SHA-256 of the label
//! `mooring-fixture/<node>/bundle`, not the digest of any rendered bundle.

/// The literal material of one fixture node.
pub(crate) struct NodeMaterial {
    pub(crate) id: &'static str,
    /// 1 for lon1, 2 for ams1; also the node's WireGuard index.
    pub(crate) ordinal: u8,
    /// An arbitrary public IPv4 outside `SPECIAL_V4`, not a real allocation.
    pub(crate) address: [u8; 4],
    pub(crate) target_host: &'static str,
    /// An arbitrary public IPv4 in the node's /24, standing in for a target.
    pub(crate) target_address: [u8; 4],
    pub(crate) target_hybrid: bool,
    pub(crate) reality_private: &'static str,
    pub(crate) reality_public: &'static str,
    pub(crate) wg_vps_private: &'static str,
    pub(crate) wg_vps_public: &'static str,
    pub(crate) wg_mac_private: &'static str,
    pub(crate) wg_mac_public: &'static str,
    pub(crate) ssh_host_public: &'static str,
    pub(crate) hy2_sni: &'static str,
    pub(crate) hy2_certificate: &'static str,
    pub(crate) hy2_key: &'static str,
    pub(crate) spki_sha256: &'static str,
    pub(crate) der_sha256: &'static str,
    pub(crate) bundle_digest: &'static str,
}

/// The certificates' notBefore, 2026-10-01T00:00:00Z.
pub(crate) const CERT_NOT_BEFORE: u64 = 1_790_812_800;
/// The certificates' notAfter, 2036-09-28T00:00:00Z (checked by the tests).
#[cfg(test)]
pub(crate) const CERT_NOT_AFTER: u64 = 2_106_172_800;

/// The primary node, London.
pub(crate) const LON1: NodeMaterial = NodeMaterial {
    id: "lon1",
    ordinal: 1,
    address: [45, 67, 89, 10],
    target_host: "www.harbour-target.test",
    target_address: [45, 67, 89, 200],
    target_hybrid: true,
    reality_private: "qAr2x8Vah8WO2JdHLUnMUUjqHpzO0vbDn7gKWAh17E8",
    reality_public: "QEsWwS6uUzMjri07Ajw6HWWPRuUgAlPCkCstYBSWq18",
    wg_vps_private: "kLHtzcgJYSDaWc3YAUUTHdXc1hGsKcrarNmI8FlXGVg=",
    wg_vps_public: "bNlQS933+LFbuy6C05O/HL03ezxdOUm0eMvwUDmokFk=",
    wg_mac_private: "GJBYG3LVAULH/bMIsc0pR3nj/Qy1ochAp6Jd1kPCylo=",
    wg_mac_public: "GCw8FzDlQheBsUANmVfmQTOTJI2m8JC87WVqLeqZYh0=",
    ssh_host_public: "4trWfS1sIdDIQszRK7tOeduPECAXUYbE8AD8k1RmExs=",
    hy2_sni: "n6c6f6e3100000001.internal",
    hy2_certificate: concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBmzCCAUKgAwIBAgIITU9PUklORwEwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwa\n",
        "bjZjNmY2ZTMxMDAwMDAwMDEuaW50ZXJuYWwwHhcNMjYxMDAxMDAwMDAwWhcNMzYw\n",
        "OTI4MDAwMDAwWjAlMSMwIQYDVQQDDBpuNmM2ZjZlMzEwMDAwMDAwMS5pbnRlcm5h\n",
        "bDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABK1e5jDHk6aZY+WwbsjXLrL7qcj9\n",
        "0MidgcNYK0Scj4GdJIkv7GAkloz1YCFk4oGbTqS+9yJ81ihcPf1iUUCHHoCjXDBa\n",
        "MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF\n",
        "BwMBMCUGA1UdEQQeMByCGm42YzZmNmUzMTAwMDAwMDAxLmludGVybmFsMAoGCCqG\n",
        "SM49BAMCA0cAMEQCID7fvy06Sl2ylYNUsKYP62dRjsdzekBjSi4jSnsUKalTAiBN\n",
        "5gI8Mnn4djsiDgn+QBFo1Whj7mqtaqYJwWyR8Tt1Ww==\n",
        "-----END CERTIFICATE-----\n",
    ),
    hy2_key: concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSjIXnHGd1K2NN891\n",
        "j3zKpm8xhs4eDhIVLR0k5vWBjCehRANCAAStXuYwx5OmmWPlsG7I1y6y+6nI/dDI\n",
        "nYHDWCtEnI+BnSSJL+xgJJaM9WAhZOKBm06kvvcifNYoXD39YlFAhx6A\n",
        "-----END PRIVATE KEY-----\n",
    ),
    spki_sha256: "m2BfzEHpKpjWF0ZVM6Vefmjwa+FTTdBMh1C5aqdjA1o=",
    der_sha256: "2d4e7710ab6fd0c32360aec182f026daaa7a822bacafd436065f1981723e14ff",
    bundle_digest: "01812c29cdf98e8594d5d0e6cbd662a26869093a5ed0d8bd009668abc35e20a2",
};

/// The standby node, Amsterdam.
pub(crate) const AMS1: NodeMaterial = NodeMaterial {
    id: "ams1",
    ordinal: 2,
    address: [46, 78, 90, 12],
    target_host: "www.quay-target.test",
    target_address: [46, 78, 90, 200],
    target_hybrid: false,
    reality_private: "6HudljXq8BadEDUaggFdT20kiJUJgqplKKzRYkctu0w",
    reality_public: "j5XOIMhZDjZl32xEe6ox0BDSDci5IAX6L-5qGqJRHR8",
    wg_vps_private: "IF1drmV2rxY5VaSPha2d3cGQtjdFGMEehWgTUyjPFGY=",
    wg_vps_public: "1+budQXrzhli3nM4sZneRvUtU8TYm1/D6NLLUJA2TBE=",
    wg_mac_private: "uBXGGOSjqNj83tgt4Fz97Od8Ot3GsAo8h1DXblzztGQ=",
    wg_mac_public: "rhNU+xRs17Q1Ac0lfGYNiKsgKAB05E/DjVZw7oJRhio=",
    ssh_host_public: "Ul29R9ZP8zIRz2hP8oNp40Ydjs7WE+ZgruOjR10VVIA=",
    hy2_sni: "n616d733100000002.internal",
    hy2_certificate: concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIBnDCCAUKgAwIBAgIITU9PUklORwIwCgYIKoZIzj0EAwIwJTEjMCEGA1UEAwwa\n",
        "bjYxNmQ3MzMxMDAwMDAwMDIuaW50ZXJuYWwwHhcNMjYxMDAxMDAwMDAwWhcNMzYw\n",
        "OTI4MDAwMDAwWjAlMSMwIQYDVQQDDBpuNjE2ZDczMzEwMDAwMDAwMi5pbnRlcm5h\n",
        "bDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD2anWcqf5TMWaRsd6J07g1qy42+\n",
        "HHW3DsvblOszxmW5nkUCz0zt0ONgeFwOorQEoJISD0hU0rzNSuXU0URSVZGjXDBa\n",
        "MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF\n",
        "BwMBMCUGA1UdEQQeMByCGm42MTZkNzMzMTAwMDAwMDAyLmludGVybmFsMAoGCCqG\n",
        "SM49BAMCA0gAMEUCIAT/D9q+yXdB8A/y3T+n9/sSd7uLVvG7o0xfxMcnoyNNAiEA\n",
        "0qw3fMHSLkABMFbbEhUThOPrFkv9znUAdI/eb1uLRkI=\n",
        "-----END CERTIFICATE-----\n",
    ),
    hy2_key: concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCnJVGQFwu/ojrFPS\n",
        "NDQDsGpFx1jVPWrFwjgCC1KUnm2hRANCAAQ9mp1nKn+UzFmkbHeidO4NasuNvhx1\n",
        "tw7L25TrM8ZluZ5FAs9M7dDjYHhcDqK0BKCSEg9IVNK8zUrl1NFEUlWR\n",
        "-----END PRIVATE KEY-----\n",
    ),
    spki_sha256: "EnsKF+ODvmyhJSDzRIh+14QX3hmvNQV158R9raL2hI8=",
    der_sha256: "e7d8b4219e0847227158ea5680f072c6b7935601ad90bdf6b886bc286cf06e50",
    bundle_digest: "02683d5e7434e861c7fcb58a4df3e5c7aa4ad4e4d4aed99d620de3e92b2ef0b7",
};
