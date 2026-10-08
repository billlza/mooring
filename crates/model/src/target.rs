// SPDX-License-Identifier: GPL-3.0-or-later

//! REALITY target qualification (design §11.7): the agent's `TargetCheck`
//! returns raw facts; [`qualify`] evaluates the rules on the Mac.
//!
//! [`TargetFacts`] mirrors the agent's wire report outcome for outcome: the
//! TLS probe may fail to connect or to complete the handshake, the HTTP
//! probe may get no response, and the name may resolve to no address. Each
//! of those is a [`TargetRejection`]; nothing is invented to fill a value
//! the agent did not measure. The agent always probes port 443, so the port
//! rule ("the target listens on 443") is the TLS connect outcome.
//!
//! In v1 the target's only `serverName` is the probed host, so "every
//! serverName is on the certificate" means "the host is a certificate name".
//! REALITY matches server names exactly, without wildcards
//! (REALITY `e1986a4` `tls.go` `config.ServerNames[hs.clientHello.serverName]`),
//! so a wildcard certificate entry does not cover the host.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::collections::NonEmpty;
use crate::dns::DnsName;
use crate::error::ModelError;
use crate::ipv4::{PublicIpv4, SpecialClass};
use crate::kinds;
use crate::time::UnixTime;

/// The largest accepted server first flight. REALITY `e1986a4` buffers 17 KiB
/// of target handshake records (`tls.go` `size = 17 * 1024`, PR #33).
pub const MAX_FIRST_FLIGHT_BYTES: u32 = 16 * 1024;
/// The largest accepted p95 TLS handshake latency from the VPS, 5 ms.
pub const MAX_HANDSHAKE_P95_MICROS: u64 = 5_000;

/// Name fragments Xray v26.9.30 warns about as REALITY server names
/// (`infra/conf/transport_security.go:165-169`); any of them would break the
/// zero-warning validation gate.
pub const XRAY_WARNED_SUBSTRINGS: [&str; 3] = ["apple", "icloud", "microsoft"];
/// Top-level domains Xray v26.9.30 warns about as REALITY server names
/// (same source).
pub const XRAY_WARNED_TLDS: [&str; 3] = ["cn", "ir", "ru"];
/// Domains widely shared as REALITY targets in public guides, or operated by
/// a large CDN or cloud; a target equal to or under one of them is refused.
/// Not exhaustive: the same-ASN and not-CDN attestations cover the rest.
pub const SHARED_TARGET_DOMAINS: [&str; 27] = [
    "akamai.net",
    "akamaized.net",
    "amazon.com",
    "amazonaws.com",
    "amd.com",
    "azure.com",
    "bing.com",
    "cloudflare.com",
    "cloudfront.net",
    "fastly.net",
    "github.com",
    "githubusercontent.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "intel.com",
    "live.com",
    "lovelive-anime.jp",
    "mozilla.org",
    "msn.com",
    "nvidia.com",
    "office.com",
    "samsung.com",
    "speedtest.net",
    "tesla.com",
    "yahoo.com",
    "youtube.com",
];

/// The TLS version the target negotiated (`xray tls ping` offers TLS 1.2 and
/// TLS 1.3 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

/// The HTTP version the target served `/` with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1.
    Http11,
    /// HTTP/2.
    Http2,
    /// HTTP/3.
    Http3,
}

/// The key exchange group the target selected in `xray tls ping`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyExchange {
    /// The hybrid X25519MLKEM768 group.
    X25519MlKem768,
    /// Classical X25519.
    X25519,
    /// Any other group, or none (TLS 1.2 RSA key transport), which a REALITY
    /// server cannot complete with a classical or hybrid X25519 client share
    /// (REALITY `e1986a4` `tls.go:215-235`).
    Other,
}

/// The key exchange a qualified target negotiates; recorded so the operator
/// knows whether hybrid clients get a post-quantum outer session (design §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKeyExchange {
    /// Classical X25519 only.
    X25519,
    /// The hybrid X25519MLKEM768 group.
    X25519MlKem768,
}

/// The longest certificate name the agent reports.
pub const MAX_CERTIFICATE_NAME_BYTES: usize = 253;

/// A DNS name from the target leaf certificate's subject alternative names,
/// as `xray tls ping` reports it: 1..=253 printable ASCII characters, the
/// agent protocol's `CertName` rule. Certificates may carry wildcards and
/// names outside LDH; [`qualify`] compares names with the host exactly
/// (ASCII case-insensitively), so neither ever matches a different host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CertificateName(String);

impl CertificateName {
    /// Validates `text` as a reported certificate name.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let valid = (1..=MAX_CERTIFICATE_NAME_BYTES).contains(&text.len())
            && text.bytes().all(|byte| byte.is_ascii_graphic());
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidCertificateName)
        }
    }

    /// The name as reported.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name is exactly `host`, ignoring ASCII case.
    #[must_use]
    pub fn names(&self, host: &DnsName) -> bool {
        self.0.eq_ignore_ascii_case(host.as_str())
    }
}

/// A completed TLS handshake with the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshake {
    /// The negotiated version.
    pub version: TlsVersion,
    /// The negotiated key exchange group.
    pub key_exchange: KeyExchange,
    /// The DNS names on the leaf certificate, as reported.
    pub certificate_names: BTreeSet<CertificateName>,
    /// The p95 handshake latency over the sample, in microseconds.
    pub handshake_p95_micros: u64,
    /// The size of the server's first flight, in bytes.
    pub first_flight_bytes: u32,
}

/// What the TLS probe of port 443 found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsOutcome {
    /// No TCP connection to port 443 could be made.
    ConnectFailed,
    /// TCP connected but the TLS handshake failed.
    HandshakeFailed,
    /// The handshake completed.
    Completed(TlsHandshake),
}

/// What the HTTP/2 probe of `/` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpOutcome {
    /// No HTTP response arrived.
    Failed,
    /// A response arrived.
    Responded {
        /// Its status.
        status: HttpStatus,
        /// Its HTTP version.
        version: HttpVersion,
    },
}

/// What `TargetCheck` observed from the VPS; raw facts, judged by [`qualify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetFacts {
    /// The host that was probed; it becomes the only `serverName`.
    pub host: DnsName,
    /// The IPv4 addresses the host resolved to from the VPS; possibly none.
    pub resolved_ipv4: BTreeSet<Ipv4Addr>,
    /// The TLS probe of port 443.
    pub tls: TlsOutcome,
    /// The HTTP/2 probe of `/`.
    pub http: HttpOutcome,
}

/// An HTTP status code in 100..=599.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct HttpStatus(u16);

impl HttpStatus {
    /// Accepts 100..=599.
    pub fn new(status: u16) -> Result<Self, ModelError> {
        if (100..=599).contains(&status) {
            Ok(Self(status))
        } else {
            Err(ModelError::InvalidHttpStatus { status })
        }
    }

    /// The status code.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Whether the status is a 3xx redirect.
    #[must_use]
    pub const fn is_redirect(self) -> bool {
        self.0 >= 300 && self.0 <= 399
    }
}

impl TryFrom<u16> for HttpStatus {
    type Error = ModelError;

    fn try_from(status: u16) -> Result<Self, Self::Error> {
        Self::new(status)
    }
}

impl From<HttpStatus> for u16 {
    fn from(status: HttpStatus) -> Self {
        status.0
    }
}

impl fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The largest accepted evidence URL.
pub const MAX_EVIDENCE_URL_BYTES: usize = 2048;

/// An `https://` URL pointing at the operator's evidence: printable ASCII,
/// at most 2048 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EvidenceUrl(String);

impl EvidenceUrl {
    /// Validates `text` as an evidence URL.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let valid = text.len() <= MAX_EVIDENCE_URL_BYTES
            && text
                .strip_prefix("https://")
                .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
            && text.bytes().all(|byte| byte.is_ascii_graphic());
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(ModelError::InvalidEvidenceUrl)
        }
    }

    /// The URL as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EvidenceUrl {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<EvidenceUrl> for String {
    fn from(url: EvidenceUrl) -> Self {
        url.0
    }
}

/// The operator's attestations about data the system does not ship.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetAttestation {
    /// The target is announced by the VPS's ASN.
    pub same_asn: bool,
    /// The target is not served by a CDN.
    pub not_cdn: bool,
    /// Where the evidence for both lives.
    pub evidence_url: EvidenceUrl,
    /// When the operator attested.
    pub at: UnixTime,
}

/// A qualified REALITY target as stored on the node.
///
/// Built by [`qualify`]; deserialisation re-checks that the attestation is
/// positive but not the compiled-in deny list, so a stored target never
/// fails to load after the list grows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "TargetSpecRepr", into = "TargetSpecRepr")]
pub struct TargetSpec {
    host: DnsName,
    ipv4: PublicIpv4,
    key_exchange: TargetKeyExchange,
    attestation: TargetAttestation,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetSpecRepr {
    host: DnsName,
    ipv4: PublicIpv4,
    key_exchange: TargetKeyExchange,
    attestation: TargetAttestation,
}

impl TargetSpec {
    /// The target host, which is also the only REALITY `serverName` and the
    /// client SNI.
    #[must_use]
    pub const fn host(&self) -> &DnsName {
        &self.host
    }

    /// The target's IPv4 address; REALITY and the camouflage forwards dial it.
    #[must_use]
    pub const fn ipv4(&self) -> PublicIpv4 {
        self.ipv4
    }

    /// The key exchange the target negotiated at qualification.
    #[must_use]
    pub const fn key_exchange(&self) -> TargetKeyExchange {
        self.key_exchange
    }

    /// The operator's attestation.
    #[must_use]
    pub const fn attestation(&self) -> &TargetAttestation {
        &self.attestation
    }
}

/// A stored target must carry a positive attestation.
pub(crate) fn require_attested(attestation: &TargetAttestation) -> Result<(), ModelError> {
    if attestation.same_asn && attestation.not_cdn {
        Ok(())
    } else {
        Err(ModelError::TargetNotAttested)
    }
}

impl TryFrom<TargetSpecRepr> for TargetSpec {
    type Error = ModelError;

    fn try_from(repr: TargetSpecRepr) -> Result<Self, Self::Error> {
        require_attested(&repr.attestation)?;
        Ok(Self {
            host: repr.host,
            ipv4: repr.ipv4,
            key_exchange: repr.key_exchange,
            attestation: repr.attestation,
        })
    }
}

impl From<TargetSpec> for TargetSpecRepr {
    fn from(spec: TargetSpec) -> Self {
        Self {
            host: spec.host,
            ipv4: spec.ipv4,
            key_exchange: spec.key_exchange,
            attestation: spec.attestation,
        }
    }
}

/// Proof that a target passed every rule; only [`qualify`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qualified {
    target: TargetSpec,
}

impl Qualified {
    /// The qualified target.
    #[must_use]
    pub const fn target(&self) -> &TargetSpec {
        &self.target
    }

    /// Whether the target negotiated X25519MLKEM768.
    #[must_use]
    pub fn negotiated_mlkem(&self) -> bool {
        self.target.key_exchange == TargetKeyExchange::X25519MlKem768
    }

    /// The target, for storing on the node.
    #[must_use]
    pub fn into_target(self) -> TargetSpec {
        self.target
    }
}

/// Which deny-list entry matched a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyRule {
    /// The name contains a fragment Xray warns about.
    XrayWarnedSubstring(&'static str),
    /// The name is under a top-level domain Xray warns about.
    XrayWarnedTld(&'static str),
    /// The name is a widely shared target domain or under one.
    SharedTarget(&'static str),
}

impl fmt::Display for DenyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XrayWarnedSubstring(fragment) => write!(f, "contains \"{fragment}\""),
            Self::XrayWarnedTld(tld) => write!(f, "is under .{tld}"),
            Self::SharedTarget(domain) => write!(f, "is a widely shared target ({domain})"),
        }
    }
}

/// The first deny-list entry `name` matches, if any.
#[must_use]
pub fn deny_rule(name: &DnsName) -> Option<DenyRule> {
    XRAY_WARNED_SUBSTRINGS
        .into_iter()
        .find(|fragment| name.as_str().contains(fragment))
        .map(DenyRule::XrayWarnedSubstring)
        .or_else(|| {
            XRAY_WARNED_TLDS
                .into_iter()
                .find(|tld| name.top_label() == *tld)
                .map(DenyRule::XrayWarnedTld)
        })
        .or_else(|| {
            SHARED_TARGET_DOMAINS
                .into_iter()
                .find(|domain| name.is_within(domain))
                .map(DenyRule::SharedTarget)
        })
}

/// One rule a target failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetRejection {
    /// No TCP connection to the target's port 443 could be made.
    #[error("the target does not accept connections on port 443")]
    TlsConnectFailed,
    /// The TLS handshake with the target failed.
    #[error("the TLS handshake with the target failed")]
    TlsHandshakeFailed,
    /// The target did not negotiate TLS 1.3.
    #[error("the target negotiated {found:?}, not TLS 1.3")]
    NotTls13 {
        /// The version negotiated.
        found: TlsVersion,
    },
    /// The host is not a name on the target's certificate.
    #[error("{host} is not a name on the target certificate")]
    HostNotOnCertificate {
        /// The host.
        host: DnsName,
    },
    /// The first flight would overflow REALITY's record buffer margin.
    #[error("the first flight is {bytes} bytes, over 16 KiB")]
    FirstFlightTooLarge {
        /// The first flight size.
        bytes: u32,
    },
    /// The target is too far from the VPS.
    #[error("p95 handshake is {p95_micros} µs, over 5 ms")]
    HandshakeTooSlow {
        /// The p95 latency in microseconds.
        p95_micros: u64,
    },
    /// The target negotiated a group REALITY cannot use.
    #[error("the target negotiated neither X25519 nor X25519MLKEM768")]
    UnsupportedKeyExchange,
    /// No HTTP response to `/` arrived.
    #[error("the target sent no HTTP response to /")]
    HttpFailed,
    /// The target did not serve HTTP/2.
    #[error("the target served {found:?}, not HTTP/2")]
    NotHttp2 {
        /// The version served.
        found: HttpVersion,
    },
    /// The target redirects `/`.
    #[error("the target answers / with redirect {status}")]
    Redirect {
        /// The 3xx status.
        status: HttpStatus,
    },
    /// The host is on the compiled-in deny list.
    #[error("{host} {rule}")]
    DeniedName {
        /// The host.
        host: DnsName,
        /// The matching entry.
        rule: DenyRule,
    },
    /// The host resolved to no IPv4 address from the VPS.
    #[error("the host resolved to no IPv4 address")]
    NoAddress,
    /// The host resolved to more than one IPv4 address.
    #[error("the host resolved to {count} IPv4 addresses; exactly one is required")]
    AmbiguousAddress {
        /// The number of addresses.
        count: usize,
    },
    /// The host resolved to a special-purpose address.
    #[error("the host resolved to {addr} in {class}")]
    NonPublicAddress {
        /// The address.
        addr: Ipv4Addr,
        /// Its special-purpose class.
        class: SpecialClass,
    },
    /// The operator did not attest that the target shares the VPS's ASN.
    #[error("the target is not attested as same-ASN")]
    SameAsnNotAttested,
    /// The operator did not attest that the target is not behind a CDN.
    #[error("the target is not attested as non-CDN")]
    CdnNotExcluded,
}

kinds! {
    /// The kind of a [`TargetRejection`], without its details.
    pub enum TargetRejectionKind {
        /// See [`TargetRejection::TlsConnectFailed`].
        TlsConnectFailed,
        /// See [`TargetRejection::TlsHandshakeFailed`].
        TlsHandshakeFailed,
        /// See [`TargetRejection::NotTls13`].
        NotTls13,
        /// See [`TargetRejection::HostNotOnCertificate`].
        HostNotOnCertificate,
        /// See [`TargetRejection::FirstFlightTooLarge`].
        FirstFlightTooLarge,
        /// See [`TargetRejection::HandshakeTooSlow`].
        HandshakeTooSlow,
        /// See [`TargetRejection::UnsupportedKeyExchange`].
        UnsupportedKeyExchange,
        /// See [`TargetRejection::HttpFailed`].
        HttpFailed,
        /// See [`TargetRejection::NotHttp2`].
        NotHttp2,
        /// See [`TargetRejection::Redirect`].
        Redirect,
        /// See [`TargetRejection::DeniedName`].
        DeniedName,
        /// See [`TargetRejection::NoAddress`].
        NoAddress,
        /// See [`TargetRejection::AmbiguousAddress`].
        AmbiguousAddress,
        /// See [`TargetRejection::NonPublicAddress`].
        NonPublicAddress,
        /// See [`TargetRejection::SameAsnNotAttested`].
        SameAsnNotAttested,
        /// See [`TargetRejection::CdnNotExcluded`].
        CdnNotExcluded,
    }
}

impl TargetRejection {
    /// The kind of this rejection.
    #[must_use]
    pub const fn kind(&self) -> TargetRejectionKind {
        match self {
            Self::TlsConnectFailed => TargetRejectionKind::TlsConnectFailed,
            Self::TlsHandshakeFailed => TargetRejectionKind::TlsHandshakeFailed,
            Self::NotTls13 { .. } => TargetRejectionKind::NotTls13,
            Self::HostNotOnCertificate { .. } => TargetRejectionKind::HostNotOnCertificate,
            Self::FirstFlightTooLarge { .. } => TargetRejectionKind::FirstFlightTooLarge,
            Self::HandshakeTooSlow { .. } => TargetRejectionKind::HandshakeTooSlow,
            Self::UnsupportedKeyExchange => TargetRejectionKind::UnsupportedKeyExchange,
            Self::HttpFailed => TargetRejectionKind::HttpFailed,
            Self::NotHttp2 { .. } => TargetRejectionKind::NotHttp2,
            Self::Redirect { .. } => TargetRejectionKind::Redirect,
            Self::DeniedName { .. } => TargetRejectionKind::DeniedName,
            Self::NoAddress => TargetRejectionKind::NoAddress,
            Self::AmbiguousAddress { .. } => TargetRejectionKind::AmbiguousAddress,
            Self::NonPublicAddress { .. } => TargetRejectionKind::NonPublicAddress,
            Self::SameAsnNotAttested => TargetRejectionKind::SameAsnNotAttested,
            Self::CdnNotExcluded => TargetRejectionKind::CdnNotExcluded,
        }
    }
}

/// A target failed one or more rules; every failed rule is listed, in rule order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct TargetRejected {
    reasons: NonEmpty<TargetRejection>,
}

impl TargetRejected {
    /// Every failed rule, in rule order.
    #[must_use]
    pub const fn reasons(&self) -> &NonEmpty<TargetRejection> {
        &self.reasons
    }
}

impl fmt::Display for TargetRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("REALITY target rejected: ")?;
        for (position, reason) in self.reasons.iter().enumerate() {
            if position > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{reason}")?;
        }
        Ok(())
    }
}

/// A rule outcome that keeps every failure.
type Checked<T> = Result<T, NonEmpty<TargetRejection>>;

/// Combines two outcomes, keeping the failures of both in order.
fn zip<A, B>(first: Checked<A>, second: Checked<B>) -> Checked<(A, B)> {
    match (first, second) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (Err(reasons), Ok(_)) | (Ok(_), Err(reasons)) => Err(reasons),
        (Err(mut reasons), Err(more)) => {
            reasons.append(more);
            Err(reasons)
        }
    }
}

/// Combines outcomes without short-circuiting, keeping every failure in order.
fn all(outcomes: impl IntoIterator<Item = Checked<()>>) -> Checked<()> {
    let mut combined = Ok(());
    for outcome in outcomes {
        combined = zip(combined, outcome).map(|((), ())| ());
    }
    combined
}

fn require(holds: bool, reason: impl FnOnce() -> TargetRejection) -> Checked<()> {
    if holds {
        Ok(())
    } else {
        Err(NonEmpty::new(reason()))
    }
}

fn fail<T>(reason: TargetRejection) -> Checked<T> {
    Err(NonEmpty::new(reason))
}

/// The TLS rules: a completed TLS 1.3 handshake with the host on the
/// certificate, a small first flight, a near target and a usable group.
fn tls_rules(host: &DnsName, tls: &TlsOutcome) -> Checked<TargetKeyExchange> {
    let session = match tls {
        TlsOutcome::ConnectFailed => return fail(TargetRejection::TlsConnectFailed),
        TlsOutcome::HandshakeFailed => return fail(TargetRejection::TlsHandshakeFailed),
        TlsOutcome::Completed(session) => session,
    };
    let rules = all([
        require(session.version == TlsVersion::Tls13, || {
            TargetRejection::NotTls13 {
                found: session.version,
            }
        }),
        require(
            session
                .certificate_names
                .iter()
                .any(|name| name.names(host)),
            || TargetRejection::HostNotOnCertificate { host: host.clone() },
        ),
        require(session.first_flight_bytes <= MAX_FIRST_FLIGHT_BYTES, || {
            TargetRejection::FirstFlightTooLarge {
                bytes: session.first_flight_bytes,
            }
        }),
        require(
            session.handshake_p95_micros <= MAX_HANDSHAKE_P95_MICROS,
            || TargetRejection::HandshakeTooSlow {
                p95_micros: session.handshake_p95_micros,
            },
        ),
    ]);
    zip(rules, supported_key_exchange(session.key_exchange)).map(|((), group)| group)
}

/// The HTTP rules: an HTTP/2 response to `/` that is not a redirect.
fn http_rules(http: HttpOutcome) -> Checked<()> {
    match http {
        HttpOutcome::Failed => fail(TargetRejection::HttpFailed),
        HttpOutcome::Responded { status, version } => all([
            require(version == HttpVersion::Http2, || {
                TargetRejection::NotHttp2 { found: version }
            }),
            require(!status.is_redirect(), || TargetRejection::Redirect {
                status,
            }),
        ]),
    }
}

fn single_public_address(resolved: &BTreeSet<Ipv4Addr>) -> Checked<PublicIpv4> {
    let mut addresses = resolved.iter();
    match (addresses.next(), addresses.next()) {
        (None, _) => fail(TargetRejection::NoAddress),
        (Some(only), None) => PublicIpv4::classified(*only).map_err(|class| {
            NonEmpty::new(TargetRejection::NonPublicAddress { addr: *only, class })
        }),
        (Some(_), Some(_)) => fail(TargetRejection::AmbiguousAddress {
            count: resolved.len(),
        }),
    }
}

fn supported_key_exchange(found: KeyExchange) -> Checked<TargetKeyExchange> {
    match found {
        KeyExchange::X25519 => Ok(TargetKeyExchange::X25519),
        KeyExchange::X25519MlKem768 => Ok(TargetKeyExchange::X25519MlKem768),
        KeyExchange::Other => fail(TargetRejection::UnsupportedKeyExchange),
    }
}

/// Evaluates every §11.7 rule and the attestation; on success the target is
/// ready to store on the node. Failures are reported in this order: the
/// TLS rules, the HTTP rules, the deny list, the resolved address, then
/// the attestation.
pub fn qualify(
    facts: &TargetFacts,
    attestation: TargetAttestation,
) -> Result<Qualified, TargetRejected> {
    let host = &facts.host;
    let tls = tls_rules(host, &facts.tls);
    let http = http_rules(facts.http);
    let name = deny_rule(host).map_or(Ok(()), |rule| {
        fail(TargetRejection::DeniedName {
            host: host.clone(),
            rule,
        })
    });
    let address = single_public_address(&facts.resolved_ipv4);
    let attested = zip(
        require(attestation.same_asn, || TargetRejection::SameAsnNotAttested),
        require(attestation.not_cdn, || TargetRejection::CdnNotExcluded),
    );
    let ((((key_exchange, ()), ()), ipv4), ((), ())) =
        zip(zip(zip(zip(tls, http), name), address), attested)
            .map_err(|reasons| TargetRejected { reasons })?;
    Ok(Qualified {
        target: TargetSpec {
            host: host.clone(),
            ipv4,
            key_exchange,
            attestation,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn name(text: &str) -> CertificateName {
        CertificateName::parse(text).unwrap()
    }

    fn passing_facts() -> TargetFacts {
        TargetFacts {
            host: DnsName::parse("www.harbour-target.test").unwrap(),
            resolved_ipv4: BTreeSet::from([Ipv4Addr::new(45, 67, 89, 200)]),
            tls: TlsOutcome::Completed(TlsHandshake {
                version: TlsVersion::Tls13,
                key_exchange: KeyExchange::X25519MlKem768,
                certificate_names: BTreeSet::from([
                    name("harbour-target.test"),
                    name("www.harbour-target.test"),
                ]),
                handshake_p95_micros: 1_800,
                first_flight_bytes: 4_300,
            }),
            http: HttpOutcome::Responded {
                status: HttpStatus::new(200).unwrap(),
                version: HttpVersion::Http2,
            },
        }
    }

    /// The completed handshake of `facts`.
    fn session(facts: &mut TargetFacts) -> &mut TlsHandshake {
        match &mut facts.tls {
            TlsOutcome::Completed(session) => session,
            TlsOutcome::ConnectFailed | TlsOutcome::HandshakeFailed => {
                panic!("the facts hold no completed handshake")
            }
        }
    }

    fn responded(status: u16, version: HttpVersion) -> HttpOutcome {
        HttpOutcome::Responded {
            status: HttpStatus::new(status).unwrap(),
            version,
        }
    }

    fn attestation() -> TargetAttestation {
        TargetAttestation {
            same_asn: true,
            not_cdn: true,
            evidence_url: EvidenceUrl::parse("https://evidence.mooring.test/lon1").unwrap(),
            at: UnixTime::from_secs(1_791_417_600),
        }
    }

    fn kinds_of(facts: &TargetFacts, attestation: TargetAttestation) -> Vec<TargetRejectionKind> {
        match qualify(facts, attestation) {
            Ok(_) => Vec::new(),
            Err(rejected) => rejected
                .reasons()
                .iter()
                .map(TargetRejection::kind)
                .collect(),
        }
    }

    #[test]
    fn a_compliant_target_qualifies_and_records_the_group() {
        let qualified = qualify(&passing_facts(), attestation()).unwrap();
        assert!(qualified.negotiated_mlkem());
        let target = qualified.into_target();
        assert_eq!(target.host().as_str(), "www.harbour-target.test");
        assert_eq!(target.ipv4().get(), Ipv4Addr::new(45, 67, 89, 200));
        let mut classical = passing_facts();
        session(&mut classical).key_exchange = KeyExchange::X25519;
        let qualified = qualify(&classical, attestation()).unwrap();
        assert!(!qualified.negotiated_mlkem());
        assert_eq!(qualified.target().key_exchange(), TargetKeyExchange::X25519);
    }

    /// Every rejection kind, each produced alone by one change to passing facts.
    #[test]
    fn each_rule_rejects_on_its_own() {
        type Mutation = fn(&mut TargetFacts, &mut TargetAttestation);
        let cases: [(Mutation, TargetRejectionKind); 16] = [
            (
                |f, _| f.tls = TlsOutcome::ConnectFailed,
                TargetRejectionKind::TlsConnectFailed,
            ),
            (
                |f, _| f.tls = TlsOutcome::HandshakeFailed,
                TargetRejectionKind::TlsHandshakeFailed,
            ),
            (
                |f, _| session(f).version = TlsVersion::Tls12,
                TargetRejectionKind::NotTls13,
            ),
            (
                |f, _| {
                    session(f).certificate_names = BTreeSet::from([name("*.harbour-target.test")]);
                },
                TargetRejectionKind::HostNotOnCertificate,
            ),
            (
                |f, _| session(f).first_flight_bytes = 16_385,
                TargetRejectionKind::FirstFlightTooLarge,
            ),
            (
                |f, _| session(f).handshake_p95_micros = 5_001,
                TargetRejectionKind::HandshakeTooSlow,
            ),
            (
                |f, _| session(f).key_exchange = KeyExchange::Other,
                TargetRejectionKind::UnsupportedKeyExchange,
            ),
            (
                |f, _| f.http = HttpOutcome::Failed,
                TargetRejectionKind::HttpFailed,
            ),
            (
                |f, _| f.http = responded(200, HttpVersion::Http11),
                TargetRejectionKind::NotHttp2,
            ),
            (
                |f, _| f.http = responded(301, HttpVersion::Http2),
                TargetRejectionKind::Redirect,
            ),
            (
                |f, _| {
                    f.host = DnsName::parse("swdist.apple.com").unwrap();
                    session(f).certificate_names = BTreeSet::from([name("swdist.apple.com")]);
                },
                TargetRejectionKind::DeniedName,
            ),
            (
                |f, _| f.resolved_ipv4.clear(),
                TargetRejectionKind::NoAddress,
            ),
            (
                |f, _| {
                    f.resolved_ipv4.insert(Ipv4Addr::new(45, 67, 89, 201));
                },
                TargetRejectionKind::AmbiguousAddress,
            ),
            (
                |f, _| f.resolved_ipv4 = BTreeSet::from([Ipv4Addr::new(10, 1, 2, 3)]),
                TargetRejectionKind::NonPublicAddress,
            ),
            (
                |_, a| a.same_asn = false,
                TargetRejectionKind::SameAsnNotAttested,
            ),
            (
                |_, a| a.not_cdn = false,
                TargetRejectionKind::CdnNotExcluded,
            ),
        ];
        for (mutate, expected) in cases {
            let mut facts = passing_facts();
            let mut attested = attestation();
            mutate(&mut facts, &mut attested);
            assert_eq!(kinds_of(&facts, attested), vec![expected], "{expected}");
        }
        let named: BTreeSet<TargetRejectionKind> = cases.iter().map(|(_, kind)| *kind).collect();
        assert_eq!(
            named.len(),
            TargetRejectionKind::ALL.len(),
            "every kind once"
        );
    }

    #[test]
    fn a_failed_tls_probe_hides_the_session_rules() {
        // Session rules cannot be judged without a session; only the failure
        // itself is reported, with the independent rules.
        for (tls, kind) in [
            (
                TlsOutcome::ConnectFailed,
                TargetRejectionKind::TlsConnectFailed,
            ),
            (
                TlsOutcome::HandshakeFailed,
                TargetRejectionKind::TlsHandshakeFailed,
            ),
        ] {
            let mut facts = passing_facts();
            facts.tls = tls;
            facts.http = HttpOutcome::Failed;
            assert_eq!(
                kinds_of(&facts, attestation()),
                vec![kind, TargetRejectionKind::HttpFailed]
            );
        }
    }

    #[test]
    fn certificate_names_match_exactly_ignoring_case() {
        let mut facts = passing_facts();
        session(&mut facts).certificate_names = BTreeSet::from([name("WWW.Harbour-Target.TEST")]);
        assert!(qualify(&facts, attestation()).is_ok());
        for other in [
            "harbour-target.test",
            "*.harbour-target.test",
            "www.harbour-target.test.",
        ] {
            session(&mut facts).certificate_names = BTreeSet::from([name(other)]);
            assert_eq!(
                kinds_of(&facts, attestation()),
                vec![TargetRejectionKind::HostNotOnCertificate],
                "{other}"
            );
        }
    }

    #[test]
    fn certificate_name_rules() {
        assert!(CertificateName::parse("*.example.com").is_ok());
        assert!(CertificateName::parse(&"a".repeat(MAX_CERTIFICATE_NAME_BYTES)).is_ok());
        for bad in [
            String::new(),
            "a".repeat(MAX_CERTIFICATE_NAME_BYTES + 1),
            "a b".to_owned(),
            "é.example".to_owned(),
            "a\nb".to_owned(),
        ] {
            assert_eq!(
                CertificateName::parse(&bad),
                Err(ModelError::InvalidCertificateName),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn boundaries_are_inclusive() {
        let mut facts = passing_facts();
        session(&mut facts).first_flight_bytes = 16 * 1024;
        session(&mut facts).handshake_p95_micros = 5_000;
        facts.http = responded(299, HttpVersion::Http2);
        assert!(qualify(&facts, attestation()).is_ok());
        facts.http = responded(400, HttpVersion::Http2);
        assert!(qualify(&facts, attestation()).is_ok());
        for redirect in [300, 399] {
            facts.http = responded(redirect, HttpVersion::Http2);
            assert_eq!(
                kinds_of(&facts, attestation()),
                vec![TargetRejectionKind::Redirect],
                "{redirect}"
            );
        }
    }

    #[test]
    fn every_failure_is_reported_in_rule_order() {
        let mut facts = passing_facts();
        session(&mut facts).handshake_p95_micros = 9_000;
        session(&mut facts).key_exchange = KeyExchange::Other;
        facts.http = responded(302, HttpVersion::Http3);
        facts.resolved_ipv4.clear();
        let mut weak = attestation();
        weak.not_cdn = false;
        let rejected = qualify(&facts, weak).unwrap_err();
        let kinds: Vec<TargetRejectionKind> = rejected
            .reasons()
            .iter()
            .map(TargetRejection::kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                TargetRejectionKind::HandshakeTooSlow,
                TargetRejectionKind::UnsupportedKeyExchange,
                TargetRejectionKind::NotHttp2,
                TargetRejectionKind::Redirect,
                TargetRejectionKind::NoAddress,
                TargetRejectionKind::CdnNotExcluded,
            ]
        );
        let message = rejected.to_string();
        assert!(message.starts_with("REALITY target rejected: p95 handshake is 9000 µs"));
        assert_eq!(message.matches("; ").count(), 5);
    }

    #[test]
    fn deny_list_covers_the_xray_warning_set_and_shared_targets() {
        let rule = |name: &str| deny_rule(&DnsName::parse(name).unwrap());
        assert_eq!(
            rule("www.apple.com"),
            Some(DenyRule::XrayWarnedSubstring("apple"))
        );
        assert_eq!(
            rule("gateway.icloud.com"),
            Some(DenyRule::XrayWarnedSubstring("icloud"))
        );
        assert_eq!(
            rule("www.microsoft.com"),
            Some(DenyRule::XrayWarnedSubstring("microsoft"))
        );
        assert_eq!(
            rule("pineapple.example"),
            Some(DenyRule::XrayWarnedSubstring("apple"))
        );
        assert_eq!(rule("www.baidu.cn"), Some(DenyRule::XrayWarnedTld("cn")));
        assert_eq!(rule("yandex.ru"), Some(DenyRule::XrayWarnedTld("ru")));
        assert_eq!(rule("example.ir"), Some(DenyRule::XrayWarnedTld("ir")));
        assert_eq!(
            rule("dl.google.com"),
            Some(DenyRule::SharedTarget("google.com"))
        );
        assert_eq!(
            rule("www.lovelive-anime.jp"),
            Some(DenyRule::SharedTarget("lovelive-anime.jp"))
        );
        assert_eq!(
            rule("addons.mozilla.org"),
            Some(DenyRule::SharedTarget("mozilla.org"))
        );
        assert_eq!(rule("www.harbour-target.test"), None);
        assert_eq!(rule("notgoogle.com"), None);
        assert_eq!(rule("cnn.com"), None);
        assert_eq!(rule("www.ru.example"), None);
    }

    #[test]
    fn stored_targets_require_a_positive_attestation() {
        let target = qualify(&passing_facts(), attestation())
            .unwrap()
            .into_target();
        let json = serde_json::to_string(&target).unwrap();
        assert_eq!(serde_json::from_str::<TargetSpec>(&json).unwrap(), target);
        let unattested = json.replace("\"same_asn\":true", "\"same_asn\":false");
        assert!(serde_json::from_str::<TargetSpec>(&unattested).is_err());
        let special = json.replace("45.67.89.200", "192.168.1.1");
        assert!(serde_json::from_str::<TargetSpec>(&special).is_err());
        let extra = json.replace("\"host\"", "\"server_names\":[],\"host\"");
        assert!(serde_json::from_str::<TargetSpec>(&extra).is_err());
    }

    #[test]
    fn evidence_url_and_http_status_rules() {
        assert!(EvidenceUrl::parse("https://bgp.he.net/AS44684#_prefixes").is_ok());
        for bad in [
            "http://bgp.he.net/",
            "https://",
            "https:///path",
            "https://a b",
            "ftp://x",
            &format!("https://{}", "a".repeat(2041)),
        ] {
            assert_eq!(
                EvidenceUrl::parse(bad),
                Err(ModelError::InvalidEvidenceUrl),
                "{bad}"
            );
        }
        assert!(EvidenceUrl::parse(&format!("https://{}", "a".repeat(2040))).is_ok());
        assert_eq!(
            HttpStatus::new(99),
            Err(ModelError::InvalidHttpStatus { status: 99 })
        );
        assert_eq!(
            HttpStatus::new(600),
            Err(ModelError::InvalidHttpStatus { status: 600 })
        );
    }

    proptest! {
        #[test]
        fn rejections_match_the_rules_exactly(
            bytes in 0_u32..40_000,
            p95 in 0_u64..20_000,
            status in 100_u16..600,
        ) {
            let mut facts = passing_facts();
            session(&mut facts).first_flight_bytes = bytes;
            session(&mut facts).handshake_p95_micros = p95;
            facts.http = responded(status, HttpVersion::Http2);
            let mut expected = Vec::new();
            if bytes > 16_384 { expected.push(TargetRejectionKind::FirstFlightTooLarge); }
            if p95 > 5_000 { expected.push(TargetRejectionKind::HandshakeTooSlow); }
            if (300..=399).contains(&status) { expected.push(TargetRejectionKind::Redirect); }
            prop_assert_eq!(kinds_of(&facts, attestation()), expected);
        }
    }
}
