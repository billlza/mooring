// SPDX-License-Identifier: GPL-3.0-or-later

//! [`TargetFacts`]: the raw measurements `TargetCheck` returns about a
//! candidate REALITY target (design §11.7). The agent only measures; the Mac
//! evaluates the qualification rules.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{CertName, RedirectUrl, TargetHost, ValueError};

/// What `TargetCheck{host}` measured.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetFacts {
    /// The host that was checked.
    pub host: TargetHost,
    /// Its IPv4 addresses as the VPS resolves them (empty if none).
    pub resolved: BTreeSet<Ipv4Addr>,
    /// `xray tls ping <host>` with SNI, against port 443.
    pub tls: TlsProbe,
    /// `curl --http2` of `https://<host>/`.
    pub http: HttpProbe,
}

/// The outcome of the TLS probe.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TlsProbe {
    /// No TCP connection to port 443 could be made.
    ConnectFailed,
    /// TCP connected but the TLS handshake failed.
    HandshakeFailed,
    /// The handshake completed.
    Completed(TlsSession),
}

/// A completed TLS handshake with the target.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSession {
    /// The negotiated version.
    pub version: TlsVersion,
    /// The negotiated key-exchange group; `None` for TLS 1.2 RSA key
    /// transport, which has none.
    #[serde(deserialize_with = "Option::deserialize")]
    pub group: Option<TlsGroup>,
    /// Total DER length of the certificate chain the target sent.
    pub chain_bytes: u32,
    /// Number of certificates in that chain.
    pub chain_certs: u16,
    /// The leaf certificate's DNS subject alternative names, in certificate
    /// order.
    pub leaf_names: Vec<CertName>,
    /// The 95th percentile of the full handshake time over
    /// [`TARGET_HANDSHAKE_SAMPLES`] handshakes, in microseconds.
    pub handshake_p95_micros: u64,
    /// The size of the server's first flight, in bytes.
    pub first_flight_bytes: u32,
}

/// The number of handshakes `TargetCheck` times for the p95 figure.
pub const TARGET_HANDSHAKE_SAMPLES: u8 = 20;

closed_enum! {
    /// A negotiated TLS version (`xray tls ping` offers 1.2 and 1.3 only).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum TlsVersion {
        /// TLS 1.2.
        Tls12,
        /// TLS 1.3.
        Tls13,
    }
}

/// A TLS key-exchange group, identified by its IANA "TLS Supported Groups"
/// code point (Go's `tls.CurveID` uses the same numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TlsGroup(u16);

impl TlsGroup {
    /// `secp256r1` (23).
    pub const SECP256R1: Self = Self(0x0017);
    /// `secp384r1` (24).
    pub const SECP384R1: Self = Self(0x0018);
    /// `x25519` (29).
    pub const X25519: Self = Self(0x001d);
    /// `X25519MLKEM768` (4588), the post-quantum hybrid.
    pub const X25519_MLKEM768: Self = Self(0x11ec);

    /// Wraps a code point.
    pub const fn new(code_point: u16) -> Self {
        Self(code_point)
    }

    /// The code point.
    pub const fn code_point(self) -> u16 {
        self.0
    }
}

/// The outcome of the HTTP/2 probe of `/`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum HttpProbe {
    /// No HTTP response arrived (`curl` printed status `000`).
    Failed,
    /// A response arrived.
    Responded {
        /// `%{http_code}`.
        status: HttpStatus,
        /// `%{http_version}`.
        version: HttpVersion,
        /// `%{redirect_url}`, absent when curl printed nothing.
        #[serde(deserialize_with = "Option::deserialize")]
        redirect: Option<RedirectUrl>,
    },
}

/// An HTTP status code, 100 to 599.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct HttpStatus(u16);

impl HttpStatus {
    /// Validates `status` in 100..=599.
    pub const fn new(status: u16) -> Result<Self, ValueError> {
        if status >= 100 && status <= 599 {
            Ok(Self(status))
        } else {
            Err(ValueError::HttpStatus { status })
        }
    }

    /// The status code.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Whether this is a redirection (3xx).
    pub const fn is_redirect(self) -> bool {
        self.0 >= 300 && self.0 <= 399
    }
}

impl TryFrom<u16> for HttpStatus {
    type Error = ValueError;

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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

closed_enum! {
    /// The HTTP version `curl` reports.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_is_bounded() {
        assert_eq!(HttpStatus::new(100).map(HttpStatus::get), Ok(100));
        assert_eq!(HttpStatus::new(599).map(HttpStatus::get), Ok(599));
        assert_eq!(
            HttpStatus::new(0),
            Err(ValueError::HttpStatus { status: 0 })
        );
        assert_eq!(
            HttpStatus::new(600),
            Err(ValueError::HttpStatus { status: 600 })
        );
        assert!(serde_json::from_str::<HttpStatus>("99").is_err());
        assert!(HttpStatus::new(301).unwrap().is_redirect());
        assert!(!HttpStatus::new(200).unwrap().is_redirect());
    }

    #[test]
    fn groups_are_iana_code_points() {
        assert_eq!(TlsGroup::X25519_MLKEM768.code_point(), 4588);
        assert_eq!(TlsGroup::X25519.code_point(), 29);
        assert_eq!(
            serde_json::to_string(&TlsGroup::X25519_MLKEM768).unwrap(),
            "4588"
        );
    }
}
