// SPDX-License-Identifier: GPL-3.0-or-later

//! The router adapter's typed errors (design §14, "daemon: router").
//!
//! No variant holds a byte of the M7's answer, a header value, a cookie,
//! the login token or the password: framing faults are fieldless, a parse
//! error names an allowlisted path, the login's answer keeps its status and
//! which of the M7's own URLs its `Location` named ([`LoginAnswer`]), and an
//! I/O failure keeps only its `io::ErrorKind`. The one exception is what the
//! M7's login-failed page reports ([`LoginFailure`]): its error number, kept
//! only as 1 to 4 digits, and which of the login form's four fields it names
//! ([`LoginField`]), any other value kept as "another field" with none of its
//! bytes, so nothing a device echoes back is printed. Each error's kind is the
//! status's [`RouterUnavailableReason`]; a document the parser refuses takes
//! the parser's own reason ([`RouterParseError::reason`]), so the CLI and the
//! router panel classify it by one rule (design §14).

use std::fmt;
use std::io;

use mooring_daemon_core::RouterParseError;
use mooring_daemon_core::exit::EgressFault;
use mooring_daemon_core::router::RouterUnavailableReason;
use mooring_daemon_core::router::netgear::LOGIN_FIELDS;
use mooring_model::iface::MacAddr;

/// The router adapter cannot give a status.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RouterError {
    /// The adapter is not set up: the M7's identity or its admin password
    /// is not recorded. Nothing was sent.
    #[error("{}: {missing}", reason_phrase(RouterUnavailableReason::NotConfigured))]
    NotConfigured {
        /// What is missing.
        missing: Missing,
    },
    /// The M7 could not be reached.
    #[error("{}: {cause}", reason_phrase(RouterUnavailableReason::Unreachable))]
    Unreachable {
        /// Why.
        cause: UnreachableCause,
    },
    /// The M7 did not grant an administrator's session.
    #[error("{}: {cause}", reason_phrase(RouterUnavailableReason::AuthFailed))]
    AuthFailed {
        /// Why.
        cause: AuthCause,
    },
    /// The gateway is not the pinned M7, so no password was sent.
    #[error(
        "{} (pinned {expected}, found {found}); no password was sent",
        reason_phrase(RouterUnavailableReason::IdentityMismatch)
    )]
    IdentityMismatch {
        /// The pinned link-layer address.
        expected: MacAddr,
        /// What the neighbour table holds for the gateway.
        found: FoundLink,
    },
    /// The device or its attachment is not supported.
    #[error("{}: {cause}", reason_phrase(RouterUnavailableReason::Unsupported))]
    Unsupported {
        /// Why.
        cause: UnsupportedCause,
    },
    /// The M7's answer could not be read.
    #[error("{}: {cause}", reason_phrase(RouterUnavailableReason::Malformed))]
    Malformed {
        /// Why.
        cause: MalformedCause,
    },
    /// The parser refused the M7's `model.json` (as a session, a status or
    /// a capture). Its kind is the parser's own reason: a session that is
    /// not an administrator's is a failed login, another device or API is
    /// unsupported, and everything else is malformed.
    #[error(
        "{}: {error}{}",
        reason_phrase(.error.reason()),
        LoginNote(*.login)
    )]
    Document {
        /// Why the parser refused it.
        error: RouterParseError,
        /// The login's answer, `None` when no login was sent.
        login: Option<LoginAnswer>,
    },
}

impl RouterError {
    /// The status's reason for this error, which is its kind.
    pub(crate) const fn reason(&self) -> RouterUnavailableReason {
        match self {
            Self::NotConfigured { .. } => RouterUnavailableReason::NotConfigured,
            Self::Unreachable { .. } => RouterUnavailableReason::Unreachable,
            Self::AuthFailed { .. } => RouterUnavailableReason::AuthFailed,
            Self::IdentityMismatch { .. } => RouterUnavailableReason::IdentityMismatch,
            Self::Unsupported { .. } => RouterUnavailableReason::Unsupported,
            Self::Malformed { .. } => RouterUnavailableReason::Malformed,
            Self::Document { error, .. } => error.reason(),
        }
    }

    /// A framing fault of the M7's HTTP answer.
    pub(crate) const fn http(fault: HttpFault) -> Self {
        Self::Malformed {
            cause: MalformedCause::Http(fault),
        }
    }

    /// A redirect the client does not follow, answering `step` with
    /// `status`.
    pub(crate) const fn redirect(step: RedirectStep, status: u16) -> Self {
        Self::Malformed {
            cause: MalformedCause::Redirect { step, status },
        }
    }

    /// The M7 could not be reached for `cause`.
    pub(crate) const fn unreachable(cause: UnreachableCause) -> Self {
        Self::Unreachable { cause }
    }
}

/// What the router adapter lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Missing {
    /// No router identity is pinned.
    Pin,
    /// No admin password is stored.
    Password,
    /// The pin records no interface to the M7 (a version-1 pin): the
    /// daemon has none to poll on.
    Interface,
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pin => "no router identity is pinned (mooringctl router pin)",
            Self::Password => "no M7 admin password is stored (mooringctl router set-password)",
            Self::Interface => {
                "the router pin records no interface to the M7 (mooringctl router pin --interface <bsd>)"
            }
        })
    }
}

/// The step that ran out of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Connecting.
    Connect,
    /// Sending the request.
    Send,
    /// Receiving the answer.
    Receive,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connecting",
            Self::Send => "sending",
            Self::Receive => "receiving",
        })
    }
}

/// Why the M7 could not be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnreachableCause {
    /// The exit's interfaces do not resolve, so there is no egress to poll
    /// the M7 on (with a deployment, design §10.1 step 2).
    ExitInterfacesUnresolved {
        /// Why.
        fault: EgressFault,
    },
    /// The interface does not exist.
    InterfaceAbsent,
    /// The interface has no IPv4 default route through a gateway.
    NoDefaultRoute,
    /// The interface has default routes through more than one gateway.
    AmbiguousDefaultRoute,
    /// The neighbour table has no link-layer address for the gateway.
    GatewayUnresolved,
    /// A socket could not be created or configured.
    Socket {
        /// The operating system's error kind.
        kind: io::ErrorKind,
    },
    /// The socket could not be bound to the interface (`IP_BOUND_IF`).
    Bind {
        /// The operating system's error kind.
        kind: io::ErrorKind,
    },
    /// The connection failed.
    Connect {
        /// The operating system's error kind.
        kind: io::ErrorKind,
    },
    /// Sending the request failed.
    Send {
        /// The operating system's error kind.
        kind: io::ErrorKind,
    },
    /// Receiving the answer failed.
    Receive {
        /// The operating system's error kind.
        kind: io::ErrorKind,
    },
    /// A step ran out of time (the per-step or the per-request limit).
    Timeout {
        /// The step.
        phase: Phase,
    },
    /// The M7 closed the connection before answering.
    Closed,
}

impl fmt::Display for UnreachableCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExitInterfacesUnresolved { fault } => {
                write!(f, "the exit's interfaces do not resolve: {fault}")
            }
            Self::InterfaceAbsent => f.write_str("the interface does not exist"),
            Self::NoDefaultRoute => {
                f.write_str("the interface has no IPv4 default route through a gateway")
            }
            Self::AmbiguousDefaultRoute => {
                f.write_str("the interface has IPv4 default routes through more than one gateway")
            }
            Self::GatewayUnresolved => {
                f.write_str("the gateway's link-layer address is not in the neighbour table")
            }
            Self::Socket { kind } => write!(f, "a socket could not be set up ({kind})"),
            Self::Bind { kind } => {
                write!(f, "the socket could not be bound to the interface ({kind})")
            }
            Self::Connect { kind } => write!(f, "connecting failed ({kind})"),
            Self::Send { kind } => write!(f, "sending the request failed ({kind})"),
            Self::Receive { kind } => write!(f, "receiving the answer failed ({kind})"),
            Self::Timeout { phase } => write!(f, "timed out {phase}"),
            Self::Closed => f.write_str("the connection closed before an answer"),
        }
    }
}

/// Why no administrator's session was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthCause {
    /// The M7 reports a password cool-off (`session.passwordCooloff`), so
    /// no password was sent.
    Cooloff {
        /// The value it reports (unit unverified).
        reported: u32,
    },
    /// The status request was refused (401 or 403).
    Refused {
        /// The status.
        status: u16,
    },
    /// The login was answered by a `302 Found` to the M7's login-failed
    /// page (the form's `err_redirect`). Nothing more was sent. The
    /// message names what the page reported, and reads the refusal as the
    /// stored admin password being wrong only when it names the password's
    /// field, or when it reports nothing *(inference: that page is
    /// where the form asks the M7 to send a failed login)*.
    LoginRefused {
        /// What that page's query reported, `None` when nothing in its
        /// shape.
        reported: Option<LoginFailure>,
    },
}

/// What a refusal read as the stored password being wrong tells the
/// operator to do.
const STORE_AGAIN: &str = "store the password again with `mooringctl router set-password`";

impl fmt::Display for AuthCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cooloff { reported } => write!(
                f,
                "it reports a password cool-off ({reported}), so no password was sent"
            ),
            Self::Refused { status } => write!(f, "the status request was refused ({status})"),
            Self::LoginRefused { reported: None } => write!(
                f,
                "it refused the stored admin password (the login was sent to its login-failed page); {STORE_AGAIN}"
            ),
            Self::LoginRefused {
                reported: Some(reported),
            } if reported.names_the_password() => write!(
                f,
                "it refused the login ({reported}, read as the stored admin password being wrong); {STORE_AGAIN}"
            ),
            Self::LoginRefused {
                reported: Some(reported),
            } => write!(f, "it refused the login ({reported})"),
        }
    }
}

/// A field the M7's login-failed page names in `errdetail`
/// (`session.password` on 2026-10-14): one of the four fields the login form
/// sends ([`LOGIN_FIELDS`]), on an exact byte match, or any other value, of
/// which nothing is kept. Only the form's own names, which the client sends,
/// can be printed, so a device that echoes a secret (the password, the token
/// or a cookie) back in `errdetail` cannot make the client print it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginField {
    /// `token`.
    Token,
    /// `err_redirect`.
    ErrRedirect,
    /// `ok_redirect`.
    OkRedirect,
    /// `session.password`.
    Password,
    /// Any other value; none of its bytes is kept.
    Other,
}

impl LoginField {
    /// The form's fields, in [`LOGIN_FIELDS`]' order.
    const NAMED: [Self; 4] = [
        Self::Token,
        Self::ErrRedirect,
        Self::OkRedirect,
        Self::Password,
    ];

    /// `value` as a field: one of the form's four names on an exact byte
    /// match, else [`LoginField::Other`].
    pub(crate) fn of(value: &[u8]) -> Self {
        LOGIN_FIELDS
            .iter()
            .zip(Self::NAMED)
            .find(|(name, _)| name.as_bytes() == value)
            .map_or(Self::Other, |(_, field)| field)
    }

    /// The form's name for the field, `None` for any other value.
    fn name(self) -> Option<&'static str> {
        let [token, err_redirect, ok_redirect, password] = LOGIN_FIELDS;
        match self {
            Self::Token => Some(token),
            Self::ErrRedirect => Some(err_redirect),
            Self::OkRedirect => Some(ok_redirect),
            Self::Password => Some(password),
            Self::Other => None,
        }
    }
}

/// `field session.password` for one of the form's fields, `another field`
/// for any other value.
impl fmt::Display for LoginField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "field {name}"),
            None => f.write_str("another field"),
        }
    }
}

/// What the M7's login-failed page reported about a refused login, read
/// from the query parameters after `?loginfailed&` (observed on 2026-10-14:
/// `errno=2&errdetail=session.password`): an error number (`errno`, 1 to 4
/// ASCII digits), a field (`errdetail`, as a [`LoginField`]), or both. Each
/// is kept only when given once, the number only in its shape and the field
/// only when not empty. What the numbers mean is unknown: the M7's own page
/// script ignores both parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginFailure {
    /// An error number, and no field.
    Number(u16),
    /// A field, and no error number.
    Field(LoginField),
    /// An error number on a field.
    NumberOnField(u16, LoginField),
}

impl LoginFailure {
    /// Whether the field named is the login form's password field
    /// (`session.password`): the only report read as the stored admin
    /// password being wrong *(inference: the M7 refused the login with it
    /// when the operator's password was refused, and documents neither
    /// parameter)*.
    pub(crate) const fn names_the_password(&self) -> bool {
        matches!(
            self,
            Self::Field(LoginField::Password) | Self::NumberOnField(_, LoginField::Password)
        )
    }
}

/// `error 2 on field session.password`, `error 2`, `an error on field
/// token`, or `error 7 on another field`.
impl fmt::Display for LoginFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(number) => write!(f, "error {number}"),
            Self::Field(field) => write!(f, "an error on {field}"),
            Self::NumberOnField(number, field) => write!(f, "error {number} on {field}"),
        }
    }
}

/// Where a `Location` points: one of the M7's own URLs the client knows, or
/// anywhere else. Only this judgement is kept ([`Location::of`]), with what
/// the login-failed page reports, never the header's bytes, and the client
/// never requests a `Location`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    /// The session set-up target on the M7.
    SessionSetup,
    /// The JSON endpoint on the M7.
    ModelJson,
    /// The login form's `ok_redirect` (`/index.html`, the start page) on
    /// the M7: where the form asks the M7 to send a login it accepts.
    LoginAccepted,
    /// The login form's `err_redirect` (`/index.html?loginfailed`, the
    /// login-failed page) on the M7, alone or followed by `&` and
    /// parameters: where the form asks the M7 to send a login it refuses.
    LoginRefused {
        /// What the page's query reported, `None` when nothing in its
        /// shape.
        reported: Option<LoginFailure>,
    },
    /// Anywhere else: another scheme, host, port, path or encoding, a
    /// relative reference, or no URL.
    Elsewhere,
}

/// What the client keeps of the login's answer: its status and where its
/// `Location` points, with what the login-failed page reported. Its body is
/// never read, and no byte of it is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoginAnswer {
    /// The status.
    pub(crate) status: u16,
    /// Where its `Location` points, `None` without one.
    pub(crate) location: Option<Location>,
}

impl LoginAnswer {
    /// The refusal, when the M7 sent the login to its login-failed page: a
    /// `302 Found` there, the only answer read as a refusal (design §15.6
    /// rule 9), with what the page reported.
    pub(crate) const fn refusal(self) -> Option<AuthCause> {
        match self {
            Self {
                status: 302,
                location: Some(Location::LoginRefused { reported }),
            } => Some(AuthCause::LoginRefused { reported }),
            _ => None,
        }
    }
}

/// The status and where the `Location` points, with what the login-failed
/// page reported, never its bytes: `status 302 and a Location to the start
/// page`, `status 303 and a Location to the login-failed page with error 2
/// on field session.password`.
impl fmt::Display for LoginAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "status {} and ", self.status)?;
        match self.location {
            Some(Location::SessionSetup) => f.write_str("a Location to the M7's session set-up"),
            Some(Location::ModelJson) => f.write_str("a Location to the JSON endpoint"),
            Some(Location::LoginAccepted) => f.write_str("a Location to the start page"),
            Some(Location::LoginRefused { reported: None }) => {
                f.write_str("a Location to the login-failed page")
            }
            Some(Location::LoginRefused {
                reported: Some(reported),
            }) => write!(f, "a Location to the login-failed page with {reported}"),
            Some(Location::Elsewhere) => f.write_str("a Location elsewhere"),
            None => f.write_str("no Location"),
        }
    }
}

/// The address Apple's iOS reports in place of a real link-layer address.
/// It is a valid unicast address, which `MacAddr` accepts, but every
/// network would match it, so it never identifies the M7: it is never
/// pinned, and never matches a pin (design §15.6 rule 4). No macOS has been
/// seen to report it; the rule guards against one that would.
pub(crate) const PRIVACY_PLACEHOLDER: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];

/// A gateway link-layer address that cannot identify the M7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnusableLink {
    /// Six bytes that are not a unicast address (zero, multicast or
    /// broadcast).
    NotUnicast([u8; 6]),
    /// The placeholder Apple's iOS reports in place of a real address
    /// (`PRIVACY_PLACEHOLDER`), which every network would match.
    PrivacyPlaceholder,
    /// An address that is not six bytes long.
    NotEthernet {
        /// Its length.
        alen: u8,
    },
    /// Different addresses for the gateway on the interface.
    Ambiguous,
}

impl fmt::Display for UnusableLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnicast(bytes) => {
                write!(f, "{}, which is not a unicast address", LinkBytes(*bytes))
            }
            Self::PrivacyPlaceholder => write!(
                f,
                "{}, the placeholder Apple's iOS reports in place of a real address",
                LinkBytes(PRIVACY_PLACEHOLDER)
            ),
            Self::NotEthernet { alen } => write!(f, "a link-layer address of {alen} bytes"),
            Self::Ambiguous => f.write_str("more than one link-layer address"),
        }
    }
}

/// Six bytes as `aa:bb:cc:dd:ee:ff`, whether or not they are a `MacAddr`.
struct LinkBytes([u8; 6]);

impl fmt::Display for LinkBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// What the neighbour table holds for the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FoundLink {
    /// A unicast address other than the pinned one.
    Address(MacAddr),
    /// Nothing that can identify a device.
    Unusable(UnusableLink),
}

impl fmt::Display for FoundLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(addr) => write!(f, "{addr}"),
            Self::Unusable(link) => write!(f, "{link}"),
        }
    }
}

/// Why the device or its attachment is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsupportedCause {
    /// The JSON endpoint answered 404.
    EndpointMissing,
    /// The gateway's link-layer address cannot identify a device, so there
    /// is nothing to pin.
    GatewayLink(UnusableLink),
}

impl fmt::Display for UnsupportedCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointMissing => f.write_str("its JSON endpoint answered 404"),
            Self::GatewayLink(link) => write!(f, "the gateway has {link}"),
        }
    }
}

/// Why the answer could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MalformedCause {
    /// The HTTP framing is broken.
    Http(HttpFault),
    /// An HTTP status the client does not accept.
    Status {
        /// The status.
        code: u16,
    },
    /// A redirect the client does not follow (design §15.6 rule 9): at
    /// the first status request, a 3xx answer other than the `302` that
    /// starts the M7's session set-up; at the set-up, any answer other
    /// than the `302` back to the status request; at the status request
    /// after the set-up, any 3xx answer. Neither its `Location` nor any
    /// other byte of it is kept.
    Redirect {
        /// The request it answered.
        step: RedirectStep,
        /// Its status.
        status: u16,
    },
    /// A web page (`text/html`), which is never read: `index.html` carries
    /// the IMEI.
    Html,
}

impl fmt::Display for MalformedCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(fault) => write!(f, "{fault}"),
            Self::Status { code } => write!(f, "unexpected HTTP status {code}"),
            Self::Redirect { step, status } => match step {
                RedirectStep::First => write!(
                    f,
                    "the status request was answered by a redirect other than the M7's session set-up (status {status})"
                ),
                RedirectStep::SessionSetup => write!(
                    f,
                    "the M7's session set-up was not answered by a redirect back to the status request (status {status})"
                ),
                RedirectStep::Retried => write!(
                    f,
                    "the status request after the M7's session set-up was answered by another redirect (status {status})"
                ),
            },
            Self::Html => f.write_str("it is a web page (text/html), which is never read"),
        }
    }
}

/// The request of one read of `model.json` that a refused redirect
/// answered: the client follows only the M7's session set-up, at most
/// once per read (design §15.6 rule 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirectStep {
    /// The first `GET` of the JSON endpoint.
    First,
    /// The `GET` of the session set-up target.
    SessionSetup,
    /// The `GET` of the JSON endpoint after the session set-up.
    Retried,
}

/// How an HTTP answer breaks its framing; no fault holds a byte of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HttpFault {
    /// The connection closed inside the head.
    TruncatedHead,
    /// The connection closed inside a body of known length or a chunk.
    TruncatedBody,
    /// The head is larger than 16 KiB.
    HeadTooLarge,
    /// The head has more than 64 header lines.
    TooManyHeaders,
    /// The status line is not `HTTP/1.1` or `HTTP/1.0` and three digits.
    StatusLine,
    /// A header line is not `name: value`.
    HeaderLine,
    /// A header line is folded (obsolete line folding).
    ObsFold,
    /// Different `Content-Length` values, or one with `Transfer-Encoding`.
    ConflictingLength,
    /// A `Content-Length` that is not a decimal number.
    BadContentLength,
    /// A `Transfer-Encoding` other than exactly `chunked`.
    TransferEncoding,
    /// A `Content-Encoding`, which the client never asks for.
    ContentEncoding,
    /// A chunk size line that is not one to eight hexadecimal digits.
    ChunkSize,
    /// A chunk's data not followed by a line end.
    ChunkTerminator,
    /// A `Set-Cookie` that is not `name=value` within 4096 bytes.
    Cookie,
    /// More than 16 cookies.
    TooManyCookies,
    /// More than one `Location`.
    RepeatedLocation,
    /// A body larger than 1 MiB.
    TooLarge,
}

impl HttpFault {
    /// Every fault, in declaration order.
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::TruncatedHead,
        Self::TruncatedBody,
        Self::HeadTooLarge,
        Self::TooManyHeaders,
        Self::StatusLine,
        Self::HeaderLine,
        Self::ObsFold,
        Self::ConflictingLength,
        Self::BadContentLength,
        Self::TransferEncoding,
        Self::ContentEncoding,
        Self::ChunkSize,
        Self::ChunkTerminator,
        Self::Cookie,
        Self::TooManyCookies,
        Self::RepeatedLocation,
        Self::TooLarge,
    ];
}

impl fmt::Display for HttpFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TruncatedHead => "the connection closed inside the HTTP head",
            Self::TruncatedBody => "the connection closed inside the body",
            Self::HeadTooLarge => "the HTTP head is larger than 16 KiB",
            Self::TooManyHeaders => "the HTTP head has more than 64 header lines",
            Self::StatusLine => "the HTTP status line is malformed",
            Self::HeaderLine => "an HTTP header line is malformed",
            Self::ObsFold => "an HTTP header line is folded",
            Self::ConflictingLength => "the body's length is given twice in conflicting ways",
            Self::BadContentLength => "the Content-Length is not a decimal number",
            Self::TransferEncoding => "the Transfer-Encoding is not exactly chunked",
            Self::ContentEncoding => "the body has a Content-Encoding",
            Self::ChunkSize => "a chunk size is malformed",
            Self::ChunkTerminator => "a chunk is not followed by a line end",
            Self::Cookie => "a Set-Cookie is malformed or longer than 4096 bytes",
            Self::TooManyCookies => "the M7 set more than 16 cookies",
            Self::RepeatedLocation => "the HTTP head has more than one Location",
            Self::TooLarge => "the body is larger than 1 MiB",
        })
    }
}

/// What every router error of `reason` begins with.
pub(crate) const fn reason_phrase(reason: RouterUnavailableReason) -> &'static str {
    match reason {
        RouterUnavailableReason::NotConfigured => "the router adapter is not set up",
        RouterUnavailableReason::Unreachable => "the M7 is unreachable",
        RouterUnavailableReason::AuthFailed => "the M7 did not grant an administrator's session",
        RouterUnavailableReason::IdentityMismatch => "the gateway is not the pinned M7",
        RouterUnavailableReason::Unsupported => "the device is not a supported M7",
        RouterUnavailableReason::Malformed => "the M7's answer is malformed",
        RouterUnavailableReason::LocalFailure => "the Mac could not poll the M7",
    }
}

/// The login's answer after a refused document, when a login was sent.
struct LoginNote(Option<LoginAnswer>);

impl fmt::Display for LoginNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(answer) => write!(f, " (the login was answered with {answer})"),
            None => Ok(()),
        }
    }
}
