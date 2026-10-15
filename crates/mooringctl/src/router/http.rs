// SPDX-License-Identifier: GPL-3.0-or-later

//! The M7's HTTP/1.1 client (design §15.6): plain HTTP on the LAN, one
//! connection per request, bound to the M7's interface (`IP_BOUND_IF`).
//!
//! - Only three requests exist ([`Request`]): the JSON status endpoint, the
//!   M7's session set-up and the login form, all from `daemon-core`'s
//!   constants, so no other target (`/`, `/index.html`, `/model.json`) can
//!   be asked for.
//! - One redirect sequence is followed, at most once per read of the JSON
//!   endpoint: the M7's session set-up (observed 2026-10-14, design §15.6
//!   rule 9). A `Location` is only compared with the two URLs of that
//!   sequence and the login form's two targets on the M7's own address
//!   (the login-failed page alone or followed by `&` and parameters), never
//!   requested and never kept; every other redirect is refused, and the
//!   login's is never followed: only its status and where its `Location`
//!   points are returned, with the login-failed page's `errno` and
//!   `errdetail` when each has its shape.
//! - Every step is bounded: connect, each read and write, the whole
//!   request, the head (16 KiB, 64 lines) and the body (1 MiB).
//! - The head is read one byte at a time, so no body byte is read before
//!   its framing is known, and the body of the login answer or of a
//!   redirect is never read.
//! - Request and body buffers are zeroizing and never grow (no copies of
//!   the password or the document are left behind by reallocation).
//! - Nothing is logged; errors never hold a byte of the answer.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use mooring_daemon_core::router::netgear::{
    LOGIN_ERR_REDIRECT, LOGIN_OK_REDIRECT, LOGIN_TARGET, MODEL_JSON_TARGET, SESSION_SETUP_TARGET,
};
use mooring_model::exact::{self, TextSink};
use mooring_model::iface::InterfaceIndex;
use socket2::{Domain, Protocol, Socket, Type};
use zeroize::Zeroizing;

use crate::router::cookies::{CookieJar, parse_set_cookie};
use crate::router::error::{
    AuthCause, HttpFault, Location, LoginAnswer, LoginFailure, LoginField, MalformedCause, Phase,
    RedirectStep, RouterError, UnreachableCause, UnsupportedCause,
};
use crate::router::form::LoginBody;
use crate::router::link::VerifiedIdentity;

/// The M7's HTTP port.
pub(crate) const HTTP_PORT: u16 = 80;

/// The largest body read, in bytes.
pub(crate) const MAX_BODY_BYTES: usize = 1 << 20;

/// The largest head read, in bytes.
pub(crate) const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The most header lines read.
pub(crate) const MAX_HEADER_LINES: usize = 64;

/// The most hexadecimal digits of a chunk size (4 GiB, far above the body
/// limit).
const MAX_CHUNK_SIZE_DIGITS: usize = 8;

/// The longest chunk size line, extensions included, in bytes.
const MAX_CHUNK_LINE_BYTES: usize = 1024;

/// The client's limits on time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Timeouts {
    /// Connecting.
    pub(crate) connect: Duration,
    /// Each read or write.
    pub(crate) io: Duration,
    /// The whole request, from connecting to the last byte read.
    pub(crate) total: Duration,
}

/// The limits used with the M7 (design §15.6 rule 7).
pub(crate) const DEVICE_TIMEOUTS: Timeouts = Timeouts {
    connect: Duration::from_secs(5),
    io: Duration::from_secs(5),
    total: Duration::from_secs(15),
};

/// Where the M7 answers: its address and port, through an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Endpoint {
    /// The gateway's address and the HTTP port.
    pub(crate) addr: SocketAddrV4,
    /// The interface the socket is bound to.
    pub(crate) interface: InterfaceIndex,
}

/// The only requests the client can send.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Request<'a> {
    /// `GET /api/model.json?internalapi=1`.
    ModelJson,
    /// `GET` of the M7's session set-up target
    /// ([`SESSION_SETUP_TARGET`]).
    SessionSetup,
    /// `POST /Forms/config` with the login form.
    Login {
        /// The form's body.
        body: &'a LoginBody,
    },
}

impl Location {
    /// Judges a `Location` value against `endpoint`, byte for byte, with
    /// `<host>` written as the `Host` header writes it (the address, and the
    /// port unless it is 80): exactly `http://<host><target>` for the
    /// session set-up's, the JSON endpoint's or the start page's target;
    /// and the login-failed page when it is exactly `http://<host>` and the
    /// form's `err_redirect`, alone or followed by `&` and parameters, of
    /// which only what the page reports is kept ([`login_failure`]).
    pub(crate) fn of(value: &[u8], endpoint: &Endpoint) -> Self {
        let url = |target: &str| {
            let mut url = String::new();
            write_url(&mut url, endpoint, target);
            url
        };
        let exact = [
            (SESSION_SETUP_TARGET, Self::SessionSetup),
            (MODEL_JSON_TARGET, Self::ModelJson),
            (LOGIN_OK_REDIRECT, Self::LoginAccepted),
        ]
        .into_iter()
        .find(|(target, _)| value == url(target).as_bytes());
        if let Some((_, location)) = exact {
            return location;
        }
        match value.strip_prefix(url(LOGIN_ERR_REDIRECT).as_bytes()) {
            Some([]) => Self::LoginRefused { reported: None },
            Some([b'&', parameters @ ..]) => Self::LoginRefused {
                reported: login_failure(parameters),
            },
            _ => Self::Elsewhere,
        }
    }
}

/// The most digits of the login-failed page's `errno`.
const MAX_ERRNO_DIGITS: usize = 4;

/// What the login-failed page reports in `parameters`, the bytes after its
/// `?loginfailed&`. They are split at `&`; a parameter's name is what comes
/// before its first `=` (all of it without one) and its value what follows,
/// never decoded. Only `errno`, as 1 to 4 ASCII digits read as a number,
/// and `errdetail`, when not empty, as a [`LoginField`] (one of the form's
/// four names, or "another field" with none of its bytes kept), are read,
/// each only when its name is given exactly once; every other parameter is
/// ignored. `None` when neither is given.
fn login_failure(parameters: &[u8]) -> Option<LoginFailure> {
    let once = |wanted: &[u8]| {
        let mut values = parameters
            .split(|&byte| byte == b'&')
            .map(name_and_value)
            .filter(|(name, _)| *name == wanted)
            .map(|(_, value)| value);
        match (values.next(), values.next()) {
            (Some(value), None) => Some(value),
            _ => None,
        }
    };
    let number = once(b"errno").and_then(parse_errno);
    let field = once(b"errdetail")
        .filter(|value| !value.is_empty())
        .map(LoginField::of);
    match (number, field) {
        (None, None) => None,
        (Some(number), None) => Some(LoginFailure::Number(number)),
        (None, Some(field)) => Some(LoginFailure::Field(field)),
        (Some(number), Some(field)) => Some(LoginFailure::NumberOnField(number, field)),
    }
}

/// A query parameter's name and value: the bytes before and after its first
/// `=`, or all of it and nothing without one.
fn name_and_value(parameter: &[u8]) -> (&[u8], &[u8]) {
    match parameter.iter().position(|&byte| byte == b'=') {
        Some(at) => (&parameter[..at], &parameter[at + 1..]),
        None => (parameter, &[]),
    }
}

/// 1 to 4 ASCII digits, read as a number.
fn parse_errno(value: &[u8]) -> Option<u16> {
    let digits =
        (1..=MAX_ERRNO_DIGITS).contains(&value.len()) && value.iter().all(u8::is_ascii_digit);
    digits.then(|| {
        value
            .iter()
            .fold(0_u16, |number, digit| number * 10 + u16::from(digit - b'0'))
    })
}

/// A response body: in a zeroizing buffer, never shown in `Debug`.
pub(crate) struct Body(Zeroizing<Vec<u8>>);

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Body(<{} bytes>)", self.0.len())
    }
}

impl Body {
    /// The body's bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Writes the request's bytes: the request line, `Host`, `User-Agent`,
/// `Accept`, for the login `Origin`, `Referer`, `Content-Type` and
/// `Content-Length`, then `Cookie` when the jar holds any, `Connection:
/// close`, and the login's body.
fn write_request(
    sink: &mut dyn TextSink,
    request: Request<'_>,
    endpoint: &Endpoint,
    jar: &CookieJar,
) {
    let (method, target) = match request {
        Request::ModelJson => ("GET", MODEL_JSON_TARGET),
        Request::SessionSetup => ("GET", SESSION_SETUP_TARGET),
        Request::Login { .. } => ("POST", LOGIN_TARGET),
    };
    sink.put(method);
    sink.put(" ");
    sink.put(target);
    sink.put(" HTTP/1.1\r\nHost: ");
    write_host(sink, endpoint);
    sink.put("\r\nUser-Agent: mooringctl/");
    sink.put(env!("CARGO_PKG_VERSION"));
    match request {
        Request::ModelJson | Request::SessionSetup => {
            sink.put("\r\nAccept: application/json\r\n");
        }
        Request::Login { body } => {
            sink.put("\r\nAccept: */*\r\nOrigin: http://");
            write_host(sink, endpoint);
            sink.put("\r\nReferer: ");
            write_url(sink, endpoint, LOGIN_OK_REDIRECT);
            sink.put("\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ");
            sink.show(&body.len());
            sink.put("\r\n");
        }
    }
    if !jar.is_empty() {
        sink.put("Cookie: ");
        jar.write_header_value(sink);
        sink.put("\r\n");
    }
    sink.put("Connection: close\r\n\r\n");
    if let Request::Login { body } = request {
        sink.put(body.expose_str());
    }
}

/// `Host`: the address, and the port unless it is 80.
fn write_host(sink: &mut dyn TextSink, endpoint: &Endpoint) {
    sink.show(endpoint.addr.ip());
    if endpoint.addr.port() != HTTP_PORT {
        sink.put(":");
        sink.show(&endpoint.addr.port());
    }
}

/// `target` on the endpoint as an absolute URL: `http://`, the host as
/// `Host` writes it, and the target.
fn write_url(sink: &mut dyn TextSink, endpoint: &Endpoint, target: &str) {
    sink.put("http://");
    write_host(sink, endpoint);
    sink.put(target);
}

/// The request's bytes in an exactly sized zeroizing buffer.
pub(crate) fn request_bytes(
    request: Request<'_>,
    endpoint: &Endpoint,
    jar: &CookieJar,
) -> Zeroizing<String> {
    exact::text(|sink| write_request(sink, request, endpoint, jar))
}

fn timed_out(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// One connection, with the request's deadline.
struct Connection {
    stream: TcpStream,
    deadline: Instant,
    io: Duration,
    read_timeout: Duration,
}

impl Connection {
    /// Connects to `endpoint` through its interface.
    fn open(endpoint: &Endpoint, timeouts: &Timeouts) -> Result<Self, RouterError> {
        let deadline = Instant::now() + timeouts.total;
        let socket_error = |error: io::Error| {
            RouterError::unreachable(UnreachableCause::Socket { kind: error.kind() })
        };
        let socket =
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(socket_error)?;
        socket
            .bind_device_by_index_v4(Some(NonZeroU32::from(endpoint.interface)))
            .map_err(|error| {
                RouterError::unreachable(UnreachableCause::Bind { kind: error.kind() })
            })?;
        let target = SocketAddr::V4(endpoint.addr).into();
        socket
            .connect_timeout(&target, timeouts.connect.min(timeouts.total))
            .map_err(|error| {
                let cause = if timed_out(error.kind()) {
                    UnreachableCause::Timeout {
                        phase: Phase::Connect,
                    }
                } else {
                    UnreachableCause::Connect { kind: error.kind() }
                };
                RouterError::unreachable(cause)
            })?;
        socket
            .set_read_timeout(Some(timeouts.io))
            .map_err(socket_error)?;
        socket
            .set_write_timeout(Some(timeouts.io))
            .map_err(socket_error)?;
        Ok(Self {
            stream: socket.into(),
            deadline,
            io: timeouts.io,
            read_timeout: timeouts.io,
        })
    }

    /// The time left before the deadline; `Timeout{phase}` when none.
    fn remaining(&self, phase: Phase) -> Result<Duration, RouterError> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(RouterError::unreachable(UnreachableCause::Timeout {
                phase,
            }))
        } else {
            Ok(left)
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), RouterError> {
        self.remaining(Phase::Send)?;
        self.stream.write_all(bytes).map_err(|error| {
            let cause = if timed_out(error.kind()) {
                UnreachableCause::Timeout { phase: Phase::Send }
            } else {
                UnreachableCause::Send { kind: error.kind() }
            };
            RouterError::unreachable(cause)
        })
    }

    /// Reads into `buffer`; 0 at the end of the stream. Each read waits at
    /// most the per-read limit, and never past the request's deadline.
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, RouterError> {
        let wait = self.remaining(Phase::Receive)?.min(self.io);
        if wait != self.read_timeout {
            self.stream.set_read_timeout(Some(wait)).map_err(|error| {
                RouterError::unreachable(UnreachableCause::Socket { kind: error.kind() })
            })?;
            self.read_timeout = wait;
        }
        loop {
            match self.stream.read(buffer) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let cause = if timed_out(error.kind()) {
                        UnreachableCause::Timeout {
                            phase: Phase::Receive,
                        }
                    } else {
                        UnreachableCause::Receive { kind: error.kind() }
                    };
                    return Err(RouterError::unreachable(cause));
                }
            }
        }
    }

    /// Reads one byte; `None` at the end of the stream.
    fn byte(&mut self) -> Result<Option<u8>, RouterError> {
        let mut one = [0_u8; 1];
        Ok((self.read(&mut one)? == 1).then_some(one[0]))
    }
}

/// How reading a line ended: a whole line, or the end of the stream
/// (after `partial` bytes of an unfinished line).
enum LineEnd {
    Text,
    End { partial: bool },
}

/// Lines read one byte at a time into one zeroizing buffer, allocated once
/// with room for the whole budget so that it never grows (a header line
/// may carry a session cookie). Every byte read, line ends included, is
/// charged to the budget; past it the line is refused with `over`.
struct Lines {
    buffer: Zeroizing<Vec<u8>>,
    budget: usize,
    over: HttpFault,
}

impl Lines {
    fn new(budget: usize, over: HttpFault) -> Self {
        Self {
            buffer: Zeroizing::new(Vec::with_capacity(budget)),
            budget,
            over,
        }
    }

    /// Reads the next line, ending in LF (a CR before it is dropped; a
    /// bare LF is accepted, RFC 9112 §2.2), into [`Lines::line`].
    fn read(&mut self, conn: &mut Connection) -> Result<LineEnd, RouterError> {
        self.buffer.clear();
        loop {
            let Some(byte) = conn.byte()? else {
                return Ok(LineEnd::End {
                    partial: !self.buffer.is_empty(),
                });
            };
            self.budget = self
                .budget
                .checked_sub(1)
                .ok_or(RouterError::http(self.over))?;
            if byte == b'\n' {
                if self.buffer.last() == Some(&b'\r') {
                    self.buffer.pop();
                }
                return Ok(LineEnd::Text);
            }
            self.buffer.push(byte);
        }
    }

    /// The last line read, without its line end.
    fn line(&self) -> &[u8] {
        &self.buffer
    }
}

/// How the body's end is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Length(usize),
    Chunked,
    Close,
}

/// A response head: the status, the framing, whether it is a web page,
/// whether its body is encoded, and where its `Location` points, if it has
/// one; its cookies are already in the jar. What only matters for reading
/// the body (its size, its encoding) is checked when the body is read, so
/// an answer whose body is never read (the login's, a redirect's) is
/// refused only for a malformed head.
#[derive(Debug)]
struct Head {
    status: u16,
    framing: Framing,
    html: bool,
    encoded: bool,
    location: Option<Location>,
}

impl Head {
    /// Whether the status is a redirect (3xx).
    fn is_redirect(&self) -> bool {
        (300..=399).contains(&self.status)
    }

    /// Whether this is a `302 Found` to `location`: the only redirect the
    /// session set-up is made of.
    fn found_at(&self, location: Location) -> bool {
        self.status == 302 && self.location == Some(location)
    }
}

/// `HTTP/1.1` or `HTTP/1.0`, a space, three digits, then the end or a
/// space and a reason phrase.
fn parse_status_line(line: &[u8]) -> Result<u16, RouterError> {
    let refused = RouterError::http(HttpFault::StatusLine);
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))
        .ok_or(refused.clone())?;
    let (code, reason) = rest.split_at_checked(3).ok_or(refused.clone())?;
    if !code.iter().all(u8::is_ascii_digit) || !(reason.is_empty() || reason[0] == b' ') {
        return Err(refused);
    }
    Ok(code
        .iter()
        .fold(0_u16, |status, digit| status * 10 + u16::from(digit - b'0')))
}

/// RFC 9110 `tchar`.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// A header line: a token, a colon, then a value without control bytes
/// other than a tab, surrounding whitespace removed.
fn parse_header(line: &[u8]) -> Result<(&[u8], &[u8]), RouterError> {
    let refused = RouterError::http(HttpFault::HeaderLine);
    let colon = line
        .iter()
        .position(|&byte| byte == b':')
        .ok_or(refused.clone())?;
    let (name, value) = (&line[..colon], &line[colon + 1..]);
    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return Err(refused);
    }
    if value
        .iter()
        .any(|&byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        return Err(refused);
    }
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |last| last + 1);
    Ok((name, &value[start..end]))
}

/// A `Content-Length` list: one or more identical decimal numbers.
fn parse_content_length(value: &[u8], known: Option<usize>) -> Result<usize, RouterError> {
    let mut length = known;
    for item in value.split(|&byte| byte == b',') {
        let digits = item.trim_ascii();
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(RouterError::http(HttpFault::BadContentLength));
        }
        let parsed = digits.iter().try_fold(0_usize, |total, digit| {
            total
                .checked_mul(10)?
                .checked_add(usize::from(digit - b'0'))
        });
        // A length that does not fit is larger than any body accepted.
        let parsed = parsed.ok_or(RouterError::http(HttpFault::TooLarge))?;
        match length {
            Some(earlier) if earlier != parsed => {
                return Err(RouterError::http(HttpFault::ConflictingLength));
            }
            _ => length = Some(parsed),
        }
    }
    length.ok_or(RouterError::http(HttpFault::BadContentLength))
}

/// Reads a response head from `endpoint`, stores its cookies in `jar` and
/// judges its `Location` against the endpoint ([`Location::of`]); a second
/// `Location` is `RepeatedLocation`. The end of the stream before any byte
/// is `Closed`; inside the head it is `TruncatedHead`.
fn read_head(
    conn: &mut Connection,
    endpoint: &Endpoint,
    jar: &mut CookieJar,
) -> Result<Head, RouterError> {
    let mut lines = Lines::new(MAX_HEAD_BYTES, HttpFault::HeadTooLarge);
    let status = match lines.read(conn)? {
        LineEnd::Text => parse_status_line(lines.line())?,
        LineEnd::End { partial: false } => {
            return Err(RouterError::unreachable(UnreachableCause::Closed));
        }
        LineEnd::End { partial: true } => {
            return Err(RouterError::http(HttpFault::TruncatedHead));
        }
    };
    let mut count = 0_usize;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut html = false;
    let mut encoded = false;
    let mut location = None;
    loop {
        if let LineEnd::End { .. } = lines.read(conn)? {
            return Err(RouterError::http(HttpFault::TruncatedHead));
        }
        let line = lines.line();
        if line.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_HEADER_LINES {
            return Err(RouterError::http(HttpFault::TooManyHeaders));
        }
        if matches!(line[0], b' ' | b'\t') {
            return Err(RouterError::http(HttpFault::ObsFold));
        }
        let (name, value) = parse_header(line)?;
        if name.eq_ignore_ascii_case(b"content-length") {
            content_length = Some(parse_content_length(value, content_length)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(RouterError::http(HttpFault::TransferEncoding));
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case(b"content-encoding") {
            encoded = true;
        } else if name.eq_ignore_ascii_case(b"content-type") {
            html |= value
                .get(..9)
                .is_some_and(|start| start.eq_ignore_ascii_case(b"text/html"));
        } else if name.eq_ignore_ascii_case(b"set-cookie") {
            let cookie = parse_set_cookie(value).map_err(RouterError::http)?;
            jar.store(cookie).map_err(RouterError::http)?;
        } else if name.eq_ignore_ascii_case(b"location") {
            if location.is_some() {
                return Err(RouterError::http(HttpFault::RepeatedLocation));
            }
            location = Some(Location::of(value, endpoint));
        }
    }
    let framing = match (chunked, content_length) {
        (true, Some(_)) => return Err(RouterError::http(HttpFault::ConflictingLength)),
        (true, None) => Framing::Chunked,
        (false, Some(length)) => Framing::Length(length),
        (false, None) => Framing::Close,
    };
    Ok(Head {
        status,
        framing,
        html,
        encoded,
        location,
    })
}

/// A body buffer of [`MAX_BODY_BYTES`], allocated once and never grown.
struct BodyBuffer {
    bytes: Zeroizing<Vec<u8>>,
    filled: usize,
}

impl BodyBuffer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0_u8; MAX_BODY_BYTES]),
            filled: 0,
        }
    }

    /// Reads exactly `count` more bytes; `TooLarge` past the limit,
    /// `TruncatedBody` at the end of the stream.
    fn read_exact(&mut self, conn: &mut Connection, count: usize) -> Result<(), RouterError> {
        let end = self
            .filled
            .checked_add(count)
            .filter(|end| *end <= MAX_BODY_BYTES)
            .ok_or(RouterError::http(HttpFault::TooLarge))?;
        while self.filled < end {
            let read = conn.read(&mut self.bytes[self.filled..end])?;
            if read == 0 {
                return Err(RouterError::http(HttpFault::TruncatedBody));
            }
            self.filled += read;
        }
        Ok(())
    }

    /// Reads to the end of the stream; `TooLarge` past the limit.
    fn read_to_end(&mut self, conn: &mut Connection) -> Result<(), RouterError> {
        loop {
            if self.filled == MAX_BODY_BYTES {
                return match conn.byte()? {
                    Some(_) => Err(RouterError::http(HttpFault::TooLarge)),
                    None => Ok(()),
                };
            }
            let read = conn.read(&mut self.bytes[self.filled..])?;
            if read == 0 {
                return Ok(());
            }
            self.filled += read;
        }
    }

    fn into_body(mut self) -> Body {
        self.bytes.truncate(self.filled);
        Body(self.bytes)
    }
}

/// A chunk size line: one to eight hexadecimal digits, then nothing or
/// (after optional whitespace) `;` and extensions, which are ignored.
fn parse_chunk_size(line: &[u8]) -> Result<usize, RouterError> {
    let refused = RouterError::http(HttpFault::ChunkSize);
    let digits = line
        .iter()
        .take_while(|byte| byte.is_ascii_hexdigit())
        .count();
    if !(1..=MAX_CHUNK_SIZE_DIGITS).contains(&digits) {
        return Err(refused);
    }
    let rest = line[digits..].trim_ascii_start();
    if !(rest.is_empty() || rest[0] == b';') {
        return Err(refused);
    }
    std::str::from_utf8(&line[..digits])
        .ok()
        .and_then(|hex| usize::from_str_radix(hex, 16).ok())
        .ok_or(refused)
}

/// Reads a chunked body, its trailers read and dropped under the head's
/// limits.
fn read_chunked(conn: &mut Connection, buffer: &mut BodyBuffer) -> Result<(), RouterError> {
    let end_of_stream = || RouterError::http(HttpFault::TruncatedBody);
    loop {
        let mut size_line = Lines::new(MAX_CHUNK_LINE_BYTES, HttpFault::ChunkSize);
        let size = match size_line.read(conn)? {
            LineEnd::Text => parse_chunk_size(size_line.line())?,
            LineEnd::End { .. } => return Err(end_of_stream()),
        };
        if size == 0 {
            break;
        }
        buffer.read_exact(conn, size)?;
        match conn.byte()?.ok_or_else(end_of_stream)? {
            b'\n' => {}
            b'\r' => {
                if conn.byte()?.ok_or_else(end_of_stream)? != b'\n' {
                    return Err(RouterError::http(HttpFault::ChunkTerminator));
                }
            }
            _ => return Err(RouterError::http(HttpFault::ChunkTerminator)),
        }
    }
    let mut trailers = Lines::new(MAX_HEAD_BYTES, HttpFault::HeadTooLarge);
    for _ in 0..=MAX_HEADER_LINES {
        match trailers.read(conn)? {
            LineEnd::Text if trailers.line().is_empty() => return Ok(()),
            LineEnd::Text => {}
            LineEnd::End { .. } => return Err(end_of_stream()),
        }
    }
    Err(RouterError::http(HttpFault::TooManyHeaders))
}

/// Reads the body the head frames. An encoded body (the client never asks
/// for one) is refused unread, and a length past the limit before a byte
/// of it is read ([`BodyBuffer::read_exact`]).
fn read_body(conn: &mut Connection, head: &Head) -> Result<Body, RouterError> {
    if head.encoded {
        return Err(RouterError::http(HttpFault::ContentEncoding));
    }
    let mut buffer = BodyBuffer::new();
    match head.framing {
        Framing::Length(length) => buffer.read_exact(conn, length)?,
        Framing::Chunked => read_chunked(conn, &mut buffer)?,
        Framing::Close => buffer.read_to_end(conn)?,
    }
    Ok(buffer.into_body())
}

/// Opens one connection to `endpoint` and closes it without sending a
/// byte (so the kernel resolves the gateway's link-layer address).
pub(crate) fn connect_only(endpoint: &Endpoint, timeouts: &Timeouts) -> Result<(), RouterError> {
    Connection::open(endpoint, timeouts).map(drop)
}

/// The client of one command: an endpoint, its limits and its cookies.
#[derive(Debug)]
pub(crate) struct Client {
    endpoint: Endpoint,
    timeouts: Timeouts,
    jar: CookieJar,
}

impl Client {
    pub(crate) fn new(endpoint: Endpoint, timeouts: Timeouts) -> Self {
        Self {
            endpoint,
            timeouts,
            jar: CookieJar::default(),
        }
    }

    /// Sends `request` to `endpoint` and reads the answer's head, storing
    /// its cookies.
    fn exchange(
        &mut self,
        endpoint: Endpoint,
        request: Request<'_>,
    ) -> Result<(Connection, Head), RouterError> {
        let bytes = request_bytes(request, &endpoint, &self.jar);
        let mut conn = Connection::open(&endpoint, &self.timeouts)?;
        conn.send(bytes.as_bytes())?;
        let head = read_head(&mut conn, &endpoint, &mut self.jar)?;
        Ok((conn, head))
    }

    /// `GET /api/model.json?internalapi=1`: the body of a 200 answer that
    /// is not a web page, after the M7's session set-up when it asks for
    /// one (design §15.6 rule 9). A `302` to the set-up target starts it,
    /// once: one `GET` of the set-up target ([`Client::set_up_session`]),
    /// then the endpoint again, so one call makes at most three requests.
    /// Any other redirect, of either `GET` of the endpoint, is
    /// `Malformed{Redirect}`, naming the request and the status; the
    /// redirect's body is never read. 401 and 403 are `AuthFailed`, 404 is
    /// `Unsupported{EndpointMissing}`, any other status `Malformed`.
    pub(crate) fn model_json(&mut self) -> Result<Body, RouterError> {
        let (mut conn, mut head) = self.exchange(self.endpoint, Request::ModelJson)?;
        if head.is_redirect() {
            if !head.found_at(Location::SessionSetup) {
                return Err(RouterError::redirect(RedirectStep::First, head.status));
            }
            drop(conn);
            self.set_up_session()?;
            (conn, head) = self.exchange(self.endpoint, Request::ModelJson)?;
            if head.is_redirect() {
                return Err(RouterError::redirect(RedirectStep::Retried, head.status));
            }
        }
        match head.status {
            200 => {}
            401 | 403 => {
                return Err(RouterError::AuthFailed {
                    cause: AuthCause::Refused {
                        status: head.status,
                    },
                });
            }
            404 => {
                return Err(RouterError::Unsupported {
                    cause: UnsupportedCause::EndpointMissing,
                });
            }
            code => {
                return Err(RouterError::Malformed {
                    cause: MalformedCause::Status { code },
                });
            }
        }
        if head.html {
            return Err(RouterError::Malformed {
                cause: MalformedCause::Html,
            });
        }
        read_body(&mut conn, &head)
    }

    /// The M7's session set-up: one `GET` of its target, whose head is
    /// read (its cookies are kept, each replacing one of the same name)
    /// and whose body never is. Only a `302` back to the JSON endpoint
    /// ends it; any other answer is `Malformed{Redirect}` at the set-up.
    fn set_up_session(&mut self) -> Result<(), RouterError> {
        let (_conn, head) = self.exchange(self.endpoint, Request::SessionSetup)?;
        if head.found_at(Location::ModelJson) {
            Ok(())
        } else {
            Err(RouterError::redirect(
                RedirectStep::SessionSetup,
                head.status,
            ))
        }
    }

    /// Posts the login form to the verified M7 and returns the answer's
    /// status and where its `Location` points ([`LoginAnswer`]). Only the
    /// head is read (its cookies are kept); the body is never read and a
    /// redirect is never followed.
    pub(crate) fn login(
        &mut self,
        verified: &VerifiedIdentity,
        body: &LoginBody,
    ) -> Result<LoginAnswer, RouterError> {
        let (_conn, head) = self.exchange(verified.endpoint(), Request::Login { body })?;
        Ok(LoginAnswer {
            status: head.status,
            location: head.location,
        })
    }

    /// The cookie names held, in order.
    #[cfg(test)]
    pub(crate) fn cookie_names(&self) -> Vec<&str> {
        self.jar.names()
    }
}
