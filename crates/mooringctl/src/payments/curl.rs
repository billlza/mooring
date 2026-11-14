// SPDX-License-Identifier: GPL-3.0-or-later

//! The pull's one request (design §9.6), made by `/usr/bin/curl`, which
//! does the name lookup, TLS with the system's trust store, and HTTP: to
//! the portal with its pull token, or, for the check against Stripe, to
//! Stripe's API with the read key and the API release it is read at.
//!
//! - **Nothing secret in an argument or the environment.** curl is started
//!   as `curl -q --config -`: `-q` first, so no `.curlrc` is read, and every
//!   option, the address and the `Authorization` header on its standard
//!   input, where `ps` cannot show them. Its environment is empty, so no
//!   proxy variable or CA path reaches it.
//! - **Only what the pull needs.** HTTPS only (`proto`), TLS 1.2 or later,
//!   no redirect followed, no proxy, at most [`MAX_FEED_BYTES`] of body.
//!   curl's own limit ends [`GRACE`] (at most half the slot) before the
//!   slot the daemon gives the request, and a curl still running at the
//!   slot's end is killed, so the request never runs into the probe's
//!   reserve. The connection has at most 10 s of it.
//! - **The secret is written once.** The configuration is built in a
//!   zeroizing buffer large enough never to grow, so no copy of the token
//!   or key is left behind by a reallocation.
//! - **What comes back.** The status and the `Retry-After` header, which
//!   curl writes on its standard error after a marker, and the body; or
//!   curl's own failure with its exit code and message. Every text kept is
//!   escaped and bounded, and the secret, were curl ever to print it, is
//!   cut out first.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use mooring_daemon_core::payments::{MAX_FEED_BYTES, STRIPE_VERSION, printable};
use mooring_model::{PortalPullToken, StripeReadKey};
use zeroize::Zeroizing;

/// The system's curl.
pub(crate) const CURL: &str = "/usr/bin/curl";

/// How long curl may take to connect, at most.
pub(crate) const CONNECT_LIMIT: Duration = Duration::from_secs(10);

/// How long before the end of its slot curl's own limit falls, at most:
/// the time it has to end by itself before it is killed.
pub(crate) const GRACE: Duration = Duration::from_secs(2);

/// The configuration's buffer: far more than the longest configuration
/// (an address of at most about 400 bytes, a token or key of at most 208,
/// and the options), so that it never grows.
const CONFIG_CAPACITY: usize = 4096;

/// The most bytes of curl's standard error kept.
const MAX_STDERR_BYTES: usize = 4096;

/// The marker before the status line curl writes on its standard error.
const STATUS_MARK: &str = "mooring-pull-status ";

/// How often a running curl is looked at.
const WAIT_STEP: Duration = Duration::from_millis(20);

/// One request of the pull: the address, the secret it carries, and how
/// long the whole request may take.
#[derive(Debug)]
pub(crate) struct PullRequest<'a> {
    /// The portal's `https://<host>/api/mooring/entitlements?after=<cursor>`,
    /// or a list on Stripe's API.
    pub(crate) url: String,
    /// Whom it asks, with what.
    pub(crate) credential: Credential<'a>,
    /// The whole request's limit.
    pub(crate) within: Duration,
}

/// Whom a request asks, and the bearer secret it carries.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Credential<'a> {
    /// The portal, with the pull token.
    Portal(&'a PortalPullToken),
    /// Stripe's API, with the read key; the request names the API release
    /// the check reads ([`STRIPE_VERSION`]).
    Stripe(&'a StripeReadKey),
}

impl Credential<'_> {
    /// The bearer secret.
    pub(crate) fn secret(&self) -> &str {
        match self {
            Self::Portal(token) => token.expose_str(),
            Self::Stripe(key) => key.expose_str(),
        }
    }

    /// Whom it asks, as a failure names them.
    pub(crate) const fn peer(&self) -> &'static str {
        match self {
            Self::Portal(_) => "the portal",
            Self::Stripe(_) => "Stripe",
        }
    }
}

/// What the portal answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortalAnswer {
    /// The HTTP status.
    pub(crate) status: u16,
    /// The `Retry-After` header as sent, if there was one: printable ASCII
    /// only, bounded.
    pub(crate) retry_after: Option<String>,
    /// The body, at most [`MAX_FEED_BYTES`].
    pub(crate) body: Vec<u8>,
}

/// Why no answer came.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FetchFailure {
    /// curl could not be started.
    #[error("curl could not be started")]
    Spawn(#[source] io::Error),
    /// Its pipes or its end could not be read.
    #[error("curl's output could not be read")]
    Io(#[source] io::Error),
    /// curl failed: its exit code and what it said, escaped.
    #[error("{}", curl_failure(peer, *code, message))]
    Curl {
        /// Whom the request asked ([`Credential::peer`]).
        peer: &'static str,
        /// Its exit code; `None` when a signal ended it.
        code: Option<i32>,
        /// Its message.
        message: String,
    },
    /// It ran past its limit and was killed.
    #[error("the request took longer than its slot")]
    TimedOut,
    /// The body was larger than the portal or a page of Stripe's ever
    /// is.
    #[error("the answer was larger than {MAX_FEED_BYTES} bytes")]
    TooLarge,
    /// curl ended well without saying what the status was.
    #[error("curl gave no status: {message}")]
    NoStatus {
        /// What it said, escaped.
        message: String,
    },
}

/// curl's failure of a request to `peer`, by its exit code where the code
/// says enough.
fn curl_failure(peer: &str, code: Option<i32>, message: &str) -> String {
    let what = match code {
        Some(6) => format!("{peer}'s name did not resolve"),
        Some(7) => format!("{peer} did not accept the connection"),
        Some(28) => "the request timed out".to_owned(),
        Some(35) => format!("the TLS handshake with {peer} failed"),
        Some(60) => format!("{peer}'s certificate was not trusted"),
        Some(code) => format!("curl exited with {code}"),
        None => "curl was ended by a signal".to_owned(),
    };
    if message.is_empty() {
        what
    } else {
        format!("{what}: {message}")
    }
}

/// How a pull reaches the portal and Stripe (`/usr/bin/curl` in the
/// binary; a script in tests).
pub(crate) trait PortalLink {
    /// Makes `request`.
    fn fetch(&self, request: &PullRequest<'_>) -> Result<PortalAnswer, FetchFailure>;
}

/// curl as the pull runs it.
#[derive(Debug, Clone)]
pub(crate) struct Curl {
    program: PathBuf,
    protocols: &'static str,
}

impl Curl {
    /// The system's curl, HTTPS only.
    pub(crate) fn system() -> Self {
        Self {
            program: PathBuf::from(CURL),
            protocols: "=https",
        }
    }

    /// `program` limited to plain HTTP, for a test's stub on the loopback
    /// interface, which has no certificate.
    #[cfg(test)]
    pub(crate) fn plain_http(program: PathBuf) -> Self {
        Self {
            program,
            protocols: "=http",
        }
    }

    /// The arguments: none that a request changes.
    pub(crate) fn arguments() -> [&'static str; 3] {
        ["-q", "--config", "-"]
    }

    /// The configuration curl reads on its standard input: curl's own
    /// limit ends [`grace`] before the request's slot.
    pub(crate) fn config(&self, request: &PullRequest<'_>) -> Zeroizing<String> {
        let max = request.within.saturating_sub(grace(request.within));
        let max = max.max(Duration::from_millis(1));
        let connect = max.min(CONNECT_LIMIT);
        let mut config = Zeroizing::new(String::with_capacity(CONFIG_CAPACITY));
        // Writing to a `String` cannot fail.
        let _ = write!(
            config,
            "url = \"{url}\"\n\
             header = \"Authorization: Bearer {secret}\"\n\
             proto = \"{protocols}\"\n\
             proto-redir = \"{protocols}\"\n\
             tlsv1.2\n\
             noproxy = \"*\"\n\
             globoff\n\
             silent\n\
             show-error\n\
             max-time = \"{max}\"\n\
             connect-timeout = \"{connect}\"\n\
             max-filesize = \"{MAX_FEED_BYTES}\"\n\
             write-out = \"%{{stderr}}{STATUS_MARK}%{{response_code}} %header{{retry-after}}\\n\"\n",
            url = request.url,
            secret = request.credential.secret(),
            protocols = self.protocols,
            max = seconds(max),
            connect = seconds(connect),
        );
        if let Credential::Stripe(_) = request.credential {
            let _ = writeln!(config, "header = \"Stripe-Version: {STRIPE_VERSION}\"");
        }
        config
    }
}

/// How long before the end of a slot of `within` curl's own limit falls:
/// [`GRACE`], or half the slot when that is less.
pub(crate) fn grace(within: Duration) -> Duration {
    GRACE.min(within / 2)
}

/// `duration` in seconds with three decimals, as curl reads it.
fn seconds(duration: Duration) -> String {
    format!("{}.{:03}", duration.as_secs(), duration.subsec_millis())
}

impl PortalLink for Curl {
    fn fetch(&self, request: &PullRequest<'_>) -> Result<PortalAnswer, FetchFailure> {
        let config = self.config(request);
        let started = Instant::now();
        let limit = request.within;
        let mut command = Command::new(&self.program);
        command
            .args(Self::arguments())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = Owned(command.spawn().map_err(FetchFailure::Spawn)?);
        let missing = || FetchFailure::Io(io::Error::other("curl's pipes are missing"));
        let mut stdin = child.0.stdin.take().ok_or_else(missing)?;
        let mut stdout = child.0.stdout.take().ok_or_else(missing)?;
        let mut stderr = child.0.stderr.take().ok_or_else(missing)?;
        thread::scope(|scope| {
            let config = &config;
            let writer = scope.spawn(move || {
                let written = stdin
                    .write_all(config.as_bytes())
                    .and_then(|()| stdin.flush());
                drop(stdin);
                written
            });
            let body = scope.spawn(move || read_bounded(&mut stdout, MAX_FEED_BYTES));
            let errors = scope.spawn(move || read_bounded(&mut stderr, MAX_STDERR_BYTES));
            let ended = wait_until(&mut child.0, started, limit);
            let ended = match ended {
                Ok(ended) => ended,
                Err(error) => {
                    let _ = stop(&mut child.0);
                    return Err(FetchFailure::Io(error));
                }
            };
            let written = writer.join().map_err(|_| panicked("writer"))?;
            let body = body.join().map_err(|_| panicked("body reader"))?;
            let errors = errors.join().map_err(|_| panicked("error reader"))?;
            let Some(status) = ended else {
                return Err(FetchFailure::TimedOut);
            };
            let (body, overflowed) = body.map_err(FetchFailure::Io)?;
            let (errors, _) = errors.map_err(FetchFailure::Io)?;
            let errors = scrubbed(&errors, request.credential.secret());
            finish(
                request.credential.peer(),
                status,
                written,
                body,
                overflowed,
                &errors,
            )
        })
    }
}

/// A child that is killed and reaped when it is let go early.
struct Owned(Child);

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = stop(&mut self.0);
    }
}

fn panicked(what: &str) -> FetchFailure {
    FetchFailure::Io(io::Error::other(format!("curl's {what} panicked")))
}

/// What curl's end, output and error text come to, for a request to
/// `peer`.
fn finish(
    peer: &'static str,
    status: ExitStatus,
    written: io::Result<()>,
    body: Vec<u8>,
    overflowed: bool,
    errors: &str,
) -> Result<PortalAnswer, FetchFailure> {
    let (marked, message) = split_status(errors);
    if overflowed || status.code() == Some(63) {
        return Err(FetchFailure::TooLarge);
    }
    if !status.success() {
        return Err(FetchFailure::Curl {
            peer,
            code: status.code(),
            message,
        });
    }
    written.map_err(FetchFailure::Io)?;
    let Some((code, retry_after)) = marked else {
        return Err(FetchFailure::NoStatus { message });
    };
    Ok(PortalAnswer {
        status: code,
        retry_after,
        body,
    })
}

/// The status line curl wrote, if any (its code and the `Retry-After`
/// value), and the rest of its error text, escaped. A status of `000`, no
/// answer, is none.
pub(crate) fn split_status(errors: &str) -> (Option<(u16, Option<String>)>, String) {
    let mut status = None;
    let mut rest = Vec::new();
    for line in errors.lines() {
        match line.strip_prefix(STATUS_MARK) {
            Some(marked) => {
                let (code, retry_after) = marked.split_once(' ').unwrap_or((marked, ""));
                let code = code
                    .parse::<u16>()
                    .ok()
                    .filter(|code| (100..=599).contains(code));
                let retry_after = retry_after.trim();
                status = code.map(|code| {
                    (
                        code,
                        (!retry_after.is_empty()).then(|| printable(retry_after)),
                    )
                });
            }
            None if !line.trim().is_empty() => rest.push(line),
            None => {}
        }
    }
    (status, printable(&rest.join(" / ")))
}

/// `bytes` as text with `secret` cut out, were curl ever to print it.
fn scrubbed(bytes: &[u8], secret: &str) -> String {
    String::from_utf8_lossy(bytes).replace(secret, "<redacted>")
}

/// Reads `reader` to its end, keeping at most `bound` bytes; says whether
/// more came.
fn read_bounded(reader: &mut dyn Read, bound: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut overflowed = false;
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok((kept, overflowed));
        }
        let room = bound.saturating_sub(kept.len());
        if read > room {
            overflowed = true;
        }
        kept.extend_from_slice(&chunk[..read.min(room)]);
    }
}

/// Waits for `child` until `limit` after `started`; a child still running
/// then is killed, and `None` says so.
fn wait_until(
    child: &mut Child,
    started: Instant,
    limit: Duration,
) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= limit {
            stop(child)?;
            return Ok(None);
        }
        thread::sleep(WAIT_STEP);
    }
}

/// Kills and reaps `child`, which may have ended meanwhile.
fn stop(child: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    child.wait()
}
