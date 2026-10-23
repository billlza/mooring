// SPDX-License-Identifier: GPL-3.0-or-later

//! The control socket's connections (design §10.1): each client sends one
//! request line and gets its replies; a client beyond [`MAX_CLIENTS`] is
//! told the daemon is busy. A `retry` is handed to the daemon's loop for
//! its next tick, and refused while there is no deployment. The request line and each reply line have a
//! deadline, however slowly their bytes go, so a stalled or dripping client
//! holds a thread for a bounded while only.

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use mooring_daemon_core::control::{
    DaemonReply, DaemonRequest, MAX_REPLY_LINE_BYTES, MAX_REQUEST_LINE_BYTES, Refusal,
    decode_request, encode_line,
};

use super::Control;
use super::hub::{Hub, HubPoisoned};

/// The most clients served at once: the app's one subscription, a few CLI
/// calls, and room for a stale connection that has not been noticed yet.
pub(crate) const MAX_CLIENTS: usize = 8;

/// The time limits of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// How long a client has to send its whole request line.
    pub(crate) request: Duration,
    /// How long one whole reply line may take to write.
    pub(crate) write: Duration,
    /// How often a subscription with nothing new checks that its client is
    /// still there.
    pub(crate) idle_check: Duration,
}

/// The daemon's limits.
pub(crate) const LIMITS: Limits = Limits {
    request: Duration::from_secs(5),
    write: Duration::from_secs(10),
    idle_check: Duration::from_secs(5),
};

/// Why the acceptor stopped: the listener failed (anything but a client
/// that reset before it was accepted).
#[derive(Debug)]
pub(crate) struct AcceptFailed(pub(crate) io::Error);

/// Accepts connections on `listener` and serves each on its own thread,
/// at most `max_clients` at once. Returns only when accepting fails.
pub(crate) fn accept(
    listener: &UnixListener,
    control: &Arc<Control>,
    limits: Limits,
    max_clients: usize,
) -> AcceptFailed {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == ErrorKind::ConnectionAborted => continue,
            Err(error) => return AcceptFailed(error),
        };
        if active.load(Ordering::SeqCst) >= max_clients {
            let mut stream = stream;
            if stream.set_write_timeout(Some(limits.write)).is_ok() {
                // The client may already be gone; the connection ends either way.
                refused(&mut stream, Refusal::Busy);
            }
            continue;
        }
        let slot = Slot::take(&active);
        let control = Arc::clone(control);
        let spawned = thread::Builder::new()
            .name("mooring-control".to_owned())
            .spawn(move || {
                let _slot = slot;
                serve(stream, &control, limits);
            });
        if let Err(error) = spawned {
            return AcceptFailed(error);
        }
    }
}

/// One of the connection slots, given back when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(active: &Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(active))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How a connection ended. Every end closes the connection; none is a
/// daemon failure except a poisoned hub, which the poller meets too and
/// stops the daemon for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// The request was answered.
    Answered,
    /// The request was refused.
    Refused(Refusal),
    /// The client closed its side, or sent more than its one request.
    ClientLeft,
    /// A read or write failed or timed out.
    Io(ErrorKind),
    /// The hub is poisoned.
    Poisoned,
    /// The daemon's loop has ended, so a retry cannot be handed to it.
    Stopping,
}

impl From<HubPoisoned> for End {
    fn from(_: HubPoisoned) -> Self {
        Self::Poisoned
    }
}

/// Serves one connection to its end.
pub(crate) fn serve(mut stream: UnixStream, control: &Control, limits: Limits) -> End {
    let request = match read_request(&mut stream, limits) {
        Ok(request) => request,
        Err(end) => return end,
    };
    let result = match request {
        DaemonRequest::Status => answer_status(&mut stream, &control.hub, limits),
        DaemonRequest::Subscribe => subscribe(&mut stream, &control.hub, limits),
        DaemonRequest::Retry => queue_retry(&mut stream, control, limits),
    };
    result.unwrap_or_else(|end| end)
}

/// `Retry`: handed to the loop, which runs it at its next tick, and
/// answered `RetryQueued`; refused as `NotDeployed` without a deployment.
fn queue_retry(stream: &mut UnixStream, control: &Control, limits: Limits) -> Result<End, End> {
    if !control.deployed.load(Ordering::SeqCst) {
        return Err(refused(stream, Refusal::NotDeployed));
    }
    control.retry.send(()).map_err(|_| End::Stopping)?;
    let line = encode_line(&DaemonReply::RetryQueued, MAX_REPLY_LINE_BYTES)
        .map_err(|_| End::Io(ErrorKind::InvalidData))?;
    write_line(stream, &line, limits)?;
    Ok(End::Answered)
}

/// Reads the one request line, a byte at a time so nothing after its
/// newline is consumed, within the line bound and before the request's
/// deadline: each read waits only for what is left of it. A line that is
/// malformed, too long or late is refused as `BadRequest`.
fn read_request(stream: &mut UnixStream, limits: Limits) -> Result<DaemonRequest, End> {
    stream
        .set_write_timeout(Some(limits.write))
        .map_err(setsockopt_end)?;
    let deadline = Instant::now() + limits.request;
    let mut line = Vec::with_capacity(32);
    let mut byte = [0_u8; 1];
    loop {
        let Some(left) = time_left(deadline) else {
            return Err(refused(stream, Refusal::BadRequest));
        };
        stream
            .set_read_timeout(Some(left))
            .map_err(setsockopt_end)?;
        match stream.read(&mut byte) {
            Ok(0) => return Err(End::ClientLeft),
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
                if line.len() >= MAX_REQUEST_LINE_BYTES {
                    return Err(refused(stream, Refusal::BadRequest));
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(refused(stream, Refusal::BadRequest));
            }
            Err(error) => return Err(End::Io(error.kind())),
        }
    }
    decode_request(&line).map_err(|_| refused(stream, Refusal::BadRequest))
}

/// How long is left before `deadline`; `None` once it has passed.
fn time_left(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// The end for a failed setsockopt(2). On macOS it fails with "[EINVAL] The
/// socket has been shut down" when the client has closed its side.
fn setsockopt_end(error: io::Error) -> End {
    match error.kind() {
        ErrorKind::InvalidInput => End::ClientLeft,
        kind => End::Io(kind),
    }
}

/// Writes the refusal and reports it as the connection's end; the caller
/// then closes the connection.
fn refused(stream: &mut UnixStream, reason: Refusal) -> End {
    match encode_line(&DaemonReply::Refused { reason }, MAX_REPLY_LINE_BYTES) {
        Ok(line) => match stream.write_all(&line) {
            Ok(()) => End::Refused(reason),
            Err(error) => End::Io(error.kind()),
        },
        // A fixed refusal always encodes; were it not to, the client is
        // still not served.
        Err(_) => End::Refused(reason),
    }
}

/// `Status`: the latest line, or `NoStatusYet` before the first poll.
fn answer_status(stream: &mut UnixStream, hub: &Hub, limits: Limits) -> Result<End, End> {
    match hub.latest()? {
        Some(published) => {
            write_line(stream, &published.line, limits)?;
            Ok(End::Answered)
        }
        None => Err(refused(stream, Refusal::NoStatusYet)),
    }
}

/// `Subscribe`: each line as it is published, the latest first (waiting
/// for the first poll if there is none yet), until the client leaves or a
/// write fails. With nothing new, it checks every `idle_check` that the
/// client is still there.
fn subscribe(stream: &mut UnixStream, hub: &Hub, limits: Limits) -> Result<End, End> {
    let mut seen = 0;
    loop {
        match hub.newer_than(seen, limits.idle_check)? {
            Some(published) => {
                write_line(stream, &published.line, limits)?;
                seen = published.seq;
            }
            None => client_still_there(stream)?,
        }
    }
}

/// How long a write waits before it tries again while the client's
/// socket buffer is full.
const WRITE_RETRY: Duration = Duration::from_millis(2);

/// Writes one reply line before its deadline, with the socket non-blocking
/// meanwhile. A blocking send(2) waits for buffer space again each time
/// the reader drains a little, and SO_SNDTIMEO bounds each of those waits,
/// not the call, so a reader draining a long line in small reads could
/// stretch it without end. Past the deadline the end is `Io(TimedOut)`.
fn write_line(stream: &mut UnixStream, line: &[u8], limits: Limits) -> Result<(), End> {
    let deadline = Instant::now() + limits.write;
    stream
        .set_nonblocking(true)
        .map_err(|error| End::Io(error.kind()))?;
    let written = write_before(stream, line, deadline);
    stream
        .set_nonblocking(false)
        .map_err(|error| End::Io(error.kind()))?;
    written
}

fn write_before(stream: &mut UnixStream, line: &[u8], deadline: Instant) -> Result<(), End> {
    let mut rest = line;
    while !rest.is_empty() {
        if time_left(deadline).is_none() {
            return Err(End::Io(ErrorKind::TimedOut));
        }
        match stream.write(rest) {
            Ok(0) => return Err(End::Io(ErrorKind::WriteZero)),
            Ok(written) => rest = &rest[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(WRITE_RETRY),
            Err(error) => {
                return Err(match error.kind() {
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => End::ClientLeft,
                    kind => End::Io(kind),
                });
            }
        }
    }
    Ok(())
}

/// Whether the client is still connected and silent, without waiting: the
/// end of its side, or any byte after its request, ends the connection.
fn client_still_there(stream: &mut UnixStream) -> Result<(), End> {
    stream
        .set_nonblocking(true)
        .map_err(|error| End::Io(error.kind()))?;
    let mut byte = [0_u8; 1];
    let read = stream.read(&mut byte);
    stream
        .set_nonblocking(false)
        .map_err(|error| End::Io(error.kind()))?;
    match read {
        Ok(_) => Err(End::ClientLeft),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(error) if error.kind() == ErrorKind::ConnectionReset => Err(End::ClientLeft),
        Err(error) => Err(End::Io(error.kind())),
    }
}
