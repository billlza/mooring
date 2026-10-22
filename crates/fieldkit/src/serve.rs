// SPDX-License-Identifier: GPL-3.0-or-later

//! `fieldkit serve`, the VPS side of the measurements (design §22 M2b): the
//! TCP reflector, the two UDP echo ports, the TCP port-ceiling target and
//! the TCP sink, run for a fixed time and then stopped.
//!
//! The servers answer anyone who reaches their ports, so they are bounded
//! rather than authenticated *(Level 0: a test server that runs only while
//! a measurement is made, on ports opened only for it)*:
//! - an echo answer is never larger than its request, one answer per
//!   request, and at most [`MAX_PENDING`] delayed answers wait at once;
//! - the port-ceiling target holds at most `ceiling_max` connections and
//!   closes any beyond;
//! - at most [`MAX_SINKS`] sink sessions run at once, each at most 120
//!   seconds plus [`SINK_GRACE`], after which it closes;
//! - nothing received is stored, and the log holds counts, never
//!   addresses.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::error::FieldkitError;
use crate::limits::ensure_open_files;
use crate::net::{read_line, timed_out};
use crate::output::Output;
use crate::wire::{
    CEILING_ACK, EchoAnswer, EchoKind, EchoRequest, MAX_LINE, SinkReport, parse_sink_line,
    reflector_line,
};

/// The most delayed echo answers waiting at once.
pub(crate) const MAX_PENDING: usize = 1024;

/// The most sink sessions running at once.
pub(crate) const MAX_SINKS: usize = 64;

/// How long a sink session waits for its opening line. Generous, because
/// on a loaded line (another flow's buffers) the line can arrive seconds
/// after the connection (measured on 2026-10-22: over 5 s through the M7).
pub(crate) const SINK_OPENING: Duration = Duration::from_secs(30);

/// How long a sink session drains what the probe still sends after its
/// report.
pub(crate) const SINK_GRACE: Duration = Duration::from_secs(30);

/// How often a worker looks at the stop flag.
const POLL: Duration = Duration::from_millis(200);

/// How long an idle accept loop sleeps.
const ACCEPT_IDLE: Duration = Duration::from_millis(10);

/// How often the port-ceiling target drops connections the probe closed.
const REAP_EVERY: Duration = Duration::from_millis(500);

/// The open files the server needs beyond the connections it holds.
const SPARE_FILES: u64 = 64;

/// What to serve, and where.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServeConfig {
    /// The address every service listens on.
    pub(crate) listen: Ipv4Addr,
    /// The TCP reflector's port.
    pub(crate) reflector: u16,
    /// The UDP echo ports A and B.
    pub(crate) echo: (u16, u16),
    /// The TCP port-ceiling target's port.
    pub(crate) ceiling: u16,
    /// The most connections the target holds.
    pub(crate) ceiling_max: u16,
    /// The TCP sink's port.
    pub(crate) sink: u16,
}

/// The ports the services were bound to (the configured ones, or the
/// kernel's choice for port 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Ports {
    /// The TCP reflector.
    pub(crate) reflector: u16,
    /// UDP echo port A.
    pub(crate) echo_a: u16,
    /// UDP echo port B.
    pub(crate) echo_b: u16,
    /// The TCP port-ceiling target.
    pub(crate) ceiling: u16,
    /// The TCP sink.
    pub(crate) sink: u16,
}

#[derive(Debug, Default)]
struct Counters {
    echo_answered: AtomicU64,
    echo_send_failed: AtomicU64,
    echo_refused: AtomicU64,
    echo_delayed_dropped: AtomicU64,
    reflector_served: AtomicU64,
    ceiling_held_peak: AtomicU64,
    ceiling_refused: AtomicU64,
    sink_sessions: AtomicU64,
    sink_refused: AtomicU64,
    sink_last_failure: Mutex<Option<String>>,
}

/// The servers' counts since they started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Counts {
    /// Echo requests answered (delayed ones when sent).
    pub(crate) echo_answered: u64,
    /// Echo answers the kernel would not send.
    pub(crate) echo_send_failed: u64,
    /// Datagrams that were not echo requests.
    pub(crate) echo_refused: u64,
    /// Delayed requests dropped because [`MAX_PENDING`] were waiting.
    pub(crate) echo_delayed_dropped: u64,
    /// Reflector connections answered.
    pub(crate) reflector_served: u64,
    /// The most connections the port-ceiling target held at once.
    pub(crate) ceiling_held_peak: u64,
    /// Port-ceiling connections closed unheld: the target was full, or the
    /// connection failed before it was acknowledged.
    pub(crate) ceiling_refused: u64,
    /// Sink sessions answered with a report.
    pub(crate) sink_sessions: u64,
    /// Sink connections closed without one (full, a bad opening line, or
    /// the connection failed).
    pub(crate) sink_refused: u64,
    /// Why the last sink session that failed did.
    pub(crate) sink_last_failure: Option<String>,
}

impl Counters {
    fn snapshot(&self) -> Counts {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Counts {
            echo_answered: get(&self.echo_answered),
            echo_send_failed: get(&self.echo_send_failed),
            echo_refused: get(&self.echo_refused),
            echo_delayed_dropped: get(&self.echo_delayed_dropped),
            reflector_served: get(&self.reflector_served),
            ceiling_held_peak: get(&self.ceiling_held_peak),
            ceiling_refused: get(&self.ceiling_refused),
            sink_sessions: get(&self.sink_sessions),
            sink_refused: get(&self.sink_refused),
            sink_last_failure: self.sink_last_failure.lock().map_or_else(
                |_| Some("the failure record is poisoned".to_owned()),
                |last| last.clone(),
            ),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

type Worker = (&'static str, JoinHandle<Result<(), FieldkitError>>);

/// The running servers.
#[derive(Debug)]
pub(crate) struct Server {
    ports: Ports,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
    workers: Vec<Worker>,
}

fn tcp_listener(
    listen: Ipv4Addr,
    port: u16,
    what: &'static str,
) -> Result<TcpListener, FieldkitError> {
    let listener = TcpListener::bind(SocketAddrV4::new(listen, port))
        .map_err(|source| FieldkitError::socket(what, source))?;
    listener
        .set_nonblocking(true)
        .map_err(|source| FieldkitError::socket(what, source))?;
    Ok(listener)
}

fn local_port(port: io::Result<SocketAddr>, what: &'static str) -> Result<u16, FieldkitError> {
    port.map(|addr| addr.port())
        .map_err(|source| FieldkitError::socket(what, source))
}

impl Server {
    /// Binds every service and starts its worker. The open-files limit
    /// must cover the port-ceiling target's connections (on macOS it is
    /// raised to that if the hard limit allows).
    pub(crate) fn start(config: ServeConfig) -> Result<Self, FieldkitError> {
        ensure_open_files(u64::from(config.ceiling_max) + SPARE_FILES)?;
        let reflector = tcp_listener(config.listen, config.reflector, "bind the reflector")?;
        let ceiling = tcp_listener(
            config.listen,
            config.ceiling,
            "bind the port-ceiling target",
        )?;
        let sink = tcp_listener(config.listen, config.sink, "bind the sink")?;
        let echo_a = UdpSocket::bind(SocketAddrV4::new(config.listen, config.echo.0))
            .map_err(|source| FieldkitError::socket("bind echo port A", source))?;
        let echo_b = UdpSocket::bind(SocketAddrV4::new(config.listen, config.echo.1))
            .map_err(|source| FieldkitError::socket("bind echo port B", source))?;
        let ports = Ports {
            reflector: local_port(reflector.local_addr(), "read the reflector's port")?,
            echo_a: local_port(echo_a.local_addr(), "read echo port A")?,
            echo_b: local_port(echo_b.local_addr(), "read echo port B")?,
            ceiling: local_port(ceiling.local_addr(), "read the port-ceiling target's port")?,
            sink: local_port(sink.local_addr(), "read the sink's port")?,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());
        let mut server = Self {
            ports,
            stop,
            counters,
            workers: Vec::new(),
        };
        let echo = Echo::new(echo_a, echo_b)?;
        server.spawn("reflector", move |stop, counters| {
            reflect(&reflector, &stop, &counters)
        })?;
        server.spawn("port-ceiling target", move |stop, counters| {
            hold(&ceiling, config.ceiling_max, &stop, &counters)
        })?;
        server.spawn("sink", move |stop, counters| {
            sink_accept(&sink, &stop, &counters)
        })?;
        for side in [Side::A, Side::B] {
            let echo = echo.clone();
            server.spawn("echo", move |stop, counters| {
                echo.serve(side, &stop, &counters)
            })?;
        }
        server.spawn("delayed echo", move |stop, counters| {
            echo.release(&stop, &counters)
        })?;
        Ok(server)
    }

    fn spawn<F>(&mut self, what: &'static str, work: F) -> Result<(), FieldkitError>
    where
        F: FnOnce(Arc<AtomicBool>, Arc<Counters>) -> Result<(), FieldkitError> + Send + 'static,
    {
        let stop = Arc::clone(&self.stop);
        let counters = Arc::clone(&self.counters);
        let handle = thread::Builder::new()
            .name(format!("fieldkit {what}"))
            .spawn(move || work(stop, counters))
            .map_err(|source| FieldkitError::socket("start a worker thread", source))?;
        self.workers.push((what, handle));
        Ok(())
    }

    /// The ports the services listen on.
    pub(crate) const fn ports(&self) -> Ports {
        self.ports
    }

    /// The counts so far.
    pub(crate) fn counts(&self) -> Counts {
        self.counters.snapshot()
    }

    /// Serves for `duration`, recording the counts every `every`, then
    /// stops. A worker that failed stops the servers early with its error.
    pub(crate) fn serve_for(
        self,
        duration: Duration,
        every: Duration,
        output: &mut Output<'_>,
    ) -> Result<Counts, FieldkitError> {
        let end = Instant::now() + duration;
        let mut next = Instant::now() + every;
        loop {
            let now = Instant::now();
            if now >= end || self.workers.iter().any(|(_, handle)| handle.is_finished()) {
                break;
            }
            thread::sleep(next.min(end).saturating_duration_since(now).min(POLL));
            if Instant::now() >= next {
                output.record(&self.counts())?;
                next += every;
            }
        }
        self.stop()
    }

    /// Stops every worker and waits for it; the first worker error, if any.
    pub(crate) fn stop(self) -> Result<Counts, FieldkitError> {
        self.stop.store(true, Ordering::Relaxed);
        let mut first = None;
        for (what, handle) in self.workers {
            let outcome = handle.join().unwrap_or(Err(FieldkitError::Worker { what }));
            if let Err(error) = outcome {
                first.get_or_insert(error);
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(self.counters.snapshot()),
        }
    }
}

/// Accepts the next connection, or `None` when none is waiting. Accepted
/// streams are made blocking, whatever the listener's mode passed on.
fn accept(
    listener: &TcpListener,
    what: &'static str,
) -> Result<Option<(TcpStream, SocketAddrV4)>, FieldkitError> {
    match listener.accept() {
        Ok((stream, SocketAddr::V4(peer))) => {
            stream
                .set_nonblocking(false)
                .map_err(|source| FieldkitError::socket(what, source))?;
            Ok(Some((stream, peer)))
        }
        Ok((_, SocketAddr::V6(_))) => Err(FieldkitError::socket(
            what,
            io::Error::other("an IPv6 peer on an IPv4 listener"),
        )),
        Err(error) if timed_out(&error) => Ok(None),
        Err(error) if accept_retryable(&error) => Ok(None),
        Err(source) => Err(FieldkitError::socket(what, source)),
    }
}

/// Accept errors that concern one connection, not the listener: the peer
/// went away before it was accepted, or the process ran out of files for
/// a moment.
fn accept_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    ) || error.raw_os_error() == Some(libc_emfile())
}

const fn libc_emfile() -> i32 {
    24 // EMFILE on macOS and Linux.
}

fn reflect(
    listener: &TcpListener,
    stop: &AtomicBool,
    counters: &Counters,
) -> Result<(), FieldkitError> {
    while !stop.load(Ordering::Relaxed) {
        let Some((mut stream, peer)) = accept(listener, "accept a reflector connection")? else {
            thread::sleep(ACCEPT_IDLE);
            continue;
        };
        let written = stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .and_then(|()| stream.write_all(reflector_line(peer).as_bytes()));
        if written.is_ok() {
            bump(&counters.reflector_served);
        }
    }
    Ok(())
}

fn hold(
    listener: &TcpListener,
    max: u16,
    stop: &AtomicBool,
    counters: &Counters,
) -> Result<(), FieldkitError> {
    let mut held: Vec<TcpStream> = Vec::new();
    let mut next_reap = Instant::now() + REAP_EVERY;
    while !stop.load(Ordering::Relaxed) {
        if Instant::now() >= next_reap {
            reap(&mut held);
            next_reap = Instant::now() + REAP_EVERY;
        }
        let Some((mut stream, _)) = accept(listener, "accept a port-ceiling connection")? else {
            thread::sleep(ACCEPT_IDLE);
            continue;
        };
        if held.len() >= usize::from(max)
            || stream.write_all(&[CEILING_ACK]).is_err()
            || stream.set_nonblocking(true).is_err()
        {
            bump(&counters.ceiling_refused);
            continue;
        }
        held.push(stream);
        counters
            .ceiling_held_peak
            .fetch_max(held.len() as u64, Ordering::Relaxed);
    }
    Ok(())
}

/// Drops the held connections the probe has closed (or reset).
fn reap(held: &mut Vec<TcpStream>) {
    let mut scratch = [0_u8; 256];
    held.retain_mut(|stream| match stream.read(&mut scratch) {
        Ok(0) => false,
        Ok(_) => true,
        Err(error) => timed_out(&error),
    });
}

fn sink_accept(
    listener: &TcpListener,
    stop: &Arc<AtomicBool>,
    counters: &Arc<Counters>,
) -> Result<(), FieldkitError> {
    let active = Arc::new(AtomicUsize::new(0));
    let mut sessions: Vec<JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        sessions.retain(|session| !session.is_finished());
        let Some((stream, _)) = accept(listener, "accept a sink connection")? else {
            thread::sleep(ACCEPT_IDLE);
            continue;
        };
        if active.load(Ordering::Relaxed) >= MAX_SINKS {
            bump(&counters.sink_refused);
            if let Ok(mut last) = counters.sink_last_failure.lock() {
                *last = Some(format!("{MAX_SINKS} sessions were already running"));
            }
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let (stop, counters, active) =
            (Arc::clone(stop), Arc::clone(counters), Arc::clone(&active));
        let session = thread::Builder::new()
            .name("fieldkit sink session".to_owned())
            .spawn(move || {
                match sink_session(stream, &stop) {
                    Ok(()) => bump(&counters.sink_sessions),
                    Err(error) => {
                        bump(&counters.sink_refused);
                        if let Ok(mut last) = counters.sink_last_failure.lock() {
                            *last = Some(error.to_string());
                        }
                    }
                }
                active.fetch_sub(1, Ordering::Relaxed);
            })
            .map_err(|source| FieldkitError::socket("start a sink session", source))?;
        sessions.push(session);
    }
    for session in sessions {
        session.join().map_err(|_| FieldkitError::Worker {
            what: "sink session",
        })?;
    }
    Ok(())
}

/// One sink session: the opening line, then the bytes of each second for
/// the seconds asked, then the report at once (the probe may still be
/// sending: what its buffers still hold is not the line's rate), then the
/// rest drained and discarded until the probe closes or [`SINK_GRACE`]
/// passes.
fn sink_session(mut stream: TcpStream, stop: &AtomicBool) -> io::Result<()> {
    stream.set_read_timeout(Some(SINK_OPENING))?;
    let line = read_line(&mut stream, MAX_LINE)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no opening line"))?;
    let seconds = parse_sink_line(&line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let started = Instant::now();
    let window = Duration::from_secs(u64::from(seconds));
    let mut buckets = vec![0_u64; usize::from(seconds)];
    let mut buffer = vec![0_u8; 64 * 1024];
    stream.set_read_timeout(Some(POLL))?;
    let mut open = true;
    while open && started.elapsed() < window {
        stopping(stop)?;
        match stream.read(&mut buffer) {
            Ok(0) => open = false,
            Ok(read) => {
                if let Some(bucket) = buckets.get_mut(started.elapsed().as_secs() as usize) {
                    *bucket += read as u64;
                }
            }
            Err(error) if timed_out(&error) => {}
            Err(error) => return Err(error),
        }
    }
    let mut report = serde_json::to_vec(&SinkReport {
        bytes_per_second: buckets,
    })
    .map_err(io::Error::other)?;
    report.push(b'\n');
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&report)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    while open && started.elapsed() < window + SINK_GRACE {
        stopping(stop)?;
        match stream.read(&mut buffer) {
            Ok(0) => open = false,
            Ok(_) => {}
            Err(error) if timed_out(&error) => {}
            // The probe aborts once it has the report, discarding what its
            // buffers still held.
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => open = false,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// `Interrupted` once the server is stopping.
fn stopping(stop: &AtomicBool) -> io::Result<()> {
    if stop.load(Ordering::Relaxed) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "the server is stopping",
        ))
    } else {
        Ok(())
    }
}

/// Counts an echo answer as sent, or as one the kernel would not send.
fn count_send(sent: io::Result<usize>, counters: &Counters) {
    bump(if sent.is_ok() {
        &counters.echo_answered
    } else {
        &counters.echo_send_failed
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    A,
    B,
}

/// A delayed answer waiting to be sent.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Pending {
    due: Instant,
    sequence: u64,
    side: SideOrder,
    to: SocketAddrV4,
    answer: [u8; 32],
}

/// [`Side`] with an order, so [`Pending`] can be ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SideOrder(bool);

impl From<Side> for SideOrder {
    fn from(side: Side) -> Self {
        Self(side == Side::B)
    }
}

/// The delayed answers waiting, soonest first, and the sequence that
/// orders answers due at the same instant.
#[derive(Debug, Default)]
struct Queue {
    waiting: BinaryHeap<Reverse<Pending>>,
    sequence: u64,
}

/// The queue and the condition its sender waits on.
#[derive(Debug, Default)]
struct DelayQueue {
    queue: Mutex<Queue>,
    wake: Condvar,
}

/// The two echo sockets and the delayed answers waiting on them.
#[derive(Debug, Clone)]
struct Echo {
    a: Arc<UdpSocket>,
    b: Arc<UdpSocket>,
    pending: Arc<DelayQueue>,
}

impl Echo {
    fn new(a: UdpSocket, b: UdpSocket) -> Result<Self, FieldkitError> {
        for socket in [&a, &b] {
            socket
                .set_read_timeout(Some(POLL))
                .map_err(|source| FieldkitError::socket("set the echo read timeout", source))?;
        }
        Ok(Self {
            a: Arc::new(a),
            b: Arc::new(b),
            pending: Arc::new(DelayQueue::default()),
        })
    }

    fn socket(&self, side: Side) -> &UdpSocket {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    fn port(&self, side: Side) -> Result<u16, FieldkitError> {
        local_port(self.socket(side).local_addr(), "read an echo port")
    }

    fn serve(
        &self,
        side: Side,
        stop: &AtomicBool,
        counters: &Counters,
    ) -> Result<(), FieldkitError> {
        let other = match side {
            Side::A => Side::B,
            Side::B => Side::A,
        };
        let (here, there) = (self.port(side)?, self.port(other)?);
        let socket = self.socket(side);
        let mut buffer = [0_u8; 64];
        while !stop.load(Ordering::Relaxed) {
            let (len, from) = match socket.recv_from(&mut buffer) {
                Ok((len, SocketAddr::V4(from))) => (len, from),
                Ok((_, SocketAddr::V6(_))) => continue,
                Err(error) if timed_out(&error) => continue,
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => continue,
                Err(source) => {
                    return Err(FieldkitError::socket("receive an echo request", source));
                }
            };
            let Ok(request) = EchoRequest::decode(&buffer[..len]) else {
                bump(&counters.echo_refused);
                continue;
            };
            match request.kind {
                EchoKind::Now => {
                    let answer = EchoAnswer::to(&request, from, here).encode();
                    count_send(socket.send_to(&answer, from), counters);
                }
                EchoKind::FromOtherPort => {
                    let answer = EchoAnswer::to(&request, from, there).encode();
                    count_send(self.socket(other).send_to(&answer, from), counters);
                }
                EchoKind::Delayed(delay) => {
                    let answer = EchoAnswer::to(&request, from, here).encode();
                    self.defer(side, from, answer, delay.duration(), counters)?;
                }
            }
        }
        Ok(())
    }

    fn defer(
        &self,
        side: Side,
        to: SocketAddrV4,
        answer: [u8; 32],
        delay: Duration,
        counters: &Counters,
    ) -> Result<(), FieldkitError> {
        let mut queue = self
            .pending
            .queue
            .lock()
            .map_err(|_| FieldkitError::Worker {
                what: "delayed echo",
            })?;
        if queue.waiting.len() >= MAX_PENDING {
            bump(&counters.echo_delayed_dropped);
            return Ok(());
        }
        queue.sequence += 1;
        let sequence = queue.sequence;
        queue.waiting.push(Reverse(Pending {
            due: Instant::now() + delay,
            sequence,
            side: side.into(),
            to,
            answer,
        }));
        self.pending.wake.notify_one();
        Ok(())
    }

    /// Sends each delayed answer when it falls due.
    fn release(&self, stop: &AtomicBool, counters: &Counters) -> Result<(), FieldkitError> {
        let DelayQueue { queue, wake } = &*self.pending;
        let poisoned = || FieldkitError::Worker {
            what: "delayed echo",
        };
        let mut guard = queue.lock().map_err(|_| poisoned())?;
        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            let due = guard.waiting.peek().map(|Reverse(next)| next.due);
            match due {
                Some(due) if due <= now => {
                    if let Some(Reverse(next)) = guard.waiting.pop() {
                        let side = if next.side.0 { Side::B } else { Side::A };
                        count_send(self.socket(side).send_to(&next.answer, next.to), counters);
                    }
                }
                Some(due) => {
                    guard = wake
                        .wait_timeout(guard, (due - now).min(POLL))
                        .map_err(|_| poisoned())?
                        .0;
                }
                None => {
                    guard = wake.wait_timeout(guard, POLL).map_err(|_| poisoned())?.0;
                }
            }
        }
        Ok(())
    }
}
