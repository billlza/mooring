// SPDX-License-Identifier: GPL-3.0-or-later

//! An in-process HTTP stub on `127.0.0.1`, scripted per connection: it
//! records every byte each connection sends and answers as scripted.
//! [`Stub::finish`] returns every connection the client made before it.
//! A stub dropped without it (a test that failed first) stops holding
//! connections at once and its thread ends at a safety limit; nothing waits
//! for that thread, so a failing test cannot hang.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How one connection is answered.
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    /// Writes these bytes, then closes.
    Bytes(Vec<u8>),
    /// Writes each piece after a pause, then closes.
    Drip {
        pieces: Vec<Vec<u8>>,
        pause: Duration,
    },
    /// Sends nothing and holds the connection for this long.
    Silent(Duration),
}

/// What one connection sent, byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Received(pub(crate) Vec<u8>);

impl Received {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    /// The request line.
    pub(crate) fn request_line(&self) -> String {
        self.text().lines().next().unwrap_or_default().to_owned()
    }
}

/// The longest a stub runs, whatever the test does.
const SAFETY_LIMIT: Duration = Duration::from_secs(20);

/// What [`Stub::finish`]'s own connection sends: no client sends it, and it
/// ends as a request head does, so the stub reads it as one.
const SENTINEL: &[u8] = b"MOORING-STUB-SENTINEL\r\n\r\n";

pub(crate) struct Stub {
    port: u16,
    stop: Arc<AtomicBool>,
    /// The stub's thread: what each connection sent, or `None` if it
    /// reached the safety limit before the sentinel.
    thread: Option<JoinHandle<Option<Vec<Received>>>>,
}

/// Reads one request: up to the end of its head, then `Content-Length`
/// bytes of body; or everything until the client closes or goes quiet.
fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    let head_end = loop {
        match stream.read(&mut byte) {
            Ok(1) => bytes.push(byte[0]),
            Ok(_) | Err(_) => return bytes,
        }
        if bytes.ends_with(b"\r\n\r\n") {
            break bytes.len();
        }
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse::<usize>().unwrap());
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).unwrap();
    bytes.extend(body);
    bytes
}

fn hold(stop: &AtomicBool, duration: Duration) {
    let until = Instant::now() + duration;
    while Instant::now() < until && !stop.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(5));
    }
}

fn answer(mut stream: TcpStream, reply: &Reply, stop: &AtomicBool) {
    match reply {
        Reply::Bytes(bytes) => {
            // The client may close first (a login answer's body is never
            // read); a failed write is then expected.
            let _ = stream.write_all(bytes);
        }
        Reply::Drip { pieces, pause } => {
            for piece in pieces {
                hold(stop, *pause);
                if stream.write_all(piece).is_err() {
                    return;
                }
            }
        }
        Reply::Silent(duration) => hold(stop, *duration),
    }
}

impl Stub {
    /// Starts a stub answering the n-th connection with `replies[n]`;
    /// connections past the script are recorded and closed unanswered.
    pub(crate) fn start(replies: Vec<Reply>) -> Self {
        Self::start_for(|_| replies)
    }

    /// Starts a stub answering as [`Stub::start`] does with the replies
    /// `script` returns for the stub's own port, so an answer can name the
    /// stub's address (a `Location`).
    pub(crate) fn start_for(script: impl FnOnce(u16) -> Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let replies = script(port);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let started = Instant::now();
            let mut received = Vec::new();
            let mut replies = replies.into_iter();
            while started.elapsed() < SAFETY_LIMIT {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let request = read_request(&mut stream);
                        if request == SENTINEL {
                            return Some(received);
                        }
                        received.push(Received(request));
                        if let Some(reply) = replies.next() {
                            answer(stream, &reply, &flag);
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("stub accept failed: {error}"),
                }
            }
            None
        });
        Self {
            port,
            stop,
            thread: Some(thread),
        }
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    /// Stops the stub and returns what each connection the client made
    /// before this call sent, in order, however late the stub's thread
    /// accepts them.
    ///
    /// A client's `connect` returns once its own side of the handshake is
    /// done; the kernel completes the stub's side, which `accept` waits for,
    /// when it processes the client's last handshake packet, on a thread of
    /// its own. Measured on macOS 27.0.1 (26A434) on 2026-10-14, an `accept`
    /// made right after a client's `connect` returned found nothing in 41 of
    /// 1500 rounds: draining the queue until `accept` would block can miss a
    /// connection, and waiting for an expected count cannot show that none
    /// follows it. So this call sets the stop flag, which cuts any hold
    /// short, and makes one connection of its own, which sends
    /// [`SENTINEL`]; the stub accepts until it has that one. Every
    /// connection the client made before this call is accepted before the
    /// sentinel: the client's last handshake packet is sent before its
    /// `connect` returns, so before the sentinel's first packet, and the
    /// kernel handles loopback packets in the order they were sent
    /// *(inference from how the kernel completes a handshake and queues
    /// loopback packets; in each of those 41 rounds, a connection made
    /// afterwards was accepted after the missed one)*.
    pub(crate) fn finish(mut self) -> Vec<Received> {
        self.stop.store(true, Ordering::SeqCst);
        let mut sentinel = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))
            .unwrap_or_else(|error| panic!("the stub stopped before the test finished: {error}"));
        sentinel.write_all(SENTINEL).unwrap();
        self.thread
            .take()
            .unwrap()
            .join()
            .unwrap()
            .unwrap_or_else(|| panic!("the stub reached its safety limit before the sentinel"))
    }
}

impl Drop for Stub {
    /// Without [`Stub::finish`] (a test that failed first), cuts any hold
    /// short; the thread then ends at the safety limit, and nothing waits
    /// for it.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// An HTTP/1.1 answer with `status`, extra header lines and a
/// `Content-Length` body.
pub(crate) fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for header in headers {
        bytes.extend(header.as_bytes());
        bytes.extend(b"\r\n");
    }
    bytes.extend(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    bytes.extend(body);
    bytes
}

/// A 200 JSON answer.
pub(crate) fn json(headers: &[&str], body: &[u8]) -> Reply {
    let mut all = vec!["Content-Type: application/json"];
    all.extend_from_slice(headers);
    Reply::Bytes(response("200 OK", &all, body))
}
