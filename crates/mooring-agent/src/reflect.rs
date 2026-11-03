// SPDX-License-Identifier: GPL-3.0-or-later

//! `reflect`, the reflector (design §11.4): on `<VPS4>:27900`, write the
//! peer's IPv4 and `\n`, then close. At most 16 connections at once, a 2 s
//! write timeout, no state and no logging of addresses. nft limits new
//! connections per source (§8.5).

use std::io::{self, ErrorKind, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// The most connections answered at once.
pub(crate) const MAX_CONNECTIONS: usize = 16;

/// The write timeout.
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the reflector waits when the node is out of files or memory
/// for a moment, instead of spinning on `accept`.
pub(crate) const PAUSE: Duration = Duration::from_millis(100);

/// The line for a peer at `peer`.
pub(crate) fn line(peer: SocketAddrV4) -> String {
    format!("{}\n", peer.ip())
}

/// Serves on `listener` until accepting fails for good, and returns that
/// failure.
pub(crate) fn serve(listener: &TcpListener) -> io::Error {
    serve_with(
        &mut || listener.accept(),
        &Slots::new(MAX_CONNECTIONS),
        answer,
        &mut pause,
    )
}

/// Serves the connections `accept` gives until it fails for good, and
/// returns that failure. Each connection is answered with `answer` on a
/// thread of its own while `slots` has one free, and holds its slot until
/// `answer` returns. A connection over the limit, or from a peer that is
/// not IPv4, is closed unanswered; one whose thread cannot be started is
/// dropped, and its slot with it.
pub(crate) fn serve_with(
    accept: &mut dyn FnMut() -> io::Result<(TcpStream, SocketAddr)>,
    slots: &Slots,
    answer: fn(TcpStream, SocketAddrV4),
    pause: &mut dyn FnMut(),
) -> io::Error {
    loop {
        let (stream, peer) = match accept() {
            Ok(accepted) => accepted,
            Err(error) => match after(&error) {
                Accepting::Pause => {
                    pause();
                    continue;
                }
                Accepting::Retry => continue,
                Accepting::Stop => return error,
            },
        };
        let SocketAddr::V4(peer) = peer else {
            continue;
        };
        let Some(slot) = slots.take() else {
            continue;
        };
        let _unanswered = thread::Builder::new()
            .name("reflect".to_owned())
            .spawn(move || {
                let _slot = slot;
                answer(stream, peer);
            });
    }
}

/// Waits [`PAUSE`].
pub(crate) fn pause() {
    thread::sleep(PAUSE);
}

/// Writes `peer`'s line to `stream` within [`WRITE_TIMEOUT`], then closes
/// it.
pub(crate) fn answer(mut stream: TcpStream, peer: SocketAddrV4) {
    // A peer that cannot be written to within the timeout gets nothing;
    // the reflector keeps no record of it.
    let _unanswered = stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .and_then(|()| stream.write_all(line(peer).as_bytes()));
}

/// The connections being answered, at most a limit at once.
#[derive(Debug)]
pub(crate) struct Slots {
    taken: Arc<AtomicUsize>,
    limit: usize,
}

/// One connection's slot, freed when dropped.
#[derive(Debug)]
pub(crate) struct Slot {
    taken: Arc<AtomicUsize>,
}

impl Slots {
    /// No slot taken, `limit` at most.
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            taken: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    /// A slot, unless `limit` are taken.
    pub(crate) fn take(&self) -> Option<Slot> {
        self.taken
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < self.limit).then_some(taken + 1)
            })
            .ok()
            .map(|_| Slot {
                taken: Arc::clone(&self.taken),
            })
    }

    /// The slots taken now (tests).
    #[cfg(test)]
    pub(crate) fn taken(&self) -> usize {
        self.taken.load(Ordering::Acquire)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.taken.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What the reflector does after `accept` failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accepting {
    /// Out of files or memory for a moment: wait [`PAUSE`], then accept.
    Pause,
    /// The failure was one connection's: accept the next.
    Retry,
    /// The listener failed: the reflector stops, and systemd restarts it.
    Stop,
}

/// What to do after `accept` failed with `error`. Linux's accept(2)
/// passes on network errors already pending on the new connection, and
/// says to retry them as `EAGAIN`; the numbers are Linux's (the same on
/// x86_64 and arm64), since the reflector runs there only.
pub(crate) fn after(error: &io::Error) -> Accepting {
    match error.raw_os_error() {
        Some(ENOMEM | ENFILE | EMFILE | ENOBUFS) => Accepting::Pause,
        Some(
            ENONET | EPROTO | ENOPROTOOPT | EOPNOTSUPP | ENETDOWN | ENETUNREACH | EHOSTDOWN
            | EHOSTUNREACH,
        ) => Accepting::Retry,
        _ => match error.kind() {
            ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted => {
                Accepting::Retry
            }
            _ => Accepting::Stop,
        },
    }
}

// Linux error numbers (asm-generic) that `accept` gives.
const ENOMEM: i32 = 12;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENONET: i32 = 64;
const EPROTO: i32 = 71;
const ENOPROTOOPT: i32 = 92;
const EOPNOTSUPP: i32 = 95;
const ENETDOWN: i32 = 100;
const ENETUNREACH: i32 = 101;
const ENOBUFS: i32 = 105;
const EHOSTDOWN: i32 = 112;
const EHOSTUNREACH: i32 = 113;
