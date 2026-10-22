// SPDX-License-Identifier: GPL-3.0-or-later

//! `reflect`, the reflector (design §11.4): on `<VPS4>:27900`, write the
//! peer's IPv4 and `\n`, then close. At most 16 connections at once, a 2 s
//! write timeout, no state and no logging of addresses. nft limits new
//! connections per source (§8.5).

use std::io::Write;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// The most connections answered at once.
pub(crate) const MAX_CONNECTIONS: usize = 16;

/// The write timeout.
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// The line for a peer at `peer`.
pub(crate) fn line(peer: SocketAddrV4) -> String {
    format!("{}\n", peer.ip())
}

/// Serves on `listener` until accepting fails for good. A connection over
/// the limit is closed unanswered; one that fails is dropped.
pub(crate) fn serve(listener: &TcpListener) -> std::io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.raw_os_error() == Some(EMFILE) => {
                // Out of files for a moment: wait instead of spinning.
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) if retryable(&error) => continue,
            Err(error) => return Err(error),
        };
        let SocketAddr::V4(peer) = peer else {
            continue;
        };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let worker = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name("reflect".to_owned())
            .spawn(move || {
                answer(stream, peer);
                worker.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            // The closure, and with it the counter's decrement, never ran.
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn answer(mut stream: TcpStream, peer: SocketAddrV4) {
    // A peer that cannot be written to within the timeout gets nothing;
    // the reflector keeps no record of it.
    let _unanswered = stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .and_then(|()| stream.write_all(line(peer).as_bytes()));
}

/// Accept errors that concern one connection, not the listener.
fn retryable(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        error.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
    )
}

/// `EMFILE` on Linux: out of files for a moment.
const EMFILE: i32 = 24;
