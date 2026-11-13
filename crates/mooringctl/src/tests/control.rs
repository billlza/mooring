// SPDX-License-Identifier: GPL-3.0-or-later

//! The control socket's connections at their edges (design §10.1, §15.1):
//! a client gone before the protocol line, a request with no time left,
//! the end a failed setsockopt(2), a failed write or a poisoned hub gives
//! a connection, and which failures of a write say that its peer has gone.

use std::io::{self, BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use mooring_daemon_core::control::{DaemonReply, Refusal, decode_reply};

use crate::daemon::hub::HubPoisoned;
use crate::daemon::serve::{End, LIMITS, Limits, serve, setsockopt_end, write_end};
use crate::daemon::{Control, peer};

/// What the connections share, with no loop behind it.
fn control() -> Control {
    Control::new().0
}

/// A client that has gone before the daemon wrote its first line has
/// left; nothing else is tried.
#[test]
fn a_client_gone_before_the_protocol_line_has_left() {
    let (client, server) = UnixStream::pair().unwrap();
    drop(client);
    assert_eq!(serve(server, &control(), LIMITS), End::ClientLeft);
}

/// A request with no time left is refused as bad before a byte of it is
/// read: the limit holds for the whole line.
#[test]
fn a_request_with_no_time_left_is_refused() {
    let (client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let none_left = Limits {
        request: Duration::ZERO,
        ..LIMITS
    };
    assert_eq!(
        serve(server, &control(), none_left),
        End::Refused(Refusal::BadRequest)
    );
    let mut reader = BufReader::new(client);
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).unwrap();
    line.clear();
    reader.read_until(b'\n', &mut line).unwrap();
    assert_eq!(
        decode_reply(&line).unwrap(),
        DaemonReply::Refused {
            reason: Refusal::BadRequest
        }
    );
}

/// setsockopt(2) fails with EINVAL on macOS once the client has shut its
/// side: that client has left. Any other failure is the connection's I/O
/// error. A poisoned hub ends the connection as such.
#[test]
fn a_failed_setsockopt_or_a_poisoned_hub_ends_the_connection() {
    assert_eq!(
        setsockopt_end(io::Error::from(io::ErrorKind::InvalidInput)),
        End::ClientLeft
    );
    assert_eq!(
        setsockopt_end(io::Error::from(io::ErrorKind::PermissionDenied)),
        End::Io(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(End::from(HubPoisoned), End::Poisoned);
}

/// A write that failed found its peer gone when it failed with a broken
/// pipe, with "not connected", which macOS gives when the close overtakes
/// the write, or with a reset: that client has left. No other failure
/// says so: it is the connection's I/O error, by its kind.
#[test]
fn only_a_closed_connection_is_a_peer_gone() {
    for kind in [
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::NotConnected,
        io::ErrorKind::ConnectionReset,
    ] {
        assert!(peer::gone(kind), "{kind:?}");
        assert_eq!(write_end(kind), End::ClientLeft, "{kind:?}");
    }
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::WriteZero,
        io::ErrorKind::Interrupted,
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::Other,
    ] {
        assert!(!peer::gone(kind), "{kind:?}");
        assert_eq!(write_end(kind), End::Io(kind), "{kind:?}");
    }
}
