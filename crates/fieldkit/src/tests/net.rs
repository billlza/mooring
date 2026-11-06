// SPDX-License-Identifier: GPL-3.0-or-later

//! The reading of socket2's connect report: a hang-up with no error set is
//! the connection only on a socket that has a peer, as one whose peer
//! answered and hung up still has, and every other report is passed on as
//! it is, so the reading is pinned whether or not a run meets the race
//! that brings it (mooringctl's `tests::probe` pins its copy alike). The
//! measurements' connects are the loopback tests'.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::net::connect_outcome;

/// A TCP socket connected to nothing.
fn unconnected() -> Socket {
    Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap()
}

/// A TCP socket as the race leaves it: its peer accepted it, answered and
/// hung up, and the listener is gone. The answer is read to its end, so
/// the hang-up has arrived.
fn answered_and_hung_up() -> Socket {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut socket = unconnected();
    socket
        .connect(&listener.local_addr().unwrap().into())
        .unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.write_all(b"x").unwrap();
    drop(peer);
    drop(listener);
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut answer = Vec::new();
    socket.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"x");
    socket
}

/// socket2's report of a hang-up with no error set.
fn hang_up() -> io::Error {
    io::Error::other("no error set after POLLHUP")
}

/// A report as these tests compare it: the error's kind, its operating
/// system's code and its text.
pub(super) fn seen(report: io::Result<()>) -> Result<(), (ErrorKind, Option<i32>, String)> {
    report.map_err(|error| (error.kind(), error.raw_os_error(), error.to_string()))
}

#[test]
fn a_hang_up_with_no_error_after_the_peer_answered_is_the_connection() {
    let socket = answered_and_hung_up();
    assert_eq!(seen(connect_outcome(&socket, Err(hang_up()))), Ok(()));
}

#[test]
fn a_hang_up_on_a_socket_with_no_peer_stays_the_failure_it_is() {
    assert_eq!(
        seen(connect_outcome(&unconnected(), Err(hang_up()))),
        seen(Err(hang_up()))
    );
}

/// A connection, socket2's own time-out and an operating system's error
/// are passed on as they are, even on a socket that has a peer.
#[test]
fn every_other_report_is_passed_on_as_it_is() {
    let socket = answered_and_hung_up();
    assert_eq!(seen(connect_outcome(&socket, Ok(()))), Ok(()));
    // Nothing listens on port 0, nor can: refused on Linux, an address the
    // system cannot assign on macOS.
    let os_error = unconnected()
        .connect(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap_err();
    assert!(os_error.raw_os_error().is_some(), "{os_error:?}");
    for error in [io::Error::from(ErrorKind::TimedOut), os_error] {
        let expected = (error.kind(), error.raw_os_error(), error.to_string());
        assert_eq!(seen(connect_outcome(&socket, Err(error))), Err(expected));
    }
}
