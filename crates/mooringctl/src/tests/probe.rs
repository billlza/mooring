// SPDX-License-Identifier: GPL-3.0-or-later

//! The probe's reading of socket2's connect report, and its read of the
//! reflector's line within what is left of its time (design §10.2). A
//! hang-up with no error set is the connection only on a socket that has
//! a peer, as one whose peer answered and hung up still has, and every
//! other report is passed on as it is, so the reading is pinned whether or
//! not a run meets the race that brings it (fieldkit's `tests::net` pins
//! its copy alike). None left is a time-out before any read, and a
//! reflector that stays silent is a read that fails at its limit. The
//! probes' answers otherwise are the runtime tests'.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mooring_daemon_core::status::ProbeStage;
use socket2::{Domain, Protocol, Socket, Type};

use crate::runtime::probe::{ProbeFailure, connect_outcome, read_address};

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
    peer.write_all(b"45.67.89.10\n").unwrap();
    drop(peer);
    drop(listener);
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut answer = Vec::new();
    socket.read_to_end(&mut answer).unwrap();
    assert_eq!(answer, b"45.67.89.10\n");
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
    // Nothing listens on port 0, nor can.
    let os_error = unconnected()
        .connect(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap_err();
    assert!(os_error.raw_os_error().is_some(), "{os_error:?}");
    for error in [io::Error::from(ErrorKind::TimedOut), os_error] {
        let expected = (error.kind(), error.raw_os_error(), error.to_string());
        assert_eq!(seen(connect_outcome(&socket, Err(error))), Err(expected));
    }
}

/// A connection to a loopback listener that never writes, and the
/// listener's end, held open.
fn silent() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn a_read_with_no_time_left_times_out_before_reading() {
    let (client, _server) = silent();
    assert_eq!(
        read_address(client, Instant::now(), Duration::ZERO),
        Err(ProbeFailure {
            stage: ProbeStage::Read,
            kind: Some(ErrorKind::TimedOut),
        })
    );
}

#[test]
fn a_silent_reflector_is_a_read_that_fails_at_its_limit() {
    let (client, _server) = silent();
    let started = Instant::now();
    let failure = read_address(client, started, Duration::from_millis(100)).unwrap_err();
    assert_eq!(failure.stage, ProbeStage::Read);
    assert!(
        matches!(
            failure.kind,
            Some(ErrorKind::WouldBlock | ErrorKind::TimedOut)
        ),
        "{failure:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}
