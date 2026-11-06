// SPDX-License-Identifier: GPL-3.0-or-later

//! A stream that a reset has ended, as the probe and the router client
//! meet it. macOS refuses every option on such a stream, both of whose
//! directions the reset has shut, and that refusal, on a stream with no
//! peer left, is no failure, while any other refusal, or that one on a
//! stream that still has its peer, is passed on as it is.
//! Each test of a reader waits until the reset has arrived before the code
//! under test sets an option: the probe still reads the line that came
//! before the reset, a reset before the line is a read the reset ended,
//! and a router connection is made on such a stream, its reads giving what
//! came first and then the reset, also where a read lowers its timeout to
//! the request's deadline.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use mooring_daemon_core::status::ProbeStage;

use super::probe::seen;
use crate::router::error::{RouterError, UnreachableCause};
use crate::router::http::{Connection, Timeouts};
use crate::runtime::probe::{PROBE_TIMEOUT, ProbeFailure, read_address};
use crate::sockopt::option_outcome;

/// An argument the call refuses, as macOS refuses an option on a stream
/// that a reset has ended.
const EINVAL: i32 = 22;

/// Permission denied: a refusal of another kind.
const EACCES: i32 = 13;

/// How long a test waits for the loopback to deliver what it waits for.
const PATIENCE: Duration = Duration::from_secs(5);

/// A connection, with a byte of ours waiting unread at its peer, and the
/// peer: the peer's close then ends the connection with a reset.
fn connected() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    stream.write_all(b"x").unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(PATIENCE)).unwrap();
    assert_eq!(peer.peek(&mut [0; 1]).unwrap(), 1, "our byte never came");
    (stream, peer)
}

/// Closes `peer`, which resets the connection, and waits until the reset
/// has reached `stream`: it then has no peer.
fn reset(stream: &TcpStream, peer: TcpStream) {
    drop(peer);
    let started = Instant::now();
    while stream.peer_addr().is_ok() {
        assert!(started.elapsed() < PATIENCE, "the reset never came");
        thread::sleep(Duration::from_millis(1));
    }
}

/// A connection on which the peer wrote `answer` and then reset it, both
/// arrived. An empty answer is not waited for, as in fieldkit's copy,
/// where a peek of nothing on Linux waits out its whole timeout.
fn reset_after(answer: &[u8]) -> TcpStream {
    let (stream, mut peer) = connected();
    if !answer.is_empty() {
        peer.write_all(answer).unwrap();
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        let mut arrived = vec![0; answer.len()];
        let started = Instant::now();
        while stream.peek(&mut arrived).unwrap() < answer.len() {
            assert!(started.elapsed() < PATIENCE, "the answer never came");
            thread::sleep(Duration::from_millis(1));
        }
        stream.set_read_timeout(None).unwrap();
    }
    reset(&stream, peer);
    stream
}

/// What a read reports on a stream that a reset has ended.
fn reset_as_read() -> io::Error {
    reset_after(b"").read(&mut [0; 1]).unwrap_err()
}

#[test]
fn macos_refuses_an_option_on_a_stream_a_reset_has_ended() {
    let refused = reset_after(b"")
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap_err();
    assert_eq!(
        (refused.kind(), refused.raw_os_error()),
        (ErrorKind::InvalidInput, Some(EINVAL))
    );
    assert_eq!(reset_as_read().kind(), ErrorKind::ConnectionReset);
}

#[test]
fn the_refusal_of_a_stream_a_reset_has_ended_is_no_failure() {
    let refused = io::Error::from_raw_os_error(EINVAL);
    assert_eq!(
        seen(option_outcome(&reset_after(b""), Err(refused))),
        Ok(())
    );
}

/// std refuses a zero timeout itself, with no system call.
#[test]
fn any_other_refusal_is_passed_on_as_it_is() {
    let (sound, _peer) = connected();
    let zero = sound.set_read_timeout(Some(Duration::ZERO)).unwrap_err();
    for refused in [zero, io::Error::from_raw_os_error(EACCES)] {
        let passed_on = (refused.kind(), refused.raw_os_error(), refused.to_string());
        assert_eq!(
            seen(option_outcome(&reset_after(b""), Err(refused))),
            Err(passed_on)
        );
    }
    let invalid = io::Error::from_raw_os_error(EINVAL);
    let passed_on = (invalid.kind(), invalid.raw_os_error(), invalid.to_string());
    assert_eq!(seen(option_outcome(&sound, Err(invalid))), Err(passed_on));
}

#[test]
fn a_line_that_came_before_a_reset_is_the_reflectors_answer() {
    assert_eq!(
        read_address(reset_after(b"45.67.89.10\n"), Instant::now(), PROBE_TIMEOUT),
        Ok(Ipv4Addr::new(45, 67, 89, 10))
    );
}

/// With nothing, or part of the line, before it.
#[test]
fn a_reset_before_the_line_ends_the_read() {
    let reset = ProbeFailure {
        stage: ProbeStage::Read,
        kind: Some(ErrorKind::ConnectionReset),
    };
    for answer in [&b""[..], b"45.67"] {
        assert_eq!(
            read_address(reset_after(answer), Instant::now(), PROBE_TIMEOUT),
            Err(reset)
        );
    }
}

/// Limits under which each read lowers its timeout to what is left of
/// the request's time.
fn lowering() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        io: Duration::from_secs(60),
        total: Duration::from_secs(5),
    }
}

/// The bytes one read of `connection` gives.
fn read_once(connection: &mut Connection) -> Result<Vec<u8>, RouterError> {
    let mut buffer = [0_u8; 64];
    let read = connection.read(&mut buffer)?;
    Ok(buffer[..read].to_vec())
}

#[test]
fn a_router_connection_a_reset_has_ended_reads_what_came_and_then_the_reset() {
    let timeouts = lowering();
    let deadline = Instant::now() + timeouts.total;
    let mut connection = Connection::over(reset_after(b"HTTP/1.1"), deadline, &timeouts).unwrap();
    assert_eq!(read_once(&mut connection), Ok(b"HTTP/1.1".to_vec()));
    assert_eq!(
        read_once(&mut connection),
        Err(RouterError::unreachable(UnreachableCause::Receive {
            kind: reset_as_read().kind(),
        }))
    );
}

#[test]
fn a_read_that_lowers_its_timeout_after_a_reset_finds_the_reset() {
    let timeouts = lowering();
    let (stream, peer) = connected();
    let watched = stream.try_clone().unwrap();
    let mut connection =
        Connection::over(stream, Instant::now() + timeouts.total, &timeouts).unwrap();
    reset(&watched, peer);
    assert_eq!(
        read_once(&mut connection),
        Err(RouterError::unreachable(UnreachableCause::Receive {
            kind: ErrorKind::ConnectionReset,
        }))
    );
}
