// SPDX-License-Identifier: GPL-3.0-or-later

//! A stream that a reset has ended, as the measurements and the sink meet
//! it. macOS refuses every option on such a stream and Linux sets it; that
//! refusal, on a stream with no peer left, is no failure, while any other
//! refusal, or that one on a stream that still has its peer, is passed on
//! as it is. Each test of a reader waits until the reset has arrived
//! before the code under test sets an option, and expects what a read or
//! a write reports on such a stream on either system. The reflector's line
//! that came before the reset is its answer, and a reset before the line
//! is a failed read; a target that resets before acknowledging refuses the
//! attempt; a flow on such a stream fails to send; aborting it is done,
//! and aborting any stream resets it; the sink's session ends with the
//! reset, its opening line read or not, and its report fails as a write on
//! such a stream does. None is the tool's own failure.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

use super::net::seen;
use crate::measure::port_ceiling::{self, Attempt, acknowledgement};
use crate::measure::uplink::{self, abort, flow_over};
use crate::net::{Failure, option_outcome, reflector_answer};
use crate::serve::{send_report, sink_session};
use crate::wire::{reflector_line, sink_line};

/// An argument the call refuses, as macOS refuses an option on a stream
/// that a reset has ended.
const EINVAL: i32 = 22;

/// Permission denied: a refusal of another kind.
const EACCES: i32 = 13;

/// How long a test waits for the loopback to deliver what it waits for.
const PATIENCE: Duration = Duration::from_secs(5);

/// The peer the plans name; the streams under test are already connected.
const PEER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9);

/// A connection and its peer.
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(PATIENCE)).unwrap();
    (stream, peer)
}

/// A connection, with a byte of ours waiting unread at its peer, and the
/// peer: the peer's close then ends the connection with a reset.
fn connected() -> (TcpStream, TcpStream) {
    let (mut stream, peer) = pair();
    stream.write_all(b"x").unwrap();
    assert_eq!(peer.peek(&mut [0; 1]).unwrap(), 1, "our byte never came");
    (stream, peer)
}

/// A connection on which the peer wrote `answer` and then reset it, both
/// arrived: the stream then has no peer. An empty answer is not waited
/// for: on Linux a peek of nothing waits out its whole timeout.
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
    drop(peer);
    let started = Instant::now();
    while stream.peer_addr().is_ok() {
        assert!(started.elapsed() < PATIENCE, "the reset never came");
        thread::sleep(Duration::from_millis(1));
    }
    stream
}

/// What a read reports on a stream that a reset has ended.
fn reset_as_read() -> io::Error {
    reset_after(b"").read(&mut [0; 1]).unwrap_err()
}

/// What a write reports on a stream that a reset has ended.
fn reset_as_written() -> io::Error {
    reset_after(b"").write(b"x").unwrap_err()
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
    let (sound, _peer) = pair();
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
    let observed = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 40_000);
    let stream = reset_after(reflector_line(observed).as_bytes());
    assert_eq!(
        reflector_answer(stream, PEER, PATIENCE).unwrap(),
        Ok(observed)
    );
}

/// With nothing, or part of the line, before it.
#[test]
fn a_reset_before_the_reflectors_line_is_a_failed_read() {
    let failed = Failure::of("read", &reset_as_read());
    for answer in [&b""[..], b"MFK1 198.51"] {
        assert_eq!(
            reflector_answer(reset_after(answer), PEER, PATIENCE).unwrap(),
            Err(failed.clone())
        );
    }
}

#[test]
fn a_target_that_resets_before_acknowledging_refuses_the_attempt() {
    let plan = port_ceiling::Plan {
        target: PEER,
        max: 1,
        timeout: PATIENCE,
    };
    match acknowledgement(reset_after(b""), plan).unwrap() {
        Attempt::TargetRefused(failure) => {
            assert_eq!(failure, Failure::of("acknowledge", &reset_as_read()));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_flow_on_a_stream_a_reset_has_ended_fails_to_send() {
    let plan = uplink::Plan {
        sink: PEER,
        echo: PEER,
        duration: Duration::from_secs(1),
        interval: Duration::from_secs(1),
        seconds: 1,
        warmup: 0,
        flows: 1,
    };
    assert_eq!(
        flow_over(reset_after(b""), plan).unwrap(),
        Err(Failure::of("send", &reset_as_written()))
    );
}

#[test]
fn aborting_a_stream_a_reset_has_ended_is_done() {
    abort(reset_after(b"")).unwrap();
}

#[test]
fn aborting_a_stream_resets_it() {
    let (stream, mut peer) = pair();
    abort(stream).unwrap();
    let ended = peer.read(&mut [0; 1]).unwrap_err();
    assert_eq!(ended.kind(), ErrorKind::ConnectionReset);
}

#[test]
fn the_sinks_session_on_a_stream_a_reset_has_ended_ends_with_the_reset() {
    let stop = AtomicBool::new(false);
    let reset = reset_as_read();
    for answer in [String::new(), sink_line(1)] {
        let ended = sink_session(reset_after(answer.as_bytes()), &stop).unwrap_err();
        assert_eq!(
            (ended.kind(), ended.to_string()),
            (reset.kind(), reset.to_string())
        );
    }
}

/// A reset that comes between the window and the report: the report's
/// write meets it.
#[test]
fn the_sinks_report_on_a_stream_a_reset_has_ended_fails_as_a_write() {
    let written = reset_as_written();
    let failed = send_report(&mut reset_after(b""), b"{}\n").unwrap_err();
    assert_eq!(
        (failed.kind(), failed.to_string()),
        (written.kind(), written.to_string())
    );
}
