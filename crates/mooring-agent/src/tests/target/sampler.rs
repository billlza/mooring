// SPDX-License-Identifier: GPL-3.0-or-later

//! The handshake sampler (design §11.7) against servers on 127.0.0.1:
//! the ClientHello it builds, the ServerHello that starts a flight, a
//! sample timed to the flight's last byte and counting all of it, however
//! late or slowly a flight that ends by the deadline comes, and the p95
//! by nearest rank; no sample from a target that refuses the connection,
//! does not answer the hello by the deadline, closes or resets it (a reset
//! after the hello described as one, whether it comes before the flight's
//! first read or during the flight), or is still sending its flight at the
//! deadline; no connection at all without randomness; and the node's
//! times, the design's. Tests that wait on a deadline give the sampler a
//! short one.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mooring_agent_proto::{AgentError, StderrTail, TargetTool};

use super::world::{Server, closed_port, flight, host, serve};
use crate::target::sampler::{self, NODE, RANDOM_BYTES, Timing};
use crate::tests::{EACCES, EINVAL};

/// The node's timing with a 200 ms deadline and a quiet longer than it,
/// so that only the deadline can end a flight.
const SHORT_DEADLINE: Timing = Timing {
    deadline: Duration::from_millis(200),
    idle: Duration::from_secs(5),
    ..NODE
};

fn random() -> [u8; RANDOM_BYTES] {
    let mut bytes = [0; RANDOM_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    bytes
}

#[test]
fn the_hello_is_a_tls_record_with_its_random_session_and_key_share() {
    let hello = sampler::client_hello(&host(), &random());
    assert_eq!(&hello[..3], [0x16, 0x03, 0x01]);
    assert_eq!(
        usize::from(u16::from_be_bytes([hello[3], hello[4]])),
        hello.len() - 5
    );
    assert_eq!(hello[5], 0x01, "a ClientHello");
    let body_length =
        usize::from(hello[6]) << 16 | usize::from(hello[7]) << 8 | usize::from(hello[8]);
    assert_eq!(body_length, hello.len() - 9);
    assert_eq!(&hello[9..11], [0x03, 0x03]);
    assert_eq!(&hello[11..43], &random()[..32]);
    assert_eq!(hello[43], 32);
    assert_eq!(&hello[44..76], &random()[32..64]);
    // The X25519 share ends the hello.
    assert_eq!(&hello[hello.len() - 32..], &random()[64..]);
    assert_eq!(&hello[hello.len() - 36..hello.len() - 34], [0x00, 0x1d]);
    let find = |needle: &[u8]| hello.windows(needle.len()).any(|window| window == needle);
    assert!(find(b"\x00\x0fwww.example.com"), "SNI");
    assert!(find(b"\x02h2\x08http/1.1"), "ALPN");
    assert!(
        find(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]),
        "TLS 1.3 and 1.2"
    );
}

#[test]
fn only_a_server_hello_that_asks_for_nothing_more_starts_a_flight() {
    assert_eq!(sampler::check_server_hello(&flight(10)), Ok(()));
    let mut retry = flight(10);
    retry[11..43].copy_from_slice(&[
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ]);
    for (bad, text) in [
        (retry, "another hello"),
        (vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28], "alert"),
        (b"HTTP/1.1 400 Bad Request\r\n".to_vec(), "not TLS"),
        (
            vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x0b, 0x00, 0x00, 0x00],
            "not a ServerHello",
        ),
        (flight(10)[..20].to_vec(), "cut short"),
    ] {
        let error = sampler::check_server_hello(&bad).unwrap_err();
        assert!(error.contains(text), "{error}");
    }
}

#[test]
fn a_sample_times_the_flight_to_its_last_byte_and_counts_all_of_it() {
    let whole = flight(3000);
    let address = serve(
        Server::Flight(
            whole[..100].to_vec(),
            Duration::from_millis(40),
            whole[100..].to_vec(),
        ),
        1,
    );
    let started = Instant::now();
    let sample = sampler::sample(address, &host(), NODE, &random()).unwrap();
    assert!(
        started.elapsed() < NODE.deadline,
        "the quiet, not the deadline, ended the flight"
    );
    assert_eq!(usize::try_from(sample.bytes).unwrap(), whole.len());
    assert!(sample.micros >= 40_000, "{sample:?}");
    assert!(
        u128::from(sample.micros) < NODE.idle.as_micros(),
        "the quiet after the flight is not counted: {sample:?}"
    );
}

#[test]
fn a_flight_that_starts_after_a_quiet_but_by_the_deadline_is_measured() {
    // The quiet ends a flight only once it began: before its first byte
    // the target has until the deadline.
    let late = Timing {
        idle: Duration::from_millis(100),
        deadline: Duration::from_secs(5),
        ..NODE
    };
    let address = serve(
        Server::Flight(Vec::new(), Duration::from_millis(300), flight(10)),
        1,
    );
    let sample = sampler::sample(address, &host(), late, &random()).unwrap();
    assert_eq!(usize::try_from(sample.bytes).unwrap(), flight(10).len());
    assert!(sample.micros >= 300_000, "{sample:?}");
}

#[test]
fn a_slow_flight_that_ends_by_the_deadline_is_measured_whole() {
    // A byte every 20 ms for half a second, with a quiet of a second to
    // end the flight and a deadline far past it.
    let slow = Timing {
        idle: Duration::from_secs(1),
        deadline: Duration::from_secs(5),
        ..NODE
    };
    let dripping = serve(Server::Drip(flight(0), Duration::from_millis(20), 25), 1);
    let sample = sampler::sample(dripping, &host(), slow, &random()).unwrap();
    assert_eq!(
        usize::try_from(sample.bytes).unwrap(),
        flight(0).len() + 25,
        "{sample:?}"
    );
    assert!(sample.micros >= 400_000, "{sample:?}");
}

#[test]
fn a_target_that_does_not_answer_a_hello_is_no_sample() {
    let silent = serve(Server::Silent, 1);
    let started = Instant::now();
    assert_eq!(
        sampler::sample(silent, &host(), SHORT_DEADLINE, &random()),
        Err("the target sent nothing back".to_owned())
    );
    let waited = started.elapsed();
    assert!(
        waited >= SHORT_DEADLINE.deadline && waited < SHORT_DEADLINE.idle,
        "it waited for the deadline, not a quiet: {waited:?}"
    );
    let closing = serve(Server::Close, 1);
    assert_eq!(
        sampler::sample(closing, &host(), SHORT_DEADLINE, &random()),
        Err("the target closed without an answer".to_owned())
    );
    let closed = SocketAddr::from((Ipv4Addr::LOCALHOST, closed_port()));
    let refused = sampler::sample(closed, &host(), NODE, &random()).unwrap_err();
    assert!(refused.starts_with("connect:"), "{refused}");
}

#[test]
fn a_flight_still_coming_at_the_deadline_is_no_sample() {
    // A byte every 20 ms for a second never leaves the quiet that ends a
    // flight; without the deadline the sampler would read all of them,
    // and a target dripping 64 KiB would hold it for hours.
    let dripping = serve(Server::Drip(flight(0), Duration::from_millis(20), 50), 1);
    let started = Instant::now();
    assert_eq!(
        sampler::sample(dripping, &host(), SHORT_DEADLINE, &random()),
        Err("the target's first flight had not ended 200 ms after the hello".to_owned())
    );
    assert!(
        started.elapsed() >= SHORT_DEADLINE.deadline,
        "the flight was read until the deadline"
    );
}

#[test]
fn the_node_holds_a_handshake_to_the_designs_times() {
    assert_eq!(
        NODE,
        Timing {
            connect: Duration::from_secs(3),
            idle: Duration::from_millis(300),
            deadline: Duration::from_secs(3),
        }
    );
    assert_eq!(NODE.bound(), Duration::from_millis(6300));
}

#[test]
fn the_p95_is_the_nearest_rank() {
    let mut twenty: Vec<u64> = (1..=20).rev().collect();
    assert_eq!(sampler::p95(&mut twenty), Some(19));
    assert_eq!(sampler::p95(&mut [7]), Some(7));
    assert_eq!(sampler::p95(&mut [3, 1]), Some(3));
    assert_eq!(sampler::p95(&mut []), None);
}

#[test]
fn randomness_the_sampler_cannot_have_ends_it_before_any_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let denied = io::Error::from_raw_os_error(EACCES);
    assert_eq!(
        sampler::measure(listener.local_addr().unwrap(), &host(), NODE, || {
            Err(io::Error::from_raw_os_error(EACCES))
        }),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::HandshakeSampler,
            stderr_tail: StderrTail::scrubbed(format!("randomness: {denied}").as_bytes(), &[]),
        })
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "no connection was made"
    );
}

/// What a reset reads as on this OS: the read after the hello, on a
/// connection to a target that resets it.
fn reset_as_read() -> io::Error {
    let mut probe = TcpStream::connect(serve(Server::Reset, 1)).unwrap();
    probe
        .write_all(&sampler::client_hello(&host(), &random()))
        .unwrap();
    let reset = probe.read(&mut [0; 16]).unwrap_err();
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);
    reset
}

#[test]
fn a_target_that_resets_the_connection_is_no_sample() {
    let reset = reset_as_read();
    assert_eq!(
        sampler::sample(serve(Server::Reset, 1), &host(), NODE, &random()),
        Err(format!("receive: {reset}"))
    );
}

/// A connection to a target that resets it after the hello, once the
/// reset has come, which leaves the socket with no peer.
fn reset_after_the_hello() -> TcpStream {
    let mut stream = TcpStream::connect(serve(Server::Reset, 1)).unwrap();
    stream
        .write_all(&sampler::client_hello(&host(), &random()))
        .unwrap();
    let started = Instant::now();
    while stream.peer_addr().is_ok() {
        assert!(started.elapsed() < Duration::from_secs(5), "no reset came");
        std::thread::sleep(Duration::from_millis(1));
    }
    stream
}

/// A reset that came before the flight's first read: macOS then refuses
/// the read timeout, Linux sets it and the read finds the reset. Either
/// way the reset is what is described.
#[test]
fn a_reset_before_the_first_read_is_described_as_the_reset() {
    let reset = reset_as_read();
    let mut stream = reset_after_the_hello();
    assert_eq!(
        sampler::first_flight(&mut stream, Instant::now(), NODE),
        Err(format!("receive: {reset}"))
    );
}

/// The refusal macOS gives a socket that a reset has closed is described
/// as the reset, on either system.
#[test]
fn the_refusal_of_a_socket_a_reset_closed_is_the_reset() {
    let reset = reset_as_read();
    let refused = io::Error::from_raw_os_error(EINVAL);
    assert_eq!(
        sampler::refused_timeout(&reset_after_the_hello(), &refused),
        format!("receive: {reset}")
    );
}

/// Any other refusal is described as itself, even on a socket that a
/// reset has closed, and so is that refusal on a socket that holds no
/// error.
#[test]
fn any_other_refusal_is_the_refusal() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let sound = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    // std refuses a zero timeout itself, with no system call.
    let zero = sound.set_read_timeout(Some(Duration::ZERO)).unwrap_err();
    for refused in [zero, io::Error::from_raw_os_error(EACCES)] {
        assert_eq!(
            sampler::refused_timeout(&reset_after_the_hello(), &refused),
            format!("socket: {refused}")
        );
    }
    let invalid = io::Error::from_raw_os_error(EINVAL);
    assert_eq!(
        sampler::refused_timeout(&sound, &invalid),
        format!("socket: {invalid}")
    );
}
