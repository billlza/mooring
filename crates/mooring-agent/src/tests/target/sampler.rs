// SPDX-License-Identifier: GPL-3.0-or-later

//! The handshake sampler (design §11.7) against servers on 127.0.0.1:
//! the ClientHello it builds, the ServerHello that starts a flight, a
//! sample timed to the flight's last byte and counting all of it, and the
//! p95 by nearest rank; no sample from a target that refuses the
//! connection, does not answer the hello, closes or resets it; and no
//! connection at all without randomness.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use mooring_agent_proto::{AgentError, StderrTail, TargetTool};

use super::world::{Server, flight, host, serve};
use crate::target::sampler::{self, RANDOM_BYTES};
use crate::tests::EACCES;

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
    let sample = sampler::sample(address, &host(), &random()).unwrap();
    assert_eq!(usize::try_from(sample.bytes).unwrap(), whole.len());
    assert!(sample.micros >= 40_000, "{sample:?}");
    assert!(
        u128::from(sample.micros) < sampler::IDLE.as_micros(),
        "the quiet after the flight is not counted: {sample:?}"
    );
}

#[test]
fn a_target_that_does_not_answer_a_hello_is_no_sample() {
    let silent = serve(Server::Silent, 1);
    assert_eq!(
        sampler::sample(silent, &host(), &random()),
        Err("the target sent nothing back".to_owned())
    );
    let closing = serve(Server::Close, 1);
    assert_eq!(
        sampler::sample(closing, &host(), &random()),
        Err("the target closed without an answer".to_owned())
    );
    let gone = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let refused = sampler::sample(gone, &host(), &random()).unwrap_err();
    assert!(refused.starts_with("connect:"), "{refused}");
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
        sampler::measure(listener.local_addr().unwrap(), &host(), || {
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

#[test]
fn a_target_that_resets_the_connection_is_no_sample() {
    // What a reset reads as on this OS.
    let mut probe = TcpStream::connect(serve(Server::Reset, 1)).unwrap();
    probe
        .write_all(&sampler::client_hello(&host(), &random()))
        .unwrap();
    let reset = probe.read(&mut [0; 16]).unwrap_err();
    assert_eq!(reset.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(
        sampler::sample(serve(Server::Reset, 1), &host(), &random()),
        Err(format!("receive: {reset}"))
    );
}
