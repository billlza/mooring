// SPDX-License-Identifier: GPL-3.0-or-later

//! The protocol: every message round-trips, and every departure from its
//! form is refused with its own error.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::wire::{
    DATAGRAM_LEN, Delay, EchoAnswer, EchoKind, EchoRequest, MAX_SINK_SECONDS, SinkReport,
    WireError, parse_reflector_line, parse_sink_line, reflector_line, sink_line,
};

const NONCE: [u8; 16] = [7; 16];

fn delay(millis: u64) -> Delay {
    Delay::new(Duration::from_millis(millis)).unwrap()
}

#[test]
fn requests_round_trip_in_32_bytes() {
    for kind in [
        EchoKind::Now,
        EchoKind::FromOtherPort,
        EchoKind::Delayed(delay(90_000)),
    ] {
        let request = EchoRequest { kind, nonce: NONCE };
        let bytes = request.encode();
        assert_eq!(bytes.len(), DATAGRAM_LEN);
        assert_eq!(&bytes[..4], b"MFK1");
        assert_eq!(EchoRequest::decode(&bytes), Ok(request), "{kind:?}");
    }
}

#[test]
fn answers_round_trip_and_are_no_larger_than_requests() {
    let observed = SocketAddrV4::new(Ipv4Addr::new(92, 40, 1, 2), 30785);
    for kind in [
        EchoKind::Now,
        EchoKind::FromOtherPort,
        EchoKind::Delayed(delay(1)),
    ] {
        let request = EchoRequest { kind, nonce: NONCE };
        let answer = EchoAnswer::to(&request, observed, 27951);
        let bytes = answer.encode();
        assert_eq!(bytes.len(), request.encode().len());
        assert_eq!(EchoAnswer::decode(&bytes), Ok(answer));
        assert_eq!(answer.observed, observed);
        assert_eq!(answer.server_port, 27951);
        assert_eq!(answer.nonce, NONCE);
    }
}

#[test]
fn delays_are_one_millisecond_to_ten_minutes() {
    assert_eq!(Delay::new(Duration::ZERO), Err(WireError::Delay));
    assert_eq!(
        Delay::new(Duration::from_micros(999)),
        Err(WireError::Delay)
    );
    assert_eq!(delay(1).duration(), Duration::from_millis(1));
    assert_eq!(delay(600_000).duration(), Duration::from_secs(600));
    assert_eq!(
        Delay::new(Duration::from_millis(600_001)),
        Err(WireError::Delay)
    );
    assert_eq!(
        Delay::new(Duration::from_secs(u64::MAX)),
        Err(WireError::Delay)
    );
}

#[test]
fn the_midpoint_lies_between_and_never_overflows() {
    assert_eq!(delay(10_000).midpoint(delay(300_000)), delay(155_000));
    assert_eq!(delay(1).midpoint(delay(2)), delay(1));
    assert_eq!(delay(3).midpoint(delay(5)), delay(4));
    assert_eq!(delay(599_999).midpoint(delay(600_000)), delay(599_999));
    assert_eq!(delay(600_000).midpoint(delay(600_000)), delay(600_000));
}

fn request_bytes(kind: u8, millis: u32) -> [u8; DATAGRAM_LEN] {
    let mut bytes = EchoRequest {
        kind: EchoKind::Now,
        nonce: NONCE,
    }
    .encode();
    bytes[4] = kind;
    bytes[24..28].copy_from_slice(&millis.to_be_bytes());
    bytes
}

#[test]
fn requests_out_of_form_are_refused() {
    let good = request_bytes(1, 0);
    let mut magic = good;
    magic[0] = b'X';
    let mut answer = good;
    answer[5] = 1;
    let mut reserved = good;
    reserved[6] = 1;
    let mut tail = good;
    tail[31] = 1;
    let cases: [(&str, &[u8], WireError); 10] = [
        ("short", &good[..31], WireError::Length { len: 31 }),
        (
            "long",
            &[good.as_slice(), &[0]].concat(),
            WireError::Length { len: 33 },
        ),
        ("magic", &magic, WireError::Magic),
        ("an answer", &answer, WireError::Direction),
        ("kind 0", &request_bytes(0, 0), WireError::Kind { code: 0 }),
        ("kind 4", &request_bytes(4, 0), WireError::Kind { code: 4 }),
        ("a delay on Now", &request_bytes(1, 5), WireError::Delay),
        ("a delay of 0", &request_bytes(2, 0), WireError::Delay),
        (
            "a delay over ten minutes",
            &request_bytes(2, 600_001),
            WireError::Delay,
        ),
        ("reserved bytes", &reserved, WireError::Reserved),
    ];
    for (case, bytes, error) in cases {
        assert_eq!(EchoRequest::decode(bytes), Err(error), "{case}");
    }
    assert_eq!(EchoRequest::decode(&tail), Err(WireError::Reserved));
    assert_eq!(
        EchoRequest::decode(&request_bytes(3, 9)),
        Err(WireError::Delay)
    );
}

#[test]
fn answers_out_of_form_are_refused() {
    let request = EchoRequest {
        kind: EchoKind::Now,
        nonce: NONCE,
    };
    let good = EchoAnswer::to(&request, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1), 2).encode();
    let mut kind = good;
    kind[4] = 9;
    let mut tail = good;
    tail[30] = 1;
    assert_eq!(
        EchoAnswer::decode(&request.encode()),
        Err(WireError::Direction)
    );
    assert_eq!(EchoAnswer::decode(&kind), Err(WireError::Kind { code: 9 }));
    assert_eq!(EchoAnswer::decode(&tail), Err(WireError::Reserved));
    assert_eq!(
        EchoAnswer::decode(&good[..8]),
        Err(WireError::Length { len: 8 })
    );
}

#[test]
fn the_reflector_line_carries_the_source() {
    let source = SocketAddrV4::new(Ipv4Addr::new(92, 40, 201, 97), 15203);
    let line = reflector_line(source);
    assert_eq!(line, "MFK1 92.40.201.97:15203\n");
    assert_eq!(parse_reflector_line(line.as_bytes()), Ok(source));
    for bad in [
        "MFK1 92.40.201.97:15203",
        "MFK2 92.40.201.97:15203\n",
        "MFK1 92.40.201.97\n",
        "MFK1 [::1]:1\n",
        "MFK1 92.40.201.97:15203 \n",
    ] {
        assert_eq!(
            parse_reflector_line(bad.as_bytes()),
            Err(WireError::Line),
            "{bad:?}"
        );
    }
    assert_eq!(parse_reflector_line(&[0xff, b'\n']), Err(WireError::Line));
}

#[test]
fn the_sink_line_asks_for_1_to_120_seconds() {
    assert_eq!(sink_line(20), "MFK1 SINK 20\n");
    assert_eq!(parse_sink_line(b"MFK1 SINK 20\n"), Ok(20));
    assert_eq!(parse_sink_line(b"MFK1 SINK 1\n"), Ok(1));
    assert_eq!(
        parse_sink_line(sink_line(MAX_SINK_SECONDS).as_bytes()),
        Ok(MAX_SINK_SECONDS)
    );
    for bad in [
        "MFK1 SINK 0\n",
        "MFK1 SINK 121\n",
        "MFK1 SINK +5\n",
        "MFK1 SINK 5",
        "MFK1 SINK \n",
        "MFK1 SINK 99999999999\n",
        "MFK1 SOAK 5\n",
    ] {
        assert_eq!(
            parse_sink_line(bad.as_bytes()),
            Err(WireError::Line),
            "{bad:?}"
        );
    }
}

#[test]
fn a_sink_report_has_one_count_per_second() {
    let report = SinkReport {
        bytes_per_second: vec![1, 2, 3],
    };
    let line = serde_json::to_vec(&report).unwrap();
    assert_eq!(SinkReport::parse(&line, 3), Ok(report));
    assert_eq!(SinkReport::parse(&line, 2), Err(WireError::Line));
    assert_eq!(
        SinkReport::parse(br#"{"bytes_per_second":[1],"extra":1}"#, 1),
        Err(WireError::Line)
    );
    assert_eq!(SinkReport::parse(b"not json", 1), Err(WireError::Line));
}

#[test]
fn wire_errors_say_what_is_wrong() {
    for (error, text) in [
        (
            WireError::Length { len: 3 },
            "the datagram is 3 bytes long, not 32",
        ),
        (WireError::Magic, "the message does not start with MFK1"),
        (WireError::Direction, "the datagram goes the wrong way"),
        (
            WireError::Kind { code: 7 },
            "the datagram's kind 7 is unknown",
        ),
        (
            WireError::Delay,
            "the datagram's delay is not one its kind allows",
        ),
        (
            WireError::Reserved,
            "the datagram's reserved bytes are not zero",
        ),
        (WireError::Line, "the line is not of its form"),
    ] {
        assert_eq!(error.to_string(), text);
    }
}
