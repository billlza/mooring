// SPDX-License-Identifier: GPL-3.0-or-later

//! The reflector on loopback: the peer's address and a newline, then
//! close; and its loop, driven by a scripted `accept`, deciding what each
//! failure and each connection gets.

use std::cell::Cell;
use std::io::{self, ErrorKind, Read};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::thread;
use std::time::{Duration, Instant};

use crate::reflect::{
    Accepting, MAX_CONNECTIONS, PAUSE, Slots, after, line, pause, serve, serve_with,
};

#[test]
fn the_line_is_the_address_and_a_newline() {
    assert_eq!(
        line(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 97), 5)),
        "198.51.100.97\n"
    );
    assert_eq!(MAX_CONNECTIONS, 16);
}

#[test]
fn the_reflector_answers_each_connection_with_its_source() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener));
    for _ in 0..3 {
        let mut stream = TcpStream::connect(address).unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert_eq!(answer, "127.0.0.1\n");
    }
}

/// Linux's numbers, as the reflector names them.
const LINUX: [(i32, Accepting); 12] = [
    (12, Accepting::Pause),  // ENOMEM
    (23, Accepting::Pause),  // ENFILE
    (24, Accepting::Pause),  // EMFILE
    (105, Accepting::Pause), // ENOBUFS
    (64, Accepting::Retry),  // ENONET
    (71, Accepting::Retry),  // EPROTO
    (92, Accepting::Retry),  // ENOPROTOOPT
    (95, Accepting::Retry),  // EOPNOTSUPP
    (100, Accepting::Retry), // ENETDOWN
    (101, Accepting::Retry), // ENETUNREACH
    (112, Accepting::Retry), // EHOSTDOWN
    (113, Accepting::Retry), // EHOSTUNREACH
];

#[test]
fn accept_failures_are_waited_out_retried_or_the_end() {
    for (errno, expected) in LINUX {
        assert_eq!(
            after(&io::Error::from_raw_os_error(errno)),
            expected,
            "{errno}"
        );
    }
    for kind in [
        ErrorKind::ConnectionAborted,
        ErrorKind::ConnectionReset,
        ErrorKind::Interrupted,
    ] {
        assert_eq!(after(&io::Error::from(kind)), Accepting::Retry, "{kind:?}");
    }
    // EBADF and EINVAL: the listener itself is broken.
    for errno in [9, 22] {
        assert_eq!(
            after(&io::Error::from_raw_os_error(errno)),
            Accepting::Stop,
            "{errno}"
        );
    }
    assert_eq!(
        after(&io::Error::from(ErrorKind::PermissionDenied)),
        Accepting::Stop
    );
}

#[test]
fn slots_are_at_most_the_limit_and_free_themselves() {
    let slots = Slots::new(2);
    let first = slots.take().unwrap();
    let second = slots.take().unwrap();
    assert!(slots.take().is_none());
    assert_eq!(slots.taken(), 2);
    drop(first);
    assert_eq!(slots.taken(), 1);
    let third = slots.take().unwrap();
    assert!(slots.take().is_none());
    drop((second, third));
    assert_eq!(slots.taken(), 0);
}

/// Waits until every slot is free: every worker has finished, so that
/// nothing of the test runs after it returns.
fn until_idle(slots: &Slots) {
    let started = Instant::now();
    while slots.taken() > 0 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a worker never ended"
        );
        thread::yield_now();
    }
}

fn read_all(mut stream: TcpStream) -> String {
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer
}

/// The loop, with `accept` scripted: a moment out of files is waited out
/// once, a connection's own failure is skipped, a peer is answered, a peer
/// that is not IPv4 is closed unanswered, and the listener's failure ends
/// it and is returned.
#[test]
fn the_loop_waits_retries_answers_and_ends_as_accept_says() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let answered = TcpStream::connect(address).unwrap();
    let unanswered = TcpStream::connect(address).unwrap();
    let slots = Slots::new(MAX_CONNECTIONS);
    let calls = Cell::new(0);
    let paused = Cell::new(0);
    let ended = serve_with(
        &mut || {
            calls.set(calls.get() + 1);
            match calls.get() {
                1 => Err(io::Error::from_raw_os_error(24)),
                2 => Err(io::Error::from(ErrorKind::ConnectionAborted)),
                3 => listener.accept(),
                4 => listener.accept().map(|(stream, _)| {
                    let v6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5, 0, 0);
                    (stream, SocketAddr::V6(v6))
                }),
                _ => Err(io::Error::from_raw_os_error(9)),
            }
        },
        &slots,
        &mut || paused.set(paused.get() + 1),
    );
    assert_eq!(ended.raw_os_error(), Some(9));
    assert_eq!((calls.get(), paused.get()), (5, 1));
    assert_eq!(read_all(answered), "127.0.0.1\n");
    assert_eq!(read_all(unanswered), "");
    until_idle(&slots);
}

/// With every slot taken, a connection is closed unanswered and no worker
/// is started for it.
#[test]
fn a_connection_over_the_limit_is_closed_unanswered() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let slots = Slots::new(1);
    let held = slots.take().unwrap();
    let calls = Cell::new(0);
    let ended = serve_with(
        &mut || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                listener.accept()
            } else {
                Err(io::Error::from(ErrorKind::PermissionDenied))
            }
        },
        &slots,
        &mut || panic!("nothing to wait out"),
    );
    assert_eq!(ended.kind(), ErrorKind::PermissionDenied);
    assert_eq!(read_all(client), "");
    assert_eq!(slots.taken(), 1, "only the test's own slot");
    drop(held);
}

#[test]
fn the_pause_waits_its_100_ms() {
    let started = Instant::now();
    pause();
    assert!(started.elapsed() >= PAUSE);
    assert_eq!(PAUSE, Duration::from_millis(100));
}
