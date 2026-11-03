// SPDX-License-Identifier: GPL-3.0-or-later

//! The reflector on loopback: the peer's address and a newline, then
//! close; and its loop, driven by a scripted `accept`, deciding what each
//! failure and each connection gets, with at most 16 answered at once.

use std::cell::Cell;
use std::io::{self, ErrorKind, Read};
use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::thread;
use std::time::{Duration, Instant};

use crate::reflect::{
    Accepting, MAX_CONNECTIONS, PAUSE, Slots, after, answer, line, pause, serve, serve_with,
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

/// How long a test waits on a worker or a peer before it fails, so that a
/// broken loop fails the test rather than hanging it.
const PATIENCE: Duration = Duration::from_secs(10);

/// Waits until at most `taken` slots are taken: the workers that held the
/// others have ended.
fn until_taken(slots: &Slots, taken: usize) {
    let started = Instant::now();
    while slots.taken() > taken {
        assert!(started.elapsed() < PATIENCE, "a worker never ended");
        thread::yield_now();
    }
}

/// Waits until every slot is free: every worker has finished, so that
/// nothing of the test runs after it returns.
fn until_idle(slots: &Slots) {
    until_taken(slots, 0);
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
        answer,
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
        answer,
        &mut || panic!("nothing to wait out"),
    );
    assert_eq!(ended.kind(), ErrorKind::PermissionDenied);
    assert_eq!(read_all(client), "");
    assert_eq!(slots.taken(), 1, "only the test's own slot");
    drop(held);
}

/// The answer, held until the peer has closed its side: the test decides
/// when each connection ends, which the real answer, written at once into
/// an empty buffer, does not let it. Held past the test's patience, it
/// answers all the same, so that a broken loop fails the test on what it
/// then sees rather than hanging it.
fn held(mut stream: TcpStream, peer: SocketAddrV4) {
    let mut sent = Vec::new();
    let _closed = stream
        .set_read_timeout(Some(PATIENCE))
        .and_then(|()| stream.read_to_end(&mut sent));
    answer(stream, peer);
}

/// A peer of the reflector at `address`, which waits for an answer only
/// as long as the test's patience. (Set at once: macOS refuses socket
/// options on a socket shut down both ways.)
fn peer_of(address: SocketAddr) -> TcpStream {
    let client = TcpStream::connect(address).unwrap();
    client.set_read_timeout(Some(PATIENCE)).unwrap();
    client
}

/// The peer's side closed, and the answer it then gets.
fn released(client: TcpStream) -> String {
    client.shutdown(Shutdown::Write).unwrap();
    read_all(client)
}

/// The cap as the design states it (§11.4): at most 16 connections are
/// answered at once. With 16 answers held, a 17th connection is closed
/// unanswered; once one answer has ended, the next connection takes its
/// slot, and every connection held is answered when its peer lets it.
#[test]
fn at_most_16_connections_are_answered_at_once() {
    assert_eq!(MAX_CONNECTIONS, 16);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let slots = Slots::new(MAX_CONNECTIONS);
    let mut clients = Vec::new();
    let mut accepted = 0;
    let ended = serve_with(
        &mut || {
            accepted += 1;
            if accepted <= MAX_CONNECTIONS + 2 {
                // Each answer held keeps its slot, and the 17th took none.
                assert_eq!(slots.taken(), (accepted - 1).min(MAX_CONNECTIONS));
            }
            if accepted == MAX_CONNECTIONS + 2 {
                // The first answer ends, and frees its slot.
                assert_eq!(released(clients.remove(0)), "127.0.0.1\n");
                until_taken(&slots, MAX_CONNECTIONS - 1);
            }
            if accepted > MAX_CONNECTIONS + 2 {
                return Err(io::Error::from_raw_os_error(9));
            }
            clients.push(peer_of(address));
            listener.accept()
        },
        &slots,
        held,
        &mut || panic!("nothing to wait out"),
    );
    assert_eq!(ended.raw_os_error(), Some(9));
    assert_eq!(accepted, MAX_CONNECTIONS + 3);
    assert_eq!(slots.taken(), MAX_CONNECTIONS, "15 held, and the next one");
    // Released like the others, so that one answered by mistake shows.
    let over = clients.remove(MAX_CONNECTIONS - 1);
    assert_eq!(released(over), "", "the 17th, over the cap");
    assert_eq!(clients.len(), MAX_CONNECTIONS);
    for client in clients {
        assert_eq!(released(client), "127.0.0.1\n");
    }
    until_idle(&slots);
}

#[test]
fn the_pause_waits_its_100_ms() {
    let started = Instant::now();
    pause();
    assert!(started.elapsed() >= PAUSE);
    assert_eq!(PAUSE, Duration::from_millis(100));
}
