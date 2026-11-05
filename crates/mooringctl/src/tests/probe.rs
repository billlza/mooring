// SPDX-License-Identifier: GPL-3.0-or-later

//! The probe's read of the reflector's line within what is left of its
//! time (design §10.2): none left is a time-out before any read, and a
//! reflector that stays silent is a read that fails at its limit. The
//! probes' answers otherwise are the runtime tests'.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mooring_daemon_core::status::ProbeStage;

use crate::runtime::probe::{ProbeFailure, read_address};

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
