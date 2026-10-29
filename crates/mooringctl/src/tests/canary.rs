// SPDX-License-Identifier: GPL-3.0-or-later

//! The leak canary (design §10.4, §16 T-bind-mac): every outbound
//! connection class the Mac opens itself binds its socket to an interface
//! (`IP_BOUND_IF`) before it connects, so a network the Mac is joined to
//! beside the M7, even one holding the default route, carries none of them.
//! A listener on the loopback counts the connections it accepts; each
//! class, bound to `en0` (the Mac's first built-in interface, present on
//! every Mac), fails at the connect and the count stays at zero; bound to
//! `lo0` each connects, the positive control that the listener and the
//! classes work. The engines' sockets are bound by their rendered configs
//! (`mooring-render`'s goldens); this covers the Rust primitives.

use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use mooring_daemon_core::status::ProbeStage;
use mooring_model::iface::InterfaceIndex;

use super::support::{TEST_TIMEOUTS, lo0};
use crate::node::NodeError;
use crate::node::dial::{M7Egress, connect};
use crate::router::error::{RouterError, UnreachableCause};
use crate::router::http::{Client, Endpoint};
use crate::runtime::probe::{ProbeFailure, direct};

/// A listener on the loopback that counts the connections it accepts and
/// answers each with a reflector line.
fn canary() -> (SocketAddrV4, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(b"198.51.100.17\n");
        }
    });
    (SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), accepted)
}

#[test]
fn no_connection_class_reaches_the_canary_through_another_interface() {
    let (target, accepted) = canary();
    let en0 = InterfaceIndex::from(mooring_macsys::interface_index("en0").unwrap());
    // The direct probe.
    assert_eq!(
        direct(en0, target),
        Err(ProbeFailure {
            stage: ProbeStage::Connect,
            kind: Some(ErrorKind::AddrNotAvailable),
        })
    );
    // The management dial (ssh's ProxyCommand, node adopt, the status
    // polls).
    match connect(&M7Egress::for_tests(en0), target, Duration::from_secs(5)) {
        Err(NodeError::Connect(error)) => assert_eq!(error.kind(), ErrorKind::AddrNotAvailable),
        other => panic!("{other:?}"),
    }
    // The M7's HTTP client.
    assert_eq!(
        Client::new(
            Endpoint {
                addr: target,
                interface: en0,
            },
            TEST_TIMEOUTS
        )
        .model_json()
        .map(|_| ()),
        Err(RouterError::unreachable(UnreachableCause::Connect {
            kind: ErrorKind::AddrNotAvailable
        }))
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "a connection leaked");
    // The positive control: bound to the loopback, each class reaches the
    // canary.
    assert_eq!(direct(lo0(), target), Ok(Ipv4Addr::new(198, 51, 100, 17)));
    drop(connect(&M7Egress::for_tests(lo0()), target, Duration::from_secs(5)).unwrap());
    // The canary answers no HTTP, so the client fails after connecting.
    assert!(
        Client::new(
            Endpoint {
                addr: target,
                interface: lo0(),
            },
            TEST_TIMEOUTS
        )
        .model_json()
        .is_err()
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}
