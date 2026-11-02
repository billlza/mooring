// SPDX-License-Identifier: GPL-3.0-or-later

//! The target check where it cannot measure: a tool that cannot start or
//! prints what the pinned one never prints, a handshake that does not
//! complete, a sampler that cannot reach the target or has no randomness,
//! and an engine store the Xray cannot be installed in. Each is reported
//! as the error the Mac reads, never as a measurement.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;

use mooring_agent_proto::{
    AgentError, HttpProbe, IoOp, StderrTail, TargetFacts, TargetTool, TlsProbe,
};

use super::{PING_TLS13, Server, check_node, host, node_answering, random, serve, stored};
use crate::target::sampler;
use crate::tests::{EACCES, EEXIST, ENOENT, FakeNode, exited, scratch};
use crate::txn::stage::{XRAY, store_path};

/// A port on 127.0.0.1 that nothing listens on, nor can: binding port 0
/// takes another, so a connection to it always fails (refused on Linux, an
/// address the system cannot assign on macOS), and no test running beside
/// this one can take it, as it could a port freed for the purpose.
const fn closed_port() -> u16 {
    0
}

#[test]
fn a_tool_the_check_cannot_start_is_a_spawn_failure() {
    let unstartable = FakeNode::answering(
        1000,
        Box::new(|_, _| Err(io::Error::from_raw_os_error(ENOENT))),
    );
    let spawn = AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: Some(ENOENT),
    };
    let address = Ipv4Addr::new(198, 51, 100, 7);
    assert_eq!(
        crate::target::resolve(&unstartable, &host()).unwrap_err(),
        spawn
    );
    assert_eq!(
        crate::target::tls_ping(&unstartable, Path::new("/opt/xray"), &host(), address)
            .unwrap_err(),
        spawn
    );
    assert_eq!(
        crate::target::http_probe(&unstartable, &host(), address).unwrap_err(),
        spawn
    );
    for call in unstartable.calls() {
        assert!(
            call.starts_with("/usr/bin/timeout --kill-after=2 10 "),
            "{call}"
        );
    }
}

#[test]
fn a_resolver_that_prints_no_address_is_unavailable() {
    let node = node_answering(|_, _| exited(0, b"www.example.com STREAM\n", b""));
    assert_eq!(
        crate::target::resolve(&node, &host()),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::Resolver,
            stderr_tail: StderrTail::scrubbed(b"www.example.com STREAM\n", &[]),
        })
    );
}

#[test]
fn a_ping_xray_prints_nothing_known_of_is_unavailable_with_both_streams() {
    let node = node_answering(|_, _| {
        exited(
            0,
            b"TLS ping:  www.example.com\n",
            b"panic: runtime error\n",
        )
    });
    assert_eq!(
        crate::target::tls_ping(&node, Path::new("/opt/xray"), &host(), Ipv4Addr::LOCALHOST),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::XrayTlsPing,
            stderr_tail: StderrTail::scrubbed(
                b"TLS ping:  www.example.com\npanic: runtime error\n",
                &[]
            ),
        })
    );
}

#[test]
fn a_handshake_that_does_not_complete_is_reported_without_sampling() {
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    for (ping, tls) in [
        (
            exited(
                1,
                b"",
                b"Failed to dial tcp: dial tcp 127.0.0.1:443: connect: connection refused\n",
            ),
            TlsProbe::ConnectFailed,
        ),
        (
            exited(0, b"Pinging with SNI\nHandshake failure:  EOF\n", b""),
            TlsProbe::HandshakeFailed,
        ),
    ] {
        let node = node_answering(move |program, _| match program {
            "/usr/bin/getent" => exited(0, b"127.0.0.1       STREAM www.example.com\n", b""),
            "/usr/bin/curl" => exited(0, b"000 0 ", b""),
            _ => ping.clone(),
        });
        // A sampler that ran would find nothing listening, and fail.
        assert_eq!(
            crate::target::check_at(&paths, &node, host(), xray, closed_port()),
            Ok(TargetFacts {
                host: host(),
                resolved: BTreeSet::from([Ipv4Addr::LOCALHOST]),
                tls,
                http: HttpProbe::Failed,
            })
        );
        assert_eq!(node.calls().len(), 3, "the resolver, the ping and curl");
    }
}

#[test]
fn a_sampler_that_cannot_reach_the_target_fails_the_check() {
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let port = closed_port();
    let refused = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).unwrap_err();
    let node = check_node(b"127.0.0.1       STREAM www.example.com\n", PING_TLS13);
    assert_eq!(
        crate::target::check_at(&paths, &node, host(), xray, port),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::HandshakeSampler,
            stderr_tail: StderrTail::scrubbed(format!("connect: {refused}").as_bytes(), &[]),
        })
    );
    assert_eq!(node.calls().len(), 2, "curl did not run");
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

#[test]
fn an_intact_xray_in_the_store_is_kept_and_a_damaged_one_replaced() {
    use std::os::unix::fs::MetadataExt;
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let node = check_node(b"", PING_TLS13);
    let installed = store_path(&paths, XRAY, &xray);
    crate::target::check(&paths, &node, host(), xray).unwrap();
    let copied = std::fs::metadata(&installed).unwrap().ino();
    crate::target::check(&paths, &node, host(), xray).unwrap();
    assert_eq!(
        std::fs::metadata(&installed).unwrap().ino(),
        copied,
        "kept, not copied again"
    );
    std::fs::write(&installed, b"#!xrax").unwrap();
    crate::target::check(&paths, &node, host(), xray).unwrap();
    assert_eq!(std::fs::read(&installed).unwrap(), b"#!xray");
}

#[test]
fn an_engine_store_that_cannot_be_made_fails_the_check_before_any_tool() {
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    // A link to nothing where the store belongs.
    std::fs::create_dir_all(paths.engine_store().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(paths.at("/nowhere"), paths.engine_store()).unwrap();
    let node = check_node(b"", PING_TLS13);
    assert_eq!(
        crate::target::check(&paths, &node, host(), xray),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert!(node.calls().is_empty());
}
