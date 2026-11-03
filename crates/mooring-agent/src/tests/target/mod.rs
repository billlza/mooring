// SPDX-License-Identifier: GPL-3.0-or-later

//! `TargetCheck` (design §11.7) against the stand-in node of [`world`],
//! whose tools print what the pinned ones print. The check installs the
//! Xray it names from the blob store (an intact copy is kept, a damaged
//! one replaced), probes the address the name resolves to, and samples
//! the handshake only once one completed; a name without an address is
//! reported without probing. A missing Xray, an engine store that cannot
//! be made (both before any tool runs) and a sampler that cannot reach
//! the target fail the check. Only the ops role is served it. The probes,
//! the sampler and the hourly check have files of their own.

mod hourly;
mod probes;
mod sampler;
mod world;

use std::collections::BTreeSet;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use mooring_agent_proto::{
    AgentError, BlobLen, HttpProbe, HttpStatus, HttpVersion, IoOp, Sha256Hex, StderrTail,
    TargetFacts, TargetTool, TlsGroup, TlsProbe, TlsVersion,
};

use super::{EEXIST, FakeNode, exited, scratch};
use crate::blobs::{digest_of, put};
use crate::paths::Paths;
use crate::txn::stage::{XRAY, store_path};
use world::{PING_TLS13, Server, flight, host, node_answering, serve, tls13};

/// Stores `bytes` as a blob and returns its digest.
fn stored(paths: &Paths, bytes: &[u8]) -> Sha256Hex {
    let sha = digest_of(bytes).unwrap();
    put(
        paths,
        sha,
        BlobLen::new(u64::try_from(bytes.len()).unwrap()).unwrap(),
        &mut Cursor::new(bytes.to_vec()),
    )
    .unwrap();
    sha
}

/// A node for a whole check: the name resolves to `resolved`, the Xray
/// answers `ping`, and curl gets an HTTP/2 200.
fn check_node(resolved: &'static [u8], ping: &'static str) -> FakeNode {
    node_answering(move |program, args| match program {
        "/usr/bin/getent" => {
            if resolved.is_empty() {
                exited(2, b"", b"")
            } else {
                exited(0, resolved, b"")
            }
        }
        "/usr/bin/curl" => exited(0, b"200 2 ", b""),
        xray => {
            assert!(xray.ends_with("/xray"), "{xray}");
            assert_eq!(&args[..3], ["tls", "ping", "-ip"]);
            exited(0, ping.as_bytes(), b"")
        }
    })
}

/// A port on 127.0.0.1 that nothing listens on, nor can: binding port 0
/// takes another, so a connection to it always fails (refused on Linux, an
/// address the system cannot assign on macOS), and no test running beside
/// this one can take it, as it could a port freed for the purpose.
const fn closed_port() -> u16 {
    0
}

#[test]
fn a_whole_check_installs_the_xray_and_measures_the_target() {
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let whole = flight(2000);
    let address = serve(
        Server::Flight(
            whole[..50].to_vec(),
            Duration::from_millis(1),
            whole[50..].to_vec(),
        ),
        usize::from(mooring_agent_proto::TARGET_HANDSHAKE_SAMPLES),
    );
    let node = check_node(b"127.0.0.1       STREAM www.example.com\n", PING_TLS13);
    let facts = crate::target::check_at(&paths, &node, host(), xray, address.port()).unwrap();
    let TlsProbe::Completed(session) = &facts.tls else {
        panic!("{facts:?}");
    };
    assert_eq!(
        usize::try_from(session.first_flight_bytes).unwrap(),
        whole.len()
    );
    assert!(session.handshake_p95_micros >= 1_000);
    assert_eq!(
        (
            session.version,
            session.group,
            session.chain_bytes,
            session.chain_certs
        ),
        (TlsVersion::Tls13, Some(TlsGroup::X25519_MLKEM768), 4431, 3)
    );
    assert_eq!(session.leaf_names, tls13().leaf_names);
    assert_eq!(facts.resolved, BTreeSet::from([Ipv4Addr::LOCALHOST]));
    assert_eq!(
        facts.http,
        HttpProbe::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
            redirect: None,
        }
    );
    // The Xray went into the engine store, runnable.
    let installed = store_path(&paths, XRAY, &xray);
    assert_eq!(std::fs::read(&installed).unwrap(), b"#!xray");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    let calls = node.calls();
    assert!(
        calls[1].ends_with(&format!(
            "{} tls ping -ip 127.0.0.1 www.example.com",
            installed.display()
        )),
        "{calls:#?}"
    );
}

#[test]
fn a_name_without_an_address_is_reported_without_probing() {
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let node = check_node(b"", PING_TLS13);
    assert_eq!(
        crate::target::check(&paths, &node, host(), xray),
        Ok(TargetFacts {
            host: host(),
            resolved: BTreeSet::new(),
            tls: TlsProbe::ConnectFailed,
            http: HttpProbe::Failed,
        })
    );
    assert_eq!(node.calls().len(), 1, "only the resolver ran");
}

#[test]
fn a_check_needs_its_xray_stored() {
    let (_dir, paths) = scratch();
    let missing = Sha256Hex::from_bytes([3; 32]);
    let node = check_node(b"", PING_TLS13);
    assert_eq!(
        crate::target::check(&paths, &node, host(), missing),
        Err(AgentError::BlobMissing { sha256: missing })
    );
    assert!(node.calls().is_empty());
}

#[test]
fn target_check_is_served_to_ops_alone() {
    use super::serve::{ask, frame};
    use mooring_agent_proto::{LineRequest, RequestKind, Response, Role};
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let node = check_node(b"", PING_TLS13);
    let request = LineRequest::TargetCheck { host: host(), xray };
    assert_eq!(
        ask(&paths, &node, Role::Ops, frame(&request)),
        Ok(Response::TargetFacts(Box::new(TargetFacts {
            host: host(),
            resolved: BTreeSet::new(),
            tls: TlsProbe::ConnectFailed,
            http: HttpProbe::Failed,
        })))
    );
    assert_eq!(
        ask(&paths, &node, Role::Viewer, frame(&request)),
        Err(AgentError::RoleNotPermitted {
            role: Role::Viewer,
            request: RequestKind::TargetCheck,
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
