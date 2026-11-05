// SPDX-License-Identifier: GPL-3.0-or-later

//! Every kind of management SSH session runs `/usr/bin/ssh` over the
//! connection this process opened (design §10.5): a remote command, the
//! empty request that checks a forced command, and a blob upload, besides
//! the agent requests the node tests run. Here a node on loopback answers
//! ssh's identification with a protocol ssh refuses, so each session ends
//! as ssh's own failure; a session with a deadline that ends before it is
//! not ended by it.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mooring_agent_proto::Sha256Hex;

use super::node::{links, private_dir, script, session_target, within};
use crate::node::dial::M7Egress;
use crate::node::{NodeError, NodeLinks};

/// ssh's failure when the node speaks a protocol it refuses.
fn refused_by_ssh(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::Ssh {
            code: Some(255),
            ..
        }
    )
}

#[test]
fn every_kind_of_session_runs_ssh_and_one_that_ends_early_beats_its_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    script(
        &helper,
        "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nexec /usr/bin/nc -U \"$2\"\n",
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let node = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"SSH-1.5-node\r\n").unwrap();
        }
    });
    let links = links(move |_: &M7Egress, _: SocketAddrV4, _: Duration| {
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(NodeError::Connect)
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let target = session_target(dir.path(), &relay_dir, &helper, Some(deadline));
    let (ran, empty, uploaded, took) = within(Duration::from_secs(60), move || {
        let started = Instant::now();
        let mut session = links.open(target);
        let ran = session.run(b"the agent's bytes");
        let empty = session.empty_request();
        let uploaded = session.put_blob(Sha256Hex::from_bytes([7; 32]), b"a blob");
        (ran, empty, uploaded, started.elapsed())
    });
    node.join().unwrap();
    for (what, error) in [
        ("run", ran.unwrap_err()),
        ("empty request", empty.unwrap_err()),
        ("blob upload", uploaded.unwrap_err()),
    ] {
        assert!(refused_by_ssh(&error), "{what}: {error:?}");
    }
    assert!(took < Duration::from_secs(25), "{took:?}");
    assert_eq!(std::fs::read_dir(&relay_dir).unwrap().count(), 0);
}
