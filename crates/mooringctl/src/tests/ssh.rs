// SPDX-License-Identifier: GPL-3.0-or-later

//! Every kind of management SSH session runs `/usr/bin/ssh` over the
//! connection this process opened (design §10.5): a remote command, the
//! empty request that checks a forced command, and a blob upload, besides
//! the agent requests the node tests run. Here a node on loopback answers
//! ssh's identification with a protocol ssh refuses, so each session ends
//! as ssh's own failure; a session with a deadline that ends before it is
//! not ended by it. A connection the node resets under a session is the
//! relay's failure, which the session names after what ssh printed; a
//! relay socket that fails itself is the session's failure, before ssh's.

use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use mooring_agent_proto::{LineRequest, Sha256Hex};

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

/// How long the test waits for the loopback to deliver what it waits for.
const PATIENCE: Duration = Duration::from_secs(10);

/// A connection the node resets under a session is the relay's failure,
/// and ssh cannot say so: it sees only its ProxyCommand end. The session
/// appends how the relay's splice ended to what ssh printed.
///
/// The node resets the connection once ssh's identification has arrived,
/// having sent none of its own, so ssh waits. The ProxyCommand ends only
/// when the reset has reached this process's end of the connection, which
/// the test watches on another handle of it: the splice has failed before
/// ssh can end, whatever the scheduler does, and nothing the session does
/// after ssh has ended can turn that failure into a clean end.
#[test]
fn a_connection_the_node_reset_is_named_after_what_ssh_printed() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let helper = dir.path().join("mooringctl");
    let arrived = dir.path().join("reset-arrived");
    // nc relays as in the other tests, until the reset has arrived. It
    // runs in the background, where a shell gives a command no standard
    // input unless it is handed one that is not the shell's own: ssh's is
    // handed on as descriptor 3.
    script(
        &helper,
        &format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nexec 3<&0\n/usr/bin/nc -U \"$2\" <&3 3<&- &\nrelay=$!\nuntil [ -e '{}' ]; do /bin/sleep 0.01; done\nkill \"$relay\"\nwait \"$relay\"\nexit 0\n",
            arrived.display()
        ),
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (opened, ours) = mpsc::channel::<TcpStream>();
    let opened = Mutex::new(opened);
    let node = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // ssh's identification is left unread, so that closing the
        // connection resets it.
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        assert_eq!(
            stream.peek(&mut [0; 1]).unwrap(),
            1,
            "ssh's identification never came"
        );
        drop(stream);
        let ours = ours.recv_timeout(PATIENCE).unwrap();
        let started = Instant::now();
        while ours.peer_addr().is_ok() {
            assert!(started.elapsed() < PATIENCE, "the reset never came");
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(ours);
        std::fs::write(arrived, b"").unwrap();
    });
    let links = links(move |_: &M7Egress, _: SocketAddrV4, _: Duration| {
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(NodeError::Connect)?;
        let watched = stream.try_clone().map_err(NodeError::Connect)?;
        opened.lock().unwrap().send(watched).unwrap();
        Ok(stream)
    });
    let target = session_target(dir.path(), &relay_dir, &helper, None);
    let error = within(Duration::from_secs(30), move || {
        links.open(target).request(&LineRequest::Hello)
    })
    .unwrap_err();
    node.join().unwrap();
    let NodeError::Ssh { code, stderr } = error else {
        panic!("{error:?}");
    };
    assert_eq!(code, Some(255));
    // ssh ends every line it prints, and the note opens a line of its own
    // after them: what ssh printed comes first, and the note is there once.
    assert!(
        stderr.ends_with(
            "\n\n(the relay to the node ended with: Connection reset by peer (os error 54))"
        ),
        "{stderr:?}"
    );
    assert!(!stderr.starts_with('\n'), "{stderr:?}");
    assert_eq!(
        stderr.matches("(the relay to the node ended with").count(),
        1
    );
    assert_eq!(std::fs::read_dir(&relay_dir).unwrap().count(), 0);
}

/// Gives a directory its owner's permissions back when the test ends,
/// however it ends, so that the temporary directory around it can be
/// removed. A test that is failing already reports its own failure.
struct Writable(PathBuf);

impl Drop for Writable {
    fn drop(&mut self) {
        let restored = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        if !std::thread::panicking() {
            restored.unwrap();
        }
    }
}

/// The relay socket's own failure is the session's, ahead of ssh's, which
/// only says that its ProxyCommand ended. Here the socket cannot be
/// unlinked once the ProxyCommand has connected: the ProxyCommand's
/// stand-in takes the write permission of the socket's directory away
/// before it connects.
#[test]
fn a_relay_socket_that_cannot_be_unlinked_is_the_session_s_failure() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = private_dir(dir.path());
    let writable = Writable(relay_dir.clone());
    let helper = dir.path().join("mooringctl");
    script(
        &helper,
        &format!(
            "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n/bin/chmod 500 '{}'\nexec /usr/bin/nc -U \"$2\"\n",
            relay_dir.display()
        ),
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (keep, kept) = mpsc::channel::<()>();
    let node = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        // Holds the connection until the test ends.
        let _ = kept.recv();
    });
    let links = links(move |_: &M7Egress, _: SocketAddrV4, _: Duration| {
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).map_err(NodeError::Connect)
    });
    let target = session_target(dir.path(), &relay_dir, &helper, None);
    let error = within(Duration::from_secs(30), move || {
        links.open(target).request(&LineRequest::Hello)
    })
    .unwrap_err();
    drop(keep);
    node.join().unwrap();
    // The directory can be listed, and removed with the test, again.
    drop(writable);
    let NodeError::Relay(source) = error else {
        panic!("{error:?}");
    };
    assert_eq!(source.kind(), ErrorKind::PermissionDenied, "{source}");
    // Nothing could remove the socket: it is the one entry left.
    assert_eq!(std::fs::read_dir(&relay_dir).unwrap().count(), 1);
}
