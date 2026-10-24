// SPDX-License-Identifier: GPL-3.0-or-later

// `mooringctl` relays only on macOS; elsewhere it only says so.
#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a byte may take to cross the relay before the test fails.
const PATIENCE: Duration = Duration::from_secs(5);

/// A running relay, killed if a test leaves it behind.
struct Relay(Child);

impl Relay {
    /// Waits for the relay to exit, at most `limit`.
    fn exited_within(&mut self, limit: Duration) -> Option<ExitStatus> {
        let until = Instant::now() + limit;
        while Instant::now() < until {
            if let Some(status) = self.0.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        None
    }
}

impl Drop for Relay {
    /// A relay that did not end is the test's failure, already reported;
    /// killing it only keeps it from outliving the test.
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `ssh-relay` passes bytes both ways as they arrive, and exits once both
/// directions have ended. The second live adopt of lon1 (2026-10-24) timed
/// out in the key exchange: the relay's sending thread waited for ever for
/// the stdin lock `main` holds, so ssh's bytes never reached the node, and
/// the node's binary packets waited in line-buffered stdout.
#[test]
fn ssh_relay_passes_bytes_both_ways_as_they_arrive_and_ends_with_both() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut relay = Relay(
        Command::new(env!("CARGO_BIN_EXE_mooringctl"))
            .arg("ssh-relay")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (mut node, _) = listener.accept().unwrap();
    node.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut ssh_in = relay.0.stdin.take().unwrap();
    let mut ssh_out = relay.0.stdout.take().unwrap();
    let (passed, arrived) = mpsc::channel();
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 4096];
        while let Ok(read @ 1..) = ssh_out.read(&mut chunk) {
            if passed.send(chunk[..read].to_vec()).is_err() {
                break;
            }
        }
    });

    // The node speaks first: its identification line, then binary.
    let from_node = b"SSH-2.0-node\r\n\x00\x00\x01\x0ckexinit";
    node.write_all(from_node).unwrap();
    let mut seen = Vec::new();
    while seen.len() < from_node.len() {
        let bytes = arrived
            .recv_timeout(PATIENCE)
            .expect("the node's bytes did not reach ssh");
        seen.extend(bytes);
    }
    assert_eq!(seen, from_node);

    // ssh answers, its identification line then binary.
    let from_ssh = b"SSH-2.0-OpenSSH_test\r\n\x00\x00\x02\x1ckexinit";
    ssh_in.write_all(from_ssh).unwrap();
    let mut answer = vec![0_u8; from_ssh.len()];
    node.read_exact(&mut answer)
        .expect("ssh's bytes did not reach the node");
    assert_eq!(answer, from_ssh);

    // The end of ssh's input reaches the node; the node's end then ends
    // the relay.
    drop(ssh_in);
    let mut rest = Vec::new();
    node.read_to_end(&mut rest)
        .expect("the end of ssh's input did not reach the node");
    assert!(rest.is_empty(), "{rest:?}");
    drop(node);
    let status = relay
        .exited_within(PATIENCE)
        .expect("the relay outlived both directions");
    assert!(status.success(), "{status:?}");
}
