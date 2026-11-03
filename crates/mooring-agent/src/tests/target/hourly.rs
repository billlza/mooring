// SPDX-License-Identifier: GPL-3.0-or-later

//! The hourly target check (design §11.3) on a node configured for one
//! target: it passes a target that still answers at the configured
//! address through the current generation's Xray, and degrades one that
//! moved, failed the handshake, did not answer over HTTP/2 or could not
//! be resolved; its reading is the state group's to read.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use mooring_agent_proto::{Generation, UnixTime, WatchConfig, WatchTarget};

use super::world::{PING_TLS13, host, node_answering};
use crate::paths::Paths;
use crate::store::{read_json, write_json};
use crate::target::hourly::TargetReading;
use crate::tests::{exited, scratch};

/// A node with generation 1 installed, configured for `www.example.com` at
/// 198.51.100.7.
fn configured() -> (tempfile::TempDir, Paths) {
    let (dir, paths) = scratch();
    let generation = paths.generation(Generation::new(1));
    std::fs::create_dir_all(&generation).unwrap();
    write_json(
        &generation.join("watch.json"),
        &WatchConfig {
            keepalive_secs: NonZeroU16::new(10).unwrap(),
            target: target(),
            emails: BTreeSet::new(),
        },
        0o640,
    )
    .unwrap();
    std::os::unix::fs::symlink("gen-1", paths.current()).unwrap();
    (dir, paths)
}

fn target() -> WatchTarget {
    WatchTarget {
        host: host(),
        ipv4: Ipv4Addr::new(198, 51, 100, 7),
    }
}

/// The hourly check with the name resolving to `resolved`, the ping
/// printing `ping` and curl printing `curl`; returns its reading and the
/// tools it ran.
fn hourly(resolved: &'static [u8], ping: &'static str, curl: &'static [u8]) -> (bool, Vec<String>) {
    let (_dir, paths) = configured();
    let node = node_answering(move |program, _| match program {
        "/usr/bin/getent" => exited(0, resolved, b""),
        "/usr/bin/curl" => exited(0, curl, b""),
        _ => exited(0, ping.as_bytes(), b""),
    });
    let reading = crate::target::hourly::watch(&paths, &node).unwrap();
    assert_eq!(
        read_json(&paths.target_reading()).unwrap(),
        Some(reading.clone())
    );
    assert_eq!(reading.target, target());
    assert_eq!(reading.at, UnixTime::from_secs(1000));
    (reading.degraded, node.calls())
}

const AT_TARGET: &[u8] = b"198.51.100.7    STREAM www.example.com\n";

#[test]
fn the_hourly_check_passes_a_target_that_still_answers() {
    let (degraded, calls) = hourly(AT_TARGET, PING_TLS13, b"200 2 ");
    assert!(!degraded);
    assert!(
        calls[1].contains(
            "/etc/mooring/current/engines/xray tls ping -ip 198.51.100.7 www.example.com"
        ),
        "{calls:#?}"
    );
}

#[test]
fn the_hourly_check_degrades_a_target_that_moved_or_stopped_answering() {
    let (moved, calls) = hourly(
        b"198.51.100.8    STREAM www.example.com\n",
        PING_TLS13,
        b"200 2 ",
    );
    assert!(moved);
    assert_eq!(calls.len(), 1, "nothing is probed at another address");
    let failed_handshake = "Pinging with SNI\nHandshake failure:  EOF\n";
    assert!(hourly(AT_TARGET, failed_handshake, b"200 2 ").0);
    assert!(hourly(AT_TARGET, PING_TLS13, b"200 1.1 ").0, "not HTTP/2");
    assert!(hourly(AT_TARGET, PING_TLS13, b"000 0 ").0, "no answer");
}

#[test]
fn the_hourly_check_degrades_a_target_it_cannot_resolve() {
    let (_dir, paths) = configured();
    let node = node_answering(|_, _| exited(124, b"", b""));
    assert!(
        crate::target::hourly::watch(&paths, &node)
            .unwrap()
            .degraded
    );
    assert_eq!(node.calls().len(), 1);
}

#[test]
fn a_reading_is_the_state_groups_to_read() {
    let (_dir, paths) = configured();
    let node = node_answering(|_, _| exited(124, b"", b""));
    crate::target::hourly::watch(&paths, &node).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(paths.target_reading())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    let _: TargetReading = read_json(&paths.target_reading()).unwrap().unwrap();
}
