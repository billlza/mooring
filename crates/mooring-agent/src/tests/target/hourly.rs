// SPDX-License-Identifier: GPL-3.0-or-later

//! The hourly target check (design §11.3) on a node configured for one
//! target: it passes a target that still answers at the configured
//! address through the current generation's Xray, and degrades one that
//! moved, failed the handshake, did not answer over HTTP/2 or could not
//! be resolved; its reading is the state group's to read, and the watch
//! reads it as its verdict on the configured target, or as unreadable.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use mooring_agent_proto::{Generation, UnixTime, WatchConfig, WatchTarget};

use super::world::{PING_TLS13, host, node_answering};
use crate::paths::Paths;
use crate::store::{read_json, write_json};
use crate::target::hourly::{TargetReading, Verdict};
use crate::tests::{EACCES, EISDIR, ModeFault, exited, scratch};

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
            abuse_guard: mooring_agent_proto::AbuseGuardVersion::V1,
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
/// printing `ping` and curl printing `curl`; returns whether it found the
/// target degraded, and the tools it ran.
fn verdict(
    resolved: &'static [u8],
    ping: &'static str,
    curl: &'static [u8],
) -> (bool, Vec<String>) {
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
    let (degraded, calls) = verdict(AT_TARGET, PING_TLS13, b"200 2 ");
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
    let (moved, calls) = verdict(
        b"198.51.100.8    STREAM www.example.com\n",
        PING_TLS13,
        b"200 2 ",
    );
    assert!(moved);
    assert_eq!(calls.len(), 1, "nothing is probed at another address");
    let failed_handshake = "Pinging with SNI\nHandshake failure:  EOF\n";
    assert!(verdict(AT_TARGET, failed_handshake, b"200 2 ").0);
    assert!(verdict(AT_TARGET, PING_TLS13, b"200 1.1 ").0, "not HTTP/2");
    assert!(verdict(AT_TARGET, PING_TLS13, b"000 0 ").0, "no answer");
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

/// No result, or one about another target, is no check yet; a result
/// about the configured target is its verdict; a result that cannot be
/// read is unreadable, with the OS error, or without one for a file that
/// holds no result, and never a verdict either way.
#[test]
fn the_watch_reads_each_result_as_its_verdict_or_as_unreadable() {
    let (_dir, paths) = configured();
    let verdict = || crate::target::hourly::verdict(&paths, &target());
    let write = |target: WatchTarget, degraded: bool| {
        let reading = TargetReading {
            at: UnixTime::from_secs(1000),
            target,
            degraded,
        };
        write_json(&paths.target_reading(), &reading, 0o640).unwrap();
    };
    assert_eq!(verdict(), Verdict::Unchecked, "no result yet");
    let moved = WatchTarget {
        ipv4: Ipv4Addr::new(198, 51, 100, 8),
        ..target()
    };
    write(moved, true);
    assert_eq!(
        verdict(),
        Verdict::Unchecked,
        "a result about another target"
    );
    write(target(), false);
    assert_eq!(verdict(), Verdict::Passed);
    write(target(), true);
    assert_eq!(verdict(), Verdict::Degraded);
    {
        let _unreadable = ModeFault::set(&paths.target_reading(), 0o000);
        assert_eq!(
            verdict(),
            Verdict::Unreadable {
                errno: Some(EACCES)
            }
        );
    }
    assert_eq!(verdict(), Verdict::Degraded, "readable again");
    std::fs::write(paths.target_reading(), "garbled").unwrap();
    assert_eq!(verdict(), Verdict::Unreadable { errno: None });
    std::fs::remove_file(paths.target_reading()).unwrap();
    std::fs::create_dir(paths.target_reading()).unwrap();
    assert_eq!(
        verdict(),
        Verdict::Unreadable {
            errno: Some(EISDIR)
        }
    );
}
