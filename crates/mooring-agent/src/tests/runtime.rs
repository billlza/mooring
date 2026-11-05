// SPDX-License-Identifier: GPL-3.0-or-later

//! Runtime proof comes from the process, and refresh preserves the node's
//! gate policy and generation while refusing incomplete evidence.

use std::fs;
use std::num::NonZeroU32;

use mooring_agent_proto::{AgentError, AgentErrorKind, IoOp, LineRequest, Request, Role};

use super::{FakeNode, failed, ok, scratch};
use crate::blobs::digest_of;
use crate::paths::Paths;
use crate::runtime::{inspect, refresh, start_ticks};

const NEW: &[u8] = b"new executable";
const OLD: &[u8] = b"old watch executable";

fn process(paths: &Paths, pid: u32, ticks: u64, executable: &[u8]) {
    let dir = paths.at(&format!("/proc/{pid}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("exe"), executable).unwrap();
    let fields = (3..=22)
        .map(|field| {
            if field == 3 {
                "S".to_owned()
            } else if field == 22 {
                ticks.to_string()
            } else {
                "0".to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(dir.join("stat"), format!("{pid} (watch (name)) {fields}\n")).unwrap();
}

fn setup(paths: &Paths) {
    fs::create_dir_all(paths.at("/proc/self")).unwrap();
    fs::write(paths.own_executable(), NEW).unwrap();
    fs::create_dir_all(paths.agent_dir()).unwrap();
    fs::write(paths.agent_current(), NEW).unwrap();
    fs::create_dir_all(paths.txn_lock().parent().unwrap()).unwrap();
    process(paths, 42, 1000, OLD);
}

fn answering(pid: &'static [u8]) -> FakeNode {
    FakeNode::answering(
        2000,
        Box::new(move |tool, args| {
            assert_eq!(tool, crate::host::Tool::Timeout);
            assert_eq!(args[0], "--kill-after=1s");
            let seconds: f64 = args[1].strip_suffix('s').unwrap().parse().unwrap();
            if args.contains(&"restart") {
                assert_eq!(args[1], "15s");
            } else {
                assert!(seconds > 0.0 && seconds <= 5.0);
            }
            Ok(ok(pid))
        }),
    )
}

/// The real Linux parser must accept the duration passed to systemd's
/// wrapper; a scripted systemd answer alone cannot prove that boundary.
#[cfg(target_os = "linux")]
#[test]
fn the_linux_timeout_accepts_the_runtime_query_duration() {
    let (_dir, paths) = scratch();
    setup(&paths);
    let node = FakeNode::answering(
        2000,
        Box::new(|tool, args| {
            let result = std::process::Command::new(tool.path())
                .args([args[0], args[1], "/usr/bin/true"])
                .status()
                .unwrap();
            assert!(result.success());
            Ok(ok(b"0\n"))
        }),
    );
    assert!(inspect(&paths, &node).unwrap().watch.is_none());
}

#[test]
fn the_current_link_does_not_prove_the_watch_was_upgraded() {
    let (_dir, paths) = scratch();
    setup(&paths);
    let result = inspect(&paths, &answering(b"42\n")).unwrap();
    assert_eq!(result.agent_sha, digest_of(NEW).unwrap());
    let watch = result.watch.unwrap();
    assert_eq!(watch.pid.get(), 42);
    assert_eq!(watch.start_ticks, 1000);
    assert_eq!(watch.executable_sha, digest_of(OLD).unwrap());
}

#[test]
fn a_stopped_service_is_distinct_from_failed_process_evidence() {
    let (_dir, paths) = scratch();
    setup(&paths);
    assert_eq!(inspect(&paths, &answering(b"0\n")).unwrap().watch, None);
    fs::remove_file(paths.at("/proc/42/stat")).unwrap();
    assert!(matches!(
        inspect(&paths, &answering(b"42\n")),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            ..
        })
    ));
    for text in [b"".as_slice(), b"-1\n", b"42\n43\n", b"MainPID=42\n"] {
        let owned = text.to_vec();
        let node = FakeNode::answering(2000, Box::new(move |_, _| Ok(ok(&owned))));
        assert!(inspect(&paths, &node).is_err());
    }
}

#[test]
fn a_reused_pid_is_not_accepted_as_the_hashed_process() {
    let (_dir, paths) = scratch();
    setup(&paths);
    let root = paths.clone();
    let calls = std::cell::Cell::new(0);
    let node = FakeNode::answering(
        2000,
        Box::new(move |_, _| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                process(&root, 42, 1001, OLD);
            }
            Ok(ok(b"42\n"))
        }),
    );
    assert!(matches!(
        inspect(&paths, &node),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            ..
        })
    ));
}

#[test]
fn refresh_verifies_the_new_process_without_editing_holds_or_halt() {
    let (_dir, paths) = scratch();
    setup(&paths);
    fs::create_dir_all(paths.gate_dir()).unwrap();
    fs::write(paths.holds(), b"preserve operator holds").unwrap();
    fs::write(paths.halted(), b"preserve halt marker").unwrap();
    let root = paths.clone();
    let pid = std::cell::Cell::new(42);
    let node = FakeNode::answering(
        2000,
        Box::new(move |_, args| {
            if args.contains(&"restart") {
                assert_eq!(args.last(), Some(&"mooring-watch.service"));
                process(&root, 43, 1010, NEW);
                pid.set(43);
                Ok(ok(b""))
            } else {
                Ok(ok(format!("{}\n", pid.get()).as_bytes()))
            }
        }),
    );
    let result = refresh(&paths, &node, digest_of(NEW).unwrap()).unwrap();
    let watch = result.watch.unwrap();
    assert_eq!((watch.pid.get(), watch.start_ticks), (43, 1010));
    assert_eq!(watch.executable_sha, result.agent_sha);
    assert_eq!(fs::read(paths.holds()).unwrap(), b"preserve operator holds");
    assert_eq!(fs::read(paths.halted()).unwrap(), b"preserve halt marker");
    assert_eq!(
        node.calls()
            .iter()
            .filter(|c| c.contains(" restart "))
            .count(),
        1
    );
}

#[test]
fn a_matching_watch_is_not_restarted_and_a_wrong_control_digest_is_refused() {
    let (_dir, paths) = scratch();
    setup(&paths);
    process(&paths, 42, 1000, NEW);
    let node = answering(b"42\n");
    refresh(&paths, &node, digest_of(NEW).unwrap()).unwrap();
    assert!(!node.calls().iter().any(|c| c.contains("restart")));
    assert!(matches!(
        refresh(&paths, &node, digest_of(OLD).unwrap()),
        Err(AgentError::AgentShaMismatch { .. })
    ));
    fs::write(paths.agent_current(), OLD).unwrap();
    assert!(matches!(
        refresh(&paths, &node, digest_of(NEW).unwrap()),
        Err(AgentError::AgentShaMismatch { .. })
    ));
}

#[test]
fn a_restart_failure_or_a_watch_that_stays_old_is_not_success() {
    let (_dir, paths) = scratch();
    setup(&paths);
    let node = FakeNode::answering(
        2000,
        Box::new(|_, args| {
            Ok(if args.contains(&"restart") {
                failed(b"restart failed")
            } else {
                ok(b"42\n")
            })
        }),
    );
    assert!(matches!(
        refresh(&paths, &node, digest_of(NEW).unwrap()),
        Err(AgentError::Systemd { .. })
    ));
    let node = answering(b"42\n");
    let error = refresh(&paths, &node, digest_of(NEW).unwrap()).unwrap_err();
    assert_eq!(error.kind(), AgentErrorKind::WatchNotUpdated);
    assert_eq!(
        node.calls()
            .iter()
            .filter(|c| c.contains(" restart "))
            .count(),
        1
    );
}

#[test]
fn process_stat_parsing_and_role_boundaries_are_strict() {
    let pid = NonZeroU32::new(42).unwrap();
    for text in ["", "42 () S", "41 (watch) S 1 2 3", "42 watch S"] {
        assert!(start_ticks(text, pid).is_err());
    }
    for request in [
        LineRequest::WatchRuntime,
        LineRequest::RefreshWatch {
            expected_agent_sha: digest_of(NEW).unwrap(),
        },
    ] {
        let request = Request::Line(request);
        assert!(request.authorize(Role::Ops).is_ok());
        assert!(request.authorize(Role::Viewer).is_err());
        assert!(request.authorize(Role::Bootstrap).is_err());
    }
}
