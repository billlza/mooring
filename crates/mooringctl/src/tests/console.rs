// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon before a deployment exists, and its start (design §10.1,
//! §15): the router console's loop until the acceptor ends or a deployment
//! appears, the start's refusals that leave everything as it was, the
//! acceptor's end, and the log's lines when they cannot be written.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::control::{DaemonReply, decode_reply};
use mooring_model::time::UnixTime;
use mooring_store::{RADIO_DIRECTORY, STATE_FILE, STATUS_SNAPSHOT_FILE};
use tempfile::TempDir;

use super::support::{FailingLog, Harness, NOW, Refusing};
use crate::daemon::deployed::Stopped;
use crate::daemon::hub::Hub;
use crate::daemon::serve::AcceptFailed;
use crate::daemon::{
    Asked, Control, Intervals, LoopState, RunPaths, acceptor_end, after_poll, deployment_exists,
    say, serve_until_stopped, spawn_acceptor, start,
};
use crate::error::{CommandError, LocalError};
use crate::router::error::{RouterError, UnreachableCause};

/// A temporary directory with a short path, for the control socket's.
fn short_dir() -> TempDir {
    tempfile::Builder::new().tempdir_in("/tmp").unwrap()
}

/// What the loop and the connections share, as `run` makes it, and the
/// loop's ends of it.
fn control() -> (Arc<Control>, Asked) {
    let (control, asked) = Control::new();
    (Arc::new(control), asked)
}

/// The log's lines after the daemon's stamp and prefix.
fn lines(log: &[u8]) -> Vec<String> {
    String::from_utf8(log.to_vec())
        .unwrap()
        .lines()
        .map(|line| {
            line.split_once("mooringctl daemon: ")
                .map_or(line, |(_, text)| text)
                .to_owned()
        })
        .collect()
}

/// Before a deployment exists the daemon says how it polls, polls the M7
/// and publishes what it found, and stops at once when its acceptor ends.
#[test]
fn the_router_console_polls_until_the_acceptor_ends() {
    let mut harness = Harness::new(9);
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    let (control, asked) = control();
    let (ended, acceptor_ended) = mpsc::channel();
    ended.send(()).unwrap();
    let mut log = Vec::new();
    let stopped = harness.with_env(|env| {
        serve_until_stopped(
            env,
            &mut log,
            &support,
            &control,
            &acceptor_ended,
            &asked,
            Intervals::DAEMON,
        )
    });
    assert_eq!(stopped.unwrap(), Stopped::AcceptorEnded);
    let lines = lines(&log);
    assert_eq!(
        lines[0],
        "daemon started: polling the M7 every 60 s on the interface the router pin records"
    );
    assert!(lines[1].starts_with("router poll failed: "), "{lines:?}");
    let published = control.hub.latest().unwrap().unwrap();
    assert_eq!(published.seq, 1);
    assert!(matches!(
        decode_reply(&published.line).unwrap(),
        DaemonReply::Status(ConsoleStatus::NoDeployment(_))
    ));
    assert!(!control.deployed.load(Ordering::SeqCst));
}

/// A deployment that appears ends the router console at its next poll,
/// and the exit is opened on it: here one whose state cannot be read,
/// which stops the daemon before it serves anything.
#[test]
fn a_deployment_that_appears_is_served_from_the_next_poll() {
    let mut harness = Harness::new(9);
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    let (control, asked) = control();
    let (_ended, acceptor_ended) = mpsc::channel::<()>();
    let quick = Intervals {
        router_poll: Duration::from_millis(20),
        ..Intervals::DAEMON
    };
    let (finished, outcome) = mpsc::channel();
    {
        let control = Arc::clone(&control);
        let support = support.clone();
        thread::spawn(move || {
            let mut log = Vec::new();
            let stopped = harness.with_env(|env| {
                serve_until_stopped(
                    env,
                    &mut log,
                    &support,
                    &control,
                    &acceptor_ended,
                    &asked,
                    quick,
                )
            });
            let _ = finished.send((stopped.map_err(|error| error.to_string()), log));
        });
    }
    let started = Instant::now();
    while control.hub.latest().unwrap().is_none() {
        assert!(started.elapsed() < Duration::from_secs(10), "no poll");
        thread::sleep(Duration::from_millis(5));
    }
    fs::write(support.join(STATE_FILE), b"{}").unwrap();
    let (stopped, log) = outcome.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(stopped.unwrap_err(), "the state could not be read");
    let lines = lines(&log);
    assert!(
        lines.contains(&"a deployment exists: serving the exit".to_owned()),
        "{lines:?}"
    );
    assert!(lines[0].contains("every 0 s"), "{lines:?}");
    assert!(!control.deployed.load(Ordering::SeqCst));
}

/// A deployment that is there when the daemon starts is served at once:
/// the M7 is not polled as the router console first.
#[test]
fn a_deployment_there_at_the_start_is_served_at_once() {
    let mut harness = super::deployed::deployed();
    super::deployed::statuses(&harness);
    harness
        .probes
        .borrow_mut()
        .push_back(Ok(super::deployed::CARRIER));
    let support = harness.support_dir();
    fs::create_dir_all(RunPaths::under(&support).dir).unwrap();
    let (control, asked) = control();
    let (ended, acceptor_ended) = mpsc::channel();
    ended.send(()).unwrap();
    let mut log = Vec::new();
    let stopped = harness.with_env(|env| {
        serve_until_stopped(
            env,
            &mut log,
            &support,
            &control,
            &acceptor_ended,
            &asked,
            Intervals::DAEMON,
        )
    });
    assert_eq!(stopped.unwrap(), Stopped::AcceptorEnded);
    assert!(control.deployed.load(Ordering::SeqCst));
    let lines = lines(&log);
    assert!(lines.contains(&"serving the exit".to_owned()), "{lines:?}");
    assert!(
        !lines.iter().any(|line| line.starts_with("daemon started")),
        "{lines:?}"
    );
}

/// A log that cannot take the daemon's first line stops it there.
#[test]
fn a_log_that_cannot_take_the_first_line_stops_the_daemon() {
    let mut harness = Harness::new(9);
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    let (control, asked) = control();
    let (_ended, acceptor_ended) = mpsc::channel::<()>();
    let mut log = FailingLog::at("daemon started");
    let error = harness
        .with_env(|env| {
            serve_until_stopped(
                env,
                &mut log,
                &support,
                &control,
                &acceptor_ended,
                &asked,
                Intervals::DAEMON,
            )
        })
        .unwrap_err();
    assert!(
        matches!(error, CommandError::Local(LocalError::Output(_))),
        "{error:?}"
    );
    assert!(control.hub.latest().unwrap().is_none(), "nothing polled");
}

/// A support directory that cannot be made stops the start before
/// anything else.
#[test]
fn a_support_directory_that_cannot_be_made_stops_the_start() {
    let dir = short_dir();
    fs::write(dir.path().join("file"), b"").unwrap();
    let support = dir.path().join("file").join("support");
    let error = start(&support).unwrap_err();
    assert!(
        matches!(&error, LocalError::SupportDir { path, .. } if *path == support),
        "{error:?}"
    );
}

/// A support directory in which the run directory cannot be made, a lock
/// that cannot be opened or taken, and a socket path too long to bind
/// each stop the start, naming the path.
#[test]
fn a_run_directory_lock_or_socket_that_cannot_be_set_up_stops_the_start() {
    let dir = short_dir();
    let support = dir.path().join("support");
    fs::create_dir(&support).unwrap();
    fs::set_permissions(&support, fs::Permissions::from_mode(0o500)).unwrap();
    let made = start(&support);
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).unwrap();
    let error = made.unwrap_err();
    assert!(
        matches!(&error, LocalError::RunDir { path, source } if *path == support.join("run") && source.kind() == io::ErrorKind::PermissionDenied),
        "{error:?}"
    );

    // A directory where the lock goes cannot be opened as one.
    let paths = RunPaths::under(&support);
    fs::create_dir_all(&paths.lock).unwrap();
    let error = start(&support).unwrap_err();
    assert!(
        matches!(&error, LocalError::DaemonLock { path, .. } if *path == paths.lock),
        "{error:?}"
    );
    fs::remove_dir(&paths.lock).unwrap();

    // A FIFO opens, but macOS takes no flock(2) on one.
    let made = Command::new("/usr/bin/mkfifo")
        .arg(&paths.lock)
        .status()
        .unwrap();
    assert!(made.success());
    let error = start(&support).unwrap_err();
    // ENOTSUP, 45 on macOS.
    assert!(
        matches!(&error, LocalError::DaemonLock { path, source } if *path == paths.lock && source.raw_os_error() == Some(45)),
        "{error:?}"
    );
    fs::remove_file(&paths.lock).unwrap();

    // A socket path longer than a Unix socket's address holds.
    let deep = dir.path().join("a".repeat(100));
    let error = start(&deep).unwrap_err();
    let socket = RunPaths::under(&deep).socket;
    assert!(
        matches!(&error, LocalError::Socket { path, .. } if *path == socket),
        "{error:?}"
    );
    assert!(!socket.exists());
}

/// Whether a deployment exists is an error, never "no", when the support
/// directory cannot be searched.
#[test]
fn a_state_that_cannot_be_inspected_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o000)).unwrap();
    let inspected = deployment_exists(dir.path());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let error = inspected.unwrap_err();
    assert!(
        matches!(&error, LocalError::StateInspect { path, source } if *path == dir.path().join(STATE_FILE) && source.kind() == io::ErrorKind::PermissionDenied),
        "{error:?}"
    );
    assert!(!deployment_exists(dir.path()).unwrap());
}

/// The acceptor ends when accepting fails, and says so; its end is its
/// error, or that it panicked.
#[test]
fn the_acceptor_s_end_is_its_error_or_its_panic() {
    let dir = short_dir();
    let listener = UnixListener::bind(dir.path().join("c.sock")).unwrap();
    // A listener that never waits fails its first accept.
    listener.set_nonblocking(true).unwrap();
    let (control, _asked) = control();
    let (acceptor, acceptor_ended) = spawn_acceptor(listener, &control).unwrap();
    acceptor_ended
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    let error = acceptor_end(acceptor);
    assert!(
        matches!(&error, LocalError::Acceptor(source) if source.kind() == io::ErrorKind::WouldBlock),
        "{error:?}"
    );
    let panicked = thread::spawn(|| -> AcceptFailed {
        std::panic::resume_unwind(Box::new("the acceptor's stand-in panicked"))
    });
    let error = acceptor_end(panicked);
    assert_eq!(
        error.to_string(),
        "the daemon's control socket stopped accepting connections"
    );
    assert!(
        matches!(&error, LocalError::Acceptor(source) if source.to_string() == "the acceptor thread panicked"),
        "{error:?}"
    );
}

/// A log line stamped past the year 9999 is the clock's error; one that
/// cannot be written is the output's.
#[test]
fn a_log_line_needs_a_stamp_and_a_writable_log() {
    let error = say(&mut Vec::new(), UnixTime::from_secs(u64::MAX), "x").unwrap_err();
    assert!(
        matches!(error, CommandError::Local(LocalError::Clock)),
        "{error:?}"
    );
    let error = say(&mut Refusing, UnixTime::from_secs(NOW), "x").unwrap_err();
    assert!(
        matches!(error, CommandError::Local(LocalError::Output(_))),
        "{error:?}"
    );
}

/// The router console stops when its log cannot be written: a changed
/// poll's line, a status that cannot be written, and a radio history that
/// cannot be.
#[test]
fn a_log_that_cannot_be_written_stops_the_router_console() {
    let unreachable = || {
        Err(CommandError::Router(RouterError::unreachable(
            UnreachableCause::GatewayUnresolved,
        )))
    };
    for needle in [
        "router poll failed",
        "status.json not written",
        "the radio history was not written",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let support = dir.path();
        // Each needle's file cannot be written; the lines before it can.
        fs::create_dir(support.join(STATUS_SNAPSHOT_FILE)).unwrap();
        fs::write(support.join(RADIO_DIRECTORY), b"").unwrap();
        let mut log = FailingLog::at(needle);
        let error = after_poll(
            &Hub::default(),
            support,
            &mut log,
            &mut LoopState::default(),
            UnixTime::from_secs(NOW),
            &unreachable(),
            UnixTime::from_secs(NOW + 1),
        )
        .unwrap_err();
        assert!(log.failed(), "{needle}");
        assert!(
            matches!(error, CommandError::Local(LocalError::Output(_))),
            "{needle}: {error:?}"
        );
        let kept = String::from_utf8(log.kept.clone()).unwrap();
        assert!(!kept.contains(needle), "{needle}: {kept}");
    }
}
