// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon (design §10.1, §15): how it starts in the support directory,
//! the status it publishes after each poll, the connections it serves and
//! refuses, and `status`, its client. Everything runs on Unix sockets in a
//! short temporary directory (a socket path has at most 104 bytes); the M7
//! and the live keychain are never touched.

use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use mooring_daemon_core::ControlError;
use mooring_daemon_core::console::{ConsoleStatus, UndeployedStatus};
use mooring_daemon_core::control::{
    DaemonReply, MAX_REPLY_LINE_BYTES, MAX_REQUEST_LINE_BYTES, Refusal, decode_reply, encode_line,
};
use mooring_daemon_core::router::netgear::parse_netgear_model_json;
use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};
use mooring_model::time::UnixTime;
use mooring_store::{ROUTER_PIN_FILE, STATE_FILE, STATUS_SNAPSHOT_FILE};
use tempfile::TempDir;

use super::support::FakeParent;
use super::support::{FIXTURE, Harness, NOW};
use crate::cli::Cli;
use crate::daemon::hub::Hub;
use crate::daemon::log::LOG_FILE;
use crate::daemon::serve::{End, Limits, accept, serve};
use crate::daemon::{
    Control, LoopState, PollOutcome, Polled, RunPaths, Waited, after_poll, poll_once, poll_router,
    start, unavailable_reason, wait_for_next_poll,
};
use crate::error::{CommandError, EXIT_LOCAL, LocalError};
use crate::router::error::{Missing, RouterError, UnreachableCause};
use crate::status::{FOLLOW_SILENCE, Next, PARENT_CHECK, read_reply_line, send_request};

/// Short limits, so the tests of time-outs are quick.
const QUICK: Limits = Limits {
    request: Duration::from_millis(300),
    write: Duration::from_secs(2),
    idle_check: Duration::from_millis(100),
};

/// How long a test waits for a reply, a connection's end or a command. A
/// regression that leaves one of them going fails the test instead of
/// hanging it.
const DEADLINE: Duration = Duration::from_secs(10);

/// Work on its own thread, whose result a test waits for at most
/// [`DEADLINE`].
struct Running<T>(mpsc::Receiver<T>);

impl<T: Send + 'static> Running<T> {
    fn start(work: impl FnOnce() -> T + Send + 'static) -> Self {
        let (done, result) = mpsc::channel();
        thread::spawn(move || {
            // Nothing waits any more once the test has failed.
            let _ = done.send(work());
        });
        Self(result)
    }

    fn result(self) -> T {
        self.0
            .recv_timeout(DEADLINE)
            .unwrap_or_else(|error| panic!("not done within {DEADLINE:?}: {error}"))
    }
}

/// A client end that fails a read after [`DEADLINE`] instead of waiting
/// for ever.
fn bounded(stream: UnixStream) -> UnixStream {
    stream.set_read_timeout(Some(DEADLINE)).unwrap();
    stream
}

/// A temporary directory with a short path: `/tmp/.tmpXXXXXX`.
fn short_dir() -> TempDir {
    tempfile::Builder::new().tempdir_in("/tmp").unwrap()
}

/// A harness whose `HOME` is short enough for the control socket's path.
fn harness() -> Harness {
    let mut harness = Harness::new(9);
    harness.home = short_dir();
    harness
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn fixture_status() -> mooring_daemon_core::RouterStatus {
    parse_netgear_model_json(FIXTURE).unwrap()
}

/// The router error a poll of an M7 that does not answer ends in.
fn unreachable() -> CommandError {
    CommandError::Router(RouterError::unreachable(
        UnreachableCause::GatewayUnresolved,
    ))
}

fn status_line(at: u64, router: RouterReading) -> Arc<[u8]> {
    let status =
        ConsoleStatus::NoDeployment(UndeployedStatus::new(UnixTime::from_secs(at), router));
    Arc::from(encode_line(&DaemonReply::Status(status), MAX_REPLY_LINE_BYTES).unwrap())
}

fn unavailable(at: u64) -> Arc<[u8]> {
    status_line(
        at,
        RouterReading::Unavailable {
            reason: RouterUnavailableReason::Unreachable,
            last_polled_at: None,
        },
    )
}

fn read_reply(reader: &mut impl BufRead) -> DaemonReply {
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).unwrap();
    decode_reply(&line).unwrap()
}

// --- Starting -----------------------------------------------------------

/// The run directory is 0700, the lock and the socket 0600, and the socket
/// is a socket that accepts connections.
#[test]
fn start_prepares_the_run_directory_the_lock_and_the_socket() {
    let dir = short_dir();
    let support = dir.path().join("support");
    let started = start(&support).unwrap();
    let paths = RunPaths::under(&support);
    assert_eq!(paths.dir, support.join("run"));
    assert_eq!(mode(&support), 0o700);
    assert_eq!(mode(&paths.dir), 0o700);
    assert_eq!(mode(&paths.lock), 0o600);
    assert_eq!(mode(&paths.socket), 0o600);
    assert!(
        fs::symlink_metadata(&paths.socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
    assert_eq!(paths.socket.file_name().unwrap(), "control.sock");
    assert_eq!(paths.lock.file_name().unwrap(), "daemon.lock");
    let _client = UnixStream::connect(&paths.socket).unwrap();
    let (_accepted, _) = started.listener.accept().unwrap();
}

/// One daemon at a time: the second is refused while the first holds the
/// lock and leaves the first's socket alone; once the first is gone, its
/// socket is replaced.
#[test]
fn a_second_daemon_is_refused_while_the_first_runs() {
    let dir = short_dir();
    let support = dir.path().join("support");
    let first = start(&support).unwrap();
    let paths = RunPaths::under(&support);
    let error = start(&support).unwrap_err();
    assert!(
        matches!(&error, LocalError::DaemonAlreadyRunning { path } if *path == paths.lock),
        "{error:?}"
    );
    assert!(
        error
            .to_string()
            .starts_with("another mooringctl daemon is running")
    );
    // The first still serves on its socket.
    let _client = UnixStream::connect(&paths.socket).unwrap();
    drop(first);
    let second = start(&support).unwrap();
    let _client = UnixStream::connect(&paths.socket).unwrap();
    let (_accepted, _) = second.listener.accept().unwrap();
}

/// A deployment does not keep the daemon from starting: it serves the
/// exit once it has started.
#[test]
fn a_deployment_does_not_keep_the_daemon_from_starting() {
    let dir = short_dir();
    let support = dir.path().join("support");
    fs::create_dir_all(&support).unwrap();
    fs::write(support.join(STATE_FILE), b"{}").unwrap();
    let _started = start(&support).unwrap();
    assert!(
        fs::symlink_metadata(RunPaths::under(&support).socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
}

/// A run directory that is a symbolic link is refused; one with a looser
/// mode, left by an earlier build, is tightened to 0700.
#[test]
fn the_run_directory_is_a_directory_of_mode_0700() {
    let dir = short_dir();
    let support = dir.path().join("support");
    fs::create_dir_all(&support).unwrap();
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, support.join("run")).unwrap();
    let error = start(&support).unwrap_err();
    assert!(
        matches!(&error, LocalError::RunDirNotDirectory { path } if *path == support.join("run")),
        "{error:?}"
    );
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
    fs::remove_file(support.join("run")).unwrap();
    fs::create_dir(support.join("run")).unwrap();
    fs::set_permissions(support.join("run"), fs::Permissions::from_mode(0o755)).unwrap();
    let _started = start(&support).unwrap();
    assert_eq!(mode(&support.join("run")), 0o700);
}

/// A file at the socket's path that is not a socket is left as it is.
#[test]
fn a_file_at_the_socket_path_is_left_alone() {
    let dir = short_dir();
    let support = dir.path().join("support");
    let paths = RunPaths::under(&support);
    fs::create_dir_all(&paths.dir).unwrap();
    fs::write(&paths.socket, b"not a socket").unwrap();
    let error = start(&support).unwrap_err();
    assert!(
        matches!(&error, LocalError::SocketPathTaken { path } if *path == paths.socket),
        "{error:?}"
    );
    assert_eq!(fs::read(&paths.socket).unwrap(), b"not a socket");
}

/// A socket left by a daemon that died is replaced.
#[test]
fn a_stale_socket_is_replaced() {
    let dir = short_dir();
    let support = dir.path().join("support");
    let paths = RunPaths::under(&support);
    fs::create_dir_all(&paths.dir).unwrap();
    drop(UnixListener::bind(&paths.socket).unwrap());
    assert!(UnixStream::connect(&paths.socket).is_err());
    let started = start(&support).unwrap();
    let _client = UnixStream::connect(&paths.socket).unwrap();
    let (_accepted, _) = started.listener.accept().unwrap();
}

// --- The hub ------------------------------------------------------------

/// Each publication has the next number; a waiter gets the latest line
/// newer than the one it saw, or nothing in time.
#[test]
fn the_hub_keeps_the_latest_line_and_numbers_them() {
    let hub = Hub::default();
    assert_eq!(hub.latest().unwrap(), None);
    assert_eq!(hub.newer_than(0, Duration::from_millis(20)).unwrap(), None);
    hub.publish(unavailable(1)).unwrap();
    hub.publish(unavailable(2)).unwrap();
    let latest = hub.latest().unwrap().unwrap();
    assert_eq!(latest.seq, 2);
    assert_eq!(latest.line, unavailable(2));
    // A slow reader skips to the latest.
    assert_eq!(
        hub.newer_than(0, Duration::from_millis(20))
            .unwrap()
            .unwrap()
            .seq,
        2
    );
    assert_eq!(hub.newer_than(2, Duration::from_millis(20)).unwrap(), None);
    // A waiter is woken by the next publication.
    let hub = Arc::new(hub);
    let publisher = {
        let hub = Arc::clone(&hub);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            hub.publish(unavailable(3)).unwrap();
        })
    };
    let next = hub.newer_than(2, Duration::from_secs(5)).unwrap().unwrap();
    assert_eq!((next.seq, next.line), (3, unavailable(3)));
    publisher.join().unwrap();
}

// --- One poll -----------------------------------------------------------

/// A poll's outcome becomes the published status and the snapshot, and the
/// log names a failure once, again when it changes, and the recovery.
#[test]
fn each_poll_publishes_snapshots_and_logs_only_changes() {
    let dir = short_dir();
    let support = dir.path().to_path_buf();
    let hub = Hub::default();
    let mut state = LoopState::default();
    let mut log = Vec::new();
    let poll = |state: &mut LoopState, log: &mut Vec<u8>, at: u64, outcome| {
        after_poll(
            &hub,
            &support,
            log,
            state,
            UnixTime::from_secs(at),
            &outcome,
            UnixTime::from_secs(at + 1),
        )
        .unwrap();
    };
    poll(&mut state, &mut log, NOW, Err(unreachable()));
    poll(&mut state, &mut log, NOW + 60, Err(unreachable()));
    let published = hub.latest().unwrap().unwrap();
    assert_eq!(published.seq, 2);
    assert_eq!(
        decode_reply(&published.line).unwrap(),
        DaemonReply::Status(ConsoleStatus::NoDeployment(UndeployedStatus::new(
            UnixTime::from_secs(NOW + 61),
            RouterReading::Unavailable {
                reason: RouterUnavailableReason::Unreachable,
                last_polled_at: None,
            },
        )))
    );
    poll(&mut state, &mut log, NOW + 120, Ok(fixture_status()));
    poll(&mut state, &mut log, NOW + 180, Ok(fixture_status()));
    let local = || CommandError::Local(LocalError::NeighbourTableHidden);
    poll(&mut state, &mut log, NOW + 240, Err(local()));
    let reading = state.previous.clone().unwrap();
    assert_eq!(
        reading,
        RouterReading::Unavailable {
            reason: RouterUnavailableReason::LocalFailure,
            last_polled_at: Some(UnixTime::from_secs(NOW + 180)),
        }
    );
    // The snapshot is the latest document, as `status --json` prints it.
    let snapshot = fs::read(support.join(STATUS_SNAPSHOT_FILE)).unwrap();
    let document: ConsoleStatus = serde_json::from_slice(&snapshot).unwrap();
    assert_eq!(document.router(), &reading);
    assert_eq!(snapshot.last(), Some(&b'\n'));
    assert_eq!(mode(&support.join(STATUS_SNAPSHOT_FILE)), 0o600);
    // A failure that comes back after a success is logged again.
    poll(&mut state, &mut log, NOW + 300, Ok(fixture_status()));
    poll(&mut state, &mut log, NOW + 360, Err(local()));
    let log = String::from_utf8(log).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 5, "{log}");
    assert!(
        lines[0].starts_with(
            "2026-10-13 19:20:01 UTC mooringctl daemon: router poll failed: the M7 is unreachable"
        ),
        "{log}"
    );
    assert_eq!(
        lines[1],
        "2026-10-13 19:22:01 UTC mooringctl daemon: router poll succeeded"
    );
    assert!(lines[2].starts_with("2026-10-13 19:24:01 UTC mooringctl daemon: router poll failed: the kernel returned an empty neighbour table"), "{log}");
    assert_eq!(
        lines[3],
        "2026-10-13 19:25:01 UTC mooringctl daemon: router poll succeeded"
    );
    assert!(lines[4].starts_with("2026-10-13 19:26:01 UTC mooringctl daemon: router poll failed: the kernel returned an empty neighbour table"), "{log}");
}

/// A snapshot that cannot be written is logged, and the status is still
/// published: the snapshot is for diagnosis only. Like a poll's failure,
/// it is logged once while it lasts, and its end is logged too.
#[test]
fn a_snapshot_that_cannot_be_written_is_logged_not_fatal() {
    let dir = short_dir();
    let missing = dir.path().join("missing");
    let hub = Hub::default();
    let mut state = LoopState::default();
    let mut log = Vec::new();
    for at in [NOW, NOW + 60] {
        after_poll(
            &hub,
            &missing,
            &mut log,
            &mut state,
            UnixTime::from_secs(at),
            &Ok(fixture_status()),
            UnixTime::from_secs(at),
        )
        .unwrap();
    }
    assert_eq!(hub.latest().unwrap().unwrap().seq, 2);
    assert!(!missing.exists());
    fs::create_dir(&missing).unwrap();
    after_poll(
        &hub,
        &missing,
        &mut log,
        &mut state,
        UnixTime::from_secs(NOW + 120),
        &Ok(fixture_status()),
        UnixTime::from_secs(NOW + 120),
    )
    .unwrap();
    assert!(missing.join(STATUS_SNAPSHOT_FILE).exists());
    let log = String::from_utf8(log).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 3, "{log}");
    assert_eq!(
        lines[0],
        "2026-10-13 19:20:00 UTC mooringctl daemon: router poll succeeded"
    );
    assert!(
        lines[1]
            .starts_with("2026-10-13 19:20:00 UTC mooringctl daemon: status.json not written: "),
        "{log}"
    );
    assert_eq!(
        lines[2],
        "2026-10-13 19:22:00 UTC mooringctl daemon: status.json written again"
    );
}

/// Each poll first checks that no deployment has appeared: the daemon
/// never publishes `no_deployment` beside one, and serves the exit instead.
#[test]
fn a_deployment_that_appears_ends_the_router_console_at_its_next_poll() {
    let mut harness = harness();
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    let hub = Hub::default();
    let mut state = LoopState::default();
    let mut log = Vec::new();
    assert_eq!(
        harness
            .with_env(|env| poll_once(env, &support, &hub, &mut log, &mut state))
            .unwrap(),
        Polled::Published
    );
    assert_eq!(hub.latest().unwrap().unwrap().seq, 1);
    fs::write(support.join(STATE_FILE), b"{}").unwrap();
    assert_eq!(
        harness
            .with_env(|env| poll_once(env, &support, &hub, &mut log, &mut state))
            .unwrap(),
        Polled::DeploymentAppeared
    );
    assert_eq!(hub.latest().unwrap().unwrap().seq, 1);
}

/// The daemon polls on the interface the router pin records, read at each
/// poll: without a pin, and with a version-1 pin, which records none, the
/// panel says the adapter is not set up and the log names what is missing;
/// once `router pin --interface` records it, the next poll reads the M7.
#[test]
fn the_daemon_polls_on_the_interface_the_pin_records() {
    let mut harness = harness();
    let support = harness.support_dir();
    let poll = |harness: &mut Harness| harness.with_env(|env| poll_router(env, &support));
    let missing = |outcome: PollOutcome| match outcome {
        Err(CommandError::Router(RouterError::NotConfigured { missing })) => missing,
        other => panic!("{other:?}"),
    };
    assert_eq!(missing(poll(&mut harness)), Missing::Pin);
    fs::create_dir_all(&support).unwrap();
    fs::write(
        support.join(ROUTER_PIN_FILE),
        "{\"version\": 1, \"gateway_lladdr\": \"02:00:5e:10:20:30\", \"pinned_at\": 1791900000}\n",
    )
    .unwrap();
    assert_eq!(missing(poll(&mut harness)), Missing::Interface);
    assert_eq!(
        unavailable_reason(&CommandError::Router(RouterError::NotConfigured {
            missing: Missing::Interface
        })),
        RouterUnavailableReason::NotConfigured
    );
    // Pinned with the interface: the poll goes to the M7 on it, and only
    // the password is missing now.
    let outcome = harness.run(&["router", "pin", "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        harness.console.asked.is_empty(),
        "the identity did not change"
    );
    assert_eq!(missing(poll(&mut harness)), Missing::Password);
}

/// The wait for the next poll ends early when the acceptor ends, or when
/// it panicked and so never said so.
#[test]
fn the_wait_for_the_next_poll_ends_with_the_acceptor() {
    let (ended, acceptor_ended) = mpsc::channel();
    let started = std::time::Instant::now();
    let pause = Duration::from_millis(100);
    assert_eq!(
        wait_for_next_poll(started + pause, &acceptor_ended),
        Waited::Elapsed
    );
    assert!(started.elapsed() >= pause);
    ended.send(()).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        wait_for_next_poll(started + DEADLINE, &acceptor_ended),
        Waited::AcceptorEnded
    );
    assert!(started.elapsed() < DEADLINE / 2);
    let (ended, acceptor_ended) = mpsc::channel::<()>();
    drop(ended);
    assert_eq!(
        wait_for_next_poll(std::time::Instant::now() + DEADLINE, &acceptor_ended),
        Waited::AcceptorEnded
    );
}

/// A router failure shows its own reason; a failure on the Mac shows
/// `LocalFailure`.
#[test]
fn failures_map_to_panel_reasons() {
    assert_eq!(
        unavailable_reason(&unreachable()),
        RouterUnavailableReason::Unreachable
    );
    assert_eq!(
        unavailable_reason(&CommandError::Router(RouterError::NotConfigured {
            missing: Missing::Interface,
        })),
        RouterUnavailableReason::NotConfigured
    );
    assert_eq!(
        unavailable_reason(&CommandError::Local(LocalError::Clock)),
        RouterUnavailableReason::LocalFailure
    );
    assert_eq!(
        Missing::Interface.to_string(),
        "the router pin records no interface to the M7 (mooringctl router pin --interface <bsd>)"
    );
}

// --- Connections --------------------------------------------------------

/// Serves one connection on a socket pair whose client has already sent
/// `request` (the pair buffers it, so a slow test thread cannot make it
/// late): the client end, and how the connection ended.
fn serve_pair(control: &Arc<Control>, request: &[u8]) -> (UnixStream, Running<End>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(request).unwrap();
    let control = Arc::clone(control);
    (
        bounded(client),
        Running::start(move || serve(server, &control, QUICK)),
    )
}

/// What the connections share, with a fresh hub, and the receiving end of
/// its retries.
fn control() -> (Arc<Control>, mpsc::Receiver<()>) {
    let (retry, retries) = mpsc::channel();
    (
        Arc::new(Control {
            hub: Hub::default(),
            retry,
            deployed: AtomicBool::new(false),
        }),
        retries,
    )
}

#[test]
fn status_answers_the_latest_line_once() {
    let (control, _retries) = control();
    let hub = &control.hub;
    hub.publish(unavailable(1)).unwrap();
    hub.publish(unavailable(2)).unwrap();
    let (mut client, server) = serve_pair(&control, b"\"status\"\n");
    let mut all = Vec::new();
    client.read_to_end(&mut all).unwrap();
    assert_eq!(all, &*unavailable(2));
    assert_eq!(server.result(), End::Answered);
}

#[test]
fn status_before_the_first_poll_is_refused() {
    let (control, _retries) = control();
    let (client, server) = serve_pair(&control, b"\"status\"\n");
    let mut reader = BufReader::new(client);
    assert_eq!(
        read_reply(&mut reader),
        DaemonReply::Refused {
            reason: Refusal::NoStatusYet
        }
    );
    assert_eq!(server.result(), End::Refused(Refusal::NoStatusYet));
}

/// A retry is handed to the loop and answered once it is queued, and
/// refused while there is no deployment; with the loop gone it is not
/// answered at all.
#[test]
fn a_retry_is_queued_for_the_loop_only_with_a_deployment() {
    let (control, retries) = control();
    let (client, server) = serve_pair(&control, b"\"retry\"\n");
    assert_eq!(
        read_reply(&mut BufReader::new(client)),
        DaemonReply::Refused {
            reason: Refusal::NotDeployed
        }
    );
    assert_eq!(server.result(), End::Refused(Refusal::NotDeployed));
    assert!(retries.try_recv().is_err());
    control
        .deployed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (client, server) = serve_pair(&control, b"\"retry\"\n");
    assert_eq!(
        read_reply(&mut BufReader::new(client)),
        DaemonReply::RetryQueued
    );
    assert_eq!(server.result(), End::Answered);
    assert_eq!(retries.try_iter().count(), 1);
    drop(retries);
    let (_client, server) = serve_pair(&control, b"\"retry\"\n");
    assert_eq!(server.result(), End::Stopping);
}

/// A subscription waits for the first status, gets each new one, skips to
/// the latest when it falls behind, and ends when the client leaves.
#[test]
fn a_subscription_follows_the_hub_until_the_client_leaves() {
    let (control, _retries) = control();
    let hub = &control.hub;
    let (client, server) = serve_pair(&control, b"\"subscribe\"\n");
    thread::sleep(Duration::from_millis(250));
    hub.publish(unavailable(1)).unwrap();
    let mut reader = BufReader::new(client.try_clone().unwrap());
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).unwrap();
    assert_eq!(line, &*unavailable(1));
    hub.publish(unavailable(2)).unwrap();
    hub.publish(unavailable(3)).unwrap();
    line.clear();
    reader.read_until(b'\n', &mut line).unwrap();
    // It sent 2 or skipped to 3, but never anything older.
    assert!(line == *unavailable(2) || line == *unavailable(3));
    if line == *unavailable(2) {
        line.clear();
        reader.read_until(b'\n', &mut line).unwrap();
        assert_eq!(line, &*unavailable(3));
    }
    // Nothing is sent again until something new is published.
    reader
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    line.clear();
    let again = reader.read_until(b'\n', &mut line);
    assert!(
        again
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "{again:?} {line:?}"
    );
    drop(reader);
    drop(client);
    assert_eq!(server.result(), End::ClientLeft);
}

/// A byte after the one request ends a subscription: the client speaks
/// nothing else.
#[test]
fn bytes_after_the_request_end_a_subscription() {
    let (control, _retries) = control();
    let hub = &control.hub;
    hub.publish(unavailable(1)).unwrap();
    let (_client, server) = serve_pair(&control, b"\"subscribe\"\n\"status\"\n");
    assert_eq!(server.result(), End::ClientLeft);
}

/// A malformed, overlong, unterminated or late request is refused as a
/// bad request.
#[test]
fn bad_requests_are_refused() {
    let (control, _retries) = control();
    let hub = &control.hub;
    hub.publish(unavailable(1)).unwrap();
    let long = vec![b' '; MAX_REQUEST_LINE_BYTES + 10];
    for request in [
        &b"\"poll_now\"\n"[..],
        b"status\n",
        b"{}\n",
        &long,
        b"\"status\"",
    ] {
        let (client, server) = serve_pair(&control, request);
        let mut reader = BufReader::new(client);
        assert_eq!(
            read_reply(&mut reader),
            DaemonReply::Refused {
                reason: Refusal::BadRequest
            },
            "{request:?}"
        );
        assert_eq!(server.result(), End::Refused(Refusal::BadRequest));
    }
    // A client that leaves before its request is gone, not refused.
    let (client, server) = serve_pair(&control, b"");
    drop(client);
    assert_eq!(server.result(), End::ClientLeft);
}

/// The request's time limit holds for the whole line, not each byte: a
/// client that drips a valid request slower than that is refused.
#[test]
fn a_request_dripped_past_the_limit_is_refused() {
    let (control, _retries) = control();
    let hub = &control.hub;
    hub.publish(unavailable(1)).unwrap();
    let (mut client, server) = serve_pair(&control, b"");
    let pause = QUICK.request / 2 + Duration::from_millis(20);
    for part in [&b"\"sta"[..], b"tus\"", b"\n"] {
        thread::sleep(pause);
        // The daemon may already have refused and closed its side.
        if client.write_all(part).is_err() {
            break;
        }
    }
    let mut reader = BufReader::new(client);
    assert_eq!(
        read_reply(&mut reader),
        DaemonReply::Refused {
            reason: Refusal::BadRequest
        }
    );
    assert_eq!(server.result(), End::Refused(Refusal::BadRequest));
}

/// A reply line's time limit holds for the whole line: a reader that
/// drains a long line a little at a time, each part well within the limit,
/// is cut off once the limit has passed.
#[test]
fn a_line_drained_past_the_write_limit_ends_the_connection() {
    let (control, _retries) = control();
    let hub = &control.hub;
    let mut long = vec![b' '; 600 * 1024];
    long.push(b'\n');
    hub.publish(Arc::from(long)).unwrap();
    let (client, server) = serve_pair(&control, b"\"status\"\n");
    // Eight bytes every 100 ms: every read wakes the writer well within
    // the limit, so only a deadline on the whole line ends it. The reader
    // stops once the server has ended, with its buffer still unread.
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let stop = Arc::clone(&stop);
        Running::start(move || {
            let mut client = client;
            let mut part = [0_u8; 8];
            let mut read = 0;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                match client.read(&mut part) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => read += n,
                }
                thread::sleep(Duration::from_millis(100));
            }
            read
        })
    };
    let started = std::time::Instant::now();
    let end = server.result();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        matches!(
            end,
            End::Io(std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
        ),
        "{end:?}"
    );
    assert!(started.elapsed() < DEADLINE / 2, "{:?}", started.elapsed());
    assert!(reader.result() < 600 * 1024);
}

/// Beyond the client limit a connection is told the daemon is busy, while
/// the clients within it are served.
#[test]
fn clients_beyond_the_limit_are_told_busy() {
    let dir = short_dir();
    let path = dir.path().join("c.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (control, _retries) = control();
    let hub = &control.hub;
    hub.publish(unavailable(1)).unwrap();
    {
        let control = Arc::clone(&control);
        thread::spawn(move || accept(&listener, &control, QUICK, 1));
    }
    let mut first = bounded(UnixStream::connect(&path).unwrap());
    first.write_all(b"\"subscribe\"\n").unwrap();
    let mut first_reader = BufReader::new(first.try_clone().unwrap());
    let mut line = Vec::new();
    first_reader.read_until(b'\n', &mut line).unwrap();
    assert_eq!(line, &*unavailable(1));
    let second = bounded(UnixStream::connect(&path).unwrap());
    let mut second_reader = BufReader::new(second);
    assert_eq!(
        read_reply(&mut second_reader),
        DaemonReply::Refused {
            reason: Refusal::Busy
        }
    );
    // Once the first leaves, its slot is free again: as soon as the server
    // notices (its idle check), the next client is served.
    drop(first_reader);
    drop(first);
    let busy = encode_line(
        &DaemonReply::Refused {
            reason: Refusal::Busy,
        },
        MAX_REPLY_LINE_BYTES,
    )
    .unwrap();
    let started = std::time::Instant::now();
    loop {
        let mut third = bounded(UnixStream::connect(&path).unwrap());
        // A busy daemon may close before the request arrives.
        let _ = third.write_all(b"\"status\"\n");
        let mut all = Vec::new();
        third.read_to_end(&mut all).unwrap();
        if all != busy {
            assert_eq!(all, &*unavailable(1));
            break;
        }
        assert!(started.elapsed() < DEADLINE, "the slot was never freed");
        thread::sleep(QUICK.idle_check);
    }
}

// --- The client ---------------------------------------------------------

/// A fake daemon on the harness's control socket that answers one
/// connection with `replies`, then closes it, and returns the request it
/// read.
fn fake_daemon(harness: &Harness, replies: Vec<Vec<u8>>) -> Running<Vec<u8>> {
    let paths = RunPaths::under(&harness.support_dir());
    fs::create_dir_all(&paths.dir).unwrap();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    Running::start(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = Vec::new();
        reader.read_until(b'\n', &mut request).unwrap();
        let mut stream = stream;
        for reply in replies {
            stream.write_all(&reply).unwrap();
        }
        request
    })
}

fn available_line(at: u64) -> Vec<u8> {
    status_line(
        at,
        RouterReading::Available {
            polled_at: UnixTime::from_secs(at - 20),
            status: Box::new(fixture_status()),
        },
    )
    .to_vec()
}

/// The document `status --json` prints for a reply line: the status alone.
fn document_of(reply: &[u8]) -> String {
    let DaemonReply::Status(status) = decode_reply(reply).unwrap() else {
        panic!("a status reply");
    };
    String::from_utf8(encode_line(&status, MAX_REPLY_LINE_BYTES).unwrap()).unwrap()
}

#[test]
fn status_prints_one_document_or_a_summary() {
    let mut harness = harness();
    let daemon = fake_daemon(&harness, vec![available_line(NOW)]);
    let outcome = harness.run(&["status", "--json"]);
    assert_eq!(daemon.result(), b"\"status\"\n");
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, document_of(&available_line(NOW)));
    assert!(
        outcome
            .stdout
            .starts_with("{\"no_deployment\":{\"version\":1,")
    );

    fs::remove_file(RunPaths::under(&harness.support_dir()).socket).unwrap();
    let daemon = fake_daemon(&harness, vec![available_line(NOW)]);
    let outcome = harness.run(&["status"]);
    daemon.result();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let mut lines = outcome.stdout.lines();
    assert_eq!(
        lines.next(),
        Some(
            "status at 2026-10-13 19:20:00 UTC: no deployment on this Mac yet (`exit init` creates it)"
        )
    );
    assert_eq!(
        lines.next(),
        Some("M7 MR7450, polled 2026-10-13 19:19:40 UTC")
    );
    assert!(
        outcome.stdout.contains("\nradio connected: "),
        "{}",
        outcome.stdout
    );
}

#[test]
fn status_summarises_an_unavailable_router() {
    let mut harness = harness();
    for (last, said) in [
        (None, "never read yet"),
        (Some(NOW - 600), "last read 2026-10-13 19:10:00 UTC"),
    ] {
        let line = status_line(
            NOW,
            RouterReading::Unavailable {
                reason: RouterUnavailableReason::AuthFailed,
                last_polled_at: last.map(UnixTime::from_secs),
            },
        );
        let daemon = fake_daemon(&harness, vec![line.to_vec()]);
        let outcome = harness.run(&["status"]);
        daemon.result();
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(
            outcome.stdout,
            format!(
                "status at 2026-10-13 19:20:00 UTC: no deployment on this Mac yet (`exit init` creates it)\nM7 unavailable: the M7 did not grant an administrator's session; {said}\n"
            )
        );
        fs::remove_file(RunPaths::under(&harness.support_dir()).socket).unwrap();
    }
}

/// `--follow` prints every status as it comes, flushed, and ends with the
/// stream: the daemon closing it is an error, so the app knows to restart.
#[test]
fn follow_prints_each_status_until_the_daemon_closes() {
    let mut harness = harness();
    let daemon = fake_daemon(
        &harness,
        vec![available_line(NOW), available_line(NOW + 60)],
    );
    let outcome = harness.run(&["status", "--follow", "--json"]);
    assert_eq!(daemon.result(), b"\"subscribe\"\n");
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stdout,
        format!(
            "{}{}",
            document_of(&available_line(NOW)),
            document_of(&available_line(NOW + 60))
        )
    );
    assert_eq!(
        outcome.stderr,
        "mooringctl: the daemon closed the status stream\n"
    );
}

/// A daemon on the harness's control socket that reads the request,
/// sends `first`, waits `pause`, sends `then`, and keeps the connection
/// until the client leaves.
fn lingering_daemon(
    harness: &Harness,
    first: Vec<u8>,
    pause: Duration,
    then: Vec<u8>,
) -> Running<()> {
    let paths = RunPaths::under(&harness.support_dir());
    fs::create_dir_all(&paths.dir).unwrap();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    Running::start(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = Vec::new();
        reader.read_until(b'\n', &mut request).unwrap();
        assert_eq!(request, b"\"subscribe\"\n");
        let mut stream = stream;
        stream.write_all(&first).unwrap();
        thread::sleep(pause);
        stream.write_all(&then).unwrap();
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    })
}

/// `--follow` ends, quietly and with success, once the process that
/// started it is gone (Mooring.app quit, crashed or was killed): nothing
/// reads what it prints any more, and it would otherwise wait for the
/// next status to fail its write.
#[test]
fn follow_ends_once_its_parent_is_gone() {
    let mut harness = harness();
    // Started by 700, there when the first status is printed, then adopted
    // by launchd.
    harness.parent.ids.replace(VecDeque::from([700, 700, 1]));
    let daemon = lingering_daemon(&harness, available_line(NOW), Duration::ZERO, Vec::new());
    let outcome = Running::start(move || {
        harness.run(&["status", "--follow", "--json", "--until-parent-exits"])
    })
    .result();
    daemon.result();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, document_of(&available_line(NOW)));
    assert_eq!(outcome.stderr, "");
}

/// A line that arrives in parts across the checks of the parent is read
/// whole.
#[test]
fn a_line_split_across_parent_checks_is_read_whole() {
    let mut harness = harness();
    // The parent is there when it starts, before the first status is
    // printed, at the check while the second is in parts and before it is
    // printed; it is gone at the check after that.
    harness
        .parent
        .ids
        .replace(VecDeque::from([700, 700, 700, 700, 1]));
    let mut second = available_line(NOW + 60);
    let rest = second.split_off(second.len() / 2);
    let mut first = available_line(NOW);
    first.extend_from_slice(&second);
    let daemon = lingering_daemon(&harness, first, PARENT_CHECK + PARENT_CHECK / 2, rest);
    let outcome = Running::start(move || {
        harness.run(&["status", "--follow", "--json", "--until-parent-exits"])
    })
    .result();
    daemon.result();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "{}{}",
            document_of(&available_line(NOW)),
            document_of(&available_line(NOW + 60))
        )
    );
}

/// The tick of the reads below.
const QUICK_TICK: Duration = Duration::from_millis(50);

/// The deadline `silence` from now.
fn quick_wait(silence: Duration) -> std::time::Instant {
    std::time::Instant::now() + silence
}

/// A reader on one end of a socket pair whose reads wait one
/// [`QUICK_TICK`], as `connect` sets them, and the other end.
fn quick_reader() -> (BufReader<UnixStream>, UnixStream) {
    let (client, daemon) = UnixStream::pair().unwrap();
    client.set_read_timeout(Some(QUICK_TICK)).unwrap();
    (BufReader::new(client), daemon)
}

/// The deadline holds for the whole wait, not a tick, and the parent is
/// asked after at every tick on the way.
#[test]
fn the_deadline_ends_the_wait_after_its_ticks() {
    let (mut reader, daemon) = quick_reader();
    let silence = Duration::from_millis(300);
    let (read, waited, asked) = Running::start(move || {
        let asked = std::cell::Cell::new(0);
        let parent_there = || {
            asked.set(asked.get() + 1);
            true
        };
        let started = std::time::Instant::now();
        let read = read_reply_line(
            &mut reader,
            Path::new("/s"),
            quick_wait(silence),
            &parent_there,
        );
        (read, started.elapsed(), asked.get())
    })
    .result();
    drop(daemon);
    assert_eq!(read.unwrap(), Next::Deadline);
    assert!(waited >= silence, "{waited:?}");
    assert!(asked >= 1, "{asked}");
}

/// The bound holds across a line's parts: it is refused one byte past it,
/// however its parts arrived.
#[test]
fn a_long_line_in_parts_is_refused_at_the_bound() {
    let (mut reader, mut daemon) = quick_reader();
    let writer = Running::start(move || {
        let part = vec![b'x'; MAX_REPLY_LINE_BYTES / 2 + 10];
        daemon.write_all(&part).unwrap();
        thread::sleep(QUICK_TICK * 3);
        // The reader stops at the bound, so this may not all be read.
        let _ = daemon.write_all(&part);
        daemon
    });
    // A deadline well past the pause, so a slow machine cannot end the
    // read early.
    let read = read_reply_line(
        &mut reader,
        Path::new("/s"),
        quick_wait(DEADLINE / 2),
        &|| true,
    );
    assert!(
        matches!(
            read,
            Err(LocalError::DaemonReply(ControlError::LineTooLong { bytes, max }))
                if bytes == MAX_REPLY_LINE_BYTES + 1 && max == MAX_REPLY_LINE_BYTES
        ),
        "{read:?}"
    );
    drop(reader);
    drop(writer.result());
}

/// A parent gone ends the wait at the next tick, without a line.
#[test]
fn a_parent_gone_ends_the_wait() {
    let (mut reader, _daemon) = quick_reader();
    let read = read_reply_line(&mut reader, Path::new("/s"), quick_wait(DEADLINE), &|| {
        false
    });
    assert_eq!(read.unwrap(), Next::ParentGone);
}

/// Without `--until-parent-exits` the follow never asks about its parent:
/// a follow left running on purpose (`nohup`) outlives the shell, and ends
/// only with the stream.
#[test]
fn without_the_flag_a_follow_never_asks_about_its_parent() {
    let mut harness = harness();
    harness.parent = FakeParent::never_asked();
    let daemon = fake_daemon(&harness, vec![available_line(NOW)]);
    let outcome = Running::start(move || harness.run(&["status", "--follow", "--json"])).result();
    assert_eq!(daemon.result(), b"\"subscribe\"\n");
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, document_of(&available_line(NOW)));
    assert_eq!(
        outcome.stderr,
        "mooringctl: the daemon closed the status stream\n"
    );
}

/// A one-shot `status` never asks about its parent, and the flag needs
/// `--follow`.
#[test]
fn a_one_shot_status_never_asks_about_its_parent() {
    let mut harness = harness();
    harness.parent = FakeParent::never_asked();
    let daemon = fake_daemon(&harness, vec![available_line(NOW)]);
    let outcome = harness.run(&["status", "--json"]);
    assert_eq!(daemon.result(), b"\"status\"\n");
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        <Cli as clap::Parser>::try_parse_from(["mooringctl", "status", "--until-parent-exits"])
            .is_err()
    );
}

/// A parent gone before the first status is printed: nothing is printed.
/// One that had gone before the follow started (launchd is its parent):
/// it ends at once, without connecting.
#[test]
fn a_follow_whose_parent_is_already_gone_prints_nothing() {
    let mut harness = harness();
    harness.parent.ids.replace(VecDeque::from([700, 1]));
    let daemon = lingering_daemon(&harness, available_line(NOW), Duration::ZERO, Vec::new());
    let mut harness = Running::start(move || {
        let outcome = harness.run(&["status", "--follow", "--json", "--until-parent-exits"]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, "");
        harness
    })
    .result();
    daemon.result();
    // No daemon listens now: connecting would fail.
    fs::remove_file(RunPaths::under(&harness.support_dir()).socket).unwrap();
    harness.parent.ids.replace(VecDeque::from([1]));
    let outcome = harness.run(&["status", "--follow", "--json", "--until-parent-exits"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, "");
}

/// A follow ends, printing nothing, when the daemon's newest status is
/// older than [`FOLLOW_SILENCE`] (its poll has not finished); at exactly
/// that age it is still printed. A one-shot `status` prints it with its
/// time.
#[test]
fn a_stale_status_ends_a_follow_unprinted() {
    let limit = FOLLOW_SILENCE.as_secs();
    let mut harness = harness();
    let daemon = fake_daemon(&harness, vec![available_line(NOW - limit - 1)]);
    let outcome = harness.run(&["status", "--follow", "--json"]);
    daemon.result();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: the daemon's latest status is from 2026-10-13 19:15:59 UTC, more than {limit} s ago: its poll of the M7 has not finished (macOS may be waiting for an answer to a keychain or local network prompt)\n"
        )
    );
    fs::remove_file(RunPaths::under(&harness.support_dir()).socket).unwrap();
    let daemon = fake_daemon(&harness, vec![available_line(NOW - limit)]);
    let outcome = harness.run(&["status", "--follow", "--json"]);
    daemon.result();
    assert_eq!(outcome.stdout, document_of(&available_line(NOW - limit)));
    assert_eq!(
        outcome.stderr,
        "mooringctl: the daemon closed the status stream\n"
    );
    fs::remove_file(RunPaths::under(&harness.support_dir()).socket).unwrap();
    let daemon = fake_daemon(&harness, vec![available_line(NOW - limit - 1)]);
    let outcome = harness.run(&["status"]);
    daemon.result();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .starts_with("status at 2026-10-13 19:15:59 UTC: "),
        "{}",
        outcome.stdout
    );
}

/// A status that is fresh when it comes is printed, and the follow ends
/// once it has grown older than [`FOLLOW_SILENCE`] with nothing newer:
/// each status sets how long the follow waits for the next.
#[test]
fn a_status_that_grows_stale_ends_the_follow() {
    let limit = FOLLOW_SILENCE.as_secs();
    let mut harness = harness();
    // One second short of the limit: stale at the first tick after it.
    let line = available_line(NOW - (limit - 1));
    let daemon = lingering_daemon(&harness, line.clone(), Duration::ZERO, Vec::new());
    let started = std::time::Instant::now();
    let outcome = Running::start(move || harness.run(&["status", "--follow", "--json"])).result();
    daemon.result();
    assert!(started.elapsed() < DEADLINE / 2, "{:?}", started.elapsed());
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, document_of(&line));
    assert!(
        outcome.stderr.starts_with(
            "mooringctl: the daemon's latest status is from 2026-10-13 19:16:01 UTC, more than "
        ),
        "{}",
        outcome.stderr
    );
}

/// A refusal the daemon wrote before it closed is read even when the
/// request can no longer be sent: the busy path's race, made certain.
#[test]
fn a_refusal_written_before_the_daemon_closed_is_read() {
    // The time limit first: setsockopt(2) fails on macOS once the peer has
    // closed.
    let (client, mut daemon) = UnixStream::pair().unwrap();
    let client = bounded(client);
    let busy = encode_line(
        &DaemonReply::Refused {
            reason: Refusal::Busy,
        },
        MAX_REPLY_LINE_BYTES,
    )
    .unwrap();
    daemon.write_all(&busy).unwrap();
    drop(daemon);
    let client = send_request(
        client,
        mooring_daemon_core::control::DaemonRequest::Status,
        Path::new("/s"),
    )
    .unwrap();
    let mut reader = BufReader::new(client);
    let next = read_reply_line(&mut reader, Path::new("/s"), quick_wait(DEADLINE), &|| true);
    assert_eq!(next.unwrap(), Next::Line(busy));
}

/// A busy daemon's refusal reaches the CLI as a refusal, even when the
/// daemon has closed before the request arrived.
#[test]
fn a_busy_daemon_is_reported_as_busy() {
    let mut harness = harness();
    let paths = RunPaths::under(&harness.support_dir());
    fs::create_dir_all(&paths.dir).unwrap();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    let (control, _retries) = control();
    let hub = &control.hub;
    hub.publish(unavailable(1)).unwrap();
    thread::spawn(move || accept(&listener, &control, QUICK, 0));
    for _ in 0..20 {
        let outcome = harness.run(&["status"]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(
            outcome.stderr,
            "mooringctl: the daemon refused the request: it already serves as many clients as it accepts; try again\n"
        );
    }
}

#[test]
fn status_reports_a_refusal_a_closed_stream_and_a_cut_line() {
    let mut harness = harness();
    let refused = encode_line(
        &DaemonReply::Refused {
            reason: Refusal::NoStatusYet,
        },
        MAX_REPLY_LINE_BYTES,
    )
    .unwrap();
    let mut cut = available_line(NOW);
    cut.truncate(cut.len() / 2);
    for (replies, stderr) in [
        (
            vec![refused],
            "mooringctl: the daemon refused the request: its first poll of the M7 has not finished yet\n",
        ),
        (vec![], "mooringctl: the daemon closed the status stream\n"),
        (
            vec![cut],
            "mooringctl: the daemon closed the status stream\n",
        ),
        (
            vec![b"{\"status\":7}\n".to_vec()],
            "mooringctl: the daemon's reply could not be read\n  caused by: a control line is not a well-formed request or reply\n",
        ),
    ] {
        let daemon = fake_daemon(&harness, replies);
        let outcome = harness.run(&["status", "--json"]);
        daemon.result();
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, stderr);
        fs::remove_file(RunPaths::under(&harness.support_dir()).socket).unwrap();
    }
}

/// A deployment's status is printed as JSON; its summary is not built yet.
#[test]
fn a_deployed_status_is_printed_only_as_json() {
    let mut harness = harness();
    let deployed: ConsoleStatus = serde_json::from_slice(include_bytes!(
        "../../../../contract/console-fixtures/deployed.json"
    ))
    .unwrap();
    let line = encode_line(&DaemonReply::Status(deployed), MAX_REPLY_LINE_BYTES).unwrap();
    let daemon = fake_daemon(&harness, vec![line.clone()]);
    let outcome = harness.run(&["status"]);
    daemon.result();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: this build prints a deployment's status only as JSON (use --json)\n"
    );
    fs::remove_file(RunPaths::under(&harness.support_dir()).socket).unwrap();
    let daemon = fake_daemon(&harness, vec![line.clone()]);
    let outcome = harness.run(&["status", "--json"]);
    daemon.result();
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, document_of(&line));
}

/// With no daemon, `status` says so, naming the socket.
#[test]
fn status_without_a_daemon_says_it_is_not_running() {
    let mut harness = harness();
    let socket: PathBuf = RunPaths::under(&harness.support_dir()).socket;
    let outcome = harness.run(&["status"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: the Mooring daemon is not running (nothing listens on {})\n",
            socket.display()
        )
    );
    // A socket file that no one listens on is the same.
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(UnixListener::bind(&socket).unwrap());
    let outcome = harness.run(&["status", "--follow", "--json"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.contains("is not running"),
        "{}",
        outcome.stderr
    );
}

/// A deployment whose state cannot be read stops the daemon, through the
/// command line: it never serves an exit it cannot read. The command opens
/// its log in the home it is given first, and points stderr at it (here a
/// stand-in that counts); its last error still reaches `err`, which in the
/// binary is that log.
#[test]
fn the_daemon_stops_on_a_state_it_cannot_read() {
    let mut harness = harness();
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    fs::write(support.join(STATE_FILE), b"{}").unwrap();
    let log = harness
        .home
        .path()
        .join("Library")
        .join("Logs")
        .join("Mooring")
        .join(LOG_FILE);
    // Read before the harness, and its home, go with the thread.
    let (outcome, redirected, log_mode) = Running::start(move || {
        let outcome = harness.run(&["daemon"]);
        (outcome, harness.redirected.get(), mode(&log))
    })
    .result();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state could not be read"),
        "{}",
        outcome.stderr
    );
    assert_eq!(redirected, 1);
    assert_eq!(log_mode, 0o600);
}
