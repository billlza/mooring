// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl daemon` (design §5.1, §10.1, §15): the LaunchAgent that
//! runs the exit and the console's polling, and serves the console's
//! status over the control socket.
//!
//! Before a deployment exists it is the router console: it polls the M7
//! every [`POLL_INTERVAL`] on the interface it is given (the same read as
//! `router status`), keeps the latest [`ConsoleStatus`] in the [`hub`],
//! writes it to `status.json`, and serves it on `run/control.sock`
//! ([`serve`]). Once `exit init` has created a deployment it runs the exit
//! ([`deployed`]), at once if the deployment is there when it starts, or
//! from its next poll when one appears.
//!
//! It runs under launchd, which starts it with no ad-hoc-signed ancestor,
//! so the kernel shows it the neighbour table the identity check reads
//! (design §15.6 rule 10). Only it and the CLI read secrets.

pub(crate) mod deployed;
pub(crate) mod hub;
pub(crate) mod serve;

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mooring_daemon_core::RouterStatus;
use mooring_daemon_core::console::{ConsoleStatus, UndeployedStatus};
use mooring_daemon_core::control::{
    CONTROL_SOCKET_FILE, DaemonReply, MAX_REPLY_LINE_BYTES, RUN_DIRECTORY, encode_line,
};
use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};
use mooring_model::iface::BsdName;
use mooring_model::time::UnixTime;
use mooring_store::{STATE_FILE, write_status_snapshot};

use crate::app::Env;
use crate::error::{CommandError, LocalError};
use crate::paths::create_support_dir;
use crate::router;

use self::hub::Hub;
use self::serve::{AcceptFailed, LIMITS, MAX_CLIENTS, accept};

/// How often the M7 is polled (design §15.6 rule 7: a 60 s poll must not
/// lock out the M7's admin session over 24 h, an M5 acceptance).
pub(crate) const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// The daemon's instance lock, in the run directory.
pub(crate) const INSTANCE_LOCK_FILE: &str = "daemon.lock";

/// One poll of the M7: its status, or the failure, whose reason the panel
/// shows and whose error the log names.
pub(crate) type PollOutcome = Result<RouterStatus, CommandError>;

/// The reason the panel shows for a failed poll: the router failure's own,
/// or `LocalFailure` for a failure on the Mac.
pub(crate) fn unavailable_reason(error: &CommandError) -> RouterUnavailableReason {
    match error {
        CommandError::Router(router) => router.reason(),
        CommandError::Local(_) => RouterUnavailableReason::LocalFailure,
    }
}

/// The run directory and the paths in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunPaths {
    /// `run/`, mode 0700.
    pub(crate) dir: PathBuf,
    /// `run/daemon.lock`.
    pub(crate) lock: PathBuf,
    /// `run/control.sock`.
    pub(crate) socket: PathBuf,
}

impl RunPaths {
    /// The run paths under the support directory.
    pub(crate) fn under(support_dir: &Path) -> Self {
        let dir = support_dir.join(RUN_DIRECTORY);
        Self {
            lock: dir.join(INSTANCE_LOCK_FILE),
            socket: dir.join(CONTROL_SOCKET_FILE),
            dir,
        }
    }
}

/// What a started daemon holds: its instance lock (released when the
/// process ends) and its listening socket.
#[derive(Debug)]
pub(crate) struct Started {
    _lock: File,
    /// The control socket.
    pub(crate) listener: UnixListener,
}

/// Prepares the daemon in `support_dir`, in this order, so that nothing is
/// touched unless this process is the one daemon:
/// 1. the support and run directories (mode 0700; a run directory that is
///    there already must be a directory, not a link, and is set to 0700);
/// 2. the instance lock (`DaemonAlreadyRunning` if another daemon holds it);
/// 3. a socket left by an earlier daemon is removed (only a socket: any
///    other file there is `SocketPathTaken` and left as it is), and the
///    control socket is bound, then given mode 0600.
pub(crate) fn start(support_dir: &Path) -> Result<Started, LocalError> {
    create_support_dir(support_dir)?;
    let paths = RunPaths::under(support_dir);
    let run_dir_error = |source| LocalError::RunDir {
        path: paths.dir.clone(),
        source,
    };
    match DirBuilder::new().mode(0o700).create(&paths.dir) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&paths.dir).map_err(run_dir_error)?;
            if !metadata.file_type().is_dir() {
                return Err(LocalError::RunDirNotDirectory { path: paths.dir });
            }
            fs::set_permissions(&paths.dir, fs::Permissions::from_mode(0o700))
                .map_err(run_dir_error)?;
        }
        Err(source) => return Err(run_dir_error(source)),
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&paths.lock)
        .map_err(|source| LocalError::DaemonLock {
            path: paths.lock.clone(),
            source,
        })?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(LocalError::DaemonAlreadyRunning { path: paths.lock });
        }
        Err(TryLockError::Error(source)) => {
            return Err(LocalError::DaemonLock {
                path: paths.lock,
                source,
            });
        }
    }
    let socket_error = |source| LocalError::Socket {
        path: paths.socket.clone(),
        source,
    };
    match fs::symlink_metadata(&paths.socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(&paths.socket).map_err(socket_error)?;
        }
        Ok(_) => return Err(LocalError::SocketPathTaken { path: paths.socket }),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(source) => return Err(socket_error(source)),
    }
    let listener = UnixListener::bind(&paths.socket).map_err(socket_error)?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600)).map_err(socket_error)?;
    Ok(Started {
        _lock: lock,
        listener,
    })
}

/// Whether `state.json` exists.
pub(crate) fn deployment_exists(support_dir: &Path) -> Result<bool, LocalError> {
    let state = support_dir.join(STATE_FILE);
    match fs::symlink_metadata(&state) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(LocalError::StateInspect {
            path: state,
            source,
        }),
    }
}

/// What the control socket's connections share with the daemon's loop:
/// the latest status, the retries asked for, and whether a deployment is
/// served (a retry is refused without one).
#[derive(Debug)]
pub(crate) struct Control {
    /// The latest status.
    pub(crate) hub: Hub,
    /// `exit retry`s, for the loop's next tick.
    pub(crate) retry: mpsc::Sender<()>,
    /// Whether the loop serves a deployment.
    pub(crate) deployed: AtomicBool,
}

/// What the poll loop carries from one poll to the next.
#[derive(Debug, Default)]
pub(crate) struct LoopState {
    /// The panel after the previous poll.
    pub(crate) previous: Option<RouterReading>,
    /// The last failure logged, so a failure that repeats every poll is
    /// logged once, and again only when it changes or after a success.
    pub(crate) last_failure: Option<String>,
    /// Why `status.json` could not be written, while that lasts, logged
    /// the same way.
    pub(crate) snapshot_failure: Option<String>,
}

/// Publishes `status` in the hub and writes it to `status.json`. A
/// snapshot that cannot be written is logged once while that lasts, and
/// its recovery is logged too; it is for diagnosis only, so not fatal.
pub(crate) fn publish(
    hub: &Hub,
    support_dir: &Path,
    log: &mut dyn Write,
    snapshot_failure: &mut Option<String>,
    status: &ConsoleStatus,
    now: UnixTime,
) -> Result<(), CommandError> {
    let line = encode_line(&DaemonReply::Status(status.clone()), MAX_REPLY_LINE_BYTES)
        .map_err(LocalError::StatusEncode)?;
    hub.publish(Arc::from(line))
        .map_err(|_| LocalError::StatusPoisoned)?;
    // The snapshot is the document itself, as `status --json` prints it.
    let document = encode_line(status, MAX_REPLY_LINE_BYTES).map_err(LocalError::StatusEncode)?;
    match write_status_snapshot(support_dir, &document) {
        Ok(()) => {
            if snapshot_failure.take().is_some() {
                say(log, now, "status.json written again")?;
            }
        }
        Err(error) => {
            let text = chain(&error);
            if snapshot_failure.as_deref() != Some(text.as_str()) {
                say(log, now, &format!("status.json not written: {text}"))?;
                *snapshot_failure = Some(text);
            }
        }
    }
    Ok(())
}

/// The panel after a poll at `polled_at` that ended in `outcome`, with the
/// log line a changed outcome gets (a new or different failure, or the
/// first success after none).
pub(crate) fn router_after_poll(
    log: &mut dyn Write,
    previous: Option<&RouterReading>,
    last_failure: &mut Option<String>,
    polled_at: UnixTime,
    outcome: &PollOutcome,
    now: UnixTime,
) -> Result<RouterReading, CommandError> {
    let result = match outcome {
        Ok(status) => Ok(status.clone()),
        Err(error) => Err(unavailable_reason(error)),
    };
    let reading = RouterReading::after_poll(previous, polled_at, result);
    match outcome {
        Err(error) => {
            let text = chain(error);
            if last_failure.as_deref() != Some(text.as_str()) {
                say(log, now, &format!("router poll failed: {text}"))?;
                *last_failure = Some(text);
            }
        }
        Ok(_) => {
            if !matches!(previous, Some(RouterReading::Available { .. })) {
                say(log, now, "router poll succeeded")?;
            }
            *last_failure = None;
        }
    }
    Ok(reading)
}

/// What follows a poll at `polled_at` that ended in `outcome`, at `now`,
/// before a deployment exists: the panel after it is published in a
/// status and written to `status.json`, and the log gets a line if the
/// outcome changed.
pub(crate) fn after_poll(
    hub: &Hub,
    support_dir: &Path,
    log: &mut dyn Write,
    state: &mut LoopState,
    polled_at: UnixTime,
    outcome: &PollOutcome,
    now: UnixTime,
) -> Result<(), CommandError> {
    let reading = router_after_poll(
        log,
        state.previous.as_ref(),
        &mut state.last_failure,
        polled_at,
        outcome,
        now,
    )?;
    let status = ConsoleStatus::NoDeployment(UndeployedStatus::new(now, reading.clone()));
    publish(
        hub,
        support_dir,
        log,
        &mut state.snapshot_failure,
        &status,
        now,
    )?;
    state.previous = Some(reading);
    Ok(())
}

/// One poll of the M7 on `interface` (none given: `NotConfigured`).
pub(crate) fn poll_router(
    env: &Env<'_>,
    support_dir: &Path,
    interface: Option<&BsdName>,
) -> PollOutcome {
    match interface {
        Some(interface) => router::status(&env.router, support_dir, &*env.secrets, interface),
        None => Err(CommandError::Router(
            router::error::RouterError::NotConfigured {
                missing: router::error::Missing::Interface,
            },
        )),
    }
}

/// How a turn of the router console's loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Polled {
    /// The M7 was polled and the status published.
    Published,
    /// A deployment has appeared: nothing was polled, and the daemon runs
    /// the exit from now on.
    DeploymentAppeared,
}

/// One turn of the router console: if a deployment has appeared since the
/// last, nothing else; otherwise a poll of the M7 on `interface` and what
/// follows it ([`after_poll`]).
pub(crate) fn poll_once(
    env: &mut Env<'_>,
    support_dir: &Path,
    interface: Option<&BsdName>,
    hub: &Hub,
    log: &mut dyn Write,
    state: &mut LoopState,
) -> Result<Polled, CommandError> {
    if deployment_exists(support_dir)? {
        return Ok(Polled::DeploymentAppeared);
    }
    let polled_at = (env.clock)()?;
    let outcome = poll_router(env, support_dir, interface);
    let now = (env.clock)()?;
    after_poll(hub, support_dir, log, state, polled_at, &outcome, now)?;
    Ok(Polled::Published)
}

/// How the wait for the next poll ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Waited {
    /// It is time for the next poll.
    Elapsed,
    /// The acceptor ended, so the control socket accepts no one: the
    /// daemon stops at once rather than at its next poll.
    AcceptorEnded,
}

/// Waits until `until`, or until the acceptor ends: it says so on
/// `acceptor_ended`, or drops its sender when it panics.
pub(crate) fn wait_for_next_poll(until: Instant, acceptor_ended: &mpsc::Receiver<()>) -> Waited {
    match acceptor_ended.recv_timeout(until.saturating_duration_since(Instant::now())) {
        Err(mpsc::RecvTimeoutError::Timeout) => Waited::Elapsed,
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Waited::AcceptorEnded,
    }
}

/// `mooringctl daemon [--router-interface <bsd>]`: starts, then serves
/// until it fails: as the router console until a deployment exists, then
/// as the exit. It never returns `Ok`.
pub(crate) fn run(
    env: &mut Env<'_>,
    log: &mut dyn Write,
    interface: Option<&BsdName>,
) -> Result<(), CommandError> {
    let support_dir = crate::app::support_dir(env)?;
    let started = start(&support_dir)?;
    let (retry, retries) = mpsc::channel();
    let control = Arc::new(Control {
        hub: Hub::default(),
        retry,
        deployed: AtomicBool::new(false),
    });
    let (acceptor, acceptor_ended) = spawn_acceptor(started.listener, &control)?;
    let begun = (env.clock)()?;
    let mut state = LoopState::default();
    if !deployment_exists(&support_dir)? {
        say(
            log,
            begun,
            &match interface {
                Some(interface) => format!(
                    "daemon started: polling the M7 on {} every {} s",
                    interface.as_str(),
                    POLL_INTERVAL.as_secs()
                ),
                None => {
                    "daemon started: no router interface given, so the M7 is not polled".to_owned()
                }
            },
        )?;
        loop {
            let next = Instant::now() + POLL_INTERVAL;
            if poll_once(env, &support_dir, interface, &control.hub, log, &mut state)?
                == Polled::DeploymentAppeared
            {
                say(log, (env.clock)()?, "a deployment exists: serving the exit")?;
                break;
            }
            if wait_for_next_poll(next, &acceptor_ended) == Waited::AcceptorEnded {
                return Err(CommandError::Local(acceptor_end(acceptor)));
            }
        }
    }
    let ended = deployed::serve(
        env,
        log,
        &support_dir,
        &control,
        &acceptor_ended,
        &retries,
        state,
    );
    match ended {
        Err(error) => Err(error),
        Ok(deployed::Stopped::AcceptorEnded) => Err(CommandError::Local(acceptor_end(acceptor))),
    }
}

/// Starts the acceptor, which says on the returned channel when it ends.
fn spawn_acceptor(
    listener: UnixListener,
    control: &Arc<Control>,
) -> Result<(JoinHandle<AcceptFailed>, mpsc::Receiver<()>), LocalError> {
    let control = Arc::clone(control);
    let (ended, acceptor_ended) = mpsc::channel();
    let acceptor = thread::Builder::new()
        .name("mooring-accept".to_owned())
        .spawn(move || {
            let failed = accept(&listener, &control, LIMITS, MAX_CLIENTS);
            // The poll loop has stopped if no one receives this.
            let _ = ended.send(());
            failed
        })
        .map_err(LocalError::Acceptor)?;
    Ok((acceptor, acceptor_ended))
}

/// Why the acceptor ended: its error, or that it panicked.
fn acceptor_end(acceptor: JoinHandle<AcceptFailed>) -> LocalError {
    match acceptor.join() {
        Ok(AcceptFailed(error)) => LocalError::Acceptor(error),
        Err(_) => LocalError::Acceptor(std::io::Error::other("the acceptor thread panicked")),
    }
}

/// An error and its causes on one line.
pub(crate) fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// Writes one log line, stamped `at` in UTC.
pub(crate) fn say(log: &mut dyn Write, at: UnixTime, text: &str) -> Result<(), CommandError> {
    let stamp =
        router::output::utc_stamp(at).map_err(|_| CommandError::Local(LocalError::Clock))?;
    writeln!(log, "{stamp} mooringctl daemon: {text}")
        .and_then(|()| log.flush())
        .map_err(|error| CommandError::Local(LocalError::Output(error)))
}
