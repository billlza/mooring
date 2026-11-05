// SPDX-License-Identifier: GPL-3.0-or-later

//! An engine the daemon runs (design §5.1, §10.1): `mooring-exit` or
//! `mooring-probe`. Its config holds private keys, so it lives in memory
//! only: `check -c stdin` validates it, then `run -c stdin` starts the
//! engine with the config on its stdin, which is closed after it. A running
//! engine is stopped with SIGKILL: it keeps no state, and a node's gate
//! closes within three keepalives once the tunnel stops (design §10.2).

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::node::ssh::escaped;

/// How long `check` may take.
pub(crate) const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a started engine may take to accept its configuration pipe.
pub(crate) const START_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a waiting call looks at the child again.
const WAIT_STEP: Duration = Duration::from_millis(20);

/// The most stderr bytes kept from `check`.
const MAX_CHECK_STDERR_BYTES: usize = 4096;

/// Why an engine did not check, start or stop.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EngineError {
    /// The binary could not be started.
    #[error("cannot start {}", path.display())]
    Spawn {
        /// The binary.
        path: PathBuf,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// `check` refused the config.
    #[error("the engine refused its config (exit status {}):\n{stderr}", code.map_or_else(|| "none".to_owned(), |code| code.to_string()))]
    Rejected {
        /// Its exit status, if it exited.
        code: Option<i32>,
        /// Its stderr, escaped and capped.
        stderr: String,
    },
    /// `check` did not finish in time and was killed.
    #[error("the engine's config check did not finish within {} s", CHECK_TIMEOUT.as_secs())]
    CheckTimeout,
    /// Waiting for, signalling or reading the child's output failed.
    #[error("waiting for the engine failed")]
    Wait(#[source] io::Error),
    /// The config could not be written to the engine.
    #[error("the engine did not take its config")]
    Config(#[source] io::Error),
}

/// An engine binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Engine {
    binary: PathBuf,
}

impl Engine {
    pub(crate) fn new(binary: &Path) -> Self {
        Self {
            binary: binary.to_path_buf(),
        }
    }

    fn command(&self, verb: &str) -> Command {
        let mut command = Command::new(&self.binary);
        command.args([verb, "-c", "stdin"]);
        command
    }

    fn spawn(&self, mut command: Command) -> Result<Child, EngineError> {
        command.spawn().map_err(|source| EngineError::Spawn {
            path: self.binary.clone(),
            source,
        })
    }

    /// `check -c stdin` with `config`: it must exit 0 within
    /// [`CHECK_TIMEOUT`].
    pub(crate) fn check(&self, config: &[u8]) -> Result<(), EngineError> {
        self.check_within(config, CHECK_TIMEOUT)
    }

    /// [`Self::check`] within `limit`: a check still running then is killed
    /// and is [`EngineError::CheckTimeout`].
    pub(crate) fn check_within(&self, config: &[u8], limit: Duration) -> Result<(), EngineError> {
        let started = Instant::now();
        let mut command = self.command("check");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        thread::scope(|scope| {
            // The guard is inside the scope: an early error stops the child
            // before the scope joins either of its pipe workers.
            let mut running = Running {
                child: self.spawn(command)?,
            };
            let mut stdin =
                running
                    .child
                    .stdin
                    .take()
                    .ok_or(EngineError::Wait(io::Error::other(
                        "the engine's stdin is missing",
                    )))?;
            let mut stderr =
                running
                    .child
                    .stderr
                    .take()
                    .ok_or(EngineError::Wait(io::Error::other(
                        "the engine's stderr is missing",
                    )))?;
            let errors = scope.spawn(move || read_check_stderr(&mut stderr));
            // Borrow the secret-bearing config; do not make another copy.
            let writer = scope.spawn(move || stdin.write_all(config).and_then(|()| stdin.flush()));
            let status = wait_for(&mut running.child, started, limit)?;
            let written = writer
                .join()
                .map_err(|_| EngineError::Wait(io::Error::other("the config writer panicked")))?;
            let stderr = errors
                .join()
                .map_err(|_| EngineError::Wait(io::Error::other("the stderr reader panicked")))?
                .map_err(EngineError::Wait)?;
            match status {
                None => Err(EngineError::CheckTimeout),
                Some(status) if status.success() => written.map_err(EngineError::Config),
                Some(status) => Err(EngineError::Rejected {
                    code: status.code(),
                    stderr: escaped(&stderr),
                }),
            }
        })
    }

    /// `run -c stdin` with `config` on its stdin, closed after it.
    pub(crate) fn start(&self, config: &[u8]) -> Result<Running, EngineError> {
        self.start_within(config, START_TIMEOUT)
    }

    /// Delivers the config within `limit`; a stalled delivery is a timed
    /// out config write, and the child is killed and reaped before return.
    pub(crate) fn start_within(
        &self,
        config: &[u8],
        limit: Duration,
    ) -> Result<Running, EngineError> {
        let started = Instant::now();
        let mut command = self.command("run");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        thread::scope(|scope| {
            let mut running = Running {
                child: self.spawn(command)?,
            };
            let mut stdin =
                running
                    .child
                    .stdin
                    .take()
                    .ok_or(EngineError::Config(io::Error::other(
                        "the engine's stdin is missing",
                    )))?;
            let (sent, received) = mpsc::sync_channel(1);
            let writer = scope.spawn(move || {
                let written = stdin.write_all(config).and_then(|()| stdin.flush());
                drop(stdin);
                // The supervisor may already have failed and left.
                let _ = sent.send(written);
            });
            let result = received.recv_timeout(limit.saturating_sub(started.elapsed()));
            if !matches!(result, Ok(Ok(()))) {
                stop_child(&mut running.child).map_err(EngineError::Wait)?;
            }
            writer
                .join()
                .map_err(|_| EngineError::Wait(io::Error::other("the config writer panicked")))?;
            match result {
                Ok(Ok(())) => Ok(running),
                Ok(Err(error)) => Err(EngineError::Config(error)),
                Err(mpsc::RecvTimeoutError::Timeout) => Err(EngineError::Config(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the engine did not read its config before the startup deadline",
                ))),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(EngineError::Wait(
                    io::Error::other("the config writer stopped without reporting"),
                )),
            }
        })
    }
}

/// Drain stderr so the child cannot block on it, retaining only the
/// diagnostic bound. A read failure remains a failure, not empty output.
pub(crate) fn read_check_stderr(reader: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(kept);
        }
        let room = MAX_CHECK_STDERR_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..read.min(room)]);
    }
}

/// Waits for `child` up to `timeout`; a child still running then is
/// killed, and `None` says so.
fn wait_for(
    child: &mut Child,
    started: Instant,
    timeout: Duration,
) -> Result<Option<ExitStatus>, EngineError> {
    loop {
        if let Some(status) = child.try_wait().map_err(EngineError::Wait)? {
            return Ok(Some(status));
        }
        if started.elapsed() >= timeout {
            stop_child(child).map_err(EngineError::Wait)?;
            return Ok(None);
        }
        thread::sleep(WAIT_STEP);
    }
}

/// Stops and reaps an owned child, including one that exited meanwhile.
fn stop_child(child: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error),
    }
    child.wait()
}

/// A started engine.
#[derive(Debug)]
pub(crate) struct Running {
    child: Child,
}

impl Running {
    /// Its process id.
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Its exit status, once it has exited. Only waiting can fail here.
    pub(crate) fn exited(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Stops it (SIGKILL) and reaps it; one that exited already is reaped.
    /// Only waiting for it or signalling it can fail here.
    pub(crate) fn stop(mut self) -> io::Result<ExitStatus> {
        stop_child(&mut self.child)
    }
}

impl Drop for Running {
    /// An engine whose handle goes (the daemon is ending on an error) is
    /// stopped with it: an engine never runs without its supervisor. Errors
    /// here have nowhere to go; one stopped or reaped already is left.
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
