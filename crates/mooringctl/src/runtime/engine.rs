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
use std::thread;
use std::time::{Duration, Instant};

use crate::node::ssh::escaped;

/// How long `check` may take.
pub(crate) const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Waiting for or signalling the child failed.
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
        let mut command = self.command("check");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = self.spawn(command)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(EngineError::Wait(io::Error::other(
                "the engine's stdin is missing",
            )))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or(EngineError::Wait(io::Error::other(
                "the engine's stderr is missing",
            )))?;
        let errors = thread::spawn(move || {
            let mut kept = Vec::new();
            let mut chunk = [0_u8; 4096];
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => return kept,
                    Ok(read) => {
                        let room = MAX_CHECK_STDERR_BYTES.saturating_sub(kept.len());
                        kept.extend_from_slice(&chunk[..read.min(room)]);
                    }
                }
            }
        });
        let written = stdin.write_all(config).and_then(|()| stdin.flush());
        drop(stdin);
        let status = wait_for(&mut child, CHECK_TIMEOUT)?;
        let stderr = errors
            .join()
            .map_err(|_| EngineError::Wait(io::Error::other("the stderr reader panicked")))?;
        match status {
            None => Err(EngineError::CheckTimeout),
            Some(status) if status.success() => written.map_err(EngineError::Config),
            Some(status) => Err(EngineError::Rejected {
                code: status.code(),
                stderr: escaped(&stderr),
            }),
        }
    }

    /// `run -c stdin` with `config` on its stdin, closed after it.
    pub(crate) fn start(&self, config: &[u8]) -> Result<Running, EngineError> {
        let mut command = self.command("run");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = self.spawn(command)?;
        let written = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("the engine's stdin is missing"))
            .and_then(|mut stdin| stdin.write_all(config).and_then(|()| stdin.flush()));
        let running = Running { child };
        match written {
            Ok(()) => Ok(running),
            Err(error) => {
                // An engine that did not take its config is stopped at once.
                running.stop()?;
                Err(EngineError::Config(error))
            }
        }
    }
}

/// Waits for `child` up to `timeout`; a child still running then is
/// killed, and `None` says so.
fn wait_for(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>, EngineError> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(EngineError::Wait)? {
            return Ok(Some(status));
        }
        if started.elapsed() >= timeout {
            child.kill().map_err(EngineError::Wait)?;
            child.wait().map_err(EngineError::Wait)?;
            return Ok(None);
        }
        thread::sleep(WAIT_STEP);
    }
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

    /// Its exit status, once it has exited.
    pub(crate) fn exited(&mut self) -> Result<Option<ExitStatus>, EngineError> {
        self.child.try_wait().map_err(EngineError::Wait)
    }

    /// Stops it (SIGKILL) and reaps it; one that exited already is reaped.
    pub(crate) fn stop(mut self) -> Result<ExitStatus, EngineError> {
        if let Some(status) = self.child.try_wait().map_err(EngineError::Wait)? {
            return Ok(status);
        }
        match self.child.kill() {
            Ok(()) => {}
            // It exited between the two calls.
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            Err(error) => return Err(EngineError::Wait(error)),
        }
        self.child.wait().map_err(EngineError::Wait)
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
