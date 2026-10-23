// SPDX-License-Identifier: GPL-3.0-or-later

//! The power helper (design §5.1, §10.3): `mooring-power`, which the app's
//! bundle carries beside `mooringctl` (`Contents/MacOS/mooring-power`), as
//! a child of the deployed daemon. Its stdout is read on a thread of its
//! own, one event per line ([`HelperEvent`]), into a channel the loop
//! drains at each tick; its stdin carries the daemon's commands
//! ([`HelperCommand`]) and is its lifetime: when the daemon ends, or closes
//! the link, the pipe closes and the helper releases its assertions and
//! exits; the link then reaps it, killing one that does not exit within
//! [`HELPER_EXIT_WAIT`], so no helper is left a zombie. The helper's stderr
//! is the daemon's, which is the daemon's log.
//!
//! It replaces the reading of `/usr/bin/pmset -g ps` every 60 s, which ran
//! until M7.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mooring_daemon_core::power::{
    HelperCommand, HelperEvent, MAX_HELPER_LINE_BYTES, decode_event, encode_command,
};

use crate::error::LocalError;

/// The helper's file name, beside `mooringctl`.
pub(crate) const HELPER: &str = "mooring-power";

/// How long a closed link waits for its helper to exit before it kills it:
/// the helper exits as soon as its input ends.
pub(crate) const HELPER_EXIT_WAIT: Duration = Duration::from_secs(1);

/// How often the closed link looks whether its helper has exited.
const EXIT_POLL: Duration = Duration::from_millis(10);

/// What the reader thread passes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PowerMessage {
    /// One event.
    Event(HelperEvent),
    /// The helper's output ended, or a line could not be read: no event
    /// follows. The text says which.
    Ended(String),
}

/// A running helper, as the loop uses it.
pub(crate) struct PowerLink {
    /// Its events, in order.
    pub(crate) messages: mpsc::Receiver<PowerMessage>,
    commands: Box<dyn Write + Send>,
    child: Option<Child>,
}

impl std::fmt::Debug for PowerLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PowerLink")
            .field("child", &self.child.as_ref().map(Child::id))
            .finish_non_exhaustive()
    }
}

impl PowerLink {
    /// A link over `messages` and `commands`, for the helper `child` if it
    /// is a process (tests pass channels and none).
    pub(crate) fn new(
        messages: mpsc::Receiver<PowerMessage>,
        commands: Box<dyn Write + Send>,
        child: Option<Child>,
    ) -> Self {
        Self {
            messages,
            commands,
            child,
        }
    }

    /// Writes `command` as one line.
    pub(crate) fn send(&mut self, command: &HelperCommand) -> Result<(), LocalError> {
        let line = encode_command(command).map_err(LocalError::PowerHelperLine)?;
        self.commands
            .write_all(&line)
            .and_then(|()| self.commands.flush())
            .map_err(LocalError::PowerHelperWrite)
    }

    /// Closes the helper's stdin, which ends it, and reaps it (see
    /// [`reap`]); says how it ended, for the log.
    pub(crate) fn close(mut self) -> String {
        self.commands = Box::new(io::sink());
        match self.child.take() {
            Some(mut child) => reap(&mut child, HELPER_EXIT_WAIT),
            None => "no process".to_owned(),
        }
    }
}

impl Drop for PowerLink {
    /// A link dropped unclosed, as the daemon's own end drops it, closes
    /// and reaps all the same; how the helper ended is the daemon's log's
    /// no longer.
    fn drop(&mut self) {
        self.commands = Box::new(io::sink());
        if let Some(mut child) = self.child.take() {
            reap(&mut child, HELPER_EXIT_WAIT);
        }
    }
}

/// Reaps `child`, whose input has closed: it has `wait` to exit, and is
/// killed past it. Says how it ended.
pub(crate) fn reap(child: &mut Child, wait: Duration) -> String {
    let until = Instant::now() + wait;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return format!("{status}"),
            Ok(None) if Instant::now() < until => thread::sleep(EXIT_POLL),
            Ok(None) => break,
            Err(error) => return format!("it could not be waited for: {error}"),
        }
    }
    match child.kill().and_then(|()| child.wait()) {
        Ok(status) => format!("killed after {wait:?}: {status}"),
        Err(error) => format!("it did not exit within {wait:?} and could not be killed: {error}"),
    }
}

/// The helper beside `executable`.
pub(crate) fn helper_path(executable: &Path) -> PathBuf {
    executable.with_file_name(HELPER)
}

/// Starts the helper beside this executable.
pub(crate) fn spawn() -> Result<PowerLink, LocalError> {
    let executable = std::env::current_exe().map_err(LocalError::PowerHelperPath)?;
    spawn_at(&helper_path(&executable))
}

/// Starts the helper at `path`.
pub(crate) fn spawn_at(path: &Path) -> Result<PowerLink, LocalError> {
    let spawn_error = |source| LocalError::PowerHelperSpawn {
        path: path.to_path_buf(),
        source,
    };
    let mut child = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(spawn_error)?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        // `spawn` gives both pipes when both are asked for; without them
        // the helper cannot be talked to, so it is ended.
        let _ = child.kill();
        return Err(spawn_error(io::Error::other("no pipe to the helper")));
    };
    let (sender, messages) = mpsc::channel();
    thread::Builder::new()
        .name("mooring-power".to_owned())
        .spawn(move || read_events(stdout, &sender))
        .map_err(spawn_error)?;
    Ok(PowerLink::new(messages, Box::new(stdin), Some(child)))
}

/// Reads `stdout` to its end, one event per line, and passes each on, then
/// why the reading ended.
fn read_events(stdout: ChildStdout, sender: &mpsc::Sender<PowerMessage>) {
    let ended = read_lines(BufReader::new(stdout), |event| {
        sender.send(PowerMessage::Event(event)).is_ok()
    });
    // The loop has stopped if no one receives this.
    let _ = sender.send(PowerMessage::Ended(ended));
}

/// Reads `reader` line by line, passing each event to `deliver` while it
/// returns `true`, and returns why the reading ended: the end of the
/// output, a line that is not an event or is longer than the protocol's
/// bound, or a read that failed.
pub(crate) fn read_lines(
    mut reader: impl BufRead,
    mut deliver: impl FnMut(HelperEvent) -> bool,
) -> String {
    // usize to u64 is lossless on every target.
    let limit = MAX_HELPER_LINE_BYTES as u64;
    let mut line = Vec::with_capacity(MAX_HELPER_LINE_BYTES);
    loop {
        line.clear();
        match (&mut reader).take(limit).read_until(b'\n', &mut line) {
            Ok(0) => return "the power helper exited".to_owned(),
            Ok(_) if line.last() != Some(&b'\n') => {
                return if line.len() >= MAX_HELPER_LINE_BYTES {
                    "the power helper wrote a line longer than its protocol allows".to_owned()
                } else {
                    "the power helper's output ended within a line".to_owned()
                };
            }
            Ok(_) => match decode_event(&line) {
                Ok(event) => {
                    if !deliver(event) {
                        return "the daemon stopped reading the power helper".to_owned();
                    }
                }
                Err(error) => {
                    return format!("the power helper wrote a line that is not an event: {error}");
                }
            },
            Err(error) => return format!("the power helper's output could not be read: {error}"),
        }
    }
}
