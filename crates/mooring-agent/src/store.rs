// SPDX-License-Identifier: GPL-3.0-or-later

//! The agent's own state files: written atomically (a temporary file in the
//! same directory, synced, renamed over the old one, the directory synced),
//! read strictly (a file that is not exactly its type is an error, never a
//! default), and serialised by advisory locks.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{AgentError, IoOp};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// An I/O failure on the agent's state, as the protocol reports it.
pub(crate) fn io_error(op: IoOp, error: &io::Error) -> AgentError {
    AgentError::Io {
        op,
        errno: error.raw_os_error(),
    }
}

/// A state file that is not its type: there is no OS error to report.
pub(crate) const fn malformed(op: IoOp) -> AgentError {
    AgentError::Io { op, errno: None }
}

/// The OS error number behind `error`, if it has one: the number a failed
/// write reports in `StateWrite`, or a rollback in its cause.
pub(crate) const fn errno(error: &AgentError) -> Option<i32> {
    match error {
        AgentError::Io { errno, .. } => *errno,
        _ => None,
    }
}

/// The value in `path`, or `None` when there is no such file.
pub(crate) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, AgentError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| malformed(IoOp::ReadState)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(IoOp::ReadState, &error)),
    }
}

/// Writes `value` to `path` atomically with `mode`, creating the directory
/// (mode 0750) if needed.
pub(crate) fn write_json<T: Serialize>(
    path: &Path,
    value: &T,
    mode: u32,
) -> Result<(), AgentError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| malformed(IoOp::WriteState))?;
    bytes.push(b'\n');
    write_atomic(path, &bytes, mode).map_err(|error| io_error(IoOp::WriteState, &error))
}

/// Writes `bytes` to `path` atomically with `mode`.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = parent_of(path)?;
    ensure_dir(dir)?;
    let temporary = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
        std::process::id()
    ));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(dir)?.sync_all()
    })();
    if written.is_err() {
        // The temporary file is the agent's own; its removal can fail only
        // if it was never created, and the original error is what matters.
        let _absent = fs::remove_file(&temporary);
    }
    written
}

/// Removes `path`; a file that is already gone is not an error.
pub(crate) fn remove(path: &Path) -> Result<(), AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    // The directory whose entry goes, synced once it has: a path without
    // one is refused before anything is removed.
    let dir = parent_of(path).map_err(fail)?;
    match fs::remove_file(path) {
        Ok(()) => File::open(dir).and_then(|dir| dir.sync_all()).map_err(fail),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(fail(error)),
    }
}

/// The directory holding `path`; a path with none (`/`) is refused.
pub(crate) fn parent_of(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a state path has no directory"))
}

/// A scratch file holding a secret (a validator's copy of an engine
/// configuration, a stripped tunnel configuration): removed when dropped,
/// whichever way the code that wrote it returns.
#[derive(Debug)]
pub(crate) struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Writes `bytes` to `path` atomically with mode 0600. The file is
    /// removed when the returned value is dropped, and at once if the write
    /// fails after its rename.
    pub(crate) fn write(path: PathBuf, bytes: &[u8]) -> io::Result<Self> {
        let scratch = Self { path };
        write_atomic(&scratch.path, bytes, 0o600)?;
        Ok(scratch)
    }

    /// The file's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A file that was never written is not there to remove.
        let _absent = fs::remove_file(&self.path);
    }
}

/// Creates `dir` and its parents with mode 0750 where missing.
pub(crate) fn ensure_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(dir)
}

/// An exclusive advisory lock, held until dropped.
#[derive(Debug)]
pub(crate) struct Lock {
    file: File,
}

impl Lock {
    /// Waits for the exclusive lock on `path`, creating the file (and its
    /// directory) if needed.
    pub(crate) fn exclusive(path: &Path) -> Result<Self, AgentError> {
        let file = Self::open(path)?;
        file.lock().map_err(lock_error)?;
        Ok(Self { file })
    }

    /// The exclusive lock on `path` if no one holds it; `None` if someone
    /// does.
    pub(crate) fn try_exclusive(path: &Path) -> Result<Option<Self>, AgentError> {
        let file = Self::open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(error)) => Err(lock_error(error)),
        }
    }

    /// Opens the lock file, creating it (and its directory) if needed.
    fn open(path: &Path) -> Result<File, AgentError> {
        ensure_dir(parent_of(path).map_err(lock_error)?).map_err(lock_error)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o660)
            .open(path)
            .map_err(lock_error)
    }
}

fn lock_error(error: io::Error) -> AgentError {
    io_error(IoOp::WriteState, &error)
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Closing the file releases the lock as well; unlocking first only
        // makes the release prompt.
        let _released = self.file.unlock();
    }
}

/// Appends `value` to `out` as one line of JSON, the form of a journal's
/// events. A value that cannot be written leaves part of it in `out`,
/// which the caller then discards.
pub(crate) fn append_json_line<T: Serialize>(
    out: &mut Vec<u8>,
    value: &T,
) -> Result<(), AgentError> {
    serde_json::to_writer(&mut *out, value).map_err(|_| malformed(IoOp::WriteState))?;
    out.push(b'\n');
    Ok(())
}
