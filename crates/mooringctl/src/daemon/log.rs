// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's log (design §15.10): `~/Library/Logs/Mooring/daemon.log`,
//! one line per event, appended. Once it holds [`ROTATE_AT_BYTES`] it is
//! renamed `daemon.log.1`, replacing the one before, and a new file is
//! begun at the next line, so the log takes at most two files of about
//! 5 MiB. Standard error points at the open file, so the daemon's last
//! error, which `main` prints, and a panic's message are kept in it too:
//! launchd gives an agent registered with `SMAppService` no log of its own
//! (design §5.1), and its plist names none.
//!
//! The lines carry times and states only, never a secret, a destination or
//! a user (design §15.5); the files are 0600 in a 0700 directory.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use mooring_macsys::MacsysError;

use crate::error::LocalError;

/// The log's file name.
pub(crate) const LOG_FILE: &str = "daemon.log";

/// The file the log is renamed to when it rotates.
pub(crate) const ROTATED_LOG_FILE: &str = "daemon.log.1";

/// The size at which the log rotates, at the next line's start.
pub(crate) const ROTATE_AT_BYTES: u64 = 5 * 1024 * 1024;

/// Points standard error at a file: `mooring_macsys::redirect_stderr`, or a
/// stand-in in tests, which must leave the test process's stderr alone.
pub(crate) type RedirectStderr<'a> = dyn Fn(BorrowedFd<'_>) -> Result<(), MacsysError> + 'a;

/// The log directory under `home`, which must be an absolute path (`Home`
/// otherwise): `~/Library/Logs/Mooring`.
pub(crate) fn log_dir(home: Option<OsString>) -> Result<PathBuf, LocalError> {
    let home = PathBuf::from(home.ok_or(LocalError::Home)?);
    if !home.is_absolute() {
        return Err(LocalError::Home);
    }
    Ok(home.join("Library").join("Logs").join("Mooring"))
}

/// The open log.
pub(crate) struct DaemonLog<'r> {
    dir: PathBuf,
    file: File,
    /// The bytes in the current file.
    written: u64,
    rotate_at: u64,
    /// Whether the next byte begins a line: the log rotates only there, so
    /// no line is split across the two files.
    at_line_start: bool,
    redirect: &'r RedirectStderr<'r>,
}

impl std::fmt::Debug for DaemonLog<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonLog")
            .field("dir", &self.dir)
            .field("written", &self.written)
            .field("rotate_at", &self.rotate_at)
            .finish_non_exhaustive()
    }
}

impl<'r> DaemonLog<'r> {
    /// Opens the log in `dir` (created with mode 0700 if missing), appending
    /// to a file that is there, and points standard error at it.
    pub(crate) fn open(
        dir: &Path,
        rotate_at: u64,
        redirect: &'r RedirectStderr<'r>,
    ) -> Result<Self, LocalError> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|source| LocalError::LogDir {
                path: dir.to_path_buf(),
                source,
            })?;
        let file = open_file(dir)?;
        let written = file
            .metadata()
            .map_err(|source| LocalError::LogFile {
                path: dir.join(LOG_FILE),
                source,
            })?
            .len();
        redirect(file.as_fd()).map_err(LocalError::LogRedirect)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            file,
            written,
            rotate_at,
            at_line_start: true,
            redirect,
        })
    }

    /// Renames the current file `daemon.log.1`, replacing the earlier one,
    /// and begins a new file, to which standard error then points.
    fn rotate(&mut self) -> io::Result<()> {
        fs::rename(self.dir.join(LOG_FILE), self.dir.join(ROTATED_LOG_FILE))?;
        self.file = open_file(&self.dir).map_err(io::Error::other)?;
        (self.redirect)(self.file.as_fd()).map_err(io::Error::other)?;
        self.written = 0;
        Ok(())
    }
}

/// `daemon.log` in `dir`, opened for appending (created with mode 0600).
fn open_file(dir: &Path) -> Result<File, LocalError> {
    let path = dir.join(LOG_FILE);
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .map_err(|source| LocalError::LogFile { path, source })
}

impl Write for DaemonLog<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.at_line_start && self.written >= self.rotate_at {
            self.rotate()?;
        }
        let count = self.file.write(buf)?;
        self.written = self.written.saturating_add(count as u64);
        if let Some(last) = buf[..count].last() {
            self.at_line_start = *last == b'\n';
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
