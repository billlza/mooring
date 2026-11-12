// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's log (design §15.10): `~/Library/Logs/Mooring/daemon.log`,
//! one line per event, appended. Once it holds [`ROTATE_AT_BYTES`] it is
//! renamed `daemon.log.1`, replacing the one before, and a new file is
//! begun at the next line, so the log takes at most two files of about
//! 5 MiB. Standard error points at the open file, so the daemon's last
//! error, which `main` prints, and a panic's message are kept in it too:
//! launchd gives an agent registered with `SMAppService` no log of its own
//! (design §5.1), and its plist names none. The apply job keeps
//! `apply.log` beside it the same way ([`APPLY_LOG`], design §13.6).
//!
//! The lines carry times and states only, never a secret, a destination or
//! a user (design §15.5); the files are 0600 in a 0700 directory. A file
//! or a directory created here gets that mode; one found with another
//! mode is set back to it when the log opens, and the open records what
//! it set back ([`RotatingLog::restored`]), for the log's first lines.
//! *2026-11-12:* until then a mode was given only at creation, so
//! `daemon.log` stayed 0644 on the operator's Mac: launchd had created it
//! for the development LaunchAgent of 2026-10-22, whose
//! `StandardErrorPath` named it (design §15.10).

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mooring_macsys::MacsysError;

use crate::error::LocalError;

/// The log's file name.
pub(crate) const LOG_FILE: &str = "daemon.log";

/// The file the log is renamed to when it rotates.
pub(crate) const ROTATED_LOG_FILE: &str = "daemon.log.1";

/// The size at which the log rotates, at the next line's start.
pub(crate) const ROTATE_AT_BYTES: u64 = 5 * 1024 * 1024;

/// The mode of each log file: the owner's alone.
const FILE_MODE: u32 = 0o600;

/// The mode of the log directory: the owner's alone.
const DIR_MODE: u32 = 0o700;

/// The bits of a mode the log sets: the permissions, and the set-id and
/// sticky bits, which it clears.
const MODE_BITS: u32 = 0o7777;

/// A mode the log's open set back: the directory, the file written or the
/// rotated file was found with another mode than the design's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModeRestored {
    /// What had it: a file's name, or "the log directory".
    pub(crate) name: String,
    /// The mode found.
    pub(crate) was: u32,
    /// The mode set.
    pub(crate) now: u32,
}

impl ModeRestored {
    /// The log's line that says so; it names a file only.
    pub(crate) fn line(&self) -> String {
        format!(
            "{} had mode {:04o}; set to {:04o}",
            self.name, self.was, self.now
        )
    }
}

/// A log's two files: the one written, and the one it is renamed to when
/// it rotates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogFiles {
    /// The file written.
    pub(crate) name: &'static str,
    /// The file it becomes when it rotates.
    pub(crate) rotated: &'static str,
}

/// The daemon's log.
pub(crate) const DAEMON_LOG: LogFiles = LogFiles {
    name: LOG_FILE,
    rotated: ROTATED_LOG_FILE,
};

/// The apply job's log (design §13.6).
pub(crate) const APPLY_LOG: LogFiles = LogFiles {
    name: "apply.log",
    rotated: "apply.log.1",
};

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

/// An open log.
pub(crate) struct RotatingLog<'r> {
    dir: PathBuf,
    files: LogFiles,
    file: File,
    /// The bytes in the current file.
    written: u64,
    rotate_at: u64,
    /// Whether the next byte begins a line: the log rotates only there, so
    /// no line is split across the two files.
    at_line_start: bool,
    redirect: &'r RedirectStderr<'r>,
    /// The modes the open set back.
    restored: Vec<ModeRestored>,
}

impl std::fmt::Debug for RotatingLog<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingLog")
            .field("dir", &self.dir)
            .field("files", &self.files)
            .field("written", &self.written)
            .field("rotate_at", &self.rotate_at)
            .finish_non_exhaustive()
    }
}

impl<'r> RotatingLog<'r> {
    /// Opens the log `files` in `dir`, appending to a file that is there,
    /// and points standard error at it. The directory (created with mode
    /// 0700 if missing), the file (created with mode 0600) and a rotated
    /// file that is there are each set back to the design's mode if found
    /// with another ([`Self::restored`]); a link where the rotated file
    /// goes is left as it is, since the log never writes through it. A mode
    /// that cannot be set stops the open, as a file that cannot be opened
    /// does.
    pub(crate) fn open(
        dir: &Path,
        files: LogFiles,
        rotate_at: u64,
        redirect: &'r RedirectStderr<'r>,
    ) -> Result<Self, LocalError> {
        let dir_error = |source| LocalError::LogDir {
            path: dir.to_path_buf(),
            source,
        };
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(dir)
            .map_err(dir_error)?;
        let mut restored = Vec::new();
        let metadata = fs::symlink_metadata(dir).map_err(dir_error)?;
        // A link to a directory is left as it is: its mode is its target's.
        if metadata.file_type().is_dir()
            && let Some(was) = loose(metadata.permissions().mode(), DIR_MODE)
        {
            fs::set_permissions(dir, Permissions::from_mode(DIR_MODE)).map_err(dir_error)?;
            restored.push(ModeRestored {
                name: "the log directory".to_owned(),
                was,
                now: DIR_MODE,
            });
        }
        let (file, found) = open_file(dir, files.name)?;
        restored.extend(found);
        restored.extend(restore_rotated(dir, files.rotated)?);
        let written = file
            .metadata()
            .map_err(|source| LocalError::LogFile {
                path: dir.join(files.name),
                source,
            })?
            .len();
        redirect(file.as_fd()).map_err(LocalError::LogRedirect)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            files,
            file,
            written,
            rotate_at,
            at_line_start: true,
            redirect,
            restored,
        })
    }

    /// The modes the open set back, in the order it set them: the
    /// directory's, the file's, the rotated file's. Each is for one line of
    /// the log, which its writer adds.
    pub(crate) fn restored(&self) -> &[ModeRestored] {
        &self.restored
    }

    /// Renames the current file to its rotated name (`daemon.log.1`),
    /// replacing the earlier one, and begins a new file, to which standard
    /// error then points. The file renamed was set to 0600 when the log
    /// opened, and the new one is created so; a file that appeared at the
    /// name between the rename and the open is set to 0600 too.
    fn rotate(&mut self) -> io::Result<()> {
        fs::rename(
            self.dir.join(self.files.name),
            self.dir.join(self.files.rotated),
        )?;
        let (file, _) = open_file(&self.dir, self.files.name).map_err(io::Error::other)?;
        self.file = file;
        (self.redirect)(self.file.as_fd()).map_err(io::Error::other)?;
        self.written = 0;
        Ok(())
    }
}

/// The mode found, when its bits ([`MODE_BITS`]) are not `wanted`.
const fn loose(mode: u32, wanted: u32) -> Option<u32> {
    let bits = mode & MODE_BITS;
    if bits == wanted { None } else { Some(bits) }
}

/// The log file `name` in `dir`, opened for appending (created with mode
/// 0600), and, if it was there with another mode, that mode, set back to
/// 0600 through the open file, so that what is set is what is written.
fn open_file(dir: &Path, name: &str) -> Result<(File, Option<ModeRestored>), LocalError> {
    let path = dir.join(name);
    let file_error = |source| LocalError::LogFile {
        path: path.clone(),
        source,
    };
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(file_error)?;
    let mode = file.metadata().map_err(file_error)?.permissions().mode();
    let Some(was) = loose(mode, FILE_MODE) else {
        return Ok((file, None));
    };
    file.set_permissions(Permissions::from_mode(FILE_MODE))
        .map_err(file_error)?;
    Ok((
        file,
        Some(ModeRestored {
            name: name.to_owned(),
            was,
            now: FILE_MODE,
        }),
    ))
}

/// Sets the rotated file `name` in `dir` back to 0600 if it is a regular
/// file found with another mode, and says what it found; anything else
/// there (nothing, a link) is left as it is.
fn restore_rotated(dir: &Path, name: &str) -> Result<Option<ModeRestored>, LocalError> {
    let path = dir.join(name);
    let file_error = |source| LocalError::LogFile {
        path: path.clone(),
        source,
    };
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(file_error(source)),
    };
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    let Some(was) = loose(metadata.permissions().mode(), FILE_MODE) else {
        return Ok(None);
    };
    fs::set_permissions(&path, Permissions::from_mode(FILE_MODE)).map_err(file_error)?;
    Ok(Some(ModeRestored {
        name: name.to_owned(),
        was,
        now: FILE_MODE,
    }))
}

impl Write for RotatingLog<'_> {
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
