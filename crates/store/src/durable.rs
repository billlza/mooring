// SPDX-License-Identifier: GPL-3.0-or-later

//! Durable file primitives (design §7): the open of a store file, the
//! `state.lock` lock, the temp file → fsync → rename → directory fsync
//! write, the durable removal, and the private directories the store keeps
//! its files in.
//!
//! Only a regular file is a store file. Every open of one by its path, to
//! read it, to append to it or to lock it, goes through
//! [`existing_regular_file`] or [`regular_file`]: the file is opened with
//! `O_NOFOLLOW` (a link there, dangling or not, is never followed) and
//! `O_NONBLOCK` (a FIFO there cannot hold the open), and checked on the open
//! descriptor itself, so what is then read, written or locked is what was
//! checked, whatever is exchanged for the path in between. Anything else
//! where the file belongs (a link, a directory, a FIFO, a socket or a
//! device) is `NotRegularFile`, and never read as no file. The writes need
//! no such open: they rename a new file over the path, which replaces what
//! is there and follows nothing. These are the operator's own files on the
//! operator's Mac (Level 0 data, design §12): the faults guarded against
//! are accidental, such as a link left by a hand edit or a restore, or a
//! FIFO or a socket made in the wrong place; they are not an attack, as
//! whoever can write the directory can replace the files themselves.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{IoOp, StoreError};

/// The mode of every file the store creates: owner read and write only.
pub(crate) const FILE_MODE: u32 = 0o600;

/// The mode of every directory the store creates: the owner's alone.
const DIR_MODE: u32 = 0o700;

/// The suffix of the temporary file a durable write goes through.
const TEMP_SUFFIX: &str = ".tmp";

fn io_error(op: IoOp, path: &Path) -> impl FnOnce(io::Error) -> StoreError {
    let path = path.to_path_buf();
    move |source| StoreError::Io { op, path, source }
}

/// A store file opened by [`regular_file`] or [`existing_regular_file`]: a
/// regular file, as its own descriptor says.
#[derive(Debug)]
pub(crate) struct RegularFile {
    /// The open file.
    pub(crate) file: File,
    /// Its length when it was checked.
    pub(crate) len: u64,
}

/// Opens the store file at `path` as `options` say (creating it, when they
/// say so), with `O_NOFOLLOW` and `O_NONBLOCK`, and checks it on the open
/// descriptor itself, as the module says. Anything but a regular file is
/// `NotRegularFile`, whether the open fails on it (a link, a directory
/// opened for writing, a socket) or the check refuses it (a directory
/// opened for reading, a FIFO, a device); any other failure, nothing there
/// included, is `Io{op}`.
pub(crate) fn regular_file(
    path: &Path,
    options: &mut OpenOptions,
    op: IoOp,
) -> Result<RegularFile, StoreError> {
    checked(path, without_following(options).open(path), op)
}

/// [`regular_file`] for a file that may be missing: `None` when nothing is
/// there (a link to nothing is something, and refused).
pub(crate) fn existing_regular_file(
    path: &Path,
    options: &mut OpenOptions,
    op: IoOp,
) -> Result<Option<RegularFile>, StoreError> {
    match without_following(options).open(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        opened => checked(path, opened, op).map(Some),
    }
}

/// `options` with `O_NOFOLLOW`, so a link is never followed, and
/// `O_NONBLOCK`, so a FIFO cannot hold the open.
fn without_following(options: &mut OpenOptions) -> &mut OpenOptions {
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
}

/// The file `opened` at `path`, if it is a regular file by its own
/// descriptor. An open that failed is named by what the path holds: a look
/// at the path itself (`lstat`) that finds anything but a regular file
/// there makes it `NotRegularFile`, as an open that `O_NOFOLLOW` refuses
/// (`ELOOP`) or that no file type allows (a socket's `EOPNOTSUPP` on macOS,
/// `ENXIO` on Linux) cannot tell; otherwise the open's own failure is the
/// error, also when the look fails. The look only names the failure:
/// nothing is opened or read through it.
fn checked(path: &Path, opened: io::Result<File>, op: IoOp) -> Result<RegularFile, StoreError> {
    let file = match opened {
        Ok(file) => file,
        Err(error) => {
            return Err(match fs::symlink_metadata(path) {
                Ok(metadata) if !metadata.file_type().is_file() => not_regular(path),
                Ok(_) | Err(_) => io_error(op, path)(error),
            });
        }
    };
    let metadata = file.metadata().map_err(io_error(op, path))?;
    if !metadata.file_type().is_file() {
        return Err(not_regular(path));
    }
    Ok(RegularFile {
        file,
        len: metadata.len(),
    })
}

fn not_regular(path: &Path) -> StoreError {
    StoreError::NotRegularFile {
        path: path.to_path_buf(),
    }
}

/// How `state.lock` is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockMode {
    /// Readers: excludes writers, admits other readers.
    Shared,
    /// Writers: excludes everyone else.
    Exclusive,
}

/// A held lock on `state.lock`, released when dropped (the descriptor is
/// closed). Each acquisition opens its own descriptor, so threads of one
/// process exclude each other as separate processes do.
#[derive(Debug)]
pub(crate) struct StateLock {
    _file: File,
}

impl StateLock {
    /// Opens (creating with mode 0600 if needed) and locks `path`, blocking
    /// until the lock is available. Anything but a regular file there, a
    /// link included, is `NotRegularFile` ([`regular_file`]): the lock is
    /// never taken on a file elsewhere, nor made where a link leads.
    pub(crate) fn acquire(path: &Path, mode: LockMode) -> Result<Self, StoreError> {
        let RegularFile { file, .. } = regular_file(
            path,
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(FILE_MODE),
            IoOp::OpenLock,
        )?;
        let locked = match mode {
            LockMode::Shared => file.lock_shared(),
            LockMode::Exclusive => file.lock(),
        };
        locked.map_err(|source| StoreError::Lock {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self { _file: file })
    }
}

/// Whether anything (file, directory or link) exists at the state path.
pub(crate) fn state_exists(path: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(IoOp::InspectState, path)(error)),
    }
}

/// What a bounded read of an optional document found.
#[derive(Debug)]
pub(crate) enum Bounded {
    /// There is no file.
    Absent,
    /// The file holds more than the bound; none of it is returned.
    TooLarge,
    /// The whole file, within the bound.
    Document(Vec<u8>),
}

/// Reads the optional document at `path` with the bound `max`: `Absent`
/// when the file does not exist, `TooLarge` when it holds more than `max`
/// bytes (one byte past the bound is read, so an oversized file is detected
/// without reading it all), the bytes otherwise. Anything but a regular
/// file there, a link included, is `NotRegularFile`
/// ([`existing_regular_file`]); any other failure is `Io{op}`.
pub(crate) fn read_bounded(path: &Path, max: usize, op: IoOp) -> Result<Bounded, StoreError> {
    let Some(RegularFile { file, .. }) =
        existing_regular_file(path, OpenOptions::new().read(true), op)?
    else {
        return Ok(Bounded::Absent);
    };
    // usize to u64 is lossless on every target.
    let mut bytes = Vec::with_capacity(max + 1);
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error(op, path))?;
    if bytes.len() > max {
        return Ok(Bounded::TooLarge);
    }
    Ok(Bounded::Document(bytes))
}

/// Reads the state file; `NotInitialized` if it does not exist. Anything
/// but a regular file there, a link included, is `NotRegularFile`
/// ([`existing_regular_file`]), never `NotInitialized`.
pub(crate) fn read_state(path: &Path) -> Result<Vec<u8>, StoreError> {
    let Some(RegularFile { mut file, .. }) =
        existing_regular_file(path, OpenOptions::new().read(true), IoOp::ReadState)?
    else {
        return Err(StoreError::NotInitialized {
            path: path.to_path_buf(),
        });
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(io_error(IoOp::ReadState, path))?;
    Ok(bytes)
}

/// The temporary file a durable write of `target` goes through.
pub(crate) fn temp_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(TEMP_SUFFIX);
    PathBuf::from(name)
}

/// Replaces `dir/name` with `bytes` so that a crash leaves either the old
/// or the new content, never a mix: the bytes go to a fresh temporary file
/// (mode 0600) that is fsynced and renamed over the target, then the
/// directory is fsynced so the rename itself is durable.
///
/// A temporary file left behind by an interrupted write is removed first;
/// readers never look at it. Callers hold the exclusive state lock, so no
/// other writer uses the same temporary file.
pub(crate) fn write_durably(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
    let target = dir.join(name);
    let temp = temp_path(&target);
    remove_stale(&temp)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&temp)
        .map_err(io_error(IoOp::CreateTemp, &temp))?;
    file.write_all(bytes)
        .map_err(io_error(IoOp::WriteTemp, &temp))?;
    file.sync_all().map_err(io_error(IoOp::SyncTemp, &temp))?;
    drop(file);
    fs::rename(&temp, &target).map_err(io_error(IoOp::Rename, &target))?;
    sync_dir(dir)
}

/// Removes `dir/name` and flushes the directory, so the removal survives a
/// crash; a file that is gone already is fine. `op` names the removal in
/// an error.
pub(crate) fn remove_durably(dir: &Path, name: &str, op: IoOp) -> Result<(), StoreError> {
    let target = dir.join(name);
    match fs::remove_file(&target) {
        Ok(()) => sync_dir(dir),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(op, &target)(error)),
    }
}

/// `parent/name`, a directory of the owner's alone, looked at first as
/// [`existing_private_dir`] looks: anything there that is not a directory,
/// a link included, is `DirNotDirectory`, and nothing is written through
/// it; a directory found is set back to mode 0700 (one left open is closed
/// again); with nothing there, it is created with mode 0700. `op` names the
/// creation in an error. Each private directory has one writer (the daemon,
/// which holds its instance lock), so nothing else makes the directory
/// between the look and the creation; were something to, the creation
/// would fail (`AlreadyExists`) rather than use a directory not looked at.
pub(crate) fn private_dir(parent: &Path, name: &str, op: IoOp) -> Result<PathBuf, StoreError> {
    if let Some(dir) = existing_private_dir(parent, name, op)? {
        fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))
            .map_err(io_error(op, &dir))?;
        return Ok(dir);
    }
    let dir = parent.join(name);
    DirBuilder::new()
        .mode(DIR_MODE)
        .create(&dir)
        .map_err(io_error(op, &dir))?;
    Ok(dir)
}

/// `parent/name`, one of the store's private directories, if it is there:
/// `None` when nothing is. Anything there that is not a directory, a link
/// included, is `DirNotDirectory`, so nothing is read, written, listed or
/// removed through it: [`private_dir`] looks with it before the writes,
/// and the reads and the prune look with it alone, creating nothing and
/// changing no mode, so they leave the directory as they find it. `op`
/// names the operation the look is part of in an error.
pub(crate) fn existing_private_dir(
    parent: &Path,
    name: &str,
    op: IoOp,
) -> Result<Option<PathBuf>, StoreError> {
    let dir = parent.join(name);
    match fs::symlink_metadata(&dir) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(Some(dir)),
        Ok(_) => Err(StoreError::DirNotDirectory { path: dir }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(op, &dir)(error)),
    }
}

/// Removes a leftover temporary file; a missing one is the normal case.
fn remove_stale(temp: &Path) -> Result<(), StoreError> {
    match fs::remove_file(temp) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(IoOp::RemoveStaleTemp, temp)(error)),
    }
}

/// Flushes the directory entry changes of `dir` to stable storage.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .map_err(io_error(IoOp::OpenDir, dir))?
        .sync_all()
        .map_err(io_error(IoOp::SyncDir, dir))
}
