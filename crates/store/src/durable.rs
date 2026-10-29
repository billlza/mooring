// SPDX-License-Identifier: GPL-3.0-or-later

//! Durable file primitives (design §7): the `state.lock` lock, the temp
//! file → fsync → rename → directory fsync write, the durable removal, and
//! the private directories the store keeps its files in.

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
    /// until the lock is available.
    pub(crate) fn acquire(path: &Path, mode: LockMode) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(FILE_MODE)
            .open(path)
            .map_err(io_error(IoOp::OpenLock, path))?;
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
/// without reading it all), the bytes otherwise. Any other failure is
/// `Io{op}`.
pub(crate) fn read_bounded(path: &Path, max: usize, op: IoOp) -> Result<Bounded, StoreError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Bounded::Absent),
        Err(error) => return Err(io_error(op, path)(error)),
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

/// Reads the state file; `NotInitialized` if it does not exist.
pub(crate) fn read_state(path: &Path) -> Result<Vec<u8>, StoreError> {
    fs::read(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            StoreError::NotInitialized {
                path: path.to_path_buf(),
            }
        } else {
            io_error(IoOp::ReadState, path)(source)
        }
    })
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

/// `parent/name`, a directory of the owner's alone: created with mode 0700
/// when missing, and set back to it when found (a directory left open is
/// closed again). Anything there that is not a directory, a link included,
/// is `DirNotDirectory`, and nothing is written through it. `op` names the
/// creation in an error.
pub(crate) fn private_dir(parent: &Path, name: &str, op: IoOp) -> Result<PathBuf, StoreError> {
    let dir = parent.join(name);
    match DirBuilder::new().mode(DIR_MODE).create(&dir) {
        Ok(()) => Ok(dir),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&dir).map_err(io_error(op, &dir))?;
            if !metadata.file_type().is_dir() {
                return Err(StoreError::DirNotDirectory { path: dir });
            }
            fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))
                .map_err(io_error(op, &dir))?;
            Ok(dir)
        }
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
