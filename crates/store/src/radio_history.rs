// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history's day files (design §15.6 rule 11, §15.7): one JSON
//! Lines file per UTC day of the poll, `radio/<YYYY-MM-DD>.jsonl`, in a
//! `radio/` directory of mode 0700 under the support directory, each file
//! mode 0600. `daemon-core`'s `radio_history` encodes and decodes the lines;
//! this module keeps the files: the append, which first cuts a torn last
//! line (a crash or a disk that filled mid-line) back to the last newline
//! so that no two lines are ever glued; the bounded read of whole lines,
//! which reports a torn tail rather than decode it; and the prune, which
//! keeps the newest day files by name.
//!
//! Only the daemon writes here, and only one daemon runs at a time (it
//! holds its instance lock), so the append takes no state lock. The CLI
//! reads the files while the daemon may be appending: a reader ignores a
//! last line without its newline, which may be a write in progress.
//!
//! Only a regular file is a day file: a link, a directory or anything
//! else where one belongs is refused (`NotRegularFile`), and the files are
//! opened with `O_NOFOLLOW`. A name in `radio/` that is not a day file's is
//! a stray: named, never removed, never fatal. These are Level 0 data (the
//! operator's own device's readings, on the operator's Mac); the faults
//! guarded against are accidental.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mooring_model::CalendarDate;

use crate::durable::{FILE_MODE, private_dir, remove_durably, sync_dir};
use crate::error::{IoOp, RadioHistoryFault, StoreError};

/// The radio history's directory, in the support directory.
pub const RADIO_DIRECTORY: &str = "radio";

/// What follows the day in a day file's name.
pub const RADIO_DAY_SUFFIX: &str = ".jsonl";

/// The largest day file read or written: a day of 60 s polls is 1440 lines
/// of about 340 bytes at most, under 500 KiB.
pub const MAX_RADIO_DAY_BYTES: usize = 4 * 1024 * 1024;

/// A day file's whole lines, and whether a torn line followed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioDay {
    /// The file up to and including its last newline.
    pub lines: Vec<u8>,
    /// Whether bytes followed the last newline: a write in progress, or
    /// one a crash cut short, which the next append removes.
    pub torn: bool,
}

/// What a prune did and found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pruned {
    /// The days whose files were removed, oldest first.
    pub removed: Vec<CalendarDate>,
    /// The entries of `radio/` that are not day files, left as they are.
    pub strays: Vec<PathBuf>,
}

/// The day files found, and the strays beside them.
#[derive(Debug, Default)]
struct Listed {
    days: Vec<CalendarDate>,
    strays: Vec<PathBuf>,
}

/// `radio/<date>.jsonl` under `support_dir`.
#[must_use]
pub fn radio_day_path(support_dir: &Path, date: CalendarDate) -> PathBuf {
    support_dir
        .join(RADIO_DIRECTORY)
        .join(format!("{date}{RADIO_DAY_SUFFIX}"))
}

fn io_error(op: IoOp, path: &Path) -> impl FnOnce(io::Error) -> StoreError {
    let path = path.to_path_buf();
    move |source| StoreError::Io { op, path, source }
}

/// Whether a day file is at `path`: `None` for nothing, `NotRegularFile`
/// for anything but a regular file (a link is never followed).
fn inspect(path: &Path) -> Result<Option<()>, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(Some(())),
        Ok(_) => Err(StoreError::RadioHistoryCorrupt {
            path: path.to_path_buf(),
            fault: RadioHistoryFault::NotRegularFile,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(IoOp::InspectRadioDay, path)(error)),
    }
}

/// Appends `line` (one whole line, its newline included) to the day's
/// file, creating the directory (mode 0700) and the file (mode 0600) when
/// missing. A torn last line is cut back to the last newline first. An
/// append that would take the file past [`MAX_RADIO_DAY_BYTES`] is refused
/// (`TooLarge`) with the file unchanged. The line is flushed to stable
/// storage, and the directory too when the file was created.
pub fn append_radio_line(
    support_dir: &Path,
    date: CalendarDate,
    line: &[u8],
) -> Result<(), StoreError> {
    let dir = private_dir(support_dir, RADIO_DIRECTORY, IoOp::CreateRadioDir)?;
    let path = dir.join(format!("{date}{RADIO_DAY_SUFFIX}"));
    let mut options = OpenOptions::new();
    options
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW);
    let created = inspect(&path)?.is_none();
    if created {
        options.create_new(true).mode(FILE_MODE);
    }
    let mut file = options
        .open(&path)
        .map_err(io_error(IoOp::OpenRadioDay, &path))?;
    let len = file
        .metadata()
        .map_err(io_error(IoOp::InspectRadioDay, &path))?
        .len();
    let complete = complete_len(&mut file, len, &path)?;
    if complete < len {
        file.set_len(complete)
            .map_err(io_error(IoOp::WriteRadioDay, &path))?;
    }
    let after = usize::try_from(complete)
        .ok()
        .and_then(|complete| complete.checked_add(line.len()));
    if after.is_none_or(|after| after > MAX_RADIO_DAY_BYTES) {
        return Err(StoreError::RadioHistoryCorrupt {
            path,
            fault: RadioHistoryFault::TooLarge,
        });
    }
    file.write_all(line)
        .and_then(|()| file.sync_all())
        .map_err(io_error(IoOp::WriteRadioDay, &path))?;
    if created {
        sync_dir(&dir)?;
    }
    Ok(())
}

/// The length of the file up to and including its last newline: its whole
/// length when the last byte is a newline (the usual case, read with one
/// byte); otherwise found by reading the file, which must be within the
/// bound.
fn complete_len(file: &mut File, len: u64, path: &Path) -> Result<u64, StoreError> {
    if len == 0 {
        return Ok(0);
    }
    let mut last = [0_u8; 1];
    file.seek(SeekFrom::Start(len - 1))
        .and_then(|_| file.read_exact(&mut last))
        .map_err(io_error(IoOp::ReadRadioDay, path))?;
    if last[0] == b'\n' {
        return Ok(len);
    }
    if len > MAX_RADIO_DAY_BYTES as u64 {
        return Err(StoreError::RadioHistoryCorrupt {
            path: path.to_path_buf(),
            fault: RadioHistoryFault::TooLarge,
        });
    }
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut bytes))
        .map_err(io_error(IoOp::ReadRadioDay, path))?;
    Ok(whole_lines(&bytes) as u64)
}

/// The length of `bytes` up to and including the last newline.
fn whole_lines(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |last| last + 1)
}

/// The day's whole lines, or `None` when there is no file for it. A file
/// over [`MAX_RADIO_DAY_BYTES`] is `TooLarge`, never read as its first
/// bytes; bytes after the last newline are reported as torn, not returned.
pub fn read_radio_day(
    support_dir: &Path,
    date: CalendarDate,
) -> Result<Option<RadioDay>, StoreError> {
    let path = radio_day_path(support_dir, date);
    if inspect(&path)?.is_none() {
        return Ok(None);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(io_error(IoOp::OpenRadioDay, &path))?;
    let mut bytes = Vec::new();
    file.take(MAX_RADIO_DAY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error(IoOp::ReadRadioDay, &path))?;
    if bytes.len() > MAX_RADIO_DAY_BYTES {
        return Err(StoreError::RadioHistoryCorrupt {
            path,
            fault: RadioHistoryFault::TooLarge,
        });
    }
    let complete = whole_lines(&bytes);
    let torn = complete < bytes.len();
    bytes.truncate(complete);
    Ok(Some(RadioDay { lines: bytes, torn }))
}

/// Removes the day files beyond the newest `keep`, by name, and flushes
/// the directory after each; names the strays beside them, which it never
/// touches. No `radio/` directory is nothing to prune, and none is made.
pub fn prune_radio_days(support_dir: &Path, keep: usize) -> Result<Pruned, StoreError> {
    let dir = support_dir.join(RADIO_DIRECTORY);
    let mut listed = match list(&dir)? {
        Some(listed) => listed,
        None => return Ok(Pruned::default()),
    };
    let excess = listed.days.len().saturating_sub(keep);
    let removed: Vec<CalendarDate> = listed.days.drain(..excess).collect();
    for day in &removed {
        remove_durably(
            &dir,
            &format!("{day}{RADIO_DAY_SUFFIX}"),
            IoOp::RemoveRadioDay,
        )?;
    }
    Ok(Pruned {
        removed,
        strays: listed.strays,
    })
}

/// The day files in `dir`, oldest first, and the strays, sorted; `None`
/// when there is no directory. Something other than a directory there is
/// `DirNotDirectory`.
fn list(dir: &Path) -> Result<Option<Listed>, StoreError> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(StoreError::DirNotDirectory {
                path: dir.to_path_buf(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(IoOp::ListRadioDays, dir)(error)),
    }
    let mut listed = Listed::default();
    for entry in fs::read_dir(dir).map_err(io_error(IoOp::ListRadioDays, dir))? {
        let entry = entry.map_err(io_error(IoOp::ListRadioDays, dir))?;
        let regular = entry
            .file_type()
            .map_err(io_error(IoOp::ListRadioDays, &entry.path()))?
            .is_file();
        let day = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(RADIO_DAY_SUFFIX))
            .and_then(|stem| CalendarDate::parse(stem).ok());
        match day {
            Some(day) if regular => listed.days.push(day),
            _ => listed.strays.push(entry.path()),
        }
    }
    listed.days.sort_unstable();
    listed.strays.sort_unstable();
    Ok(Some(listed))
}
