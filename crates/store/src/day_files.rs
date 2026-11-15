// SPDX-License-Identifier: GPL-3.0-or-later

//! UTC day files of JSON lines, the mechanics the radio history and the
//! event journals share (design §15.6 rule 11, §15.7): one file per UTC
//! day, `<YYYY-MM-DD>.jsonl`, in a private directory (mode 0700, each
//! level of it) under the support directory, each file mode 0600. A kind
//! of day file ([`DayFiles`]) names its directory, the operations its
//! errors name and its bound. The append first cuts a torn last line (a
//! crash or a disk that filled mid-line) back to the last newline, so that
//! no two lines are ever glued; the bounded read gives the whole lines and
//! reports a torn tail rather than give it; the listing names the day
//! files and the strays beside them; the prunes remove the oldest day
//! files by name, beyond a count or before a day.
//!
//! Only the daemon writes day files, and only one daemon runs at a time
//! (it holds its instance lock), so the append takes no state lock. The
//! CLI reads them while the daemon may be appending: a reader ignores a
//! last line without its newline, which may be a write in progress.
//!
//! Only a regular file is a day file: a link, a directory, a FIFO, a
//! socket or anything else where one belongs is refused (`NotRegularFile`),
//! and nothing is read or written through it. The files are opened as
//! every store file is (`durable`'s [`existing_regular_file`]): with
//! `O_NOFOLLOW` (a link is never followed) and `O_NONBLOCK` (a FIFO cannot
//! hold the open), and checked on the open descriptor itself, so what is
//! then read or written is what was checked, whatever is exchanged for the
//! path between a look and the open. Only a directory is a level of the
//! directory: anything else where one belongs, a link included, is refused
//! (`DirNotDirectory`) by the append, the read, the listing and the prune
//! alike, and nothing is read, written or removed through it. A name in
//! the directory that is not a day file's is a stray: named, never
//! removed, never fatal. These are Level 0 data on the operator's Mac; the
//! faults guarded against are accidental, so each level of the directory
//! is looked at before a day file is opened, not checked on a descriptor
//! of its own.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mooring_model::CalendarDate;

use crate::durable::{
    FILE_MODE, RegularFile, existing_private_dir, existing_regular_file, private_dir,
    remove_durably, sync_dir,
};
use crate::error::{IoOp, StoreError};

/// What follows the day in a day file's name.
pub const DAY_FILE_SUFFIX: &str = ".jsonl";

/// A day file's whole lines, and whether a torn line followed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayLines {
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
    /// The entries of the directory that are not day files, left as they
    /// are.
    pub strays: Vec<PathBuf>,
}

/// The day files of a directory, oldest first, and the strays beside
/// them, sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listed {
    /// The days that have a file.
    pub days: Vec<CalendarDate>,
    /// The entries that are not day files.
    pub strays: Vec<PathBuf>,
}

/// The operations a kind of day file's errors name.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DayOps {
    /// Creating or inspecting a level of the directory, to append.
    pub(crate) create_dir: IoOp,
    /// Opening, inspecting or creating a day file, or inspecting a level
    /// of the directory to read one.
    pub(crate) open: IoOp,
    /// Reading a day file.
    pub(crate) read: IoOp,
    /// Writing, truncating or flushing a day file.
    pub(crate) write: IoOp,
    /// Inspecting a level of the directory or listing its day files.
    pub(crate) list: IoOp,
    /// Removing a day file.
    pub(crate) remove: IoOp,
}

/// A kind of day file: where its directory is, what its errors name, and
/// its bound.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DayFiles<'a> {
    /// The directory's path from the support directory, one name per
    /// level; every level is a private directory.
    pub(crate) dirs: &'a [&'a str],
    /// The operations its errors name.
    pub(crate) ops: DayOps,
    /// The largest day file read or written.
    pub(crate) max_bytes: usize,
    /// The error for a day file at `path` larger than the bound, or one an
    /// append would make so.
    pub(crate) too_large: fn(PathBuf) -> StoreError,
}

impl DayFiles<'_> {
    /// The day's file under `support_dir`.
    pub(crate) fn path(&self, support_dir: &Path, date: CalendarDate) -> PathBuf {
        self.dirs
            .iter()
            .fold(support_dir.to_path_buf(), |path, name| path.join(name))
            .join(day_file_name(date))
    }

    /// Appends `bytes` (whole lines, the last newline included) to the
    /// day's file, creating each level of the directory (mode 0700) and
    /// the file (mode 0600) when missing. A torn last line is cut back to
    /// the last newline first. An append that would take the file past the
    /// bound is refused (`too_large`) with the file unchanged. Anything but
    /// a regular file where the day file belongs is `NotRegularFile`, and
    /// nothing is written through it. The bytes are flushed to stable
    /// storage, and the directory too when the file was created.
    pub(crate) fn append(
        &self,
        support_dir: &Path,
        date: CalendarDate,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let mut dir = support_dir.to_path_buf();
        for name in self.dirs {
            dir = private_dir(&dir, name, self.ops.create_dir)?;
        }
        let path = dir.join(day_file_name(date));
        let mut options = OpenOptions::new();
        options.read(true).append(true);
        let (mut file, len, created) =
            match existing_regular_file(&path, &mut options, self.ops.open)? {
                Some(RegularFile { file, len }) => (file, len, false),
                // Nothing there: made new, mode 0600, and never a file put
                // there since (`O_EXCL`: that append fails, and the next
                // finds the file).
                None => {
                    let file = options
                        .create_new(true)
                        .mode(FILE_MODE)
                        .open(&path)
                        .map_err(io_error(self.ops.open, &path))?;
                    (file, 0, true)
                }
            };
        let complete = self.complete_len(&mut file, len, &path)?;
        if complete < len {
            file.set_len(complete)
                .map_err(io_error(self.ops.write, &path))?;
        }
        let after = usize::try_from(complete)
            .ok()
            .and_then(|complete| complete.checked_add(bytes.len()));
        if after.is_none_or(|after| after > self.max_bytes) {
            return Err((self.too_large)(path));
        }
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(io_error(self.ops.write, &path))?;
        if created {
            sync_dir(&dir)?;
        }
        Ok(())
    }

    /// The length of the file up to and including its last newline: its
    /// whole length when the last byte is a newline (the usual case, read
    /// with one byte); otherwise found by reading the file, which must be
    /// within the bound.
    fn complete_len(&self, file: &mut File, len: u64, path: &Path) -> Result<u64, StoreError> {
        if len == 0 {
            return Ok(0);
        }
        let mut last = [0_u8; 1];
        file.seek(SeekFrom::Start(len - 1))
            .and_then(|_| file.read_exact(&mut last))
            .map_err(io_error(self.ops.read, path))?;
        if last[0] == b'\n' {
            return Ok(len);
        }
        if len > self.max_bytes as u64 {
            return Err((self.too_large)(path.to_path_buf()));
        }
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.read_to_end(&mut bytes))
            .map_err(io_error(self.ops.read, path))?;
        Ok(whole_lines(&bytes) as u64)
    }

    /// The day's whole lines, or `None` when there is no file for it (or
    /// no directory at all). Anything but a directory where a level of the
    /// directory belongs, a link included, is `DirNotDirectory`, as for the
    /// append and the prune, and nothing is read through it; anything but
    /// a regular file where the day file belongs, a link included, is
    /// `NotRegularFile`, as for the append. A file over the bound is
    /// `too_large`, never read as its first bytes; bytes after the last
    /// newline are reported as torn, not returned.
    pub(crate) fn read(
        &self,
        support_dir: &Path,
        date: CalendarDate,
    ) -> Result<Option<DayLines>, StoreError> {
        let Some(dir) = self.existing_dir(support_dir, self.ops.open)? else {
            return Ok(None);
        };
        let path = dir.join(day_file_name(date));
        let Some(RegularFile { file, .. }) =
            existing_regular_file(&path, OpenOptions::new().read(true), self.ops.open)?
        else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(self.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(self.ops.read, &path))?;
        if bytes.len() > self.max_bytes {
            return Err((self.too_large)(path));
        }
        let complete = whole_lines(&bytes);
        let torn = complete < bytes.len();
        bytes.truncate(complete);
        Ok(Some(DayLines { lines: bytes, torn }))
    }

    /// The day files under `support_dir`, oldest first, and the strays
    /// beside them; none when there is no directory, and none is made.
    /// Anything but a directory where a level of it belongs, a link
    /// included, is `DirNotDirectory`, and nothing is listed through it.
    pub(crate) fn list(&self, support_dir: &Path) -> Result<Listed, StoreError> {
        match self.existing_dir(support_dir, self.ops.list)? {
            Some(dir) => self.list_dir(&dir),
            None => Ok(Listed::default()),
        }
    }

    /// Removes the day files beyond the newest `keep`, by name, and
    /// flushes the directory after each; names the strays beside them,
    /// which it never touches. No directory is nothing to prune, and none
    /// is made; anything but a directory where a level of it belongs, a
    /// link included, is `DirNotDirectory`, and nothing is listed or
    /// removed through it.
    pub(crate) fn prune(&self, support_dir: &Path, keep: usize) -> Result<Pruned, StoreError> {
        self.remove_oldest(support_dir, |days| days.len().saturating_sub(keep))
    }

    /// Removes the day files of the days before `oldest`, by name, as
    /// [`DayFiles::prune`] removes the oldest: the files of `oldest` and
    /// later are kept however many there are.
    pub(crate) fn prune_before(
        &self,
        support_dir: &Path,
        oldest: CalendarDate,
    ) -> Result<Pruned, StoreError> {
        self.remove_oldest(support_dir, |days| {
            days.partition_point(|day| *day < oldest)
        })
    }

    /// Removes the oldest day files, as many as `count` gives for the days
    /// that have one (oldest first), as the prunes say.
    fn remove_oldest(
        &self,
        support_dir: &Path,
        count: impl FnOnce(&[CalendarDate]) -> usize,
    ) -> Result<Pruned, StoreError> {
        let Some(dir) = self.existing_dir(support_dir, self.ops.list)? else {
            return Ok(Pruned::default());
        };
        let mut listed = self.list_dir(&dir)?;
        let excess = count(&listed.days);
        let removed: Vec<CalendarDate> = listed.days.drain(..excess).collect();
        for day in &removed {
            remove_durably(&dir, &day_file_name(*day), self.ops.remove)?;
        }
        Ok(Pruned {
            removed,
            strays: listed.strays,
        })
    }

    /// The directory, if every level of it is there: `None` as soon as one
    /// is missing. `op` names the look in an error.
    fn existing_dir(&self, support_dir: &Path, op: IoOp) -> Result<Option<PathBuf>, StoreError> {
        let mut dir = support_dir.to_path_buf();
        for name in self.dirs {
            match existing_private_dir(&dir, name, op)? {
                Some(level) => dir = level,
                None => return Ok(None),
            }
        }
        Ok(Some(dir))
    }

    /// The day files in the directory `dir`, oldest first, and the strays,
    /// sorted.
    fn list_dir(&self, dir: &Path) -> Result<Listed, StoreError> {
        let mut listed = Listed::default();
        for entry in fs::read_dir(dir).map_err(io_error(self.ops.list, dir))? {
            let entry = entry.map_err(io_error(self.ops.list, dir))?;
            let regular = entry
                .file_type()
                .map_err(io_error(self.ops.list, &entry.path()))?
                .is_file();
            let day = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(DAY_FILE_SUFFIX))
                .and_then(|stem| CalendarDate::parse(stem).ok());
            match day {
                Some(day) if regular => listed.days.push(day),
                _ => listed.strays.push(entry.path()),
            }
        }
        listed.days.sort_unstable();
        listed.strays.sort_unstable();
        Ok(listed)
    }
}

/// The name of the day's file: `<date>.jsonl`.
fn day_file_name(date: CalendarDate) -> String {
    format!("{date}{DAY_FILE_SUFFIX}")
}

fn io_error(op: IoOp, path: &Path) -> impl FnOnce(io::Error) -> StoreError {
    let path = path.to_path_buf();
    move |source| StoreError::Io { op, path, source }
}

/// The length of `bytes` up to and including the last newline.
fn whole_lines(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |last| last + 1)
}
