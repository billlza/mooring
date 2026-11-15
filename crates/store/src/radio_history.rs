// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history's day files (design §15.6 rule 11, §15.7): one JSON
//! Lines file per UTC day of the poll, `radio/<YYYY-MM-DD>.jsonl`, in a
//! `radio/` directory of mode 0700 under the support directory, each file
//! mode 0600, kept as `day_files` keeps every kind of day file: the append
//! that first cuts a torn last line, the bounded read of whole lines that
//! reports a torn tail rather than decode it, and the prune that keeps the
//! newest day files by name. `daemon-core`'s `radio_history` encodes and
//! decodes the lines; the daemon writes, the CLI reads, both through this
//! crate, which alone knows the directory, the names and the framing.

use std::path::{Path, PathBuf};

use mooring_model::CalendarDate;

use crate::day_files::{DayFiles, DayLines, DayOps, Pruned};
use crate::error::{IoOp, RadioHistoryFault, StoreError};

/// The radio history's directory, in the support directory.
pub const RADIO_DIRECTORY: &str = "radio";

/// The largest day file read or written: a day of 60 s polls is 1440 lines
/// of about 340 bytes at most, under 500 KiB.
pub const MAX_RADIO_DAY_BYTES: usize = 4 * 1024 * 1024;

/// The radio history's day files.
const RADIO: DayFiles<'static> = DayFiles {
    dirs: &[RADIO_DIRECTORY],
    ops: DayOps {
        create_dir: IoOp::CreateRadioDir,
        open: IoOp::OpenRadioDay,
        read: IoOp::ReadRadioDay,
        write: IoOp::WriteRadioDay,
        list: IoOp::ListRadioDays,
        remove: IoOp::RemoveRadioDay,
    },
    max_bytes: MAX_RADIO_DAY_BYTES,
    too_large: |path| StoreError::RadioHistoryCorrupt {
        path,
        fault: RadioHistoryFault::TooLarge,
    },
};

/// `radio/<date>.jsonl` under `support_dir`.
#[must_use]
pub fn radio_day_path(support_dir: &Path, date: CalendarDate) -> PathBuf {
    RADIO.path(support_dir, date)
}

/// Appends `line` (one whole line, its newline included) to the day's
/// file, creating the directory (mode 0700) and the file (mode 0600) when
/// missing. A torn last line is cut back to the last newline first. An
/// append that would take the file past [`MAX_RADIO_DAY_BYTES`] is refused
/// (`TooLarge`) with the file unchanged. Anything but a regular file where
/// the day file belongs is `NotRegularFile`, and nothing is written through
/// it. The line is flushed to stable storage, and the directory too when
/// the file was created.
pub fn append_radio_line(
    support_dir: &Path,
    date: CalendarDate,
    line: &[u8],
) -> Result<(), StoreError> {
    RADIO.append(support_dir, date, line)
}

/// The day's whole lines, or `None` when there is no file for it (or no
/// radio directory at all). Anything but a directory where `radio/`
/// belongs, a link included, is `DirNotDirectory`, as for the append and
/// the prune, and nothing is read through it; anything but a regular file
/// where the day file belongs, a link included, is `NotRegularFile`, as for
/// the append. A file over [`MAX_RADIO_DAY_BYTES`] is `TooLarge`, never
/// read as its first bytes; bytes after the last newline are reported as
/// torn, not returned.
pub fn read_radio_day(
    support_dir: &Path,
    date: CalendarDate,
) -> Result<Option<DayLines>, StoreError> {
    RADIO.read(support_dir, date)
}

/// Removes the day files beyond the newest `keep`, by name, and flushes
/// the directory after each; names the strays beside them, which it never
/// touches. No `radio/` directory is nothing to prune, and none is made;
/// anything but a directory there, a link included, is `DirNotDirectory`,
/// and nothing is listed or removed through it.
pub fn prune_radio_days(support_dir: &Path, keep: usize) -> Result<Pruned, StoreError> {
    RADIO.prune(support_dir, keep)
}
