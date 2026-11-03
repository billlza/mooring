// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history's day files (design §15.6 rule 11, §15.7): the private
//! `radio/` directory, the append that heals a torn tail first, the bounded
//! read of whole lines, the listing that names strays without failing, the
//! count-based prune, the refusal of anything that is not a regular file
//! where a day file belongs, and the refusal of anything that is not a
//! directory where `radio/` belongs, by the read as by the append and the
//! prune.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use mooring_model::CalendarDate;

use super::{assert_dir_not_directory, assert_io_error, mode_of};
use crate::error::{IoOp, RadioHistoryFault, StoreError, StoreErrorKind};
use crate::radio_history::{
    MAX_RADIO_DAY_BYTES, Pruned, RADIO_DAY_SUFFIX, RADIO_DIRECTORY, RadioDay, append_radio_line,
    prune_radio_days, radio_day_path, read_radio_day,
};

fn date(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

fn radio_dir(support: &Path) -> std::path::PathBuf {
    support.join(RADIO_DIRECTORY)
}

fn day_bytes(support: &Path, day: &str) -> Vec<u8> {
    fs::read(radio_day_path(support, date(day))).unwrap()
}

/// `error` refuses the day file at `path` as not a regular file.
fn assert_not_regular(error: &StoreError, path: &Path) {
    assert!(
        matches!(
            error,
            StoreError::RadioHistoryCorrupt {
                path: found,
                fault: RadioHistoryFault::NotRegularFile
            } if found == path
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "radio history file {} is corrupt: it is not a regular file",
            path.display()
        )
    );
}

#[test]
fn lines_are_appended_under_a_private_radio_directory_in_order() {
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    assert_eq!(RADIO_DIRECTORY, "radio");
    assert_eq!(RADIO_DAY_SUFFIX, ".jsonl");
    assert_eq!(
        radio_day_path(support.path(), day),
        support.path().join("radio").join("2026-10-24.jsonl")
    );
    assert_eq!(read_radio_day(support.path(), day).unwrap(), None);
    append_radio_line(support.path(), day, b"a\n").unwrap();
    append_radio_line(support.path(), day, b"b\n").unwrap();
    assert_eq!(mode_of(&radio_dir(support.path())), 0o700);
    assert_eq!(mode_of(&radio_day_path(support.path(), day)), 0o600);
    assert_eq!(day_bytes(support.path(), "2026-10-24"), b"a\nb\n");
    assert_eq!(
        read_radio_day(support.path(), day).unwrap(),
        Some(RadioDay {
            lines: b"a\nb\n".to_vec(),
            torn: false,
        })
    );
    // Another day is another file; the first is untouched.
    append_radio_line(support.path(), date("2026-10-25"), b"c\n").unwrap();
    assert_eq!(day_bytes(support.path(), "2026-10-24"), b"a\nb\n");
    assert_eq!(day_bytes(support.path(), "2026-10-25"), b"c\n");
    // A radio directory left open is closed again.
    fs::set_permissions(radio_dir(support.path()), fs::Permissions::from_mode(0o755)).unwrap();
    append_radio_line(support.path(), day, b"d\n").unwrap();
    assert_eq!(mode_of(&radio_dir(support.path())), 0o700);
}

/// A file whose last byte is not a newline ends in a torn line (a crash or
/// a disk that filled mid-line): the append cuts it back to the last
/// newline first, so no two lines are ever glued; the reader gives the
/// whole lines and says the file was torn.
#[test]
fn a_torn_tail_is_cut_before_the_next_append_and_reported_by_the_reader() {
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    append_radio_line(support.path(), day, b"a\n").unwrap();
    let path = radio_day_path(support.path(), day);
    fs::write(&path, b"a\nb\n{\"ver").unwrap();
    assert_eq!(
        read_radio_day(support.path(), day).unwrap(),
        Some(RadioDay {
            lines: b"a\nb\n".to_vec(),
            torn: true,
        })
    );
    append_radio_line(support.path(), day, b"c\n").unwrap();
    assert_eq!(day_bytes(support.path(), "2026-10-24"), b"a\nb\nc\n");
    // A fragment alone is cut to nothing.
    fs::write(&path, b"{\"ver").unwrap();
    assert_eq!(
        read_radio_day(support.path(), day).unwrap(),
        Some(RadioDay {
            lines: Vec::new(),
            torn: true,
        })
    );
    append_radio_line(support.path(), day, b"d\n").unwrap();
    assert_eq!(day_bytes(support.path(), "2026-10-24"), b"d\n");
    // An empty file is whole.
    fs::write(&path, b"").unwrap();
    assert_eq!(
        read_radio_day(support.path(), day).unwrap(),
        Some(RadioDay {
            lines: Vec::new(),
            torn: false,
        })
    );
    // A torn tail longer than one line is cut whole too.
    let long = [b"a\n".as_slice(), &[b'x'; 5000]].concat();
    fs::write(&path, &long).unwrap();
    append_radio_line(support.path(), day, b"e\n").unwrap();
    assert_eq!(day_bytes(support.path(), "2026-10-24"), b"a\ne\n");
}

/// The day bound holds on both sides: a file over it reads as corrupt
/// (never as its first bytes), and an append that would take the file past
/// it is refused with the file unchanged.
#[test]
fn the_day_file_is_bounded_on_read_and_on_append() {
    assert_eq!(MAX_RADIO_DAY_BYTES, 4 * 1024 * 1024);
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    append_radio_line(support.path(), day, b"a\n").unwrap();
    let path = radio_day_path(support.path(), day);
    let mut full = vec![b'x'; MAX_RADIO_DAY_BYTES - 3];
    full.push(b'\n');
    fs::write(&path, &full).unwrap();
    assert_eq!(full.len(), MAX_RADIO_DAY_BYTES - 2);
    let error = append_radio_line(support.path(), day, b"abc\n").unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::RadioHistoryCorrupt {
                path: found,
                fault: RadioHistoryFault::TooLarge
            } if *found == path
        ),
        "{error:?}"
    );
    assert_eq!(error.kind(), StoreErrorKind::RadioHistoryCorrupt);
    assert_eq!(fs::read(&path).unwrap(), full);
    append_radio_line(support.path(), day, b"b\n").unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().len() as usize,
        MAX_RADIO_DAY_BYTES
    );
    assert!(read_radio_day(support.path(), day).unwrap().is_some());
    let mut over = vec![b'x'; MAX_RADIO_DAY_BYTES];
    over.push(b'\n');
    fs::write(&path, &over).unwrap();
    let error = read_radio_day(support.path(), day).unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::RadioHistoryCorrupt {
                fault: RadioHistoryFault::TooLarge,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "radio history file {} is corrupt: it is larger than 4194304 bytes",
            path.display()
        )
    );
}

/// A torn day file is healed within the bound and refused past it: at
/// exactly the bound it is cut back to its last newline and appended to;
/// one byte over, the append is refused with the file as it stands.
#[test]
fn a_torn_day_file_is_healed_within_the_bound_and_refused_past_it() {
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    append_radio_line(support.path(), day, b"a\n").unwrap();
    let path = radio_day_path(support.path(), day);
    // Sparse: zeros after the whole lines, so the last byte is no newline.
    let grow = |len: usize| {
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len as u64)
            .unwrap();
    };
    grow(MAX_RADIO_DAY_BYTES);
    append_radio_line(support.path(), day, b"b\n").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"a\nb\n");
    grow(MAX_RADIO_DAY_BYTES + 1);
    let error = append_radio_line(support.path(), day, b"c\n").unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::RadioHistoryCorrupt {
                path: found,
                fault: RadioHistoryFault::TooLarge
            } if *found == path
        ),
        "{error:?}"
    );
    let after = fs::read(&path).unwrap();
    assert_eq!(after.len(), MAX_RADIO_DAY_BYTES + 1);
    assert_eq!(&after[..4], b"a\nb\n");
}

/// Only a regular file is a day file: a link or a directory where one
/// belongs is refused, on append and on read, and nothing is written
/// through it.
#[test]
fn a_day_path_that_is_not_a_regular_file_is_refused() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    append_radio_line(support.path(), date("2026-10-23"), b"a\n").unwrap();
    let path = radio_day_path(support.path(), day);
    let target = elsewhere.path().join("target");
    fs::write(&target, b"t\n").unwrap();
    symlink(&target, &path).unwrap();
    let refused = |error: StoreError| assert_not_regular(&error, &path);
    refused(append_radio_line(support.path(), day, b"b\n").unwrap_err());
    refused(read_radio_day(support.path(), day).unwrap_err());
    assert_eq!(fs::read(&target).unwrap(), b"t\n");
    // A dangling link is not a missing file either.
    fs::remove_file(&target).unwrap();
    refused(append_radio_line(support.path(), day, b"b\n").unwrap_err());
    refused(read_radio_day(support.path(), day).unwrap_err());
    assert!(!target.exists());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    refused(append_radio_line(support.path(), day, b"b\n").unwrap_err());
    refused(read_radio_day(support.path(), day).unwrap_err());
}

/// A FIFO where a day file belongs is refused too, and holds neither the
/// append nor the read: the open never waits on it (`O_NONBLOCK`), and the
/// check is on the open descriptor itself, so what an open cannot refuse by
/// itself (as it refuses a link, or a directory opened for writing) is
/// refused before anything is written into it or read from it.
#[test]
fn a_fifo_where_a_day_file_belongs_is_refused_without_blocking() {
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    append_radio_line(support.path(), date("2026-10-23"), b"a\n").unwrap();
    let path = radio_day_path(support.path(), day);
    let made = Command::new("/usr/bin/mkfifo").arg(&path).status().unwrap();
    assert!(made.success(), "{made}");
    assert_not_regular(
        &append_radio_line(support.path(), day, b"b\n").unwrap_err(),
        &path,
    );
    assert_not_regular(&read_radio_day(support.path(), day).unwrap_err(), &path);
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
}

/// A day file that cannot be opened is an error naming the open, never no
/// day for the read and never a new file for the append: here it is mode
/// 0000. (The tests run unprivileged, on the Mac and in CI; root would open
/// it.)
#[test]
fn a_day_file_that_cannot_be_opened_is_an_error_not_no_day() {
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    append_radio_line(support.path(), day, b"a\n").unwrap();
    let path = radio_day_path(support.path(), day);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(
        fs::File::open(&path).is_err(),
        "an unprivileged user cannot open a mode-0000 file"
    );
    let unopened = |error: StoreError| {
        assert_io_error(
            &error,
            IoOp::OpenRadioDay,
            &path,
            io::ErrorKind::PermissionDenied,
        );
    };
    unopened(read_radio_day(support.path(), day).unwrap_err());
    unopened(append_radio_line(support.path(), day, b"b\n").unwrap_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(day_bytes(support.path(), "2026-10-24"), b"a\n");
}

/// The radio directory itself must be a directory: a link or a file where
/// it belongs is refused and nothing is written through it (as the usage
/// directory is).
#[test]
fn a_radio_path_that_is_not_a_directory_is_refused() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    symlink(elsewhere.path(), radio_dir(support.path())).unwrap();
    let error = append_radio_line(support.path(), date("2026-10-24"), b"a\n").unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::DirNotDirectory);
    assert_eq!(
        error.to_string(),
        format!("{} is not a directory", radio_dir(support.path()).display())
    );
    assert!(fs::read_dir(elsewhere.path()).unwrap().next().is_none());
    let support = tempfile::tempdir().unwrap();
    fs::write(radio_dir(support.path()), b"").unwrap();
    assert_eq!(
        append_radio_line(support.path(), date("2026-10-24"), b"a\n")
            .unwrap_err()
            .kind(),
        StoreErrorKind::DirNotDirectory
    );
    assert_eq!(
        prune_radio_days(support.path(), 1).unwrap_err().kind(),
        StoreErrorKind::DirNotDirectory
    );
    // A prune that cannot look at the radio path is an error naming the
    // listing, never an empty listing.
    let not_a_directory = support.path().join("not-a-directory");
    fs::write(&not_a_directory, b"").unwrap();
    assert_io_error(
        &prune_radio_days(&not_a_directory, 1).unwrap_err(),
        IoOp::ListRadioDays,
        &radio_dir(&not_a_directory),
        io::ErrorKind::NotADirectory,
    );
}

/// The read checks the radio directory as the append and the prune do: a
/// link where it belongs is `DirNotDirectory`, whether it leads to a
/// directory holding the day's file, which is then never read (nor written
/// or pruned), or to nothing, which is never read as no day. No directory
/// at all is no day, and so is a directory without the day's file.
#[test]
fn the_read_refuses_a_radio_link_and_reads_nothing_through_it() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    let radio = radio_dir(support.path());
    assert_eq!(read_radio_day(support.path(), day).unwrap(), None);
    assert!(!radio.exists());
    append_radio_line(elsewhere.path(), day, b"a\n").unwrap();
    assert_eq!(
        read_radio_day(elsewhere.path(), date("2026-10-25")).unwrap(),
        None
    );
    symlink(radio_dir(elsewhere.path()), &radio).unwrap();
    assert_dir_not_directory(&read_radio_day(support.path(), day).unwrap_err(), &radio);
    assert_dir_not_directory(
        &append_radio_line(support.path(), day, b"b\n").unwrap_err(),
        &radio,
    );
    assert_dir_not_directory(&prune_radio_days(support.path(), 0).unwrap_err(), &radio);
    assert_eq!(day_bytes(elsewhere.path(), "2026-10-24"), b"a\n");
    // A dangling link is not a missing directory either.
    fs::remove_dir_all(radio_dir(elsewhere.path())).unwrap();
    assert_dir_not_directory(&read_radio_day(support.path(), day).unwrap_err(), &radio);
}

/// A file where the radio directory belongs is refused by the read as by
/// the append and the prune (`DirNotDirectory`), never read as no day; a
/// radio path that cannot be looked at (the support path is a file) is an
/// error naming the read's open, never no day either.
#[test]
fn the_read_refuses_a_radio_path_that_is_a_file() {
    let support = tempfile::tempdir().unwrap();
    let day = date("2026-10-24");
    let radio = radio_dir(support.path());
    fs::write(&radio, b"").unwrap();
    assert_dir_not_directory(&read_radio_day(support.path(), day).unwrap_err(), &radio);
    assert_dir_not_directory(
        &append_radio_line(support.path(), day, b"a\n").unwrap_err(),
        &radio,
    );
    assert_dir_not_directory(&prune_radio_days(support.path(), 0).unwrap_err(), &radio);
    assert_eq!(fs::read(&radio).unwrap(), b"");
    let not_a_directory = support.path().join("not-a-directory");
    fs::write(&not_a_directory, b"").unwrap();
    assert_io_error(
        &read_radio_day(&not_a_directory, day).unwrap_err(),
        IoOp::OpenRadioDay,
        &radio_dir(&not_a_directory),
        io::ErrorKind::NotADirectory,
    );
}

/// The prune keeps the newest `keep` day files by name and removes the
/// rest; entries that are not day files are named as strays and left as
/// they are, and never stop the prune.
#[test]
fn the_prune_keeps_the_newest_days_and_names_the_strays() {
    let support = tempfile::tempdir().unwrap();
    // No directory yet: nothing to prune, and none is created.
    assert_eq!(
        prune_radio_days(support.path(), 3).unwrap(),
        Pruned {
            removed: Vec::new(),
            strays: Vec::new(),
        }
    );
    assert!(!radio_dir(support.path()).exists());
    let days = [
        "2026-10-20",
        "2026-10-21",
        "2026-10-22",
        "2026-10-23",
        "2026-10-24",
    ];
    // Written out of order: the names decide.
    for day in [
        "2026-10-23",
        "2026-10-20",
        "2026-10-24",
        "2026-10-22",
        "2026-10-21",
    ] {
        append_radio_line(support.path(), date(day), b"a\n").unwrap();
    }
    let dir = radio_dir(support.path());
    // (A `.JSONL` spelling is not tried: APFS is case-insensitive by
    // default, so it would be the day file itself.)
    let strays = [
        ".DS_Store",
        "notes.txt",
        "2026-10-24.jsonl.tmp",
        "2026-13-01.jsonl",
        "2026-10-19.jsonl.bak",
    ];
    for stray in strays {
        fs::write(dir.join(stray), b"").unwrap();
    }
    fs::create_dir(dir.join("2026-10-26.jsonl")).unwrap();
    let pruned = prune_radio_days(support.path(), 3).unwrap();
    assert_eq!(pruned.removed, [date("2026-10-20"), date("2026-10-21")]);
    let mut expected_strays: Vec<_> = strays.iter().map(|stray| dir.join(stray)).collect();
    expected_strays.push(dir.join("2026-10-26.jsonl"));
    expected_strays.sort();
    assert_eq!(pruned.strays, expected_strays);
    for (day, kept) in days.iter().zip([false, false, true, true, true]) {
        assert_eq!(
            radio_day_path(support.path(), date(day)).exists(),
            kept,
            "{day}"
        );
    }
    for stray in expected_strays {
        assert!(stray.exists(), "{}", stray.display());
    }
    // Pruning again removes nothing; keeping more than there is removes
    // nothing; keeping none removes every day.
    assert_eq!(prune_radio_days(support.path(), 3).unwrap().removed, []);
    assert_eq!(prune_radio_days(support.path(), 10).unwrap().removed, []);
    assert_eq!(
        prune_radio_days(support.path(), 0).unwrap().removed,
        [date("2026-10-22"), date("2026-10-23"), date("2026-10-24")]
    );
    assert!(!radio_day_path(support.path(), date("2026-10-24")).exists());
}

/// The new faults and operations have fixed texts, and the new kinds are
/// named: `RadioHistoryCorrupt` and `DirNotDirectory` (the usage
/// directory's refusal, now shared with the radio directory).
#[test]
fn radio_history_texts_are_fixed() {
    assert_eq!(
        RadioHistoryFault::TooLarge.to_string(),
        "it is larger than 4194304 bytes"
    );
    assert_eq!(
        RadioHistoryFault::NotRegularFile.to_string(),
        "it is not a regular file"
    );
    for (op, text) in [
        (IoOp::CreateRadioDir, "create the radio directory"),
        (IoOp::InspectRadioDay, "inspect a radio history day file"),
        (IoOp::OpenRadioDay, "open a radio history day file"),
        (IoOp::ReadRadioDay, "read a radio history day file"),
        (IoOp::WriteRadioDay, "write a radio history day file"),
        (IoOp::ListRadioDays, "list the radio history's day files"),
        (IoOp::RemoveRadioDay, "remove a radio history day file"),
    ] {
        assert_eq!(op.to_string(), text);
    }
    let corrupt = StoreError::RadioHistoryCorrupt {
        path: Path::new("/x/radio/2026-10-24.jsonl").to_path_buf(),
        fault: RadioHistoryFault::TooLarge,
    };
    assert_eq!(corrupt.kind(), StoreErrorKind::RadioHistoryCorrupt);
    let not_dir = StoreError::DirNotDirectory {
        path: Path::new("/x/radio").to_path_buf(),
    };
    assert_eq!(not_dir.kind(), StoreErrorKind::DirNotDirectory);
    assert_eq!(not_dir.to_string(), "/x/radio is not a directory");
}
