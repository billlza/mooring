// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter's file (design §10.1 step 5): the usage directory created
//! with mode 0700 (and set back to it when found open), the document with
//! mode 0600, the bounded read, the refusal of a usage path that is not a
//! directory by the write and the read alike, and a read that fails
//! reported as such.

use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::{assert_dir_not_directory, assert_io_error, mode_of};
use crate::error::{IoOp, StoreError, StoreErrorKind};
use crate::sim_meter::{SIM_METER_FILE, USAGE_DIRECTORY, read_sim_meter, write_sim_meter};

#[test]
fn the_meter_is_written_under_a_private_usage_directory_and_read_back() {
    let support = tempfile::tempdir().unwrap();
    assert_eq!(read_sim_meter(support.path(), 64).unwrap(), None);
    write_sim_meter(support.path(), b"{\"version\": 1}\n").unwrap();
    let dir = support.path().join(USAGE_DIRECTORY);
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(mode_of(&dir.join(SIM_METER_FILE)), 0o600);
    assert_eq!(
        read_sim_meter(support.path(), 64).unwrap().as_deref(),
        Some(&b"{\"version\": 1}\n"[..])
    );
    // A usage directory left open is closed again at the next write.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    write_sim_meter(support.path(), b"{\"version\": 1}\n").unwrap();
    assert_eq!(mode_of(&dir), 0o700);
    // A second write replaces it; the read stops at its bound.
    write_sim_meter(support.path(), b"0123456789").unwrap();
    assert_eq!(
        read_sim_meter(support.path(), 4).unwrap().as_deref(),
        Some(&b"0123"[..])
    );
}

#[test]
fn a_usage_path_that_is_not_a_directory_is_refused() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    symlink(elsewhere.path(), support.path().join(USAGE_DIRECTORY)).unwrap();
    let error = write_sim_meter(support.path(), b"{}").unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::DirNotDirectory);
    assert!(fs::read_dir(elsewhere.path()).unwrap().next().is_none());
    let support = tempfile::tempdir().unwrap();
    fs::write(support.path().join(USAGE_DIRECTORY), b"").unwrap();
    assert_eq!(
        write_sim_meter(support.path(), b"{}").unwrap_err().kind(),
        StoreErrorKind::DirNotDirectory
    );
}

/// The read checks the usage directory as the write does: a link where it
/// belongs is `DirNotDirectory`, whether it leads to a directory holding a
/// meter, which is then never read (nor written), or to nothing, which is
/// never read as no meter. No directory at all is no meter, and so is a
/// directory without the meter's file.
#[test]
fn the_read_refuses_a_usage_link_and_reads_nothing_through_it() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let usage = support.path().join(USAGE_DIRECTORY);
    let elsewhere_usage = elsewhere.path().join(USAGE_DIRECTORY);
    assert_eq!(read_sim_meter(support.path(), 64).unwrap(), None);
    assert!(!usage.exists());
    fs::create_dir(&elsewhere_usage).unwrap();
    assert_eq!(read_sim_meter(elsewhere.path(), 64).unwrap(), None);
    write_sim_meter(elsewhere.path(), b"{\"version\": 1}\n").unwrap();
    symlink(&elsewhere_usage, &usage).unwrap();
    assert_dir_not_directory(&read_sim_meter(support.path(), 64).unwrap_err(), &usage);
    assert_dir_not_directory(&write_sim_meter(support.path(), b"{}").unwrap_err(), &usage);
    assert_eq!(
        fs::read(elsewhere_usage.join(SIM_METER_FILE)).unwrap(),
        b"{\"version\": 1}\n"
    );
    // A dangling link is not a missing directory either.
    fs::remove_dir_all(&elsewhere_usage).unwrap();
    assert_dir_not_directory(&read_sim_meter(support.path(), 64).unwrap_err(), &usage);
}

/// A file where the usage directory belongs is refused by the read as by
/// the write (`DirNotDirectory`), never read as no meter; a usage path that
/// cannot be looked at (the support path is a file) is an error naming the
/// read, never no meter either.
#[test]
fn the_read_refuses_a_usage_path_that_is_a_file() {
    let support = tempfile::tempdir().unwrap();
    let usage = support.path().join(USAGE_DIRECTORY);
    fs::write(&usage, b"").unwrap();
    assert_dir_not_directory(&read_sim_meter(support.path(), 64).unwrap_err(), &usage);
    assert_dir_not_directory(&write_sim_meter(support.path(), b"{}").unwrap_err(), &usage);
    assert_eq!(fs::read(&usage).unwrap(), b"");
    let not_a_directory = support.path().join("not-a-directory");
    fs::write(&not_a_directory, b"").unwrap();
    assert_io_error(
        &read_sim_meter(&not_a_directory, 64).unwrap_err(),
        IoOp::ReadSimMeter,
        &not_a_directory.join(USAGE_DIRECTORY),
        io::ErrorKind::NotADirectory,
    );
}

/// A meter that cannot be read is an error naming the read, never "no
/// meter", on which the daemon would start a fresh meter and lose the
/// cycle's usage: here the open fails (the meter is a link to itself), then
/// the read does (the meter path is a directory).
#[test]
fn a_meter_that_cannot_be_read_is_an_error_not_a_fresh_meter() {
    let support = tempfile::tempdir().unwrap();
    fs::create_dir(support.path().join(USAGE_DIRECTORY)).unwrap();
    let path = support.path().join(USAGE_DIRECTORY).join(SIM_METER_FILE);
    symlink(SIM_METER_FILE, &path).unwrap();
    let error = read_sim_meter(support.path(), 64).unwrap_err();
    // (`io::ErrorKind::FilesystemLoop` is unstable, so the system's error
    // is checked by its number.)
    assert!(
        matches!(&error, StoreError::Io { op: IoOp::ReadSimMeter, path: found, source }
            if *found == path && source.raw_os_error() == Some(libc::ELOOP)),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!("failed to read the SIM meter at {}", path.display())
    );
    let support = tempfile::tempdir().unwrap();
    let path = support.path().join(USAGE_DIRECTORY).join(SIM_METER_FILE);
    fs::create_dir_all(&path).unwrap();
    assert_io_error(
        &read_sim_meter(support.path(), 64).unwrap_err(),
        IoOp::ReadSimMeter,
        &path,
        io::ErrorKind::IsADirectory,
    );
}
