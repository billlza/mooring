// SPDX-License-Identifier: GPL-3.0-or-later

//! The record of pending applies (design §13.6, §15.3): written with mode
//! 0600 in the daemon's run directory, read back with a bound, none where
//! there is no file, and a read that fails reported as such.
//! (`tests::regular_files` refuses a link, and anything else but a regular
//! file, where the record belongs.)

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

use super::{assert_io_error, mode_of};
use crate::error::IoOp;
use crate::pending_applies::{PENDING_APPLIES_FILE, read_pending_applies, write_pending_applies};

#[test]
fn the_record_is_written_private_and_read_back_within_its_bound() {
    let run = tempfile::tempdir().unwrap();
    assert_eq!(read_pending_applies(run.path(), 64).unwrap(), None);
    write_pending_applies(run.path(), b"{\"version\": 1}\n").unwrap();
    assert_eq!(mode_of(&run.path().join(PENDING_APPLIES_FILE)), 0o600);
    assert_eq!(
        read_pending_applies(run.path(), 64).unwrap().as_deref(),
        Some(&b"{\"version\": 1}\n"[..])
    );
    // A second write replaces it; the read stops at its bound.
    write_pending_applies(run.path(), b"0123456789").unwrap();
    assert_eq!(
        read_pending_applies(run.path(), 4).unwrap().as_deref(),
        Some(&b"0123"[..])
    );
}

/// A record that cannot be read is an error naming the read, never no
/// record, which the daemon would take as no node behind: here the open
/// fails (the record is mode 0000; the tests run unprivileged).
#[test]
fn a_record_that_cannot_be_read_is_an_error_naming_the_read() {
    let run = tempfile::tempdir().unwrap();
    write_pending_applies(run.path(), b"{\"version\": 1}\n").unwrap();
    let path = run.path().join(PENDING_APPLIES_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let error = read_pending_applies(run.path(), 64).unwrap_err();
    assert_io_error(
        &error,
        IoOp::ReadPendingApplies,
        &path,
        io::ErrorKind::PermissionDenied,
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to read the record of pending applies at {}",
            path.display()
        )
    );
}
