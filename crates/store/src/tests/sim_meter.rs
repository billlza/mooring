// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM meter's file (design §10.1 step 5): the usage directory created
//! with mode 0700 (and set back to it when found open), the document with
//! mode 0600, the bounded read, and the refusal of a usage path that is not
//! a directory.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::mode_of;
use crate::error::StoreErrorKind;
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
