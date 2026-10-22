// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's status snapshot: written whole with mode 0600, replaced
//! whole, and never into a directory the store did not find.

use std::fs;

use super::mode_of;
use crate::error::{IoOp, StoreError};
use crate::status_snapshot::{STATUS_SNAPSHOT_FILE, write_status_snapshot};

#[test]
fn the_snapshot_is_replaced_whole_with_mode_0600() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STATUS_SNAPSHOT_FILE);
    assert_eq!(STATUS_SNAPSHOT_FILE, "status.json");
    write_status_snapshot(dir.path(), b"{\"first\":1}\n").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{\"first\":1}\n");
    assert_eq!(mode_of(&path), 0o600);
    write_status_snapshot(dir.path(), b"{\"second\":2}\n").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{\"second\":2}\n");
    assert_eq!(mode_of(&path), 0o600);
    // Only the snapshot is left: no temporary file stays behind.
    let names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, [STATUS_SNAPSHOT_FILE]);
}

#[test]
fn a_missing_directory_is_an_error_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent");
    let error = write_status_snapshot(&absent, b"{}\n").unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::Io {
                op: IoOp::CreateTemp,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!absent.exists());
}
