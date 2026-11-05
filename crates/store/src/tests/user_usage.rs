// SPDX-License-Identifier: GPL-3.0-or-later

//! Private durable user accounting, separate from the SIM meter.

use std::fs;
use std::os::unix::fs::symlink;

use super::mode_of;
use crate::{
    IoOp, StoreError, StoreErrorKind, USAGE_DIRECTORY, USER_USAGE_FILE, read_sim_meter,
    read_user_usage, write_sim_meter, write_user_usage,
};

#[test]
fn user_usage_is_private_and_independent_of_the_sim_meter() {
    let support = tempfile::tempdir().unwrap();
    assert_eq!(read_user_usage(support.path(), 100).unwrap(), None);
    write_sim_meter(support.path(), b"SIM readings preserved").unwrap();
    write_user_usage(support.path(), b"first ledger").unwrap();
    write_user_usage(support.path(), b"second ledger").unwrap();
    let path = support.path().join(USAGE_DIRECTORY).join(USER_USAGE_FILE);
    assert_eq!(mode_of(path.parent().unwrap()), 0o700);
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        read_user_usage(support.path(), 6).unwrap().unwrap(),
        b"second"
    );
    assert_eq!(
        read_user_usage(support.path(), 100).unwrap().unwrap(),
        b"second ledger"
    );
    assert_eq!(
        read_sim_meter(support.path(), 100).unwrap().unwrap(),
        b"SIM readings preserved"
    );
}

#[test]
fn a_link_or_directory_is_never_read_as_a_usage_document() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::NamedTempFile::new().unwrap();
    fs::write(elsewhere.path(), b"private canary").unwrap();
    let dir = support.path().join(USAGE_DIRECTORY);
    fs::create_dir(&dir).unwrap();
    let path = dir.join(USER_USAGE_FILE);
    symlink(elsewhere.path(), &path).unwrap();
    assert_eq!(
        read_user_usage(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::NotRegularFile
    );
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(
        read_user_usage(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::NotRegularFile
    );
    assert!(write_user_usage(support.path(), b"replacement").is_err());
    assert_eq!(fs::read(elsewhere.path()).unwrap(), b"private canary");
    let not_dir = support.path().join("file");
    fs::write(&not_dir, b"").unwrap();
    let StoreError::Io { op, .. } = read_user_usage(&not_dir, 100).unwrap_err() else {
        panic!("not an I/O error")
    };
    assert_eq!(op, IoOp::ReadUserUsage);
}
