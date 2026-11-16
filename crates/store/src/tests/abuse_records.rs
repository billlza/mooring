// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's copy of the nodes' abuse records (design §11.8): a private
//! file in its own private directory, replaced durably under a lock of its
//! own, never read through a link, and left as it was by a refused change.

use std::fs;
use std::os::unix::fs::symlink;

use super::mode_of;
use crate::{
    ABUSE_DIRECTORY, ABUSE_RECORDS_FILE, IoOp, StoreErrorKind, read_abuse_records,
    update_abuse_records,
};

#[test]
fn the_records_are_private_and_replaced_whole() {
    let support = tempfile::tempdir().unwrap();
    assert_eq!(read_abuse_records(support.path(), 100).unwrap(), None);
    let mut seen = Vec::new();
    update_abuse_records::<()>(support.path(), 100, |old| {
        seen.push(old);
        Ok(b"first copy".to_vec())
    })
    .unwrap()
    .unwrap();
    update_abuse_records::<()>(support.path(), 100, |old| {
        seen.push(old);
        Ok(b"second copy".to_vec())
    })
    .unwrap()
    .unwrap();
    assert_eq!(seen, [None, Some(b"first copy".to_vec())]);
    let path = support
        .path()
        .join(ABUSE_DIRECTORY)
        .join(ABUSE_RECORDS_FILE);
    assert_eq!(mode_of(path.parent().unwrap()), 0o700);
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        read_abuse_records(support.path(), 6).unwrap().unwrap(),
        b"second"
    );
    // A refused change writes nothing and comes back as the refusal.
    assert_eq!(
        update_abuse_records(support.path(), 100, |_| Err("conflict")).unwrap(),
        Err("conflict")
    );
    assert_eq!(
        read_abuse_records(support.path(), 100).unwrap().unwrap(),
        b"second copy"
    );
}

#[test]
fn a_link_or_directory_is_never_read_or_written_as_the_records() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::NamedTempFile::new().unwrap();
    fs::write(elsewhere.path(), b"private canary").unwrap();
    let dir = support.path().join(ABUSE_DIRECTORY);
    fs::create_dir(&dir).unwrap();
    let path = dir.join(ABUSE_RECORDS_FILE);
    symlink(elsewhere.path(), &path).unwrap();
    assert_eq!(
        read_abuse_records(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::NotRegularFile
    );
    assert_eq!(
        update_abuse_records::<()>(support.path(), 100, |_| Ok(b"x".to_vec()))
            .unwrap_err()
            .kind(),
        StoreErrorKind::NotRegularFile
    );
    assert_eq!(fs::read(elsewhere.path()).unwrap(), b"private canary");
    // The update took its lock before it met the link.
    assert!(dir.join("records.lock").exists());
    fs::remove_dir_all(&dir).unwrap();
    symlink(elsewhere.path(), &dir).unwrap();
    assert_eq!(
        read_abuse_records(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::DirNotDirectory
    );
    assert_eq!(
        update_abuse_records::<()>(support.path(), 100, |_| Ok(b"x".to_vec()))
            .unwrap_err()
            .kind(),
        StoreErrorKind::DirNotDirectory
    );
    assert_eq!(IoOp::ReadAbuseRecords.to_string(), "read the abuse records");
    assert_eq!(
        IoOp::CreateAbuseDir.to_string(),
        "create the abuse directory"
    );
}
