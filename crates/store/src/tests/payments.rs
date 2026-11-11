// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull's files: the daemon's private ledger and the CLI's
//! settings, each a regular file and nothing else.

use std::fs;
use std::os::unix::fs::symlink;

use super::mode_of;
use crate::{
    ChangeError, IoOp, LOCK_FILE, PAYMENT_LEDGER_FILE, PAYMENT_PULL_FILE, PAYMENTS_DIRECTORY,
    StoreError, StoreErrorKind, read_payment_ledger, read_payment_pull, update_payment_pull,
    write_payment_ledger,
};

/// The ledger is the owner's alone, replaced whole, and read within the
/// caller's bound; before the first write there is none.
#[test]
fn the_ledger_is_private_replaced_whole_and_read_within_a_bound() {
    let support = tempfile::tempdir().unwrap();
    assert_eq!(read_payment_ledger(support.path(), 100).unwrap(), None);
    write_payment_ledger(support.path(), b"first ledger").unwrap();
    write_payment_ledger(support.path(), b"second ledger").unwrap();
    let path = support
        .path()
        .join(PAYMENTS_DIRECTORY)
        .join(PAYMENT_LEDGER_FILE);
    assert_eq!(mode_of(path.parent().unwrap()), 0o700);
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        read_payment_ledger(support.path(), 6).unwrap().unwrap(),
        b"second"
    );
    assert_eq!(
        read_payment_ledger(support.path(), 100).unwrap().unwrap(),
        b"second ledger"
    );
    // A directory left open is closed again by the next write.
    fs::set_permissions(
        path.parent().unwrap(),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    write_payment_ledger(support.path(), b"third").unwrap();
    assert_eq!(mode_of(path.parent().unwrap()), 0o700);
}

/// A link or a directory where the ledger or its directory belongs is
/// never read as a ledger, nor written through.
#[test]
fn a_link_is_never_read_or_written_as_the_ledger() {
    let support = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::NamedTempFile::new().unwrap();
    fs::write(elsewhere.path(), b"private canary").unwrap();
    let dir = support.path().join(PAYMENTS_DIRECTORY);
    fs::create_dir(&dir).unwrap();
    let path = dir.join(PAYMENT_LEDGER_FILE);
    symlink(elsewhere.path(), &path).unwrap();
    assert_eq!(
        read_payment_ledger(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::NotRegularFile
    );
    fs::remove_file(&path).unwrap();
    symlink(support.path().join("nothing"), &path).unwrap();
    assert_eq!(
        read_payment_ledger(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::NotRegularFile
    );
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert_eq!(
        read_payment_ledger(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::NotRegularFile
    );
    assert!(write_payment_ledger(support.path(), b"replacement").is_err());
    assert_eq!(fs::read(elsewhere.path()).unwrap(), b"private canary");
    // A link where the directory belongs.
    let other = tempfile::tempdir().unwrap();
    let linked = tempfile::tempdir().unwrap();
    symlink(linked.path(), other.path().join(PAYMENTS_DIRECTORY)).unwrap();
    assert_eq!(
        read_payment_ledger(other.path(), 100).unwrap_err().kind(),
        StoreErrorKind::DirNotDirectory
    );
    assert_eq!(
        write_payment_ledger(other.path(), b"ledger")
            .unwrap_err()
            .kind(),
        StoreErrorKind::DirNotDirectory
    );
    assert!(fs::read_dir(linked.path()).unwrap().next().is_none());
    let not_dir = support.path().join("file");
    fs::write(&not_dir, b"").unwrap();
    let StoreError::Io { op, .. } = write_payment_ledger(&not_dir, b"x").unwrap_err() else {
        panic!("not an I/O error")
    };
    assert_eq!(op, IoOp::CreatePaymentsDir);
}

/// The settings change under the exclusive lock: the change gets the file
/// as it is, a refusal writes nothing, and the file is the owner's alone.
#[test]
fn the_settings_change_under_the_lock_and_a_refusal_writes_nothing() {
    let support = tempfile::tempdir().unwrap();
    assert_eq!(read_payment_pull(support.path(), 100).unwrap(), None);
    let written = update_payment_pull::<()>(support.path(), 100, |current| {
        assert_eq!(current, None);
        Ok(Some(b"revision 1".to_vec()))
    })
    .unwrap();
    assert_eq!(written.as_deref(), Some(&b"revision 1"[..]));
    let path = support.path().join(PAYMENT_PULL_FILE);
    assert_eq!(mode_of(&path), 0o600);
    assert!(support.path().join(LOCK_FILE).exists());
    update_payment_pull::<()>(support.path(), 100, |current| {
        assert_eq!(current, Some(&b"revision 1"[..]));
        Ok(Some(b"revision 2".to_vec()))
    })
    .unwrap();
    // A change that leaves the file as it is writes nothing.
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(
        update_payment_pull::<()>(support.path(), 100, |_| Ok(None)).unwrap(),
        None
    );
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    let refused = update_payment_pull(support.path(), 100, |_| Err("no"));
    assert!(matches!(refused, Err(ChangeError::Refused("no"))));
    assert_eq!(
        read_payment_pull(support.path(), 100).unwrap().unwrap(),
        b"revision 2"
    );
    assert_eq!(
        read_payment_pull(support.path(), 3).unwrap().unwrap(),
        b"rev"
    );
    fs::remove_file(&path).unwrap();
    let elsewhere = tempfile::NamedTempFile::new().unwrap();
    symlink(elsewhere.path(), &path).unwrap();
    assert_eq!(
        read_payment_pull(support.path(), 100).unwrap_err().kind(),
        StoreErrorKind::NotRegularFile
    );
    let through_link = update_payment_pull::<()>(support.path(), 100, |_| Ok(Some(b"x".to_vec())));
    assert!(matches!(through_link, Err(ChangeError::Store(_))));
    assert!(fs::read(elsewhere.path()).unwrap().is_empty());
}
