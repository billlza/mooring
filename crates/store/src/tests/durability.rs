// SPDX-License-Identifier: GPL-3.0-or-later

//! Atomic, durable, private writes (design §7): temp file → fsync → rename
//! → directory fsync, mode 0600; crashes leave the old or the new state.

use std::convert::Infallible;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use mooring_model::state::{StateFile, StateV2};

use super::builders::initialised;
use super::{mode_of, state_bytes, store_error};
use crate::durable::temp_path;
use crate::error::{IoOp, StoreError, StoreErrorKind};

fn bump(store: &crate::store::Store, state: &StateV2) -> StateV2 {
    store
        .update_config(state.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap()
}

#[test]
fn state_files_are_private() {
    let (_dir, store, state) = initialised();
    assert_eq!(mode_of(&store.state_path()), 0o600);
    assert_eq!(mode_of(&store.lock_path()), 0o600);
    bump(&store, &state);
    assert_eq!(mode_of(&store.state_path()), 0o600);
}

#[test]
fn the_document_is_the_versioned_envelope() {
    let (_dir, store, state) = initialised();
    let text = String::from_utf8(state_bytes(&store)).unwrap();
    assert!(text.starts_with("{\n  \"version\": 2,\n"), "{text}");
    assert!(text.ends_with("}\n"), "{text}");
    let file = crate::migrate::parse(text.as_bytes()).unwrap();
    assert_eq!(file, StateFile::V2(state));
}

#[test]
fn writes_replace_the_file_instead_of_rewriting_it() {
    let (_dir, store, state) = initialised();
    let old_bytes = state_bytes(&store);
    let mut old_file = File::open(store.state_path()).unwrap();
    let old_inode = old_file.metadata().unwrap().ino();

    let next = bump(&store, &state);

    // A reader that opened the old file still reads all of it, unchanged:
    // the new state went to a different file renamed over the path.
    let mut seen = Vec::new();
    old_file.read_to_end(&mut seen).unwrap();
    assert_eq!(seen, old_bytes);
    assert_ne!(fs::metadata(store.state_path()).unwrap().ino(), old_inode);
    assert_eq!(store.load().unwrap(), next);
    assert!(!temp_path(&store.state_path()).exists());
}

#[test]
fn a_temp_file_left_by_a_crash_is_ignored_then_replaced() {
    let (_dir, store, state) = initialised();
    let temp = temp_path(&store.state_path());
    // A crash in the middle of a write leaves a partial temporary file.
    fs::write(&temp, b"{\"version\":1,\"deployment\":{\"config_gen").unwrap();
    assert_eq!(store.load().unwrap(), state, "readers never look at it");

    let next = bump(&store, &state);
    assert!(!temp.exists(), "the next write replaced and renamed it");
    assert_eq!(store.load().unwrap(), next);
    assert_eq!(mode_of(&store.state_path()), 0o600);
}

#[test]
fn a_failed_write_leaves_the_state_untouched() {
    let (_dir, store, state) = initialised();
    let before = state_bytes(&store);
    let temp = temp_path(&store.state_path());
    // Something the store cannot remove sits where its temporary file goes.
    fs::create_dir(&temp).unwrap();
    fs::write(temp.join("keep"), b"x").unwrap();

    let error = store_error(
        store
            .update_config(state.deployment.config_generation(), Ok::<_, Infallible>)
            .unwrap_err(),
    );
    assert_eq!(error.kind(), StoreErrorKind::Io);
    assert!(
        matches!(&error, StoreError::Io { op: IoOp::RemoveStaleTemp, path, .. } if *path == temp),
        "{error:?}"
    );
    let error = store
        .set_exit_enabled(state.runtime.revision, true)
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::Io);

    assert_eq!(state_bytes(&store), before);
    assert_eq!(store.load().unwrap(), state);
}

#[cfg(target_os = "macos")]
#[test]
fn a_lock_that_cannot_be_taken_is_a_typed_error() {
    use std::process::Command;

    let (_dir, store, state) = initialised();
    // macOS refuses flock(2) on a FIFO with EOPNOTSUPP.
    fs::remove_file(store.lock_path()).unwrap();
    let status = Command::new("/usr/bin/mkfifo")
        .arg(store.lock_path())
        .status()
        .unwrap();
    assert!(status.success());

    let error = store.load().unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::Lock);
    assert!(
        matches!(&error, StoreError::Lock { path, .. } if *path == store.lock_path()),
        "{error:?}"
    );
    let error = store
        .set_exit_enabled(state.runtime.revision, true)
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::Lock);
}
