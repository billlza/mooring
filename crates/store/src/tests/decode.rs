// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading `state.json`: missing, corrupt and newer documents (design §7,
//! §14 `StateCorrupt`, `DowngradeRefused`).

use std::convert::Infallible;
use std::fs;

use mooring_model::exit::TrafficPolicy;

use super::builders::{applied_record, empty_store, exit_site, initialised};
use super::{state_bytes, store_error};
use crate::error::{IoOp, StoreError, StoreErrorKind};
use crate::store::Store;

/// Asserts that every operation fails with an error of `kind` and that
/// `state.json` is left as it was.
fn assert_every_operation_fails(store: &Store, kind: StoreErrorKind) {
    let before = fs::read(store.state_path()).ok();
    let generation = mooring_model::counters::ConfigGeneration::INITIAL;
    let revision = mooring_model::counters::RuntimeRevision::INITIAL;
    let errors = [
        store.load().unwrap_err(),
        store_error(
            store
                .update_config(generation, Ok::<_, Infallible>)
                .unwrap_err(),
        ),
        store
            .record(generation, applied_record("lon1", generation))
            .unwrap_err(),
        store.set_exit_enabled(revision, true).unwrap_err(),
    ];
    for error in errors {
        assert_eq!(error.kind(), kind, "{error:?}");
    }
    assert_eq!(fs::read(store.state_path()).ok(), before);
}

#[test]
fn a_missing_state_is_not_initialised() {
    let (_dir, store) = empty_store();
    assert_every_operation_fails(&store, StoreErrorKind::NotInitialized);
    assert!(
        matches!(store.load().unwrap_err(), StoreError::NotInitialized { path } if path == store.state_path())
    );
}

#[test]
fn a_missing_directory_is_an_io_error() {
    let (dir, _) = empty_store();
    let store = Store::new(dir.path().join("absent"));
    let error = store.load().unwrap_err();
    assert!(
        matches!(&error, StoreError::Io { op: IoOp::OpenLock, path, .. } if *path == store.lock_path()),
        "{error:?}"
    );
    assert_eq!(
        store
            .init(exit_site(), TrafficPolicy::default())
            .unwrap_err()
            .kind(),
        StoreErrorKind::Io
    );
}

#[test]
fn init_never_replaces_an_existing_state() {
    let (_dir, store, state) = initialised();
    let error = store
        .init(exit_site(), TrafficPolicy::default())
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::AlreadyInitialized);
    assert!(
        matches!(&error, StoreError::AlreadyInitialized { path } if *path == store.state_path()),
        "{error:?}"
    );
    assert_eq!(store.load().unwrap(), state);

    // Not even a corrupt one: the operator must look at it first.
    fs::write(store.state_path(), b"garbage").unwrap();
    let error = store
        .init(exit_site(), TrafficPolicy::default())
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::AlreadyInitialized);
    assert_eq!(state_bytes(&store), b"garbage");
}

#[test]
fn a_fresh_state_references_no_secrets() {
    let (_dir, _store, state) = initialised();
    assert!(state.deployment.required_secrets().is_empty());
    assert!(state.deployment.nodes().is_empty());
    assert!(state.deployment.users().is_empty());
    assert!(!state.runtime.exit_enabled);
}

#[test]
fn corrupt_documents_are_refused() {
    let (_dir, store, _) = initialised();
    let valid = String::from_utf8(state_bytes(&store)).unwrap();
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("not JSON", "garbage".to_owned()),
        ("truncated", valid[..valid.len() / 2].to_owned()),
        ("trailing bytes", format!("{valid}x")),
        ("no version", valid.replacen("\"version\": 1,", "", 1)),
        (
            "string version",
            valid.replacen("\"version\": 1", "\"version\": \"1\"", 1),
        ),
        (
            "negative version",
            valid.replacen("\"version\": 1", "\"version\": -1", 1),
        ),
        (
            "version beyond u32",
            valid.replacen("\"version\": 1", "\"version\": 4294967296", 1),
        ),
        (
            "version 0",
            valid.replacen("\"version\": 1", "\"version\": 0", 1),
        ),
        (
            "unknown field",
            valid.replacen("\"version\": 1,", "\"version\": 1, \"secrets\": {},", 1),
        ),
        (
            "invalid counter",
            valid.replacen("\"config_generation\": 1", "\"config_generation\": 0", 1),
        ),
        ("missing runtime", {
            let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
            value.as_object_mut().unwrap().remove("runtime");
            value.to_string()
        }),
    ];
    for (label, text) in cases {
        assert_ne!(
            text, valid,
            "{label}: the case must differ from the valid document"
        );
        fs::write(store.state_path(), &text).unwrap();
        let error = store.load().unwrap_err();
        assert!(
            matches!(&error, StoreError::StateCorrupt { path, .. } if *path == store.state_path()),
            "{label}: {error:?}"
        );
        assert_every_operation_fails(&store, StoreErrorKind::StateCorrupt);
    }
}

#[test]
fn newer_versions_are_never_downgraded() {
    let (_dir, store, _) = initialised();
    let valid = String::from_utf8(state_bytes(&store)).unwrap();
    for (found, text) in [
        (2, valid.replacen("\"version\": 1", "\"version\": 2", 1)),
        // The newer schema is unknown, so only its version is read.
        (
            3,
            r#"{"version": 3, "a_field_from_the_future": [1, 2, 3]}"#.to_owned(),
        ),
        (u32::MAX, format!(r#"{{"version": {}}}"#, u32::MAX)),
    ] {
        fs::write(store.state_path(), &text).unwrap();
        let error = store.load().unwrap_err();
        assert!(
            matches!(error, StoreError::DowngradeRefused { found: f, newest: 1 } if f == found),
            "{error:?}"
        );
        assert_every_operation_fails(&store, StoreErrorKind::DowngradeRefused);
        assert_eq!(state_bytes(&store), text.as_bytes());
        assert!(!store.backup_path(found, 1).exists());
    }
}
