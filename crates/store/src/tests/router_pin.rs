// SPDX-License-Identifier: GPL-3.0-or-later

//! The router identity file (design §15.6 rule 4): its exact format, its
//! mode, and the typed refusal of anything that is not a version-1 pin.

use std::fs;

use mooring_model::iface::MacAddr;
use mooring_model::time::UnixTime;

use super::mode_of;
use crate::error::{IoOp, StoreError, StoreErrorKind};
use crate::router_pin::{
    MAX_ROUTER_PIN_BYTES, ROUTER_PIN_FILE, RouterPin, RouterPinFault, read_router_pin,
    write_router_pin,
};

/// A made-up, locally administered unicast address (not a real device).
fn pin() -> RouterPin {
    RouterPin {
        gateway_lladdr: MacAddr::parse("02:00:5e:10:20:30").unwrap(),
        pinned_at: UnixTime::from_secs(1_791_900_000),
    }
}

const PIN_TEXT: &str = "{\n  \"version\": 1,\n  \"gateway_lladdr\": \"02:00:5e:10:20:30\",\n  \"pinned_at\": 1791900000\n}\n";

#[test]
fn router_pin_round_trips_with_mode_0600() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read_router_pin(dir.path()).unwrap(), None);
    write_router_pin(dir.path(), &pin()).unwrap();
    let path = dir.path().join(ROUTER_PIN_FILE);
    assert_eq!(fs::read_to_string(&path).unwrap(), PIN_TEXT);
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(read_router_pin(dir.path()).unwrap(), Some(pin()));
    // A second pin replaces the first, durably, with the same mode.
    let replaced = RouterPin {
        gateway_lladdr: MacAddr::parse("02:00:5e:10:20:31").unwrap(),
        pinned_at: UnixTime::from_secs(1_791_900_060),
    };
    write_router_pin(dir.path(), &replaced).unwrap();
    assert_eq!(read_router_pin(dir.path()).unwrap(), Some(replaced));
    assert_eq!(mode_of(&path), 0o600);
    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["router-identity.json", "state.lock"]);
}

#[test]
fn an_absent_pin_is_none_and_a_corrupt_one_is_typed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(ROUTER_PIN_FILE);
    let padded_to = |text: &str, len: usize| {
        let mut padded = text.trim_end().to_owned();
        padded.push_str(&" ".repeat(len - padded.len()));
        padded
    };
    let at_limit = padded_to(PIN_TEXT, MAX_ROUTER_PIN_BYTES);
    fs::write(&path, &at_limit).unwrap();
    assert_eq!(read_router_pin(dir.path()).unwrap(), Some(pin()));
    for (text, fault) in [
        ("garbage".to_owned(), RouterPinFault::Undecodable),
        (String::new(), RouterPinFault::Undecodable),
        (
            PIN_TEXT.replace("\"version\": 1", "\"version\": 2"),
            RouterPinFault::UnsupportedVersion,
        ),
        (
            "{\"version\": 2, \"other\": true}".to_owned(),
            RouterPinFault::UnsupportedVersion,
        ),
        (
            PIN_TEXT.replace("\"version\": 1", "\"version\": 0"),
            RouterPinFault::UnsupportedVersion,
        ),
        (
            PIN_TEXT.replace("\"pinned_at\"", "\"extra\": 1, \"pinned_at\""),
            RouterPinFault::Undecodable,
        ),
        (
            PIN_TEXT.replace(",\n  \"pinned_at\": 1791900000", ""),
            RouterPinFault::Undecodable,
        ),
        (
            PIN_TEXT.replace("02:00:5e:10:20:30", "01:00:5e:00:00:01"),
            RouterPinFault::Undecodable,
        ),
        (
            PIN_TEXT.replace("02:00:5e:10:20:30", "02:00:5E:10:20:30"),
            RouterPinFault::Undecodable,
        ),
        (
            padded_to(PIN_TEXT, MAX_ROUTER_PIN_BYTES + 1),
            RouterPinFault::TooLarge,
        ),
        (padded_to(PIN_TEXT, 5 * 1024), RouterPinFault::TooLarge),
    ] {
        fs::write(&path, &text).unwrap();
        let error = read_router_pin(dir.path()).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::RouterPinCorrupt, "{text}");
        match &error {
            StoreError::RouterPinCorrupt {
                path: named,
                fault: found,
            } => {
                assert_eq!(named, &path);
                assert_eq!(*found, fault, "{text}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            error.to_string(),
            format!(
                "router identity file {} is corrupt: {fault}",
                path.display()
            )
        );
    }
    assert_eq!(
        RouterPinFault::TooLarge.to_string(),
        "it is larger than 4096 bytes"
    );
    assert_eq!(
        RouterPinFault::Undecodable.to_string(),
        "it is not a version-1 router identity document"
    );
    assert_eq!(
        RouterPinFault::UnsupportedVersion.to_string(),
        "it names a format version other than 1"
    );
}

/// A pin that cannot be read is an I/O error naming the file, never "no
/// pin"; the store never creates the directory it is given.
#[test]
fn unreadable_pins_and_missing_directories_are_io_errors() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(ROUTER_PIN_FILE)).unwrap();
    match read_router_pin(dir.path()).unwrap_err() {
        StoreError::Io { op, path, .. } => {
            assert_eq!(op, IoOp::ReadRouterPin);
            assert_eq!(path, dir.path().join(ROUTER_PIN_FILE));
        }
        other => panic!("{other:?}"),
    }
    let missing = dir.path().join("absent");
    let error = write_router_pin(&missing, &pin()).unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::Io);
    assert!(!missing.exists());
}
