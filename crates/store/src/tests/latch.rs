// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit's latch (design §10.2): its exact format and mode, its removal,
//! the typed refusal of anything that is not a version-1 latch, and a read
//! that fails reported as such.

use std::fs;
use std::io;
use std::net::Ipv4Addr;

use mooring_model::counters::ConfigGeneration;
use mooring_model::iface::{BsdName, EgressIdentity, MacAddr};
use mooring_model::time::UnixTime;
use mooring_model::verdict::{LatchRecord, Violation};

use super::{assert_io_error, mode_of};
use crate::error::{IoOp, StoreError, StoreErrorKind};
use crate::latch::{LATCH_FILE, clear_latch, read_latch, write_latch};

fn latch() -> LatchRecord {
    LatchRecord {
        violation: Violation::OutsideCarrierPrefixes {
            ip: Ipv4Addr::new(46, 78, 90, 99),
        },
        at: UnixTime::from_secs(1_791_900_000),
        config_generation: ConfigGeneration::new(7).unwrap(),
        egress: EgressIdentity {
            bsd_name: BsdName::parse("en9").unwrap(),
            lladdr: MacAddr::parse("02:00:5e:10:20:31").unwrap(),
        },
    }
}

#[test]
fn a_latch_round_trips_with_mode_0600_and_clears() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read_latch(dir.path()).unwrap(), None);
    write_latch(dir.path(), &latch()).unwrap();
    let path = dir.path().join(LATCH_FILE);
    assert_eq!(mode_of(&path), 0o600);
    let text = fs::read_to_string(&path).unwrap();
    assert!(
        text.starts_with("{\n  \"version\": 1,\n  \"latch\": {"),
        "{text}"
    );
    assert!(text.ends_with("}\n"));
    assert_eq!(read_latch(dir.path()).unwrap(), Some(latch()));
    clear_latch(dir.path()).unwrap();
    assert!(!path.exists());
    assert_eq!(read_latch(dir.path()).unwrap(), None);
    // Clearing no latch is fine.
    clear_latch(dir.path()).unwrap();
}

#[test]
fn anything_but_a_version_one_latch_is_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    write_latch(dir.path(), &latch()).unwrap();
    let path = dir.path().join(LATCH_FILE);
    let good = fs::read_to_string(&path).unwrap();
    for bad in [
        String::new(),
        "not json".to_owned(),
        good.replace("\"version\": 1", "\"version\": 2"),
        good.replace("\"latch\": {", "\"latch\": {\"extra\": 1,"),
        "x".repeat(64 * 1024 + 1),
    ] {
        fs::write(&path, &bad).unwrap();
        let error = read_latch(dir.path()).unwrap_err();
        assert_eq!(error.kind(), StoreErrorKind::LatchCorrupt, "{bad:.40}");
        assert!(matches!(error, StoreError::LatchCorrupt { path: ref found } if *found == path));
    }
}

/// A latch that cannot be read is an error naming the read, never "no
/// latch", on which the exit would serve again past a latched violation:
/// here the open fails (the run path is a file), then the read does (the
/// latch path is a directory).
#[test]
fn a_latch_that_cannot_be_read_is_an_error_not_no_latch() {
    let dir = tempfile::tempdir().unwrap();
    let run_file = dir.path().join("run");
    fs::write(&run_file, b"").unwrap();
    assert_io_error(
        &read_latch(&run_file).unwrap_err(),
        IoOp::ReadLatch,
        &run_file.join(LATCH_FILE),
        io::ErrorKind::NotADirectory,
    );
    let run_dir = tempfile::tempdir().unwrap();
    let path = run_dir.path().join(LATCH_FILE);
    fs::create_dir(&path).unwrap();
    assert_io_error(
        &read_latch(run_dir.path()).unwrap_err(),
        IoOp::ReadLatch,
        &path,
        io::ErrorKind::IsADirectory,
    );
}

/// A latch that cannot be removed is an error naming the removal, never a
/// latch cleared: here a directory is where the latch belongs, which
/// `unlink` refuses (`EISDIR` on Linux, `EPERM` on macOS).
#[test]
fn a_latch_that_cannot_be_removed_is_an_error_not_cleared() {
    let run_dir = tempfile::tempdir().unwrap();
    let path = run_dir.path().join(LATCH_FILE);
    fs::create_dir(&path).unwrap();
    let refused = if cfg!(target_os = "linux") {
        io::ErrorKind::IsADirectory
    } else {
        io::ErrorKind::PermissionDenied
    };
    assert_io_error(
        &clear_latch(run_dir.path()).unwrap_err(),
        IoOp::RemoveLatch,
        &path,
        refused,
    );
    assert!(path.is_dir());
}
