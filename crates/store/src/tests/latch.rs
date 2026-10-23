// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit's latch (design §10.2): its exact format and mode, its removal,
//! and the typed refusal of anything that is not a version-1 latch.

use std::fs;
use std::net::Ipv4Addr;

use mooring_model::counters::ConfigGeneration;
use mooring_model::iface::{BsdName, EgressIdentity, MacAddr};
use mooring_model::time::UnixTime;
use mooring_model::verdict::{LatchRecord, Violation};

use super::mode_of;
use crate::error::{StoreError, StoreErrorKind};
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
