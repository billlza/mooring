// SPDX-License-Identifier: GPL-3.0-or-later

//! State files: atomic, strict, and absent read as absent.

use std::os::unix::fs::PermissionsExt;

use mooring_agent_proto::{AgentError, Holds, IoOp, OperatorHold, UnixTime};

use super::scratch;
use crate::store::{Lock, read_json, write_json};

#[test]
fn state_round_trips_with_its_mode_and_leaves_no_temporary_file() {
    let (_dir, paths) = scratch();
    let held = Holds {
        operator: Some(OperatorHold {
            at: UnixTime::from_secs(9),
        }),
        ..Holds::NONE
    };
    write_json(&paths.holds(), &held, 0o640).unwrap();
    assert_eq!(read_json::<Holds>(&paths.holds()).unwrap(), Some(held));
    let mode = std::fs::metadata(paths.holds())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o640);
    let names: Vec<String> = std::fs::read_dir(paths.gate_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["holds.json".to_owned()]);
}

#[test]
fn an_absent_file_is_none_and_a_damaged_one_an_error() {
    let (_dir, paths) = scratch();
    assert_eq!(read_json::<Holds>(&paths.holds()).unwrap(), None);
    std::fs::create_dir_all(paths.gate_dir()).unwrap();
    for damaged in [
        "",
        "{}",
        r#"{"mac_drain":null,"egress_violation":null,"operator":null,"extra":1}"#,
        "not json",
    ] {
        std::fs::write(paths.holds(), damaged).unwrap();
        assert_eq!(
            read_json::<Holds>(&paths.holds()),
            Err(AgentError::Io {
                op: IoOp::ReadState,
                errno: None
            }),
            "{damaged:?}"
        );
    }
}

#[test]
fn the_lock_is_exclusive_across_handles() {
    let (_dir, paths) = scratch();
    let held = Lock::exclusive(&paths.gate_lock()).unwrap();
    let second = std::fs::OpenOptions::new()
        .write(true)
        .open(paths.gate_lock())
        .unwrap();
    assert!(second.try_lock().is_err(), "a second lock was granted");
    drop(held);
    second.try_lock().unwrap();
}
