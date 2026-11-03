// SPDX-License-Identifier: GPL-3.0-or-later

//! State files: atomic, strict, and absent read as absent.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mooring_agent_proto::{AgentError, Holds, IoOp, OperatorHold, UnixTime};

use super::{EACCES, EISDIR, ModeFault, scratch};
use crate::store::{
    Lock, append_json_line, errno, malformed, read_json, remove, write_atomic, write_json,
};

/// A value serde cannot write, as no value the agent stores is: its
/// `Serialize` fails.
struct Unserialisable;

impl serde::Serialize for Unserialisable {
    fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("refused"))
    }
}

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
    let mode = fs::metadata(paths.holds()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);
    let names: Vec<String> = fs::read_dir(paths.gate_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["holds.json".to_owned()]);
}

#[test]
fn an_absent_file_is_none_and_a_damaged_one_an_error() {
    let (_dir, paths) = scratch();
    assert_eq!(read_json::<Holds>(&paths.holds()).unwrap(), None);
    fs::create_dir_all(paths.gate_dir()).unwrap();
    for damaged in [
        "",
        "{}",
        r#"{"mac_drain":null,"egress_violation":null,"operator":null,"extra":1}"#,
        "not json",
    ] {
        fs::write(paths.holds(), damaged).unwrap();
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
    let second = fs::OpenOptions::new()
        .write(true)
        .open(paths.gate_lock())
        .unwrap();
    assert!(second.try_lock().is_err(), "a second lock was granted");
    drop(held);
    second.try_lock().unwrap();
}

#[test]
fn only_an_io_error_has_an_error_number() {
    assert_eq!(
        errno(&AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EISDIR)
        }),
        Some(EISDIR)
    );
    assert_eq!(errno(&malformed(IoOp::ReadState)), None);
    assert_eq!(errno(&AgentError::MacReportMissing), None);
}

#[test]
fn a_value_serde_cannot_write_is_refused_before_anything_is_written() {
    let (_dir, paths) = scratch();
    assert_eq!(
        write_json(&paths.holds(), &Unserialisable, 0o640),
        Err(malformed(IoOp::WriteState))
    );
    assert!(!paths.gate_dir().exists());
    let mut lines = Vec::new();
    assert_eq!(
        append_json_line(&mut lines, &Unserialisable),
        Err(malformed(IoOp::WriteState))
    );
}

#[test]
fn values_are_appended_one_per_line() {
    let mut lines = Vec::new();
    append_json_line(&mut lines, &1_u8).unwrap();
    append_json_line(&mut lines, &"two").unwrap();
    assert_eq!(lines, b"1\n\"two\"\n");
}

#[test]
fn a_path_without_a_directory_is_refused_before_anything_is_written() {
    assert_eq!(
        write_json(Path::new("/"), &Holds::NONE, 0o640),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: None
        })
    );
    assert_eq!(
        write_atomic(Path::new("/"), b"", 0o640).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn a_removal_whose_directory_cannot_be_synced_is_reported() {
    let (_dir, paths) = scratch();
    write_json(&paths.holds(), &Holds::NONE, 0o640).unwrap();
    {
        // Writable and searchable, so the file goes; not readable, so the
        // directory cannot be opened to sync the removal.
        let _unreadable = ModeFault::set(&paths.gate_dir(), 0o300);
        assert_eq!(
            remove(&paths.holds()),
            Err(AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(EACCES)
            })
        );
    }
    assert!(!paths.holds().exists(), "removed all the same");
    assert_eq!(remove(&paths.holds()), Ok(()), "and gone is not an error");
    assert_eq!(
        remove(Path::new("/")),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: None
        }),
        "a path without a directory is refused before anything is removed"
    );
}

#[test]
fn a_lock_that_cannot_be_opened_is_a_state_write() {
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.gate_lock()).unwrap();
    let refused = AgentError::Io {
        op: IoOp::WriteState,
        errno: Some(EISDIR),
    };
    assert_eq!(Lock::exclusive(&paths.gate_lock()).unwrap_err(), refused);
    assert_eq!(
        Lock::try_exclusive(&paths.gate_lock()).unwrap_err(),
        refused
    );
}

/// A lock the filesystem refuses is an error, never taken for a lock
/// someone holds. Whether flock(2) refuses a FIFO is the OS's to say: macOS
/// does (`ENOTSUP`), Linux locks it; the test asks the OS first.
#[test]
fn a_lock_the_filesystem_refuses_is_an_error_not_a_holder() {
    let (_dir, paths) = scratch();
    let lock = paths.txn_lock();
    fs::create_dir_all(lock.parent().unwrap()).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(&lock)
        .status()
        .unwrap();
    assert!(made.success());
    let probe = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .unwrap();
    let refused = match probe.try_lock() {
        Ok(()) => None,
        Err(fs::TryLockError::Error(error)) => error.raw_os_error(),
        Err(fs::TryLockError::WouldBlock) => panic!("no one else holds it"),
    };
    drop(probe);
    match refused {
        Some(errno) => assert_eq!(
            Lock::try_exclusive(&lock).unwrap_err(),
            AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(errno)
            }
        ),
        None => assert!(Lock::try_exclusive(&lock).unwrap().is_some()),
    }
}
