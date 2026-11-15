// SPDX-License-Identifier: GPL-3.0-or-later

//! The record of the SIM's network (design §10.2, §15.3): written with
//! mode 0600 in the daemon's run directory, read back with a bound, none
//! where there is no file, and a read that fails reported as such.
//! (`tests::regular_files` refuses a link, and anything else but a regular
//! file, where the record belongs.)

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;

use super::{assert_io_error, mode_of};
use crate::error::IoOp;
use crate::sim_network::{SIM_NETWORK_FILE, read_sim_network, write_sim_network};

#[test]
fn the_record_is_written_private_and_read_back_within_its_bound() {
    let run = tempfile::tempdir().unwrap();
    assert_eq!(read_sim_network(run.path(), 64).unwrap(), None);
    write_sim_network(run.path(), b"{\"version\": 1}\n").unwrap();
    let path = run.path().join(SIM_NETWORK_FILE);
    assert_eq!(path.file_name().unwrap(), "sim-network.json");
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(
        read_sim_network(run.path(), 64).unwrap().as_deref(),
        Some(&b"{\"version\": 1}\n"[..])
    );
    // A second write replaces it; the read stops at its bound.
    write_sim_network(run.path(), b"0123456789").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"0123456789");
    assert_eq!(
        read_sim_network(run.path(), 4).unwrap().as_deref(),
        Some(&b"0123"[..])
    );
}

/// A record that cannot be read is an error naming the read, never no
/// record, which the daemon would take as its first run: here the open
/// fails (the record is mode 0000; the tests run unprivileged).
#[test]
fn a_record_that_cannot_be_read_is_an_error_naming_the_read() {
    let run = tempfile::tempdir().unwrap();
    write_sim_network(run.path(), b"{\"version\": 1}\n").unwrap();
    let path = run.path().join(SIM_NETWORK_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let error = read_sim_network(run.path(), 64).unwrap_err();
    assert_io_error(
        &error,
        IoOp::ReadSimNetwork,
        &path,
        io::ErrorKind::PermissionDenied,
    );
    assert_eq!(
        error.to_string(),
        format!(
            "failed to read the record of the SIM's network at {}",
            path.display()
        )
    );
}

/// A write into a run directory that is not there fails, and leaves
/// nothing behind for a later read to find.
#[test]
fn a_write_without_its_directory_fails_and_leaves_no_record() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("run");
    assert!(write_sim_network(&missing, b"{\"version\": 1}\n").is_err());
    assert!(!missing.exists());
    assert_eq!(read_sim_network(&missing, 64).unwrap(), None);
}
