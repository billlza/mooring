// SPDX-License-Identifier: GPL-3.0-or-later

//! Host-profile convergence (design §8.6, §11.6) where a step fails: the
//! staging, the validators and the installation each report the failure
//! they meet, and the installed profile version is recorded only once
//! every file is in place.

use std::fs;
use std::io;
use std::path::PathBuf;

use mooring_agent_proto::{
    AgentError, ApplyStep, BootstrapStep, HostFile, HostProfile, HostProfileVersion, IoOp,
};

use super::{EEXIST, ENOENT, ENOTDIR, FakeNode, bootstrapped, occupy_temporary, scratch};
use crate::hostfiles::{self, HostStep};
use crate::paths::Paths;
use crate::store::{malformed, read_json};

/// The profile staged in a scratch directory of `paths`.
fn staged(paths: &Paths) -> PathBuf {
    let dir = paths.at("/staged");
    hostfiles::stage(&dir, &HostProfile::CURRENT).unwrap();
    dir
}

#[test]
fn staging_through_a_file_is_a_state_write() {
    let (_dir, paths) = scratch();
    fs::write(paths.at("/staged"), "not a directory").unwrap();
    assert_eq!(
        hostfiles::stage(&paths.at("/staged/host"), &HostProfile::CURRENT),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(ENOTDIR)
        })
    );
}

#[test]
fn validation_reports_scratch_space_it_cannot_make() {
    let (_dir, paths) = scratch();
    bootstrapped(&paths);
    let staged = staged(&paths);
    let refused = Err(AgentError::Io {
        op: IoOp::WriteState,
        errno: Some(EEXIST),
    });
    // A file stands where the validators' scratch directory belongs.
    fs::create_dir_all(paths.validate_dir().parent().unwrap()).unwrap();
    fs::write(paths.validate_dir(), "not a directory").unwrap();
    let node = FakeNode::new(1);
    assert_eq!(hostfiles::validate(&paths, &node, &staged, None), refused);
    assert!(node.calls().is_empty());
    // And where the copies of the units belong.
    fs::remove_file(paths.validate_dir()).unwrap();
    fs::create_dir_all(paths.validate_dir()).unwrap();
    fs::write(paths.validate_dir().join("units"), "not a directory").unwrap();
    assert_eq!(hostfiles::validate(&paths, &node, &staged, None), refused);
    assert_eq!(node.calls().len(), 1, "sshd judged the drop-in first");
}

#[test]
fn a_validator_that_cannot_start_is_a_spawn_failure_and_leaves_no_copy() {
    let (_dir, paths) = scratch();
    bootstrapped(&paths);
    let staged = staged(&paths);
    let node = FakeNode::answering(
        1,
        Box::new(|_, _| Err(io::Error::from_raw_os_error(ENOENT))),
    );
    assert_eq!(
        hostfiles::validate(&paths, &node, &staged, None),
        Err(AgentError::Io {
            op: IoOp::SpawnProcess,
            errno: Some(ENOENT)
        })
    );
    assert!(
        !paths.validate_dir().join("sshd_config").exists(),
        "the drop-in's wrapper is removed"
    );
}

#[test]
fn a_staged_unit_that_is_gone_cannot_be_verified() {
    let (_dir, paths) = scratch();
    bootstrapped(&paths);
    let staged = staged(&paths);
    fs::remove_file(staged.join(HostFile::WatchUnit.staged_name())).unwrap();
    assert_eq!(
        hostfiles::validate(&paths, &FakeNode::new(1), &staged, None),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOENT)
        })
    );
}

#[test]
fn an_installation_that_fails_records_no_version() {
    let unrecorded = |paths: &Paths| {
        assert_eq!(
            read_json::<HostProfileVersion>(&paths.host_profile()),
            Ok(None)
        );
    };
    // A staged file is gone.
    let (_dir, paths) = scratch();
    let files = staged(&paths);
    fs::remove_file(files.join(HostFile::SshdDropIn.staged_name())).unwrap();
    assert_eq!(
        hostfiles::install(&paths, &files),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOENT)
        })
    );
    unrecorded(&paths);
    // A target cannot be written.
    let (_dir, paths) = scratch();
    let files = staged(&paths);
    let _blocker = occupy_temporary(&paths.host_file(HostFile::Journald));
    assert_eq!(
        hostfiles::install(&paths, &files),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    unrecorded(&paths);
    // No version was staged.
    let (_dir, paths) = scratch();
    let files = staged(&paths);
    fs::remove_file(files.join("profile.json")).unwrap();
    assert_eq!(
        hostfiles::install(&paths, &files),
        Err(malformed(IoOp::ReadState))
    );
    unrecorded(&paths);
}

#[test]
fn each_step_is_reported_as_the_protocol_names_it() {
    for (step, apply, bootstrap) in [
        (
            HostStep::Units,
            ApplyStep::DaemonReload,
            BootstrapStep::Units,
        ),
        (HostStep::Sysctl, ApplyStep::Sysctl, BootstrapStep::Sysctl),
        (
            HostStep::Tmpfiles,
            ApplyStep::Tmpfiles,
            BootstrapStep::Tmpfiles,
        ),
        (
            HostStep::Journald,
            ApplyStep::Journald,
            BootstrapStep::Journald,
        ),
        (
            HostStep::SshdReload,
            ApplyStep::SshdReload,
            BootstrapStep::SshdReload,
        ),
    ] {
        assert_eq!(
            (step.apply_step(), step.bootstrap_step()),
            (apply, bootstrap),
            "{step:?}"
        );
    }
}
