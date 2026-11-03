// SPDX-License-Identifier: GPL-3.0-or-later

//! Bootstrap's host profile (design §8.6), applied once the agent is
//! installed and before the keys: a profile that `sshd -t` rejects fails
//! bootstrap at its validation, with nothing installed and root's keys as
//! they were; and the profile lets the watch search the directory of the
//! upgrade log it reads, which Debian keeps from everyone else.

use std::fs;

use mooring_agent_proto::{AgentError, HostAccount, HostFile, HostProfile, ValidationTool};

use super::world::Host;
use crate::tests::scratch;

#[test]
fn a_profile_sshd_rejects_installs_nothing_and_keeps_the_old_keys() {
    let host = Host::new();
    host.faults.borrow_mut().sshd_warns = true;
    let node = host.node();
    let Err(AgentError::StageValidation { tool, stderr_tail }) = host.bootstrap(&node) else {
        panic!("not a validation failure");
    };
    assert_eq!(tool, ValidationTool::Sshd);
    assert!(stderr_tail.as_str().contains("Deprecated option"));
    assert!(!host.paths.host_file(HostFile::SshdDropIn).exists());
    assert!(
        fs::read_to_string(host.paths.root_authorized_keys())
            .unwrap()
            .contains("provider-console")
    );
}

/// The watch reads the upgrade log's time; the profile lets it search the
/// log's directory, which Debian keeps from everyone else.
#[test]
fn the_watch_may_reach_the_upgrade_log_it_reads() {
    let (_dir, paths) = scratch();
    let log = paths.unattended_upgrades_log();
    let grants: Vec<(std::path::PathBuf, &str)> = HostProfile::CURRENT
        .search_grants
        .iter()
        .map(|grant| (paths.at(grant.dir), grant.user))
        .collect();
    assert_eq!(
        grants,
        [(
            log.parent().unwrap().to_path_buf(),
            HostAccount::Watch.name()
        )]
    );
}
