// SPDX-License-Identifier: GPL-3.0-or-later

//! Bootstrap's host profile (design §8.6), applied once the agent is
//! installed and before the keys: a profile that `sshd -t` rejects fails
//! bootstrap at its validation, and one that cannot be staged or
//! installed fails it as the write or read that failed, each with nothing
//! applied and root's keys as they were. A step of applying it that
//! fails stops bootstrap at that step; units that cannot be started stop
//! it with the profile applied, and units that cannot be enabled stop a
//! later run with the recorded key kept. The profile lets the watch
//! search the directory of the upgrade log it reads, which Debian keeps
//! from everyone else.

use std::fs;

use mooring_agent_proto::{
    AgentError, BootstrapStep, HostAccount, HostFile, HostProfile, IoOp, StderrTail, ValidationTool,
};

use super::world::{Failing, Host, new_key, write};
use crate::host::Tool;
use crate::store::read_json;
use crate::tests::{EISDIR, ENOTDIR, scratch};

/// Whether `calls` hold none of the tools that validate or apply a host
/// profile, sshd's reload included: a bootstrap stopped before them.
fn applies_nothing(calls: &[String]) -> bool {
    calls.iter().all(|call| {
        [
            "/usr/sbin/sshd",
            "systemd-analyze",
            "systemd-tmpfiles",
            "sysctl",
            "systemctl",
        ]
        .iter()
        .all(|tool| !call.contains(tool))
    })
}

/// Root's `authorized_keys` and the host key as the user-data left them.
fn assert_keys_as_they_were(host: &Host, keys: &str) {
    assert_eq!(
        fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
        keys,
        "the keys as the user-data left them"
    );
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "injected private"
    );
}

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

/// A profile that cannot be staged (a file stands where the scratch space
/// belongs) is validated, installed and applied not at all.
#[test]
fn a_profile_that_cannot_be_staged_installs_nothing_and_keeps_the_old_keys() {
    let host = Host::new();
    write(&host.paths, "/run/mooring/validate", "not a directory");
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(ENOTDIR)
        })
    );
    assert!(
        host.paths.agent_current().exists(),
        "the agent, installed first"
    );
    assert!(!host.paths.host_profile().exists());
    for (file, _) in HostProfile::CURRENT.files() {
        assert!(!host.paths.host_file(file).exists(), "{file:?}");
    }
    assert!(applies_nothing(&node.calls()), "{:#?}", node.calls());
    assert_keys_as_they_were(&host, &keys);
}

/// A profile file that cannot be installed (a directory stands where the
/// first belongs) records no version and applies nothing, its scratch
/// staging goes all the same, and a retry goes through.
#[test]
fn a_profile_that_cannot_be_installed_applies_nothing_and_keeps_the_old_keys() {
    let host = Host::new();
    let sysctl = host.paths.host_file(HostFile::Sysctl);
    fs::create_dir_all(&sysctl).unwrap();
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(EISDIR)
        })
    );
    assert!(!host.paths.host_profile().exists());
    for (file, _) in HostProfile::CURRENT.files() {
        if file != HostFile::Sysctl {
            assert!(!host.paths.host_file(file).exists(), "{file:?}");
        }
    }
    assert!(!host.paths.validate_dir().join("bootstrap-host").exists());
    let calls = node.calls();
    assert!(
        calls
            .last()
            .unwrap()
            .starts_with("/usr/bin/systemd-analyze verify "),
        "validated, then nothing: {calls:#?}"
    );
    assert_keys_as_they_were(&host, &keys);
    fs::remove_dir(&sysctl).unwrap();
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
}

/// A step of applying the profile that fails stops bootstrap at that
/// step, with what it printed, and nothing after it runs: no later step,
/// no final start of the units, no keys. The files are installed by then.
#[test]
fn a_profile_step_that_fails_stops_bootstrap_at_that_step() {
    for (failing, step, command) in [
        (
            Failing {
                tool: Tool::SystemdTmpfiles,
                argument: "--create",
                stderr: "Failed to create directory or subvolume \"/run/mooring\": Permission denied\n",
            },
            BootstrapStep::Tmpfiles,
            "/usr/bin/systemd-tmpfiles --create /etc/tmpfiles.d/mooring.conf",
        ),
        (
            Failing {
                tool: Tool::Sysctl,
                argument: "--system",
                stderr: "sysctl: setting key \"net.core.default_qdisc\": Invalid argument\n",
            },
            BootstrapStep::Sysctl,
            "/usr/sbin/sysctl --system",
        ),
        (
            Failing {
                tool: Tool::Systemctl,
                argument: "daemon-reload",
                stderr: "Failed to reload daemon: Access denied\n",
            },
            BootstrapStep::Units,
            "/usr/bin/systemctl daemon-reload",
        ),
        (
            Failing {
                tool: Tool::Systemctl,
                argument: "systemd-journald.service",
                stderr: "Job for systemd-journald.service failed.\n",
            },
            BootstrapStep::Journald,
            "/usr/bin/systemctl restart systemd-journald.service",
        ),
    ] {
        let host = Host::new();
        let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
        host.faults.borrow_mut().failing = Some(failing);
        let node = host.node();
        assert_eq!(
            host.bootstrap(&node),
            Err(AgentError::Bootstrap {
                step,
                stderr_tail: StderrTail::scrubbed(failing.stderr.as_bytes(), &[]),
            }),
            "{command}"
        );
        assert_eq!(node.calls().last().unwrap(), command, "nothing after it");
        for (file, text) in HostProfile::CURRENT.files() {
            assert_eq!(
                fs::read_to_string(host.paths.host_file(file)).unwrap(),
                text,
                "{command}: {file:?}"
            );
        }
        assert_keys_as_they_were(&host, &keys);
    }
}

/// Units that cannot be started stop bootstrap at the units, with the
/// profile applied and the keys as they were; a retry goes through.
#[test]
fn units_that_cannot_be_started_stop_bootstrap_before_the_keys() {
    const FAILED: &str = "Job for mooring-watch.service failed because the control process exited with error code.\n";
    let host = Host::new();
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    host.faults.borrow_mut().failing = Some(Failing {
        tool: Tool::Systemctl,
        argument: "start",
        stderr: FAILED,
    });
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Bootstrap {
            step: BootstrapStep::Units,
            stderr_tail: StderrTail::scrubbed(FAILED.as_bytes(), &[]),
        })
    );
    let calls = node.calls();
    assert_eq!(
        &calls[calls.len() - 3..],
        [
            "/usr/bin/systemctl restart systemd-journald.service",
            "/usr/bin/systemctl enable nftables.service wg-quick@wgexit.service mooring-xray.service mooring-hy2.service mooring-watch.service mooring-reflect.service mooring-txn-recover.service mooring-target-check.timer",
            "/usr/bin/systemctl start mooring-watch.service mooring-reflect.service mooring-target-check.timer",
        ],
        "the profile's last step, its units enabled, then the start that failed"
    );
    assert_eq!(
        read_json(&host.paths.host_profile()),
        Ok(Some(HostProfile::CURRENT.version)),
        "the profile installed"
    );
    assert_keys_as_they_were(&host, &keys);
    host.faults.borrow_mut().failing = None;
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
}

/// Every run enables the profile's units, a later one too, which has no
/// changed unit to enable them before: units that cannot be enabled stop
/// it at the units, before sshd is reloaded, with the recorded key kept.
#[test]
fn units_that_cannot_be_enabled_stop_a_later_bootstrap_with_its_key_kept() {
    const FAILED: &str = "Failed to enable unit: Access denied\n";
    let host = Host::new();
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()));
    host.faults.borrow_mut().failing = Some(Failing {
        tool: Tool::Systemctl,
        argument: "enable",
        stderr: FAILED,
    });
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Err(AgentError::Bootstrap {
            step: BootstrapStep::Units,
            stderr_tail: StderrTail::scrubbed(FAILED.as_bytes(), &[]),
        })
    );
    let calls = node.calls();
    assert!(
        calls
            .last()
            .unwrap()
            .starts_with("/usr/bin/systemctl enable "),
        "{calls:#?}"
    );
    assert!(
        calls.iter().all(|call| !call.contains("daemon-reload")),
        "no unit changed: {calls:#?}"
    );
    assert_eq!(
        read_json(&host.paths.host_key_record()),
        Ok(Some(new_key()))
    );
    host.faults.borrow_mut().failing = None;
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
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
