// SPDX-License-Identifier: GPL-3.0-or-later

//! `Bootstrap` and `RevokeBootstrap` (design §13.2) against the fresh
//! stand-in host of [`world`]. This file holds bootstrap's whole path: the
//! host set up step by step in order and its new key returned, a second
//! run that only converges and keeps the key, an agent that is not the
//! one expected refused before anything is done, and an agent link that
//! cannot be made stopping it before the keys, so that a retry goes
//! through; and both requests served to their roles. The packages, the
//! accounts, the layout, the host profile and the SSH steps have files of
//! their own, as does revoke.

mod accounts;
mod host_profile;
mod layout;
mod packages;
mod revoke;
mod ssh;
mod world;

use std::fs;

use mooring_agent_proto::{
    AgentError, HostAccount, HostProfile, IoOp, LineRequest, Response, Role, Sha256Hex,
    SshEd25519Key,
};

use super::EEXIST;
use super::serve::{ask, frame};
use crate::store::read_json;
use world::{BOOTSTRAP_KEY, Host, NEW_HOST_KEY, OPS_KEY, keys, mode, new_key};

#[test]
fn bootstrap_sets_the_host_up_and_returns_its_new_key() {
    let host = Host::new();
    let node = host.node();
    assert_eq!(
        host.bootstrap(&node),
        Ok(SshEd25519Key::new(NEW_HOST_KEY).unwrap())
    );
    let paths = &host.paths;
    // The accounts, each with its group, home and shell.
    for account in HostAccount::ALL {
        let user = crate::accounts::user(paths, account.name())
            .unwrap()
            .unwrap();
        assert_eq!(
            (user.home.as_str(), user.shell.as_str()),
            (account.home(), account.shell())
        );
        assert!(
            crate::accounts::group_id(paths, account.group())
                .unwrap()
                .is_some()
        );
    }
    // The layout, with its modes.
    for dir in HostProfile::CURRENT.directories {
        assert_eq!(mode(&paths.at(dir.path)), dir.mode, "{}", dir.path);
    }
    // The agent, installed and current.
    let installed = paths.agent_dir().join(host.sha.to_string());
    assert_eq!(fs::read(&installed).unwrap(), b"the agent's bytes");
    assert_eq!(mode(&installed), 0o755);
    assert_eq!(
        fs::read_link(paths.agent_current()).unwrap(),
        std::path::Path::new(&host.sha.to_string())
    );
    // The profile's files and version.
    for (file, text) in HostProfile::CURRENT.files() {
        assert_eq!(fs::read_to_string(paths.host_file(file)).unwrap(), text);
    }
    assert_eq!(
        read_json(&paths.host_profile()).unwrap(),
        Some(HostProfile::CURRENT.version)
    );
    // Only the two role lines; the provider's key is gone.
    assert_eq!(
        fs::read_to_string(paths.root_authorized_keys()).unwrap(),
        format!(
            "{} {BOOTSTRAP_KEY}\n{} {OPS_KEY}\n",
            Role::Bootstrap.authorized_keys_options(),
            Role::Ops.authorized_keys_options()
        )
    );
    assert_eq!(mode(&paths.root_authorized_keys()), 0o600);
    assert_eq!(mode(&paths.at("/root/.ssh")), 0o700);
    // The new host key alone, and on record.
    assert_eq!(
        fs::read_to_string(paths.ssh_host_key()).unwrap(),
        "fresh private"
    );
    let mut keys: Vec<String> = fs::read_dir(paths.ssh_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("ssh_host_"))
        .collect();
    keys.sort();
    assert_eq!(keys, ["ssh_host_ed25519_key", "ssh_host_ed25519_key.pub"]);
    assert_eq!(
        read_json(&paths.host_key_record()).unwrap(),
        Some(SshEd25519Key::new(NEW_HOST_KEY).unwrap())
    );
    // sshd was reloaded once, last, with the keys already in place.
    assert_eq!(host.faults.borrow().keys_at_reload, Some(true));
    let calls = node.calls();
    assert_eq!(
        calls.last().unwrap(),
        "/usr/bin/systemctl reload ssh.service"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.contains("reload ssh.service"))
            .count(),
        1
    );
    let tools: Vec<&str> = calls
        .iter()
        .map(|call| call.split(' ').next().unwrap())
        .collect();
    assert_eq!(
        tools,
        [
            "/usr/bin/dpkg-query",
            "/usr/sbin/groupadd",
            "/usr/sbin/useradd",
            "/usr/sbin/useradd",
            "/usr/sbin/groupadd",
            "/usr/sbin/useradd",
            "/usr/sbin/groupadd",
            "/usr/sbin/useradd",
            "/usr/sbin/sshd",
            "/usr/bin/systemd-analyze",
            "/usr/bin/systemd-tmpfiles",
            "/usr/sbin/sysctl",
            "/usr/bin/systemctl",
            "/usr/bin/systemctl",
            "/usr/bin/systemctl",
            "/usr/bin/systemctl",
            "/usr/bin/systemctl",
            "/usr/bin/systemctl",
            "/usr/bin/systemctl",
            "/usr/bin/systemctl",
            "/usr/bin/ssh-keygen",
            "/usr/bin/systemctl",
        ]
    );
    assert_eq!(
        calls[2],
        "/usr/sbin/useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid mooring mooring-watch"
    );
    assert_eq!(
        calls[3],
        "/usr/sbin/useradd --system --no-create-home --home-dir /nonexistent --shell /bin/sh --gid mooring mooring-view"
    );
    assert_eq!(calls[4], "/usr/sbin/groupadd --system mooring-xray");
    // Only the units that need no generation are verified before there
    // is one.
    let verify = &calls[9];
    for unit in [
        "mooring-watch.service",
        "mooring-reflect.service",
        "mooring-txn-recover.service",
        "mooring-target-check.service",
        "mooring-target-check.timer",
    ] {
        assert!(verify.contains(unit), "{verify}");
    }
    assert!(!verify.contains("mooring-xray.service"), "{verify}");
    assert!(!verify.contains("mooring-hy2.service"), "{verify}");
    assert_eq!(
        &calls[14..20],
        [
            "/usr/bin/systemctl restart mooring-watch.service",
            "/usr/bin/systemctl restart mooring-reflect.service",
            "/usr/bin/systemctl restart mooring-target-check.timer",
            "/usr/bin/systemctl restart systemd-journald.service",
            "/usr/bin/systemctl enable nftables.service wg-quick@wgexit.service mooring-xray.service mooring-hy2.service mooring-watch.service mooring-reflect.service mooring-txn-recover.service mooring-target-check.timer",
            "/usr/bin/systemctl start mooring-watch.service mooring-reflect.service mooring-target-check.timer",
        ]
    );
    // Nothing of the scratch staging is left.
    assert!(!paths.validate_dir().join("bootstrap-host").exists());
}

#[test]
fn a_second_bootstrap_keeps_the_host_key_and_only_converges() {
    let host = Host::new();
    let first = host.bootstrap(&host.node()).unwrap();
    let node = host.node();
    assert_eq!(host.bootstrap(&node), Ok(first));
    let calls = node.calls();
    for absent in [
        "groupadd",
        "useradd",
        "usermod",
        "ssh-keygen",
        "daemon-reload",
        "sysctl",
        "journald",
    ] {
        assert!(
            calls.iter().all(|call| !call.contains(absent)),
            "{absent}: {calls:#?}"
        );
    }
    assert_eq!(
        calls.last().unwrap(),
        "/usr/bin/systemctl reload ssh.service"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("/usr/bin/systemctl enable "))
    );
}

#[test]
fn bootstrap_refuses_an_agent_that_is_not_the_one_expected() {
    let host = Host::new();
    let node = host.node();
    let (bootstrap_key, ops_key) = keys();
    let expected = Sha256Hex::from_bytes([7; 32]);
    let request = LineRequest::Bootstrap {
        expected_agent_sha: expected,
        bootstrap_pubkey: bootstrap_key,
        ops_pubkey: ops_key,
    };
    assert_eq!(
        ask(&host.paths, &node, Role::Bootstrap, frame(&request)),
        Err(AgentError::AgentShaMismatch {
            expected,
            actual: host.sha,
        })
    );
    assert!(node.calls().is_empty());
    assert!(!host.paths.var_lib().exists());
}

#[test]
fn bootstrap_and_revoke_are_served_to_their_roles() {
    let host = Host::new();
    let node = host.node();
    let (bootstrap_key, ops_key) = keys();
    let request = LineRequest::Bootstrap {
        expected_agent_sha: host.sha,
        bootstrap_pubkey: bootstrap_key,
        ops_pubkey: ops_key,
    };
    assert_eq!(
        ask(&host.paths, &node, Role::Bootstrap, frame(&request)),
        Ok(Response::BootstrapDone {
            host_pubkey: SshEd25519Key::new(NEW_HOST_KEY).unwrap()
        })
    );
    assert_eq!(
        ask(
            &host.paths,
            &node,
            Role::Ops,
            frame(&LineRequest::RevokeBootstrap)
        ),
        Ok(Response::BootstrapRevoked)
    );
    assert!(
        !fs::read_to_string(host.paths.root_authorized_keys())
            .unwrap()
            .contains(BOOTSTRAP_KEY)
    );
}

#[test]
fn an_agent_link_that_cannot_be_made_stops_bootstrap_before_the_keys() {
    let host = Host::new();
    // The link's temporary name is taken.
    let link = host.paths.agent_current();
    let blocker = link.with_extension(format!("swap.{}", std::process::id()));
    fs::create_dir_all(&blocker).unwrap();
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    assert_eq!(
        host.bootstrap(&host.node()),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert!(fs::symlink_metadata(&link).is_err(), "no link");
    assert_eq!(
        fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
        keys,
        "the keys as the user-data left them"
    );
    fs::remove_dir(&blocker).unwrap();
    assert_eq!(host.bootstrap(&host.node()), Ok(new_key()), "a retry");
}
