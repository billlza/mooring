// SPDX-License-Identifier: GPL-3.0-or-later

//! `Bootstrap` and `RevokeBootstrap` against a fresh stand-in host: root
//! only in its account databases, the user-data's injected host keys, and
//! a stand-in node whose account and key tools change the scratch files as
//! Debian's would.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;

use mooring_agent_proto::{
    AgentError, BootstrapStep, HostAccount, HostFile, HostProfile, LineRequest, Response, Role,
    Sha256Hex, SshEd25519Key, ValidationTool,
};

use super::serve::{ask, frame};
use super::{FakeNode, failed, ok, own_ids, scratch};
use crate::blobs::digest_of;
use crate::bootstrap::{Keys, bootstrap, revoke};
use crate::host::Tool;
use crate::paths::Paths;
use crate::store::read_json;

const BOOTSTRAP_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDovDYBFQ/EJvmYfk0of5lLLTslEzJnEr8ZzZjVXapq4";
const OPS_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH";
/// The key the stand-in `ssh-keygen` makes.
const NEW_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// The host key the user-data injected.
const INJECTED_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// How the stand-in host misbehaves, and what it saw.
#[derive(Debug, Default)]
struct Faults {
    /// `dpkg-query` lists only the first two packages installed.
    missing_packages: bool,
    /// `apt-get install` fails.
    apt_fails: bool,
    /// `useradd` fails.
    useradd_fails: bool,
    /// `usermod` succeeds but changes nothing.
    usermod_ignored: bool,
    /// `dpkg-query` lists every package, the last as removed (`rc`).
    last_package_removed: bool,
    /// `ssh-keygen` fails.
    keygen_fails: bool,
    /// `sshd -t` warns.
    sshd_warns: bool,
    /// Whether `authorized_keys` held the ops line when sshd was reloaded.
    keys_at_reload: Option<bool>,
}

struct Host {
    _dir: tempfile::TempDir,
    paths: Paths,
    sha: Sha256Hex,
    faults: Rc<RefCell<Faults>>,
}

fn write(paths: &Paths, path: &str, text: &str) {
    let path = paths.at(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn keys() -> (SshEd25519Key, SshEd25519Key) {
    (
        SshEd25519Key::new(BOOTSTRAP_KEY).unwrap(),
        SshEd25519Key::new(OPS_KEY).unwrap(),
    )
}

impl Host {
    /// A Debian host as the user-data leaves it.
    fn new() -> Self {
        let (dir, paths) = scratch();
        let (uid, gid) = own_ids(&paths);
        write(
            &paths,
            "/etc/passwd",
            &format!("root:x:{uid}:{gid}:root:/root:/bin/bash\n"),
        );
        write(&paths, "/etc/group", &format!("root:x:{gid}:\n"));
        write(&paths, "/proc/self/exe", "the agent's bytes");
        write(&paths, "/etc/ssh/ssh_host_ed25519_key", "injected private");
        write(
            &paths,
            "/etc/ssh/ssh_host_ed25519_key.pub",
            &format!("{INJECTED_HOST_KEY} root@cloud\n"),
        );
        write(&paths, "/etc/ssh/ssh_host_rsa_key", "rsa private");
        write(
            &paths,
            "/etc/ssh/ssh_host_rsa_key.pub",
            "ssh-rsa AAAA root@cloud\n",
        );
        write(
            &paths,
            "/etc/ssh/sshd_config",
            "Include /etc/ssh/sshd_config.d/*.conf\n",
        );
        write(
            &paths,
            "/root/.ssh/authorized_keys",
            &format!("{BOOTSTRAP_KEY} mooring-bootstrap\nssh-rsa AAAA provider-console\n"),
        );
        for sysctl in HostProfile::CURRENT.sysctls {
            write(&paths, &sysctl.proc_path(), "0\n");
        }
        let sha = digest_of(fs::File::open(paths.own_executable()).unwrap()).unwrap();
        Self {
            _dir: dir,
            paths,
            sha,
            faults: Rc::new(RefCell::new(Faults::default())),
        }
    }

    /// The stand-in node: `groupadd`, `useradd`, `usermod` and
    /// `ssh-keygen` change the scratch files; every other tool succeeds.
    fn node(&self) -> FakeNode {
        let faults = Rc::clone(&self.faults);
        let apt = Rc::clone(&self.faults);
        let paths = self.paths.clone();
        let (uid, gid) = own_ids(&paths);
        FakeNode::answering(
            0,
            Box::new(move |tool, args| {
                let mut faults = faults.borrow_mut();
                let append = |path: std::path::PathBuf, line: String| {
                    let mut text = fs::read_to_string(&path).unwrap();
                    text.push_str(&line);
                    fs::write(path, text).unwrap();
                };
                let after = |flag: &str| {
                    args.iter()
                        .position(|arg| *arg == flag)
                        .map(|index| args[index + 1].to_owned())
                };
                Ok(match tool {
                    Tool::DpkgQuery => {
                        let listed = if faults.missing_packages { 2 } else { 5 };
                        let text: String = args[2..2 + listed]
                            .iter()
                            .enumerate()
                            .map(|(index, package)| {
                                let status = if faults.last_package_removed && index == 4 {
                                    "rc"
                                } else {
                                    "ii"
                                };
                                format!("{package} {status} \n")
                            })
                            .collect();
                        ok(text.as_bytes())
                    }
                    Tool::Groupadd => {
                        append(paths.group(), format!("{}:x:{gid}:\n", args[1]));
                        ok(b"")
                    }
                    Tool::Useradd if faults.useradd_fails => {
                        failed(b"useradd: cannot lock /etc/passwd\n")
                    }
                    Tool::Useradd => {
                        append(
                            paths.passwd(),
                            format!(
                                "{}:x:{uid}:{gid}::{}:{}\n",
                                args.last().unwrap(),
                                after("--home-dir").unwrap(),
                                after("--shell").unwrap()
                            ),
                        );
                        ok(b"")
                    }
                    Tool::Usermod if faults.usermod_ignored => ok(b""),
                    Tool::Usermod => {
                        let name = args.last().unwrap();
                        let text: String = fs::read_to_string(paths.passwd())
                            .unwrap()
                            .lines()
                            .map(|line| {
                                if line.starts_with(&format!("{name}:")) {
                                    format!(
                                        "{name}:x:{uid}:{gid}::{}:{}\n",
                                        after("--home").unwrap(),
                                        after("--shell").unwrap()
                                    )
                                } else {
                                    format!("{line}\n")
                                }
                            })
                            .collect();
                        fs::write(paths.passwd(), text).unwrap();
                        ok(b"")
                    }
                    Tool::SshKeygen if faults.keygen_fails => failed(b"ssh-keygen: no space\n"),
                    Tool::SshKeygen => {
                        let path = after("-f").unwrap();
                        fs::write(&path, "fresh private").unwrap();
                        fs::write(format!("{path}.pub"), format!("{NEW_HOST_KEY} \n")).unwrap();
                        ok(b"")
                    }
                    Tool::Sshd if faults.sshd_warns => {
                        failed(b"/etc/ssh/sshd_config line 3: Deprecated option\n")
                    }
                    Tool::Systemctl if args == ["reload", "ssh.service"] => {
                        let keys = fs::read_to_string(paths.root_authorized_keys()).unwrap();
                        faults.keys_at_reload = Some(keys.contains(OPS_KEY));
                        ok(b"")
                    }
                    _ => ok(b""),
                })
            }),
        )
        .programs(Box::new(move |_, args| {
            Ok(
                if apt.borrow().apt_fails && args.first() == Some(&"install") {
                    failed(b"E: Unable to locate package wireguard-tools\n")
                } else {
                    ok(b"")
                },
            )
        }))
    }

    fn bootstrap(&self, node: &FakeNode) -> Result<SshEd25519Key, AgentError> {
        let (bootstrap_key, ops_key) = keys();
        bootstrap(
            &self.paths,
            node,
            self.sha,
            Keys {
                bootstrap: &bootstrap_key,
                ops: &ops_key,
            },
        )
    }
}

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

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
    assert_eq!(
        bootstrap(
            &host.paths,
            &node,
            expected,
            Keys {
                bootstrap: &bootstrap_key,
                ops: &ops_key,
            },
        ),
        Err(AgentError::AgentShaMismatch {
            expected,
            actual: host.sha,
        })
    );
    assert!(node.calls().is_empty());
    assert!(!host.paths.var_lib().exists());
}

#[test]
fn missing_packages_are_installed_non_interactively() {
    let host = Host::new();
    host.faults.borrow_mut().missing_packages = true;
    let node = host.node();
    host.bootstrap(&node).unwrap();
    let calls = node.calls();
    assert_eq!(
        &calls[1..3],
        [
            "DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update -q",
            "DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y -q --no-install-recommends wireguard-tools nftables chrony unattended-upgrades curl",
        ]
    );
}

#[test]
fn an_apt_failure_is_reported_with_its_stderr_and_nothing_else_is_done() {
    let host = Host::new();
    {
        let mut faults = host.faults.borrow_mut();
        faults.missing_packages = true;
        faults.apt_fails = true;
    }
    let node = host.node();
    let Err(AgentError::Apt { stderr_tail }) = host.bootstrap(&node) else {
        panic!("not an apt failure");
    };
    assert!(stderr_tail.as_str().contains("Unable to locate package"));
    assert_eq!(node.calls().len(), 3);
    assert!(!host.paths.var_lib().exists());
}

#[test]
fn an_account_that_differs_from_the_profile_is_corrected() {
    let host = Host::new();
    let (uid, gid) = own_ids(&host.paths);
    write(
        &host.paths,
        "/etc/passwd",
        &format!(
            "root:x:{uid}:{gid}:root:/root:/bin/bash\n\
             mooring-view:x:{uid}:{gid}::/home/view:/usr/sbin/nologin\n"
        ),
    );
    write(
        &host.paths,
        "/etc/group",
        &format!("root:x:{gid}:\nmooring:x:{gid}:\n"),
    );
    let node = host.node();
    host.bootstrap(&node).unwrap();
    assert!(
        node.calls().contains(
            &"/usr/sbin/usermod --gid mooring --home /nonexistent --shell /bin/sh mooring-view"
                .to_owned()
        )
    );
    let view = crate::accounts::user(&host.paths, "mooring-view")
        .unwrap()
        .unwrap();
    assert_eq!(view.shell, "/bin/sh");
}

#[test]
fn an_account_tool_failure_stops_bootstrap_with_its_step() {
    let host = Host::new();
    host.faults.borrow_mut().useradd_fails = true;
    let node = host.node();
    let Err(AgentError::Bootstrap { step, stderr_tail }) = host.bootstrap(&node) else {
        panic!("not a bootstrap failure");
    };
    assert_eq!(step, BootstrapStep::Accounts);
    assert!(stderr_tail.as_str().contains("cannot lock"));
    assert!(!host.paths.etc().exists());
}

#[test]
fn a_host_key_failure_leaves_the_keys_restricted_and_sshd_as_it_was() {
    let host = Host::new();
    host.faults.borrow_mut().keygen_fails = true;
    let node = host.node();
    assert!(matches!(
        host.bootstrap(&node),
        Err(AgentError::Bootstrap {
            step: BootstrapStep::HostKey,
            ..
        })
    ));
    // The bootstrap key can run the forced command again: a retry works.
    let keys = fs::read_to_string(host.paths.root_authorized_keys()).unwrap();
    assert!(keys.starts_with(Role::Bootstrap.authorized_keys_options()));
    assert!(host.paths.agent_current().exists());
    assert_eq!(
        fs::read_to_string(host.paths.ssh_host_key()).unwrap(),
        "injected private"
    );
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("reload ssh.service"))
    );
    assert_eq!(
        read_json::<SshEd25519Key>(&host.paths.host_key_record()),
        Ok(None)
    );
    // The retry replaces the key.
    host.faults.borrow_mut().keygen_fails = false;
    assert_eq!(
        host.bootstrap(&host.node()),
        Ok(SshEd25519Key::new(NEW_HOST_KEY).unwrap())
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

#[test]
fn revoke_removes_only_the_bootstrap_line() {
    let host = Host::new();
    host.bootstrap(&host.node()).unwrap();
    revoke(&host.paths).unwrap();
    let ops_only = format!("{} {OPS_KEY}\n", Role::Ops.authorized_keys_options());
    assert_eq!(
        fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
        ops_only
    );
    assert_eq!(mode(&host.paths.root_authorized_keys()), 0o600);
    // Again: nothing to remove.
    revoke(&host.paths).unwrap();
    assert_eq!(
        fs::read_to_string(host.paths.root_authorized_keys()).unwrap(),
        ops_only
    );
}

#[test]
fn revoke_with_no_keys_file_has_nothing_to_do() {
    let (_dir, paths) = scratch();
    assert_eq!(revoke(&paths), Ok(()));
    assert!(!paths.root_authorized_keys().exists());
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
fn the_layout_refuses_a_link_where_a_directory_belongs() {
    let host = Host::new();
    super::bootstrapped(&host.paths);
    fs::create_dir_all(host.paths.var_lib()).unwrap();
    std::os::unix::fs::symlink("/tmp", host.paths.gate_dir()).unwrap();
    assert_eq!(
        crate::layout::converge(&host.paths, &HostProfile::CURRENT),
        Err(crate::store::malformed(
            mooring_agent_proto::IoOp::WriteState
        ))
    );
}

/// Every directory the agent and the watch write is one the layout sets,
/// and the watch's unit lets it write exactly its own.
#[test]
fn the_agent_writes_only_inside_the_layout() {
    let (_dir, paths) = scratch();
    let layout: Vec<std::path::PathBuf> = HostProfile::CURRENT
        .directories
        .iter()
        .map(|dir| paths.at(dir.path))
        .collect();
    for dir in [
        paths.var_lib(),
        paths.blobs(),
        paths.txn_dir(),
        paths.gate_dir(),
        paths.stop_dir(),
        paths.watch_dir(),
        paths.usage_dir(),
        paths.etc(),
        paths.engine_store(),
        paths.agent_dir(),
        paths.geodata_link().parent().unwrap().to_path_buf(),
    ] {
        assert!(layout.contains(&dir), "{}", dir.display());
    }
    let writable: Vec<std::path::PathBuf> = HostProfile::CURRENT
        .watch_writable()
        .iter()
        .map(|dir| paths.at(dir))
        .collect();
    for dir in [
        paths.gate_dir(),
        paths.stop_dir(),
        paths.watch_dir(),
        paths.usage_dir(),
        paths.gate_lock().parent().unwrap().to_path_buf(),
    ] {
        assert!(writable.contains(&dir), "{}", dir.display());
    }
    assert_eq!(paths.stop_request().parent().unwrap(), paths.stop_dir());
    assert_eq!(paths.holds().parent().unwrap(), paths.gate_dir());
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

#[test]
fn a_package_dpkg_knows_but_has_not_installed_is_installed() {
    let host = Host::new();
    host.faults.borrow_mut().last_package_removed = true;
    let node = host.node();
    host.bootstrap(&node).unwrap();
    assert!(
        node.calls()
            .iter()
            .any(|call| call.contains("/usr/bin/apt-get install")),
        "curl is only rc"
    );
}

/// Writes a viewer that differs from the profile only in `shell`.
fn viewer_with_shell(host: &Host, shell: &str) {
    let (uid, gid) = own_ids(&host.paths);
    write(
        &host.paths,
        "/etc/passwd",
        &format!(
            "root:x:{uid}:{gid}:root:/root:/bin/bash\n\
             mooring-view:x:{uid}:{gid}::/nonexistent:{shell}\n"
        ),
    );
    write(
        &host.paths,
        "/etc/group",
        &format!("root:x:{gid}:\nmooring:x:{gid}:\n"),
    );
}

#[test]
fn a_viewer_without_a_real_shell_is_given_one() {
    let host = Host::new();
    viewer_with_shell(&host, "/usr/sbin/nologin");
    let node = host.node();
    host.bootstrap(&node).unwrap();
    assert!(
        node.calls().contains(
            &"/usr/sbin/usermod --gid mooring --home /nonexistent --shell /bin/sh mooring-view"
                .to_owned()
        )
    );
}

#[test]
fn an_account_the_tools_did_not_correct_is_reported() {
    let host = Host::new();
    viewer_with_shell(&host, "/usr/sbin/nologin");
    host.faults.borrow_mut().usermod_ignored = true;
    let node = host.node();
    let Err(AgentError::Bootstrap { step, stderr_tail }) = host.bootstrap(&node) else {
        panic!("not a bootstrap failure");
    };
    assert_eq!(step, BootstrapStep::Accounts);
    assert!(stderr_tail.as_str().contains("mooring-view still differs"));
    assert!(!host.paths.etc().exists(), "nothing after the accounts");
}

#[test]
fn a_missing_state_group_is_the_watchs_missing_account() {
    let host = Host::new();
    super::bootstrapped(&host.paths);
    let (_, gid) = own_ids(&host.paths);
    write(
        &host.paths,
        "/etc/group",
        &format!("root:x:{gid}:\nmooring-xray:x:{gid}:\nmooring-hy2:x:{gid}:\n"),
    );
    assert_eq!(
        crate::layout::converge(&host.paths, &HostProfile::CURRENT),
        Err(AgentError::AccountMissing {
            account: HostAccount::Watch
        })
    );
}

#[test]
fn the_layout_gives_each_directory_its_group() {
    use std::os::unix::fs::MetadataExt;
    let host = Host::new();
    super::bootstrapped(&host.paths);
    let (_, primary) = own_ids(&host.paths);
    let output = std::process::Command::new("id").arg("-G").output().unwrap();
    let other: u32 = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|gid| gid.parse().unwrap())
        .find(|gid| *gid != primary)
        .expect("this test needs a user in a group besides its own");
    write(
        &host.paths,
        "/etc/group",
        &format!(
            "root:x:{primary}:\nmooring:x:{other}:\nmooring-xray:x:{primary}:\nmooring-hy2:x:{primary}:\n"
        ),
    );
    crate::layout::converge(&host.paths, &HostProfile::CURRENT).unwrap();
    for dir in HostProfile::CURRENT.directories {
        let expected = if dir.group == "mooring" {
            other
        } else {
            primary
        };
        assert_eq!(
            fs::metadata(host.paths.at(dir.path)).unwrap().gid(),
            expected,
            "{}",
            dir.path
        );
    }
}
