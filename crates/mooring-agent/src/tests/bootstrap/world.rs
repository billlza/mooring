// SPDX-License-Identifier: GPL-3.0-or-later

//! The fresh stand-in host the bootstrap tests run against: root only in
//! its account databases, the user-data's injected host keys, and a
//! stand-in node whose account and key tools change the scratch files as
//! Debian's would, with the faults a test can set in it; and the keys
//! bootstrap is given and the host key it makes.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::rc::Rc;

use mooring_agent_proto::{AgentError, HostProfile, Sha256Hex, SshEd25519Key};

use crate::blobs::digest_of;
use crate::bootstrap::{Keys, bootstrap};
use crate::host::Tool;
use crate::paths::Paths;
use crate::tests::{ENOENT, FakeNode, failed, ok, own_ids, scratch};

pub(super) const BOOTSTRAP_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDovDYBFQ/EJvmYfk0of5lLLTslEzJnEr8ZzZjVXapq4";

pub(super) const OPS_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH";

/// The key the stand-in `ssh-keygen` makes.
pub(super) const NEW_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// The host key the user-data injected.
pub(super) const INJECTED_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// How the stand-in host misbehaves, and what it saw.
#[derive(Debug, Default)]
pub(super) struct Faults {
    /// `dpkg-query` lists only the first two packages installed.
    pub(super) missing_packages: bool,
    /// `apt-get install` fails.
    pub(super) apt_fails: bool,
    /// `useradd` fails.
    pub(super) useradd_fails: bool,
    /// This tool succeeds but does nothing.
    pub(super) ignored: Option<Tool>,
    /// `dpkg-query` lists every package, the last as removed (`rc`).
    pub(super) last_package_removed: bool,
    /// `ssh-keygen` fails.
    pub(super) keygen_fails: bool,
    /// `ssh-keygen` writes this half of the new key only.
    pub(super) keygen_writes_only: Option<KeyHalf>,
    /// `sshd -t` warns.
    pub(super) sshd_warns: bool,
    /// This tool cannot be started.
    pub(super) unstartable: Option<Tool>,
    /// A call that fails.
    pub(super) failing: Option<Failing>,
    /// `systemctl reload ssh.service` fails.
    pub(super) reload_fails: bool,
    /// Whether `authorized_keys` held the ops line when sshd was reloaded.
    pub(super) keys_at_reload: Option<bool>,
}

/// One half of a key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyHalf {
    /// The private key.
    Private,
    /// The public key, `<private key>.pub`.
    Public,
}

/// A call of `tool` with `argument` among its arguments, which exits 1
/// printing `stderr`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Failing {
    pub(super) tool: Tool,
    pub(super) argument: &'static str,
    pub(super) stderr: &'static str,
}

pub(super) struct Host {
    _dir: tempfile::TempDir,
    pub(super) paths: Paths,
    pub(super) sha: Sha256Hex,
    pub(super) faults: Rc<RefCell<Faults>>,
}

pub(super) fn write(paths: &Paths, path: &str, text: &str) {
    let path = paths.at(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

pub(super) fn keys() -> (SshEd25519Key, SshEd25519Key) {
    (
        SshEd25519Key::new(BOOTSTRAP_KEY).unwrap(),
        SshEd25519Key::new(OPS_KEY).unwrap(),
    )
}

impl Host {
    /// A Debian host as the user-data leaves it.
    pub(super) fn new() -> Self {
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
    pub(super) fn node(&self) -> FakeNode {
        let faults = Rc::clone(&self.faults);
        let apt = Rc::clone(&self.faults);
        let paths = self.paths.clone();
        let (uid, gid) = own_ids(&paths);
        FakeNode::answering(
            0,
            Box::new(move |tool, args| {
                let mut faults = faults.borrow_mut();
                if faults.unstartable == Some(tool) {
                    return Err(io::Error::from_raw_os_error(ENOENT));
                }
                if let Some(failing) = faults.failing
                    && failing.tool == tool
                    && args.contains(&failing.argument)
                {
                    return Ok(failed(failing.stderr.as_bytes()));
                }
                if faults.ignored == Some(tool) {
                    return Ok(ok(b""));
                }
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
                    // As OpenSSH's does, with no terminal to say yes on.
                    Tool::SshKeygen if std::path::Path::new(&after("-f").unwrap()).exists() => {
                        failed(b"ssh_host_ed25519_key.mooring already exists.\nOverwrite (y/n)? ")
                    }
                    Tool::SshKeygen => {
                        let path = after("-f").unwrap();
                        if faults.keygen_writes_only != Some(KeyHalf::Public) {
                            fs::write(&path, "fresh private").unwrap();
                        }
                        if faults.keygen_writes_only != Some(KeyHalf::Private) {
                            fs::write(format!("{path}.pub"), format!("{NEW_HOST_KEY} \n")).unwrap();
                        }
                        ok(b"")
                    }
                    Tool::Sshd if faults.sshd_warns => {
                        failed(b"/etc/ssh/sshd_config line 3: Deprecated option\n")
                    }
                    Tool::Systemctl if args == ["reload", "ssh.service"] => {
                        let keys = fs::read_to_string(paths.root_authorized_keys()).unwrap();
                        faults.keys_at_reload = Some(keys.contains(OPS_KEY));
                        if faults.reload_fails {
                            failed(b"Job for ssh.service failed.\n")
                        } else {
                            ok(b"")
                        }
                    }
                    _ => ok(b""),
                })
            }),
        )
        .programs(Box::new(move |program, args| {
            let faults = apt.borrow();
            if faults
                .unstartable
                .is_some_and(|tool| std::path::Path::new(tool.path()) == program)
            {
                return Err(io::Error::from_raw_os_error(ENOENT));
            }
            Ok(if faults.apt_fails && args.first() == Some(&"install") {
                failed(b"E: Unable to locate package wireguard-tools\n")
            } else {
                ok(b"")
            })
        }))
    }

    pub(super) fn bootstrap(&self, node: &FakeNode) -> Result<SshEd25519Key, AgentError> {
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

pub(super) fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

pub(super) fn new_key() -> SshEd25519Key {
    SshEd25519Key::new(NEW_HOST_KEY).unwrap()
}
