// SPDX-License-Identifier: GPL-3.0-or-later

//! `Bootstrap` and `RevokeBootstrap` (design §13.2): adoption's one-time
//! set-up of a fresh Debian host, as root over the bootstrap key, and the
//! end of that key's window.
//!
//! `Bootstrap` may run again: every step converges, and the host key is
//! replaced only until a replacement has been recorded, so a retry after
//! a lost reply returns the same key. The order keeps a way back in at
//! every step: the agent is installed before `authorized_keys` restricts
//! the bootstrap key to its forced command, and sshd, which enforces the
//! profile's drop-in, is reloaded only once both are in place.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use mooring_agent_proto::{
    AgentError, BootstrapStep, ENABLED_UNITS, HostProfile, IoOp, PACKAGES, Role, Sha256Hex,
    SshEd25519Key, StderrTail,
};

use crate::host::{Node, Tool, run_ok};
use crate::hostfiles::{self, HostStep, SSHD_UNIT};
use crate::paths::Paths;
use crate::store::{io_error, malformed, read_json, write_atomic, write_json};
use crate::{accounts, layout};

/// The keys `Bootstrap` authorises.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Keys<'a> {
    /// The bootstrap key, kept for its role until `RevokeBootstrap`.
    pub(crate) bootstrap: &'a SshEd25519Key,
    /// The operations key.
    pub(crate) ops: &'a SshEd25519Key,
}

/// `Bootstrap`: returns the host's new ed25519 key, for the Mac to pin.
pub(crate) fn bootstrap(
    paths: &Paths,
    node: &dyn Node,
    expected_agent_sha: Sha256Hex,
    keys: Keys<'_>,
) -> Result<SshEd25519Key, AgentError> {
    let actual = crate::hello::own_sha(paths)?;
    if actual != expected_agent_sha {
        return Err(AgentError::AgentShaMismatch {
            expected: expected_agent_sha,
            actual,
        });
    }
    packages(node)?;
    accounts::converge(paths, node)?;
    layout::converge(paths, &HostProfile::CURRENT)?;
    crate::txn::activate::install(paths, &actual, &paths.own_executable())?;
    crate::txn::replace_link(&paths.agent_current(), Path::new(&actual.to_string()))
        .map_err(|error| io_error(IoOp::WriteState, &error))?;
    host_profile(paths, node)?;
    authorize(paths, keys)?;
    let replaced: Option<SshEd25519Key> = read_json(&paths.host_key_record())?;
    if replaced.is_none() {
        replace_host_key(paths, node)?;
    }
    host_tool(
        node,
        BootstrapStep::SshdReload,
        Tool::Systemctl,
        &["reload", SSHD_UNIT],
    )?;
    let key = host_key(paths)?;
    if replaced.is_none() {
        write_json(&paths.host_key_record(), &key, 0o640)?;
    }
    Ok(key)
}

/// `RevokeBootstrap`: removes the bootstrap role's `authorized_keys`
/// lines, whether or not any is left.
pub(crate) fn revoke(paths: &Paths) -> Result<(), AgentError> {
    let path = paths.root_authorized_keys();
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(IoOp::ReadState, &error)),
    };
    let bootstrap = format!("{} ", Role::Bootstrap.authorized_keys_options());
    let kept: String = text
        .lines()
        .filter(|line| !line.starts_with(&bootstrap))
        .flat_map(|line| [line, "\n"])
        .collect();
    if kept == text {
        return Ok(());
    }
    write_atomic(&path, kept.as_bytes(), 0o600).map_err(|error| io_error(IoOp::WriteState, &error))
}

/// Runs a tool of `step`; a failure is `Bootstrap{step}` with its stderr.
fn host_tool(
    node: &dyn Node,
    step: BootstrapStep,
    tool: Tool,
    args: &[&str],
) -> Result<(), AgentError> {
    match run_ok(node, tool, args)? {
        Ok(_) => Ok(()),
        Err(stderr) => Err(AgentError::Bootstrap {
            step,
            stderr_tail: StderrTail::scrubbed(&stderr, &[]),
        }),
    }
}

/// The node's packages ([`PACKAGES`]): nothing to do when `dpkg-query`
/// shows every one installed (the user-data installs them at first boot),
/// else `apt-get update` and `install`, non-interactively.
fn packages(node: &dyn Node) -> Result<(), AgentError> {
    let mut query = vec!["-W", "-f=${Package} ${db:Status-Abbrev}\\n"];
    query.extend(PACKAGES);
    // dpkg-query exits 1 when it knows a package not at all; what it
    // printed still lists the others.
    let listed = node
        .run(Tool::DpkgQuery, &query)
        .map_err(|error| io_error(IoOp::SpawnProcess, &error))?;
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    let installed = |package: &str| {
        listed.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some(package) && fields.next().is_some_and(|status| status == "ii")
        })
    };
    if PACKAGES.iter().all(|package| installed(package)) {
        return Ok(());
    }
    let mut install = vec!["install", "-y", "-q", "--no-install-recommends"];
    install.extend(PACKAGES);
    for args in [vec!["update", "-q"], install] {
        let output = node
            .run_program(
                Path::new(Tool::AptGet.path()),
                &args,
                &[("DEBIAN_FRONTEND", "noninteractive")],
            )
            .map_err(|error| io_error(IoOp::SpawnProcess, &error))?;
        if !output.success {
            return Err(AgentError::Apt {
                stderr_tail: StderrTail::scrubbed(&output.stderr, &[]),
            });
        }
    }
    Ok(())
}

/// The host profile: staged in scratch space, validated (the units that
/// run a generation's programs wait for the first transaction), installed,
/// and applied, sshd's reload aside, which comes once the keys are in
/// place; then every profile unit enabled, and the watch, the reflector
/// and the target check's timer started.
fn host_profile(paths: &Paths, node: &dyn Node) -> Result<(), AgentError> {
    let staged = paths.validate_dir().join("bootstrap-host");
    let _stale = fs::remove_dir_all(&staged);
    hostfiles::stage(&staged, &HostProfile::CURRENT)?;
    hostfiles::validate(paths, node, &staged, None)?;
    let changed = hostfiles::install(paths, &staged);
    let _absent = fs::remove_dir_all(&staged);
    for command in hostfiles::commands(&changed?) {
        if command.step == HostStep::SshdReload {
            continue;
        }
        let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
        host_tool(node, command.step.bootstrap_step(), command.tool, &args)?;
    }
    let mut enable = vec!["enable"];
    enable.extend(ENABLED_UNITS);
    host_tool(node, BootstrapStep::Units, Tool::Systemctl, &enable)?;
    host_tool(
        node,
        BootstrapStep::Units,
        Tool::Systemctl,
        &[
            "start",
            "mooring-watch.service",
            "mooring-reflect.service",
            "mooring-target-check.timer",
        ],
    )
}

/// Root's `authorized_keys`: the bootstrap and ops keys, each restricted
/// to its role's forced command (design §8.6), and nothing else.
fn authorize(paths: &Paths, keys: Keys<'_>) -> Result<(), AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    let path = paths.root_authorized_keys();
    let dir = path.parent().ok_or(malformed(IoOp::WriteState))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(fail)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(fail)?;
    let text = format!(
        "{} {}\n{} {}\n",
        Role::Bootstrap.authorized_keys_options(),
        keys.bootstrap,
        Role::Ops.authorized_keys_options(),
        keys.ops,
    );
    write_atomic(&path, text.as_bytes(), 0o600).map_err(fail)
}

/// Replaces the host key the user-data injected (readable from the
/// provider's metadata service for the VM's whole life, design §8.9) with
/// a fresh ed25519 key, and removes every other host key, so sshd offers
/// that one alone. The key is made beside the old one and renamed over
/// it, public half first.
fn replace_host_key(paths: &Paths, node: &dyn Node) -> Result<(), AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    let key = paths.ssh_host_key();
    let fresh = paths.ssh_dir().join("ssh_host_ed25519_key.mooring");
    for stale in [fresh.clone(), public(&fresh)] {
        match fs::remove_file(&stale) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(fail(error)),
        }
    }
    host_tool(
        node,
        BootstrapStep::HostKey,
        Tool::SshKeygen,
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "",
            "-f",
            &fresh.display().to_string(),
        ],
    )?;
    fs::rename(public(&fresh), public(&key)).map_err(fail)?;
    fs::rename(&fresh, &key).map_err(fail)?;
    for entry in fs::read_dir(paths.ssh_dir()).map_err(fail)? {
        let entry = entry.map_err(fail)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let host_key =
            name.starts_with("ssh_host_") && (name.ends_with("_key") || name.ends_with("_key.pub"));
        if host_key && !name.starts_with("ssh_host_ed25519_key") {
            fs::remove_file(entry.path()).map_err(fail)?;
        }
    }
    fs::File::open(paths.ssh_dir())
        .and_then(|dir| dir.sync_all())
        .map_err(fail)
}

/// The public half beside the private key at `path`: `<path>.pub`.
fn public(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    name.into()
}

/// The host's ed25519 public key, from `ssh_host_ed25519_key.pub`
/// (`ssh-ed25519 <base64> [comment]`).
fn host_key(paths: &Paths) -> Result<SshEd25519Key, AgentError> {
    let text = fs::read_to_string(public(&paths.ssh_host_key()))
        .map_err(|error| io_error(IoOp::ReadState, &error))?;
    let mut fields = text.split_whitespace();
    match (fields.next(), fields.next()) {
        (Some(kind), Some(blob)) => {
            SshEd25519Key::new(format!("{kind} {blob}")).map_err(|_| malformed(IoOp::ReadState))
        }
        _ => Err(malformed(IoOp::ReadState)),
    }
}
