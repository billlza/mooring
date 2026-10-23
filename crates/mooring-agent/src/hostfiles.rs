// SPDX-License-Identifier: GPL-3.0-or-later

//! Host-profile convergence (design §8.6, §11.6): the profile's files are
//! staged, validated, installed where their text differs from what is
//! installed, and applied by the steps their change needs. A transaction
//! stages them with its generation (`gen-<N>/host/`), so a rollback puts
//! back the previous generation's; `Bootstrap` stages them in a scratch
//! directory of its own.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, BootstrapStep, CURRENT_DIR, ENABLED_UNITS, HostFile, HostProfile,
    HostProfileVersion, IoOp, StderrTail, ValidationTool,
};

use crate::host::{Node, Tool};
use crate::paths::Paths;
use crate::store::{ensure_dir, io_error, read_json, write_atomic, write_json};

/// A generation's subdirectory holding its staged profile files.
pub(crate) const HOST_DIR: &str = "host";

/// The staged files' profile version, beside them.
const VERSION_FILE: &str = "profile.json";

/// The installed host profile version's mode: the state group reads it.
const VERSION_MODE: u32 = 0o640;

/// Writes every file of `profile` into `dir` (0644: none holds a secret)
/// with the profile's version.
pub(crate) fn stage(dir: &Path, profile: &HostProfile) -> Result<(), AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    ensure_dir(dir).map_err(fail)?;
    for (file, text) in profile.files() {
        write_atomic(&dir.join(file.staged_name()), text.as_bytes(), 0o644).map_err(fail)?;
    }
    write_json(&dir.join(VERSION_FILE), &profile.version, 0o644)
}

/// Whether a staged unit file runs a program of the current generation
/// (an engine): `systemd-analyze verify` checks that a unit's programs
/// exist, and before the first swap those do not. A path it only names in
/// a condition does not need to exist.
fn runs_a_generation(text: &str) -> bool {
    text.lines()
        .any(|line| line.starts_with("ExecStart=") && line.contains(CURRENT_DIR))
}

/// The host validators (design §11.2 step 3), run after the bundle's on
/// the files staged in `staged`: every kernel parameter's key exists under
/// `/proc/sys`; sshd accepts the staged drop-in in front of the host's own
/// configuration; and systemd verifies the staged units. A unit that runs
/// a program of the current generation (an engine) is verified with the
/// generation in `generation` in its place, which is what `current` will
/// be after the swap; `Bootstrap`, which has no generation yet, verifies
/// the other units only. Both tools print nothing when they accept, and
/// their diagnostics carry no level word (`systemd-analyze` reports an
/// unknown key or a missing program as plain text, and exits 0 for the
/// former), so they must exit 0 and print nothing at all.
pub(crate) fn validate(
    paths: &Paths,
    node: &dyn Node,
    staged: &Path,
    generation: Option<&Path>,
) -> Result<(), AgentError> {
    let rejected = |tool: ValidationTool, text: &[u8]| AgentError::StageValidation {
        tool,
        stderr_tail: StderrTail::scrubbed(text, &[]),
    };
    for sysctl in HostProfile::CURRENT.sysctls {
        let key = sysctl.proc_path();
        if fs::symlink_metadata(paths.at(&key)).is_err() {
            return Err(rejected(
                ValidationTool::SysctlKeys,
                format!("{key} does not exist").as_bytes(),
            ));
        }
    }
    let scratch = paths.validate_dir();
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    ensure_dir(&scratch).map_err(fail)?;
    // The staged drop-in first: for every directive but `AllowUsers`
    // sshd keeps the first value it reads.
    let wrapper = scratch.join("sshd_config");
    let wrapper_text = format!(
        "Include {}\nInclude /etc/ssh/sshd_config\n",
        staged.join(HostFile::SshdDropIn.staged_name()).display()
    );
    write_atomic(&wrapper, wrapper_text.as_bytes(), 0o600).map_err(fail)?;
    let sshd = judge(
        node,
        Tool::Sshd,
        &["-t", "-f", &wrapper.display().to_string()],
        ValidationTool::Sshd,
    );
    let _absent = fs::remove_file(&wrapper);
    sshd?;
    let units_dir = scratch.join("units");
    let units = unit_copies(staged, &units_dir, generation)?;
    let mut args = vec!["verify".to_owned()];
    args.extend(units.iter().map(|unit| unit.display().to_string()));
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let verified = judge(
        node,
        Tool::SystemdAnalyze,
        &args,
        ValidationTool::SystemdAnalyze,
    );
    let _absent = fs::remove_dir_all(&units_dir);
    verified
}

/// Copies the staged unit files to verify into `dir`, with the current
/// generation's directory replaced by `generation`'s; without a
/// generation, the units that run one of its programs are left out.
fn unit_copies(
    staged: &Path,
    dir: &Path,
    generation: Option<&Path>,
) -> Result<Vec<std::path::PathBuf>, AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    let _stale = fs::remove_dir_all(dir);
    ensure_dir(dir).map_err(fail)?;
    let mut copies = Vec::new();
    for file in HostFile::ALL.iter().filter(|file| file.unit().is_some()) {
        let text = fs::read_to_string(staged.join(file.staged_name()))
            .map_err(|error| io_error(IoOp::ReadState, &error))?;
        let text = match generation {
            Some(generation) => text.replace(CURRENT_DIR, &generation.display().to_string()),
            None if runs_a_generation(&text) => continue,
            None => text,
        };
        let copy = dir.join(file.staged_name());
        write_atomic(&copy, text.as_bytes(), 0o644).map_err(fail)?;
        copies.push(copy);
    }
    Ok(copies)
}

/// Runs a validator; `StageValidation{tool}` unless it exits 0 and prints
/// nothing but blank space.
fn judge(
    node: &dyn Node,
    run: Tool,
    args: &[&str],
    tool: ValidationTool,
) -> Result<(), AgentError> {
    let output = node
        .run(run, args)
        .map_err(|error| io_error(IoOp::SpawnProcess, &error))?;
    let judged = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    if output.success && judged.iter().all(u8::is_ascii_whitespace) {
        Ok(())
    } else {
        Err(AgentError::StageValidation {
            tool,
            stderr_tail: StderrTail::scrubbed(&judged, &[]),
        })
    }
}

/// Installs every file staged in `staged` whose text differs from the
/// installed one (atomically, 0644, creating its directory 0755), records
/// the staged profile version as the installed one, and returns the files
/// it changed.
pub(crate) fn install(paths: &Paths, staged: &Path) -> Result<BTreeSet<HostFile>, AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    let mut changed = BTreeSet::new();
    for &file in HostFile::ALL {
        let text = fs::read(staged.join(file.staged_name()))
            .map_err(|error| io_error(IoOp::ReadState, &error))?;
        let target = paths.host_file(file);
        let installed = match fs::read(&target) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error(IoOp::ReadState, &error)),
        };
        if installed.as_deref() != Some(text.as_slice()) {
            if let Some(parent) = target.parent() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o755)
                    .create(parent)
                    .map_err(fail)?;
            }
            write_atomic(&target, &text, 0o644).map_err(fail)?;
            changed.insert(file);
        }
    }
    let version: HostProfileVersion = read_json(&staged.join(VERSION_FILE))?
        .ok_or_else(|| crate::store::malformed(IoOp::ReadState))?;
    write_json(&paths.host_profile(), &version, VERSION_MODE)?;
    Ok(changed)
}

/// Whether `file` is read by systemd's manager, so a change needs a
/// `daemon-reload`.
fn read_by_systemd(file: HostFile) -> bool {
    file.unit().is_some() || file == HostFile::TunnelDropIn
}

/// A step a change of the profile's files needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostStep {
    /// `daemon-reload`, the units enabled, the watch or reflector
    /// restarted.
    Units,
    /// `sysctl --system`.
    Sysctl,
    /// `systemd-tmpfiles --create`.
    Tmpfiles,
    /// journald restarted.
    Journald,
    /// sshd reloaded.
    SshdReload,
}

impl HostStep {
    /// The step as a transaction reports it.
    pub(crate) const fn apply_step(self) -> ApplyStep {
        match self {
            Self::Units => ApplyStep::DaemonReload,
            Self::Sysctl => ApplyStep::Sysctl,
            Self::Tmpfiles => ApplyStep::Tmpfiles,
            Self::Journald => ApplyStep::Journald,
            Self::SshdReload => ApplyStep::SshdReload,
        }
    }

    /// The step as `Bootstrap` reports it.
    pub(crate) const fn bootstrap_step(self) -> BootstrapStep {
        match self {
            Self::Units => BootstrapStep::Units,
            Self::Sysctl => BootstrapStep::Sysctl,
            Self::Tmpfiles => BootstrapStep::Tmpfiles,
            Self::Journald => BootstrapStep::Journald,
            Self::SshdReload => BootstrapStep::SshdReload,
        }
    }
}

/// One command a change needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Command {
    /// The step it belongs to.
    pub(crate) step: HostStep,
    /// The tool.
    pub(crate) tool: Tool,
    /// Its arguments.
    pub(crate) args: Vec<String>,
}

fn command(step: HostStep, tool: Tool, args: &[&str]) -> Command {
    Command {
        step,
        tool,
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
    }
}

/// What a change of the profile files in `changed` needs, in order
/// (design §11.2 step 5): `/run/mooring` first, which the watch's unit
/// needs to start (its lock, and a `ReadWritePaths` entry that must
/// exist); the kernel parameters; the units reloaded and enabled, and the
/// watch, the reflector or the target check's timer restarted when its
/// unit changed; journald, which
/// reads its drop-in only at start; sshd. Restarting an engine whose unit
/// changed is the transaction's own step, with its configuration's. The
/// kernel modules and the upgrade policy take effect when they are next
/// read (at boot, at the next upgrade run).
pub(crate) fn commands(changed: &BTreeSet<HostFile>) -> Vec<Command> {
    let mut commands = Vec::new();
    if changed.contains(&HostFile::Tmpfiles) {
        commands.push(command(
            HostStep::Tmpfiles,
            Tool::SystemdTmpfiles,
            &["--create", HostFile::Tmpfiles.path()],
        ));
    }
    if changed.contains(&HostFile::Sysctl) {
        commands.push(command(HostStep::Sysctl, Tool::Sysctl, &["--system"]));
    }
    if changed.iter().any(|file| read_by_systemd(*file)) {
        commands.push(command(
            HostStep::Units,
            Tool::Systemctl,
            &["daemon-reload"],
        ));
        let mut enable = vec!["enable"];
        enable.extend(ENABLED_UNITS);
        commands.push(command(HostStep::Units, Tool::Systemctl, &enable));
        for file in [
            HostFile::WatchUnit,
            HostFile::ReflectUnit,
            HostFile::TargetCheckTimer,
        ] {
            if changed.contains(&file)
                && let Some(unit) = file.unit()
            {
                commands.push(command(
                    HostStep::Units,
                    Tool::Systemctl,
                    &["restart", unit],
                ));
            }
        }
    }
    if changed.contains(&HostFile::Journald) {
        commands.push(command(
            HostStep::Journald,
            Tool::Systemctl,
            &["restart", "systemd-journald.service"],
        ));
    }
    if changed.contains(&HostFile::SshdDropIn) {
        commands.push(command(
            HostStep::SshdReload,
            Tool::Systemctl,
            &["reload", SSHD_UNIT],
        ));
    }
    commands
}

/// Debian's sshd unit.
pub(crate) const SSHD_UNIT: &str = "ssh.service";
