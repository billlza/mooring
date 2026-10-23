// SPDX-License-Identifier: GPL-3.0-or-later

//! Transactions with commit-confirm (design §11.2).
//!
//! `Apply` checks what it can at once (busy, halted, unchanged, not newer),
//! records the transaction and launches `txn <N>` as a transient systemd
//! unit, so a dropped SSH session or 5G link cannot leave a half-applied
//! state. The worker runs the stages under `txn.lock`: preconditions,
//! staging, validation, the confirm timer, the swap, applying only what
//! changed, and the local health gate. A failure after the swap rolls back
//! to the previous generation; a rollback that fails too stops both engines
//! and closes the gate. The confirm timer (armed before the swap, so that
//! nothing is ever switched without it) reverts a change nobody confirms
//! within 120 s.
//!
//! The pending change's phase (launched, armed, awaiting confirmation)
//! says what a revert has to undo, so that a transaction unit that died,
//! or a reboot that lost the timer, cannot leave the node stuck `Busy`.

pub(crate) mod activate;
pub(crate) mod health;
pub(crate) mod record;
pub(crate) mod resume;
pub(crate) mod stage;
pub(crate) mod validate;

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, BundleHeader, EngineUser, Generation, HostFile, HostProfile, IoOp,
    ManagedFile, RollbackCause, StderrTail, SystemdOp, TxnStage, TxnState, UnitName, WG_INTERFACE,
};

use crate::gate::{self, engine_unit};
use crate::host::{Node, Tool, run_ok};
use crate::hostfiles;
use crate::paths::{Paths, generation_name};
use crate::store::{Lock, io_error};
use record::{
    Change, Pending, Phase, TxnRecord, clear_pending, pending, set_pending, set_record, set_state,
};

/// The confirm window (design §11.2 step 7).
pub(crate) const CONFIRM_SECS: u64 = 120;

/// The previous generations kept besides the current one (design §11.2
/// step 4).
pub(crate) const KEPT_PREVIOUS: usize = 2;

/// The transient unit of the transaction for `generation`.
pub(crate) fn txn_unit(generation: Generation) -> String {
    format!("mooring-txn-{}", generation.get())
}

/// The transient timer that reverts an unconfirmed change under
/// `generation`.
pub(crate) fn revert_unit(generation: Generation) -> String {
    format!("mooring-txn-revert-{}", generation.get())
}

fn unit_name(name: &str) -> Result<UnitName, AgentError> {
    UnitName::new(name).map_err(|_| AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: None,
    })
}

/// `Busy` with the generation of the change that holds the lock or is
/// pending.
fn busy(paths: &Paths) -> AgentError {
    let generation = match pending(paths) {
        Ok(Some(pending)) => Ok(pending.generation),
        // The lock is held but nothing is pending: a `Confirm` or revert
        // is finishing; the generation is the node's.
        Ok(None) => gate::current_generation(paths),
        Err(error) => Err(error),
    };
    match generation {
        Ok(generation) => AgentError::Busy { generation },
        Err(error) => error,
    }
}

/// Takes the transaction lock if it is free and no change is pending.
pub(crate) fn exclusive(paths: &Paths) -> Result<Lock, AgentError> {
    let Some(lock) = Lock::try_exclusive(&paths.txn_lock())? else {
        return Err(busy(paths));
    };
    if let Some(pending) = pending(paths)? {
        return Err(AgentError::Busy {
            generation: pending.generation,
        });
    }
    Ok(lock)
}

/// What `Apply` answers: the transaction launched, or the node already on
/// this bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Launched {
    /// `TxnLaunched{generation}`.
    Launched(Generation),
    /// `Unchanged{generation}`: the current generation's digest is the
    /// bundle's; nothing is restarted and holds and halt are untouched.
    Unchanged(Generation),
}

/// `Apply`: the checks that need no work, then the transaction's unit.
pub(crate) fn apply(
    paths: &Paths,
    node: &dyn Node,
    header: BundleHeader,
) -> Result<Launched, AgentError> {
    let _lock = exclusive(paths)?;
    let current = gate::current_generation(paths)?;
    if stage::installed_header(paths, current)?
        .is_some_and(|installed| installed.digest == header.digest)
    {
        return Ok(Launched::Unchanged(current));
    }
    if gate::halted(paths)?.is_some() {
        return Err(AgentError::NodeHalted);
    }
    if header.config_generation <= current {
        return Err(AgentError::GenerationNotNewer { current });
    }
    let generation = header.config_generation;
    set_record(
        paths,
        generation,
        &TxnRecord {
            header,
            state: TxnState::Running {
                stage: TxnStage::Preconditions,
            },
        },
    )?;
    set_pending(
        paths,
        &Pending {
            generation,
            change: Change::Apply { previous: current },
            phase: Phase::Launched,
        },
    )?;
    let unit = txn_unit(generation);
    let unit_arg = format!("--unit={unit}");
    let generation_arg = generation.get().to_string();
    let launched = run_ok(
        node,
        Tool::SystemdRun,
        &[
            &unit_arg,
            "--collect",
            "--quiet",
            mooring_agent_proto::AGENT_CURRENT_PATH,
            "txn",
            &generation_arg,
        ],
    )?;
    if launched.is_err() {
        let error = AgentError::Systemd {
            unit: unit_name(&format!("{unit}.service"))?,
            op: SystemdOp::Run,
        };
        set_state(
            paths,
            generation,
            TxnState::Failed {
                error: error.clone(),
            },
        )?;
        clear_pending(paths)?;
        return Err(error);
    }
    Ok(Launched::Launched(generation))
}

/// `txn <N>`, the transaction unit: runs the transaction for `generation`
/// and records how it ended.
pub(crate) fn run(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
) -> Result<(), AgentError> {
    let _lock = Lock::exclusive(&paths.txn_lock())?;
    let Some(Pending {
        change: Change::Apply { previous },
        phase: Phase::Launched,
        ..
    }) = pending(paths)?.filter(|pending| pending.generation == generation)
    else {
        return Err(AgentError::UnknownTransaction { generation });
    };
    let header = record::record(paths, generation)?.header;
    match attempt(paths, node, generation, previous, &header) {
        Ok(()) => {
            set_state(paths, generation, TxnState::AwaitingConfirm)?;
            set_pending(
                paths,
                &Pending {
                    generation,
                    change: Change::Apply { previous },
                    phase: Phase::AwaitingConfirm,
                },
            )
        }
        Err(error) => {
            let armed = pending(paths)?.is_some_and(|pending| pending.phase.armed());
            set_state(paths, generation, TxnState::Failed { error })?;
            abandon(paths, node, generation, armed)
        }
    }
}

/// Ends a change that failed. The pending record goes first, so that a
/// timer that cannot be stopped finds nothing to revert when it fires; then
/// the timer, if one was armed, so that the generation can be retried at
/// once rather than meeting the unit name still in use.
fn abandon(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
    armed: bool,
) -> Result<(), AgentError> {
    clear_pending(paths)?;
    if armed {
        disarm_revert(node, generation)?;
    }
    Ok(())
}

fn running(paths: &Paths, generation: Generation, stage: TxnStage) -> Result<(), AgentError> {
    set_state(paths, generation, TxnState::Running { stage })
}

/// The stages of a transaction; `Ok` once it awaits confirmation.
fn attempt(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
    previous: Generation,
    header: &BundleHeader,
) -> Result<(), AgentError> {
    running(paths, generation, TxnStage::Preconditions)?;
    preconditions(paths, node, header)?;
    running(paths, generation, TxnStage::Stage)?;
    prune(paths, previous)?;
    let staged = stage::stage(paths, generation, header).and_then(|dir| {
        running(paths, generation, TxnStage::Validate)?;
        validate::validate(paths, node, &dir)?;
        arm_revert(
            node,
            generation,
            Path::new(mooring_agent_proto::AGENT_CURRENT_PATH),
        )?;
        set_pending(
            paths,
            &Pending {
                generation,
                change: Change::Apply { previous },
                phase: Phase::Armed,
            },
        )?;
        Ok(dir)
    });
    let dir = match staged {
        Ok(dir) => dir,
        Err(error) => {
            remove_generation(paths, generation)?;
            return Err(error);
        }
    };
    running(paths, generation, TxnStage::Swap)?;
    if let Err(error) = swap(paths, generation) {
        return Err(roll_back(
            paths,
            node,
            generation,
            previous,
            RollbackCause::Swap {
                errno: error.raw_os_error(),
            },
        ));
    }
    let host = match install_host(paths, &dir) {
        Ok(host) => host,
        Err(cause) => return Err(roll_back(paths, node, generation, previous, cause)),
    };
    running(paths, generation, TxnStage::Apply)?;
    let before = stage::installed_header(paths, previous)?;
    if let Err(cause) = apply_changes(paths, node, before.as_ref(), header, &dir, &host) {
        return Err(roll_back(paths, node, generation, previous, cause));
    }
    running(paths, generation, TxnStage::HealthGate)?;
    if let Err(failed) = health::wait(paths, node, &dir, health::BUDGET) {
        return Err(roll_back(
            paths,
            node,
            generation,
            previous,
            RollbackCause::HealthGate { failed },
        ));
    }
    Ok(())
}

/// Preconditions (design §11.2 step 1): not halted, a host profile this
/// agent has, the live host facts and port range those of the bundle, and
/// every blob stored and intact.
fn preconditions(paths: &Paths, node: &dyn Node, header: &BundleHeader) -> Result<(), AgentError> {
    if gate::halted(paths)?.is_some() {
        return Err(AgentError::NodeHalted);
    }
    let supported = HostProfile::CURRENT.version;
    if header.host_profile_version > supported {
        return Err(AgentError::HostProfileUnsupported {
            required: header.host_profile_version,
            supported,
        });
    }
    header
        .host_facts
        .check_live(&crate::hello::host_facts(paths, node)?)?;
    let wanted: BTreeSet<_> = header
        .files
        .iter()
        .map(|(_, sha256)| *sha256)
        .chain(header.engines.digests().into_iter().copied())
        .collect();
    let present = crate::blobs::present(paths, &wanted)?;
    match wanted.difference(&present).next() {
        Some(sha256) => Err(AgentError::BlobMissing { sha256: *sha256 }),
        None => Ok(()),
    }
}

/// Arms the timer that reverts the change under `generation` unless it is
/// confirmed within [`CONFIRM_SECS`], run by `agent`.
fn arm_revert(node: &dyn Node, generation: Generation, agent: &Path) -> Result<(), AgentError> {
    let unit = revert_unit(generation);
    let unit_arg = format!("--unit={unit}");
    let delay = format!("--on-active={CONFIRM_SECS}");
    let generation_arg = generation.get().to_string();
    let agent = agent.display().to_string();
    match run_ok(
        node,
        Tool::SystemdRun,
        &[
            &unit_arg,
            &delay,
            "--collect",
            "--quiet",
            &agent,
            "txn-revert",
            &generation_arg,
        ],
    )? {
        Ok(_) => Ok(()),
        Err(_) => Err(AgentError::Systemd {
            unit: unit_name(&format!("{unit}.timer"))?,
            op: SystemdOp::Run,
        }),
    }
}

/// Stops the revert timer of `generation`.
fn disarm_revert(node: &dyn Node, generation: Generation) -> Result<(), AgentError> {
    let unit = format!("{}.timer", revert_unit(generation));
    match run_ok(node, Tool::Systemctl, &["stop", &unit])? {
        Ok(_) => Ok(()),
        Err(_) => Err(AgentError::Systemd {
            unit: unit_name(&unit)?,
            op: SystemdOp::Stop,
        }),
    }
}

/// Makes `link` a symbolic link to `target` with one rename.
pub(crate) fn replace_link(link: &Path, target: &Path) -> io::Result<()> {
    if fs::read_link(link).is_ok_and(|current| current == target) {
        return Ok(());
    }
    let parent = link
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    crate::store::ensure_dir(parent)?;
    let temporary = link.with_extension(format!("swap.{}", std::process::id()));
    let _stale = fs::remove_file(&temporary);
    symlink(target, &temporary)?;
    fs::rename(&temporary, link)?;
    fs::File::open(parent)?.sync_all()
}

/// The swap (design §11.2 step 4): `current` to `gen-<N>`, and the fixed
/// links into `current`. A Debian `/etc/nftables.conf` that is a file, not
/// the link, is kept as `/etc/nftables.conf.pre-mooring` the first time.
pub(crate) fn swap(paths: &Paths, generation: Generation) -> io::Result<()> {
    replace_link(&paths.current(), Path::new(&generation_name(generation)))?;
    fixed_links(paths)
}

fn fixed_links(paths: &Paths) -> io::Result<()> {
    let nft = paths.nft_conf_link();
    if fs::symlink_metadata(&nft).is_ok_and(|meta| meta.file_type().is_file()) {
        let kept = nft.with_extension("conf.pre-mooring");
        if !kept.exists() {
            fs::rename(&nft, &kept)?;
        }
    }
    replace_link(&nft, Path::new("mooring/current/nftables.conf"))?;
    replace_link(
        &paths.wg_conf_link(),
        Path::new("../mooring/current/wgexit.conf"),
    )?;
    replace_link(
        &paths.geodata_link(),
        Path::new("../../../../etc/mooring/current/geodata"),
    )
}

/// A `key = value` line of a WireGuard configuration.
fn wg_value(conf: &str, key: &str) -> Option<String> {
    conf.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim().to_owned())
    })
}

/// Installs the host profile's files staged with the generation in `dir`
/// (the swap's last part, design §11.2 step 4) and returns those that
/// changed. A generation an older agent staged has none, and changes none.
fn install_host(paths: &Paths, dir: &Path) -> Result<BTreeSet<HostFile>, RollbackCause> {
    let staged = dir.join(hostfiles::HOST_DIR);
    if !staged.is_dir() {
        return Ok(BTreeSet::new());
    }
    hostfiles::install(paths, &staged).map_err(|error| RollbackCause::Swap {
        errno: match error {
            AgentError::Io { errno, .. } => errno,
            _ => None,
        },
    })
}

/// Applies only what changed (design §11.2 step 5) from `before` to the
/// generation now current, in `dir`: the ruleset, the tunnel (a restart if
/// its address or MTU changed, else `wg syncconf`), what the host profile
/// files in `host` need, and the engines whose configuration, artifacts or
/// unit changed. Nothing is restarted while the node is halted. Tool
/// output is scrubbed of the generation's secrets; if they cannot be read,
/// nothing is run.
pub(crate) fn apply_changes(
    paths: &Paths,
    node: &dyn Node,
    before: Option<&BundleHeader>,
    next: &BundleHeader,
    dir: &Path,
    host: &BTreeSet<HostFile>,
) -> Result<(), RollbackCause> {
    let secrets = validate::secrets(dir).map_err(|error| RollbackCause::Apply {
        step: ApplyStep::Nftables,
        stderr_tail: StderrTail::scrubbed(error.to_string().as_bytes(), &[]),
    })?;
    let step = Step {
        node,
        secrets: &secrets,
    };
    let changed = |file: ManagedFile| {
        before.is_none_or(|before| before.files.get(file) != next.files.get(file))
    };
    if changed(ManagedFile::Nftables) {
        let file = paths.nft_conf_link().display().to_string();
        step.run(ApplyStep::Nftables, Tool::Nft, &["-f", &file])?;
    }
    if changed(ManagedFile::WgConf) {
        apply_wireguard(paths, &step, before, dir)?;
    }
    for command in hostfiles::commands(host) {
        let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
        step.run(command.step.apply_step(), command.tool, &args)?;
    }
    if gate::halted(paths)
        .map_err(|error| step.failed(ApplyStep::EngineRestart, &error))?
        .is_some()
    {
        return Ok(());
    }
    let engines_changed = before.is_none_or(|before| before.engines != next.engines);
    for (engine, file, unit) in [
        (
            EngineUser::Xray,
            ManagedFile::XrayConfig,
            HostFile::XrayUnit,
        ),
        (EngineUser::Hy2, ManagedFile::Hy2Config, HostFile::Hy2Unit),
    ] {
        if changed(file) || engines_changed || host.contains(&unit) {
            let unit = engine_unit(engine)
                .map_err(|error| step.failed(ApplyStep::EngineRestart, &error))?;
            step.run(
                ApplyStep::EngineRestart,
                Tool::Systemctl,
                &["restart", unit.as_str()],
            )?;
        }
    }
    Ok(())
}

/// One apply step's tool runs, their failures scrubbed of `secrets`.
struct Step<'a> {
    node: &'a dyn Node,
    secrets: &'a [Vec<u8>],
}

impl Step<'_> {
    fn tail(&self, text: &[u8]) -> StderrTail {
        let refs: Vec<&[u8]> = self.secrets.iter().map(Vec::as_slice).collect();
        StderrTail::scrubbed(text, &refs)
    }

    fn failed(&self, step: ApplyStep, error: &AgentError) -> RollbackCause {
        RollbackCause::Apply {
            step,
            stderr_tail: self.tail(error.to_string().as_bytes()),
        }
    }

    /// Runs `tool`; its stdout, or the step's failure with its stderr.
    fn run(&self, step: ApplyStep, tool: Tool, args: &[&str]) -> Result<Vec<u8>, RollbackCause> {
        match run_ok(self.node, tool, args) {
            Ok(Ok(stdout)) => Ok(stdout),
            Ok(Err(stderr)) => Err(RollbackCause::Apply {
                step,
                stderr_tail: self.tail(&stderr),
            }),
            Err(error) => Err(self.failed(step, &error)),
        }
    }
}

/// The tunnel's step: `wg-quick@wgexit` restarted when it is new or its
/// address or MTU changed (or the old configuration cannot be read), else
/// the peers synchronised with `wg syncconf`.
fn apply_wireguard(
    paths: &Paths,
    step: &Step<'_>,
    before: Option<&BundleHeader>,
    dir: &Path,
) -> Result<(), RollbackCause> {
    let next = fs::read_to_string(dir.join(ManagedFile::WgConf.file_name()))
        .map_err(|error| step.failed(ApplyStep::WireGuard, &io_error(IoOp::ReadState, &error)))?;
    let restart = before.is_none_or(|before| {
        let old = paths
            .generation(before.config_generation)
            .join(ManagedFile::WgConf.file_name());
        fs::read_to_string(old).map_or(true, |old| {
            ["Address", "MTU"]
                .iter()
                .any(|key| wg_value(&old, key) != wg_value(&next, key))
        })
    });
    let unit = format!("wg-quick@{WG_INTERFACE}.service");
    if restart {
        return step
            .run(ApplyStep::WireGuard, Tool::Systemctl, &["restart", &unit])
            .map(drop);
    }
    let conf = paths.wg_conf_link().display().to_string();
    let stripped = step.run(ApplyStep::WireGuard, Tool::WgQuick, &["strip", &conf])?;
    let scratch = paths.validate_dir().join("wgexit.stripped");
    crate::store::write_atomic(&scratch, &stripped, 0o600)
        .map_err(|error| step.failed(ApplyStep::WireGuard, &io_error(IoOp::WriteState, &error)))?;
    let scratch_arg = scratch.display().to_string();
    let synced = step.run(
        ApplyStep::WireGuard,
        Tool::Wg,
        &["syncconf", WG_INTERFACE, &scratch_arg],
    );
    // The stripped copy holds the private key; it goes whatever happened.
    let _absent = fs::remove_file(&scratch);
    synced.map(drop)
}

/// Rolls back the transaction for `generation` (design §11.2 step 8) and
/// returns the error the transaction ends with.
fn roll_back(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
    previous: Generation,
    cause: RollbackCause,
) -> AgentError {
    match revert(paths, node, generation, previous) {
        Ok(()) => AgentError::RolledBack { generation, cause },
        Err(_) => AgentError::RollbackFailed { generation, cause },
    }
}

/// Puts `previous` back in place of `failed`: the links, what changed, and
/// the health gate. With no previous generation the node goes back to
/// serving nothing: no `current`, engines and tunnel stopped, and the
/// ruleset it had before Mooring's first one reloaded. If any of it fails,
/// both engines are stopped and the gate closed, and the failure is
/// returned.
pub(crate) fn revert(
    paths: &Paths,
    node: &dyn Node,
    failed: Generation,
    previous: Generation,
) -> Result<(), RollbackCause> {
    // A failed generation whose header cannot be read counts as having
    // changed everything, so everything of the previous one is re-applied.
    let failed_header = stage::installed_header(paths, failed).ok().flatten();
    let outcome = if previous == Generation::ZERO {
        to_nothing(paths, node)
    } else {
        to_previous(paths, node, failed_header.as_ref(), previous)
    };
    if outcome.is_err() {
        safe_stop(paths, node);
    }
    remove_failed(paths, failed)?;
    outcome
}

/// Removes the failed generation's directory, a revert's last step.
fn remove_failed(paths: &Paths, failed: Generation) -> Result<(), RollbackCause> {
    remove_generation(paths, failed).map_err(|error| RollbackCause::Swap {
        errno: match error {
            AgentError::Io { errno, .. } => errno,
            _ => None,
        },
    })
}

fn to_previous(
    paths: &Paths,
    node: &dyn Node,
    failed: Option<&BundleHeader>,
    previous: Generation,
) -> Result<(), RollbackCause> {
    swap(paths, previous).map_err(|error| RollbackCause::Swap {
        errno: error.raw_os_error(),
    })?;
    let dir = paths.generation(previous);
    let header = match stage::installed_header(paths, previous) {
        Ok(Some(header)) => header,
        Ok(None) => return Err(RollbackCause::Swap { errno: None }),
        Err(AgentError::Io { errno, .. }) => return Err(RollbackCause::Swap { errno }),
        Err(_) => return Err(RollbackCause::Swap { errno: None }),
    };
    let host = install_host(paths, &dir)?;
    apply_changes(paths, node, failed, &header, &dir, &host)?;
    health::wait(paths, node, &dir, health::BUDGET)
        .map_err(|failed| RollbackCause::HealthGate { failed })
}

fn to_nothing(paths: &Paths, node: &dyn Node) -> Result<(), RollbackCause> {
    match fs::remove_file(paths.current()) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(RollbackCause::Swap {
                errno: error.raw_os_error(),
            });
        }
    }
    let step = Step { node, secrets: &[] };
    let tunnel = format!("wg-quick@{WG_INTERFACE}.service");
    for unit in [
        "mooring-xray.service",
        "mooring-hy2.service",
        tunnel.as_str(),
    ] {
        step.run(ApplyStep::EngineRestart, Tool::Systemctl, &["stop", unit])?;
    }
    // The ruleset the node had before Mooring's first one, so that a first
    // generation whose ruleset shut the operator out is undone too.
    let nft = paths.nft_conf_link();
    let kept = nft.with_extension("conf.pre-mooring");
    if kept.exists() {
        fs::rename(&kept, &nft).map_err(|error| RollbackCause::Swap {
            errno: error.raw_os_error(),
        })?;
        let file = nft.display().to_string();
        step.run(ApplyStep::Nftables, Tool::Nft, &["-f", &file])?;
    }
    Ok(())
}

/// The safe state after a failed rollback: both engines stopped and the
/// gate closed, as far as the node lets either happen.
fn safe_stop(paths: &Paths, node: &dyn Node) {
    for engine in [EngineUser::Xray, EngineUser::Hy2] {
        if let Ok(unit) = engine_unit(engine) {
            let _attempted = run_ok(node, Tool::Systemctl, &["stop", unit.as_str()]);
        }
    }
    let _attempted = Lock::exclusive(&paths.gate_lock()).and_then(|_lock| gate::close(node));
}

/// Removes generation `generation`'s directory, if it exists.
fn remove_generation(paths: &Paths, generation: Generation) -> Result<(), AgentError> {
    match fs::remove_dir_all(paths.generation(generation)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(IoOp::WriteState, &error)),
    }
}

/// Keeps the current generation and the [`KEPT_PREVIOUS`] newest before
/// it, and the engine artifacts they use; removes the rest.
fn prune(paths: &Paths, current: Generation) -> Result<(), AgentError> {
    let fail = |error: io::Error| io_error(IoOp::WriteState, &error);
    let mut generations: Vec<u64> = match fs::read_dir(paths.etc()) {
        Ok(entries) => entries
            .filter_map(|entry| {
                entry
                    .ok()?
                    .file_name()
                    .to_str()?
                    .strip_prefix("gen-")?
                    .parse()
                    .ok()
            })
            .collect(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(fail(error)),
    };
    generations.sort_unstable_by(|a, b| b.cmp(a));
    let older: Vec<u64> = generations
        .into_iter()
        .filter(|&generation| generation < current.get())
        .collect();
    for generation in older.iter().skip(KEPT_PREVIOUS) {
        remove_generation(paths, Generation::new(*generation))?;
    }
    let mut kept = vec![current];
    kept.extend(
        older
            .iter()
            .take(KEPT_PREVIOUS)
            .map(|&generation| Generation::new(generation)),
    );
    let mut used = BTreeSet::new();
    for generation in kept {
        if let Some(header) = stage::installed_header(paths, generation)? {
            used.extend(
                header
                    .engines
                    .digests()
                    .into_iter()
                    .map(ToString::to_string),
            );
        }
    }
    let store = match fs::read_dir(paths.engine_store()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(fail(error)),
    };
    for entry in store {
        let entry = entry.map_err(fail)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !used.contains(&name) {
            fs::remove_dir_all(entry.path()).map_err(fail)?;
        }
    }
    Ok(())
}

/// `TxnStatus{generation}`.
pub(crate) fn status(paths: &Paths, generation: Generation) -> Result<TxnState, AgentError> {
    Ok(record::record(paths, generation)?.state)
}

/// `Confirm{generation}`: commits the change awaiting confirmation under
/// `generation`, from a new SSH session.
pub(crate) fn confirm(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
) -> Result<Generation, AgentError> {
    let _lock = Lock::exclusive(&paths.txn_lock())?;
    let pending = pending(paths)?
        .filter(|pending| {
            pending.generation == generation && pending.phase == Phase::AwaitingConfirm
        })
        .ok_or(AgentError::NotAwaitingConfirm)?;
    disarm_revert(node, generation)?;
    if let Change::Apply { .. } = pending.change {
        set_state(paths, generation, TxnState::Committed)?;
    }
    clear_pending(paths)?;
    Ok(generation)
}

/// Why the pending change is reverted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// A `Rollback` request: whatever is pending, its timer stopped first.
    Requested,
    /// The confirm timer of this generation fired: the change it was armed
    /// for, if that is still pending.
    Unconfirmed(Generation),
    /// The node booted (`txn-recover`): whatever is pending, its timer lost
    /// with the reboot.
    Rebooted,
}

/// Reverts the pending change. A transaction unit holds the lock for its
/// whole run, so a pending `Apply` found here that does not await
/// confirmation belongs to a unit that died (or to one launched but not
/// started, which then finds nothing to run), and is reverted too: rolled
/// back if its generation is current, else, having switched nothing, only
/// its staged directory removed.
pub(crate) fn revert_pending(
    paths: &Paths,
    node: &dyn Node,
    why: Why,
) -> Result<Generation, AgentError> {
    let _lock = Lock::exclusive(&paths.txn_lock())?;
    let pending = pending(paths)?
        .filter(|pending| match why {
            Why::Requested | Why::Rebooted => true,
            Why::Unconfirmed(generation) => {
                pending.generation == generation && pending.phase.armed()
            }
        })
        .ok_or(AgentError::NotAwaitingConfirm)?;
    let generation = pending.generation;
    if why == Why::Requested && pending.phase.armed() {
        disarm_revert(node, generation)?;
    }
    let outcome = match pending.change {
        Change::Apply { previous } => {
            let reverted = if gate::current_generation(paths)? == generation {
                revert(paths, node, generation, previous)
            } else {
                remove_failed(paths, generation)
            };
            let state = match (&reverted, why) {
                (Ok(()), Why::Requested) => TxnState::Reverted,
                (Ok(()), Why::Unconfirmed(_) | Why::Rebooted) => TxnState::Failed {
                    error: AgentError::RevertedUnconfirmed { generation },
                },
                (Err(cause), _) => TxnState::Failed {
                    error: AgentError::RollbackFailed {
                        generation,
                        cause: cause.clone(),
                    },
                },
            };
            set_state(paths, generation, state)?;
            reverted.map_err(|cause| AgentError::RollbackFailed { generation, cause })
        }
        Change::Activate { previous, .. } => activate::restore(paths, &previous),
    };
    clear_pending(paths)?;
    outcome.map(|()| generation)
}
