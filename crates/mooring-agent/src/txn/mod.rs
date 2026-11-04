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
mod changes;
pub(crate) mod health;
pub(crate) mod links;
mod prune;
pub(crate) mod record;
pub(crate) mod resume;
pub(crate) mod rollback;
pub(crate) mod stage;
mod timer;
pub(crate) mod validate;

use std::collections::BTreeSet;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, BundleHeader, EngineUser, Generation, HostProfile, RollbackCause, SystemdOp,
    TxnStage, TxnState, UnitName,
};

use crate::gate;
use crate::hello;
use crate::host::{Node, Tool, run_ok};
use crate::hostfiles::Applied;
use crate::paths::Paths;
use crate::store::{Lock, errno};
use changes::{apply_changes, install_host};
use links::swap;
use prune::prune;
use record::{
    Change, Pending, Phase, TxnRecord, clear_pending, pending, set_pending, set_record, set_state,
};
use rollback::{revert, roll_back};
use stage::remove_generation;
use timer::{arm_revert, disarm_revert};

/// The units a generation runs: both engines and the tunnel.
pub(crate) fn generation_units() -> [UnitName; 3] {
    [
        UnitName::engine(EngineUser::Xray),
        UnitName::engine(EngineUser::Hy2),
        UnitName::tunnel(),
    ]
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
    // Once recorded, a change that cannot be launched is recorded as
    // failed and leaves nothing pending: nothing will run it, and the node
    // is free for the next change.
    match launch(paths, node, generation, current) {
        Ok(()) => Ok(Launched::Launched(generation)),
        Err(error) => {
            end(
                paths,
                node,
                generation,
                Some(TxnState::Failed {
                    error: error.clone(),
                }),
                false,
            )?;
            Err(error)
        }
    }
}

/// Records the change under `generation` as pending and launches the
/// transaction's unit: `systemd-run` refusing it and `systemd-run` that
/// cannot be started are both failures.
fn launch(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
    previous: Generation,
) -> Result<(), AgentError> {
    set_pending(
        paths,
        &Pending {
            generation,
            change: Change::Apply { previous },
            phase: Phase::Launched,
        },
    )?;
    let unit = UnitName::transaction(generation);
    let unit_arg = format!("--unit={}", unit.stem());
    let generation_arg = generation.get().to_string();
    match run_ok(
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
    )? {
        Ok(_) => Ok(()),
        Err(_) => Err(AgentError::Systemd {
            unit,
            op: SystemdOp::Run,
        }),
    }
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
    let mut armed = false;
    match attempt(paths, node, generation, previous, &header, &mut armed) {
        // Should either write fail, the change stays pending with its timer
        // armed, which then reverts it, as when the unit dies.
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
        Err(error) => end(
            paths,
            node,
            generation,
            Some(TxnState::Failed { error }),
            armed,
        ),
    }
}

/// Ends the pending change under `generation`, the one way every change
/// ends: the record's final `state` (an activation has no record), then
/// the pending change, then the confirm timer if one was armed. In this
/// order a write that fails leaves the change pending with its timer still
/// armed, so that the timer, or a retried request, can still end it; and a
/// timer that cannot be stopped finds nothing to revert when it fires. A
/// timer stopped last also lets the generation be retried at once rather
/// than meet its unit name still in use.
fn end(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
    state: Option<TxnState>,
    armed: bool,
) -> Result<(), AgentError> {
    if let Some(state) = state {
        set_state(paths, generation, state)?;
    }
    clear_pending(paths)?;
    if armed {
        disarm_revert(node, generation)?;
    }
    Ok(())
}

fn running(paths: &Paths, generation: Generation, stage: TxnStage) -> Result<(), AgentError> {
    set_state(paths, generation, TxnState::Running { stage })
}

/// The stages of a transaction; `Ok` once it awaits confirmation. Before
/// the swap a failure removes what was staged; from the swap on, every
/// failure is rolled back. `armed` is set once the confirm timer is armed,
/// so that the change's end stops it even when the phase that says so
/// could not be recorded.
fn attempt(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
    previous: Generation,
    header: &BundleHeader,
    armed: &mut bool,
) -> Result<(), AgentError> {
    running(paths, generation, TxnStage::Preconditions)?;
    preconditions(paths, node, header)?;
    running(paths, generation, TxnStage::Stage)?;
    // What the change changes, read once from the previous generation
    // before anything is staged or switched; pruning keeps its engines.
    let before = stage::installed_header(paths, previous)?;
    prune(paths, previous, before.as_ref())?;
    let staged = stage::stage(paths, generation, header).and_then(|dir| {
        running(paths, generation, TxnStage::Validate)?;
        validate::validate(paths, node, &dir)?;
        arm_revert(
            node,
            generation,
            Path::new(mooring_agent_proto::AGENT_CURRENT_PATH),
        )?;
        *armed = true;
        set_pending(
            paths,
            &Pending {
                generation,
                change: Change::Apply { previous },
                phase: Phase::Armed,
            },
        )?;
        running(paths, generation, TxnStage::Swap)?;
        Ok(dir)
    });
    let dir = match staged {
        Ok(dir) => dir,
        Err(error) => {
            // The change's own failure is the one reported: a directory that
            // cannot be removed now is replaced by the next staging of this
            // generation, or refused there with its own error.
            let _left = remove_generation(paths, generation);
            return Err(error);
        }
    };
    switch(paths, node, generation, header, before.as_ref(), &dir)
        .map_err(|cause| roll_back(paths, node, generation, previous, cause))
}

/// The swap and what follows it (design §11.2 steps 4 to 6), each failure
/// with the cause the rollback reports.
fn switch(
    paths: &Paths,
    node: &dyn Node,
    generation: Generation,
    header: &BundleHeader,
    before: Option<&BundleHeader>,
    dir: &Path,
) -> Result<(), RollbackCause> {
    swap(paths, generation).map_err(|error| RollbackCause::Swap {
        errno: error.raw_os_error(),
    })?;
    // A node's first generation applies its whole profile: one rolled back
    // to nothing left the files it installed, never applied.
    let applied = if before.is_none() {
        Applied::Every
    } else {
        Applied::Changed
    };
    let host = install_host(paths, dir, applied)?;
    progress(paths, generation, TxnStage::Apply)?;
    apply_changes(paths, node, before, header, dir, &host)?;
    progress(paths, generation, TxnStage::HealthGate)?;
    health::wait(paths, node, dir, health::BUDGET)
        .map_err(|failed| RollbackCause::HealthGate { failed })
}

/// Records a stage reached after the swap. A record that cannot be written
/// there fails the change as a `Swap` with the write's error number: a
/// change whose progress cannot be recorded could not be confirmed either,
/// so it is rolled back at once rather than left switched.
fn progress(paths: &Paths, generation: Generation, stage: TxnStage) -> Result<(), RollbackCause> {
    running(paths, generation, stage).map_err(|error| RollbackCause::Swap {
        errno: errno(&error),
    })
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
        .check_live(&hello::host_facts(paths, node)?)?;
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

/// `TxnStatus{generation}`.
pub(crate) fn status(paths: &Paths, generation: Generation) -> Result<TxnState, AgentError> {
    Ok(record::record(paths, generation)?.state)
}

/// `Confirm{generation}`: commits the change awaiting confirmation under
/// `generation`, from a new SSH session. A timer that cannot be stopped
/// afterwards is the answer, though the change is committed: when it
/// fires it finds nothing to revert.
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
    let state = match pending.change {
        Change::Apply { .. } => Some(TxnState::Committed),
        Change::Activate { .. } => None,
    };
    end(paths, node, generation, state, true)?;
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
/// started, which then finds nothing to run), and is reverted too. One
/// whose timer was armed may have been switched, by its transaction or by
/// a revert that stopped part-way (one that failed, or died, with
/// `current` already back on the previous generation), so it is rolled
/// back, which puts back only what still differs. One only launched never
/// reached its swap: only its staged directory goes, and a directory that
/// cannot be removed is the request's error, the change reverted all the
/// same. A revert that fails is `RollbackFailed` with the revert's own
/// cause (a transaction's rollback reports the failure that made it roll
/// back instead), after the node was stopped. An activation ends only
/// once the forced command is back on the previous agent; a link that
/// cannot be put back leaves it pending with its timer. A requested
/// revert stops the timer last, as every change ends (`end`); an
/// unconfirmed change's timer has fired, and a reboot lost it.
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
    let disarm = why == Why::Requested && pending.phase.armed();
    let (state, outcome) = match pending.change {
        Change::Apply { previous } if pending.phase.armed() => {
            match revert(paths, node, generation, previous) {
                Ok(()) => (Some(reverted(why, generation)), Ok(())),
                Err(cause) => {
                    let error = AgentError::RollbackFailed { generation, cause };
                    let failed = TxnState::Failed {
                        error: error.clone(),
                    };
                    (Some(failed), Err(error))
                }
            }
        }
        Change::Apply { .. } => (
            Some(reverted(why, generation)),
            remove_generation(paths, generation),
        ),
        Change::Activate { previous, .. } => {
            activate::restore(paths, &previous)?;
            (None, Ok(()))
        }
    };
    end(paths, node, generation, state, disarm)?;
    outcome.map(|()| generation)
}

/// The state of a change reverted for `why`.
const fn reverted(why: Why, generation: Generation) -> TxnState {
    match why {
        Why::Requested => TxnState::Reverted,
        Why::Unconfirmed(_) | Why::Rebooted => TxnState::Failed {
            error: AgentError::RevertedUnconfirmed { generation },
        },
    }
}
