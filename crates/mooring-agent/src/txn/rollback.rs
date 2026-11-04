// SPDX-License-Identifier: GPL-3.0-or-later

//! The rollback (design §11.2 step 8): the previous generation put back in
//! place of a failed one, or the node back to serving nothing, and the safe
//! stop when that fails too. Whether a pending change is reverted, for
//! `Rollback`, `txn-revert` and `txn-recover`, is decided by
//! [`super::revert_pending`].

use std::fs;
use std::io;

use mooring_agent_proto::{
    AcceptLocal, AgentError, ApplyStep, BundleHeader, EngineUser, Generation, RollbackCause,
    UnitName, WG_INTERFACE,
};

use super::changes::{Step, apply_changes, install_host};
use super::links::swap;
use super::stage::{self, remove_generation};
use super::{generation_units, health};
use crate::gate;
use crate::hello;
use crate::host::{Node, Tool, run_ok};
use crate::hostfiles::Applied;
use crate::paths::Paths;
use crate::store::{Lock, errno};

/// Rolls back the transaction for `generation` (design §11.2 step 8) and
/// returns the error the transaction ends with.
pub(super) fn roll_back(
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
/// ruleset it had before Mooring's first one reloaded. The failed
/// generation's directory is removed once `current` no longer names it: a
/// revert that could not switch back keeps it, so that `current` and the
/// fixed links into it stay whole. If any of it fails, both engines are
/// stopped and the gate closed, and the first failure is returned. Done
/// again, it puts back only what still differs.
pub(crate) fn revert(
    paths: &Paths,
    node: &dyn Node,
    failed: Generation,
    previous: Generation,
) -> Result<(), RollbackCause> {
    // A failed generation whose header cannot be read counts as having
    // changed everything, so everything of the previous one is re-applied.
    let failed_header = stage::installed_header(paths, failed).ok().flatten();
    let reverted = if previous == Generation::ZERO {
        to_nothing(paths, node)
    } else {
        to_previous(paths, node, failed_header.as_ref(), previous)
    };
    let removed = match gate::current_generation(paths) {
        Ok(current) if current == failed => Ok(()),
        Ok(_) => remove_failed(paths, failed),
        // Where `current` points is unknown: the directory stays, and the
        // node is stopped as for any failure of the revert.
        Err(error) => Err(RollbackCause::Swap {
            errno: errno(&error),
        }),
    };
    let outcome = reverted.and(removed);
    if outcome.is_err() {
        safe_stop(paths, node);
    }
    outcome
}

/// Removes the failed generation's directory, a revert's last step.
fn remove_failed(paths: &Paths, failed: Generation) -> Result<(), RollbackCause> {
    remove_generation(paths, failed).map_err(|error| RollbackCause::Swap {
        errno: errno(&error),
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
    let header = stage::installed_header(paths, previous)
        .map_err(|error| RollbackCause::Swap {
            errno: errno(&error),
        })?
        .ok_or(RollbackCause::Swap { errno: None })?;
    let host = install_host(paths, &dir, Applied::Changed)?;
    apply_changes(paths, node, failed, &header, &dir, &host)?;
    health::wait(paths, node, &dir, health::BUDGET)
        .map_err(|failed| RollbackCause::HealthGate { failed })
}

/// The node back to serving nothing (design §11.2 step 8): both engines and
/// the tunnel stopped while `current` still points at the generation, since
/// the tunnel's stop (`wg-quick down`) reads `/etc/wireguard/wgexit.conf`
/// through it, and `wg-quick down` run for an interface the stop left (a
/// `down` that failed), with that configuration still in place for its
/// `PreDown` hooks; then `current` removed, whatever the stops did; and the
/// ruleset the node had before Mooring's first one reloaded, so that a first
/// generation whose ruleset shut the operator out is undone too. A rule the
/// hooks left behind an interface that is already gone stays: it names no
/// interface the kernel has, so it matches nothing, and the next `up`
/// tolerates it (design §8.4).
fn to_nothing(paths: &Paths, node: &dyn Node) -> Result<(), RollbackCause> {
    let step = Step { node, secrets: &[] };
    let stopped = generation_units().iter().try_for_each(|unit| {
        step.run(
            ApplyStep::EngineRestart,
            Tool::Systemctl,
            &["stop", unit.as_str()],
        )
        .map(drop)
    });
    let torn_down = stopped.and_then(|()| {
        let interface = hello::accept_local(paths)
            .map_err(|error| step.failed(ApplyStep::WireGuard, &error))?;
        if interface == AcceptLocal::NoInterface {
            Ok(())
        } else {
            step.run(ApplyStep::WireGuard, Tool::WgQuick, &["down", WG_INTERFACE])
                .map(drop)
        }
    });
    let removed = match fs::remove_file(paths.current()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RollbackCause::Swap {
            errno: error.raw_os_error(),
        }),
    };
    torn_down?;
    removed?;
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
    for engine in EngineUser::ALL {
        let unit = UnitName::engine(*engine);
        let _attempted = run_ok(node, Tool::Systemctl, &["stop", unit.as_str()]);
    }
    let _attempted = Lock::exclusive(&paths.gate_lock()).and_then(|_lock| gate::close(node));
}
