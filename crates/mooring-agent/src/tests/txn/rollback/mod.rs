// SPDX-License-Identifier: GPL-3.0-or-later

//! Rollback (design §11.2 step 8): a change that fails after the swap goes
//! back to the previous generation; a rollback that fails too says what
//! stopped it, keeps that in the record, and leaves both engines stopped
//! and the gate closed. A first generation's rollback to serving nothing,
//! and what a revert leaves, have files of their own, which share the
//! helpers here.

mod revert;
mod to_nothing;

use std::fs;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, Generation, HealthCheck, HostFile, IoOp, ManagedFile, RollbackCause,
    StderrTail, TxnState,
};

use super::world::{ENGINE_RESTART_FAILED, World, awaiting_second, idle, index_of, same};
use crate::host::Tool;
use crate::tests::{EACCES, EEXIST, EISDIR, ENOENT, ModeFault, occupy_temporary};
use crate::txn::record::pending;
use crate::txn::stage::BUNDLE_FILE;
use crate::txn::{self, Why};

/// The node left safe: both engines stopped and the gate closed.
fn assert_stopped_safe(calls: &[String]) {
    index_of(calls, "/usr/bin/systemctl stop mooring-xray.service");
    index_of(calls, "/usr/bin/systemctl stop mooring-hy2.service");
    index_of(
        calls,
        "/usr/sbin/nft add element inet mooring exit_closed { \"wgexit\" }",
    );
}

/// A step's failure as the rollback reports it: `error`'s text, scrubbed.
fn step_failed(step: ApplyStep, error: &AgentError) -> RollbackCause {
    RollbackCause::Apply {
        step,
        stderr_tail: StderrTail::scrubbed(error.to_string().as_bytes(), &[]),
    }
}

/// A rollback that failed with `cause`, as the request is answered and the
/// record keeps it.
fn assert_rollback_failed(world: &World, generation: u64, cause: RollbackCause) {
    let error = AgentError::RollbackFailed {
        generation: Generation::new(generation),
        cause,
    };
    assert_eq!(world.state(generation), TxnState::Failed { error });
    assert_eq!(pending(&world.paths).unwrap(), None);
}

/// A tunnel change that keeps its address and MTU: the peers are synced.
fn peers_only(file: ManagedFile, text: String) -> String {
    if file == ManagedFile::WgConf {
        text.replace(
            "AllowedIPs = 0.0.0.0/0",
            "AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 10",
        )
    } else {
        text
    }
}

#[test]
fn a_swap_that_fails_again_for_the_previous_generation_leaves_the_node_stopped() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let wireguard = world.paths.at("/etc/wireguard");
    fs::remove_dir_all(&wireguard).unwrap();
    fs::write(&wireguard, "").unwrap();
    let node = world.node(2000);
    world.apply_and_run(&node, world.bundle(2, idle(301)));
    assert_rollback_failed(
        &world,
        2,
        RollbackCause::Swap {
            errno: Some(EEXIST),
        },
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(!world.paths.generation(Generation::new(2)).exists());
    let calls = node.calls();
    assert_stopped_safe(&calls);
    index_of(&calls, "/usr/bin/systemctl stop mooring-txn-revert-2.timer");
}

/// Profile files that cannot be installed are a failed swap: the rollback
/// goes back to a generation an older agent staged, which has no profile
/// files of its own and so installs none.
#[test]
fn profile_files_that_cannot_be_installed_roll_back_to_a_generation_without_any() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    fs::remove_dir_all(world.paths.generation(Generation::new(1)).join("host")).unwrap();
    let drop_in = world.paths.host_file(HostFile::SshdDropIn);
    fs::remove_file(&drop_in).unwrap();
    fs::create_dir(&drop_in).unwrap();
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, idle(301))),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::Swap {
                    errno: Some(EISDIR)
                },
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(drop_in.is_dir(), "the rollback installed no profile file");
}

#[test]
fn an_engine_that_does_not_restart_rolls_the_change_back() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow().failing_engine_restarts.set(1);
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, idle(301))),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::Apply {
                    step: ApplyStep::EngineRestart,
                    stderr_tail: StderrTail::scrubbed(ENGINE_RESTART_FAILED, &[]),
                },
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let calls = node.calls();
    let restarts: Vec<&String> = calls
        .iter()
        .filter(|call| call.contains("restart mooring-xray.service"))
        .collect();
    assert_eq!(restarts.len(), 2, "the change's, then the rollback's");
}

#[test]
fn a_tool_that_cannot_be_started_fails_its_step() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow_mut().unstartable = Some((Tool::Systemctl, "restart"));
    let node = world.node(2000);
    world.apply_and_run(&node, world.bundle(2, idle(301)));
    assert_rollback_failed(
        &world,
        2,
        step_failed(
            ApplyStep::EngineRestart,
            &AgentError::Io {
                op: IoOp::SpawnProcess,
                errno: Some(ENOENT),
            },
        ),
    );
    assert_stopped_safe(&node.calls());
}

#[test]
fn a_rollback_to_a_generation_without_a_readable_header_stops_the_node() {
    for (damage, errno) in [
        (
            (|header: &Path| fs::remove_file(header).unwrap()) as fn(&Path),
            None,
        ),
        (
            |header: &Path| {
                fs::remove_file(header).unwrap();
                fs::create_dir(header).unwrap();
            },
            Some(EISDIR),
        ),
    ] {
        let world = awaiting_second(idle(301));
        damage(&world.paths.generation(Generation::new(1)).join(BUNDLE_FILE));
        let node = world.node(2050);
        let cause = RollbackCause::Swap { errno };
        assert_eq!(
            txn::revert_pending(&world.paths, &node, Why::Requested),
            Err(AgentError::RollbackFailed {
                generation: Generation::new(2),
                cause: cause.clone(),
            })
        );
        assert_rollback_failed(&world, 2, cause);
        assert_stopped_safe(&node.calls());
        assert!(!world.paths.generation(Generation::new(2)).exists());
    }
}

#[test]
fn a_rollback_whose_health_gate_fails_says_so() {
    let world = awaiting_second(idle(301));
    world.faults.borrow().missing_listeners.set(100);
    let node = world.node(2050);
    let cause = RollbackCause::HealthGate {
        failed: HealthCheck::Listeners,
    };
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::RollbackFailed {
            generation: Generation::new(2),
            cause: cause.clone(),
        })
    );
    assert_rollback_failed(&world, 2, cause);
    assert_stopped_safe(&node.calls());
}

/// The tool output a rollback reports is scrubbed of the generation's
/// secrets, so secrets that cannot be read stop it before any tool runs.
#[test]
fn a_rollback_to_a_generation_whose_secrets_cannot_be_read_runs_no_tool() {
    let world = awaiting_second(idle(301));
    let xray = world
        .paths
        .generation(Generation::new(1))
        .join(ManagedFile::XrayConfig.file_name());
    fs::remove_file(&xray).unwrap();
    fs::create_dir(&xray).unwrap();
    let node = world.node(2050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    assert_rollback_failed(
        &world,
        2,
        step_failed(
            ApplyStep::Nftables,
            &AgentError::Io {
                op: IoOp::ReadState,
                errno: Some(EISDIR),
            },
        ),
    );
    let calls = node.calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.contains("nft -f") || call.contains("restart")),
        "{calls:#?}"
    );
    assert_stopped_safe(&calls);
}

#[test]
fn a_halt_marker_that_cannot_be_read_stops_the_rollback_before_any_restart() {
    let world = awaiting_second(idle(301));
    fs::write(world.paths.halted(), "{").unwrap();
    let node = world.node(2050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    assert_rollback_failed(
        &world,
        2,
        step_failed(
            ApplyStep::EngineRestart,
            &AgentError::Io {
                op: IoOp::ReadState,
                errno: None,
            },
        ),
    );
    let calls = node.calls();
    assert!(
        !calls.iter().any(|call| call.contains("restart")),
        "{calls:#?}"
    );
    assert_stopped_safe(&calls);
}

#[test]
fn a_tunnel_configuration_that_is_not_text_fails_the_rollback() {
    let world = awaiting_second(peers_only);
    fs::write(
        world
            .paths
            .generation(Generation::new(1))
            .join(ManagedFile::WgConf.file_name()),
        b"[Interface]\n\xff\n",
    )
    .unwrap();
    let node = world.node(2050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    assert_rollback_failed(
        &world,
        2,
        step_failed(
            ApplyStep::WireGuard,
            &AgentError::Io {
                op: IoOp::ReadState,
                errno: None,
            },
        ),
    );
    assert_stopped_safe(&node.calls());
}

#[test]
fn a_stripped_tunnel_configuration_that_cannot_be_written_fails_the_rollback() {
    let world = awaiting_second(peers_only);
    let stripped = world.paths.validate_dir().join("wgexit.stripped");
    occupy_temporary(&stripped);
    let node = world.node(2050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    assert_rollback_failed(
        &world,
        2,
        step_failed(
            ApplyStep::WireGuard,
            &AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(EEXIST),
            },
        ),
    );
    let calls = node.calls();
    assert!(
        !calls.iter().any(|call| call.contains("syncconf")),
        "{calls:#?}"
    );
    assert!(!stripped.exists());
    assert_stopped_safe(&calls);
}

/// The stripped copy holds the tunnel's private key, so it goes even when
/// writing it failed after it was renamed into place.
#[test]
fn a_stripped_tunnel_configuration_whose_write_fails_late_is_removed() {
    let world = awaiting_second(peers_only);
    let validate = world.paths.validate_dir();
    // Everything but listing: the copy is created and renamed into place,
    // and the directory cannot then be opened to sync it.
    let fault = ModeFault::set(&validate, 0o300);
    let node = world.node(2050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    drop(fault);
    assert_rollback_failed(
        &world,
        2,
        step_failed(
            ApplyStep::WireGuard,
            &AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(EACCES),
            },
        ),
    );
    assert!(!validate.join("wgexit.stripped").exists());
}

/// Every failure after the swap is rolled back: here the record of the
/// stage reached cannot be written once the change is applied, and the
/// previous generation is put back rather than the change left switched.
#[test]
fn a_record_that_cannot_be_written_after_the_swap_rolls_the_change_back() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow_mut().block_at_restart = Some(world.paths.txn_record(Generation::new(2)));
    let node = world.node(2000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(2, idle(301))),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::Swap {
                    errno: Some(EEXIST)
                },
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(!world.paths.generation(Generation::new(2)).exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
    index_of(
        &node.calls(),
        "/usr/bin/systemctl stop mooring-txn-revert-2.timer",
    );
}

#[test]
fn a_failed_health_gate_rolls_back_to_the_previous_generation() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow().missing_listeners.set(21);
    let node = world.node(2000);
    let next = world.bundle(2, |file, text| {
        if file == ManagedFile::Hy2Config {
            text.replace("fatal", "panic")
        } else {
            text
        }
    });
    assert_eq!(
        world.apply_and_run(&node, next),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(2),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners
                },
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(!world.paths.generation(Generation::new(2)).exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert_eq!(node.slept(), 20, "the gate waited its whole budget once");
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/systemctl stop mooring-txn-revert-2.timer")
            > index_of(&calls, "--on-active=120"),
        "the failed transaction's timer is stopped, so the generation can be retried"
    );
}

#[test]
fn a_failed_apply_step_rolls_back_with_its_scrubbed_output() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.faults.borrow_mut().nft_load = true;
    let node = world.node(2000);
    let next = world.bundle(2, |file, text| {
        if file == ManagedFile::Nftables {
            text.replace("ct count over 4096", "ct count over 4000")
        } else {
            text
        }
    });
    let state = world.apply_and_run(&node, next);
    let TxnState::Failed {
        error:
            AgentError::RollbackFailed {
                cause: RollbackCause::Apply { step, stderr_tail },
                ..
            },
    } = state
    else {
        panic!("{state:?}");
    };
    assert_eq!(step, ApplyStep::Nftables);
    assert!(stderr_tail.as_str().contains("syntax error"));
    let calls = node.calls();
    let stops = calls
        .iter()
        .filter(|call| {
            call.contains("systemctl stop mooring-xray")
                || call.contains("systemctl stop mooring-hy2")
        })
        .count();
    assert_eq!(
        stops, 2,
        "a rollback that fails too stops both engines: {calls:#?}"
    );
    index_of(&calls, "add element inet mooring exit_closed");
}
