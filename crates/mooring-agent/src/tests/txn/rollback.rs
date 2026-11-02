// SPDX-License-Identifier: GPL-3.0-or-later

//! Rollback (design §11.2 step 8): a change that fails after the swap goes
//! back to the previous generation, or to serving nothing; a rollback that
//! fails too says what stopped it, keeps that in the record, and leaves
//! both engines stopped and the gate closed.

use std::fs;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, Generation, HealthCheck, HostFile, IoOp, ManagedFile, RollbackCause,
    StderrTail, TxnState,
};

use super::world::{ENGINE_RESTART_FAILED, World, idle, index_of, same};
use crate::host::Tool;
use crate::tests::{
    EACCES, EEXIST, EISDIR, ENOENT, ENOTDIR, FakeNode, ModeFault, header, occupy_temporary, scratch,
};
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

/// Generation 1 committed and generation 2 (made by `edit`) awaiting its
/// confirmation, as a `Rollback` finds them.
fn awaiting_second(edit: impl Fn(ManagedFile, String) -> String) -> World {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    assert_eq!(
        world.apply_and_run(&world.node(2000), world.bundle(2, edit)),
        TxnState::AwaitingConfirm
    );
    world
}

#[test]
fn a_first_generation_whose_swap_fails_rolls_back_to_serving_nothing() {
    let world = World::new();
    // The tunnel's link cannot go where a file holds its directory's name.
    fs::write(world.paths.at("/etc/wireguard"), "").unwrap();
    let node = world.node(1000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(1),
                cause: RollbackCause::Swap {
                    errno: Some(EEXIST)
                },
            }
        }
    );
    assert_eq!(world.current(), None);
    assert_eq!(
        fs::read_to_string(world.paths.nft_conf_link()).unwrap(),
        "#!/usr/sbin/nft -f\nflush ruleset\n",
        "the ruleset the node had before Mooring is back"
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
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

/// The first generation awaiting its confirmation, as a `Rollback` to
/// serving nothing finds it.
fn awaiting_first() -> World {
    let world = World::new();
    assert_eq!(
        world.apply_and_run(&world.node(1000), world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
    world
}

#[test]
fn a_rollback_to_nothing_that_cannot_read_the_tunnel_stops_the_node() {
    let world = awaiting_first();
    let accept_local = world.paths.wgexit_accept_local();
    fs::remove_file(&accept_local).unwrap();
    fs::create_dir(&accept_local).unwrap();
    let node = world.node(1050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    assert_rollback_failed(
        &world,
        1,
        step_failed(
            ApplyStep::WireGuard,
            &AgentError::Io {
                op: IoOp::ReadState,
                errno: Some(EISDIR),
            },
        ),
    );
    assert_eq!(world.current(), None, "current goes whatever the stops did");
    assert_stopped_safe(&node.calls());
}

#[test]
fn a_rollback_to_nothing_that_cannot_restore_the_ruleset_says_why() {
    let world = awaiting_first();
    // What `rename` gives for a file moved onto a directory that holds
    // something, on this system.
    let probe = world.paths.at("/probe");
    fs::create_dir_all(probe.join("full/entry")).unwrap();
    fs::write(probe.join("file"), "").unwrap();
    let errno = fs::rename(probe.join("file"), probe.join("full"))
        .unwrap_err()
        .raw_os_error();
    let nft = world.paths.nft_conf_link();
    fs::remove_file(&nft).unwrap();
    fs::create_dir_all(nft.join("entry")).unwrap();
    let node = world.node(1050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    assert_rollback_failed(&world, 1, RollbackCause::Swap { errno });
    assert!(
        world.paths.at("/etc/nftables.conf.pre-mooring").exists(),
        "the kept ruleset stays where it was"
    );
}

#[test]
fn a_rollback_to_nothing_whose_ruleset_does_not_load_says_why() {
    let world = awaiting_first();
    world.faults.borrow_mut().nft_load = true;
    let node = world.node(1050);
    txn::revert_pending(&world.paths, &node, Why::Requested).unwrap_err();
    assert_rollback_failed(
        &world,
        1,
        RollbackCause::Apply {
            step: ApplyStep::Nftables,
            stderr_tail: StderrTail::scrubbed(b"Error: syntax error\n", &[]),
        },
    );
    assert_eq!(
        fs::read_to_string(world.paths.nft_conf_link()).unwrap(),
        "#!/usr/sbin/nft -f\nflush ruleset\n"
    );
}

/// `current` that cannot be removed: the revert to nothing reports it, and
/// still stops both engines and closes the gate.
#[test]
fn a_current_that_cannot_be_removed_fails_the_revert_to_nothing() {
    let world = awaiting_first();
    let probe = world.paths.at("/probe");
    fs::create_dir_all(probe.join("entry")).unwrap();
    let errno = fs::remove_file(&probe).unwrap_err().raw_os_error();
    let current = world.paths.current();
    fs::remove_file(&current).unwrap();
    fs::create_dir_all(current.join("entry")).unwrap();
    let node = world.node(1050);
    assert_eq!(
        txn::revert(&world.paths, &node, Generation::new(1), Generation::ZERO),
        Err(RollbackCause::Swap { errno })
    );
    assert_stopped_safe(&node.calls());
}

/// A change that was launched but never ran has switched nothing; its
/// rollback only removes what it staged. A directory that cannot be
/// removed is the request's error, while the change is reverted all the
/// same: nothing is stopped for it.
#[test]
fn a_cancelled_change_whose_directory_cannot_be_removed_says_so_and_stops_nothing() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_000);
    let one = Generation::new(1);
    txn::apply(&paths, &node, header(1)).unwrap();
    let staged = paths.generation(one);
    fs::create_dir_all(staged.parent().unwrap()).unwrap();
    fs::write(&staged, "").unwrap();
    let node = FakeNode::new(1_010);
    assert_eq!(
        txn::revert_pending(&paths, &node, Why::Requested),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(ENOTDIR),
        })
    );
    assert_eq!(txn::status(&paths, one), Ok(TxnState::Reverted));
    assert_eq!(pending(&paths), Ok(None));
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
}

/// `RollbackFailed` means the node was stopped: a rollback whose failed
/// generation cannot be removed stops both engines and closes the gate,
/// though the previous generation is back.
#[test]
fn a_failed_generation_that_cannot_be_removed_stops_the_node() {
    let world = awaiting_second(idle(301));
    let engines = world.paths.generation(Generation::new(2)).join("engines");
    let fault = ModeFault::set(&engines, 0o555);
    let node = world.node(2050);
    let cause = RollbackCause::Swap {
        errno: Some(EACCES),
    };
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::RollbackFailed {
            generation: Generation::new(2),
            cause: cause.clone(),
        })
    );
    drop(fault);
    assert_rollback_failed(&world, 2, cause);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_stopped_safe(&node.calls());
}

/// A rollback that fails reports its own failure, not the removal of the
/// failed generation that fails after it.
#[test]
fn a_failed_rollback_keeps_its_cause_when_its_generation_cannot_be_removed_either() {
    let world = awaiting_second(idle(301));
    fs::remove_file(world.paths.generation(Generation::new(1)).join(BUNDLE_FILE)).unwrap();
    let engines = world.paths.generation(Generation::new(2)).join("engines");
    let fault = ModeFault::set(&engines, 0o555);
    let node = world.node(2050);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::RollbackFailed {
            generation: Generation::new(2),
            cause: RollbackCause::Swap { errno: None },
        })
    );
    drop(fault);
    assert_stopped_safe(&node.calls());
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
fn the_ruleset_the_node_had_before_mooring_is_kept_once() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let nft = world.paths.nft_conf_link();
    fs::remove_file(&nft).unwrap();
    fs::write(&nft, "#!/usr/sbin/nft -f\n# written later\n").unwrap();
    world.commit(&world.node(2000), world.bundle(2, idle(301)));
    assert_eq!(
        fs::read_link(&nft).unwrap(),
        Path::new("mooring/current/nftables.conf")
    );
    assert_eq!(
        fs::read_to_string(world.paths.at("/etc/nftables.conf.pre-mooring")).unwrap(),
        "#!/usr/sbin/nft -f\nflush ruleset\n"
    );
}

#[test]
fn a_link_without_a_parent_directory_is_refused() {
    assert_eq!(
        txn::replace_link(Path::new("/"), Path::new("gen-1"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}

/// A listener check that cannot run fails the health gate, never passes
/// it: here `ss` cannot be started, and the first generation is rolled
/// back to serving nothing.
#[test]
fn a_listener_check_that_cannot_run_fails_the_health_gate() {
    let world = World::new();
    world.faults.borrow_mut().unstartable = Some((Tool::Ss, "-Hltnu"));
    assert_eq!(
        world.apply_and_run(&world.node(1000), world.bundle(1, same)),
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(1),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners
                },
            }
        }
    );
    assert_eq!(world.current(), None);
}
