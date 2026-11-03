// SPDX-License-Identifier: GPL-3.0-or-later

//! A first generation rolled back to serving nothing (design §11.2 step
//! 8), after a failed swap, apply step or health gate (a listener check
//! that cannot run fails the gate), or for a `Rollback`: the engines and
//! the tunnel stopped, a tunnel interface left over taken down, `current`
//! removed, and the ruleset the node had before Mooring's first one
//! reloaded; and each way that fails, with the cause it reports. Where the
//! tunnel cannot be read or `current` cannot be removed, the node is
//! checked to be stopped all the same.

use std::fs;

use mooring_agent_proto::{
    AgentError, ApplyStep, Generation, HealthCheck, IoOp, RollbackCause, StderrTail, TxnState,
};

use super::{assert_rollback_failed, assert_stopped_safe, step_failed};
use crate::host::Tool;
use crate::tests::txn::world::{TUNNEL_START_FAILED, World, index_of, same};
use crate::tests::{EEXIST, EISDIR};
use crate::txn::record::pending;
use crate::txn::{self, Why};

#[test]
fn the_first_generation_rolls_back_to_serving_nothing() {
    let world = World::new();
    world.faults.borrow().missing_listeners.set(100);
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
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
    let calls = node.calls();
    for unit in [
        "mooring-xray.service",
        "mooring-hy2.service",
        "wg-quick@wgexit.service",
    ] {
        index_of(&calls, &format!("systemctl stop {unit}"));
    }
    assert_eq!(
        fs::read_to_string(world.paths.nft_conf_link()).unwrap(),
        "#!/usr/sbin/nft -f\nflush ruleset\n",
        "the node's own ruleset file is back"
    );
    assert!(!world.paths.at("/etc/nftables.conf.pre-mooring").exists());
    let reloaded = calls
        .iter()
        .rposition(|call| call.starts_with("/usr/sbin/nft -f "))
        .unwrap();
    assert!(
        reloaded > index_of(&calls, "systemctl stop wg-quick@wgexit.service"),
        "reloaded last"
    );
}

/// The tunnel's stop (`wg-quick down`) reads `/etc/wireguard/wgexit.conf`,
/// a link through `current`, so the units stop before `current` goes: the
/// rollback leaves no interface, and the next apply starts the tunnel.
#[test]
fn a_rolled_back_first_generation_leaves_no_tunnel_interface() {
    let world = World::new();
    world.follow_tunnel();
    world.faults.borrow().missing_listeners.set(100);
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(1),
                cause: RollbackCause::HealthGate {
                    failed: HealthCheck::Listeners
                },
            }
        }
    );
    assert!(
        !world.paths.wgexit_accept_local().exists(),
        "the rollback took the tunnel down"
    );
    let calls = node.calls();
    assert!(
        calls.iter().all(|call| !call.contains("wg-quick down")),
        "the unit's own stop took it down: {calls:#?}"
    );
    world.faults.borrow().missing_listeners.set(0);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
    assert!(world.paths.wgexit_accept_local().exists());
}

/// An interface left by an earlier failure (lon1, 2026-10-25: a rollback
/// whose stop could not read the configuration) makes `wg-quick up` refuse.
/// The rollback to nothing takes it down with `wg-quick down` while the
/// configuration is still in place, and the next apply works.
#[test]
fn a_tunnel_interface_left_over_is_taken_down_by_the_rollback_to_nothing() {
    let world = World::new();
    world.follow_tunnel();
    fs::write(world.paths.wgexit_accept_local(), "1\n").unwrap();
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RolledBack {
                generation: Generation::new(1),
                cause: RollbackCause::Apply {
                    step: ApplyStep::WireGuard,
                    stderr_tail: StderrTail::scrubbed(TUNNEL_START_FAILED, &[]),
                },
            }
        }
    );
    assert_eq!(world.current(), None);
    assert!(
        !world.paths.wgexit_accept_local().exists(),
        "the rollback took the interface down"
    );
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/wg-quick down wgexit")
            > index_of(&calls, "systemctl stop wg-quick@wgexit.service"),
        "taken down once the unit's stop had left it: {calls:#?}"
    );
    assert_eq!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
}

/// An interface whose `wg-quick down` fails fails the rollback.
#[test]
fn a_tunnel_interface_whose_down_fails_fails_the_rollback() {
    let world = World::new();
    world.follow_tunnel();
    fs::write(world.paths.wgexit_accept_local(), "1\n").unwrap();
    world.faults.borrow_mut().wg_down_fails = true;
    let node = world.node(1000);
    let state = world.apply_and_run(&node, world.bundle(1, same));
    assert_eq!(
        state,
        TxnState::Failed {
            error: AgentError::RollbackFailed {
                generation: Generation::new(1),
                cause: RollbackCause::Apply {
                    step: ApplyStep::WireGuard,
                    stderr_tail: StderrTail::scrubbed(TUNNEL_START_FAILED, &[]),
                },
            }
        }
    );
    assert_eq!(world.current(), None);
    assert!(world.paths.wgexit_accept_local().exists());
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
        txn::rollback::revert(&world.paths, &node, Generation::new(1), Generation::ZERO),
        Err(RollbackCause::Swap { errno })
    );
    assert_stopped_safe(&node.calls());
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
