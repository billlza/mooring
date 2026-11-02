// SPDX-License-Identifier: GPL-3.0-or-later

//! How a change ends (design §11.2: step 7, and what follows step 9):
//! `Confirm` commits it, `Rollback` reverts it at once, and the confirm
//! timer, or a reboot that lost it, reverts it unconfirmed; a timer reverts
//! only the change it was armed for. Nothing is switched without the timer,
//! and every change ends one way (`txn::end`): its outcome recorded, the
//! pending change cleared, then its timer stopped if it is still armed,
//! neither fired nor lost to a reboot. So a write of the end that fails
//! leaves the timer armed for a retry or to revert the change, and a timer
//! that cannot be stopped finds nothing to revert when it fires.

use mooring_agent_proto::{AgentError, Generation, IoOp, SystemdOp, TxnState, UnitName};

use super::world::{ToolFault, World, idle, index_of, same};
use crate::tests::{EEXIST, ENOENT, occupy_temporary};
use crate::txn::record::{Phase, pending};
use crate::txn::{self, Launched, Why};

fn timer(generation: u64) -> UnitName {
    UnitName::new(format!("mooring-txn-revert-{generation}.timer")).unwrap()
}

/// Whether the node was asked to stop the confirm timer of `generation`.
fn stopped(calls: &[String], generation: u64) -> bool {
    let stop = format!("/usr/bin/systemctl stop mooring-txn-revert-{generation}.timer");
    calls.contains(&stop)
}

/// Generation 1 committed and generation 2 awaiting its confirmation.
fn awaiting_second() -> World {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    assert_eq!(
        world.apply_and_run(&world.node(2000), world.bundle(2, idle(301))),
        TxnState::AwaitingConfirm
    );
    world
}

#[test]
fn a_change_whose_timer_cannot_be_armed_fails_before_the_swap() {
    for (fault, error) in [
        (
            ToolFault::Fails,
            AgentError::Systemd {
                unit: timer(2),
                op: SystemdOp::Run,
            },
        ),
        (
            ToolFault::Unstartable,
            AgentError::Io {
                op: IoOp::SpawnProcess,
                errno: Some(ENOENT),
            },
        ),
    ] {
        let world = World::new();
        world.commit(&world.node(1000), world.bundle(1, same));
        world.faults.borrow_mut().arm = Some(fault);
        let node = world.node(2000);
        assert_eq!(
            world.apply_and_run(&node, world.bundle(2, idle(301))),
            TxnState::Failed { error },
            "{fault:?}"
        );
        assert_eq!(world.current().as_deref(), Some("gen-1"));
        assert!(!world.paths.generation(Generation::new(2)).exists());
        assert_eq!(pending(&world.paths).unwrap(), None);
        let calls = node.calls();
        assert!(
            !calls
                .iter()
                .any(|call| call.contains("systemctl stop") || call.contains("restart")),
            "nothing to stop or restart: {calls:#?}"
        );
    }
}

/// The timer is armed, but the phase that says so cannot be recorded: the
/// change fails, and its end stops the timer all the same, so that the
/// generation can be retried at once.
#[test]
fn a_timer_armed_whose_phase_cannot_be_recorded_is_stopped() {
    let world = World::new();
    let node = world.node(1000);
    txn::apply(&world.paths, &node, world.bundle(1, same)).unwrap();
    let blocker = occupy_temporary(&world.paths.pending());
    txn::run(&world.paths, &node, Generation::new(1)).unwrap();
    std::fs::remove_dir(blocker).unwrap();
    assert_eq!(
        world.state(1),
        TxnState::Failed {
            error: AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(EEXIST),
            }
        }
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert_eq!(world.current(), None);
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/systemctl stop mooring-txn-revert-1.timer")
            > index_of(&calls, "--on-active=120"),
        "{calls:#?}"
    );
}

#[test]
fn a_confirm_whose_timer_cannot_be_stopped_is_committed_and_says_so() {
    let world = awaiting_second();
    let two = Generation::new(2);
    world.faults.borrow_mut().disarm = true;
    let node = world.node(2050);
    assert_eq!(
        txn::confirm(&world.paths, &node, two),
        Err(AgentError::Systemd {
            unit: timer(2),
            op: SystemdOp::Stop,
        })
    );
    assert_eq!(world.state(2), TxnState::Committed);
    assert_eq!(pending(&world.paths).unwrap(), None);
    // The timer that kept running finds nothing to revert.
    assert_eq!(
        txn::revert_pending(&world.paths, &world.node(2120), Why::Unconfirmed(two)),
        Err(AgentError::NotAwaitingConfirm)
    );
    assert_eq!(world.current().as_deref(), Some("gen-2"));
    assert_eq!(world.state(2), TxnState::Committed);
}

#[test]
fn a_rollback_whose_timer_cannot_be_stopped_is_reverted_and_says_so() {
    let world = awaiting_second();
    world.faults.borrow_mut().disarm = true;
    let node = world.node(2050);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::Systemd {
            unit: timer(2),
            op: SystemdOp::Stop,
        })
    );
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_eq!(pending(&world.paths).unwrap(), None);
}

/// A commit that cannot be recorded stops nothing: the timer stays armed,
/// so the `Confirm` can be retried, and a change left unconfirmed is still
/// reverted.
#[test]
fn a_confirm_that_cannot_be_recorded_keeps_its_timer() {
    let world = awaiting_second();
    let two = Generation::new(2);
    let blocker = occupy_temporary(&world.paths.txn_record(two));
    let node = world.node(2050);
    assert_eq!(
        txn::confirm(&world.paths, &node, two),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST),
        })
    );
    assert!(!stopped(&node.calls(), 2), "{:#?}", node.calls());
    assert_eq!(
        pending(&world.paths).unwrap().map(|pending| pending.phase),
        Some(Phase::AwaitingConfirm)
    );
    std::fs::remove_dir(blocker).unwrap();
    let node = world.node(2060);
    assert_eq!(txn::confirm(&world.paths, &node, two), Ok(two));
    assert!(stopped(&node.calls(), 2));
    assert_eq!(world.state(2), TxnState::Committed);
}

/// A rollback whose end cannot be recorded leaves the change pending with
/// its timer armed; a retry finds it switched back already and ends it.
#[test]
fn a_rollback_that_cannot_be_recorded_keeps_its_timer() {
    let world = awaiting_second();
    let two = Generation::new(2);
    let blocker = occupy_temporary(&world.paths.txn_record(two));
    let node = world.node(2050);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST),
        })
    );
    assert!(!stopped(&node.calls(), 2), "{:#?}", node.calls());
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_eq!(
        pending(&world.paths).unwrap().map(|pending| pending.phase),
        Some(Phase::AwaitingConfirm)
    );
    std::fs::remove_dir(blocker).unwrap();
    let node = world.node(2060);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(two)
    );
    assert!(stopped(&node.calls(), 2));
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(pending(&world.paths).unwrap(), None);
}

#[test]
fn confirm_commits_only_the_change_awaiting_it() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(1, same)),
        Ok(Launched::Launched(Generation::new(1)))
    );
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(1)),
        Err(AgentError::NotAwaitingConfirm),
        "still running"
    );
    txn::run(&world.paths, &node, Generation::new(1)).unwrap();
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(2)),
        Err(AgentError::NotAwaitingConfirm)
    );
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(1)),
        Ok(Generation::new(1))
    );
    index_of(
        &node.calls(),
        "/usr/bin/systemctl stop mooring-txn-revert-1.timer",
    );
    assert_eq!(world.state(1), TxnState::Committed);
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(1)),
        Err(AgentError::NotAwaitingConfirm)
    );
}

#[test]
fn an_unconfirmed_change_is_reverted_by_the_timer() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    let next = world.bundle(2, idle(302));
    assert_eq!(world.apply_and_run(&node, next), TxnState::AwaitingConfirm);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2))),
        Ok(Generation::new(2))
    );
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed {
                generation: Generation::new(2)
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2))),
        Err(AgentError::NotAwaitingConfirm),
        "a timer firing after the fact changes nothing"
    );
}

#[test]
fn rollback_reverts_now_and_disarms_the_timer() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::NotAwaitingConfirm)
    );
    let next = world.bundle(2, idle(303));
    world.apply_and_run(&node, next);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    index_of(&node.calls(), "systemctl stop mooring-txn-revert-2.timer");
}

#[test]
fn a_timer_reverts_only_the_change_it_was_armed_for() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    let next = world.bundle(2, idle(304));
    assert_eq!(
        txn::apply(&world.paths, &node, next),
        Ok(Launched::Launched(Generation::new(2)))
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(2))),
        Err(AgentError::NotAwaitingConfirm),
        "a stale timer of an earlier attempt leaves a launched retry alone"
    );
    assert!(pending(&world.paths).unwrap().is_some());
    txn::run(&world.paths, &node, Generation::new(2)).unwrap();
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(Generation::new(3))),
        Err(AgentError::NotAwaitingConfirm),
        "another generation's timer"
    );
    assert_eq!(world.current().as_deref(), Some("gen-2"));
    assert_eq!(world.state(2), TxnState::AwaitingConfirm);
}

#[test]
fn a_reboot_reverts_whatever_was_pending() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let next = world.bundle(2, idle(305));
    assert_eq!(
        world.apply_and_run(&world.node(2000), next),
        TxnState::AwaitingConfirm
    );
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Rebooted),
        Ok(Generation::new(2))
    );
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed {
                generation: Generation::new(2)
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("mooring-txn-revert")),
        "the reboot took the timer with it"
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Rebooted),
        Err(AgentError::NotAwaitingConfirm)
    );
    let cut_short = world.bundle(3, idle(306));
    assert_eq!(
        txn::apply(&world.paths, &node, cut_short),
        Ok(Launched::Launched(Generation::new(3)))
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Rebooted),
        Ok(Generation::new(3)),
        "a transaction the reboot cut short"
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
}
