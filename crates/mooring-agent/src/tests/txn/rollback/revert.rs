// SPDX-License-Identifier: GPL-3.0-or-later

//! What a revert leaves and a revert done again (design §11.2 step 8): a
//! `Rollback` of a transaction that died before or after its swap, the
//! failed generation's directory removed only once `current` is known not
//! to name it, and a revert that stopped part-way or could not be recorded
//! taken up again. A directory that cannot be removed is the error: the
//! request's for a cancelled change, which stops nothing, and
//! `RollbackFailed` for a switched one, unless the rollback had already
//! failed, whose own cause is kept.

use std::fs;

use mooring_agent_proto::{AgentError, Generation, IoOp, RollbackCause, TxnState};

use super::{assert_rollback_failed, assert_stopped_safe, awaiting_second};
use crate::tests::txn::world::{World, idle, index_of, same};
use crate::tests::{
    EACCES, EEXIST, ENOTDIR, FakeNode, ModeFault, header, occupy_temporary, scratch,
};
use crate::txn::record::{Change, Pending, Phase, pending, set_pending};
use crate::txn::stage::BUNDLE_FILE;
use crate::txn::{self, Launched, Why};

#[test]
fn rollback_cancels_a_transaction_that_died_before_its_swap() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(2, idle(311))),
        Ok(Launched::Launched(Generation::new(2)))
    );
    // What a unit that died while staging leaves behind.
    let staged = world.paths.generation(Generation::new(2));
    fs::create_dir_all(&staged).unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, idle(312))),
        Err(AgentError::Busy {
            generation: Generation::new(2)
        })
    );
    let node = world.node(3000);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert!(!staged.exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert!(
        node.calls().is_empty(),
        "nothing was switched, so nothing is undone and no timer stopped: {:#?}",
        node.calls()
    );
    assert_eq!(
        txn::run(&world.paths, &node, Generation::new(2)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(2)
        }),
        "a unit that starts late finds nothing to run"
    );
}

#[test]
fn rollback_reverts_a_transaction_that_died_after_its_swap() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let next = world.bundle(2, idle(303));
    assert_eq!(
        world.apply_and_run(&world.node(2000), next),
        TxnState::AwaitingConfirm
    );
    // The unit died after the swap, before it recorded `AwaitingConfirm`.
    set_pending(
        &world.paths,
        &Pending {
            generation: Generation::new(2),
            change: Change::Apply {
                previous: Generation::new(1),
            },
            phase: Phase::Armed,
        },
    )
    .unwrap();
    let node = world.node(3000);
    assert_eq!(
        txn::confirm(&world.paths, &node, Generation::new(2)),
        Err(AgentError::NotAwaitingConfirm),
        "a transaction that never passed its health gate cannot be confirmed"
    );
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::new(2))
    );
    assert_eq!(world.state(2), TxnState::Reverted);
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    let calls = node.calls();
    assert!(
        index_of(&calls, "/usr/bin/systemctl stop mooring-txn-revert-2.timer")
            > index_of(&calls, "restart mooring-xray.service"),
        "the timer is stopped last, once the revert is recorded"
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
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

/// A revert that died after its first step, the swap back, is done again
/// when the timer fires: `current` already naming the previous generation
/// does not mean the change switched nothing.
#[test]
fn a_revert_that_died_after_its_swap_back_is_done_again() {
    let world = awaiting_second(idle(301));
    let two = Generation::new(2);
    txn::links::swap(&world.paths, Generation::new(1)).unwrap();
    let node = world.node(2120);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(two)),
        Ok(two)
    );
    index_of(
        &node.calls(),
        "/usr/bin/systemctl restart mooring-xray.service",
    );
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed { generation: two }
        }
    );
    assert!(!world.paths.generation(two).exists());
    assert_eq!(pending(&world.paths).unwrap(), None);
}

/// A revert that failed, and whose failure could not be recorded, is tried
/// again when the timer fires rather than taken as done: here the second
/// attempt re-applies everything of the previous generation and the node
/// serves again.
#[test]
fn a_failed_revert_that_could_not_be_recorded_is_tried_again() {
    let world = awaiting_second(idle(301));
    let two = Generation::new(2);
    world.faults.borrow().failing_engine_restarts.set(1);
    let blocker = occupy_temporary(&world.paths.txn_record(two));
    let node = world.node(2050);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST),
        })
    );
    assert_stopped_safe(&node.calls());
    fs::remove_dir(blocker).unwrap();
    let node = world.node(2120);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Unconfirmed(two)),
        Ok(two)
    );
    let calls = node.calls();
    index_of(&calls, "/usr/bin/systemctl restart mooring-xray.service");
    index_of(&calls, "/usr/bin/systemctl restart mooring-hy2.service");
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed { generation: two }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    assert_eq!(pending(&world.paths).unwrap(), None);
}

/// A revert that cannot swap back keeps the directory `current` still
/// names, so that `current` and the fixed links into it stay whole for the
/// stopped node.
#[test]
fn a_revert_that_cannot_swap_back_keeps_the_generation_current_names() {
    let world = awaiting_second(idle(301));
    let current = world.paths.current();
    fs::create_dir_all(
        current
            .with_extension(format!("swap.{}", std::process::id()))
            .join("entry"),
    )
    .unwrap();
    let node = world.node(2050);
    assert_eq!(
        txn::rollback::revert(&world.paths, &node, Generation::new(2), Generation::new(1)),
        Err(RollbackCause::Swap {
            errno: Some(EEXIST)
        })
    );
    assert_eq!(world.current().as_deref(), Some("gen-2"));
    assert!(world.paths.generation(Generation::new(2)).is_dir());
    assert!(fs::metadata(world.paths.nft_conf_link()).is_ok());
    assert!(fs::metadata(world.paths.wg_conf_link()).is_ok());
    assert_stopped_safe(&node.calls());
}

/// A revert that cannot tell where `current` points keeps the failed
/// generation: here `current` is a directory, which the swap back cannot
/// replace and no reading takes for a link. The node is stopped, and the
/// swap's own failure is the one reported.
#[test]
fn a_revert_that_cannot_read_current_keeps_the_failed_generation() {
    let world = awaiting_second(idle(301));
    // What renaming a link onto a directory that holds something gives, on
    // this system.
    let probe = world.paths.at("/probe");
    fs::create_dir_all(probe.join("full/entry")).unwrap();
    std::os::unix::fs::symlink("gen-1", probe.join("link")).unwrap();
    let errno = fs::rename(probe.join("link"), probe.join("full"))
        .unwrap_err()
        .raw_os_error();
    let current = world.paths.current();
    fs::remove_file(&current).unwrap();
    fs::create_dir_all(current.join("entry")).unwrap();
    let node = world.node(2050);
    assert_eq!(
        txn::rollback::revert(&world.paths, &node, Generation::new(2), Generation::new(1)),
        Err(RollbackCause::Swap { errno })
    );
    assert!(world.paths.generation(Generation::new(2)).is_dir());
    assert_stopped_safe(&node.calls());
}
