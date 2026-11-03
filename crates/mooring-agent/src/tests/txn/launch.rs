// SPDX-License-Identifier: GPL-3.0-or-later

//! `Apply`'s side (design §11.2): the record it writes and the unit it
//! launches, what it checks at once (busy, halted, unchanged, not newer),
//! and the transaction unit, which runs only the transaction launched for
//! it. An apply whose record or pending change cannot be written launches
//! nothing. A launch that fails leaves nothing pending and the generation
//! free to retry, unless its failure cannot be recorded either: the change
//! then stays pending for a `Rollback`.

use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};

use mooring_agent_proto::{
    AgentError, BundleHeader, Generation, Halt, IoOp, ManagedFile, ShutdownReason, TxnStage,
    TxnState, UnixTime,
};

use super::world::{World, idle, same};
use crate::host::Tool;
use crate::store::{Lock, write_json};
use crate::tests::{
    EEXIST, ENOENT, FakeNode, failed, header, occupy_temporary, ok, scratch, temporary_of,
};
use crate::txn::record::{Change, Pending, Phase, pending};
use crate::txn::{self, Launched, Why};

#[test]
fn a_launcher_that_cannot_be_started_fails_the_transaction_and_leaves_nothing_pending() {
    let (_dir, paths) = scratch();
    let node = FakeNode::answering(
        1_000,
        Box::new(|tool, _| match tool {
            Tool::SystemdRun => Err(io::Error::from_raw_os_error(ENOENT)),
            _ => Ok(ok(b"")),
        }),
    );
    let one = Generation::new(1);
    let error = AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: Some(ENOENT),
    };
    assert_eq!(txn::apply(&paths, &node, header(1)), Err(error.clone()));
    assert_eq!(txn::status(&paths, one), Ok(TxnState::Failed { error }));
    assert_eq!(pending(&paths), Ok(None));
    // Nothing is left busy: the generation is retried at once.
    let node = FakeNode::new(1_100);
    assert_eq!(
        txn::apply(&paths, &node, header(1)),
        Ok(Launched::Launched(one))
    );
}

#[test]
fn an_apply_while_the_lock_is_held_names_the_nodes_generation_or_the_unreadable_change() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_000);
    fs::create_dir_all(paths.etc()).unwrap();
    symlink("gen-3", paths.current()).unwrap();
    // A `Confirm` or revert finishing holds the lock with nothing pending.
    let _held = Lock::exclusive(&paths.txn_lock()).unwrap();
    assert_eq!(
        txn::apply(&paths, &node, header(4)),
        Err(AgentError::Busy {
            generation: Generation::new(3)
        })
    );
    // A pending change that cannot be read is the answer, not a guess.
    fs::create_dir_all(paths.txn_dir()).unwrap();
    fs::write(paths.pending(), "{").unwrap();
    assert_eq!(
        txn::apply(&paths, &node, header(4)),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: None
        })
    );
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
}

#[test]
fn an_apply_whose_record_cannot_be_written_launches_nothing() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_000);
    let one = Generation::new(1);
    let blocker = occupy_temporary(&paths.txn_record(one));
    assert_eq!(
        txn::apply(&paths, &node, header(1)),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert_eq!(
        txn::status(&paths, one),
        Err(AgentError::UnknownTransaction { generation: one })
    );
    assert_eq!(pending(&paths), Ok(None));
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
    fs::remove_dir(blocker).unwrap();
    assert_eq!(
        txn::apply(&paths, &node, header(1)),
        Ok(Launched::Launched(one))
    );
}

#[test]
fn an_apply_whose_pending_change_cannot_be_written_launches_nothing() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_000);
    let blocker = occupy_temporary(&paths.pending());
    let error = AgentError::Io {
        op: IoOp::WriteState,
        errno: Some(EEXIST),
    };
    assert_eq!(txn::apply(&paths, &node, header(1)), Err(error.clone()));
    assert_eq!(
        txn::status(&paths, Generation::new(1)),
        Ok(TxnState::Failed { error }),
        "a record never says running for a change nothing runs"
    );
    assert_eq!(pending(&paths), Ok(None));
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
    fs::remove_dir(blocker).unwrap();
    assert_eq!(
        txn::apply(&paths, &node, header(1)),
        Ok(Launched::Launched(Generation::new(1)))
    );
}

/// A launch that fails when its failure cannot be recorded either: the
/// write's error is the answer (the node cannot keep its state), and the
/// change stays pending, as after a crash at that point, for a `Rollback`
/// (or the next boot's `txn-recover`) to end.
#[test]
fn a_launch_failure_that_cannot_be_recorded_is_left_for_a_rollback() {
    let (_dir, paths) = scratch();
    let one = Generation::new(1);
    let record = paths.txn_record(one);
    let node = FakeNode::answering(
        1_000,
        Box::new(move |tool, _| {
            Ok(match tool {
                Tool::SystemdRun => {
                    occupy_temporary(&record);
                    failed(b"Failed to start transient service unit.\n")
                }
                _ => ok(b""),
            })
        }),
    );
    assert_eq!(
        txn::apply(&paths, &node, header(1)),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST)
        })
    );
    assert_eq!(
        pending(&paths).unwrap().map(|pending| pending.phase),
        Some(Phase::Launched)
    );
    fs::remove_dir(temporary_of(&paths.txn_record(one))).unwrap();
    assert_eq!(txn::revert_pending(&paths, &node, Why::Requested), Ok(one));
    assert_eq!(txn::status(&paths, one), Ok(TxnState::Reverted));
    assert_eq!(pending(&paths), Ok(None));
}

#[test]
fn apply_records_the_transaction_and_launches_its_unit() {
    let world = World::new();
    let node = world.node(1000);
    let header = world.bundle(1, same);
    assert_eq!(
        txn::apply(&world.paths, &node, header),
        Ok(Launched::Launched(Generation::new(1)))
    );
    assert_eq!(
        world.state(1),
        TxnState::Running {
            stage: TxnStage::Preconditions
        }
    );
    assert_eq!(
        fs::metadata(world.paths.txn_record(Generation::new(1)))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640,
        "the watch reads the records"
    );
    assert_eq!(
        pending(&world.paths).unwrap(),
        Some(Pending {
            generation: Generation::new(1),
            change: Change::Apply {
                previous: Generation::ZERO
            },
            phase: Phase::Launched,
        })
    );
    assert_eq!(
        node.calls(),
        vec!["/usr/bin/systemd-run --unit=mooring-txn-1 --collect --quiet /usr/local/lib/mooring/agent/current txn 1".to_owned()]
    );
}

#[test]
fn apply_refuses_while_busy_halted_or_not_newer() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(2, same)),
        Ok(Launched::Launched(Generation::new(2)))
    );
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::Busy {
            generation: Generation::new(2)
        })
    );
    let held = Lock::exclusive(&world.paths.txn_lock()).unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::Busy {
            generation: Generation::new(2)
        })
    );
    drop(held);
    fs::remove_file(world.paths.pending()).unwrap();
    let held = Lock::exclusive(&world.paths.txn_lock()).unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::Busy {
            generation: Generation::ZERO
        }),
        "the lock held with nothing pending: a confirm or revert finishing"
    );
    drop(held);
    write_json(
        &world.paths.halted(),
        &Halt {
            at: UnixTime::from_secs(1),
            reason: ShutdownReason::Operator,
        },
        0o640,
    )
    .unwrap();
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(3, same)),
        Err(AgentError::NodeHalted)
    );
    fs::remove_file(world.paths.halted()).unwrap();
    world.commit(
        &node,
        world.bundle(5, |file, text| {
            if file == ManagedFile::WatchConfig {
                text.replace("10", "12")
            } else {
                text
            }
        }),
    );
    for older_or_same in [4, 5] {
        assert_eq!(
            txn::apply(&world.paths, &node, world.bundle(older_or_same, same)),
            Err(AgentError::GenerationNotNewer {
                current: Generation::new(5)
            }),
            "generation {older_or_same}"
        );
    }
}

#[test]
fn a_bundle_the_node_already_runs_is_unchanged() {
    let world = World::new();
    let node = world.node(1000);
    let header = world.bundle(1, same);
    world.commit(&node, header.clone());
    let again = BundleHeader {
        config_generation: Generation::new(9),
        ..header
    };
    let node = world.node(2000);
    assert_eq!(
        txn::apply(&world.paths, &node, again),
        Ok(Launched::Unchanged(Generation::new(1)))
    );
    assert!(node.calls().is_empty(), "nothing ran");
    assert_eq!(
        txn::status(&world.paths, Generation::new(9)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(9)
        })
    );
}

#[test]
fn a_transaction_unit_runs_only_its_own_launched_transaction() {
    let world = World::new();
    world.faults.borrow_mut().launch = true;
    let node = world.node(1000);
    let unlaunched = txn::apply(&world.paths, &node, world.bundle(3, idle(313)));
    assert!(
        matches!(unlaunched, Err(AgentError::Systemd { .. })),
        "{unlaunched:?}"
    );
    let recorded = world.state(3);
    world.faults.borrow_mut().launch = false;
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(2, same)),
        Ok(Launched::Launched(Generation::new(2)))
    );
    assert_eq!(
        txn::run(&world.paths, &node, Generation::new(3)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(3)
        }),
        "a unit for a recorded generation that is not the pending one"
    );
    assert_eq!(world.state(3), recorded);
    assert_eq!(world.current(), None);
    txn::run(&world.paths, &node, Generation::new(2)).unwrap();
    assert_eq!(world.state(2), TxnState::AwaitingConfirm);
    assert_eq!(
        txn::run(&world.paths, &node, Generation::new(2)),
        Err(AgentError::UnknownTransaction {
            generation: Generation::new(2)
        }),
        "a second run of the unit does nothing"
    );
    assert_eq!(world.state(2), TxnState::AwaitingConfirm);
}

#[test]
fn a_unit_that_cannot_be_launched_leaves_nothing_pending() {
    let world = World::new();
    world.faults.borrow_mut().launch = true;
    let node = world.node(1000);
    let refused = txn::apply(&world.paths, &node, world.bundle(1, same));
    let Err(error @ AgentError::Systemd { .. }) = refused else {
        panic!("{refused:?}");
    };
    assert_eq!(world.state(1), TxnState::Failed { error });
    assert_eq!(pending(&world.paths).unwrap(), None);
    world.faults.borrow_mut().launch = false;
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(1, same)),
        Ok(Launched::Launched(Generation::new(1))),
        "the generation can be launched again"
    );
}
