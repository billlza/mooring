// SPDX-License-Identifier: GPL-3.0-or-later

//! `Apply`'s side (design §11.2): what it checks at once and the launch of
//! the transaction's unit, each way it can fail leaving the node free to
//! retry, against a scratch root and a stand-in node.

use std::fs;
use std::io;
use std::os::unix::fs::symlink;

use mooring_agent_proto::{AgentError, Generation, IoOp, TxnState};

use crate::host::Tool;
use crate::store::Lock;
use crate::tests::{
    EEXIST, ENOENT, ENOTDIR, FakeNode, failed, header, occupy_temporary, ok, scratch, temporary_of,
};
use crate::txn::record::{Phase, last_committed, pending};
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

/// Records that cannot be listed are an error, never "no commit yet".
#[test]
fn records_that_cannot_be_listed_are_an_error() {
    let (_dir, paths) = scratch();
    fs::create_dir_all(paths.txn_dir().parent().unwrap()).unwrap();
    fs::write(paths.txn_dir(), "").unwrap();
    assert_eq!(
        last_committed(&paths),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(ENOTDIR),
        })
    );
}
