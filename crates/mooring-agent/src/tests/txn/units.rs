// SPDX-License-Identifier: GPL-3.0-or-later

//! The transaction's systemd units, `txn <N>`, `txn-revert <N>` and
//! `txn-recover`, with the exit statuses systemd sees: a timer or a boot
//! that finds nothing to revert has done its work.

use std::process::ExitCode;

use mooring_agent_proto::{AgentError, Generation, IoOp, TxnState};

use super::world::{World, same};
use crate::agent::Invocation;
use crate::tests::cli::ran;
use crate::tests::{FakeNode, scratch};
use crate::txn;

#[test]
fn a_transaction_unit_exits_0_once_its_change_awaits_confirmation() {
    let world = World::new();
    let node = world.node(1000);
    let one = Generation::new(1);
    txn::apply(&world.paths, &node, world.bundle(1, same)).unwrap();
    let done = ran(Invocation::Txn(one), &world.paths, &node, b"");
    assert_eq!(done.code, ExitCode::SUCCESS, "{}", done.stderr);
    assert!(done.stderr.is_empty());
    assert_eq!(world.state(1), TxnState::AwaitingConfirm);
    let again = ran(Invocation::Txn(one), &world.paths, &node, b"");
    assert_eq!(again.code, ExitCode::from(1));
    assert_eq!(
        again.stderr,
        format!(
            "mooring-agent: transaction 1 could not run: {}\n",
            AgentError::UnknownTransaction { generation: one }
        )
    );
}

#[test]
fn a_timer_that_fires_reverts_its_change_and_exits_0() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        world.apply_and_run(&node, world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
    let fired = ran(
        Invocation::TxnRevert(Generation::new(1)),
        &world.paths,
        &world.node(1120),
        b"",
    );
    assert_eq!(fired.code, ExitCode::SUCCESS, "{}", fired.stderr);
    assert_eq!(
        world.state(1),
        TxnState::Failed {
            error: AgentError::RevertedUnconfirmed {
                generation: Generation::new(1)
            }
        }
    );
    assert_eq!(world.current(), None);
}

#[test]
fn the_revert_units_exit_0_with_nothing_to_revert_and_1_when_reverting_fails() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    for invocation in [
        Invocation::TxnRevert(Generation::new(3)),
        Invocation::TxnRecover,
    ] {
        let nothing = ran(invocation.clone(), &paths, &node, b"");
        assert_eq!(nothing.code, ExitCode::SUCCESS, "{invocation:?}");
        assert!(nothing.stderr.is_empty());
    }
    std::fs::create_dir_all(paths.txn_dir()).unwrap();
    std::fs::write(paths.pending(), "{").unwrap();
    let damaged = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    let revert = ran(
        Invocation::TxnRevert(Generation::new(3)),
        &paths,
        &node,
        b"",
    );
    assert_eq!(revert.code, ExitCode::from(1));
    assert_eq!(
        revert.stderr,
        format!("mooring-agent: reverting 3 failed: {damaged}\n")
    );
    let recover = ran(Invocation::TxnRecover, &paths, &node, b"");
    assert_eq!(recover.code, ExitCode::from(1));
    assert_eq!(
        recover.stderr,
        format!("mooring-agent: reverting the change pending at boot failed: {damaged}\n")
    );
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
}
