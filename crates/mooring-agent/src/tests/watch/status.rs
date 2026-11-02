// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch's view and `Status` (design §11.3, §11.5): a view that cannot
//! be written reported at the next tick; `Status` serving the view with the
//! live holds, the halt and the last commit, an error before the watch's
//! first tick, and a refusal for a view that is not one; and the last
//! commit, the newest committed record, where names that are not records
//! are skipped, and a record that cannot be read, or records that cannot be
//! listed, are an error.

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    AgentError, AgentEventKind, AppliedGeneration, Generation, Holds, IoOp, LineRequest,
    OperatorHold, Response, Role, Sha256Hex, TxnState, WatchError, WatchErrorKind,
};

use super::world::{OCT_8, World, email, halt, minute, tick};
use crate::gate::write_holds;
use crate::host::Node;
use crate::store::malformed;
use crate::tests::serve::{ask, frame};
use crate::tests::{ENOTDIR, occupy_temporary, scratch};
use crate::txn::record::last_committed;
use crate::watch::Watch;

#[test]
fn a_view_that_cannot_be_written_is_reported_at_the_next_tick() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(58_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    let blocker = occupy_temporary(&world.paths.watch_status());
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    fs::remove_dir(&blocker).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::StateWrite],
        "the write before this tick's failed"
    );
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::GateOpened,
            AgentEventKind::ConditionRaised {
                condition: WatchError::StateWrite { errno: Some(17) }
            },
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::StateWrite
            },
        ]
    );
}

#[test]
fn status_is_the_watch_view_with_live_holds_halt_and_last_commit() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    assert_eq!(
        ask(&world.paths, &node, Role::Ops, frame(&LineRequest::Status)),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(2)
        }),
        "no view before the watch's first tick"
    );
    let mut watch = Watch::start(&world.paths).unwrap();
    world.xray().counters = BTreeMap::from([("u01@reality", (1, 1))]);
    minute(&mut watch, &world, &node);
    world.xray().counters = BTreeMap::from([("u01@reality", (2, 2))]);
    minute(&mut watch, &world, &node);
    world.install(2, TxnState::AwaitingConfirm);
    let held = Holds {
        operator: Some(OperatorHold { at: node.now() }),
        ..Holds::NONE
    };
    write_holds(&world.paths, &held).unwrap();
    halt(&world.paths, node.now().as_secs());
    let view = world.status();
    for role in [Role::Ops, Role::Viewer] {
        let Ok(Response::Status(status)) =
            ask(&world.paths, &node, role, frame(&LineRequest::Status))
        else {
            panic!("{role:?}");
        };
        assert_eq!(status.now, node.now());
        assert_eq!(status.watch_at, view.at);
        assert_eq!(status.gate, view.observed.gate);
        assert_eq!(status.holds, held, "read live, not from the view");
        assert_eq!(status.halted.map(|halt| halt.at), Some(node.now()));
        assert_eq!(status.latest_handshake, view.latest_handshake);
        assert_eq!(
            status.applied,
            Some(AppliedGeneration {
                generation: Generation::new(1),
                digest: Sha256Hex::from_bytes([9; 32]),
            }),
            "generation 2 awaits its confirmation"
        );
        assert_eq!(status.conditions, view.observed.conditions);
        assert_eq!(status.accounting_at, view.accounting.at);
        assert_eq!(
            status.last_active,
            BTreeMap::from([(email("u01@reality"), view.accounting.at.unwrap())])
        );
        assert_eq!(status.engines, view.engines);
        assert_eq!(status.host, view.host.health);
        assert_eq!(status.transfer, view.transfer.reported);
    }
}

#[test]
fn a_view_that_is_not_one_is_refused_not_served() {
    let world = World::new();
    world.write("/var/lib/mooring/watch/status.json", "{}");
    for role in [Role::Ops, Role::Viewer] {
        assert_eq!(
            ask(
                &world.paths,
                &world.node(1),
                role,
                frame(&LineRequest::Status)
            ),
            Err(malformed(IoOp::ReadState))
        );
    }
}

#[test]
fn the_last_commit_is_the_newest_committed_record() {
    let world = World::new();
    assert_eq!(last_committed(&world.paths), Ok(None), "no records yet");
    world.record(1, TxnState::Committed);
    world.record(3, TxnState::Committed);
    world.record(4, TxnState::AwaitingConfirm);
    world.record(5, TxnState::Reverted);
    let txn = world.paths.txn_dir();
    // Not records: a name that is not canonical, the change in flight, a
    // temporary file.
    fs::write(txn.join("gen-07.json"), "{}").unwrap();
    fs::write(txn.join("pending.json"), "{}").unwrap();
    fs::write(txn.join(".gen-6.json.4242.tmp"), "{}").unwrap();
    assert_eq!(
        last_committed(&world.paths),
        Ok(Some(AppliedGeneration {
            generation: Generation::new(3),
            digest: Sha256Hex::from_bytes([9; 32]),
        }))
    );
    fs::write(world.paths.txn_record(Generation::new(9)), "not a record").unwrap();
    assert_eq!(
        last_committed(&world.paths),
        Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: None
        }),
        "a damaged record is an error, never skipped"
    );
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
