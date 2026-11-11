// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's cut and lift, and the records (design §11.8), through the
//! forced command's dispatcher: the state written first, the cut set
//! changed after, every refusal changing nothing.

use mooring_agent_proto::{
    AbuseAction, AbuseSeq, AgentError, LineRequest, OpaqueUserId, Reply, Response, Role, TxnState,
    user_source,
};

use crate::abuse::state::AbuseState;
use crate::serve::{Session, line_reply};
use crate::tests::FakeNode;
use crate::tests::watch::world::World;

const NOW: u64 = 1_791_600_000;

fn user(id: &str) -> OpaqueUserId {
    OpaqueUserId::new(id).unwrap()
}

fn send(world: &World, node: &FakeNode, role: Role, line: LineRequest) -> Reply {
    line_reply(
        &world.paths,
        node,
        Session {
            role,
            ssh_connection: None,
        },
        line,
    )
}

fn cut(world: &World, node: &FakeNode, id: &str) -> Reply {
    send(
        world,
        node,
        Role::Ops,
        LineRequest::AbuseCut { user: user(id) },
    )
}

fn clear(world: &World, node: &FakeNode, id: &str) -> Reply {
    send(
        world,
        node,
        Role::Ops,
        LineRequest::AbuseClear { user: user(id) },
    )
}

fn in_kernel(world: &World, id: &str) -> bool {
    world
        .net
        .cut
        .borrow()
        .contains(&user_source(&user(id)).to_string())
}

#[test]
fn the_operator_cuts_a_served_user_at_once_and_once() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(NOW);
    let Ok(Response::AbuseCutDone { record, cuts }) = cut(&world, &node, "u01") else {
        panic!("not cut");
    };
    assert_eq!(record, AbuseSeq::FIRST);
    assert_eq!(cuts.get(&user("u01")).unwrap().since.as_secs(), NOW);
    assert!(in_kernel(&world, "u01"));
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(state.records().len(), 1);
    assert_eq!(state.records()[0].action, AbuseAction::OperatorCut);
    assert_eq!(state.records()[0].figures, None);
    // Again: the first cut stands, and nothing more is recorded.
    let later = world.node(NOW + 60);
    let Ok(Response::AbuseCutDone { record, .. }) = cut(&world, &later, "u01") else {
        panic!("not answered");
    };
    assert_eq!(record, AbuseSeq::FIRST);
    assert_eq!(AbuseState::read(&world.paths).unwrap().records().len(), 1);
}

#[test]
fn a_cut_is_refused_without_the_guard_or_for_a_user_not_served() {
    let world = World::new();
    let node = world.node(NOW);
    assert_eq!(
        cut(&world, &node, "u01"),
        Err(AgentError::AbuseGuardNotInstalled)
    );
    world.install_before_guard(1, TxnState::Committed);
    assert_eq!(
        cut(&world, &node, "u01"),
        Err(AgentError::AbuseGuardNotInstalled)
    );
    world.install(2, TxnState::Committed);
    assert_eq!(
        cut(&world, &node, "u09"),
        Err(AgentError::AbuseUserNotServed { user: user("u09") })
    );
    assert_eq!(AbuseState::read(&world.paths).unwrap(), AbuseState::empty());
    assert!(world.net.cut.borrow().is_empty());
    assert!(
        node.calls().iter().all(|call| !call.contains("abuse_cut")),
        "{:#?}",
        node.calls()
    );
}

/// nft refusing the change is reported, and the state holds the cut, which
/// the watch applies at its next re-read.
#[test]
fn a_cut_nft_refuses_is_recorded_and_reported() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    world.net.cut_fails.set(true);
    let node = world.node(NOW);
    let Err(AgentError::AbuseSetFailed { stderr_tail }) = cut(&world, &node, "u01") else {
        panic!("not refused");
    };
    assert!(stderr_tail.as_str().contains("Operation not permitted"));
    let state = AbuseState::read(&world.paths).unwrap();
    assert!(state.cuts().get(&user("u01")).is_some());
    assert!(!in_kernel(&world, "u01"));
}

#[test]
fn the_operator_lifts_a_cut_at_once_with_a_record() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(NOW);
    assert_eq!(
        clear(&world, &node, "u01"),
        Ok(Response::AbuseCleared {
            record: None,
            cuts: mooring_agent_proto::AbuseCuts::EMPTY,
        }),
        "not cut: nothing recorded"
    );
    assert!(AbuseState::read(&world.paths).unwrap().records().is_empty());
    cut(&world, &node, "u01").unwrap();
    let Ok(Response::AbuseCleared { record, cuts }) = clear(&world, &world.node(NOW + 30), "u01")
    else {
        panic!("not lifted");
    };
    assert_eq!(record, Some(AbuseSeq::new(1)));
    assert!(cuts.is_empty());
    assert!(!in_kernel(&world, "u01"));
    let state = AbuseState::read(&world.paths).unwrap();
    assert_eq!(state.records()[1].action, AbuseAction::Cleared);
    assert_eq!(state.records()[1].at.as_secs(), NOW + 30);
}

/// A generation rendered before the guard has no cut set: the lift is
/// recorded and nft is not asked.
#[test]
fn a_lift_on_a_generation_before_the_guard_changes_the_state_only() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(NOW);
    cut(&world, &node, "u01").unwrap();
    world.install_before_guard(2, TxnState::Committed);
    let lifting = world.node(NOW + 10);
    let Ok(Response::AbuseCleared { record, .. }) = clear(&world, &lifting, "u01") else {
        panic!("not lifted");
    };
    assert_eq!(record, Some(AbuseSeq::new(1)));
    assert!(lifting.calls().iter().all(|call| !call.contains("nft")));
    world.net.cut_fails.set(true);
    world.install(3, TxnState::Committed);
    cut(&world, &world.node(NOW + 20), "u01").unwrap_err();
    let Err(AgentError::AbuseSetFailed { .. }) = clear(&world, &world.node(NOW + 30), "u01") else {
        panic!("nft's refusal not reported");
    };
    assert!(
        AbuseState::read(&world.paths).unwrap().cuts().is_empty(),
        "the lift is recorded all the same"
    );
}

/// The records page answers both roles that may read it.
#[test]
fn the_ops_and_viewer_roles_read_the_records() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(NOW);
    cut(&world, &node, "u01").unwrap();
    for role in [Role::Ops, Role::Viewer] {
        let Ok(Response::AbuseRecords(page)) = send(
            &world,
            &node,
            role,
            LineRequest::AbuseRecords {
                since: AbuseSeq::FIRST,
            },
        ) else {
            panic!("no page");
        };
        assert_eq!(page.records().len(), 1);
        assert_eq!(page.cuts().len(), 1);
        assert_eq!(page.end(), AbuseSeq::new(1));
    }
    let Ok(Response::AbuseRecords(page)) = send(
        &world,
        &node,
        Role::Ops,
        LineRequest::AbuseRecords {
            since: AbuseSeq::new(1),
        },
    ) else {
        panic!("no page");
    };
    assert!(page.records().is_empty());
    std::fs::write(world.paths.abuse_state(), "garbled").unwrap();
    assert!(matches!(
        send(
            &world,
            &node,
            Role::Viewer,
            LineRequest::AbuseRecords {
                since: AbuseSeq::FIRST
            }
        ),
        Err(AgentError::Io { .. })
    ));
}
