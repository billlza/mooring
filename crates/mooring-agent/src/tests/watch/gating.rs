// SPDX-License-Identifier: GPL-3.0-or-later

//! The gate each tick sets (design §11.3): open only for a live peer,
//! with a fresh handshake and growing rx, no hold and no halt; a gate closed
//! behind the watch's back found at the next re-read; closed while WireGuard
//! cannot be read; and none to set before the first generation.

use std::fs;

use mooring_agent_proto::{
    AgentEventKind, GateReason, GateState, Generation, Holds, OperatorHold, ShutdownReason,
    TxnState, UnixTime, WatchError, WatchErrorKind,
};

use super::world::{World, halt, tick};
use crate::gate::write_holds;
use crate::host::Node;
use crate::tests::FakeNode;
use crate::watch::Watch;

#[test]
fn the_gate_opens_only_for_a_live_peer_with_no_hold_and_no_halt() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(10_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 100);
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.status().observed.gate,
        GateState::Closed,
        "the first reading shows no growth yet"
    );
    world.traffic(&node, 100);
    tick(&mut watch, &world, &node);
    assert!(!world.net.closed.get());
    assert_eq!(world.status().observed.gate, GateState::Open);
    assert_eq!(world.events(), vec![AgentEventKind::GateOpened]);

    write_holds(
        &world.paths,
        &Holds {
            operator: Some(OperatorHold {
                at: UnixTime::from_secs(10_010),
            }),
            ..Holds::NONE
        },
    )
    .unwrap();
    world.traffic(&node, 100);
    tick(&mut watch, &world, &node);
    assert!(world.net.closed.get(), "a hold closes the gate");
    crate::gate::clear(&world.paths, mooring_agent_proto::ClearableHold::Operator).unwrap();
    world.traffic(&node, 100);
    tick(&mut watch, &world, &node);
    assert!(!world.net.closed.get());

    halt(&world.paths, 10_020);
    world.traffic(&node, 100);
    tick(&mut watch, &world, &node);
    assert!(world.net.closed.get(), "a halt closes the gate");
    fs::remove_file(world.paths.halted()).unwrap();
    world.traffic(&node, 100);
    tick(&mut watch, &world, &node);
    assert!(!world.net.closed.get());

    // The handshake ages past 180 s while rx keeps growing.
    let handshake = world.net.handshake.get();
    for _ in 0..36 {
        world.net.rx.set(world.net.rx.get() + 1);
        tick(&mut watch, &world, &node);
        assert!(!world.net.closed.get(), "at {}", node.now().as_secs());
    }
    world.net.rx.set(world.net.rx.get() + 1);
    tick(&mut watch, &world, &node);
    assert_eq!(node.now().as_secs() - 5 - handshake, 185);
    assert!(
        world.net.closed.get(),
        "a handshake over 180 s old closes it"
    );

    // A fresh handshake, then rx stops growing for over three keepalives.
    world.traffic(&node, 100);
    tick(&mut watch, &world, &node);
    assert!(!world.net.closed.get());
    for _ in 0..6 {
        world.net.handshake.set(node.now().as_secs());
        tick(&mut watch, &world, &node);
    }
    assert!(!world.net.closed.get(), "rx grew 30 s ago");
    world.net.handshake.set(node.now().as_secs());
    tick(&mut watch, &world, &node);
    assert!(world.net.closed.get(), "no rx growth within 30 s closes it");

    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::GateOpened,
            AgentEventKind::HoldRecorded {
                hold: GateReason::Operator
            },
            AgentEventKind::GateClosed,
            AgentEventKind::HoldCleared {
                hold: GateReason::Operator
            },
            AgentEventKind::GateOpened,
            AgentEventKind::Halted {
                reason: ShutdownReason::Operator
            },
            AgentEventKind::GateClosed,
            AgentEventKind::Resumed {
                generation: Generation::new(1)
            },
            AgentEventKind::GateOpened,
            AgentEventKind::GateClosed,
            AgentEventKind::GateOpened,
            AgentEventKind::GateClosed,
        ]
    );
}

#[test]
fn a_gate_closed_behind_the_watch_is_found_at_the_next_reread() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(10_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(!world.net.closed.get());
    // A transaction's `nft -f` reloads the set closed.
    world.net.closed.set(true);
    let reread = |node: &FakeNode| {
        node.calls()
            .iter()
            .filter(|call| call.contains("list set"))
            .count()
    };
    let before = reread(&node);
    for _ in 0..10 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert_eq!(reread(&node), before, "no re-read within 60 s");
    assert!(world.net.closed.get(), "the gate stays closed until then");
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(reread(&node), before + 1);
    assert!(!world.net.closed.get(), "reopened after the re-read");
    assert_eq!(
        world.events(),
        vec![AgentEventKind::GateOpened],
        "the watch's view never saw it closed"
    );
}

#[test]
fn wireguard_that_cannot_be_read_closes_the_gate() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(60_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(!world.net.closed.get());
    world.net.wg_fails.set(true);
    tick(&mut watch, &world, &node);
    assert!(world.net.closed.get());
    assert_eq!(world.conditions(), vec![WatchErrorKind::WgReadFailed]);
    assert_eq!(world.status().latest_handshake, None);
    world.net.wg_fails.set(false);
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::GateOpened,
            AgentEventKind::ConditionRaised {
                condition: WatchError::WgReadFailed
            },
            AgentEventKind::GateClosed,
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::WgReadFailed
            },
            AgentEventKind::GateOpened,
        ]
    );
}

#[test]
fn with_no_generation_the_watch_touches_neither_wireguard_nor_nft() {
    let world = World::new();
    let node = world.node(120_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    *world.net.chrony.borrow_mut() = None;
    tick(&mut watch, &world, &node);
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("/usr/bin/wg ") && !call.contains("/usr/sbin/nft ")),
        "{:#?}",
        node.calls()
    );
    let status = world.status();
    assert_eq!(status.observed.gate, GateState::Closed);
    assert_eq!(status.observed.generation, Generation::ZERO);
    assert_eq!(world.conditions(), vec![WatchErrorKind::ClockUnsynced]);
}
