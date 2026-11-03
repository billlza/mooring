// SPDX-License-Identifier: GPL-3.0-or-later

//! A viewer's stop and the Mac's drain hold (design §11.3): a stop recorded
//! as an Operator hold, and confirmed to the viewer only once the watch's
//! view shows it; a drain hold cleared once the Mac handshakes anew and
//! sends, and kept while WireGuard cannot be read; and the writes that fail
//! on the way, which keep the gate closed and record a stop once.

use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
use std::time::Duration;

use mooring_agent_proto::{
    AgentError, AgentEventKind, GateReason, GateState, Holds, MacDrainHold, OperatorHold, TxnState,
    UnixTime, WatchError, WatchErrorKind,
};

use super::world::{World, tick};
use crate::gate::{StopRequest, holds, set_by_viewer, write_holds};
use crate::host::Node;
use crate::store::{read_json, write_json};
use crate::tests::{EACCES, EEXIST, FakeNode, ModeFault, occupy_temporary};
use crate::watch::{self, Watch};

#[test]
fn a_viewer_stop_is_recorded_by_the_watch_and_confirmed_to_the_viewer() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let watch_node = world.node(20_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&watch_node, 1);
    tick(&mut watch, &world, &watch_node);
    world.traffic(&watch_node, 1);
    tick(&mut watch, &world, &watch_node);
    assert!(!world.net.closed.get());
    let paths = world.paths.clone();
    let shared = Rc::new(RefCell::new((watch, watch_node)));
    let ticking = Rc::clone(&shared);
    let net = Rc::clone(&world.net);
    let viewer = FakeNode::new(20_010).on_sleep(move |slept| {
        if slept == 3 {
            let (watch, node) = &mut *ticking.borrow_mut();
            node.sleep(Duration::from_secs(3));
            net.rx.set(net.rx.get() + 1);
            watch.tick(&paths, node).unwrap();
        }
    });
    let held = set_by_viewer(&world.paths, &viewer).unwrap();
    assert_eq!(viewer.slept(), 3);
    assert_eq!(
        held.operator,
        Some(OperatorHold {
            at: UnixTime::from_secs(20_013)
        })
    );
    assert!(viewer.calls().is_empty(), "the viewer ran nothing itself");
    assert!(world.net.closed.get());
    assert!(!world.paths.stop_request().exists());
    // A request left behind (its removal failed) after its hold was
    // recorded is only removed, not recorded again.
    write_json(
        &world.paths.stop_request(),
        &StopRequest {
            at: UnixTime::from_secs(20_010),
        },
        0o660,
    )
    .unwrap();
    {
        let (watch, node) = &mut *shared.borrow_mut();
        node.sleep(Duration::from_secs(5));
        watch.tick(&world.paths, node).unwrap();
    }
    assert!(!world.paths.stop_request().exists());
    assert_eq!(
        holds(&world.paths).unwrap().operator,
        Some(OperatorHold {
            at: UnixTime::from_secs(20_013)
        })
    );
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::GateOpened,
            AgentEventKind::HoldRecorded {
                hold: GateReason::Operator
            },
            AgentEventKind::GateClosed,
        ]
    );
}

#[test]
fn a_viewer_stop_is_unconfirmed_while_the_watch_view_predates_it() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let watch_node = world.node(30_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &watch_node);
    // An operator hold recorded after the view, as by a hung watch's
    // predecessor: the view is older than the request.
    write_holds(
        &world.paths,
        &Holds {
            operator: Some(OperatorHold {
                at: UnixTime::from_secs(30_100),
            }),
            ..Holds::NONE
        },
    )
    .unwrap();
    let viewer = FakeNode::new(30_100);
    assert_eq!(
        set_by_viewer(&world.paths, &viewer),
        Err(AgentError::GateStopUnconfirmed {
            waited_secs: mooring_agent_proto::VIEWER_STOP_WAIT_SECS
        })
    );
    let request: StopRequest = read_json(&world.paths.stop_request()).unwrap().unwrap();
    assert_eq!(request.at, UnixTime::from_secs(30_100));
}

#[test]
fn a_viewer_stop_is_unconfirmed_while_the_view_shows_the_gate_open() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(170_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    write_holds(
        &world.paths,
        &Holds {
            operator: Some(OperatorHold {
                at: UnixTime::from_secs(170_100),
            }),
            ..Holds::NONE
        },
    )
    .unwrap();
    let mut view = world.status();
    view.at = UnixTime::from_secs(170_100);
    view.observed.gate = GateState::Open;
    watch::status::write(&world.paths, &view).unwrap();
    assert_eq!(
        set_by_viewer(&world.paths, &FakeNode::new(170_100)),
        Err(AgentError::GateStopUnconfirmed {
            waited_secs: mooring_agent_proto::VIEWER_STOP_WAIT_SECS
        })
    );
}

#[test]
fn a_stop_whose_hold_cannot_be_written_keeps_the_gate_closed() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(40_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(!world.net.closed.get());
    write_json(
        &world.paths.stop_request(),
        &StopRequest {
            at: UnixTime::from_secs(40_010),
        },
        0o660,
    )
    .unwrap();
    // The atomic write's temporary name is taken, so the hold cannot be
    // written while holds.json reads as before.
    let blocker = occupy_temporary(&world.paths.holds());
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(
        world.net.closed.get(),
        "closed while the stop is unrecorded"
    );
    assert_eq!(holds(&world.paths).unwrap(), Holds::NONE);
    assert!(
        world.paths.stop_request().exists(),
        "kept for the next tick"
    );
    assert_eq!(
        world
            .status()
            .observed
            .conditions
            .get(WatchErrorKind::StateWrite),
        Some(&WatchError::StateWrite { errno: Some(17) })
    );
    fs::remove_dir(&blocker).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(
        holds(&world.paths).unwrap().operator,
        Some(OperatorHold {
            at: UnixTime::from_secs(40_015)
        })
    );
    assert!(!world.paths.stop_request().exists());
    assert!(world.net.closed.get());
}

#[test]
fn a_stop_whose_request_cannot_be_removed_is_recorded_once_and_reported() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(40_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert!(!world.net.closed.get());
    write_json(
        &world.paths.stop_request(),
        &StopRequest {
            at: UnixTime::from_secs(40_010),
        },
        0o660,
    )
    .unwrap();
    {
        // The request can be read, but not removed.
        let _kept = ModeFault::set(&world.paths.stop_dir(), 0o500);
        for _ in 0..2 {
            world.traffic(&node, 1);
            tick(&mut watch, &world, &node);
        }
        assert!(world.net.closed.get());
        assert_eq!(
            world
                .status()
                .observed
                .conditions
                .get(WatchErrorKind::StateWrite),
            Some(&WatchError::StateWrite {
                errno: Some(EACCES)
            })
        );
    }
    assert!(world.paths.stop_request().exists());
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(!world.paths.stop_request().exists());
    assert_eq!(
        holds(&world.paths).unwrap().operator,
        Some(OperatorHold {
            at: UnixTime::from_secs(40_010)
        }),
        "recorded at the first tick, and not again"
    );
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::GateOpened,
            AgentEventKind::HoldRecorded {
                hold: GateReason::Operator
            },
            AgentEventKind::ConditionRaised {
                condition: WatchError::StateWrite {
                    errno: Some(EACCES)
                }
            },
            AgentEventKind::GateClosed,
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::StateWrite
            },
        ]
    );
}

#[test]
fn a_drain_hold_clears_once_the_mac_handshakes_anew_and_sends() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(50_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    let drain = |handshake: u64| {
        write_holds(
            &world.paths,
            &Holds {
                mac_drain: Some(MacDrainHold {
                    handshake_at_drain: Some(UnixTime::from_secs(handshake)),
                }),
                ..Holds::NONE
            },
        )
        .unwrap();
    };
    drain(world.net.handshake.get());
    tick(&mut watch, &world, &node);
    world.net.handshake.set(node.now().as_secs());
    tick(&mut watch, &world, &node);
    assert!(
        holds(&world.paths).unwrap().mac_drain.is_some(),
        "a new handshake without new rx does not clear it"
    );
    world.net.rx.set(world.net.rx.get() + 10);
    tick(&mut watch, &world, &node);
    assert_eq!(holds(&world.paths).unwrap(), Holds::NONE);
    assert!(!world.net.closed.get(), "reopened in the same tick");

    drain(world.net.handshake.get());
    tick(&mut watch, &world, &node);
    world.net.rx.set(world.net.rx.get() + 10);
    tick(&mut watch, &world, &node);
    world.net.rx.set(world.net.rx.get() + 10);
    tick(&mut watch, &world, &node);
    assert!(
        holds(&world.paths).unwrap().mac_drain.is_some(),
        "rx alone does not clear it"
    );
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::HoldRecorded {
                hold: GateReason::MacDrain
            },
            AgentEventKind::HoldCleared {
                hold: GateReason::MacDrain
            },
            AgentEventKind::GateOpened,
            AgentEventKind::HoldRecorded {
                hold: GateReason::MacDrain
            },
            AgentEventKind::GateClosed,
        ]
    );
}

#[test]
fn a_watch_that_first_sees_a_drain_hold_after_the_new_handshake_still_waits_for_rx() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(55_000);
    world.traffic(&node, 1);
    write_holds(
        &world.paths,
        &Holds {
            mac_drain: Some(MacDrainHold {
                handshake_at_drain: Some(UnixTime::from_secs(world.net.handshake.get())),
            }),
            ..Holds::NONE
        },
    )
    .unwrap();
    // The Mac came back while no watch was running.
    node.sleep(Duration::from_secs(30));
    world.traffic(&node, 10);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    world.net.handshake.set(node.now().as_secs());
    tick(&mut watch, &world, &node);
    assert!(
        holds(&world.paths).unwrap().mac_drain.is_some(),
        "rx from before the watch saw the hold does not clear it"
    );
    world.net.rx.set(world.net.rx.get() + 1);
    tick(&mut watch, &world, &node);
    assert_eq!(holds(&world.paths).unwrap(), Holds::NONE);
}

#[test]
fn a_drain_hold_that_cannot_be_cleared_keeps_the_gate_closed_until_it_is() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(50_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    write_holds(
        &world.paths,
        &Holds {
            mac_drain: Some(MacDrainHold {
                handshake_at_drain: Some(UnixTime::from_secs(50_000)),
            }),
            ..Holds::NONE
        },
    )
    .unwrap();
    // The watch first sees the hold, and the rx it began from.
    tick(&mut watch, &world, &node);
    let blocker = occupy_temporary(&world.paths.holds());
    // A new handshake and new rx: the hold has cleared, but cannot be
    // written as cleared.
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(holds(&world.paths).unwrap().mac_drain.is_some());
    assert!(world.net.closed.get(), "closed while the hold stands");
    assert_eq!(
        world
            .status()
            .observed
            .conditions
            .get(WatchErrorKind::StateWrite),
        Some(&WatchError::StateWrite {
            errno: Some(EEXIST)
        })
    );
    fs::remove_dir(&blocker).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(holds(&world.paths).unwrap(), Holds::NONE);
    assert!(!world.net.closed.get());
    assert!(world.conditions().is_empty());
}

#[test]
fn a_drain_hold_stands_while_wireguard_cannot_be_read() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(55_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    let held = Holds {
        mac_drain: Some(MacDrainHold {
            handshake_at_drain: Some(UnixTime::from_secs(55_000)),
        }),
        ..Holds::NONE
    };
    write_holds(&world.paths, &held).unwrap();
    tick(&mut watch, &world, &node);
    world.net.wg_fails.set(true);
    for _ in 0..3 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert_eq!(
        holds(&world.paths).unwrap(),
        held,
        "a peer that cannot be read has not come back"
    );
    assert!(world.net.closed.get());
    world.net.wg_fails.set(false);
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(holds(&world.paths).unwrap(), Holds::NONE);
}
