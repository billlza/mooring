// SPDX-License-Identifier: GPL-3.0-or-later

//! Faults the watch lives through (design §11.3): a state write, a journal
//! append or a poll of Xray that fails is reported and taken again at a
//! later tick, and none of them opens the gate.

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    AgentEventKind, EngineRun, GateReason, Holds, MacDrainHold, OperatorHold, Traffic, TxnState,
    UnixTime, WatchError, WatchErrorKind,
};

use super::world::{BOOT_SECS, OCT_8, World, email, minute, tick};
use crate::gate::{StopRequest, holds, write_holds};
use crate::journal::{Journal, RETENTION_SECS};
use crate::store::write_json;
use crate::tests::{EACCES, EEXIST, EISDIR, ModeFault, occupy_temporary};
use crate::watch::Watch;

#[test]
fn a_change_journaled_while_the_journal_cannot_be_pruned_is_recorded_once() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    // An event so old that the next append prunes it.
    Journal::open(&world.paths)
        .unwrap()
        .append(UnixTime::from_secs(1_000), &[AgentEventKind::HostBooted])
        .unwrap();
    let node = world.node(1_001 + RETENTION_SECS);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    let blocker = occupy_temporary(&world.paths.journal());
    for _ in 0..3 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert!(
        !world.net.closed.get(),
        "the gate does not depend on the journal"
    );
    assert_eq!(world.conditions(), vec![WatchErrorKind::StateWrite]);
    fs::remove_dir(&blocker).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::ConditionRaised {
                condition: WatchError::StateWrite {
                    errno: Some(EEXIST)
                }
            },
            AgentEventKind::GateOpened,
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::StateWrite
            },
        ],
        "each change once, and the expired event pruned"
    );
}

#[test]
fn a_journal_that_failed_an_append_is_reopened_and_what_it_tore_cut_off() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(140_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert_eq!(world.events(), vec![AgentEventKind::GateOpened]);
    // A directory stands where the journal was opened, so the next append
    // fails.
    let aside = world.paths.watch_dir().join("journal.aside");
    fs::rename(world.paths.journal(), &aside).unwrap();
    fs::create_dir(world.paths.journal()).unwrap();
    world.net.wg_fails.set(true);
    tick(&mut watch, &world, &node);
    // The journal is back, with a line a failed append left torn.
    fs::remove_dir(world.paths.journal()).unwrap();
    let mut torn = fs::read(&aside).unwrap();
    torn.extend_from_slice(br#"{"seq":1,"at":140010,"ki"#);
    fs::write(world.paths.journal(), torn).unwrap();
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::GateOpened,
            AgentEventKind::ConditionRaised {
                condition: WatchError::WgReadFailed
            },
            AgentEventKind::ConditionRaised {
                condition: WatchError::StateWrite {
                    errno: Some(EISDIR)
                }
            },
            AgentEventKind::GateClosed,
        ]
    );
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
fn a_poll_whose_counters_cannot_be_read_is_stats_query_failed() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.xray().counters = BTreeMap::from([("u01@reality", (1, 1))]);
    minute(&mut watch, &world, &node);
    // `statssys` answers, `statsquery` does not.
    world.xray().query_fails = true;
    world.xray().counters = BTreeMap::from([("u01@reality", (9, 9))]);
    minute(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::StatsQueryFailed]);
    assert_eq!(
        world.status().accounting.at,
        Some(UnixTime::from_secs(OCT_8)),
        "the poll before"
    );
    assert_eq!(
        world.status().engines.xray.run,
        EngineRun::Active {
            uptime_secs: BOOT_SECS - 100,
            go_heap_bytes: None
        }
    );
    world.xray().query_fails = false;
    minute(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    assert_eq!(
        world.usage(&node),
        BTreeMap::from([(
            email("u01@reality"),
            Traffic {
                uplink: 8,
                downlink: 8
            }
        )])
    );
}
