// SPDX-License-Identifier: GPL-3.0-or-later

//! What the watch journals (design §15.7): commits, boots, halts and engine
//! restarts from what it sees, causes before effects, and the first tick's
//! conditions; a change the journal cannot take, or cannot prune for,
//! recorded once it can, and only once; and a journal that failed an append
//! reopened, with what it tore cut off.

use std::fs;

use mooring_agent_proto::{
    AgentEventKind, EngineUser, EventSeq, GateReason, Generation, Halt, OperatorHold,
    ShutdownReason, TxnState, UnixTime, WatchError, WatchErrorKind,
};

use super::world::{OCT_8, World, halt, minute, tick};
use crate::journal::{self, Journal, RETENTION_SECS};
use crate::tests::{EEXIST, EISDIR, occupy_temporary};
use crate::watch::Watch;
use crate::watch::journaling::changes;

#[test]
fn commits_boots_and_halts_are_journaled_from_what_the_watch_sees() {
    let world = World::new();
    halt(&world.paths, 1);
    world.install(1, TxnState::Committed);
    let node = world.node(130_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(
        world.events().is_empty(),
        "the first tick is the baseline: {:?}",
        world.events()
    );
    world.install(2, TxnState::AwaitingConfirm);
    tick(&mut watch, &world, &node);
    assert!(
        world.events().is_empty(),
        "a generation awaiting its confirmation is not committed: {:?}",
        world.events()
    );
    assert_eq!(world.status().observed.committed, Some(Generation::new(1)));
    world.record(2, TxnState::Committed);
    tick(&mut watch, &world, &node);
    // A rollback to generation 1 commits nothing new.
    world.install(1, TxnState::Committed);
    tick(&mut watch, &world, &node);
    fs::remove_file(world.paths.halted()).unwrap();
    tick(&mut watch, &world, &node);
    // A reboot, then the restarted watch.
    world.write("/proc/sys/kernel/random/boot_id", "a-new-boot\n");
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::Committed {
                generation: Generation::new(2)
            },
            AgentEventKind::Resumed {
                generation: Generation::new(1)
            },
            AgentEventKind::HostBooted,
        ]
    );
    let page = journal::page(&world.paths, EventSeq::new(1)).unwrap();
    assert_eq!(page.end(), EventSeq::new(3));
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.seq)
            .collect::<Vec<_>>(),
        vec![EventSeq::new(1), EventSeq::new(2)]
    );
    assert!(
        journal::page(&world.paths, EventSeq::new(3))
            .unwrap()
            .events()
            .is_empty()
    );
}

#[test]
fn a_change_the_journal_cannot_take_is_recorded_once_it_can() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(140_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    // The journal cannot be appended to: a directory stands in its place.
    fs::create_dir_all(world.paths.journal()).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(
        !world.net.closed.get(),
        "the gate does not depend on the journal"
    );
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::StateWrite]);
    fs::remove_dir(world.paths.journal()).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::ConditionRaised {
                condition: WatchError::StateWrite { errno: Some(21) }
            },
            AgentEventKind::GateOpened,
        ],
        "the opening is recorded late, not lost"
    );
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
}

#[test]
fn the_changes_of_an_observation_come_causes_first() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(150_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    let before = world.status().observed;
    let mut after = before.clone();
    after.boot_id = "another".to_owned();
    after.halted = Some(Halt {
        at: UnixTime::from_secs(1),
        reason: ShutdownReason::Retire,
    });
    after.holds.operator = Some(OperatorHold {
        at: UnixTime::from_secs(2),
    });
    after.committed = Some(Generation::new(1));
    after.conditions =
        mooring_agent_proto::WatchConditions::new([WatchError::ClockUnsynced]).unwrap();
    assert_eq!(
        changes(&before, &after),
        vec![
            AgentEventKind::HostBooted,
            AgentEventKind::Halted {
                reason: ShutdownReason::Retire
            },
            AgentEventKind::HoldRecorded {
                hold: GateReason::Operator
            },
            AgentEventKind::ConditionRaised {
                condition: WatchError::ClockUnsynced
            },
        ],
        "generation 1 was committed already"
    );
    let mut again = after.clone();
    again.holds.operator = Some(OperatorHold {
        at: UnixTime::from_secs(3),
    });
    assert_eq!(
        changes(&after, &again),
        vec![AgentEventKind::HoldRecorded {
            hold: GateReason::Operator
        }],
        "a hold recorded again is a new recording"
    );
}

#[test]
fn the_first_tick_journals_its_conditions_and_what_it_does_to_the_gate() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    // Found open: a watch that was killed before its `ExecStopPost`.
    world.net.closed.set(false);
    let node = world.node(160_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    assert!(world.net.closed.get());
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::ConditionRaised {
                condition: WatchError::MacSilent { since: None }
            },
            AgentEventKind::GateClosed,
        ]
    );
}

#[test]
fn engine_restarts_are_journaled_when_systemd_counts_more() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    minute(&mut watch, &world, &node);
    world.xray().restarts = 2;
    world.net.hy2_restarts.set(1);
    minute(&mut watch, &world, &node);
    assert_eq!(world.status().engines.xray.restarts, 2);
    // An explicit restart sets `NRestarts` back to zero.
    world.xray().restarts = 0;
    minute(&mut watch, &world, &node);
    world.xray().restarts = 1;
    minute(&mut watch, &world, &node);
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::EngineRestarted {
                engine: EngineUser::Xray
            },
            AgentEventKind::EngineRestarted {
                engine: EngineUser::Hy2
            },
            AgentEventKind::EngineRestarted {
                engine: EngineUser::Xray
            },
        ]
    );
}

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
