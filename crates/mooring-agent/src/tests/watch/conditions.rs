// SPDX-License-Identifier: GPL-3.0-or-later

//! The conditions a tick raises (design §11.3): MacSilent after 600 s unless
//! an Operator hold explains it, the host's figures read every minute, the
//! exit flow cap hit, the hourly target check's TargetDegraded, and its
//! result that cannot be read, TargetReadFailed.

use std::fs;

use mooring_agent_proto::{
    AgentEventKind, GateReason, GateState, TargetHost, TxnState, UnixTime, WatchError,
    WatchErrorKind, WatchTarget,
};

use super::world::{OCT_8, World, tick};
use crate::host::Node;
use crate::store::write_json;
use crate::tests::EISDIR;
use crate::watch::{HOST_READING_SECS, Watch};

#[test]
fn mac_silent_is_raised_after_600_s_unless_an_operator_hold_explains_it() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(70_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::MacSilent],
        "no handshake has ever completed"
    );
    world.traffic(&node, 1);
    let handshake = world.net.handshake.get();
    tick(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    while node.now().as_secs() - handshake <= 600 {
        tick(&mut watch, &world, &node);
        assert!(world.conditions().is_empty(), "at {}", node.now().as_secs());
    }
    tick(&mut watch, &world, &node);
    assert_eq!(
        world
            .status()
            .observed
            .conditions
            .get(WatchErrorKind::MacSilent),
        Some(&WatchError::MacSilent {
            since: Some(UnixTime::from_secs(handshake))
        })
    );
    // WireGuard unreadable: the handshake is unknown, the condition stays.
    world.net.wg_fails.set(true);
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::WgReadFailed, WatchErrorKind::MacSilent]
    );
    crate::gate::set_by_ops(&world.paths, &node, GateReason::Operator).unwrap();
    tick(&mut watch, &world, &node);
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::WgReadFailed],
        "an operator hold suppresses it, the handshake unknown or not"
    );
    world.net.wg_fails.set(false);
    tick(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
}

#[test]
fn the_host_is_read_every_minute_and_raises_its_conditions() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    world.traffic(&world.node(80_000), 1);
    let node = world.node(80_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    let host = world.status().host;
    assert_eq!(host.health.uptime_secs, 350_735);
    assert_eq!(host.health.load_milli, 520);
    assert_eq!(host.health.mem_available_bytes, 1_500_000 * 1024);
    assert_eq!(host.health.disk_free_bytes, 2_000_000 * 4096);
    assert_eq!(host.disk_total_bytes, 2_500_000 * 4096);
    assert!(host.health.ntp_synced);
    assert!(!host.health.reboot_required);
    assert_eq!(host.health.last_unattended_upgrade, None);
    assert_eq!(host.health.journal_bytes, 0, "no persistent journal");
    assert!(world.conditions().is_empty());

    // Under 10 % free is low, here with far more than 1 GiB free.
    *world.net.stat.borrow_mut() = "2249999 4096 22500000".to_owned();
    *world.net.chrony.borrow_mut() = None;
    world.write("/run/reboot-required", "*** System restart required ***\n");
    world.write("/var/log/journal/abc/system.journal", "0123456789");
    world.write("/var/log/journal/abc/user-1000.journal", "01234");
    world.write("/var/big", &"x".repeat(1000));
    std::os::unix::fs::symlink(
        world.paths.at("/var/big"),
        world.paths.at("/var/log/journal/abc/link"),
    )
    .unwrap();
    world.write(
        "/var/log/unattended-upgrades/unattended-upgrades-dpkg.log",
        "Log started\n",
    );
    for _ in 0..11 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
        assert!(world.conditions().is_empty(), "read only every 60 s");
    }
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    let status = world.status();
    assert_eq!(
        world.conditions(),
        vec![
            WatchErrorKind::DiskLow,
            WatchErrorKind::ClockUnsynced,
            WatchErrorKind::RebootPending,
        ]
    );
    assert_eq!(
        status.observed.conditions.get(WatchErrorKind::DiskLow),
        Some(&WatchError::DiskLow {
            free: 2_249_999 * 4096
        })
    );
    assert_eq!(status.host.health.journal_bytes, 15);
    assert!(status.host.health.reboot_required);
    assert!(status.host.reboot_required_since.is_some());
    assert!(status.host.health.last_unattended_upgrade.is_some());

    *world.net.stat.borrow_mut() = "2250000 4096 22500000".to_owned();
    *world.net.chrony.borrow_mut() = Some("Leap status     : Not synchronised\n".to_owned());
    for _ in 0..12 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::ClockUnsynced, WatchErrorKind::RebootPending],
        "exactly 10 % free is not low"
    );
    // Under 1 GiB free is low whatever the share.
    *world.net.stat.borrow_mut() = "262143 4096 300000".to_owned();
    for _ in 0..12 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert!(world.conditions().contains(&WatchErrorKind::DiskLow));
}

#[test]
fn rejected_flows_raise_exit_flow_cap_hit_with_the_count() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(90_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.net.flow_cap.set(1);
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(
        world
            .status()
            .observed
            .conditions
            .get(WatchErrorKind::ExitFlowCapHit),
        Some(&WatchError::ExitFlowCapHit { count: 1 }),
        "one rejected flow raises it"
    );
    world.net.flow_cap.set(0);
    for _ in 0..HOST_READING_SECS / 5 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
    }
    assert!(
        world.conditions().is_empty(),
        "cleared when the counter resets"
    );
}

#[test]
fn the_hourly_target_check_raises_target_degraded_for_the_configured_target_only() {
    use crate::target::hourly::TargetReading;
    let world = World::new();
    let reading = |ipv4: &str, degraded: bool| TargetReading {
        at: UnixTime::from_secs(OCT_8),
        target: WatchTarget {
            host: TargetHost::new("www.example.com").unwrap(),
            ipv4: ipv4.parse().unwrap(),
        },
        degraded,
    };
    // Before the first Apply a reading means nothing.
    write_json(
        &world.paths.target_reading(),
        &reading("198.51.100.7", true),
        0o640,
    )
    .unwrap();
    let node = world.node(OCT_8);
    let mut watch = Watch::start(&world.paths).unwrap();
    let degraded = |world: &World| world.conditions().contains(&WatchErrorKind::TargetDegraded);
    tick(&mut watch, &world, &node);
    assert!(!degraded(&world));
    world.install(1, TxnState::Committed);
    tick(&mut watch, &world, &node);
    assert!(degraded(&world));
    // A result about another target than the configured one says nothing.
    write_json(
        &world.paths.target_reading(),
        &reading("198.51.100.8", true),
        0o640,
    )
    .unwrap();
    tick(&mut watch, &world, &node);
    assert!(!degraded(&world));
    write_json(
        &world.paths.target_reading(),
        &reading("198.51.100.7", true),
        0o640,
    )
    .unwrap();
    tick(&mut watch, &world, &node);
    write_json(
        &world.paths.target_reading(),
        &reading("198.51.100.7", false),
        0o640,
    )
    .unwrap();
    tick(&mut watch, &world, &node);
    assert!(!degraded(&world));
    let raised = AgentEventKind::ConditionRaised {
        condition: WatchError::TargetDegraded,
    };
    let cleared = AgentEventKind::ConditionCleared {
        condition: WatchErrorKind::TargetDegraded,
    };
    let target_events: Vec<AgentEventKind> = world
        .events()
        .into_iter()
        .filter(|event| *event == raised || *event == cleared)
        .collect();
    assert_eq!(target_events, vec![raised, cleared, raised, cleared]);
}

/// A result of the hourly target check that the watch cannot read is
/// reported at every tick (`TargetReadFailed`): with the OS error, or
/// without one for a file that holds no result this agent reads, and
/// never as `TargetDegraded` or as nothing. The watch goes on, its gate
/// opening as before, and the condition clears once the result can be
/// read again (2026-11-03: the tick ended the watch with `Fatal::Reading`).
#[test]
fn a_target_result_the_watch_cannot_read_is_reported_and_the_watch_goes_on() {
    use crate::target::hourly::TargetReading;
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    let mut watch = Watch::start(&world.paths).unwrap();
    let target = |world: &World| {
        let conditions = world.status().observed.conditions;
        [
            WatchErrorKind::TargetReadFailed,
            WatchErrorKind::TargetDegraded,
        ]
        .map(|kind| conditions.get(kind).copied())
    };
    let unreadable = |errno| [Some(WatchError::TargetReadFailed { errno }), None];
    // A directory where the result belongs: reading it is EISDIR.
    fs::create_dir_all(world.paths.target_reading()).unwrap();
    for _ in 0..2 {
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
        assert_eq!(target(&world), unreadable(Some(EISDIR)));
    }
    assert_eq!(
        world.status().observed.gate,
        GateState::Open,
        "the watch gates as before"
    );
    // A file that holds no result this agent reads: garbled, or a result
    // with a field it does not know, as another agent's could be.
    let result = TargetReading {
        at: UnixTime::from_secs(OCT_8),
        target: WatchTarget {
            host: TargetHost::new("www.example.com").unwrap(),
            ipv4: "198.51.100.7".parse().unwrap(),
        },
        degraded: true,
    };
    let mut unknown = serde_json::to_value(&result).unwrap();
    unknown["checked_by"] = serde_json::json!(2);
    fs::remove_dir(world.paths.target_reading()).unwrap();
    for text in ["garbled".to_owned(), unknown.to_string()] {
        fs::write(world.paths.target_reading(), &text).unwrap();
        world.traffic(&node, 1);
        tick(&mut watch, &world, &node);
        assert_eq!(target(&world), unreadable(None), "{text}");
        assert_eq!(world.status().observed.gate, GateState::Open);
    }
    // Readable again: its verdict, and no news once it is gone.
    write_json(&world.paths.target_reading(), &result, 0o640).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(target(&world), [None, Some(WatchError::TargetDegraded)]);
    fs::remove_file(world.paths.target_reading()).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert_eq!(target(&world), [None, None]);
    // Raised once: a change in its errno is no event.
    let target_events: Vec<AgentEventKind> = world
        .events()
        .into_iter()
        .filter(|event| match event {
            AgentEventKind::ConditionRaised { condition } => matches!(
                condition,
                WatchError::TargetReadFailed { .. } | WatchError::TargetDegraded
            ),
            AgentEventKind::ConditionCleared { condition } => matches!(
                condition,
                WatchErrorKind::TargetReadFailed | WatchErrorKind::TargetDegraded
            ),
            _ => false,
        })
        .collect();
    assert_eq!(
        target_events,
        vec![
            AgentEventKind::ConditionRaised {
                condition: WatchError::TargetReadFailed {
                    errno: Some(EISDIR)
                }
            },
            AgentEventKind::ConditionRaised {
                condition: WatchError::TargetDegraded
            },
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::TargetReadFailed
            },
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::TargetDegraded
            },
        ]
    );
}
