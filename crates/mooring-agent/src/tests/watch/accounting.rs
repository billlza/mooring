// SPDX-License-Identifier: GPL-3.0-or-later

//! What the watch counts at its readings (design §11.3 step 4, §11.5): the
//! users' traffic polled from Xray's API and dated for the applied emails;
//! a poll that fails, or that Xray restarted during, taken again; the
//! canary, the usage files' writes and their retention; and the uplink's
//! transfer over the month.

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    AgentEventKind, EngineHealth, EngineRun, EngineState, Inbound, InboundSet, Traffic, TxnState,
    UnixTime, UplinkTransfer, UsageMonth, WatchError, WatchErrorKind,
};

use super::world::{BOOT_SECS, NOV, OCT_8, World, email, minute};
use crate::host::Node;
use crate::tests::occupy_temporary;
use crate::watch::Watch;

#[test]
fn accounting_polls_at_each_reading_and_dates_growth_for_applied_emails() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.xray().counters = BTreeMap::from([("u01@reality", (1, 1))]);
    minute(&mut watch, &world, &node);
    assert_eq!(
        world.status().accounting.at,
        Some(UnixTime::from_secs(OCT_8))
    );
    assert!(
        world.status().accounting.last_active.is_empty(),
        "a baseline"
    );
    let polled = node.now();
    world.xray().counters = BTreeMap::from([
        ("u01@reality", (5, 50)),
        ("u02@reality", (2, 2)),
        ("probe@hy2", (0, 15)),
    ]);
    minute(&mut watch, &world, &node);
    let view = world.status();
    assert_eq!(view.accounting.at, Some(polled));
    assert_eq!(
        view.accounting.last_active,
        BTreeMap::from([(email("probe@hy2"), polled), (email("u01@reality"), polled)]),
        "u02 is not in the applied configuration"
    );
    let traffic = |up, down| Traffic {
        uplink: up,
        downlink: down,
    };
    assert_eq!(
        world.usage(&node),
        BTreeMap::from([
            (email("probe@hy2"), traffic(0, 15)),
            (email("u01@reality"), traffic(4, 49)),
            (email("u02@reality"), traffic(2, 2)),
        ]),
        "the month counts whatever Xray counted"
    );
    assert_eq!(
        view.engines,
        EngineHealth {
            xray: EngineState {
                restarts: 0,
                run: EngineRun::Active {
                    uptime_secs: BOOT_SECS - 100,
                    go_heap_bytes: Some(52_000_000),
                },
            },
            hy2: EngineState {
                restarts: 0,
                run: EngineRun::Active {
                    uptime_secs: BOOT_SECS - 90,
                    go_heap_bytes: None,
                },
            },
        }
    );
    // A revoked user leaves the configuration, and its time goes with it.
    world.applied(1, &["probe@reality", "probe@hy2"]);
    minute(&mut watch, &world, &node);
    assert_eq!(
        world.status().accounting.last_active,
        BTreeMap::from([(email("probe@hy2"), polled)])
    );
    assert!(world.events().is_empty(), "{:?}", world.events());
}

#[test]
fn xray_api_failures_raise_stats_query_failed_until_a_poll_succeeds() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    minute(&mut watch, &world, &node);
    world.xray().api_fails = true;
    minute(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::StatsQueryFailed]);
    assert_eq!(
        world.status().engines.xray.run,
        EngineRun::Active {
            uptime_secs: BOOT_SECS - 100,
            go_heap_bytes: None
        }
    );
    assert_eq!(
        world.status().accounting.at,
        Some(UnixTime::from_secs(OCT_8)),
        "the latest poll that recorded"
    );
    // A stopped Xray is not asked (a halted node stops it on purpose).
    world.xray().active_since = None;
    minute(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    assert_eq!(world.status().engines.xray.run, EngineRun::Inactive);
    world.xray().active_since = Some(400);
    minute(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::StatsQueryFailed]);
    world.xray().api_fails = false;
    minute(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    let raised = AgentEventKind::ConditionRaised {
        condition: WatchError::StatsQueryFailed,
    };
    let cleared = AgentEventKind::ConditionCleared {
        condition: WatchErrorKind::StatsQueryFailed,
    };
    assert_eq!(world.events(), vec![raised, cleared, raised, cleared]);
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

#[test]
fn uncounted_probe_flows_raise_the_canary_until_a_probe_counter_exists() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.xray().counters = BTreeMap::from([("u01@reality", (1, 1))]);
    minute(&mut watch, &world, &node);
    world.net.probe_flows.set(3);
    minute(&mut watch, &world, &node);
    let both = InboundSet::of(Inbound::Reality).with(Inbound::Hy2);
    assert_eq!(
        world
            .status()
            .observed
            .conditions
            .get(WatchErrorKind::AccountingCanaryMissing),
        Some(&WatchError::AccountingCanaryMissing { inbounds: both })
    );
    minute(&mut watch, &world, &node);
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::AccountingCanaryMissing],
        "kept without new evidence"
    );
    world.xray().counters.insert("probe@reality", (0, 15));
    minute(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::ConditionRaised {
                condition: WatchError::AccountingCanaryMissing { inbounds: both }
            },
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::AccountingCanaryMissing
            },
        ]
    );
}

#[test]
fn a_poll_xray_restarted_during_is_taken_again_at_the_next_reading() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.xray().counters = BTreeMap::from([("u01@reality", (10, 10))]);
    minute(&mut watch, &world, &node);
    // The counters come from the run before; the second `statssys` from
    // the new one.
    world.xray().counters = BTreeMap::from([("u01@reality", (20, 20))]);
    world.xray().restart_after_query = Some((5_000, BTreeMap::from([("u01@reality", (3, 3))])));
    minute(&mut watch, &world, &node);
    assert_eq!(
        world.status().accounting.at,
        Some(UnixTime::from_secs(OCT_8))
    );
    assert!(world.conditions().is_empty());
    world.xray().counters = BTreeMap::from([("u01@reality", (7, 7))]);
    minute(&mut watch, &world, &node);
    assert_eq!(
        world.usage(&node),
        BTreeMap::from([(
            email("u01@reality"),
            Traffic {
                uplink: 7,
                downlink: 7
            }
        )]),
        "only the new run's counters"
    );
}

#[test]
fn a_usage_file_that_cannot_be_written_is_state_write_until_a_reading_writes_it() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(OCT_8);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    minute(&mut watch, &world, &node);
    let blocker = occupy_temporary(&world.paths.accounting());
    world.xray().counters = BTreeMap::from([("u01@reality", (5, 5))]);
    minute(&mut watch, &world, &node);
    assert_eq!(world.conditions(), vec![WatchErrorKind::StateWrite]);
    assert_eq!(
        world.status().accounting.at,
        Some(UnixTime::from_secs(OCT_8))
    );
    fs::remove_dir(&blocker).unwrap();
    minute(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    assert_eq!(
        world.usage(&node),
        BTreeMap::from([(
            email("u01@reality"),
            Traffic {
                uplink: 5,
                downlink: 5
            }
        )]),
        "nothing lost: the poll counts from the last one written"
    );
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::ConditionRaised {
                condition: WatchError::StateWrite { errno: Some(17) }
            },
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::StateWrite
            },
        ],
        "raised for the whole minute, once"
    );
}

#[test]
fn retention_runs_even_while_xray_is_stopped() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    world.xray().active_since = None;
    let august = world.paths.usage_month(UsageMonth::new(2026, 8).unwrap());
    let september = world.paths.usage_month(UsageMonth::new(2026, 9).unwrap());
    for (file, month) in [(&august, "2026-08"), (&september, "2026-09")] {
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(
            file,
            format!(
                r#"{{"usage":{{"month":"{month}","updated_at":1,"traffic":{{}}}},"poll":{{"at":1,"seq":1}}}}"#
            ),
        )
        .unwrap();
    }
    // A second before September's seven days end.
    let node = world.node(OCT_8 - 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    minute(&mut watch, &world, &node);
    assert!(!august.exists(), "seven days after August ended");
    assert!(september.exists(), "kept until its seven days end");
}

#[test]
fn the_uplink_transfer_counts_its_month_across_resets() {
    let world = World::new();
    let node = world.node(NOV - 180);
    let mut watch = Watch::start(&world.paths).unwrap();
    let transfer = |world: &World| world.status().transfer.reported;
    let october = UsageMonth::new(2026, 10).unwrap();
    minute(&mut watch, &world, &node);
    assert_eq!(
        transfer(&world),
        UplinkTransfer {
            month: october,
            counted_from: UnixTime::from_secs(NOV - 180),
            rx_bytes: 0,
            tx_bytes: 0,
            counter_resets: 0,
        }
    );
    world.uplink(1_500, 2_100);
    minute(&mut watch, &world, &node);
    // A reboot whose counters already passed the last reading.
    world.write("/proc/sys/kernel/random/boot_id", "a-new-boot\n");
    world.uplink(1_600, 2_200);
    minute(&mut watch, &world, &node);
    assert_eq!(
        transfer(&world),
        UplinkTransfer {
            month: october,
            counted_from: UnixTime::from_secs(NOV - 180),
            rx_bytes: 500 + 1_600,
            tx_bytes: 100 + 2_200,
            counter_resets: 1,
        }
    );
    minute(&mut watch, &world, &node);
    let november = UplinkTransfer {
        month: UsageMonth::new(2026, 11).unwrap(),
        counted_from: UnixTime::from_secs(NOV),
        rx_bytes: 0,
        tx_bytes: 0,
        counter_resets: 0,
    };
    assert_eq!(
        transfer(&world),
        november,
        "a month counts from its first reading"
    );
    world.uplink(1_700, 2_300);
    minute(&mut watch, &world, &node);
    // Only rx below the last reading: a reset all the same.
    world.uplink(50, 2_400);
    minute(&mut watch, &world, &node);
    assert_eq!(
        transfer(&world),
        UplinkTransfer {
            rx_bytes: 100 + 50,
            tx_bytes: 100 + 2_400,
            counter_resets: 1,
            ..november
        }
    );
}
