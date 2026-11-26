// SPDX-License-Identifier: GPL-3.0-or-later

//! What ends the watch (design §11.3): a view it cannot read at start, a
//! reading it needs, and `nft` failing or printing what nft never prints,
//! which it records first where it can. `run` ends with exit status 1 and
//! the cause on stderr; its unit restarts it.

use std::fs;
use std::io;
use std::process::ExitCode;
use std::rc::Rc;
use std::time::Duration;

use mooring_agent_proto::{
    AgentError, AgentEventKind, GateState, IoOp, TxnState, UnixTime, WatchError, WatchErrorKind,
};

use super::world::{World, tick};
use crate::host::{Node, Tool, ToolOutput};
use crate::store::malformed;
use crate::tests::{EEXIST, ENOENT, FakeNode, failed, occupy_temporary, ok};
use crate::watch::{self, Fatal, Watch};

/// How `run` reports `nft -j list set` failing on the stand-in node.
const NFT_FAILED: &str = "mooring-agent: nft failed: nft -j list set inet mooring exit_closed failed: netlink: Error: Operation not permitted\n";

/// The watch run on `node` until it ends: its exit status and its stderr.
fn run(world: &World, node: &FakeNode) -> (ExitCode, String) {
    let mut stderr = Vec::new();
    let code = watch::run(&world.paths, node, &mut stderr);
    (code, String::from_utf8(stderr).unwrap())
}

/// A node at `now` for a run that must end at its first tick: a sleep,
/// which comes before a second tick, fails the test rather than let the
/// watch run on.
fn first_tick_only(world: &World, now: u64) -> FakeNode {
    world
        .node(now)
        .on_sleep(|_| panic!("the watch went on to a second tick"))
}

/// Ticks of generation 1, with the peer sending, on a node whose tools
/// answer as `first` says where it says anything, until one ends the
/// watch (at most three): the world and what ended it.
fn ticks_until_fatal(
    first: impl Fn(Tool, &[&str]) -> Option<io::Result<ToolOutput>> + 'static,
) -> (World, Fatal) {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node_answering(1_000, first);
    let mut watch = Watch::start(&world.paths).unwrap();
    for _ in 0..3 {
        world.traffic(&node, 1);
        match watch.tick(&world.paths, &node) {
            Ok(()) => node.sleep(Duration::from_secs(5)),
            Err(fatal) => return (world, fatal),
        }
    }
    panic!("no tick ended the watch");
}

/// Whether `args` are nft's for `list <kind> inet mooring <name>`.
fn lists(args: &[&str], kind: &str, name: &str) -> bool {
    args == ["-j", "list", kind, "inet", "mooring", name]
}

#[test]
fn a_watch_whose_view_cannot_be_read_does_not_start() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    world.write("/var/lib/mooring/watch/status.json", "garbled");
    let node = first_tick_only(&world, 1_000);
    assert_eq!(
        run(&world, &node),
        (
            ExitCode::from(1),
            format!(
                "mooring-agent: the watch cannot start: {}\n",
                malformed(IoOp::ReadState)
            )
        )
    );
    assert!(node.calls().is_empty());
    assert_eq!(node.slept(), 0);
}

#[test]
fn a_reading_the_watch_needs_ends_it_with_its_cause() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    fs::remove_file(world.paths.proc_sys("kernel/random/boot_id")).unwrap();
    let node = first_tick_only(&world, 1_000);
    let missing = AgentError::Io {
        op: IoOp::ReadState,
        errno: Some(ENOENT),
    };
    assert_eq!(
        run(&world, &node),
        (
            ExitCode::from(1),
            format!("mooring-agent: a reading the watch needs failed: {missing}\n")
        )
    );
    assert!(node.calls().is_empty(), "the boot id is read first");
    assert!(!world.paths.watch_status().exists());
    // An empty boot id is no reading either.
    world.write("/proc/sys/kernel/random/boot_id", "\n");
    let mut watch = Watch::start(&world.paths).unwrap();
    assert_eq!(
        watch.tick(&world.paths, &node),
        Err(Fatal::Reading(malformed(IoOp::ReadState)))
    );
}

#[test]
fn a_clock_past_the_last_month_ends_the_watch() {
    let world = World::new();
    // 10000-01-01T00:00:00Z: the uplink's transfer has no month to count in.
    let node = world.node(253_402_300_800);
    let mut watch = Watch::start(&world.paths).unwrap();
    assert_eq!(
        watch.tick(&world.paths, &node),
        Err(Fatal::Reading(malformed(IoOp::ReadState)))
    );
    assert!(!world.paths.watch_status().exists());
}

#[test]
fn an_nft_failure_before_any_view_ends_the_watch_recording_nothing() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    world.net.nft_fails.set(true);
    let node = first_tick_only(&world, 1_000);
    assert_eq!(
        run(&world, &node),
        (ExitCode::from(1), NFT_FAILED.to_owned())
    );
    assert_eq!(
        node.calls(),
        [
            "/usr/bin/wg show wgexit dump",
            "/usr/sbin/nft -j list set inet mooring exit_closed",
        ]
    );
    assert!(!world.paths.watch_status().exists());
    assert!(!world.paths.journal().exists());
}

#[test]
fn an_nft_failure_whose_view_cannot_be_written_reports_both() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(1_000);
    world.traffic(&node, 1);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    let view = world.status();
    world.net.nft_fails.set(true);
    let blocker = occupy_temporary(&world.paths.watch_status());
    let refused = AgentError::Io {
        op: IoOp::WriteState,
        errno: Some(EEXIST),
    };
    assert_eq!(
        run(&world, &first_tick_only(&world, 1_005)),
        (
            ExitCode::from(1),
            format!("mooring-agent: recording NftFailed failed: {refused}\n{NFT_FAILED}")
        )
    );
    fs::remove_dir(&blocker).unwrap();
    assert_eq!(world.status(), view, "the view as it was");
    assert_eq!(
        world.events(),
        vec![AgentEventKind::ConditionRaised {
            condition: WatchError::NftFailed
        }],
        "the journal took it"
    );
}

#[test]
fn a_watch_restarted_while_nft_fails_records_nft_failed_once() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    // No handshake has completed: the view holds MacSilent.
    let node = world.node(1_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    tick(&mut watch, &world, &node);
    world.net.nft_fails.set(true);
    assert_eq!(
        run(&world, &first_tick_only(&world, 2_000)),
        (ExitCode::from(1), NFT_FAILED.to_owned())
    );
    // Restarted by its unit, with nft failing still.
    assert_eq!(
        run(&world, &first_tick_only(&world, 3_000)),
        (ExitCode::from(1), NFT_FAILED.to_owned())
    );
    assert_eq!(world.status().at, UnixTime::from_secs(3_000));
    assert_eq!(
        world.conditions(),
        vec![WatchErrorKind::NftFailed, WatchErrorKind::MacSilent]
    );
    assert_eq!(
        world.events(),
        vec![
            AgentEventKind::ConditionRaised {
                condition: WatchError::MacSilent { since: None }
            },
            AgentEventKind::ConditionRaised {
                condition: WatchError::NftFailed
            },
        ]
    );
}

#[test]
fn a_gate_set_listed_as_nft_never_prints_it_ends_the_watch() {
    let (world, fatal) = ticks_until_fatal(|tool, args| {
        (tool == Tool::Nft && lists(args, "set", "exit_closed")).then(|| Ok(ok(b"garbled")))
    });
    assert_eq!(fatal, Fatal::Nft(malformed(IoOp::ReadState).to_string()));
    assert!(!world.paths.watch_status().exists());
}

#[test]
fn nft_that_cannot_be_started_ends_the_watch_naming_the_command() {
    let (_world, fatal) = ticks_until_fatal(|tool, _| {
        (tool == Tool::Nft).then(|| Err(io::Error::from_raw_os_error(ENOENT)))
    });
    let spawn = AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: Some(ENOENT),
    };
    assert_eq!(
        fatal,
        Fatal::Nft(format!("nft -j list set inet mooring exit_closed: {spawn}"))
    );
}

#[test]
fn a_counter_nft_cannot_read_ends_the_watch() {
    let (_world, fatal) = ticks_until_fatal(|tool, args| {
        (tool == Tool::Nft && lists(args, "counter", "flow_cap")).then(|| Ok(ok(b"garbled")))
    });
    assert_eq!(fatal, Fatal::Nft(malformed(IoOp::ReadState).to_string()));
    let (_world, fatal) = ticks_until_fatal(|tool, args| {
        (tool == Tool::Nft && lists(args, "counter", "probe_flows"))
            .then(|| Ok(failed(b"Error: No such file or directory\n")))
    });
    assert_eq!(
        fatal,
        Fatal::Nft(
            "nft -j list counter inet mooring probe_flows failed: Error: No such file or directory"
                .to_owned()
        )
    );
}

#[test]
fn an_element_nft_will_not_change_ends_the_watch_with_the_gate_as_it_was() {
    // With the abuse guard the gate opens in the command line that sets the
    // cut set; nft refusing it changes neither (one transaction).
    let (world, fatal) = ticks_until_fatal(|tool, args| {
        (tool == Tool::Nft && args.contains(&"delete")).then(|| {
            Ok(failed(
                b"Error: Could not process rule: No such file or directory\n",
            ))
        })
    });
    assert_eq!(
        fatal,
        Fatal::Nft(
            "nft flush set inet mooring abuse_cut ; delete element inet mooring exit_closed { \"wgexit\" } failed: Error: Could not process rule: No such file or directory"
                .to_owned()
        )
    );
    assert_eq!(
        world.status().observed.gate,
        GateState::Closed,
        "the view of the tick before"
    );
    // A generation rendered before the guard opens the gate alone.
    let world = World::new();
    world.install_before_guard(1, TxnState::Committed);
    let node = world.node_answering(1_000, |tool, args| {
        (tool == Tool::Nft && args.first() == Some(&"delete")).then(|| {
            Ok(failed(
                b"Error: Could not process rule: No such file or directory\n",
            ))
        })
    });
    let mut watch = Watch::start(&world.paths).unwrap();
    let fatal = (0..3)
        .find_map(|_| {
            world.traffic(&node, 1);
            let result = watch.tick(&world.paths, &node);
            node.sleep(Duration::from_secs(5));
            result.err()
        })
        .unwrap();
    assert_eq!(
        fatal,
        Fatal::Nft(
            "nft delete element inet mooring exit_closed { \"wgexit\" } failed: Error: Could not process rule: No such file or directory"
                .to_owned()
        )
    );
}

#[test]
fn an_nft_failure_ends_the_watch_with_nft_failed_recorded() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(100_000);
    world.traffic(&node, 1);
    let net = Rc::clone(&world.net);
    let node = node.on_sleep(move |slept| {
        if slept == 10 {
            net.nft_fails.set(true);
        }
        net.handshake.set(100_000 + slept);
        net.rx.set(net.rx.get() + 1);
    });
    let mut stderr = Vec::new();
    let code = watch::run(&world.paths, &node, &mut stderr);
    assert_eq!(code, ExitCode::from(1));
    let message = String::from_utf8(stderr).unwrap();
    assert!(message.contains("nft failed"), "{message}");
    assert!(message.contains("Operation not permitted"), "{message}");
    // The guard's reading, every third tick, failed first: it cannot read
    // its sets either, which it reports without touching the gate.
    assert_eq!(
        world.conditions(),
        vec![
            WatchErrorKind::NftFailed,
            WatchErrorKind::AbuseGuardUnavailable
        ]
    );
    assert_eq!(
        world.events().last(),
        Some(&AgentEventKind::ConditionRaised {
            condition: WatchError::NftFailed
        })
    );
    // `ExecStopPost` closes the gate; the restarted watch clears the
    // condition once nft works again, and journals the closing it finds.
    world.net.closed.set(true);
    world.net.nft_fails.set(false);
    let node = world.node(100_100);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    assert!(world.conditions().is_empty());
    let events = world.events();
    assert_eq!(
        events[events.len() - 3..],
        [
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::NftFailed
            },
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::AbuseGuardUnavailable
            },
            AgentEventKind::GateClosed,
        ]
    );
}

#[test]
fn a_reading_the_watch_needs_ends_it() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(110_000);
    fs::remove_file(world.paths.proc("uptime")).unwrap();
    let mut watch = Watch::start(&world.paths).unwrap();
    assert!(matches!(
        watch.tick(&world.paths, &node),
        Err(Fatal::Reading(AgentError::Io {
            op: IoOp::ReadState,
            ..
        }))
    ));
    fs::remove_file(world.paths.watch_config()).unwrap();
    assert!(matches!(
        watch.tick(&world.paths, &node),
        Err(Fatal::Reading(_))
    ));
}
