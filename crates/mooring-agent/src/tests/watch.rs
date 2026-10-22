// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch loop (design §11.3) against a stand-in node whose WireGuard
//! peer, gate set, flow-cap counter, filesystem and chrony a test sets, and
//! the event journal it keeps (design §15.7).

use std::cell::{Cell, RefCell};
use std::fs;
use std::num::NonZeroU16;
use std::rc::Rc;
use std::time::Duration;

use mooring_agent_proto::{
    AgentError, AgentEvent, AgentEventKind, BundleFiles, BundleHeader, EngineSet, EventSeq,
    GateReason, GateState, Generation, Halt, Holds, HostProfile, IoOp, MacDrainHold, OperatorHold,
    Sha256Hex, ShutdownReason, TargetHost, TxnState, UnixTime, WatchConfig, WatchError,
    WatchErrorKind, WatchTarget,
};

use super::{FakeNode, failed, nft_set, ok, scratch};
use crate::gate::{StopRequest, holds, set_by_viewer, write_holds};
use crate::host::{Node, Tool};
use crate::journal::{self, Journal, MAX_KEPT, RETENTION_SECS};
use crate::paths::Paths;
use crate::store::{read_json, write_json};
use crate::txn::record::{TxnRecord, set_record};
use crate::watch::status::WatchStatus;
use crate::watch::{self, Fatal, HOST_READING_SECS, Watch, changes};

const BOOT: &str = "4f1b0d5e-7c39-4a8e-9a51-1c0e2b6d3f70";

/// What the stand-in node reports.
struct Net {
    /// The gate set holds `wgexit`.
    closed: Cell<bool>,
    /// The peer's latest handshake (0: none).
    handshake: Cell<u64>,
    rx: Cell<u64>,
    wg_fails: Cell<bool>,
    nft_fails: Cell<bool>,
    flow_cap: Cell<u64>,
    /// `stat -f`: available blocks, block size, total blocks.
    stat: RefCell<String>,
    /// `chronyc tracking`; `None` when chrony does not answer.
    chrony: RefCell<Option<String>>,
}

struct World {
    _dir: tempfile::TempDir,
    paths: Paths,
    net: Rc<Net>,
}

impl World {
    fn new() -> Self {
        let (dir, paths) = scratch();
        let world = Self {
            _dir: dir,
            paths,
            net: Rc::new(Net {
                closed: Cell::new(true),
                handshake: Cell::new(0),
                rx: Cell::new(0),
                wg_fails: Cell::new(false),
                nft_fails: Cell::new(false),
                flow_cap: Cell::new(0),
                stat: RefCell::new("2000000 4096 2500000".to_owned()),
                chrony: RefCell::new(Some(
                    "Reference ID    : C0A80001 (192.168.0.1)\nLeap status     : Normal\n"
                        .to_owned(),
                )),
            }),
        };
        world.write("/proc/uptime", "350735.47 234388.90\n");
        world.write("/proc/loadavg", "0.52 0.58 0.59 1/123 4567\n");
        world.write(
            "/proc/meminfo",
            "MemTotal:  2000000 kB\nMemAvailable:   1500000 kB\n",
        );
        world.write("/proc/sys/kernel/random/boot_id", &format!("{BOOT}\n"));
        world
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.paths.at(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// Installs generation `generation` with a 10 s keepalive, its record
    /// in `state`, as the current one.
    fn install(&self, generation: u64, state: TxnState) {
        let dir = self.paths.generation(Generation::new(generation));
        fs::create_dir_all(&dir).unwrap();
        let config = WatchConfig {
            keepalive_secs: NonZeroU16::new(10).unwrap(),
            target: WatchTarget {
                host: TargetHost::new("www.example.com").unwrap(),
                ipv4: "198.51.100.7".parse().unwrap(),
            },
        };
        write_json(&dir.join("watch.json"), &config, 0o640).unwrap();
        let _replaced = fs::remove_file(self.paths.current());
        std::os::unix::fs::symlink(format!("gen-{generation}"), self.paths.current()).unwrap();
        self.record(generation, state);
    }

    fn record(&self, generation: u64, state: TxnState) {
        let header = BundleHeader {
            config_generation: Generation::new(generation),
            digest: Sha256Hex::from_bytes([9; 32]),
            host_facts: super::txn::facts(),
            host_profile_version: HostProfile::CURRENT.version,
            files: BundleFiles::from_fn(|_| Sha256Hex::from_bytes([1; 32])),
            engines: EngineSet {
                xray: Sha256Hex::from_bytes([2; 32]),
                hy2: Sha256Hex::from_bytes([3; 32]),
                geoip: Sha256Hex::from_bytes([4; 32]),
                geosite: Sha256Hex::from_bytes([5; 32]),
            },
        };
        set_record(
            &self.paths,
            Generation::new(generation),
            &TxnRecord { header, state },
        )
        .unwrap();
    }

    fn node(&self, now: u64) -> FakeNode {
        let net = Rc::clone(&self.net);
        FakeNode::answering(
            now,
            Box::new(move |tool, args| {
                Ok(match (tool, args) {
                    (Tool::Nft, _) if net.nft_fails.get() => failed(b"netlink: Error: Operation not permitted\n"),
                    (Tool::Nft, ["-j", "list", "set", ..]) => ok(&nft_set(net.closed.get())),
                    (Tool::Nft, ["-j", "list", "counter", ..]) => ok(format!(
                        r#"{{"nftables":[{{"metainfo":{{"version":"1.1.3"}}}},{{"counter":{{"family":"inet","name":"flow_cap","table":"mooring","handle":4,"packets":{},"bytes":0}}}}]}}"#,
                        net.flow_cap.get()
                    ).as_bytes()),
                    (Tool::Nft, ["add", "element", ..]) => {
                        net.closed.set(true);
                        ok(b"")
                    }
                    (Tool::Nft, ["delete", "element", ..]) => {
                        net.closed.set(false);
                        ok(b"")
                    }
                    (Tool::Wg, _) if net.wg_fails.get() => failed(b"Unable to access interface: No such device\n"),
                    (Tool::Wg, ["show", "wgexit", "dump"]) => ok(format!(
                        "SECRETPRIVATEKEY=\tPUBLICKEY=\t27820\toff\nMACKEY=\t(none)\t92.40.201.7:4500\t10.66.0.2/32\t{}\t{}\t900\t10\n",
                        net.handshake.get(),
                        net.rx.get()
                    ).as_bytes()),
                    (Tool::Stat, _) => ok(net.stat.borrow().as_bytes()),
                    (Tool::Chronyc, _) => match net.chrony.borrow().as_deref() {
                        Some(report) => ok(report.as_bytes()),
                        None => failed(b"506 Cannot talk to daemon\n"),
                    },
                    _ => ok(b""),
                })
            }),
        )
    }

    fn status(&self) -> WatchStatus {
        watch::status::read(&self.paths).unwrap().unwrap()
    }

    fn conditions(&self) -> Vec<WatchErrorKind> {
        self.status()
            .observed
            .conditions
            .iter()
            .map(WatchError::kind)
            .collect()
    }

    fn events(&self) -> Vec<AgentEventKind> {
        journal::page(&self.paths, EventSeq::FIRST)
            .unwrap()
            .events()
            .iter()
            .map(|event| event.kind)
            .collect()
    }

    /// The peer handshakes at `node`'s time and sends `bytes` more.
    fn traffic(&self, node: &FakeNode, bytes: u64) {
        self.net.handshake.set(node.now().as_secs());
        self.net.rx.set(self.net.rx.get() + bytes);
    }
}

fn tick(watch: &mut Watch, world: &World, node: &FakeNode) {
    watch.tick(&world.paths, node).unwrap();
    node.sleep(Duration::from_secs(5));
}

fn halt(paths: &Paths, at: u64) {
    write_json(
        &paths.halted(),
        &Halt {
            at: UnixTime::from_secs(at),
            reason: ShutdownReason::Operator,
        },
        0o640,
    )
    .unwrap();
}

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
    let blocker = world
        .paths
        .gate_dir()
        .join(format!(".holds.json.{}.tmp", std::process::id()));
    fs::create_dir_all(&blocker).unwrap();
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
fn a_view_that_cannot_be_written_is_reported_at_the_next_tick() {
    let world = World::new();
    world.install(1, TxnState::Committed);
    let node = world.node(58_000);
    let mut watch = Watch::start(&world.paths).unwrap();
    world.traffic(&node, 1);
    tick(&mut watch, &world, &node);
    let blocker = world
        .paths
        .watch_dir()
        .join(format!(".status.json.{}.tmp", std::process::id()));
    fs::create_dir_all(&blocker).unwrap();
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
    assert_eq!(code, std::process::ExitCode::from(1));
    let message = String::from_utf8(stderr).unwrap();
    assert!(message.contains("nft failed"), "{message}");
    assert!(message.contains("Operation not permitted"), "{message}");
    assert_eq!(world.conditions(), vec![WatchErrorKind::NftFailed]);
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
        events[events.len() - 2..],
        [
            AgentEventKind::ConditionCleared {
                condition: WatchErrorKind::NftFailed
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
fn the_journal_continues_its_numbers_and_cuts_off_a_torn_line() {
    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(
            UnixTime::from_secs(5),
            &[AgentEventKind::GateOpened, AgentEventKind::GateClosed],
        )
        .unwrap();
    let mut torn = fs::read(paths.journal()).unwrap();
    torn.extend_from_slice(br#"{"seq":2,"at":6,"ki"#);
    fs::write(paths.journal(), &torn).unwrap();
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert_eq!(page.events().len(), 2, "a reader ignores the torn line");
    assert_eq!(page.end(), EventSeq::new(2));
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(UnixTime::from_secs(7), &[AgentEventKind::HostBooted])
        .unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST).unwrap().events(),
        &[
            event(0, 5, AgentEventKind::GateOpened),
            event(1, 5, AgentEventKind::GateClosed),
            event(2, 7, AgentEventKind::HostBooted),
        ]
    );
    let page = journal::page(&paths, EventSeq::new(9)).unwrap();
    assert!(page.events().is_empty());
    assert_eq!(page.end(), EventSeq::new(3));
    // A gap is refused rather than served.
    let text = fs::read_to_string(paths.journal()).unwrap();
    let gapped: String = text
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, line)| format!("{line}\n"))
        .collect();
    fs::write(paths.journal(), gapped).unwrap();
    let refused = AgentError::Io {
        op: IoOp::ReadState,
        errno: None,
    };
    assert_eq!(journal::page(&paths, EventSeq::FIRST), Err(refused.clone()));
    assert_eq!(Journal::open(&paths).unwrap_err(), refused, "nor continued");
}

#[test]
fn the_journal_is_created_empty_and_group_readable_when_opened() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, paths) = scratch();
    let _journal = Journal::open(&paths).unwrap();
    let meta = fs::metadata(paths.journal()).unwrap();
    assert_eq!(meta.len(), 0);
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert!(page.events().is_empty());
    assert_eq!(page.end(), EventSeq::FIRST);
}

fn event(seq: u64, at: u64, kind: AgentEventKind) -> AgentEvent {
    AgentEvent {
        seq: EventSeq::new(seq),
        at: UnixTime::from_secs(at),
        kind,
    }
}

#[test]
fn the_journal_keeps_thirteen_months_and_a_bounded_count() {
    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    journal
        .append(UnixTime::from_secs(1_000), &[AgentEventKind::GateOpened])
        .unwrap();
    journal
        .append(UnixTime::from_secs(2_000), &[AgentEventKind::GateClosed])
        .unwrap();
    journal
        .append(
            UnixTime::from_secs(1_000 + RETENTION_SECS),
            &[AgentEventKind::GateOpened],
        )
        .unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST)
            .unwrap()
            .events()
            .len(),
        3,
        "exactly 393 days old is kept"
    );
    journal
        .append(
            UnixTime::from_secs(1_001 + RETENTION_SECS),
            &[AgentEventKind::GateClosed],
        )
        .unwrap();
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.seq.get())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    // Long after, only the newest stays, so its number is never reused.
    journal
        .append(
            UnixTime::from_secs(10 * RETENTION_SECS),
            &[AgentEventKind::HostBooted],
        )
        .unwrap();
    let page = journal::page(&paths, EventSeq::FIRST).unwrap();
    assert_eq!(
        page.events(),
        &[event(4, 10 * RETENTION_SECS, AgentEventKind::HostBooted)]
    );
    assert_eq!(page.end(), EventSeq::new(5));

    let (_dir, paths) = scratch();
    let mut journal = Journal::open(&paths).unwrap();
    let many = vec![AgentEventKind::GateOpened; MAX_KEPT];
    journal.append(UnixTime::from_secs(5), &many).unwrap();
    assert_eq!(
        journal::page(&paths, EventSeq::FIRST).unwrap().events()[0].seq,
        EventSeq::FIRST,
        "at the bound nothing is pruned"
    );
    journal
        .append(UnixTime::from_secs(5), &[AgentEventKind::GateClosed])
        .unwrap();
    let first = journal::page(&paths, EventSeq::FIRST).unwrap().events()[0].seq;
    assert_eq!(first.get(), (MAX_KEPT + 1 - MAX_KEPT / 4 * 3) as u64);
    let text = fs::read_to_string(paths.journal()).unwrap();
    assert_eq!(text.lines().count(), MAX_KEPT / 4 * 3);
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
fn the_readings_are_parsed_exactly() {
    use crate::watch::host::{load_milli, mem_available, synchronised, uptime};
    use crate::wg::parse_dump;
    let dump = "PRIVATE=\tPUBLIC=\t27820\toff\nMAC=\t(none)\t92.40.201.7:4500\t10.66.0.2/32\t1790000000\t123\t456\t10\n";
    let peer = parse_dump(dump.as_bytes()).unwrap();
    assert_eq!(
        peer.latest_handshake,
        Some(UnixTime::from_secs(1_790_000_000))
    );
    assert_eq!(peer.rx_bytes, 123, "rx is the sixth field, not tx");
    let none = dump.replace("1790000000", "0");
    assert_eq!(parse_dump(none.as_bytes()).unwrap().latest_handshake, None);
    for bad in [
        String::new(),
        "PRIVATE=\tPUBLIC=\t27820\toff\n".to_owned(),
        dump.replace("\t123\t", "\t-1\t"),
        dump.replace("\t10\n", "\n"),
        format!("{dump}{}", dump.lines().nth(1).unwrap()),
    ] {
        assert!(parse_dump(bad.as_bytes()).is_err(), "{bad:?}");
    }

    assert_eq!(uptime("350735.47 234388.90\n").unwrap(), 350_735);
    assert_eq!(uptime("12 3\n").unwrap(), 12);
    assert!(uptime("").is_err() && uptime("soon 1\n").is_err());

    assert_eq!(load_milli("0.52 0.58 0.59 1/123 4567\n").unwrap(), 520);
    assert_eq!(load_milli("12.05 1 1\n").unwrap(), 12_050);
    assert_eq!(load_milli("3 1 1\n").unwrap(), 3_000);
    assert_eq!(load_milli("0.125 1 1\n").unwrap(), 125);
    for bad in [
        "",
        "-1.00 1 1",
        "1.2345 1 1",
        "1. 1 1",
        ".5 1 1",
        "x.50 1 1",
    ] {
        assert!(load_milli(bad).is_err(), "{bad:?}");
    }

    assert_eq!(
        mem_available("MemTotal: 9 kB\nMemFree: 1 kB\nMemAvailable:   1500 kB\n").unwrap(),
        1500 * 1024
    );
    for bad in [
        "MemTotal: 9 kB\n",
        "MemAvailable: 15 MB\n",
        "MemAvailable: lots kB\n",
    ] {
        assert!(mem_available(bad).is_err(), "{bad:?}");
    }

    for (status, synced) in [
        ("Normal", true),
        ("Insert second", true),
        ("Delete second", true),
        ("Not synchronised", false),
    ] {
        assert_eq!(
            synchronised(&format!("Reference ID : 0\nLeap status     : {status}\n")),
            synced,
            "{status}"
        );
    }
    assert!(!synchronised("Reference ID : 0\n"), "no leap status");
}

#[test]
fn disk_low_is_under_1_gib_or_under_a_tenth_free() {
    use crate::watch::host::conditions;
    use crate::watch::status::HostReading;
    let reading = |free: u64, total: u64| HostReading {
        at: UnixTime::from_secs(1),
        health: mooring_agent_proto::HostHealth {
            uptime_secs: 1,
            load_milli: 0,
            mem_available_bytes: 1,
            disk_free_bytes: free,
            journal_bytes: 0,
            reboot_required: false,
            last_unattended_upgrade: None,
            ntp_synced: true,
        },
        disk_total_bytes: total,
        reboot_required_since: None,
    };
    let gib = 1 << 30;
    assert!(
        conditions(&reading(gib, 2 * gib)).is_empty(),
        "exactly 1 GiB"
    );
    assert_eq!(
        conditions(&reading(gib - 1, 2 * gib)),
        vec![WatchError::DiskLow { free: gib - 1 }]
    );
    assert!(
        conditions(&reading(10 * gib, 100 * gib)).is_empty(),
        "exactly 10 %"
    );
    assert_eq!(
        conditions(&reading(10 * gib - 1, 100 * gib)),
        vec![WatchError::DiskLow { free: 10 * gib - 1 }]
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
