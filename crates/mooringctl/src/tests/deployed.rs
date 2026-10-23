// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon with a deployment (design §10.1, §10.2), end to end against
//! the harness: the fixture deployment, its egress on `lo0` facing the
//! pinned M7, the Keychain holding the fixture's keys, a stand-in engine
//! pinned in the support directory's `engines/`, and scripted probes and
//! node sessions. The machine's timing is `daemon-core`'s to test; these
//! check the wiring: the rendered config reaching the engine, the status
//! published and written, the latch file, the node calls, the stale
//! engine, and the refusals at start.

use std::fs;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::time::Instant;

use mooring_agent_proto::WATCH_STALE_SECS;
use mooring_agent_proto::{AgentError, Holds, RequestKind, Response};
use mooring_daemon_core::alert::MacEngine;
use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::control::{DaemonReply, decode_reply};
use mooring_daemon_core::power::HelperEvent;
use mooring_daemon_core::snapshot::NodePoll;
use mooring_daemon_core::status::{
    AgentUnreachable, DegradedReason, DownReason, DrainOutcome, ExitState, NodeAgentState,
    PowerSource,
};
use mooring_macsys::{Interface, InterfaceAddrV4};
use mooring_model::Sha256Digest;
use mooring_model::secret::SecretEntry;
use mooring_model::verdict::Violation;
use mooring_store::{
    LATCH_FILE, SIM_METER_FILE, STATUS_SNAPSHOT_FILE, SecretStore, Store, USAGE_DIRECTORY,
    read_latch,
};

use super::runtime::STAND_IN;
use super::support::{Answered, Expected, ExpectedRemote, Harness, PINNED, Sent, lo0};
use super::user::{fixture, harness_with, store};
use crate::daemon::deployed::{
    DRAIN_BUDGET, Deployed, ENGINES_DIRECTORY, budget_left, first_power_source, stale_watches,
    unreachable_cause,
};
use crate::daemon::hub::Hub;
use crate::daemon::{Control, RunPaths};
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::runtime::ports::{ENGINE_PID_FILE, EXIT_ENGINE, PROBE_ENGINE, PROBER_PID_FILE};
use crate::runtime::power::PowerMessage;

/// Inside the fixtures' carrier prefix, 31.120.0.0/14.
const CARRIER: Ipv4Addr = Ipv4Addr::new(31, 120, 5, 6);
const OUTSIDE: Ipv4Addr = Ipv4Addr::new(82, 10, 20, 30);

/// The fixture, enabled, with everything the exit needs on this Mac.
fn deployed() -> Harness {
    let mut harness = harness_with(fixture(|_| {}));
    harness.pin(PINNED);
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    for secret_ref in fixture.secrets.refs() {
        let material = fixture.secrets.material(&secret_ref).unwrap();
        harness
            .secrets
            .put(SecretEntry::new(secret_ref, material).unwrap())
            .unwrap();
    }
    // The fixture's egress selector names 02:6d:6f:6f:72:01 on
    // 192.168.1.0/24; here that interface is lo0, which faces the M7.
    harness.link.gateway = Ok(Ipv4Addr::new(192, 168, 1, 1));
    harness.link.listed = Ok(vec![Interface {
        index: NonZeroU32::from(lo0()),
        name: "lo0".to_owned(),
        link_type: 6,
        lladdr: Some([0x02, 0x6d, 0x6f, 0x6f, 0x72, 0x01]),
        up: true,
        running: true,
        mtu: 1500,
        ibytes: 0,
        obytes: 0,
        baudrate: 0,
        ipv4: vec![InterfaceAddrV4 {
            addr: Ipv4Addr::new(192, 168, 1, 20),
            prefix_len: Some(24),
        }],
    }]);
    let state = store(&harness).load().unwrap();
    store(&harness)
        .set_exit_enabled(state.runtime.revision, true)
        .unwrap();
    for name in [EXIT_ENGINE, PROBE_ENGINE] {
        let engine = harness.support_dir().join(ENGINES_DIRECTORY).join(name);
        fs::create_dir_all(engine.parent().unwrap()).unwrap();
        fs::write(&engine, STAND_IN).unwrap();
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
        harness
            .mac_pins
            .push((name, Sha256Digest::of(STAND_IN.as_bytes()).to_string()));
    }
    harness
}

fn shared() -> (Control, mpsc::Receiver<()>) {
    let (retry, retries) = mpsc::channel();
    (
        Control {
            hub: Hub::default(),
            retry,
            deployed: AtomicBool::new(true),
        },
        retries,
    )
}

/// The status the hub holds.
fn published(control: &Control) -> mooring_daemon_core::MacStatusV1 {
    let line = control.hub.latest().unwrap().unwrap().line;
    match decode_reply(&line).unwrap() {
        DaemonReply::Status(ConsoleStatus::Deployed(status)) => *status,
        other => panic!("{other:?}"),
    }
}

/// Runs `work` with a deployed exit opened on the harness.
fn with_exit<T>(
    harness: &mut Harness,
    work: impl FnOnce(&mut Deployed<'_, '_>, &mut Vec<u8>) -> T,
) -> T {
    let support = harness.support_dir();
    // `start` makes the run directory before the exit opens.
    fs::create_dir_all(RunPaths::under(&support).dir).unwrap();
    harness.with_env(|env| {
        let mut log = Vec::new();
        let mut exit = Deployed::open(env, &support, &mut log, None).unwrap();
        work(&mut exit, &mut log)
    })
}

#[test]
fn the_exit_starts_its_engine_on_the_rendered_config_and_publishes_its_status() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    let support = harness.support_dir();
    let (control, _retries) = shared();
    let log = with_exit(&mut harness, |exit, log| {
        assert_eq!(
            exit.tick(&control, log, false).unwrap(),
            ExitState::Starting
        );
        let status = published(&control);
        let parts = status.parts();
        assert_eq!(parts.exit.state, ExitState::Starting);
        assert_eq!(
            parts.exit.egress.as_ref().unwrap().interface.as_str(),
            "lo0"
        );
        assert_eq!(parts.exit.carrier_check.unwrap().egress_ip, CARRIER);
        let pid = parts.exit.engines.exit.pid.unwrap();
        let run = RunPaths::under(&support).dir;
        assert_eq!(
            fs::read_to_string(run.join(ENGINE_PID_FILE)).unwrap(),
            format!("{pid}\n")
        );
        // The engine got the rendered config on its stdin.
        let ran = support
            .join(ENGINES_DIRECTORY)
            .join("darwin-arm64/mooring-exit.ran");
        let started = Instant::now();
        while !ran.exists() {
            assert!(started.elapsed().as_secs() < 5);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let config = fs::read_to_string(&ran).unwrap();
        assert!(config.starts_with('{'), "{config:.40}");
        assert!(config.contains("\"lo0\""), "the egress binding");
        // The prober runs beside it, on its own config.
        let prober = parts.exit.engines.probe.pid.unwrap();
        assert_eq!(
            fs::read_to_string(run.join(PROBER_PID_FILE)).unwrap(),
            format!("{prober}\n")
        );
        // The status is written too.
        assert!(support.join(STATUS_SNAPSHOT_FILE).exists());
        // Disabled, the engine stops and its pid file goes.
        let store = Store::new(support.clone());
        let state = store.load().unwrap();
        store
            .set_exit_enabled(state.runtime.revision, false)
            .unwrap();
        assert_eq!(
            exit.tick(&control, log, false).unwrap(),
            ExitState::Disabled
        );
        assert!(!run.join(ENGINE_PID_FILE).exists());
        assert!(!run.join(PROBER_PID_FILE).exists());
        let engines = published(&control).parts().exit.engines;
        assert_eq!((engines.exit.pid, engines.probe.pid), (None, None));
        String::from_utf8(log.clone()).unwrap()
    });
    assert!(log.contains("mooringctl daemon: exit: Starting\n"), "{log}");
    assert!(log.contains("mooringctl daemon: exit: Disabled\n"), "{log}");
    // The meter is written when it stops.
    assert!(support.join(USAGE_DIRECTORY).join(SIM_METER_FILE).exists());
}

/// The agent's `Status` reply as protocol 1 pins it, its watch fresh by
/// the node's clock.
pub(crate) fn status_reply() -> Response {
    let text = include_str!("../../../../contract/agent-proto-golden/status.response.snap");
    let line = text.lines().last().unwrap();
    serde_json::from_str::<Result<Response, AgentError>>(line)
        .unwrap()
        .unwrap()
}

/// Scripts a `Status` answer from every node (ams1, lon1).
fn statuses(harness: &Harness) {
    for _ in 0..2 {
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::Status,
            },
            Answered::Replied(Ok(status_reply())),
        );
    }
}

fn gate_closed() -> Answered {
    Answered::Replied(Ok(Response::GateClosed {
        holds: Holds {
            mac_drain: None,
            egress_violation: None,
            operator: None,
        },
    }))
}

#[test]
fn a_violation_is_latched_in_its_file_and_every_gate_is_closed() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(OUTSIDE));
    for _ in 0..2 {
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::GateSet,
            },
            gate_closed(),
        );
    }
    statuses(&harness);
    let support = harness.support_dir();
    let (control, _retries) = shared();
    let log = with_exit(&mut harness, |exit, log| {
        let state = exit.tick(&control, log, false).unwrap();
        assert_eq!(
            state,
            ExitState::Down {
                reason: DownReason::Violation(Violation::OutsideCarrierPrefixes { ip: OUTSIDE })
            }
        );
        String::from_utf8(log.clone()).unwrap()
    });
    let run = RunPaths::under(&support).dir;
    assert!(run.join(LATCH_FILE).exists());
    let latch = read_latch(&run).unwrap().unwrap();
    assert_eq!(
        latch.violation,
        Violation::OutsideCarrierPrefixes { ip: OUTSIDE }
    );
    assert!(log.contains("ams1: GateSet done"), "{log}");
    assert!(log.contains("lon1: GateSet done"), "{log}");
    assert!(harness.nodes.script.borrow().is_empty());
    // A new daemon reads the latch, stays down, and tells the nodes again.
    for _ in 0..2 {
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::GateSet,
            },
            gate_closed(),
        );
    }
    statuses(&harness);
    let (control, _retries) = shared();
    with_exit(&mut harness, |exit, log| {
        assert!(matches!(
            exit.tick(&control, log, false).unwrap(),
            ExitState::Down {
                reason: DownReason::Violation(_)
            }
        ));
    });
    assert!(harness.nodes.script.borrow().is_empty());
}

/// A gate call the agent refuses is logged and not tried again; one that
/// cannot be delivered waits for the next try.
#[test]
fn a_refused_gate_call_is_not_tried_again() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(OUTSIDE));
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::GateSet,
        },
        Answered::Replied(Err(NodeError::Agent(AgentError::TrailingInput))),
    );
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::GateSet,
        },
        Answered::Replied(Err(NodeError::Pipe)),
    );
    statuses(&harness);
    let (control, _retries) = shared();
    let log = with_exit(&mut harness, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        // Nothing is due again within the retry interval.
        exit.tick(&control, log, false).unwrap();
        String::from_utf8(log.clone()).unwrap()
    });
    assert!(log.contains("ams1: the agent refused GateSet"), "{log}");
    assert!(log.contains("lon1: GateSet not delivered"), "{log}");
    assert!(harness.nodes.script.borrow().is_empty());
}

/// The power helper (design §10.3): the daemon tells it to hold its
/// assertions while the exit is enabled on mains, and to release them on
/// battery; a sleep is drained (the engine stopped, every node's gate
/// closed for the drain, each session bounded by the drain's budget) and
/// let proceed once the paused status is published; the exit stays paused
/// until the wake.
#[test]
fn the_power_helper_holds_on_mains_and_a_sleep_is_drained_before_it_proceeds() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    for _ in 0..2 {
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::GateSet,
            },
            gate_closed(),
        );
    }
    let helper = harness.helper.handle.clone();
    let (control, _retries) = shared();
    let log = with_exit(&mut harness, |exit, log| {
        assert_eq!(
            exit.tick(&control, log, false).unwrap(),
            ExitState::Starting
        );
        assert_eq!(helper.commands(), ["{\"hold\":true}"]);
        helper.send(PowerMessage::Event(HelperEvent::Assertions { held: true }));
        exit.tick(&control, log, false).unwrap();
        assert!(published(&control).parts().exit.power.assertions_held);
        // The Mac will sleep: drained in the tick, then let proceed.
        helper.send(PowerMessage::Event(HelperEvent::WillSleep { id: 1 }));
        let asleep = Instant::now();
        assert_eq!(exit.tick(&control, log, false).unwrap(), ExitState::Paused);
        let drained = Instant::now();
        let paused = published(&control);
        let exit_section = &paused.parts().exit;
        assert_eq!(exit_section.state, ExitState::Paused);
        assert_eq!(exit_section.engines.exit.pid, None);
        let drain = exit_section.power.last_drain.unwrap();
        assert_eq!(drain.outcome, DrainOutcome::Completed);
        assert_eq!(exit_section.power.last_sleep, Some(drain.at));
        assert_eq!(
            helper.commands(),
            ["{\"hold\":true}", "{\"allow_sleep\":{\"id\":1}}"]
        );
        // Still paused until the wake: nothing starts the engine.
        assert_eq!(exit.tick(&control, log, false).unwrap(), ExitState::Paused);
        helper.send(PowerMessage::Event(HelperEvent::DidWake));
        exit.tick(&control, log, false).unwrap();
        let woken = published(&control);
        assert_ne!(woken.parts().exit.state, ExitState::Paused);
        assert!(woken.parts().exit.power.last_wake.is_some());
        // On battery the hold is released, and the exit is degraded.
        helper.send(PowerMessage::Event(HelperEvent::PowerSource(
            PowerSource::Battery,
        )));
        exit.tick(&control, log, false).unwrap();
        assert_eq!(helper.commands().last().unwrap(), "{\"hold\":false}");
        (String::from_utf8(log.clone()).unwrap(), asleep, drained)
    });
    let (log, asleep, drained) = log;
    // The drain's two sessions end by its budget; no other has a deadline.
    let seen = harness.nodes.seen.borrow();
    let deadlines: Vec<_> = seen
        .iter()
        .filter_map(|(target, sent)| match sent {
            Sent::Request(request) if request.kind() == RequestKind::GateSet => {
                Some(target.deadline.expect("a drain session has a deadline"))
            }
            _ => {
                assert_eq!(target.deadline, None, "{sent:?}");
                None
            }
        })
        .collect();
    assert_eq!(deadlines.len(), 2);
    for deadline in deadlines {
        assert!(deadline > asleep && deadline <= drained + DRAIN_BUDGET);
    }
    drop(seen);
    assert!(log.contains("ams1: GateSet done"), "{log}");
    assert!(log.contains("lon1: GateSet done"), "{log}");
    assert!(log.contains("the Mac will sleep: drain Completed"), "{log}");
    assert!(log.contains("the Mac woke"), "{log}");
    assert!(log.contains("power: Battery"), "{log}");
    assert!(harness.nodes.script.borrow().is_empty());
}

/// The drain's budget shrinks as time passes, and is none from its end on.
#[test]
fn the_drains_budget_is_what_is_left_of_it() {
    let start = Instant::now();
    let deadline = start + DRAIN_BUDGET;
    assert_eq!(budget_left(deadline, start), Some(DRAIN_BUDGET));
    assert_eq!(
        budget_left(deadline, start + std::time::Duration::from_millis(2_500)),
        Some(std::time::Duration::from_millis(1_500))
    );
    assert_eq!(budget_left(deadline, deadline), None);
    assert_eq!(
        budget_left(deadline, deadline + std::time::Duration::from_secs(1)),
        None
    );
}

/// A helper that ends degrades the exit (`PowerHelperExited`), and nothing
/// holds the Mac awake; a helper that does not start, or does not report
/// the power source in time, stops the daemon at its start.
#[test]
fn a_lost_power_helper_degrades_the_exit_and_a_missing_one_stops_the_start() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    let helper = harness.helper.handle.clone();
    let (control, _retries) = shared();
    let log = with_exit(&mut harness, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        helper.send(PowerMessage::Ended("the power helper exited".to_owned()));
        exit.tick(&control, log, false).unwrap();
        let status = published(&control);
        assert!(!status.parts().exit.power.assertions_held);
        String::from_utf8(log.clone()).unwrap()
    });
    assert!(
        log.contains("the power helper ended: the power helper exited (no process)"),
        "{log}"
    );
    assert_eq!(harness.helper.starts.get(), 1);

    let support = harness.support_dir();
    harness.helper.refuse.set(true);
    let error =
        harness.with_env(|env| Deployed::open(env, &support, &mut Vec::new(), None).unwrap_err());
    assert!(
        matches!(
            error,
            CommandError::Local(LocalError::PowerHelperSpawn { .. })
        ),
        "{error:?}"
    );
    harness.helper.refuse.set(false);
    harness.helper.silent.set(true);
    let link = harness.with_env(|env| (env.power_helper)().unwrap());
    let error = first_power_source(&link, std::time::Duration::from_millis(20)).unwrap_err();
    assert!(
        matches!(error, LocalError::PowerHelperSilent { .. }),
        "{error:?}"
    );
    harness
        .helper
        .handle
        .send(PowerMessage::Ended("gone".to_owned()));
    let error = first_power_source(&link, std::time::Duration::from_secs(5)).unwrap_err();
    assert!(
        matches!(&error, LocalError::PowerHelperEnded(text) if text == "gone"),
        "{error:?}"
    );
    // A helper whose first report is anything but the power source is
    // refused, not skipped past.
    let link = harness.with_env(|env| (env.power_helper)().unwrap());
    harness
        .helper
        .handle
        .send(PowerMessage::Event(HelperEvent::DidWake));
    let error = first_power_source(&link, std::time::Duration::from_secs(5)).unwrap_err();
    assert!(
        matches!(
            error,
            LocalError::PowerHelperFirstReport(HelperEvent::DidWake)
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the power helper's first report was DidWake, not the power source"
    );
}

#[test]
fn an_engine_that_is_missing_or_unpinned_keeps_the_exit_down() {
    for change in ["missing", "changed"] {
        let mut harness = deployed();
        harness.probes.borrow_mut().push_back(Ok(CARRIER));
        let engine = harness
            .support_dir()
            .join(ENGINES_DIRECTORY)
            .join(EXIT_ENGINE);
        if change == "missing" {
            fs::remove_file(&engine).unwrap();
        } else {
            fs::write(&engine, format!("{STAND_IN}# changed\n")).unwrap();
        }
        statuses(&harness);
        let (control, _retries) = shared();
        let log = with_exit(&mut harness, |exit, log| {
            assert_eq!(
                exit.tick(&control, log, false).unwrap(),
                ExitState::Down {
                    reason: DownReason::EngineSpawnFailed {
                        engine: MacEngine::Exit
                    }
                }
            );
            String::from_utf8(log.clone()).unwrap()
        });
        assert!(
            log.contains("is missing or does not match its pin"),
            "{change}: {log}"
        );
    }
}

#[test]
fn a_corrupt_latch_or_meter_stops_the_daemon_at_its_start() {
    for (file, kind) in [("latch", "Latch"), ("meter", "Meter")] {
        let mut harness = deployed();
        let support = harness.support_dir();
        let run = RunPaths::under(&support).dir;
        if file == "latch" {
            fs::create_dir_all(&run).unwrap();
            fs::write(run.join(LATCH_FILE), b"{}").unwrap();
        } else {
            fs::create_dir_all(support.join(USAGE_DIRECTORY)).unwrap();
            fs::write(support.join(USAGE_DIRECTORY).join(SIM_METER_FILE), b"{}").unwrap();
        }
        let error = harness
            .with_env(|env| Deployed::open(env, &support, &mut Vec::new(), None).unwrap_err());
        let found = match error {
            CommandError::Local(LocalError::Latch(_)) => "Latch",
            CommandError::Local(LocalError::Meter(_)) => "Meter",
            other => panic!("{other:?}"),
        };
        assert_eq!(found, kind);
    }
}

/// The process an earlier daemon left is the engine binary itself (a
/// script would show its interpreter), so a copy of `/bin/sleep` stands in.
#[test]
fn an_engine_an_earlier_daemon_left_is_stopped_at_the_start() {
    let mut harness = deployed();
    let support = harness.support_dir();
    let run = RunPaths::under(&support).dir;
    fs::create_dir_all(&run).unwrap();
    let engine = support.join(ENGINES_DIRECTORY).join(EXIT_ENGINE);
    fs::copy("/bin/sleep", &engine).unwrap();
    let mut left = std::process::Command::new(&engine)
        .arg("30")
        .spawn()
        .unwrap();
    fs::write(run.join(ENGINE_PID_FILE), format!("{}\n", left.id())).unwrap();
    let log = harness.with_env(|env| {
        let mut log = Vec::new();
        let _exit = Deployed::open(env, &support, &mut log, None).unwrap();
        String::from_utf8(log).unwrap()
    });
    assert!(
        log.contains(&format!(
            "stopped the engine an earlier daemon left (pid {})",
            left.id()
        )),
        "{log}"
    );
    assert_eq!(left.wait().unwrap().signal(), Some(9));
    assert!(!run.join(ENGINE_PID_FILE).exists());
}

/// The first tick polls every node: one that answers is reported, one that
/// does not is unreachable from that poll on, logged once.
#[test]
fn every_node_is_polled_and_one_that_does_not_answer_is_unreachable() {
    let mut harness = deployed();
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Status,
        },
        Answered::Replied(Ok(status_reply())),
    );
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Status,
        },
        Answered::Replied(Err(NodeError::Pipe)),
    );
    let (control, _retries) = shared();
    let log = with_exit(&mut harness, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        String::from_utf8(log.clone()).unwrap()
    });
    assert!(log.contains("lon1: poll failed: "), "{log}");
    let status = published(&control);
    let nodes = &status.parts().nodes;
    assert!(matches!(
        nodes[&mooring_model::NodeId::parse("ams1").unwrap()].agent,
        NodeAgentState::Reported(_)
    ));
    assert!(matches!(
        nodes[&mooring_model::NodeId::parse("lon1").unwrap()].agent,
        NodeAgentState::Unreachable {
            cause: AgentUnreachable::Transport,
            ..
        }
    ));
    assert!(harness.nodes.script.borrow().is_empty());
}

/// A node whose watch has not written for longer than the bound when it
/// answered is stale, by its own clock: the Mac's does not enter.
#[test]
fn a_watch_older_than_the_bound_is_stale() {
    let Response::Status(fresh) = status_reply() else {
        panic!("not a status");
    };
    let mut status = *fresh;
    let lon1 = mooring_model::NodeId::parse("lon1").unwrap();
    let poll = |status: &mooring_agent_proto::StatusV1| {
        std::collections::BTreeMap::from([(
            lon1.clone(),
            NodePoll {
                polled_at: mooring_model::UnixTime::from_secs(1),
                status: status.clone(),
            },
        )])
    };
    // The golden's watch is 3 s old.
    assert_eq!(stale_watches(&poll(&status)), []);
    let now = status.now.as_secs();
    status.watch_at = mooring_agent_proto::UnixTime::from_secs(now - WATCH_STALE_SECS);
    assert_eq!(stale_watches(&poll(&status)), []);
    status.watch_at = mooring_agent_proto::UnixTime::from_secs(now - WATCH_STALE_SECS - 1);
    assert_eq!(
        stale_watches(&poll(&status)),
        [DegradedReason::WatchStale { node: lon1.clone() }]
    );
    // A watch time after the answer cannot be judged: stale.
    status.watch_at = mooring_agent_proto::UnixTime::from_secs(now + 1);
    assert_eq!(stale_watches(&poll(&status)).len(), 1);
}

#[test]
fn every_failure_of_a_poll_has_its_cause() {
    use mooring_agent_proto::ReadError;
    for (error, cause) in [
        (
            NodeError::Spawn(std::io::Error::other("x")),
            AgentUnreachable::Spawn,
        ),
        (NodeError::Pipe, AgentUnreachable::Transport),
        (
            NodeError::Read(std::io::Error::other("x")),
            AgentUnreachable::Transport,
        ),
        (
            NodeError::Ssh {
                code: Some(255),
                stderr: String::new(),
            },
            AgentUnreachable::Transport,
        ),
        (
            NodeError::Connect(std::io::Error::other("x")),
            AgentUnreachable::Transport,
        ),
        (
            NodeError::Relay(std::io::Error::other("x")),
            AgentUnreachable::Transport,
        ),
        (NodeError::Reply(ReadError::Empty), AgentUnreachable::Decode),
        (
            NodeError::Reply(ReadError::TooLarge { limit: 1 }),
            AgentUnreachable::ResponseTooLarge,
        ),
        (
            NodeError::Agent(AgentError::TrailingInput),
            AgentUnreachable::ProtocolMismatch,
        ),
    ] {
        assert_eq!(
            unreachable_cause(&CommandError::Local(LocalError::Node(error))),
            cause
        );
    }
    assert_eq!(
        unreachable_cause(&LocalError::NodeUnreachableWithoutEgress.into()),
        AgentUnreachable::Transport
    );
}

/// The prober's probes are each node's, aimed at its reflector, on the
/// ports the exit site's probe policy gives.
#[test]
fn the_prober_s_probes_aim_at_each_node_s_reflector() {
    use mooring_daemon_core::exit::ExitPorts;

    let mut harness = deployed();
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let support = harness.support_dir();
    let targets = harness.with_env(|env| {
        let mut ports = crate::runtime::ports::DaemonPorts::new(
            env,
            RunPaths::under(&support).dir,
            support.join(ENGINES_DIRECTORY),
        );
        ports
            .render_prober(&fixture.deployment, &fixture.interfaces)
            .unwrap()
            .unwrap()
            .targets
    });
    let aimed: Vec<(String, u16, String)> = targets
        .iter()
        .map(|target| {
            (
                format!("{}-{:?}", target.node, target.protocol),
                target.port,
                target.reflector.to_string(),
            )
        })
        .collect();
    assert_eq!(
        aimed,
        [
            (
                "ams1-Reality".to_owned(),
                47101,
                "46.78.90.12:27900".to_owned()
            ),
            ("ams1-Hy2".to_owned(), 47102, "46.78.90.12:27900".to_owned()),
            (
                "lon1-Reality".to_owned(),
                47103,
                "45.67.89.10:27900".to_owned()
            ),
            ("lon1-Hy2".to_owned(), 47104, "45.67.89.10:27900".to_owned()),
        ]
    );
}
