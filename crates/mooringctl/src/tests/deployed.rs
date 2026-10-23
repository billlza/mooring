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

use mooring_agent_proto::{AgentError, Holds, RequestKind, Response};
use mooring_daemon_core::alert::MacEngine;
use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::control::{DaemonReply, decode_reply};
use mooring_daemon_core::status::{DownReason, ExitState};
use mooring_macsys::{Interface, InterfaceAddrV4};
use mooring_model::Sha256Digest;
use mooring_model::secret::SecretEntry;
use mooring_model::verdict::Violation;
use mooring_store::{
    LATCH_FILE, SIM_METER_FILE, STATUS_SNAPSHOT_FILE, SecretStore, Store, USAGE_DIRECTORY,
    read_latch,
};

use super::runtime::STAND_IN;
use super::support::{Answered, Expected, ExpectedRemote, Harness, PINNED, lo0};
use super::user::{fixture, harness_with, store};
use crate::daemon::deployed::{Deployed, ENGINES_DIRECTORY};
use crate::daemon::hub::Hub;
use crate::daemon::{Control, RunPaths};
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::runtime::ports::{ENGINE_PID_FILE, EXIT_ENGINE};

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
    let engine = harness
        .support_dir()
        .join(ENGINES_DIRECTORY)
        .join(EXIT_ENGINE);
    fs::create_dir_all(engine.parent().unwrap()).unwrap();
    fs::write(&engine, STAND_IN).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
    harness.mac_pins = vec![(
        EXIT_ENGINE,
        Sha256Digest::of(STAND_IN.as_bytes()).to_string(),
    )];
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
        let ran = support.join(ENGINES_DIRECTORY).join("darwin-arm64/ran");
        let started = std::time::Instant::now();
        while !ran.exists() {
            assert!(started.elapsed().as_secs() < 5);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let config = fs::read_to_string(&ran).unwrap();
        assert!(config.starts_with('{'), "{config:.40}");
        assert!(config.contains("\"lo0\""), "the egress binding");
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
        assert_eq!(published(&control).parts().exit.engines.exit.pid, None);
        String::from_utf8(log.clone()).unwrap()
    });
    assert!(log.contains("mooringctl daemon: exit: Starting\n"), "{log}");
    assert!(log.contains("mooringctl daemon: exit: Disabled\n"), "{log}");
    // The meter is written when it stops.
    assert!(support.join(USAGE_DIRECTORY).join(SIM_METER_FILE).exists());
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
