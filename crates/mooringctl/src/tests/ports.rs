// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit's ports on the Mac (design §10.1, §10.2), each called alone
//! against the deployed harness: the configs rendered from the Keychain's
//! secrets, read once per generation; the engines' check, start, end and
//! stop with their pid files; what an engine's failure is to the machine;
//! the latch file; the node calls; the in-chain probe; and an engine an
//! earlier daemon left.

use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mooring_agent_proto::{Halt, Holds, RequestKind, Response, ShutdownReason};
use mooring_daemon_core::exit::{CallFault, ExitPorts, NodeCall, RenderOutcome, StartFault};
use mooring_daemon_core::status::{ProbeStage, ProcessEnd};
use mooring_model::counters::ConfigGeneration;
use mooring_model::iface::{EgressIdentity, InterfaceSelector, MacAddr};
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::SecretRef;
use mooring_model::time::UnixTime;
use mooring_model::verdict::{LatchRecord, Violation};
use mooring_model::{NodeId, Sha256Digest};
use mooring_store::{STATE_FILE, read_latch};

use super::deployed::deployed;
use super::runtime::{STAND_IN, reflector};
use super::support::{Answered, Expected, ExpectedRemote, Harness, Refusals, Sent, lo0_name};
use super::user::fixture;
use crate::daemon::RunPaths;
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::{CommandError, LocalError};
use crate::runtime::engine::EngineError;
use crate::runtime::ports::{
    DaemonPorts, ENGINE_PID_FILE, EXIT_ENGINE, INTERACTION_NOT_ALLOWED, PROBE_ENGINE,
    PROBER_PID_FILE, end_of, start_fault, stop_stale_engine,
};

/// An engine that takes any config and, run, exits 7 at once.
const QUICK_EXIT: &str = "#!/bin/sh\ncat > /dev/null\n[ \"$1\" = run ] && exit 7\nexit 0\n";

/// An engine that refuses every config, saying why on stderr.
const REFUSING: &str =
    "#!/bin/sh\ncat > /dev/null\necho 'refused: listen port taken' >&2\nexit 3\n";

/// Writes `script` as the engine `name` in the harness's engine directory
/// and pins it there.
fn engine(harness: &mut Harness, name: &'static str, script: &str) {
    let path = harness.support_dir().join(ENGINES_DIRECTORY).join(name);
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    harness.mac_pins.retain(|(pinned, _)| *pinned != name);
    harness
        .mac_pins
        .push((name, Sha256Digest::of(script.as_bytes()).to_string()));
}

/// The run directory, which `start` makes before the exit opens.
fn run_dir(harness: &Harness) -> PathBuf {
    let run = RunPaths::under(&harness.support_dir()).dir;
    fs::create_dir_all(&run).unwrap();
    run
}

/// Runs `work` with the ports of a daemon on the harness.
fn with_ports<T>(harness: &mut Harness, work: impl FnOnce(&mut DaemonPorts<'_, '_>) -> T) -> T {
    let run = run_dir(harness);
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    harness.with_env(|env| work(&mut DaemonPorts::new(env, run, engines)))
}

/// Waits, for at most 5 s, until `seen` gives something.
fn until_some<T>(mut seen: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(found) = seen() {
            return found;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// A latch as the machine records one.
fn latch() -> LatchRecord {
    LatchRecord {
        violation: Violation::OutsideCarrierPrefixes {
            ip: Ipv4Addr::new(82, 10, 20, 30),
        },
        at: UnixTime::from_secs(1_791_919_200),
        config_generation: ConfigGeneration::new(3).unwrap(),
        egress: EgressIdentity {
            bsd_name: lo0_name(),
            lladdr: MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
        },
    }
}

/// An engine that cannot be started, that refuses its config, that does
/// not take it, or whose check does not finish is a fault the machine
/// reports, a refusal noted with what the engine said; one that cannot be
/// waited for is the daemon's own failure.
#[test]
fn an_engine_failure_is_the_machine_s_fault_unless_it_cannot_be_waited_for() {
    let mut notes = Vec::new();
    for (error, fault) in [
        (
            EngineError::Spawn {
                path: PathBuf::from("/e/mooring-exit"),
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            },
            StartFault::Spawn,
        ),
        (
            EngineError::Config(io::Error::from(io::ErrorKind::BrokenPipe)),
            StartFault::Rejected,
        ),
        (EngineError::CheckTimeout, StartFault::CheckTimedOut),
    ] {
        assert_eq!(
            start_fault("mooring-exit", error, &mut notes).unwrap(),
            fault
        );
    }
    assert_eq!(notes, ["mooring-exit did not take its config: broken pipe"]);
    for (engine, code, stderr) in [
        ("mooring-probe", Some(3), "bad port\\x1b\n"),
        ("mooring-exit", None, ""),
    ] {
        let refused = EngineError::Rejected {
            code,
            stderr: stderr.to_owned(),
        };
        assert_eq!(
            start_fault(engine, refused, &mut notes).unwrap(),
            StartFault::Rejected
        );
    }
    assert_eq!(
        notes,
        [
            "mooring-exit did not take its config: broken pipe",
            "mooring-probe refused its config (exit status 3): bad port\\x1b\n",
            "mooring-exit refused its config (exit status none): ",
        ]
    );
    let error = start_fault(
        "mooring-exit",
        EngineError::Wait(io::Error::other("no child")),
        &mut notes,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LocalError::EngineWait(source) if source.to_string() == "no child"),
        "{error:?}"
    );
    assert_eq!(notes.len(), 3);
}

/// An engine's end is its exit code or its signal; a status that is
/// neither (a stopped process, which `wait` reports only when asked to) is
/// the daemon's error.
#[test]
fn an_engine_ends_by_its_exit_or_its_signal() {
    assert_eq!(
        end_of(ExitStatus::from_raw(0)).unwrap(),
        ProcessEnd::Exited { code: 0 }
    );
    assert_eq!(
        end_of(ExitStatus::from_raw(7 << 8)).unwrap(),
        ProcessEnd::Exited { code: 7 }
    );
    assert_eq!(
        end_of(ExitStatus::from_raw(9)).unwrap(),
        ProcessEnd::Signalled { signal: 9 }
    );
    // WIFSTOPPED: 0x7f in the low byte, the signal (SIGSTOP, 17) above it.
    let error = end_of(ExitStatus::from_raw(0x117f)).unwrap_err();
    let LocalError::EngineWait(source) = &error else {
        panic!("{error:?}");
    };
    assert!(
        source
            .to_string()
            .ends_with("is neither an exit nor a signal"),
        "{source}"
    );
}

/// With no engine started, none has ended and none can be stopped; an
/// engine that ends by itself is seen once, with its exit code, and its
/// pid file goes with it. The prober's are its own.
#[test]
fn an_engine_that_ends_by_itself_is_seen_once_and_its_pid_file_goes() {
    let mut harness = deployed();
    engine(&mut harness, EXIT_ENGINE, QUICK_EXIT);
    engine(&mut harness, PROBE_ENGINE, QUICK_EXIT);
    let run = run_dir(&harness);
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    with_ports(&mut harness, |ports| {
        assert_eq!(ports.exited().unwrap(), None);
        assert_eq!(ports.prober_exited().unwrap(), None);
        for error in [ports.stop().unwrap_err(), ports.stop_prober().unwrap_err()] {
            let CommandError::Local(LocalError::EngineWait(source)) = &error else {
                panic!("{error:?}");
            };
            assert!(source.to_string().ends_with(" runs"), "{source}");
        }
        let rendered = ports
            .render(&world.deployment, &world.interfaces)
            .unwrap()
            .unwrap();
        assert_eq!(ports.check(&rendered.config).unwrap(), Ok(()));
        let pid = ports.start(&rendered.config).unwrap().unwrap();
        assert_eq!(
            fs::read_to_string(run.join(ENGINE_PID_FILE)).unwrap(),
            format!("{pid}\n")
        );
        let end = until_some(|| ports.exited().unwrap());
        assert_eq!(end, ProcessEnd::Exited { code: 7 });
        assert!(!run.join(ENGINE_PID_FILE).exists());
        assert_eq!(ports.exited().unwrap(), None);

        let prober = ports
            .render_prober(&world.deployment, &world.interfaces)
            .unwrap()
            .unwrap();
        let pid = ports.start_prober(&prober.config).unwrap().unwrap();
        assert_eq!(
            fs::read_to_string(run.join(PROBER_PID_FILE)).unwrap(),
            format!("{pid}\n")
        );
        let end = until_some(|| ports.prober_exited().unwrap());
        assert_eq!(end, ProcessEnd::Exited { code: 7 });
        assert!(!run.join(PROBER_PID_FILE).exists());
        assert!(ports.take_notes().is_empty());
    });
}

/// An engine that refuses its config is the fault `Rejected`, noted with
/// what it said; one that matches its pin but cannot be started, or that is
/// not there, is `Spawn`, which only the missing one is noted for.
#[test]
fn a_refused_unstartable_or_missing_engine_is_a_fault_with_its_note() {
    let mut harness = deployed();
    engine(&mut harness, EXIT_ENGINE, REFUSING);
    engine(&mut harness, PROBE_ENGINE, REFUSING);
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    let (exit, probe) = with_ports(&mut harness, |ports| {
        let exit = ports
            .render(&world.deployment, &world.interfaces)
            .unwrap()
            .unwrap()
            .config;
        let probe = ports
            .render_prober(&world.deployment, &world.interfaces)
            .unwrap()
            .unwrap()
            .config;
        assert_eq!(ports.check(&exit).unwrap(), Err(StartFault::Rejected));
        assert_eq!(
            ports.start_prober(&probe).unwrap(),
            Err(StartFault::Rejected)
        );
        assert_eq!(
            ports.take_notes(),
            [
                "mooring-exit refused its config (exit status 3): refused: listen port taken\n",
                "mooring-probe refused its config (exit status 3): refused: listen port taken\n",
            ]
        );
        (exit, probe)
    });
    // Pinned but not executable: it cannot be started.
    for name in [EXIT_ENGINE, PROBE_ENGINE] {
        fs::set_permissions(engines.join(name), fs::Permissions::from_mode(0o644)).unwrap();
    }
    with_ports(&mut harness, |ports| {
        assert_eq!(ports.check(&exit).unwrap(), Err(StartFault::Spawn));
        assert_eq!(ports.start(&exit).unwrap(), Err(StartFault::Spawn));
        assert_eq!(ports.start_prober(&probe).unwrap(), Err(StartFault::Spawn));
        assert!(ports.take_notes().is_empty());
    });
    for name in [EXIT_ENGINE, PROBE_ENGINE] {
        fs::remove_file(engines.join(name)).unwrap();
    }
    with_ports(&mut harness, |ports| {
        assert_eq!(ports.start(&exit).unwrap(), Err(StartFault::Spawn));
        assert_eq!(ports.start_prober(&probe).unwrap(), Err(StartFault::Spawn));
        assert_eq!(
            ports.take_notes(),
            [EXIT_ENGINE, PROBE_ENGINE].map(|name| format!(
                "{} is missing or does not match its pin",
                engines.join(name).display()
            ))
        );
    });
}

/// A pid file that cannot be written once the engine started, or removed
/// once it stopped, is the daemon's error, naming the file.
#[test]
fn a_pid_file_that_cannot_be_written_or_removed_is_the_daemon_s_error() {
    let mut harness = deployed();
    let run = run_dir(&harness);
    let pid_file = run.join(ENGINE_PID_FILE);
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    let names_the_file = |error: CommandError| {
        assert!(
            matches!(&error, CommandError::Local(LocalError::EnginePidFile { path, .. }) if *path == pid_file),
            "{error:?}"
        );
    };
    // A directory where the pid file goes.
    fs::create_dir(&pid_file).unwrap();
    with_ports(&mut harness, |ports| {
        let rendered = ports
            .render(&world.deployment, &world.interfaces)
            .unwrap()
            .unwrap();
        names_the_file(ports.start(&rendered.config).unwrap_err());
    });
    fs::remove_dir(&pid_file).unwrap();
    with_ports(&mut harness, |ports| {
        let rendered = ports
            .render(&world.deployment, &world.interfaces)
            .unwrap()
            .unwrap();
        ports.start(&rendered.config).unwrap().unwrap();
        fs::remove_file(&pid_file).unwrap();
        fs::create_dir(&pid_file).unwrap();
        names_the_file(ports.stop().unwrap_err());
    });
}

/// The Keychain is read once per configuration generation: one that
/// locks after a render does not stop the next render of that generation,
/// and is read again for the next one. While it would have to ask, nothing
/// renders and the machine says the secrets are unavailable; any other
/// refusal is the daemon's error.
#[test]
fn the_keychain_is_read_once_per_generation_and_a_locked_one_renders_nothing() {
    let mut harness = deployed();
    let keychain = Arc::clone(&harness.keychain);
    let lock = |status| {
        *keychain.lock().unwrap() = Refusals {
            get: status,
            put: None,
            delete: None,
        };
    };
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    let interfaces = &world.interfaces;
    let next = fixture(|parts| {
        parts.config_generation = parts.config_generation.next().unwrap();
    });
    with_ports(&mut harness, |ports| {
        assert!(ports.render(&world.deployment, interfaces).unwrap().is_ok());
        lock(Some(INTERACTION_NOT_ALLOWED));
        assert!(ports.render(&world.deployment, interfaces).unwrap().is_ok());
        assert!(
            ports
                .render_prober(&world.deployment, interfaces)
                .unwrap()
                .is_ok()
        );
        assert_eq!(
            ports.render(&next, interfaces).unwrap().err(),
            Some(RenderOutcome::SecretsUnavailable)
        );
        assert_eq!(
            ports.render_prober(&next, interfaces).unwrap().err(),
            Some(RenderOutcome::SecretsUnavailable)
        );
        // errSecAuthFailed: not a prompt the daemon may wait out.
        lock(Some(-25_293));
        let error = ports.render(&next, interfaces).unwrap_err();
        assert!(
            matches!(error, CommandError::Local(LocalError::ExitSecrets(_))),
            "{error:?}"
        );
    });
}

/// The fixture with its nodes adopted and none applied yet, at the
/// fixture's configuration generation.
fn adopted() -> mooring_model::Deployment {
    fixture(|parts| {
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &node.lifecycle {
                node.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
    })
}

/// `node apply` records a node applied without a new configuration
/// generation (`Bookkeeping::Applied`), and the configs then need that
/// node's secrets: they are read for it, not taken from the read made
/// while no node was applied, which held none of them.
#[test]
fn a_node_applied_within_a_generation_has_its_secrets_read() {
    let mut harness = deployed();
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    let interfaces = &world.interfaces;
    let adopted = adopted();
    assert_eq!(
        adopted.config_generation(),
        world.deployment.config_generation()
    );
    with_ports(&mut harness, |ports| {
        assert_eq!(
            ports.render(&adopted, interfaces).unwrap().err(),
            Some(RenderOutcome::NoAppliedNode)
        );
        assert_eq!(
            ports.render(&world.deployment, interfaces).unwrap().err(),
            None
        );
        assert_eq!(
            ports
                .render_prober(&world.deployment, interfaces)
                .unwrap()
                .err(),
            None
        );
    });
}

/// A deployment with no applied node renders nothing, which is the exit's
/// state; interfaces resolved for another exit site cannot be rendered,
/// which is the daemon's error.
#[test]
fn no_applied_node_renders_nothing_and_another_site_s_interfaces_are_an_error() {
    let mut harness = deployed();
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    let interfaces = &world.interfaces;
    let adopted = adopted();
    let moved = fixture(|parts| {
        parts.exit.egress = InterfaceSelector::LinkAddr {
            lladdr: MacAddr::parse("02:6d:6f:6f:72:02").unwrap(),
            subnet: "192.168.1.0/24".parse().unwrap(),
        };
    });
    with_ports(&mut harness, |ports| {
        assert_eq!(
            ports.render(&adopted, interfaces).unwrap().err(),
            Some(RenderOutcome::NoAppliedNode)
        );
        assert_eq!(
            ports.render_prober(&adopted, interfaces).unwrap().err(),
            Some(RenderOutcome::NoAppliedNode)
        );
        for error in [
            ports.render(&moved, interfaces).unwrap_err(),
            ports.render_prober(&moved, interfaces).unwrap_err(),
        ] {
            assert!(
                matches!(error, CommandError::Local(LocalError::ExitRender(_))),
                "{error:?}"
            );
        }
    });
}

/// The latch is written and cleared in the run directory; a latch that
/// cannot be written is the daemon's error, never a latch taken as kept.
#[test]
fn the_latch_is_written_and_cleared_and_a_failed_write_is_an_error() {
    let mut harness = deployed();
    let run = run_dir(&harness);
    with_ports(&mut harness, |ports| {
        ports.persist_latch(Some(&latch())).unwrap();
        assert_eq!(read_latch(&run).unwrap(), Some(latch()));
        ports.persist_latch(None).unwrap();
        assert_eq!(read_latch(&run).unwrap(), None);
    });
    let missing = harness.support_dir().join("no-run-directory");
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    let error = harness.with_env(|env| {
        DaemonPorts::new(env, missing, engines)
            .persist_latch(Some(&latch()))
            .unwrap_err()
    });
    assert!(
        matches!(error, CommandError::Local(LocalError::Latch(_))),
        "{error:?}"
    );
}

fn expect_request(harness: &Harness, kind: RequestKind, reply: Response) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind,
        },
        Answered::Replied(Ok(reply)),
    );
}

fn no_holds() -> Holds {
    Holds {
        mac_drain: None,
        egress_violation: None,
        operator: None,
    }
}

/// Each node call sends its own request through the egress and is done
/// only on that request's own answer: a halt for a shutdown, the hold
/// cleared, the gate closed for a drain (whose session ends within the
/// drain's budget); any other answer is a refusal, noted. Without an
/// egress, or without a state to find the node in, nothing is delivered.
#[test]
fn each_node_call_is_done_only_on_its_own_answer() {
    let mut harness = deployed();
    let halt = Halt {
        at: mooring_agent_proto::UnixTime::from_secs(1_791_919_200),
        reason: ShutdownReason::EgressIsNodeAddress,
    };
    expect_request(&harness, RequestKind::Shutdown, Response::Halted(halt));
    expect_request(
        &harness,
        RequestKind::ClearHold,
        Response::HoldCleared { holds: no_holds() },
    );
    expect_request(
        &harness,
        RequestKind::GateSet,
        Response::GateClosed { holds: no_holds() },
    );
    expect_request(
        &harness,
        RequestKind::GateSet,
        Response::HoldCleared { holds: no_holds() },
    );
    let support = harness.support_dir();
    let lon1 = node("lon1");
    let budget = Duration::from_secs(4);
    let (notes, asked) = with_ports(&mut harness, |ports| {
        ports.set_egress(Some(lo0_name()));
        assert_eq!(ports.call(&lon1, &NodeCall::Shutdown(latch())), Ok(()));
        assert_eq!(ports.call(&lon1, &NodeCall::ClearHold), Ok(()));
        let asked = Instant::now();
        assert_eq!(
            ports.call(&node("ams1"), &NodeCall::Drain { within: budget }),
            Ok(())
        );
        assert_eq!(
            ports.call(&lon1, &NodeCall::CloseGate(latch())),
            Err(CallFault::Refused)
        );
        ports.set_egress(None);
        assert_eq!(
            ports.call(&lon1, &NodeCall::ClearHold),
            Err(CallFault::Unreachable)
        );
        ports.set_egress(Some(lo0_name()));
        fs::write(support.join(STATE_FILE), b"{}").unwrap();
        assert_eq!(
            ports.call(&lon1, &NodeCall::ClearHold),
            Err(CallFault::Unreachable)
        );
        (ports.take_notes(), asked)
    });
    assert_eq!(
        notes[..5],
        [
            "lon1: Shutdown done",
            "lon1: ClearHold done",
            "ams1: GateSet done",
            "lon1: the agent answered GateSet with HoldCleared",
            "lon1: not asked: the egress does not resolve",
        ]
    );
    assert!(
        notes[5].starts_with("lon1: ClearHold not delivered: the state could not be read"),
        "{}",
        notes[5]
    );
    assert_eq!(notes.len(), 6);
    assert!(harness.nodes.script.borrow().is_empty());
    let seen = harness.nodes.seen.borrow();
    let deadlines: Vec<_> = seen.iter().map(|(target, _)| target.deadline).collect();
    assert_eq!(deadlines.len(), 4);
    assert_eq!(
        (deadlines[0], deadlines[1], deadlines[3]),
        (None, None, None)
    );
    let drained = deadlines[2].expect("the drain's session has a deadline");
    assert!(drained > asked && drained <= asked + budget + Duration::from_secs(1));
    assert!(
        matches!(&seen[0].1, Sent::Request(request) if request.kind() == RequestKind::Shutdown)
    );
}

/// The in-chain probe reads the line the reflector at the chain's end
/// wrote, through the probe inbound on loopback; with nothing listening it
/// fails at its connection.
#[test]
fn the_in_chain_probe_reads_through_the_probe_inbound() {
    let mut harness = deployed();
    let answering = reflector(b"31.120.5.6\n");
    let closed = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    with_ports(&mut harness, |ports| {
        let probe = ports.probe_in_chain(answering.port()).unwrap();
        assert_eq!(probe.ip, Ipv4Addr::new(31, 120, 5, 6));
        assert!(probe.latency < Duration::from_secs(5));
        assert_eq!(ports.probe_in_chain(closed), Err(ProbeStage::Connect));
    });
}

/// The ports' debug output names their directories and never a secret,
/// even once the secrets are read.
#[test]
fn the_ports_debug_output_holds_no_secret() {
    let mut harness = deployed();
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    let secret = world
        .secrets
        .material(&SecretRef::NodeWgMacPrivate(node("lon1")))
        .unwrap()
        .encode();
    let run = run_dir(&harness);
    let shown = with_ports(&mut harness, |ports| {
        ports
            .render(&world.deployment, &world.interfaces)
            .unwrap()
            .unwrap();
        format!("{ports:?}")
    });
    assert!(shown.starts_with("DaemonPorts { run_dir: "), "{shown}");
    assert!(shown.contains(&format!("{run:?}")), "{shown}");
    assert!(!shown.contains(secret.as_str()), "{shown}");
}

/// What a pid file an earlier daemon left is: one that cannot be read, a
/// pid the kernel cannot be asked about, and one that cannot be removed
/// are each an error, and nothing is stopped.
#[test]
fn a_stale_pid_file_that_cannot_be_read_asked_about_or_removed_is_an_error() {
    let run = tempfile::tempdir().unwrap();
    let pid_file = run.path().join(ENGINE_PID_FILE);
    let engine = run.path().join("mooring-exit");
    fs::write(&engine, STAND_IN).unwrap();
    // A directory where the pid file goes cannot be read as one.
    fs::create_dir(&pid_file).unwrap();
    let error = stop_stale_engine(run.path(), ENGINE_PID_FILE, &engine).unwrap_err();
    assert!(
        matches!(&error, LocalError::EnginePidFile { path, .. } if *path == pid_file),
        "{error:?}"
    );
    fs::remove_dir(&pid_file).unwrap();
    // A pid past the kernel's range: proc_pidpath(2) is never reached.
    fs::write(&pid_file, format!("{}\n", u32::MAX)).unwrap();
    let error = stop_stale_engine(run.path(), ENGINE_PID_FILE, &engine).unwrap_err();
    assert!(
        matches!(error, LocalError::StaleEngine { pid, .. } if pid == u32::MAX),
        "{error:?}"
    );
    // A run directory that cannot be written keeps the file.
    fs::write(&pid_file, b"not a pid\n").unwrap();
    fs::set_permissions(run.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let removed = stop_stale_engine(run.path(), ENGINE_PID_FILE, &engine);
    fs::set_permissions(run.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let error = removed.unwrap_err();
    assert!(
        matches!(&error, LocalError::EnginePidFile { path, source } if *path == pid_file && source.kind() == io::ErrorKind::PermissionDenied),
        "{error:?}"
    );
    assert!(pid_file.exists());
}
