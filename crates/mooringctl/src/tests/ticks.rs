// SPDX-License-Identifier: GPL-3.0-or-later

//! The deployed daemon over several ticks (design §10.1, §10.3), with its
//! loop's intervals shortened where a test cannot wait for them: the M7
//! and the nodes polled again, the status published again, the power
//! helper lost and started again, the SIM meter's failed writes logged,
//! the loop served until its acceptor ends, a node applied while the exit
//! runs, and the failures that stop a tick (a state that cannot be read, a
//! pid file, a log that cannot be written).

use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mooring_agent_proto::{AgentError, RequestKind, Response};
use mooring_daemon_core::power::HelperEvent;
use mooring_daemon_core::radio_history::decode_line;
use mooring_daemon_core::status::{
    AgentUnreachable, DownReason, ExitState, NodeAgentState, PowerSource,
};
use mooring_model::node::NodeLifecycle;
use mooring_model::{Bookkeeping, CalendarDate, NodeId};
use mooring_store::{
    LATCH_FILE, SIM_METER_FILE, STATE_FILE, STATUS_SNAPSHOT_FILE, Store, USAGE_DIRECTORY,
    read_radio_day,
};

use super::deployed::{
    CARRIER, deployed, deployed_with, published, shared, status_reply, statuses, with_exit_on,
};
use super::support::{Answered, Expected, ExpectedRemote, FailingLog, Harness};
use super::user::fixture;
use crate::daemon::deployed::{Deployed, Stopped, first_power_source, serve};
use crate::daemon::{Control, Intervals, LoopState, RunPaths};
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::runtime::ports::ENGINE_PID_FILE;
use crate::runtime::power::PowerMessage;

/// The daemon's intervals, with `edit` applied.
fn every(edit: impl FnOnce(&mut Intervals)) -> Intervals {
    let mut intervals = Intervals::DAEMON;
    edit(&mut intervals);
    intervals
}

/// Gives the harness `count` direct probes that see the carrier.
fn probes(harness: &Harness, count: usize) {
    for _ in 0..count {
        harness.probes.borrow_mut().push_back(Ok(CARRIER));
    }
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// Scripts `node`'s next `Status` poll: the order is the nodes' (ams1,
/// lon1).
fn poll_answer(harness: &Harness, answer: Result<Response, NodeError>) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Status,
        },
        Answered::Replied(answer),
    );
}

/// The log's lines after the daemon's stamp and prefix.
fn lines(log: &[u8]) -> Vec<String> {
    String::from_utf8(log.to_vec())
        .unwrap()
        .lines()
        .map(|line| {
            line.split_once("mooringctl daemon: ")
                .map_or(line, |(_, text)| text)
                .to_owned()
        })
        .collect()
}

/// The samples the radio history holds for the fixed clock's day.
fn samples(harness: &Harness) -> usize {
    read_radio_day(
        &harness.support_dir(),
        CalendarDate::parse("2026-10-13").unwrap(),
    )
    .unwrap()
    .map_or(0, |day| {
        day.lines
            .split_inclusive(|&byte| byte == b'\n')
            .inspect(|line| {
                decode_line(line).unwrap();
            })
            .count()
    })
}

/// The deployment's nodes adopted, none applied yet.
fn adopted() -> mooring_model::Deployment {
    fixture(|parts| {
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &node.lifecycle {
                node.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
    })
}

/// `node apply` while the exit is enabled: each node is recorded applied,
/// which keeps the configuration generation, and the next tick starts the
/// engine on the nodes' secrets, which it reads then; the daemon serves on.
#[test]
fn a_node_applied_while_the_exit_runs_is_served_at_the_next_tick() {
    let mut harness = deployed_with(adopted());
    probes(&harness, 2);
    statuses(&harness);
    let applied = mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .deployment;
    let store = Store::new(harness.support_dir());
    let (control, _retries) = shared();
    with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        assert_eq!(
            exit.tick(&control, log, false).unwrap(),
            ExitState::Down {
                reason: DownReason::NoAppliedNode
            }
        );
        let generation = store.load().unwrap().deployment.config_generation();
        for node in applied.nodes().values() {
            let NodeLifecycle::Applied { applied, .. } = &node.lifecycle else {
                continue;
            };
            store
                .record(
                    generation,
                    Bookkeeping::Applied {
                        node: node.id.clone(),
                        applied: *applied,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            store.load().unwrap().deployment.config_generation(),
            generation
        );
        assert_eq!(
            exit.tick(&control, log, false).unwrap(),
            ExitState::Starting
        );
        assert!(published(&control).parts().exit.engines.exit.pid.is_some());
    });
}

/// The M7 is polled at the exit's start and then once per interval, in
/// the slot after a direct-probe round: each poll is one more sample in
/// the radio history.
#[test]
fn the_m7_is_polled_again_once_its_interval_has_passed() {
    let mut harness = deployed();
    probes(&harness, 2);
    statuses(&harness);
    let (control, _retries) = shared();
    with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..3 {
            exit.tick(&control, log, false).unwrap();
        }
    });
    assert_eq!(samples(&harness), 1, "only the start's poll");
    statuses(&harness);
    let (control, _retries) = shared();
    with_exit_on(
        &mut harness,
        every(|intervals| intervals.router_poll = Duration::ZERO),
        |exit, log| {
            for _ in 0..3 {
                exit.tick(&control, log, false).unwrap();
            }
        },
    );
    assert_eq!(samples(&harness), 1 + 1 + 3, "the start's and each tick's");
}

/// Each node is polled again once its interval has passed: a node that
/// answers with another reply is a protocol mismatch, one that keeps
/// failing is logged once, and a node that answers again is logged as
/// polled again and reported.
#[test]
fn the_nodes_are_polled_again_and_a_recovery_is_logged() {
    let mut harness = deployed();
    probes(&harness, 2);
    // ams1, then lon1, at each of three ticks.
    poll_answer(&harness, Ok(status_reply()));
    poll_answer(&harness, Err(NodeError::Pipe));
    poll_answer(&harness, Ok(super::node::hello_at([45, 67, 89, 10].into())));
    poll_answer(&harness, Err(NodeError::Pipe));
    poll_answer(&harness, Ok(status_reply()));
    poll_answer(&harness, Ok(status_reply()));
    let (control, _retries) = shared();
    let quick = every(|intervals| {
        intervals.node_poll = Duration::ZERO;
        intervals.publish = Duration::ZERO;
    });
    let agent =
        |control: &Control, id: &str| published(control).parts().nodes[&node(id)].agent.clone();
    let log = with_exit_on(&mut harness, quick, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        assert!(matches!(
            agent(&control, "ams1"),
            NodeAgentState::Reported(_)
        ));
        exit.tick(&control, log, false).unwrap();
        assert!(matches!(
            agent(&control, "ams1"),
            NodeAgentState::Unreachable {
                cause: AgentUnreachable::ProtocolMismatch,
                ..
            }
        ));
        assert!(matches!(
            agent(&control, "lon1"),
            NodeAgentState::Unreachable {
                cause: AgentUnreachable::Transport,
                ..
            }
        ));
        exit.tick(&control, log, false).unwrap();
        for id in ["ams1", "lon1"] {
            assert!(
                matches!(agent(&control, id), NodeAgentState::Reported(_)),
                "{id}"
            );
        }
        lines(log)
    });
    assert!(harness.nodes.script.borrow().is_empty());
    let polls: Vec<&String> = log
        .iter()
        .filter(|line| line.starts_with("ams1: ") || line.starts_with("lon1: "))
        .collect();
    assert_eq!(polls.len(), 4, "{log:?}");
    assert!(polls[0].starts_with("lon1: poll failed: "), "{log:?}");
    assert_eq!(
        polls[1],
        "ams1: poll failed: the agent answered Status with Hello"
    );
    assert_eq!(polls[2], "ams1: polled again");
    assert_eq!(polls[3], "lon1: polled again");
}

/// The status is published when the exit's state changes, and again once
/// the publication interval has passed with nothing changed.
#[test]
fn an_unchanged_status_is_published_again_after_its_interval() {
    let mut harness = deployed();
    probes(&harness, 2);
    statuses(&harness);
    let (control, _retries) = shared();
    with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..3 {
            exit.tick(&control, log, false).unwrap();
        }
    });
    assert_eq!(control.hub.latest().unwrap().unwrap().seq, 1);
    statuses(&harness);
    let (control, _retries) = shared();
    with_exit_on(
        &mut harness,
        every(|intervals| intervals.publish = Duration::ZERO),
        |exit, log| {
            for _ in 0..3 {
                exit.tick(&control, log, false).unwrap();
            }
        },
    );
    assert_eq!(control.hub.latest().unwrap().unwrap().seq, 3);
}

/// A helper that ends is started again once its restart interval has
/// passed; one that cannot be started is tried again an interval later,
/// and logged each time.
#[test]
fn a_lost_helper_is_started_again_after_its_interval() {
    let mut harness = deployed();
    probes(&harness, 2);
    statuses(&harness);
    let helper = harness.helper.handle.clone();
    let (control, _retries) = shared();
    let quick = every(|intervals| intervals.helper_restart = Duration::ZERO);
    let log = with_exit_on(&mut harness, quick, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        helper.send(PowerMessage::Event(HelperEvent::Assertions { held: true }));
        exit.tick(&control, log, false).unwrap();
        assert!(published(&control).parts().exit.power.assertions_held);
        helper.send(PowerMessage::Ended("gone".to_owned()));
        exit.tick(&control, log, false).unwrap();
        assert!(!published(&control).parts().exit.power.assertions_held);
        // Restarted at the next tick, its first report read at the one
        // after it.
        exit.tick(&control, log, false).unwrap();
        exit.tick(&control, log, false).unwrap();
        helper.refuse(true);
        helper.send(PowerMessage::Ended("gone again".to_owned()));
        exit.tick(&control, log, false).unwrap();
        exit.tick(&control, log, false).unwrap();
        exit.tick(&control, log, false).unwrap();
        lines(log)
    });
    assert_eq!(harness.helper.starts.get(), 2);
    let helper_lines: Vec<&String> = log
        .iter()
        .filter(|line| line.starts_with("the power helper"))
        .collect();
    assert_eq!(
        helper_lines[..3],
        [
            "the power helper ended: gone (no process)",
            "the power helper started again",
            "the power helper ended: gone again (no process)",
        ]
    );
    assert_eq!(helper_lines.len(), 5, "{log:?}");
    for line in &helper_lines[3..] {
        assert!(
            line.starts_with("the power helper could not be started: ")
                && line.ends_with(": refused by the test"),
            "{line}"
        );
    }
}

/// A helper whose reader stopped, or that cannot be written to, is lost:
/// nothing holds the Mac awake any more, and the log says why. A helper
/// that reports the power source it reported before adds no line.
#[test]
fn a_helper_that_stopped_reading_or_cannot_be_written_to_is_lost() {
    let mut harness = deployed();
    probes(&harness, 2);
    statuses(&harness);
    let helper = harness.helper.handle.clone();
    let (control, _retries) = shared();
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        helper.send(PowerMessage::Event(HelperEvent::PowerSource(
            PowerSource::Ac,
        )));
        exit.tick(&control, log, false).unwrap();
        helper.disconnect();
        exit.tick(&control, log, false).unwrap();
        lines(log)
    });
    assert!(
        !log.iter().any(|line| line.starts_with("power: ")),
        "{log:?}"
    );
    assert!(
        log.contains(
            &"the power helper ended: the power helper's reader stopped (no process)".to_owned()
        ),
        "{log:?}"
    );

    let mut harness = deployed();
    harness.helper.deaf.set(true);
    probes(&harness, 2);
    statuses(&harness);
    let (control, _retries) = shared();
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        lines(log)
    });
    let ended: Vec<&String> = log
        .iter()
        .filter(|line| line.starts_with("the power helper ended: "))
        .collect();
    assert_eq!(ended.len(), 1, "{log:?}");
    assert!(ended[0].ends_with("(no process)"), "{log:?}");
}

/// A helper's first report, read at the start, must come: a helper whose
/// reader has stopped before it reported stops the start.
#[test]
fn a_helper_whose_reader_stopped_before_its_first_report_stops_the_start() {
    let mut harness = deployed();
    harness.helper.silent.set(true);
    let link = harness.with_env(|env| (env.power_helper)().unwrap());
    harness.helper.handle.disconnect();
    let error = first_power_source(&link, Duration::from_secs(5)).unwrap_err();
    assert!(
        matches!(&error, LocalError::PowerHelperEnded(text) if text == "the power helper's reader stopped"),
        "{error:?}"
    );
}

/// A helper lost while the Mac sleeps has let the sleep proceed or died
/// with it: the exit is woken, not left paused.
#[test]
fn a_helper_lost_while_the_mac_sleeps_wakes_the_exit() {
    let mut harness = deployed();
    probes(&harness, 3);
    statuses(&harness);
    for _ in 0..2 {
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::GateSet,
            },
            Answered::Replied(Err(NodeError::Agent(AgentError::TrailingInput))),
        );
    }
    let helper = harness.helper.handle.clone();
    let (control, _retries) = shared();
    with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        helper.send(PowerMessage::Event(HelperEvent::WillSleep { id: 4 }));
        assert_eq!(exit.tick(&control, log, false).unwrap(), ExitState::Paused);
        helper.send(PowerMessage::Ended("gone in the sleep".to_owned()));
        assert_ne!(exit.tick(&control, log, false).unwrap(), ExitState::Paused);
    });
}

/// The SIM meter's failed writes are logged once while they last, and
/// their end once.
#[test]
fn a_failing_meter_write_is_logged_once_and_its_recovery_too() {
    let mut harness = deployed();
    probes(&harness, 2);
    statuses(&harness);
    // A directory where the meter's temporary file goes (the store writes
    // `<file>.tmp` and renames it): every write fails, while the meter
    // itself can still be read.
    let blocked = harness
        .support_dir()
        .join(USAGE_DIRECTORY)
        .join(format!("{SIM_METER_FILE}.tmp"));
    fs::create_dir_all(&blocked).unwrap();
    let (control, _retries) = shared();
    let quick = every(|intervals| {
        intervals.meter_tick = Duration::from_millis(5);
        intervals.meter_persist = Duration::from_millis(5);
    });
    let ticks_until = |exit: &mut Deployed<'_, '_>, log: &mut Vec<u8>, text: &str| {
        let started = Instant::now();
        while !lines(log).iter().any(|line| line.starts_with(text)) {
            assert!(started.elapsed() < Duration::from_secs(5), "{text}");
            exit.tick(&control, log, false).unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let log = with_exit_on(&mut harness, quick, |exit, log| {
        ticks_until(exit, log, "the SIM meter was not written: ");
        // Further failed writes add no line.
        std::thread::sleep(Duration::from_millis(50));
        exit.tick(&control, log, false).unwrap();
        fs::remove_dir(&blocked).unwrap();
        ticks_until(exit, log, "the SIM meter is written again");
        lines(log)
    });
    assert_eq!(
        log.iter()
            .filter(|line| line.starts_with("the SIM meter was not written: "))
            .count(),
        1,
        "{log:?}"
    );
}

/// The loop ticks, with a retry when one was asked for (every node's
/// violation hold is cleared), until the acceptor ends; it marks the
/// deployment served, so retries are taken.
#[test]
fn the_exit_is_served_until_the_acceptor_ends() {
    let mut harness = deployed();
    probes(&harness, 2);
    for _ in 0..2 {
        harness.nodes.expect(
            Expected::Request {
                identity: "ops_ed25519",
                remote: ExpectedRemote::Forced,
                kind: RequestKind::ClearHold,
            },
            Answered::Replied(Ok(Response::HoldCleared {
                holds: mooring_agent_proto::Holds {
                    mac_drain: None,
                    egress_violation: None,
                    operator: None,
                },
            })),
        );
    }
    statuses(&harness);
    let (retry, retries) = mpsc::channel();
    let control = Control {
        hub: crate::daemon::hub::Hub::default(),
        retry,
        deployed: AtomicBool::new(false),
    };
    control.retry.send(()).unwrap();
    let (ended, acceptor_ended) = mpsc::channel();
    ended.send(()).unwrap();
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        assert_eq!(
            serve(exit, log, &control, &acceptor_ended, &retries).unwrap(),
            Stopped::AcceptorEnded
        );
        lines(log)
    });
    assert!(control.deployed.load(Ordering::SeqCst));
    assert!(retries.try_recv().is_err(), "the retry was taken");
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(published(&control).parts().exit.state, ExitState::Starting);
    assert!(log.contains(&"serving the exit".to_owned()), "{log:?}");
}

/// A tick that cannot read the state, or whose engine's pid file cannot
/// be written, stops the daemon: it never serves on a guess.
#[test]
fn a_state_or_pid_file_the_tick_cannot_use_stops_the_daemon() {
    let mut harness = deployed();
    probes(&harness, 1);
    statuses(&harness);
    let support = harness.support_dir();
    let (control, _retries) = shared();
    let error = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        fs::write(support.join(STATE_FILE), b"{}").unwrap();
        exit.tick(&control, log, false).unwrap_err()
    });
    assert!(
        matches!(error, CommandError::Local(LocalError::StateRead(_))),
        "{error:?}"
    );

    let mut harness = deployed();
    probes(&harness, 1);
    statuses(&harness);
    let run = RunPaths::under(&harness.support_dir()).dir;
    let (control, _retries) = shared();
    let error = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        // A directory where the engine's pid file goes, once the exit has
        // looked for an engine an earlier daemon left.
        fs::create_dir(run.join(ENGINE_PID_FILE)).unwrap();
        exit.tick(&control, log, false).unwrap_err()
    });
    assert!(
        matches!(error, CommandError::Local(LocalError::EnginePidFile { .. })),
        "{error:?}"
    );
}

/// The network check's own lines stop the tick like any other when the log
/// cannot take them: configd or the declarations not read, the
/// declarations read again, and a change of their set. `prepare` runs
/// before the first tick and `between` before the second, on the support
/// directory; the line `needle` is the one the log refuses.
#[test]
fn a_network_check_line_the_log_cannot_take_stops_the_tick() {
    use mooring_macsys::{ConfigdFault, MacsysError};
    use mooring_store::ALLOWED_NETWORKS_FILE;

    use super::deployed::{declare_hotspot_in, joined_to_the_declared_hotspot};

    type Step = fn(&std::path::Path);
    let corrupt: Step = |support| fs::write(support.join(ALLOWED_NETWORKS_FILE), b"{}").unwrap();
    let mend: Step = |support| {
        fs::remove_file(support.join(ALLOWED_NETWORKS_FILE)).unwrap();
        declare_hotspot_in(support);
    };
    let withdraw_all: Step =
        |support| fs::remove_file(support.join(ALLOWED_NETWORKS_FILE)).unwrap();
    let nothing: Step = |_| {};
    for (configd_reads, prepare, between, needle) in [
        (
            false,
            nothing,
            None,
            "the network services were not read from configd",
        ),
        (
            true,
            corrupt,
            None,
            "the own-network declarations were not read",
        ),
        (
            true,
            corrupt,
            Some(mend),
            "the own-network declarations are read again",
        ),
        (
            true,
            nothing,
            Some(withdraw_all),
            "the own-network declarations changed",
        ),
    ] {
        let mut harness = joined_to_the_declared_hotspot();
        if !configd_reads {
            harness.link.services = Err(MacsysError::Configd {
                fault: ConfigdFault::StoreUnavailable,
            });
        }
        probes(&harness, 2);
        statuses(&harness);
        let support = harness.support_dir();
        fs::create_dir_all(RunPaths::under(&support).dir).unwrap();
        prepare(&support);
        let (control, _retries) = shared();
        let (error, failed) = harness.with_env(|env| {
            let mut log = FailingLog::at(needle);
            let mut exit = Deployed::open(
                env,
                &support,
                &mut log,
                LoopState::default(),
                Intervals::DAEMON,
            )
            .unwrap();
            let error = match between {
                None => exit.tick(&control, &mut log, false).unwrap_err(),
                Some(between) => {
                    exit.tick(&control, &mut log, false).unwrap();
                    between(&support);
                    exit.tick(&control, &mut log, false).unwrap_err()
                }
            };
            (error, log.failed())
        });
        assert!(failed, "{needle}");
        assert!(
            matches!(error, CommandError::Local(LocalError::Output(_))),
            "{needle}: {error:?}"
        );
    }
}

/// A log that cannot be written stops the daemon, at its start or at a
/// tick: the log is where the daemon reports, and it does not run on
/// without it.
#[test]
fn a_log_that_cannot_be_written_stops_the_daemon() {
    use mooring_model::verdict::{LatchRecord, Violation};

    // At the start: the latch it reads, and its first poll of the M7.
    let mut harness = deployed();
    let run = RunPaths::under(&harness.support_dir()).dir;
    fs::create_dir_all(&run).unwrap();
    let world = mooring_fixtures::two_nodes_three_users().unwrap();
    let latch = LatchRecord {
        violation: Violation::OutsideCarrierPrefixes {
            ip: [82, 10, 20, 30].into(),
        },
        at: mooring_model::UnixTime::from_secs(super::support::NOW - 600),
        config_generation: world.deployment.config_generation(),
        egress: mooring_model::iface::EgressIdentity {
            bsd_name: super::support::lo0_name(),
            lladdr: mooring_model::iface::MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
        },
    };
    mooring_store::write_latch(&run, &latch).unwrap();
    assert!(run.join(LATCH_FILE).exists());
    let support = harness.support_dir();
    for needle in ["a violation is latched", "router poll failed"] {
        let mut log = FailingLog::at(needle);
        let error = harness.with_env(|env| {
            Deployed::open(
                env,
                &support,
                &mut log,
                LoopState::default(),
                Intervals::DAEMON,
            )
            .unwrap_err()
        });
        assert!(log.failed(), "{needle}");
        assert!(
            matches!(error, CommandError::Local(LocalError::Output(_))),
            "{needle}: {error:?}"
        );
    }

    // At a tick: its state's line, and a status that cannot be written.
    for needle in ["exit: Starting", "status.json not written"] {
        let mut harness = deployed();
        probes(&harness, 1);
        statuses(&harness);
        fs::create_dir_all(harness.support_dir().join(STATUS_SNAPSHOT_FILE)).unwrap();
        let (control, _retries) = shared();
        let support = harness.support_dir();
        fs::create_dir_all(RunPaths::under(&support).dir).unwrap();
        let (error, failed) = harness.with_env(|env| {
            let mut log = FailingLog::at(needle);
            let mut exit = Deployed::open(
                env,
                &support,
                &mut log,
                LoopState::default(),
                Intervals::DAEMON,
            )
            .unwrap();
            let error = exit.tick(&control, &mut log, false).unwrap_err();
            (error, log.failed())
        });
        assert!(failed, "{needle}");
        assert!(
            matches!(error, CommandError::Local(LocalError::Output(_))),
            "{needle}: {error:?}"
        );
    }
}

/// The exit's debug output names its support directory, its machine and
/// its ports (whose own output holds no secret, the ports tests show).
#[test]
fn the_exit_s_debug_output_names_its_parts() {
    let mut harness = deployed();
    let support = harness.support_dir();
    let shown = with_exit_on(&mut harness, Intervals::DAEMON, |exit, _| {
        format!("{exit:?}")
    });
    assert!(
        shown.starts_with(&format!("Deployed {{ support_dir: {support:?}, machine: ")),
        "{shown}"
    );
    assert!(shown.contains("ports: DaemonPorts { "), "{shown}");
    assert!(shown.ends_with(", .. }"), "{shown}");
}

/// A separate uplink is the exit's own path, like the egress: the network
/// check exempts it although it holds a routable address and the default
/// route, so the exit starts (design §10.2, P0-2).
#[test]
fn a_separate_uplink_is_exempt_from_the_network_check() {
    use std::net::Ipv4Addr;
    use std::num::NonZeroU32;

    use mooring_macsys::{DefaultRoute, Interface, InterfaceAddrV4};
    use mooring_model::exit::Uplink;
    use mooring_model::iface::{InterfaceSelector, MacAddr};

    /// The home router the uplink is behind, a made-up address.
    const HOME: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x20, 0x61];
    let mut harness = deployed_with(fixture(|parts| {
        parts.exit.uplink = Uplink::Separate(InterfaceSelector::GatewayLinkAddr {
            gw_lladdr: MacAddr::from_bytes(HOME).unwrap(),
            subnet: "192.168.0.0/24".parse().unwrap(),
        });
    }));
    if let Ok(listed) = &mut harness.link.listed {
        listed.push(Interface {
            index: NonZeroU32::new(7).unwrap(),
            name: "en7".to_owned(),
            link_type: 6,
            lladdr: Some([0x02, 0x6d, 0x6f, 0x6f, 0x72, 0x07]),
            up: true,
            running: true,
            mtu: 1500,
            ibytes: 0,
            obytes: 0,
            baudrate: 0,
            ipv4: vec![InterfaceAddrV4 {
                addr: Ipv4Addr::new(192, 168, 0, 20),
                prefix_len: Some(24),
            }],
            ipv6: Vec::new(),
        });
    }
    harness
        .link
        .routes
        .insert(7, (Ok(Ipv4Addr::new(192, 168, 0, 1)), Ok(HOME)));
    harness.link.default_routes = Ok(vec![DefaultRoute {
        interface_index: 7,
        gateway: Ipv4Addr::new(192, 168, 0, 1),
        scoped: false,
    }]);
    probes(&harness, 1);
    statuses(&harness);
    let (control, _retries) = shared();
    with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        assert_eq!(
            exit.tick(&control, log, false).unwrap(),
            ExitState::Starting
        );
    });
    assert!(published(&control).parts().exit.foreign_networks.is_empty());
}
