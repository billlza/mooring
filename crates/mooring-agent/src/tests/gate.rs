// SPDX-License-Identifier: GPL-3.0-or-later

//! The gate: the agent records a hold before it closes the gate, never
//! opens it, halts in the documented order, and a viewer's stop is
//! answered by what the watch did, never by the hand-off.

use std::os::unix::fs::symlink;

use mooring_agent_proto::{
    AgentError, ClearableHold, EgressViolationHold, EngineUser, GateReason, GateState, Generation,
    Halt, Holds, IoOp, MacDrainHold, OperatorHold, ShutdownReason, SystemdOp, UnixTime,
    VIEWER_STOP_WAIT_SECS,
};

use super::{FakeNode, failed, nft_set, ok, scratch};
use crate::gate::{
    StopRequest, clear, current_generation, engine_unit, halted, holds, may_start_engines,
    set_by_ops, set_by_viewer, shutdown, state,
};
use crate::host::Tool;
use crate::store::{read_json, write_json};

const CLOSE: &str = "/usr/sbin/nft add element inet mooring exit_closed { \"wgexit\" }";

#[test]
fn an_operator_stop_records_the_hold_then_closes_the_gate() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1000);
    let held = set_by_ops(&paths, &node, GateReason::Operator).unwrap();
    let expected = Holds {
        operator: Some(OperatorHold {
            at: UnixTime::from_secs(1000),
        }),
        ..Holds::NONE
    };
    assert_eq!(held, expected);
    assert_eq!(holds(&paths).unwrap(), expected);
    assert_eq!(node.calls(), vec![CLOSE.to_owned()]);
}

#[test]
fn an_egress_violation_is_recorded_with_the_current_generation() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(7);
    assert_eq!(current_generation(&paths).unwrap(), Generation::ZERO);
    std::fs::create_dir_all(paths.at("/etc/mooring/gen-12")).unwrap();
    symlink("gen-12", paths.current()).unwrap();
    assert_eq!(current_generation(&paths).unwrap(), Generation::new(12));
    let held = set_by_ops(&paths, &node, GateReason::EgressViolation).unwrap();
    assert_eq!(
        held.egress_violation,
        Some(EgressViolationHold {
            at: UnixTime::from_secs(7),
            generation: Generation::new(12),
        })
    );
}

#[test]
fn a_current_link_not_naming_a_generation_is_an_error() {
    let (_dir, paths) = scratch();
    std::fs::create_dir_all(paths.at("/etc/mooring")).unwrap();
    for target in ["gen-", "gen-x1", "generation-3", "gen--1", "gen-+5"] {
        let _ = std::fs::remove_file(paths.current());
        symlink(target, paths.current()).unwrap();
        assert_eq!(
            current_generation(&paths),
            Err(AgentError::Io {
                op: IoOp::ReadState,
                errno: None
            }),
            "{target}"
        );
    }
}

fn wg(stdout: &'static [u8]) -> FakeNode {
    FakeNode::answering(
        50,
        Box::new(move |tool, _| {
            Ok(match tool {
                Tool::Wg => ok(stdout),
                _ => ok(b""),
            })
        }),
    )
}

#[test]
fn a_drain_records_the_peers_handshake_or_none() {
    let (_dir, paths) = scratch();
    let held = set_by_ops(&paths, &wg(b"PEERKEY=\t1790000000\n"), GateReason::MacDrain).unwrap();
    assert_eq!(
        held.mac_drain,
        Some(MacDrainHold {
            handshake_at_drain: Some(UnixTime::from_secs(1_790_000_000)),
        })
    );
    let held = set_by_ops(&paths, &wg(b"PEERKEY=\t0\n"), GateReason::MacDrain).unwrap();
    assert_eq!(
        held.mac_drain,
        Some(MacDrainHold {
            handshake_at_drain: None
        })
    );
}

#[test]
fn a_drain_whose_handshake_cannot_be_read_closes_the_gate_and_records_nothing() {
    for output in [&b""[..], b"A\t1\nB\t2\n", b"A\tsoon\n", b"A 1\n"] {
        let (_dir, paths) = scratch();
        let node = wg(output);
        let error = set_by_ops(&paths, &node, GateReason::MacDrain).unwrap_err();
        assert_eq!(
            error,
            AgentError::Io {
                op: IoOp::ReadState,
                errno: None
            },
            "{output:?}"
        );
        assert_eq!(holds(&paths).unwrap(), Holds::NONE);
        assert!(
            node.calls().contains(&CLOSE.to_owned()),
            "the gate was not closed"
        );
    }
}

#[test]
fn a_failed_close_is_reported_with_the_hold_kept() {
    let (_dir, paths) = scratch();
    let node = FakeNode::answering(
        5,
        Box::new(|_, _| Ok(failed(b"Error: No such file or directory\n"))),
    );
    let error = set_by_ops(&paths, &node, GateReason::Operator).unwrap_err();
    let AgentError::GateCloseFailed { stderr_tail } = error else {
        panic!("{error:?}");
    };
    assert!(stderr_tail.as_str().contains("No such file"));
    assert!(holds(&paths).unwrap().operator.is_some());
}

#[test]
fn clearing_removes_only_that_hold_and_never_opens_the_gate() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(3);
    set_by_ops(&paths, &node, GateReason::Operator).unwrap();
    set_by_ops(&paths, &node, GateReason::EgressViolation).unwrap();
    let held = clear(&paths, ClearableHold::Operator).unwrap();
    assert_eq!(held.operator, None);
    assert!(held.egress_violation.is_some());
    let held = clear(&paths, ClearableHold::EgressViolation).unwrap();
    assert_eq!(held, Holds::NONE);
    assert_eq!(clear(&paths, ClearableHold::Operator).unwrap(), Holds::NONE);
    assert!(node.calls().iter().all(|call| !call.contains("delete")));
}

#[test]
fn a_shutdown_marks_closes_and_stops_in_that_order_and_keeps_the_first_marker() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(77);
    let halt = shutdown(&paths, &node, ShutdownReason::Operator).unwrap();
    let expected = Halt {
        at: UnixTime::from_secs(77),
        reason: ShutdownReason::Operator,
    };
    assert_eq!(halt, expected);
    assert_eq!(halted(&paths).unwrap(), Some(expected));
    assert_eq!(
        node.calls(),
        vec![
            CLOSE.to_owned(),
            "/usr/bin/systemctl stop mooring-xray.service".to_owned(),
            "/usr/bin/systemctl stop mooring-hy2.service".to_owned(),
        ]
    );
    let again = shutdown(&paths, &FakeNode::new(99), ShutdownReason::Retire).unwrap();
    assert_eq!(again, expected);
}

#[test]
fn a_failed_engine_stop_names_the_unit() {
    let (_dir, paths) = scratch();
    let node = FakeNode::answering(
        1,
        Box::new(|tool, args| {
            Ok(
                if tool == Tool::Systemctl && args.contains(&"mooring-hy2.service") {
                    failed(b"")
                } else {
                    ok(b"")
                },
            )
        }),
    );
    assert_eq!(
        shutdown(&paths, &node, ShutdownReason::Operator).unwrap_err(),
        AgentError::Systemd {
            unit: engine_unit(EngineUser::Hy2).unwrap(),
            op: SystemdOp::Stop,
        }
    );
    assert!(halted(&paths).unwrap().is_some(), "the marker comes first");
}

#[test]
fn a_shutdown_whose_gate_will_not_close_still_stops_both_engines() {
    let (_dir, paths) = scratch();
    let node = FakeNode::answering(
        1,
        Box::new(|tool, _| {
            Ok(match tool {
                Tool::Nft => failed(b"Error: No such file or directory\n"),
                _ => ok(b""),
            })
        }),
    );
    let error = shutdown(&paths, &node, ShutdownReason::Operator).unwrap_err();
    assert!(
        matches!(error, AgentError::GateCloseFailed { .. }),
        "{error:?}"
    );
    assert_eq!(
        node.calls()[1..],
        [
            "/usr/bin/systemctl stop mooring-xray.service".to_owned(),
            "/usr/bin/systemctl stop mooring-hy2.service".to_owned(),
        ]
    );
    assert!(!may_start_engines(&paths));
    let node = FakeNode::answering(
        1,
        Box::new(|tool, args| {
            Ok(
                if tool == Tool::Systemctl && args.contains(&"mooring-xray.service") {
                    failed(b"")
                } else {
                    ok(b"")
                },
            )
        }),
    );
    assert_eq!(
        shutdown(&paths, &node, ShutdownReason::Operator).unwrap_err(),
        AgentError::Systemd {
            unit: engine_unit(EngineUser::Xray).unwrap(),
            op: SystemdOp::Stop,
        }
    );
    assert!(
        node.calls()
            .iter()
            .any(|call| call.ends_with("stop mooring-hy2.service"))
    );
}

#[test]
fn engines_may_start_only_without_a_readable_marker() {
    let (_dir, paths) = scratch();
    assert!(may_start_engines(&paths));
    write_json(
        &paths.halted(),
        &Halt {
            at: UnixTime::from_secs(1),
            reason: ShutdownReason::Retire,
        },
        0o640,
    )
    .unwrap();
    assert!(!may_start_engines(&paths));
    std::fs::write(paths.halted(), "garbled").unwrap();
    assert!(!may_start_engines(&paths));
}

#[test]
fn the_engine_units_are_named_as_design_5_2_says() {
    assert_eq!(
        engine_unit(EngineUser::Xray).unwrap().as_str(),
        "mooring-xray.service"
    );
    assert_eq!(
        engine_unit(EngineUser::Hy2).unwrap().as_str(),
        "mooring-hy2.service"
    );
}

#[test]
fn the_gate_state_is_read_from_the_set() {
    let reading = |stdout: Vec<u8>| {
        let node = FakeNode::answering(0, Box::new(move |_, _| Ok(ok(&stdout))));
        state(&node)
    };
    assert_eq!(reading(nft_set(true)), Ok(GateState::Closed));
    assert_eq!(reading(nft_set(false)), Ok(GateState::Open));
    let other = br#"{"nftables":[{"set":{"name":"exit_closed","elem":["eth0"]}}]}"#.to_vec();
    assert_eq!(reading(other), Ok(GateState::Open));
    for bad in [
        b"".to_vec(),
        br#"{"nftables":[]}"#.to_vec(),
        br#"{"nftables":[{"set":{"elem":"wgexit"}}]}"#.to_vec(),
        br#"{"nftables":[{"set":{}},{"set":{}}]}"#.to_vec(),
    ] {
        assert_eq!(
            reading(bad.clone()),
            Err(AgentError::Io {
                op: IoOp::ReadState,
                errno: None
            }),
            "{}",
            String::from_utf8_lossy(&bad)
        );
    }
}

/// A node whose gate set reads closed or open as `closed` says.
fn gate_reads(closed: bool) -> FakeNode {
    FakeNode::answering(
        1000,
        Box::new(move |tool, _| {
            Ok(match tool {
                Tool::Nft => ok(&nft_set(closed)),
                _ => ok(b""),
            })
        }),
    )
}

#[test]
fn a_viewer_stop_is_answered_once_the_watch_has_carried_it_out() {
    let (_dir, paths) = scratch();
    let watch_paths = paths.clone();
    let node = gate_reads(true).on_sleep(move |slept| {
        if slept == 2 {
            let request: StopRequest = read_json(&watch_paths.stop_request()).unwrap().unwrap();
            let held = Holds {
                operator: Some(OperatorHold { at: request.at }),
                ..Holds::NONE
            };
            write_json(&watch_paths.holds(), &held, 0o640).unwrap();
        }
    });
    let held = set_by_viewer(&paths, &node).unwrap();
    assert_eq!(held.operator.unwrap().at, UnixTime::from_secs(1000));
    assert_eq!(node.slept(), 2);
    let request: StopRequest = read_json(&paths.stop_request()).unwrap().unwrap();
    assert_eq!(request.at, UnixTime::from_secs(1000));
    assert!(
        node.calls()
            .iter()
            .all(|call| !call.contains("add element")),
        "the viewer closed the gate itself"
    );
}

#[test]
fn a_viewer_stop_the_watch_does_not_carry_out_is_unconfirmed() {
    let (_dir, paths) = scratch();
    let node = gate_reads(true);
    write_json(
        &paths.holds(),
        &Holds {
            operator: Some(OperatorHold {
                at: UnixTime::from_secs(999),
            }),
            ..Holds::NONE
        },
        0o640,
    )
    .unwrap();
    assert_eq!(
        set_by_viewer(&paths, &node).unwrap_err(),
        AgentError::GateStopUnconfirmed {
            waited_secs: VIEWER_STOP_WAIT_SECS
        },
        "an older Operator hold is not this stop"
    );
    assert_eq!(node.slept(), VIEWER_STOP_WAIT_SECS);
    assert!(
        paths.stop_request().exists(),
        "the request stays for the watch"
    );
}

#[test]
fn a_viewer_stop_with_the_hold_but_an_open_gate_is_unconfirmed() {
    let (_dir, paths) = scratch();
    let watch_paths = paths.clone();
    let node = gate_reads(false).on_sleep(move |_| {
        let held = Holds {
            operator: Some(OperatorHold {
                at: UnixTime::from_secs(5000),
            }),
            ..Holds::NONE
        };
        write_json(&watch_paths.holds(), &held, 0o640).unwrap();
    });
    assert!(matches!(
        set_by_viewer(&paths, &node),
        Err(AgentError::GateStopUnconfirmed { .. })
    ));
}
