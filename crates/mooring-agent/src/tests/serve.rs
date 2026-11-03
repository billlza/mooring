// SPDX-License-Identifier: GPL-3.0-or-later

//! The forced command end to end: one frame in, one reply out, the role
//! checked before anything is done, and every request served.

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::symlink;

use mooring_agent_proto::{
    AgentError, AgentEvent, AgentEventKind, BlobLen, ClearableHold, EventSeq, GateReason,
    Generation, Holds, IoOp, LineRequest, Reply, Request, RequestKind, Response, Role,
    ShutdownReason, TxnStage, TxnState, UnixTime, read_reply, write_put_blob, write_request,
};

use super::{ENOENT, FakeNode, header, nft_set, ok, scratch, sha};
use crate::blobs::{digest_of, put};
use crate::host::Tool;
use crate::paths::Paths;
use crate::serve::{Session, answer, line_reply, serve};
use crate::store::write_json;
use crate::txn::record::{Change, Pending, Phase, set_pending};
use crate::txn::stage::BUNDLE_FILE;

/// `SSH_CONNECTION` as sshd sets it for the requests `ask` sends.
pub(super) const SSH: &str = "198.51.100.97 51234 203.0.113.203 22";

fn session(role: Role) -> Session<'static> {
    Session {
        role,
        ssh_connection: Some(SSH),
    }
}

pub(super) fn frame(request: &LineRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_request(&mut bytes, request).unwrap();
    bytes
}

pub(super) fn ask(paths: &Paths, node: &FakeNode, role: Role, bytes: Vec<u8>) -> Reply {
    answer(paths, node, session(role), &mut Cursor::new(bytes))
}

/// The pinned `PutMacReport` frame (contract/agent-proto-golden).
fn put_mac_report_frame() -> Vec<u8> {
    let golden =
        include_str!("../../../../contract/agent-proto-golden/put_mac_report.request.snap");
    let line = golden.lines().last().unwrap();
    format!("{line}\n").into_bytes()
}

#[test]
fn a_reply_is_one_line_on_stdout() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(10);
    let mut output = Vec::new();
    serve(
        &paths,
        &node,
        session(Role::Ops),
        &mut Cursor::new(frame(&LineRequest::ClearHold {
            hold: ClearableHold::Operator,
        })),
        &mut output,
    )
    .unwrap();
    assert_eq!(output.iter().filter(|&&byte| byte == b'\n').count(), 1);
    assert_eq!(
        read_reply(&mut Cursor::new(output)).unwrap(),
        Ok(Response::HoldCleared { holds: Holds::NONE })
    );
}

#[test]
fn the_role_is_checked_before_anything_is_done() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(10);
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Viewer,
            frame(&LineRequest::Shutdown {
                reason: ShutdownReason::Operator
            })
        ),
        Err(AgentError::RoleNotPermitted {
            role: Role::Viewer,
            request: RequestKind::Shutdown,
        })
    );
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Viewer,
            frame(&LineRequest::GateSet {
                reason: GateReason::MacDrain
            })
        ),
        Err(AgentError::GateReasonNotPermitted {
            role: Role::Viewer,
            reason: GateReason::MacDrain,
        })
    );
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Bootstrap,
            frame(&LineRequest::GateSet {
                reason: GateReason::Operator
            })
        ),
        Err(AgentError::RoleNotPermitted {
            role: Role::Bootstrap,
            request: RequestKind::GateSet,
        })
    );
    let mut blob = Vec::new();
    write_put_blob(&mut blob, digest_of(&b"x"[..]).unwrap(), b"x").unwrap();
    assert_eq!(
        ask(&paths, &node, Role::Viewer, blob),
        Err(AgentError::RoleNotPermitted {
            role: Role::Viewer,
            request: RequestKind::PutBlob,
        })
    );
    assert!(node.calls().is_empty(), "a refused request ran a tool");
    assert!(!paths.halted().exists() && !paths.blobs().exists());
}

#[test]
fn input_that_is_not_one_frame_is_refused() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    for bytes in [
        b"".to_vec(),
        b"\"Hello\"".to_vec(),
        b"{\"Nope\":1}\n".to_vec(),
        b"true\n".to_vec(),
    ] {
        assert_eq!(
            ask(&paths, &node, Role::Ops, bytes),
            Err(AgentError::UnknownRequest)
        );
    }
    let mut trailing = frame(&LineRequest::MacReport);
    trailing.extend_from_slice(b"more");
    assert_eq!(
        ask(&paths, &node, Role::Ops, trailing),
        Err(AgentError::TrailingInput)
    );
}

#[test]
fn a_blob_is_stored_and_then_present() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let payload = b"engine bytes".to_vec();
    let sha256 = digest_of(&payload[..]).unwrap();
    let mut bytes = Vec::new();
    write_put_blob(&mut bytes, sha256, &payload).unwrap();
    assert_eq!(
        ask(&paths, &node, Role::Ops, bytes),
        Ok(Response::BlobStored { sha256 })
    );
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::HaveBlobs {
                blobs: [sha256].into()
            })
        ),
        Ok(Response::Blobs {
            present: [sha256].into()
        })
    );
    assert_eq!(BlobLen::new(payload.len() as u64).unwrap().get(), 12);
}

#[test]
fn gate_requests_answer_with_the_holds_and_the_halt() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(500);
    let Ok(Response::GateClosed { holds }) = ask(
        &paths,
        &node,
        Role::Ops,
        frame(&LineRequest::GateSet {
            reason: GateReason::Operator,
        }),
    ) else {
        panic!("not closed");
    };
    assert!(holds.operator.is_some());
    let Ok(Response::Halted(halt)) = ask(
        &paths,
        &node,
        Role::Ops,
        frame(&LineRequest::Shutdown {
            reason: ShutdownReason::Retire,
        }),
    ) else {
        panic!("not halted");
    };
    assert_eq!(halt.reason, ShutdownReason::Retire);
}

#[test]
fn a_viewer_stop_goes_through_the_watch() {
    let (_dir, paths) = scratch();
    let node = FakeNode::answering(
        800,
        Box::new(|tool, _| {
            Ok(match tool {
                Tool::Nft => ok(&nft_set(false)),
                _ => ok(b""),
            })
        }),
    );
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Viewer,
            frame(&LineRequest::GateSet {
                reason: GateReason::Operator
            })
        ),
        Err(AgentError::GateStopUnconfirmed { waited_secs: 15 })
    );
    assert!(paths.stop_request().exists());
    assert!(!paths.holds().exists(), "the viewer wrote the holds itself");
}

#[test]
fn the_mac_report_is_stored_with_the_nodes_time_and_read_back() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_791_418_000);
    assert_eq!(
        ask(&paths, &node, Role::Viewer, frame(&LineRequest::MacReport)),
        Err(AgentError::MacReportMissing)
    );
    let Request::Line(LineRequest::PutMacReport(report)) =
        mooring_agent_proto::read_request(&mut Cursor::new(put_mac_report_frame())).unwrap()
    else {
        panic!("the golden is not a PutMacReport");
    };
    let at = report.parts().at;
    assert_eq!(
        ask(&paths, &node, Role::Ops, put_mac_report_frame()),
        Ok(Response::MacReportStored { at })
    );
    let Ok(Response::MacReport(stored)) =
        ask(&paths, &node, Role::Viewer, frame(&LineRequest::MacReport))
    else {
        panic!("no report");
    };
    assert_eq!(stored.received_at.as_secs(), 1_791_418_000);
    assert_eq!(stored.report, *report);
    assert_eq!(
        ask(&paths, &node, Role::Viewer, put_mac_report_frame()),
        Err(AgentError::RoleNotPermitted {
            role: Role::Viewer,
            request: RequestKind::PutMacReport,
        })
    );
}

#[test]
fn events_are_served_from_the_journal_to_ops_and_the_viewer() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let request = LineRequest::Events {
        since: EventSeq::new(1),
    };
    let Ok(Response::Events(empty)) = ask(&paths, &node, Role::Ops, frame(&request)) else {
        panic!("no page");
    };
    assert!(empty.events().is_empty());
    assert_eq!(empty.end(), EventSeq::FIRST, "no journal yet");
    let mut journal = crate::journal::Journal::open(&paths).unwrap();
    journal
        .append(
            UnixTime::from_secs(9),
            &[AgentEventKind::HostBooted, AgentEventKind::GateOpened],
        )
        .unwrap();
    let Ok(Response::Events(page)) = ask(&paths, &node, Role::Ops, frame(&request)) else {
        panic!("no page");
    };
    assert_eq!(
        page.events(),
        &[AgentEvent {
            seq: EventSeq::new(1),
            at: UnixTime::from_secs(9),
            kind: AgentEventKind::GateOpened,
        }]
    );
    assert_eq!(page.end(), EventSeq::new(2));
    assert_eq!(
        ask(&paths, &node, Role::Viewer, frame(&request)),
        Ok(Response::Events(page)),
        "the remote viewer reads the journal too"
    );
    assert_eq!(
        ask(&paths, &node, Role::Bootstrap, frame(&request)),
        Err(AgentError::RoleNotPermitted {
            role: Role::Bootstrap,
            request: RequestKind::Events,
        })
    );
}

/// The bootstrap key's role check is made twice: `authorize` refuses its
/// `GateSet`, and the dispatch would refuse it again, so that no gate
/// handler can run for that key even if `authorize` let one through.
#[test]
fn the_bootstrap_key_never_reaches_a_gate_handler() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(10);
    for reason in GateReason::ALL {
        assert_eq!(
            line_reply(
                &paths,
                &node,
                session(Role::Bootstrap),
                LineRequest::GateSet { reason: *reason }
            ),
            Err(AgentError::RoleNotPermitted {
                role: Role::Bootstrap,
                request: RequestKind::GateSet,
            })
        );
    }
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
    assert!(!paths.gate_dir().exists());
}

#[test]
fn the_transaction_requests_reach_their_handlers() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_000);
    let one = Generation::new(1);
    let apply = |generation| frame(&LineRequest::Apply(Box::new(header(generation))));
    let status = frame(&LineRequest::TxnStatus { generation: one });
    assert_eq!(
        ask(&paths, &node, Role::Ops, apply(1)),
        Ok(Response::TxnLaunched { generation: one })
    );
    assert_eq!(
        node.calls(),
        vec![
            "/usr/bin/systemd-run --unit=mooring-txn-1 --collect --quiet \
             /usr/local/lib/mooring/agent/current txn 1"
                .to_owned()
        ]
    );
    assert_eq!(
        ask(&paths, &node, Role::Ops, status.clone()),
        Ok(Response::TxnStatus {
            generation: one,
            state: TxnState::Running {
                stage: TxnStage::Preconditions
            },
        })
    );
    // Launched but never run: the rollback has switched nothing to undo.
    assert_eq!(
        ask(&paths, &node, Role::Ops, frame(&LineRequest::Rollback)),
        Ok(Response::Reverted { generation: one })
    );
    assert_eq!(
        ask(&paths, &node, Role::Ops, status.clone()),
        Ok(Response::TxnStatus {
            generation: one,
            state: TxnState::Reverted,
        })
    );
    // As the transaction's unit leaves a change it ran through.
    assert_eq!(
        ask(&paths, &node, Role::Ops, apply(2)),
        Ok(Response::TxnLaunched {
            generation: Generation::new(2)
        })
    );
    set_pending(
        &paths,
        &Pending {
            generation: Generation::new(2),
            change: Change::Apply {
                previous: Generation::ZERO,
            },
            phase: Phase::AwaitingConfirm,
        },
    )
    .unwrap();
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::Confirm {
                generation: Generation::new(2)
            })
        ),
        Ok(Response::Confirmed {
            generation: Generation::new(2)
        })
    );
    assert_eq!(
        node.calls().last().map(String::as_str),
        Some("/usr/bin/systemctl stop mooring-txn-revert-2.timer")
    );
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::TxnStatus {
                generation: Generation::new(2)
            })
        ),
        Ok(Response::TxnStatus {
            generation: Generation::new(2),
            state: TxnState::Committed,
        })
    );
    // The viewer may ask none of them.
    for (request, kind) in [
        (apply(3), RequestKind::Apply),
        (status, RequestKind::TxnStatus),
        (frame(&LineRequest::Rollback), RequestKind::Rollback),
    ] {
        assert_eq!(
            ask(&paths, &node, Role::Viewer, request),
            Err(AgentError::RoleNotPermitted {
                role: Role::Viewer,
                request: kind,
            })
        );
    }
}

#[test]
fn an_apply_of_the_bundle_the_node_runs_is_unchanged() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_000);
    let four = Generation::new(4);
    let dir = paths.generation(four);
    write_json(&dir.join(BUNDLE_FILE), &header(4), 0o644).unwrap();
    symlink("gen-4", paths.current()).unwrap();
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::Apply(Box::new(header(4))))
        ),
        Ok(Response::Unchanged { generation: four })
    );
    assert!(node.calls().is_empty(), "{:#?}", node.calls());
}

#[test]
fn an_activation_and_a_resume_reach_their_handlers() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(1_000).programs(Box::new(|_, args| {
        Ok(match args {
            ["self-test"] => ok(b"1\n"),
            _ => ok(b""),
        })
    }));
    let binary = b"new agent binary";
    let agent = sha("new agent binary");
    put(
        &paths,
        agent,
        BlobLen::new(binary.len() as u64).unwrap(),
        &mut Cursor::new(binary.to_vec()),
    )
    .unwrap();
    fs::create_dir_all(paths.agent_dir()).unwrap();
    symlink("old-agent", paths.agent_current()).unwrap();
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::ActivateAgent { sha: agent })
        ),
        Ok(Response::AwaitingConfirm {
            generation: Generation::ZERO
        })
    );
    assert_eq!(
        fs::read_link(paths.agent_current()).unwrap(),
        std::path::Path::new(&agent.to_string())
    );
    // `Resume` reaches its handler, which resumes only a halted node.
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::Resume {
                config_generation: Generation::ZERO
            })
        ),
        Err(AgentError::Busy {
            generation: Generation::ZERO
        }),
        "the activation awaits its confirmation"
    );
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::Confirm {
                generation: Generation::ZERO
            })
        ),
        Ok(Response::Confirmed {
            generation: Generation::ZERO
        })
    );
    assert_eq!(
        ask(
            &paths,
            &node,
            Role::Ops,
            frame(&LineRequest::Resume {
                config_generation: Generation::ZERO
            })
        ),
        Err(AgentError::NotHalted)
    );
}

/// A `Hello` the node cannot answer is the reply's error.
#[test]
fn a_hello_the_node_cannot_answer_is_its_error() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    assert_eq!(
        ask(&paths, &node, Role::Ops, frame(&LineRequest::Hello)),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(ENOENT),
        })
    );
}
