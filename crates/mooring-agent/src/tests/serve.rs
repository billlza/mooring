// SPDX-License-Identifier: GPL-3.0-or-later

//! The forced command end to end: one frame in, one reply out, the role
//! checked before anything is done, and every request either served or
//! answered `NotServedYet`.

use std::io::Cursor;

use mooring_agent_proto::{
    AgentError, BlobLen, ClearableHold, GateReason, Holds, LineRequest, Reply, Request,
    RequestKind, Response, Role, ShutdownReason, read_reply, write_put_blob, write_request,
};

use super::{FakeNode, nft_set, ok, scratch};
use crate::blobs::digest_of;
use crate::host::Tool;
use crate::paths::Paths;
use crate::serve::{Session, answer, serve};

const SSH: &str = "92.40.201.97 51234 176.126.246.203 22";

fn session(role: Role) -> Session<'static> {
    Session {
        role,
        ssh_connection: Some(SSH),
    }
}

fn frame(request: &LineRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_request(&mut bytes, request).unwrap();
    bytes
}

fn ask(paths: &Paths, node: &FakeNode, role: Role, bytes: Vec<u8>) -> Reply {
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

/// The requests this slice does not serve yet; the list shrinks as M4's
/// slices land, and `NotServedYet` goes when it is empty.
const NOT_SERVED_YET: [RequestKind; 13] = [
    RequestKind::ActivateAgent,
    RequestKind::Confirm,
    RequestKind::Bootstrap,
    RequestKind::RevokeBootstrap,
    RequestKind::Apply,
    RequestKind::TxnStatus,
    RequestKind::Rollback,
    RequestKind::Status,
    RequestKind::Usage,
    RequestKind::UsageSeries,
    RequestKind::Events,
    RequestKind::TargetCheck,
    RequestKind::Resume,
];

#[test]
fn requests_of_later_slices_are_answered_not_served_yet() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(0);
    let golden_requests =
        include_str!("../../../../contract/agent-proto-golden/hello.request.snap");
    assert!(golden_requests.contains("Hello"));
    for kind in NOT_SERVED_YET {
        let role = if kind == RequestKind::Bootstrap {
            Role::Bootstrap
        } else {
            Role::Ops
        };
        let request = super::requests::of(kind);
        assert_eq!(
            ask(&paths, &node, role, frame(&request)),
            Err(AgentError::NotServedYet { request: kind }),
            "{kind:?}"
        );
    }
    assert!(node.calls().is_empty());
    let served: Vec<RequestKind> = RequestKind::ALL
        .iter()
        .copied()
        .filter(|kind| !NOT_SERVED_YET.contains(kind))
        .collect();
    assert_eq!(
        served,
        [
            RequestKind::Hello,
            RequestKind::HaveBlobs,
            RequestKind::PutBlob,
            RequestKind::GateSet,
            RequestKind::ClearHold,
            RequestKind::Shutdown,
            RequestKind::PutMacReport,
            RequestKind::MacReport,
        ]
    );
}
