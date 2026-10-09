// SPDX-License-Identifier: GPL-3.0-or-later

//! The role permission table (design §11.1 "Roles") and the viewer's
//! emergency-stop rule (design §15.9, decision F5).

use mooring_agent_proto::{
    AgentError, AgentErrorKind, GateReason, LineRequest, Request, RequestKind, Role,
    VIEWER_STOP_WAIT_SECS, WATCH_TICK_SECS,
};

use crate::fixtures;

/// The expected table, written out independently of the implementation:
/// `(request, bootstrap role may send, ops role may send, viewer role may
/// send)`.
const TABLE: &[(RequestKind, bool, bool, bool)] = &[
    (RequestKind::Hello, false, true, false),
    (RequestKind::HaveBlobs, false, true, false),
    (RequestKind::PutBlob, false, true, false),
    (RequestKind::ActivateAgent, false, true, false),
    (RequestKind::Confirm, false, true, false),
    (RequestKind::Bootstrap, true, false, false),
    (RequestKind::RevokeBootstrap, false, true, false),
    (RequestKind::Apply, false, true, false),
    (RequestKind::TxnStatus, false, true, false),
    (RequestKind::Rollback, false, true, false),
    (RequestKind::Status, false, true, true),
    (RequestKind::Usage, false, true, true),
    (RequestKind::UsageSeries, false, true, true),
    (RequestKind::Events, false, true, true),
    (RequestKind::TargetCheck, false, true, false),
    (RequestKind::GateSet, false, true, true),
    (RequestKind::ClearHold, false, true, false),
    (RequestKind::Shutdown, false, true, false),
    (RequestKind::Resume, false, true, false),
    (RequestKind::PutMacReport, false, true, false),
    (RequestKind::MacReport, false, true, true),
];

/// The roles of a row, with whether each may send the request.
fn row_roles(bootstrap: bool, ops: bool, viewer: bool) -> [(Role, bool); 3] {
    [
        (Role::Bootstrap, bootstrap),
        (Role::Ops, ops),
        (Role::Viewer, viewer),
    ]
}

#[test]
fn the_table_lists_every_request_and_role_once() {
    let listed: Vec<RequestKind> = TABLE.iter().map(|(kind, ..)| *kind).collect();
    assert_eq!(listed, RequestKind::ALL);
    let roles: Vec<Role> = row_roles(false, false, false)
        .iter()
        .map(|(role, _)| *role)
        .collect();
    assert_eq!(roles, Role::ALL);
}

#[test]
fn each_role_is_permitted_exactly_the_tabled_requests() {
    for (kind, bootstrap, ops, viewer) in TABLE {
        for (role, permitted) in row_roles(*bootstrap, *ops, *viewer) {
            assert_eq!(role.permits(*kind), permitted, "{role:?} {kind:?}");
        }
    }
}

/// Every fixture request is checked by kind; the fixture `GateSet` closes
/// the gate for `MacDrain`, which the viewer may not (see below), so for
/// the viewer it fails on its reason instead.
#[test]
fn authorize_refuses_with_a_typed_error_naming_role_and_request() {
    for (kind, bootstrap, ops, viewer) in TABLE {
        let request = fixtures::request(*kind);
        assert_eq!(request.kind(), *kind);
        for (role, permitted) in row_roles(*bootstrap, *ops, *viewer) {
            let expected = if !permitted {
                Err(AgentError::RoleNotPermitted {
                    role,
                    request: *kind,
                })
            } else if (role, *kind) == (Role::Viewer, RequestKind::GateSet) {
                Err(AgentError::GateReasonNotPermitted {
                    role,
                    reason: GateReason::MacDrain,
                })
            } else {
                Ok(())
            };
            assert_eq!(request.authorize(role), expected, "{role:?} {kind:?}");
        }
    }
}

#[test]
fn bootstrap_is_the_bootstrap_roles_only_request() {
    let bootstrap_only: Vec<_> = RequestKind::ALL
        .iter()
        .filter(|kind| Role::Bootstrap.permits(**kind))
        .collect();
    assert_eq!(bootstrap_only, [&RequestKind::Bootstrap]);
    assert!(!Role::Ops.permits(RequestKind::Bootstrap));
    assert!(Role::Ops.permits(RequestKind::RevokeBootstrap));
    assert!(!Role::Bootstrap.permits(RequestKind::RevokeBootstrap));
}

/// The viewer reads and may stop, never more: every request it may send
/// is one the ops role may send too, and none of them changes the
/// configuration, clears a hold, halts or resumes the node, or stores a
/// report.
#[test]
fn the_viewer_only_reads_and_stops() {
    let viewer: Vec<RequestKind> = RequestKind::ALL
        .iter()
        .copied()
        .filter(|kind| Role::Viewer.permits(*kind))
        .collect();
    assert_eq!(
        viewer,
        [
            RequestKind::Status,
            RequestKind::Usage,
            RequestKind::UsageSeries,
            RequestKind::Events,
            RequestKind::GateSet,
            RequestKind::MacReport,
        ]
    );
    assert!(viewer.iter().all(|kind| Role::Ops.permits(*kind)));
    assert!(viewer.iter().all(|kind| !kind.is_frozen_core()));
}

/// The expected gate rule over every role and reason: the ops role may
/// close the gate for any reason, the viewer for the operator hold only,
/// the bootstrap key for none.
#[test]
fn the_viewer_may_close_the_gate_only_for_the_operator_hold() {
    for role in Role::ALL {
        for reason in GateReason::ALL {
            let expected = match role {
                Role::Bootstrap => false,
                Role::Ops => true,
                Role::Viewer => *reason == GateReason::Operator,
            };
            assert_eq!(
                role.may_close_gate_for(*reason),
                expected,
                "{role:?} {reason:?}"
            );
            let request = Request::Line(LineRequest::GateSet { reason: *reason });
            let decision = if !role.permits(RequestKind::GateSet) {
                Err(AgentError::RoleNotPermitted {
                    role: *role,
                    request: RequestKind::GateSet,
                })
            } else if expected {
                Ok(())
            } else {
                Err(AgentError::GateReasonNotPermitted {
                    role: *role,
                    reason: *reason,
                })
            };
            assert_eq!(request.authorize(*role), decision, "{role:?} {reason:?}");
        }
    }
    assert_eq!(
        AgentError::GateReasonNotPermitted {
            role: Role::Viewer,
            reason: GateReason::EgressViolation,
        }
        .to_string(),
        "role viewer may not close the gate for EgressViolation"
    );
}

/// The two tables agree: a role may send `GateSet` exactly when it may
/// close the gate for some reason, so neither check can admit what the
/// other refuses.
#[test]
fn the_gate_rule_agrees_with_the_permission_table() {
    for role in Role::ALL {
        assert_eq!(
            role.permits(RequestKind::GateSet),
            GateReason::ALL
                .iter()
                .any(|reason| role.may_close_gate_for(*reason)),
            "{role:?}"
        );
    }
}

/// The viewer's stop is done by the watch, so the viewer handler waits for
/// it for at most three watch ticks; a stop the watch did not confirm in
/// that time has its own error, which says the gate may still be open and
/// survives the wire, and is never a `GateClosed` (design §11.3).
#[test]
fn an_unconfirmed_viewer_stop_is_an_error_never_a_success() {
    assert_eq!(VIEWER_STOP_WAIT_SECS, 3 * WATCH_TICK_SECS);
    assert_eq!(VIEWER_STOP_WAIT_SECS, 15);
    let error = AgentError::GateStopUnconfirmed {
        waited_secs: VIEWER_STOP_WAIT_SECS,
    };
    assert_eq!(error.kind(), AgentErrorKind::GateStopUnconfirmed);
    assert_eq!(
        error.to_string(),
        "the stop was not confirmed within 15 s; the gate may still be open"
    );
    let json = serde_json::to_string(&error).unwrap();
    assert_eq!(json, r#"{"GateStopUnconfirmed":{"waited_secs":15}}"#);
    assert_eq!(serde_json::from_str::<AgentError>(&json).unwrap(), error);
}
