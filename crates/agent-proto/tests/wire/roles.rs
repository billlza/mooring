// SPDX-License-Identifier: GPL-3.0-or-later

//! The role permission table (design §11.1 "Roles").

use mooring_agent_proto::{AgentError, RequestKind, Role};

use crate::fixtures;

/// The expected table, written out independently of the implementation:
/// `(request, bootstrap role may send, ops role may send)`.
const TABLE: &[(RequestKind, bool, bool)] = &[
    (RequestKind::Hello, false, true),
    (RequestKind::HaveBlobs, false, true),
    (RequestKind::PutBlob, false, true),
    (RequestKind::ActivateAgent, false, true),
    (RequestKind::Confirm, false, true),
    (RequestKind::Bootstrap, true, false),
    (RequestKind::RevokeBootstrap, false, true),
    (RequestKind::Apply, false, true),
    (RequestKind::TxnStatus, false, true),
    (RequestKind::Rollback, false, true),
    (RequestKind::Status, false, true),
    (RequestKind::Usage, false, true),
    (RequestKind::TargetCheck, false, true),
    (RequestKind::GateSet, false, true),
    (RequestKind::ClearHold, false, true),
    (RequestKind::Shutdown, false, true),
    (RequestKind::Resume, false, true),
];

#[test]
fn the_table_lists_every_request_once() {
    let listed: Vec<RequestKind> = TABLE.iter().map(|(kind, _, _)| *kind).collect();
    assert_eq!(listed, RequestKind::ALL);
}

#[test]
fn each_role_is_permitted_exactly_the_tabled_requests() {
    for (kind, bootstrap, ops) in TABLE {
        assert_eq!(
            Role::Bootstrap.permits(*kind),
            *bootstrap,
            "bootstrap role, {kind:?}"
        );
        assert_eq!(Role::Ops.permits(*kind), *ops, "ops role, {kind:?}");
    }
}

#[test]
fn authorize_refuses_with_a_typed_error_naming_role_and_request() {
    for (kind, bootstrap, ops) in TABLE {
        let request = fixtures::request(*kind);
        assert_eq!(request.kind(), *kind);
        for (role, permitted) in [(Role::Bootstrap, *bootstrap), (Role::Ops, *ops)] {
            let expected = if permitted {
                Ok(())
            } else {
                Err(AgentError::RoleNotPermitted {
                    role,
                    request: *kind,
                })
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
