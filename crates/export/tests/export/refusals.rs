// SPDX-License-Identifier: GPL-3.0-or-later

//! Every refusal of `export_user`, through the public API.

use std::collections::BTreeMap;

use mooring_export::{ExportError, ExportErrorKind, ExportFormat, NotApplied, export_user};
use mooring_fixtures::FIXTURE_NOW;
use mooring_model::node::LifecycleStage;
use mooring_model::secret::{SecretRef, SecretSnapshotError};
use mooring_model::{
    Capability, ClientLine, Deployment, LocalLabel, ModelError, NodeLifecycle, UserId, UserStatus,
};

use crate::support::{edited, first_user, node, profile, two_nodes, with_profile};

fn refusal(deployment: &Deployment, user: &UserId) -> ExportError {
    let fixture = two_nodes();
    let error = export_user(
        deployment,
        &fixture.secrets,
        user,
        ExportFormat::SingBoxJson,
        FIXTURE_NOW,
    )
    .unwrap_err();
    // Both formats refuse identically.
    let clash = export_user(
        deployment,
        &fixture.secrets,
        user,
        ExportFormat::ClashYaml,
        FIXTURE_NOW,
    )
    .unwrap_err();
    assert_eq!(clash.kind(), error.kind());
    error
}

#[test]
fn an_unknown_user_is_a_model_error() {
    let fixture = two_nodes();
    let stranger = UserId::parse("zzzzzzzzzz").unwrap();
    let error = refusal(&fixture.deployment, &stranger);
    assert_eq!(error.kind(), ExportErrorKind::Model);
    assert!(
        matches!(error, ExportError::Model(ModelError::UnknownUser { ref id }) if *id == stranger)
    );
}

#[test]
fn inactive_users_are_refused() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let pending = edited(&fixture.deployment, |parts| {
        parts.users[0].status = UserStatus::RevokePending;
    });
    let revoked = edited(&fixture.deployment, |parts| {
        parts.users[0].status = UserStatus::Revoked;
        parts.users[0].per_node = BTreeMap::new();
    });
    for deployment in [pending, revoked] {
        let error = refusal(&deployment, &user);
        assert_eq!(error.kind(), ExportErrorKind::UserNotActive);
        assert!(matches!(error, ExportError::UserNotActive { user: ref u } if *u == user));
    }
}

#[test]
fn a_user_without_credentials_has_nothing_to_export() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let deployment = edited(&fixture.deployment, |parts| {
        parts.users[0].per_node = BTreeMap::new();
    });
    let error = refusal(&deployment, &user);
    assert_eq!(error.kind(), ExportErrorKind::NothingToExport);
}

#[test]
fn nodes_must_have_confirmed_the_current_generation() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    for (lifecycle_of, stage) in [
        (
            (|site| NodeLifecycle::Adopted { site }) as fn(_) -> NodeLifecycle,
            LifecycleStage::Adopted,
        ),
        (
            |site| NodeLifecycle::Retiring { site },
            LifecycleStage::Retiring,
        ),
    ] {
        let deployment = edited(&fixture.deployment, |parts| {
            let ams1 = parts
                .nodes
                .iter_mut()
                .find(|n| n.id == node("ams1"))
                .unwrap();
            ams1.lifecycle = lifecycle_of(ams1.lifecycle.site().unwrap().clone());
        });
        let error = refusal(&deployment, &user);
        assert_eq!(error.kind(), ExportErrorKind::NodeNotApplied);
        assert!(matches!(
            error,
            ExportError::NodeNotApplied { node: ref n, reason: NotApplied::Stage(s) }
                if *n == node("ams1") && s == stage
        ));
    }
    let stale = edited(&fixture.deployment, |parts| {
        parts.config_generation = parts.config_generation.next().unwrap();
    });
    let error = refusal(&stale, &user);
    // lon1 is the primary, so it is checked first.
    assert!(matches!(
        error,
        ExportError::NodeNotApplied { node: ref n, reason: NotApplied::Stale { applied, current } }
            if *n == node("lon1") && applied < current
    ));
}

#[test]
fn a_capability_the_line_does_not_accept_is_refused() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let deployment = with_profile(
        &fixture.deployment,
        &user,
        &profile(ClientLine::Cfm04, &[Capability::RealityMlkemOptIn]),
    );
    let error = refusal(&deployment, &user);
    assert_eq!(error.kind(), ExportErrorKind::CapabilityUnsupported);
    assert!(matches!(
        error,
        ExportError::CapabilityUnsupported {
            line: ClientLine::Cfm04,
            cap: Capability::RealityMlkemOptIn
        }
    ));
}

#[test]
fn a_missing_credential_is_a_secret_error() {
    let fixture = two_nodes();
    let newcomer = UserId::parse("newcomeraa").unwrap();
    let deployment = edited(&fixture.deployment, |parts| {
        let mut user = parts.users[0].clone();
        user.id = newcomer.clone();
        user.label = LocalLabel::parse("Newcomer").unwrap();
        // Short ids are unique per node.
        for public in user.per_node.values_mut() {
            public.short_id = "0123456789abcdef".parse().unwrap();
        }
        parts.users.push(user);
    });
    let error = refusal(&deployment, &newcomer);
    assert_eq!(error.kind(), ExportErrorKind::Secret);
    assert!(matches!(
        error,
        ExportError::Secret(SecretSnapshotError::Missing {
            secret_ref: SecretRef::UserVlessUuid(ref u, ref n)
        }) if *u == newcomer && *n == node("lon1")
    ));
}
