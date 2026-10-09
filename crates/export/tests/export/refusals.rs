// SPDX-License-Identifier: GPL-3.0-or-later

//! Every refusal of `export_user`, through the public API.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use mooring_export::{ExportError, ExportErrorKind, ExportFormat, NotApplied, export_user};
use mooring_fixtures::FIXTURE_NOW;
use mooring_model::node::LifecycleStage;
use mooring_model::secret::{SecretRef, SecretSnapshotError};
use mooring_model::{
    CalendarDate, Capability, ClientLine, Deployment, LocalLabel, ModelError, NodeLifecycle,
    QuotaAction, SuspendReason, UnixTime, UserId, UserPolicy, UserQuota, UserStatus, WarnPercent,
};

use crate::support::{edited, export, first_user, node, profile, two_nodes, with_profile};

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
    let suspended: Vec<Deployment> = [
        SuspendReason::Operator,
        SuspendReason::QuotaExceeded {
            cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
        },
        SuspendReason::Expired,
        SuspendReason::AbuseReview,
    ]
    .into_iter()
    .map(|reason| {
        edited(&fixture.deployment, |parts| {
            parts.users[0].suspend(reason, FIXTURE_NOW).unwrap();
        })
    })
    .collect();
    for deployment in [pending, revoked].into_iter().chain(suspended) {
        let error = refusal(&deployment, &user);
        assert_eq!(error.kind(), ExportErrorKind::UserNotActive);
        assert!(matches!(error, ExportError::UserNotActive { user: ref u } if *u == user));
    }
}

/// A suspended user keeps its credentials, so resuming it restores the
/// exact file it had: nothing new has to be delivered.
#[test]
fn resuming_a_suspended_user_restores_its_file() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let before = export(
        &fixture,
        &fixture.deployment,
        &user,
        ExportFormat::SingBoxJson,
    );
    let resumed = edited(&fixture.deployment, |parts| {
        parts.users[0]
            .suspend(SuspendReason::Operator, FIXTURE_NOW)
            .unwrap();
        parts.users[0].resume().unwrap();
    });
    let after = export(&fixture, &resumed, &user, ExportFormat::SingBoxJson);
    assert_eq!(after.expose_bytes(), before.expose_bytes());
}

/// Export looks only at the status: a user whose expiry has passed is still
/// exported until an explicit action suspends it (`Suspended { Expired }`),
/// and a quota changes nothing by itself.
#[test]
fn an_expired_or_quota_bound_active_user_is_still_exported() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let before = export(
        &fixture,
        &fixture.deployment,
        &user,
        ExportFormat::SingBoxJson,
    );
    let policed = edited(&fixture.deployment, |parts| {
        parts.users[0].policy = UserPolicy {
            expires_at: Some(UnixTime::from_secs(FIXTURE_NOW.as_secs() - 1)),
            quota: Some(UserQuota {
                cycle_served_bytes: NonZeroU64::new(1).unwrap(),
                warn_percent: WarnPercent::new(80).unwrap(),
                action: QuotaAction::Suspend,
            }),
        };
    });
    let after = export(&fixture, &policed, &user, ExportFormat::SingBoxJson);
    assert_eq!(after.expose_bytes(), before.expose_bytes());
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
