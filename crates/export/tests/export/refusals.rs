// SPDX-License-Identifier: GPL-3.0-or-later

//! Every refusal of `export_user`, through the public API.

use std::collections::BTreeMap;
use std::num::{NonZeroU16, NonZeroU64};

use mooring_export::{ExportError, ExportErrorKind, ExportFormat, NotApplied, export_user};
use mooring_fixtures::FIXTURE_NOW;
use mooring_model::node::LifecycleStage;
use mooring_model::secret::{SecretRef, SecretSnapshotError};
use mooring_model::{
    AgreementRecord, AgreementVersion, CalendarDate, Capability, ClientLine, Deployment,
    DeploymentParts, LocalLabel, ModelError, NodeLifecycle, QuotaAction, SecretSnapshot,
    SuspendReason, UnixTime, UserId, UserPolicy, UserQuota, UserStatus, WarnPercent,
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

/// Decision F9: a file goes only to a user who accepted the agreement
/// revision this build ships. No record, or a record of another revision,
/// is refused, and the error names both revisions.
#[test]
fn a_user_without_the_current_agreement_is_refused() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let newer =
        AgreementVersion::new(NonZeroU16::new(AgreementVersion::CURRENT.get() + 1).unwrap());
    for recorded in [None, Some(newer)] {
        let deployment = edited(&fixture.deployment, |parts| {
            parts.users[0].agreement = recorded.map(|version| AgreementRecord {
                version,
                accepted_on: CalendarDate::parse("2026-10-08").unwrap(),
            });
        });
        let error = refusal(&deployment, &user);
        assert_eq!(error.kind(), ExportErrorKind::AgreementNotAccepted);
        assert!(
            matches!(
                error,
                ExportError::AgreementNotAccepted { user: ref u, recorded: r, required }
                    if *u == user && r == recorded && required == AgreementVersion::CURRENT
            ),
            "{error:?}"
        );
        let detail = match recorded {
            None => "no acceptance is recorded".to_owned(),
            Some(version) => format!("the recorded acceptance is of revision {version}"),
        };
        assert_eq!(
            error.to_string(),
            format!("user {user} has not accepted agreement revision 1: {detail}")
        );
    }
}

/// The agreement is checked after the status, because an inactive user is
/// refused for that whatever its record, and before anything about the
/// file: no capability, node, generation or secret decides the refusal of
/// a user who has not agreed.
#[test]
fn the_agreement_is_checked_after_the_status_and_before_the_file() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let without = |change: fn(&mut DeploymentParts)| {
        edited(&fixture.deployment, |parts| {
            parts.users[0].agreement = None;
            change(parts);
        })
    };
    let suspended = without(|parts| {
        parts.users[0]
            .suspend(SuspendReason::Operator, FIXTURE_NOW)
            .unwrap();
    });
    assert_eq!(
        refusal(&suspended, &user).kind(),
        ExportErrorKind::UserNotActive
    );
    let unsupported = without(|parts| {
        parts.users[0].client = profile(ClientLine::Cfm04, &[Capability::RealityMlkemOptIn]);
    });
    let bare = without(|parts| parts.users[0].per_node = BTreeMap::new());
    let stale = without(|parts| {
        parts.config_generation = parts.config_generation.next().unwrap();
    });
    for deployment in [unsupported, bare, stale] {
        assert_eq!(
            refusal(&deployment, &user).kind(),
            ExportErrorKind::AgreementNotAccepted
        );
    }
    // Nor is any secret read.
    let error = export_user(
        &without(|_| {}),
        &SecretSnapshot::new(),
        &user,
        ExportFormat::SingBoxJson,
        FIXTURE_NOW,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ExportErrorKind::AgreementNotAccepted);
}

/// The record's day is never compared with `now`: it is a calendar day
/// without a time zone. Nor does the record change anything in the file.
#[test]
fn the_agreement_day_is_not_compared_with_now_and_changes_nothing_in_the_file() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    for format in [ExportFormat::SingBoxJson, ExportFormat::ClashYaml] {
        let before = export(&fixture, &fixture.deployment, &user, format);
        for day in ["1970-01-01", "2026-10-09", "9999-12-31"] {
            let deployment = edited(&fixture.deployment, |parts| {
                parts.users[0].agreement = Some(AgreementRecord {
                    version: AgreementVersion::CURRENT,
                    accepted_on: CalendarDate::parse(day).unwrap(),
                });
            });
            let after = export(&fixture, &deployment, &user, format);
            assert_eq!(after.expose_bytes(), before.expose_bytes(), "{day}");
        }
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
