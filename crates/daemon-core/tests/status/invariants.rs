// SPDX-License-Identifier: GPL-3.0-or-later

//! The status document's invariants: every node it names has a row, user
//! rows agree with the usage view, open alerts are listed once and in
//! order, the version is 1, and every key is required and known.

use std::net::Ipv4Addr;

use mooring_daemon_core::alert::{AlertCondition, OpenAlert, Severity};
use mooring_daemon_core::status::{DegradedReason, DownReason, ExitState, Latch, UsageView};
use mooring_daemon_core::{
    MacStatusParts, MacStatusV1, StatusError, StatusErrorKind, UsageErrorKind,
};
use mooring_model::collections::NonEmpty;
use mooring_model::verdict::Violation;
use mooring_model::{NodeId, UnixTime};

use crate::scenarios;
use crate::support::node;

fn serving() -> MacStatusParts {
    scenarios::all().remove(0).1.into_parts()
}

fn degraded() -> MacStatusParts {
    scenarios::all().remove(1).1.into_parts()
}

fn ghost() -> NodeId {
    node("ghost1")
}

fn unknown_node(parts: MacStatusParts) {
    assert_eq!(
        MacStatusV1::new(parts),
        Err(StatusError::UnknownNode { node: ghost() })
    );
}

/// Each place a status names a node, pointed at a node with no row.
#[test]
fn every_node_named_has_a_row() {
    assert!(MacStatusV1::new(serving()).is_ok());
    let first_user = |parts: &mut MacStatusParts| parts.users.values_mut().next().unwrap().clone();
    let mut parts = serving();
    parts
        .users
        .values_mut()
        .next()
        .unwrap()
        .nodes
        .insert(ghost());
    unknown_node(parts);

    let mut parts = serving();
    let mut row = first_user(&mut parts);
    let activity = row.activity.by_node.values().next().copied().unwrap();
    row.activity.by_node.insert(ghost(), activity);
    *parts.users.values_mut().next().unwrap() = row;
    unknown_node(parts);

    // A usage row whose cycle (and so its shares) was carried by a node
    // with no row: the figures stay consistent, the node is unknown.
    let mut parts = serving();
    let row = parts.users.values_mut().next().unwrap();
    let usage = row.usage.as_ref().unwrap();
    let mut value = serde_json::to_value(usage).unwrap();
    for path in ["/cycle_by_node", "/cycle_shares/by_node"] {
        let map = value.pointer_mut(path).unwrap().as_object_mut().unwrap();
        let carried = map.remove("lon1").unwrap();
        map.insert(ghost().as_str().to_owned(), carried);
    }
    row.usage = Some(serde_json::from_value(value).unwrap());
    unknown_node(parts);

    let mut parts = serving();
    parts.alerts = vec![OpenAlert {
        severity: Severity::Critical,
        condition: AlertCondition::MacSilent { node: ghost() },
        active_since: UnixTime::from_secs(1),
        raised_at: UnixTime::from_secs(1),
    }];
    unknown_node(parts);

    let mut parts = serving();
    parts.exit.state = ExitState::Degraded {
        reasons: NonEmpty::from_parts(
            DegradedReason::OnBattery,
            vec![DegradedReason::WatchStale { node: ghost() }],
        ),
    };
    unknown_node(parts);

    for reason in [
        DownReason::AgentNotEnabled { node: ghost() },
        DownReason::DirectProbeFailed {
            node: ghost(),
            stage: mooring_daemon_core::status::ProbeStage::Read,
        },
        DownReason::Violation(Violation::EgressIsNodeAddress {
            node: ghost(),
            ip: Ipv4Addr::new(45, 67, 89, 10),
        }),
    ] {
        let mut parts = serving();
        parts.exit.state = ExitState::Down { reason };
        unknown_node(parts);
    }

    let mut parts = serving();
    parts.exit.latches.push(Latch {
        violation: Violation::EgressIsNodeAddress {
            node: ghost(),
            ip: Ipv4Addr::new(45, 67, 89, 10),
        },
        at: UnixTime::from_secs(1),
    });
    unknown_node(parts);

    // Removing a node row that a user still names is caught too.
    let mut parts = serving();
    parts.nodes.remove(&node("ams1"));
    assert_eq!(
        MacStatusV1::new(parts),
        Err(StatusError::UnknownNode { node: node("ams1") })
    );
}

#[test]
fn user_rows_carry_usage_exactly_when_the_view_is_a_report() {
    let mut parts = serving();
    let user = parts.users.keys().nth(1).unwrap().clone();
    parts.users.get_mut(&user).unwrap().usage = None;
    assert_eq!(
        MacStatusV1::new(parts),
        Err(StatusError::UsageMismatch { user })
    );
    let mut parts = serving();
    parts.usage = UsageView::Unavailable {
        reason: UsageErrorKind::NotCoveredThrough,
    };
    let first = parts.users.keys().next().unwrap().clone();
    assert_eq!(
        MacStatusV1::new(parts.clone()),
        Err(StatusError::UsageMismatch { user: first })
    );
    for row in parts.users.values_mut() {
        row.usage = None;
    }
    assert!(MacStatusV1::new(parts).is_ok());
}

#[test]
fn open_alerts_are_listed_once_in_key_order() {
    let parts = degraded();
    assert!(
        parts.alerts.len() >= 3,
        "the degraded scenario has open alerts"
    );
    let mut repeated = parts.clone();
    let again = repeated.alerts[1].clone();
    repeated.alerts.insert(2, again.clone());
    assert_eq!(
        MacStatusV1::new(repeated),
        Err(StatusError::AlertsNotOrdered { key: again.key() })
    );
    let mut swapped = parts;
    swapped.alerts.swap(0, 1);
    let out_of_place = swapped.alerts[1].key();
    assert_eq!(
        MacStatusV1::new(swapped),
        Err(StatusError::AlertsNotOrdered { key: out_of_place })
    );
}

fn json(parts: MacStatusParts) -> serde_json::Value {
    serde_json::to_value(MacStatusV1::new(parts).unwrap()).unwrap()
}

#[test]
fn the_document_is_version_1_with_every_key_required_and_known() {
    let document = json(serving());
    assert_eq!(document["version"], 1);
    for version in [0, 2, u32::MAX] {
        let mut other = document.clone();
        other["version"] = version.into();
        let error = serde_json::from_value::<MacStatusV1>(other).unwrap_err();
        assert!(
            error.to_string().contains(&format!("not {version}")),
            "{error}"
        );
    }
    let mut extra = document.clone();
    extra["labels"] = serde_json::json!({});
    assert!(serde_json::from_value::<MacStatusV1>(extra).is_err());
    // Every top-level key, and the optional ones inside, are required.
    for key in [
        "version", "at", "exit", "sim", "router", "capacity", "usage", "users", "nodes", "alerts",
    ] {
        let mut missing = document.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<MacStatusV1>(missing).is_err(),
            "{key}"
        );
    }
    for path in [
        ["exit", "egress"],
        ["exit", "carrier_check"],
        ["sim", "thresholds"],
    ] {
        let mut missing = document.clone();
        missing[path[0]].as_object_mut().unwrap().remove(path[1]);
        assert!(
            serde_json::from_value::<MacStatusV1>(missing).is_err(),
            "{path:?}"
        );
    }
    let mut no_capacity = document.clone();
    no_capacity["capacity"] = serde_json::Value::Null;
    assert!(
        serde_json::from_value::<MacStatusV1>(no_capacity).is_ok(),
        "null is no sample yet"
    );
    let user = document["users"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    for key in ["alias", "usage", "activity", "quota", "expiry", "accuracy"] {
        let mut missing = document.clone();
        missing["users"][&user].as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<MacStatusV1>(missing).is_err(),
            "users.*.{key}"
        );
    }
    // A decoded document is checked like a built one.
    let mut ghost_row = document;
    ghost_row["users"][&user]["nodes"] = serde_json::json!(["ghost1"]);
    let error = serde_json::from_value::<MacStatusV1>(ghost_row).unwrap_err();
    assert!(error.to_string().contains("ghost1"), "{error}");
}

#[test]
fn every_status_error_kind_is_named_once() {
    let user = serving().users.keys().next().unwrap().clone();
    let key = degraded().alerts[0].key();
    let errors = [
        (
            StatusErrorKind::UnsupportedVersion,
            StatusError::UnsupportedVersion { found: 2 },
        ),
        (
            StatusErrorKind::UnknownNode,
            StatusError::UnknownNode { node: ghost() },
        ),
        (
            StatusErrorKind::UsageMismatch,
            StatusError::UsageMismatch { user },
        ),
        (
            StatusErrorKind::AlertsNotOrdered,
            StatusError::AlertsNotOrdered { key },
        ),
    ];
    for (kind, error) in &errors {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        StatusErrorKind::ALL
    );
}
