// SPDX-License-Identifier: GPL-3.0-or-later

//! The store keeps `config_generation` only for `Bookkeeping` records
//! (design §7), so each record must leave every node's bundle and every
//! user's export exactly as it was: a node that confirmed the generation
//! still serves exactly what the exports describe.

use std::collections::BTreeMap;

use mooring_export::{ExportFormat, export_user};
use mooring_fixtures::{FIXTURE_NOW, Fixture};
use mooring_model::node::{AppliedConfig, NodeLifecycle};
use mooring_model::user::UserStatus;
use mooring_model::{Bookkeeping, Deployment, NodeId, Sha256Digest, UserId};

use crate::tests::support::{edit, engines, node};
use crate::vps::bundle;

/// Everything a deployment renders that a generation stands for: the
/// bundle digest of every node that can be applied, and every export that
/// can be made, by user and format.
#[derive(Debug, PartialEq, Eq)]
struct Rendered {
    bundles: BTreeMap<NodeId, Sha256Digest>,
    exports: BTreeMap<(UserId, ExportFormat), Vec<u8>>,
}

fn rendered(fixture: &Fixture, deployment: &Deployment) -> Rendered {
    let catalog = engines();
    let bundles = deployment
        .nodes()
        .values()
        .filter(|node| node.apply_inputs().is_ok())
        .map(|node| {
            let bundle = bundle(deployment, &node.id, &fixture.secrets, &catalog).unwrap();
            (node.id.clone(), bundle.digest())
        })
        .collect();
    let mut exports = BTreeMap::new();
    for user in deployment.users().keys() {
        for format in ExportFormat::ALL {
            if let Ok(document) =
                export_user(deployment, &fixture.secrets, user, format, FIXTURE_NOW)
            {
                exports.insert((user.clone(), format), document.expose_bytes().to_vec());
            }
        }
    }
    Rendered { bundles, exports }
}

/// Records `entry` on `before` and checks that the generation stayed, no
/// bundle changed, and every export that could be made before is byte for
/// byte the same after. (Retiring a node can make an export possible that
/// was not: a user who held credentials on the retiring node.)
fn assert_neutral(fixture: &Fixture, before: &Deployment, entry: Bookkeeping) {
    let after = before.clone().record(entry.clone()).unwrap();
    assert_eq!(after.config_generation(), before.config_generation());
    assert_ne!(&after, before, "{entry:?} recorded nothing");
    let (old, new) = (rendered(fixture, before), rendered(fixture, &after));
    assert_eq!(old.bundles, new.bundles, "{entry:?} changed a bundle");
    assert!(!old.bundles.is_empty());
    for (key, document) in &old.exports {
        assert_eq!(
            new.exports.get(key),
            Some(document),
            "{entry:?} changed the export {key:?}"
        );
    }
}

#[test]
fn recording_an_apply_changes_no_bundle_and_no_export() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    assert!(!rendered(&fixture, &fixture.deployment).exports.is_empty());
    assert_neutral(
        &fixture,
        &fixture.deployment,
        Bookkeeping::Applied {
            node: node("ams1"),
            applied: AppliedConfig {
                config_generation: fixture.deployment.config_generation(),
                digest: Sha256Digest::from_bytes([0x42; 32]),
            },
        },
    );
}

#[test]
fn committing_a_revocation_changes_no_bundle_and_no_export() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let revoking = edit(&fixture.deployment, |parts| {
        parts.users[2].status = UserStatus::RevokePending;
    });
    let user = revoking.users().keys().nth(2).unwrap().clone();
    assert_neutral(
        &fixture,
        &revoking,
        Bookkeeping::RevocationCommitted {
            user: user.clone(),
            node: node("lon1"),
        },
    );
    // The last commit revokes the user, still without a rendered change.
    let one_left = revoking
        .record(Bookkeeping::RevocationCommitted {
            user: user.clone(),
            node: node("lon1"),
        })
        .unwrap();
    assert_neutral(
        &fixture,
        &one_left,
        Bookkeeping::RevocationCommitted {
            user,
            node: node("ams1"),
        },
    );
}

#[test]
fn shutting_down_a_retiring_node_changes_no_bundle_and_no_export() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let retiring = edit(&fixture.deployment, |parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|candidate| candidate.id == node("ams1"))
            .unwrap();
        let site = ams1.lifecycle.site().unwrap().clone();
        ams1.lifecycle = NodeLifecycle::Retiring { site };
    });
    assert_neutral(
        &fixture,
        &retiring,
        Bookkeeping::RetirementShutDown { node: node("ams1") },
    );
}
