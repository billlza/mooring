// SPDX-License-Identifier: GPL-3.0-or-later

//! `export_secret_refs` lists exactly the secrets an export of the user
//! reads, after the same checks in the same order as `export_user`, so a
//! caller reads a secret store only for a user the export would not refuse
//! before reading a secret (design §9.2).

use std::collections::BTreeMap;

use mooring_export::{ExportFormat, export_secret_refs, export_user};
use mooring_fixtures::{FIXTURE_NOW, Fixture};
use mooring_model::{
    Capability, ClientLine, Deployment, DeploymentParts, SecretEntry, SecretRef, SecretSnapshot,
    SuspendReason, UnixTime, UserId, UserStatus,
};

use crate::support::{edited, first_user, fixtures, profile, two_nodes};

/// An edit of the fixture's deployment.
type Edit = fn(&mut DeploymentParts);

/// A snapshot holding `refs` only, copied from the fixture's secrets.
fn snapshot_of<'a>(
    fixture: &Fixture,
    refs: impl IntoIterator<Item = &'a SecretRef>,
) -> SecretSnapshot {
    let mut snapshot = SecretSnapshot::new();
    for secret_ref in refs {
        let material = fixture.secrets.material(secret_ref).unwrap();
        snapshot
            .insert(SecretEntry::new(secret_ref.clone(), material).unwrap())
            .unwrap();
    }
    snapshot
}

/// With only the listed secrets, every user of every fixture exports the
/// same bytes in both formats as with every secret, and each listed secret
/// is needed: without any one of them the export fails.
#[test]
fn the_listed_secrets_are_exactly_what_an_export_reads() {
    for fixture in fixtures() {
        for user in fixture.deployment.users().keys() {
            let refs = export_secret_refs(&fixture.deployment, user, FIXTURE_NOW).unwrap();
            assert!(!refs.is_empty());
            let listed = snapshot_of(&fixture, &refs);
            for format in ExportFormat::ALL {
                let full = export_user(
                    &fixture.deployment,
                    &fixture.secrets,
                    user,
                    format,
                    FIXTURE_NOW,
                )
                .unwrap();
                let minimal =
                    export_user(&fixture.deployment, &listed, user, format, FIXTURE_NOW).unwrap();
                assert_eq!(
                    minimal.expose_bytes(),
                    full.expose_bytes(),
                    "{user} {format:?}"
                );
            }
            for dropped in &refs {
                let without = snapshot_of(&fixture, refs.iter().filter(|r| *r != dropped));
                assert!(
                    export_user(
                        &fixture.deployment,
                        &without,
                        user,
                        ExportFormat::SingBoxJson,
                        FIXTURE_NOW
                    )
                    .is_err(),
                    "{user} exported without {dropped}"
                );
            }
        }
    }
}

/// A user's own credentials and its nodes' salamander passwords, and
/// nothing of another user, a probe or a node's private keys.
#[test]
fn the_listed_secrets_are_the_users_credentials_and_its_nodes_obfs_passwords() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let refs = export_secret_refs(&fixture.deployment, &user, FIXTURE_NOW).unwrap();
    for secret_ref in &refs {
        match secret_ref {
            SecretRef::UserVlessUuid(owner, _) | SecretRef::UserHy2Password(owner, _) => {
                assert_eq!(owner, &user);
            }
            SecretRef::NodeHy2Obfs(node, _) => {
                assert!(
                    fixture.deployment.users()[&user]
                        .per_node
                        .contains_key(node)
                );
            }
            other => panic!("{other} is not read by an export"),
        }
    }
}

/// Every refusal `export_user` makes before reading a secret is made by
/// `export_secret_refs` too, with the same error, even with no secret at
/// all to read.
#[test]
fn the_listing_refuses_as_the_export_does() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let cases: [(&str, Edit); 6] = [
        ("suspended", |parts| {
            parts.users[0]
                .suspend(SuspendReason::Operator, FIXTURE_NOW)
                .unwrap();
        }),
        ("no agreement", |parts| parts.users[0].agreement = None),
        ("capability", |parts| {
            parts.users[0].client = profile(ClientLine::Cfm04, &[Capability::RealityMlkemOptIn]);
        }),
        ("no credentials", |parts| {
            parts.users[0].per_node = BTreeMap::new()
        }),
        ("stale node", |parts| {
            parts.config_generation = parts.config_generation.next().unwrap();
        }),
        ("revoking", |parts| {
            parts.users[0].status = UserStatus::RevokePending;
        }),
    ];
    for (name, change) in cases {
        let deployment: Deployment = edited(&fixture.deployment, change);
        let exported = export_user(
            &deployment,
            &fixture.secrets,
            &user,
            ExportFormat::SingBoxJson,
            FIXTURE_NOW,
        )
        .unwrap_err();
        let listed = export_secret_refs(&deployment, &user, FIXTURE_NOW).unwrap_err();
        assert_eq!(listed.kind(), exported.kind(), "{name}");
        assert_eq!(listed.to_string(), exported.to_string(), "{name}");
    }
    let unknown = UserId::parse("zzzzzzzzzz").unwrap();
    assert_eq!(
        export_secret_refs(&fixture.deployment, &unknown, FIXTURE_NOW)
            .unwrap_err()
            .to_string(),
        export_user(
            &fixture.deployment,
            &fixture.secrets,
            &unknown,
            ExportFormat::SingBoxJson,
            FIXTURE_NOW
        )
        .unwrap_err()
        .to_string()
    );
}

/// A certificate that is not current at `now` is refused by the listing
/// as by the export, so no secret is read for a file that cannot be made.
#[test]
fn the_listing_checks_certificates_at_now() {
    let fixture = two_nodes();
    let user = first_user(&fixture);
    let late = UnixTime::from_secs(u64::from(u32::MAX) * 4);
    let exported = export_user(
        &fixture.deployment,
        &fixture.secrets,
        &user,
        ExportFormat::SingBoxJson,
        late,
    )
    .unwrap_err();
    let listed = export_secret_refs(&fixture.deployment, &user, late).unwrap_err();
    assert_eq!(listed.kind(), exported.kind());
    assert_eq!(listed.to_string(), exported.to_string());
}
