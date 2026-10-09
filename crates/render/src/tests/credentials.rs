// SPDX-License-Identifier: GPL-3.0-or-later

//! Credential uniqueness on a node (`DuplicateCredential`, design §8.1): no
//! two identities holding credentials on a node may share a VLESS UUID, a
//! loopback UUID or a Hysteria2 password as the engines key them. Each case
//! copies a fixture's snapshot with one identity's credential replaced by
//! another's, which `xray run -test` would not catch: Xray keeps the last
//! client with a given UUID, and sing-quic the last user with a password.

use mooring_fixtures::{FIXTURE_NOW, Fixture};
use mooring_model::Secret;
use mooring_model::ids::{NodeId, UserId, Uuid};
use mooring_model::secret::{
    SecretEntry, SecretMaterial, SecretRef, SecretSnapshot, SecretSnapshotError,
};
use mooring_model::user::{SuspendReason, UserStatus};

use crate::error::{CredentialHolder, CredentialKind, RenderError, RenderErrorKind};
use crate::tests::support::{edit, engines, node, secrets_without};
use crate::vps::{VpsBundle, bundle};

/// An identity holding credentials on a node, in the order rendering
/// checks them: users in id order, then the probe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Holder {
    User(UserId),
    Probe,
}

impl Holder {
    fn named(&self) -> CredentialHolder {
        match self {
            Self::User(user) => CredentialHolder::User(user.clone()),
            Self::Probe => CredentialHolder::Probe,
        }
    }
}

fn three_users() -> Fixture {
    mooring_fixtures::two_nodes_three_users().unwrap()
}

fn users(fixture: &Fixture) -> Vec<UserId> {
    fixture.deployment.users().keys().cloned().collect()
}

/// The reference of `holder`'s credential of `kind` on `node`.
fn secret_ref(holder: &Holder, kind: CredentialKind, node: &NodeId) -> SecretRef {
    let node = node.clone();
    match (holder, kind) {
        (Holder::User(user), CredentialKind::VlessUuid) => {
            SecretRef::UserVlessUuid(user.clone(), node)
        }
        (Holder::User(user), CredentialKind::LoopbackUuid) => {
            SecretRef::UserLoopUuid(user.clone(), node)
        }
        (Holder::User(user), CredentialKind::Hy2Password) => {
            SecretRef::UserHy2Password(user.clone(), node)
        }
        (Holder::Probe, CredentialKind::VlessUuid) => SecretRef::ProbeVlessUuid(node),
        (Holder::Probe, CredentialKind::LoopbackUuid) => SecretRef::ProbeLoopUuid(node),
        (Holder::Probe, CredentialKind::Hy2Password) => SecretRef::ProbeHy2Password(node),
    }
}

/// A copy of the credential `secret_ref` names.
fn material(secrets: &SecretSnapshot, secret_ref: &SecretRef) -> SecretMaterial {
    match secret_ref {
        SecretRef::UserVlessUuid(user, node) => {
            SecretMaterial::Uuid(secrets.user_vless_uuid(user, node).unwrap().clone())
        }
        SecretRef::UserLoopUuid(user, node) => {
            SecretMaterial::Uuid(secrets.user_loop_uuid(user, node).unwrap().clone())
        }
        SecretRef::UserHy2Password(user, node) => {
            SecretMaterial::Password(secrets.user_hy2_password(user, node).unwrap().clone())
        }
        SecretRef::ProbeVlessUuid(node) => {
            SecretMaterial::Uuid(secrets.probe_vless_uuid(node).unwrap().clone())
        }
        SecretRef::ProbeLoopUuid(node) => {
            SecretMaterial::Uuid(secrets.probe_loop_uuid(node).unwrap().clone())
        }
        SecretRef::ProbeHy2Password(node) => {
            SecretMaterial::Password(secrets.probe_hy2_password(node).unwrap().clone())
        }
        other => panic!("{other} is not a per-identity credential"),
    }
}

/// `secrets` with `target` holding `material` instead.
fn replaced(
    secrets: &SecretSnapshot,
    target: &SecretRef,
    material: SecretMaterial,
) -> SecretSnapshot {
    let mut copy = secrets_without(secrets, target);
    copy.insert(SecretEntry::new(target.clone(), material).unwrap())
        .unwrap();
    copy
}

/// `secrets` with `target` holding a copy of `source`'s credential.
fn copied(secrets: &SecretSnapshot, source: &SecretRef, target: &SecretRef) -> SecretSnapshot {
    replaced(secrets, target, material(secrets, source))
}

fn render(fixture: &Fixture, secrets: &SecretSnapshot, id: &str) -> Result<VpsBundle, RenderError> {
    bundle(&fixture.deployment, &node(id), secrets, &engines())
}

/// The refusal names lon1, the kind, and the two holders that share the
/// credential, in the order they are checked.
fn assert_duplicate(
    result: Result<VpsBundle, RenderError>,
    kind: CredentialKind,
    holders: [&Holder; 2],
    what: &str,
) {
    let error = result.expect_err(what);
    assert_eq!(error.kind(), RenderErrorKind::DuplicateCredential, "{what}");
    let RenderError::DuplicateCredential {
        node: found_node,
        kind: found_kind,
        first,
        second,
    } = error
    else {
        unreachable!()
    };
    let [earlier, later] = if holders[0] < holders[1] {
        holders
    } else {
        [holders[1], holders[0]]
    };
    assert_eq!(
        (found_node, found_kind, first, second),
        (node("lon1"), kind, earlier.named(), later.named()),
        "{what}"
    );
}

/// Every ordered pair of distinct holders on lon1 (three users and the
/// probe), for every credential kind: giving the second the first's
/// credential is refused, naming the node and the kind, while ams1, whose
/// credentials are untouched, still renders.
#[test]
fn no_two_identities_on_a_node_share_a_credential() {
    let fixture = three_users();
    let lon1 = node("lon1");
    let mut holders: Vec<Holder> = users(&fixture).into_iter().map(Holder::User).collect();
    holders.push(Holder::Probe);
    assert!(render(&fixture, &fixture.secrets, "lon1").is_ok());
    let mut cases = 0;
    for kind in [
        CredentialKind::VlessUuid,
        CredentialKind::LoopbackUuid,
        CredentialKind::Hy2Password,
    ] {
        for source in &holders {
            for target in holders.iter().filter(|holder| *holder != source) {
                let what = format!("{target:?} takes {source:?}'s {kind}");
                let secrets = copied(
                    &fixture.secrets,
                    &secret_ref(source, kind, &lon1),
                    &secret_ref(target, kind, &lon1),
                );
                assert_duplicate(
                    render(&fixture, &secrets, "lon1"),
                    kind,
                    [source, target],
                    &what,
                );
                assert!(render(&fixture, &secrets, "ams1").is_ok(), "{what}");
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 3 * 4 * 3);
}

/// `uuid`'s bytes with `index` replaced by `value`.
fn with_byte(uuid: &Secret<Uuid>, index: usize, value: u8) -> SecretMaterial {
    let mut bytes = *uuid.expose_secret().as_bytes();
    assert_ne!(bytes[index], value);
    bytes[index] = value;
    SecretMaterial::Uuid(Secret::new(Uuid::from_bytes(bytes).unwrap()))
}

/// A value for `index` that differs from `current` and keeps the UUID a
/// valid version-4 RFC 9562 UUID: byte 6 keeps its version nibble (4) and
/// byte 8 its variant bits (10).
fn other_byte(index: usize, current: u8) -> u8 {
    match index {
        6 => 0x40 | ((current + 1) & 0x0f),
        8 => 0x80 | ((current + 1) & 0x3f),
        _ => current ^ 0x5a,
    }
}

/// Xray keys a VLESS client by its UUID with bytes 6 and 7 cleared, so two
/// UUIDs that differ only there are one client to it; a difference in any
/// other byte, on either side of that pair, keeps them apart. Every byte
/// is tried.
#[test]
fn uuids_are_compared_as_xray_keys_them() {
    let fixture = three_users();
    let lon1 = node("lon1");
    let [first, second, _] = <[UserId; 3]>::try_from(users(&fixture)).unwrap();
    for (kind, source, target, holders) in [
        (
            CredentialKind::VlessUuid,
            SecretRef::UserVlessUuid(first.clone(), lon1.clone()),
            SecretRef::UserVlessUuid(second.clone(), lon1.clone()),
            [Holder::User(first.clone()), Holder::User(second.clone())],
        ),
        (
            CredentialKind::LoopbackUuid,
            SecretRef::ProbeLoopUuid(lon1.clone()),
            SecretRef::UserLoopUuid(second.clone(), lon1.clone()),
            [Holder::Probe, Holder::User(second.clone())],
        ),
    ] {
        let SecretMaterial::Uuid(uuid) = material(&fixture.secrets, &source) else {
            unreachable!()
        };
        let bytes = *uuid.expose_secret().as_bytes();
        for (index, &current) in bytes.iter().enumerate() {
            let secrets = replaced(
                &fixture.secrets,
                &target,
                with_byte(&uuid, index, other_byte(index, current)),
            );
            let result = render(&fixture, &secrets, "lon1");
            if index == 6 || index == 7 {
                let what = format!("{kind} differing only in byte {index}");
                assert_duplicate(result, kind, [&holders[0], &holders[1]], &what);
            } else {
                assert!(result.is_ok(), "{kind} differing in byte {index}");
            }
        }
    }
}

/// A user that holds credentials on the node but is not served (suspended,
/// or pending revocation) still holds a working client: its credentials
/// must not equal a served identity's, and rendering needs them.
#[test]
fn credentials_of_identities_the_node_does_not_serve_are_checked_too() {
    let mut fixture = three_users();
    let lon1 = node("lon1");
    let [first, second, third] = <[UserId; 3]>::try_from(users(&fixture)).unwrap();
    fixture.deployment = edit(&fixture.deployment, |parts| {
        parts.users[1]
            .suspend(SuspendReason::AbuseReview, FIXTURE_NOW)
            .unwrap();
        parts.users[2].status = UserStatus::RevokePending;
    });
    assert!(!fixture.deployment.users()[&second].is_served_on(&lon1));
    assert!(!fixture.deployment.users()[&third].is_served_on(&lon1));
    assert!(render(&fixture, &fixture.secrets, "lon1").is_ok());

    let suspended_takes_active = copied(
        &fixture.secrets,
        &SecretRef::UserVlessUuid(first.clone(), lon1.clone()),
        &SecretRef::UserVlessUuid(second.clone(), lon1.clone()),
    );
    assert_duplicate(
        render(&fixture, &suspended_takes_active, "lon1"),
        CredentialKind::VlessUuid,
        [&Holder::User(first.clone()), &Holder::User(second.clone())],
        "a suspended user holding an active user's UUID",
    );
    let revoking_takes_probe = copied(
        &fixture.secrets,
        &SecretRef::ProbeHy2Password(lon1.clone()),
        &SecretRef::UserHy2Password(third.clone(), lon1.clone()),
    );
    assert_duplicate(
        render(&fixture, &revoking_takes_probe, "lon1"),
        CredentialKind::Hy2Password,
        [&Holder::User(third.clone()), &Holder::Probe],
        "a user pending revocation holding the probe's password",
    );

    let missing = SecretRef::UserLoopUuid(second, lon1);
    let error = render(
        &fixture,
        &secrets_without(&fixture.secrets, &missing),
        "lon1",
    )
    .unwrap_err();
    let RenderError::Secret(SecretSnapshotError::Missing { secret_ref }) = error else {
        panic!("expected a missing secret, got {error:?}");
    };
    assert_eq!(secret_ref, missing);
}

/// The refusal names the node, the kind and the two holders (opaque user
/// ids or the probe, never a secret), so the operator can find them.
#[test]
fn the_refusal_names_the_node_the_kind_and_both_holders() {
    let user = UserId::from_low_bits(1);
    let error = RenderError::DuplicateCredential {
        node: node("lon1"),
        kind: CredentialKind::LoopbackUuid,
        first: CredentialHolder::User(user.clone()),
        second: CredentialHolder::Probe,
    };
    assert_eq!(error.kind(), RenderErrorKind::DuplicateCredential);
    assert_eq!(
        error.to_string(),
        "user aaaaaaaaab and the probe share a credential on node lon1 (LoopbackUuid)"
    );
    let two_users = RenderError::DuplicateCredential {
        node: node("lon1"),
        kind: CredentialKind::VlessUuid,
        first: CredentialHolder::User(user),
        second: CredentialHolder::User(UserId::from_low_bits(2)),
    };
    assert_eq!(
        two_users.to_string(),
        "user aaaaaaaaab and user aaaaaaaaac share a credential on node lon1 (VlessUuid)"
    );
    assert_eq!(
        CredentialKind::ALL,
        [
            CredentialKind::VlessUuid,
            CredentialKind::LoopbackUuid,
            CredentialKind::Hy2Password
        ]
    );
}
