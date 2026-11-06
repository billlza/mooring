// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal's profile bundle (`docs/portal-contract.md`): its structure
//! against the contract's golden, each document against the user's own
//! export, who is left out and why, and every refusal.
//!
//! `contract/portal-fixtures/cfm-profiles-v1/pilot.json` is a copy of the
//! portal repository's `contract/fixtures/cfm-profiles-v1/valid/pilot.json`
//! at its commit c070413. Its values are synthetic and of a shape no export
//! makes (a documentation address, a pin that is no SHA-256), so the bundle
//! is compared with it key by key and type by type, as the contract says,
//! not byte by byte.

use std::collections::BTreeSet;
use std::num::NonZeroU16;

use mooring_export::{
    ExportError, ExportErrorKind, ExportFormat, MAX_BUNDLE_BYTES, MAX_PROFILE_DOCUMENT_BYTES,
    Omission, ProfilesError, ProfilesErrorKind, export_profiles, export_secret_refs, export_user,
    profile_selection,
};
use mooring_fixtures::FIXTURE_NOW;
use mooring_model::{
    AgreementRecord, AgreementVersion, CalendarDate, ClientLine, ConfigGeneration, Deployment,
    PortalAgreement, SecretSnapshot, SuspendReason, UnixTime, UserId, UserStatus,
};
use saphyr::YamlOwned;

use crate::support::{edited, keys, parse, profile, two_nodes};

const GOLDEN: &str =
    include_str!("../../../../contract/portal-fixtures/cfm-profiles-v1/pilot.json");

/// The gate opened on the revision this build ships.
fn open() -> PortalAgreement {
    PortalAgreement::since(Some(AgreementVersion::CURRENT))
}

fn user_ids(deployment: &Deployment) -> Vec<UserId> {
    deployment.users().keys().cloned().collect()
}

fn bundle_text(deployment: &Deployment) -> String {
    let fixture = two_nodes();
    let bundle = export_profiles(deployment, &fixture.secrets, FIXTURE_NOW, open()).unwrap();
    String::from_utf8(bundle.expose_bytes().to_vec()).unwrap()
}

/// A value's structure: a mapping's keys in order with each value's
/// structure, a sequence's items', and a scalar's type.
fn structure(value: &YamlOwned) -> String {
    if let Some(mapping) = value.as_mapping() {
        let entries: Vec<String> = mapping
            .iter()
            .map(|(key, value)| format!("{}:{}", key.as_str().unwrap(), structure(value)))
            .collect();
        format!("{{{}}}", entries.join(","))
    } else if let Some(items) = value.as_sequence() {
        let items: Vec<String> = items.iter().map(structure).collect();
        format!("[{}]", items.join(","))
    } else if value.as_str().is_some() {
        "string".to_owned()
    } else if value.as_integer().is_some() {
        "integer".to_owned()
    } else if value.as_bool().is_some() {
        "boolean".to_owned()
    } else {
        panic!("no other kind of value is in a bundle: {value:?}")
    }
}

fn profiles(bundle: &YamlOwned) -> &[YamlOwned] {
    bundle
        .as_mapping_get("profiles")
        .unwrap()
        .as_sequence()
        .unwrap()
}

fn outbounds(entry: &YamlOwned) -> &[YamlOwned] {
    entry
        .as_mapping_get("document")
        .unwrap()
        .as_mapping_get("outbounds")
        .unwrap()
        .as_sequence()
        .unwrap()
}

fn kind(outbound: &YamlOwned) -> &str {
    outbound.as_mapping_get("type").unwrap().as_str().unwrap()
}

/// The bundle has the golden's keys in its order at every level, and each
/// outbound of either protocol the golden's structure for that protocol.
#[test]
fn the_bundle_has_the_contract_goldens_structure() {
    // Every user on the line the golden shows, without the ML-KEM key.
    let deployment = edited(&two_nodes().deployment, |parts| {
        for user in &mut parts.users {
            user.client = profile(ClientLine::Cfm05, &[]);
        }
    });
    let golden = parse(GOLDEN);
    let made = parse(&bundle_text(&deployment));
    assert_eq!(keys(&made), keys(&golden));
    assert_eq!(
        keys(&made),
        ["format", "version", "generated_at", "profiles"]
    );
    for key in ["format", "version"] {
        assert_eq!(
            made.as_mapping_get(key).unwrap(),
            golden.as_mapping_get(key).unwrap()
        );
    }
    assert_eq!(
        structure(made.as_mapping_get("generated_at").unwrap()),
        "integer"
    );
    let mut seen = BTreeSet::new();
    for entry in profiles(&made) {
        assert_eq!(keys(entry), ["user", "document"]);
        assert_eq!(
            keys(entry.as_mapping_get("document").unwrap()),
            ["outbounds"]
        );
        for outbound in outbounds(entry) {
            let expected = profiles(&golden)
                .iter()
                .flat_map(outbounds)
                .find(|candidate| kind(candidate) == kind(outbound))
                .unwrap();
            assert_eq!(
                structure(outbound),
                structure(expected),
                "{}",
                kind(outbound)
            );
            seen.insert(kind(outbound).to_owned());
        }
    }
    // Both of the golden's protocols were compared.
    assert_eq!(
        seen,
        BTreeSet::from(["hysteria2".to_owned(), "vless".to_owned()])
    );
}

/// Every user to be served is in the bundle, in id order, with the very
/// document their own sing-box export holds, ML-KEM opt-in included; the
/// bundle's time is the export's.
#[test]
fn each_profile_is_the_users_own_sing_box_file() {
    let fixture = two_nodes();
    let bundle =
        export_profiles(&fixture.deployment, &fixture.secrets, FIXTURE_NOW, open()).unwrap();
    let text = std::str::from_utf8(bundle.expose_bytes()).unwrap();
    assert!(text.ends_with("}\n") && !text.ends_with("\n\n"));
    let made = parse(text);
    assert_eq!(
        made.as_mapping_get("generated_at").unwrap().as_integer(),
        Some(i64::try_from(FIXTURE_NOW.as_secs()).unwrap())
    );
    let users = user_ids(&fixture.deployment);
    assert_eq!(bundle.selection().included(), users.as_slice());
    assert!(bundle.selection().omitted().is_empty());
    let entries = profiles(&made);
    assert_eq!(entries.len(), users.len());
    for (entry, user) in entries.iter().zip(&users) {
        assert_eq!(
            entry.as_mapping_get("user").unwrap().as_str(),
            Some(user.as_str())
        );
        let own = export_user(
            &fixture.deployment,
            &fixture.secrets,
            user,
            ExportFormat::SingBoxJson,
            FIXTURE_NOW,
        )
        .unwrap();
        let own = parse(std::str::from_utf8(own.expose_bytes()).unwrap());
        assert_eq!(entry.as_mapping_get("document").unwrap(), &own, "{user}");
    }
    // Its debug form gives counts and the size only.
    assert_eq!(
        format!("{bundle:?}"),
        format!(
            "ProfileBundle {{ included: 3, omitted: 0, len: {}, .. }}",
            bundle.expose_bytes().len()
        )
    );
    assert!(bundle.expose_bytes().len() <= MAX_BUNDLE_BYTES);
    // The contract's bounds: 1 MiB per bundle, 64 KiB per document.
    assert_eq!(MAX_BUNDLE_BYTES, 1_048_576);
    assert_eq!(MAX_PROFILE_DOCUMENT_BYTES, 65_536);
}

fn suspended() -> UserStatus {
    UserStatus::Suspended {
        reason: SuspendReason::Operator,
        since: UnixTime::from_secs(FIXTURE_NOW.as_secs() - 60),
    }
}

/// A suspended, revoking or revoked user is served nowhere, and an active
/// user without an acceptance of the required revision gets no file, so
/// neither is in the bundle; each is named with the reason, in id order,
/// and their secrets are not read.
#[test]
fn users_not_to_be_served_are_left_out_and_named() {
    let fixture = mooring_fixtures::two_nodes_twenty_users().unwrap();
    let other = AgreementVersion::new(NonZeroU16::new(2).unwrap());
    let deployment = edited(&fixture.deployment, |parts| {
        parts.users[0].status = suspended();
        parts.users[1].status = UserStatus::RevokePending;
        parts.users[2].status = UserStatus::Revoked;
        parts.users[2].per_node.clear();
        parts.users[3].agreement = None;
        parts.users[4].agreement = Some(AgreementRecord {
            version: other,
            accepted_on: CalendarDate::utc_of(FIXTURE_NOW).unwrap(),
        });
    });
    let users = user_ids(&deployment);
    let selection = profile_selection(&deployment, FIXTURE_NOW, open()).unwrap();
    let required = AgreementVersion::CURRENT;
    assert_eq!(
        selection.omitted(),
        [
            (users[0].clone(), Omission::Suspended),
            (users[1].clone(), Omission::BeingRevoked),
            (users[2].clone(), Omission::Revoked),
            (
                users[3].clone(),
                Omission::AgreementNotAccepted {
                    recorded: None,
                    required
                }
            ),
            (
                users[4].clone(),
                Omission::AgreementNotAccepted {
                    recorded: Some(other),
                    required
                }
            ),
        ]
    );
    assert_eq!(selection.included(), &users[5..]);
    let said: Vec<String> = selection
        .omitted()
        .iter()
        .map(|(_, omission)| omission.to_string())
        .collect();
    assert_eq!(
        said,
        [
            "suspended",
            "being revoked",
            "revoked",
            "has not accepted agreement revision 1: no acceptance is recorded",
            "has not accepted agreement revision 1: the recorded acceptance is of revision 2",
        ]
    );
    // Exactly the included users' secrets are listed.
    let mut expected = BTreeSet::new();
    for user in selection.included() {
        expected.extend(export_secret_refs(&deployment, user, FIXTURE_NOW).unwrap());
    }
    assert_eq!(selection.secret_refs(), &expected);
    // A snapshot of exactly those secrets makes the bundle.
    let mut secrets = SecretSnapshot::new();
    for secret_ref in selection.secret_refs() {
        secrets
            .insert(
                mooring_model::SecretEntry::new(
                    secret_ref.clone(),
                    fixture.secrets.material(secret_ref).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let bundle = export_profiles(&deployment, &secrets, FIXTURE_NOW, open()).unwrap();
    assert_eq!(bundle.selection(), &selection);
    let made = parse(std::str::from_utf8(bundle.expose_bytes()).unwrap());
    let listed: Vec<&str> = profiles(&made)
        .iter()
        .map(|entry| entry.as_mapping_get("user").unwrap().as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        users[5..].iter().map(UserId::as_str).collect::<Vec<_>>()
    );
}

/// Nothing is made while the shipped agreement does not cover the portal:
/// neither the selection nor the bundle, whatever the users accepted.
#[test]
fn nothing_is_made_while_the_agreement_does_not_cover_the_portal() {
    let fixture = two_nodes();
    let shipped = PortalAgreement::SHIPPED;
    let refused = profile_selection(&fixture.deployment, FIXTURE_NOW, shipped).unwrap_err();
    assert_eq!(refused.kind(), ProfilesErrorKind::NotCovered);
    let refused =
        export_profiles(&fixture.deployment, &fixture.secrets, FIXTURE_NOW, shipped).unwrap_err();
    assert_eq!(refused.kind(), ProfilesErrorKind::NotCovered);
    assert_eq!(
        refused.to_string(),
        "agreement revision 1, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links"
    );
}

/// A bundle holds at least one profile.
#[test]
fn no_bundle_is_made_without_a_user_to_serve() {
    let fixture = two_nodes();
    let deployment = edited(&fixture.deployment, |parts| {
        for user in &mut parts.users {
            user.status = suspended();
        }
    });
    let refused = profile_selection(&deployment, FIXTURE_NOW, open()).unwrap_err();
    assert_eq!(refused.kind(), ProfilesErrorKind::NoProfiles);
    assert_eq!(
        refused.to_string(),
        "no user is to be served: every user is suspended, being revoked, revoked or without an acceptance of the agreement revision the portal requires"
    );
    let refused = export_profiles(&deployment, &fixture.secrets, FIXTURE_NOW, open()).unwrap_err();
    assert_eq!(refused.kind(), ProfilesErrorKind::NoProfiles);
}

fn user_refusal(error: &ProfilesError) -> (&UserId, &ExportError) {
    match error {
        ProfilesError::User { user, source } => (user, source),
        other => panic!("not a user's refusal: {other:?}"),
    }
}

/// A user to be served whose file cannot be made refuses the whole bundle,
/// named with the export's own refusal: at the selection when a node has
/// not confirmed the current generation, and when making the files when a
/// secret is missing.
#[test]
fn a_user_whose_file_cannot_be_made_refuses_the_bundle() {
    let fixture = two_nodes();
    let users = user_ids(&fixture.deployment);
    let stale = edited(&fixture.deployment, |parts| {
        parts.config_generation = ConfigGeneration::INITIAL.next().unwrap();
    });
    let refused = profile_selection(&stale, FIXTURE_NOW, open()).unwrap_err();
    let (user, source) = user_refusal(&refused);
    assert_eq!(*user, users[0]);
    assert_eq!(source.kind(), ExportErrorKind::NodeNotApplied);
    assert_eq!(
        refused.to_string(),
        format!("user {}'s file cannot be made", users[0])
    );
    let refused = export_profiles(&stale, &fixture.secrets, FIXTURE_NOW, open()).unwrap_err();
    assert_eq!(
        user_refusal(&refused).1.kind(),
        ExportErrorKind::NodeNotApplied
    );
    // Every check passes, but the snapshot holds no secret.
    let refused = export_profiles(
        &fixture.deployment,
        &SecretSnapshot::new(),
        FIXTURE_NOW,
        open(),
    )
    .unwrap_err();
    let (user, source) = user_refusal(&refused);
    assert_eq!(*user, users[0]);
    assert_eq!(source.kind(), ExportErrorKind::Secret);
}

/// Every kind names its variant.
#[test]
fn every_profiles_error_kind_is_named() {
    let fixture = two_nodes();
    let user = user_ids(&fixture.deployment).remove(0);
    let encode = || serde_json::from_str::<u8>("x").unwrap_err();
    let cases = [
        (
            ProfilesError::NotCovered(PortalAgreement::SHIPPED.required().unwrap_err()),
            ProfilesErrorKind::NotCovered,
        ),
        (ProfilesError::NoProfiles, ProfilesErrorKind::NoProfiles),
        (
            ProfilesError::User {
                user: user.clone(),
                source: Box::new(ExportError::Encode(encode())),
            },
            ProfilesErrorKind::User,
        ),
        (
            ProfilesError::DocumentTooLarge {
                user,
                bytes: 2,
                limit: 1,
            },
            ProfilesErrorKind::DocumentTooLarge,
        ),
        (
            ProfilesError::BundleTooLarge { bytes: 2, limit: 1 },
            ProfilesErrorKind::BundleTooLarge,
        ),
        (ProfilesError::Encode(encode()), ProfilesErrorKind::Encode),
    ];
    assert_eq!(cases.len(), ProfilesErrorKind::ALL.len());
    for (error, kind) in cases {
        assert_eq!(error.kind(), kind, "{error:?}");
    }
    assert_eq!(
        ProfilesError::Encode(encode()).to_string(),
        "the profile bundle could not be encoded"
    );
}
