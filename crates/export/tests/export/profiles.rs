// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal's profile bundle (`docs/portal-contract.md`): its structure
//! against the contract's goldens, each document against the user's own
//! export, who is delivered and who is withheld and why, and every refusal.
//!
//! `contract/portal-fixtures/cfm-profiles-v2/` holds copies of the portal
//! repository's `contract/fixtures/cfm-profiles-v2/valid/pilot.json` and
//! `valid/all-withheld.json` at its commit 520c358. Their values are
//! synthetic and of a shape no export makes (a documentation address, a
//! pin that is no SHA-256), so a bundle is compared with them key by key
//! and type by type, as the contract says, not byte by byte.

use std::collections::BTreeSet;
use std::num::NonZeroU16;

use mooring_export::{
    ExportError, ExportErrorKind, ExportFormat, MAX_BUNDLE_BYTES, MAX_PROFILE_DOCUMENT_BYTES,
    ProfilesError, ProfilesErrorKind, Withheld, export_profiles, export_secret_refs, export_user,
    profile_selection,
};
use mooring_fixtures::FIXTURE_NOW;
use mooring_model::{
    AgreementRecord, AgreementVersion, CalendarDate, ClientLine, ConfigGeneration, Deployment,
    NamedUsersError, PortalAgreement, PortalNotCovered, SecretSnapshot, SuspendReason, UnixTime,
    UserId, UserStatus,
};
use saphyr::YamlOwned;

use crate::support::{edited, keys, parse, profile, two_nodes};

const PILOT: &str = include_str!("../../../../contract/portal-fixtures/cfm-profiles-v2/pilot.json");
const ALL_WITHHELD: &str =
    include_str!("../../../../contract/portal-fixtures/cfm-profiles-v2/all-withheld.json");

/// The gate opened on the revision this build ships.
fn open() -> PortalAgreement {
    PortalAgreement::since(Some(AgreementVersion::CURRENT))
}

fn user_ids(deployment: &Deployment) -> Vec<UserId> {
    deployment.users().keys().cloned().collect()
}

/// The bundle of `users` of `deployment`, with the fixture's secrets.
fn bundle_text(deployment: &Deployment, users: &[UserId]) -> String {
    let fixture = two_nodes();
    let bundle = export_profiles(deployment, &fixture.secrets, users, FIXTURE_NOW, open()).unwrap();
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

fn list<'a>(bundle: &'a YamlOwned, key: &str) -> &'a [YamlOwned] {
    bundle.as_mapping_get(key).unwrap().as_sequence().unwrap()
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

fn text_of<'a>(entry: &'a YamlOwned, key: &str) -> &'a str {
    entry.as_mapping_get(key).unwrap().as_str().unwrap()
}

/// The users listed under `key`, with the value of `field` for each.
fn listed<'a>(bundle: &'a YamlOwned, key: &str, field: &str) -> Vec<(&'a str, String)> {
    list(bundle, key)
        .iter()
        .map(|entry| {
            let value = entry.as_mapping_get(field).unwrap();
            let value = value
                .as_str()
                .map_or_else(|| structure(value), str::to_owned);
            (text_of(entry, "user"), value)
        })
        .collect()
}

fn suspended(reason: SuspendReason) -> UserStatus {
    UserStatus::Suspended {
        reason,
        since: UnixTime::from_secs(FIXTURE_NOW.as_secs() - 60),
    }
}

/// The top level has the golden's keys in its order, with its format and
/// version; `generated_at` is an integer.
fn assert_top_level(made: &YamlOwned, golden: &YamlOwned) {
    assert_eq!(keys(made), keys(golden));
    assert_eq!(
        keys(made),
        ["format", "version", "generated_at", "profiles", "withheld"]
    );
    for key in ["format", "version"] {
        assert_eq!(
            made.as_mapping_get(key).unwrap(),
            golden.as_mapping_get(key).unwrap(),
            "{key}"
        );
    }
    assert_eq!(
        made.as_mapping_get("version").unwrap().as_integer(),
        Some(2)
    );
    assert_eq!(
        structure(made.as_mapping_get("generated_at").unwrap()),
        "integer"
    );
}

/// A bundle delivering some users and withholding another has the pilot
/// golden's keys in its order at every level: each outbound of either
/// protocol has the golden's structure for that protocol, and a withheld
/// entry the golden's.
#[test]
fn a_bundle_has_the_pilot_goldens_structure() {
    // Every user on the line the golden shows, without the ML-KEM key; the
    // last one suspended, as the golden's last user is.
    let deployment = edited(&two_nodes().deployment, |parts| {
        for user in &mut parts.users {
            user.client = profile(ClientLine::Cfm05, &[]);
        }
        parts.users[2].status = suspended(SuspendReason::Operator);
    });
    let users = user_ids(&deployment);
    let golden = parse(PILOT);
    let made = parse(&bundle_text(&deployment, &users));
    assert_top_level(&made, &golden);
    let mut seen = BTreeSet::new();
    for entry in list(&made, "profiles") {
        assert_eq!(keys(entry), ["user", "document"]);
        assert_eq!(
            keys(entry.as_mapping_get("document").unwrap()),
            ["outbounds"]
        );
        for outbound in outbounds(entry) {
            let expected = list(&golden, "profiles")
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
    let withheld = list(&made, "withheld");
    assert_eq!(withheld.len(), 1);
    assert_eq!(
        structure(&withheld[0]),
        structure(&list(&golden, "withheld")[0])
    );
    assert_eq!(keys(&withheld[0]), ["user", "reason"]);
    assert_eq!(
        listed(&made, "withheld", "reason"),
        listed(&golden, "withheld", "reason")
            .into_iter()
            .map(|(_, reason)| (users[2].as_str(), reason))
            .collect::<Vec<_>>()
    );
}

/// A bundle that withholds every user named is still made, with no
/// profile, and has the all-withheld golden's structure and reasons.
#[test]
fn a_bundle_withholding_everyone_has_the_all_withheld_goldens_structure() {
    // As in the golden: the first user without an acceptance, the second
    // revoked. The third is not named.
    let deployment = edited(&two_nodes().deployment, |parts| {
        parts.users[0].agreement = None;
        parts.users[1].status = UserStatus::Revoked;
        parts.users[1].per_node.clear();
    });
    let users = user_ids(&deployment);
    let golden = parse(ALL_WITHHELD);
    let made = parse(&bundle_text(&deployment, &users[..2]));
    assert_top_level(&made, &golden);
    assert!(list(&made, "profiles").is_empty());
    assert_eq!(
        structure(made.as_mapping_get("withheld").unwrap()),
        structure(golden.as_mapping_get("withheld").unwrap())
    );
    let reasons = |bundle: &YamlOwned| {
        listed(bundle, "withheld", "reason")
            .into_iter()
            .map(|(_, reason)| reason)
            .collect::<Vec<_>>()
    };
    assert_eq!(reasons(&made), reasons(&golden));
    assert_eq!(reasons(&made), ["agreement_not_accepted", "revoked"]);
    assert_eq!(
        listed(&made, "withheld", "reason")
            .into_iter()
            .map(|(user, _)| user)
            .collect::<Vec<_>>(),
        [users[0].as_str(), users[1].as_str()]
    );
}

/// Every user named and to be delivered is in the bundle, in id order,
/// with the very document their own sing-box export holds, ML-KEM opt-in
/// included; the bundle's time is the export's.
#[test]
fn each_profile_is_the_users_own_sing_box_file() {
    let fixture = two_nodes();
    let users = user_ids(&fixture.deployment);
    let bundle = export_profiles(
        &fixture.deployment,
        &fixture.secrets,
        &users,
        FIXTURE_NOW,
        open(),
    )
    .unwrap();
    let text = std::str::from_utf8(bundle.expose_bytes()).unwrap();
    assert!(text.ends_with("}\n") && !text.ends_with("\n\n"));
    let made = parse(text);
    assert_eq!(
        made.as_mapping_get("generated_at").unwrap().as_integer(),
        Some(i64::try_from(FIXTURE_NOW.as_secs()).unwrap())
    );
    assert_eq!(bundle.selection().delivered(), users.as_slice());
    assert!(bundle.selection().withheld().is_empty());
    assert!(list(&made, "withheld").is_empty());
    let entries = list(&made, "profiles");
    assert_eq!(entries.len(), users.len());
    for (entry, user) in entries.iter().zip(&users) {
        assert_eq!(text_of(entry, "user"), user.as_str());
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
            "ProfileBundle {{ delivered: 3, withheld: 0, len: {}, .. }}",
            bundle.expose_bytes().len()
        )
    );
    assert!(bundle.expose_bytes().len() <= MAX_BUNDLE_BYTES);
    // The contract's bounds: 1 MiB per bundle, 64 KiB per document.
    assert_eq!(MAX_BUNDLE_BYTES, 1_048_576);
    assert_eq!(MAX_PROFILE_DOCUMENT_BYTES, 65_536);
}

/// Only the users named are in the bundle, in id order whatever the order
/// named, and only their secrets are read: a user not named has no entry
/// on either side.
#[test]
fn only_the_users_named_are_in_the_bundle() {
    let fixture = two_nodes();
    let users = user_ids(&fixture.deployment);
    let named = [users[2].clone(), users[0].clone()];
    let selection = profile_selection(&fixture.deployment, &named, FIXTURE_NOW, open()).unwrap();
    assert_eq!(selection.delivered(), [users[0].clone(), users[2].clone()]);
    assert!(selection.withheld().is_empty());
    let mut expected = BTreeSet::new();
    for user in [&users[0], &users[2]] {
        expected.extend(export_secret_refs(&fixture.deployment, user, FIXTURE_NOW).unwrap());
    }
    assert_eq!(selection.secret_refs(), &expected);
    // The user not named has secrets of their own (the nodes' are shared),
    // and so none of theirs is among those.
    let not_named = export_secret_refs(&fixture.deployment, &users[1], FIXTURE_NOW).unwrap();
    assert!(not_named.difference(&expected).next().is_some());
    let made = parse(&bundle_text(&fixture.deployment, &named));
    assert_eq!(
        listed(&made, "profiles", "document")
            .into_iter()
            .map(|(user, _)| user)
            .collect::<Vec<_>>(),
        [users[0].as_str(), users[2].as_str()]
    );
    assert!(list(&made, "withheld").is_empty());
}

/// A user named who is suspended (for any reason), being revoked or
/// revoked is served nowhere, and an active user without an acceptance of
/// the required revision gets no file: each is withheld with the reason,
/// in id order, the contract's reason in the bundle, and none of their
/// secrets is read. The status decides before the acceptance: a user who
/// is not active is withheld for that, accepted or not, as a suspended
/// user is likely to be right after the revision that opens the portal.
#[test]
fn users_named_but_not_to_be_delivered_are_withheld_with_the_reason() {
    let fixture = mooring_fixtures::two_nodes_twenty_users().unwrap();
    let current = AgreementVersion::CURRENT;
    let other = AgreementVersion::new(NonZeroU16::new(current.get() + 1).unwrap());
    let quota = SuspendReason::QuotaExceeded {
        cycle_start: CalendarDate::utc_of(FIXTURE_NOW).unwrap(),
    };
    let deployment = edited(&fixture.deployment, |parts| {
        parts.users[0].status = suspended(SuspendReason::Operator);
        parts.users[1].status = suspended(quota);
        parts.users[2].status = suspended(SuspendReason::Expired);
        parts.users[3].status = suspended(SuspendReason::AbuseReview);
        parts.users[4].status = UserStatus::RevokePending;
        parts.users[5].status = UserStatus::Revoked;
        parts.users[5].per_node.clear();
        parts.users[6].agreement = None;
        parts.users[7].agreement = Some(AgreementRecord {
            version: other,
            accepted_on: CalendarDate::utc_of(FIXTURE_NOW).unwrap(),
        });
        // Not active, and without the acceptance either.
        parts.users[1].agreement = None;
        parts.users[4].agreement = Some(AgreementRecord {
            version: other,
            accepted_on: CalendarDate::utc_of(FIXTURE_NOW).unwrap(),
        });
        parts.users[5].agreement = None;
    });
    let users = user_ids(&deployment);
    let selection = profile_selection(&deployment, &users, FIXTURE_NOW, open()).unwrap();
    let required = current;
    let expected = [
        Withheld::Suspended,
        Withheld::Suspended,
        Withheld::Suspended,
        Withheld::Suspended,
        Withheld::BeingRevoked,
        Withheld::Revoked,
        Withheld::AgreementNotAccepted {
            recorded: None,
            required,
        },
        Withheld::AgreementNotAccepted {
            recorded: Some(other),
            required,
        },
    ];
    assert_eq!(
        selection.withheld(),
        users
            .iter()
            .cloned()
            .zip(expected)
            .collect::<Vec<_>>()
            .as_slice()
    );
    assert_eq!(selection.delivered(), &users[8..]);
    let said: Vec<String> = selection
        .withheld()
        .iter()
        .map(|(_, why)| why.to_string())
        .collect();
    assert_eq!(
        said[3..],
        [
            "suspended".to_owned(),
            "being revoked".to_owned(),
            "revoked".to_owned(),
            format!("has not accepted agreement revision {current}: no acceptance is recorded"),
            format!(
                "has not accepted agreement revision {current}: the recorded acceptance is of revision {other}"
            ),
        ]
    );
    // Exactly the delivered users' secrets are listed.
    let mut refs = BTreeSet::new();
    for user in selection.delivered() {
        refs.extend(export_secret_refs(&deployment, user, FIXTURE_NOW).unwrap());
    }
    assert_eq!(selection.secret_refs(), &refs);
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
    let bundle = export_profiles(&deployment, &secrets, &users, FIXTURE_NOW, open()).unwrap();
    assert_eq!(bundle.selection(), &selection);
    let made = parse(std::str::from_utf8(bundle.expose_bytes()).unwrap());
    assert_eq!(
        listed(&made, "profiles", "document")
            .into_iter()
            .map(|(user, _)| user)
            .collect::<Vec<_>>(),
        users[8..].iter().map(UserId::as_str).collect::<Vec<_>>()
    );
    let reasons = [
        "suspended",
        "suspended",
        "suspended",
        "suspended",
        "revoked",
        "revoked",
        "agreement_not_accepted",
        "agreement_not_accepted",
    ];
    assert_eq!(
        listed(&made, "withheld", "reason"),
        users
            .iter()
            .map(UserId::as_str)
            .zip(reasons.map(str::to_owned))
            .collect::<Vec<_>>()
    );
}

/// Nothing is made while the gate is closed: neither the selection nor the
/// bundle, whatever the users accepted. In particular no bundle withholds
/// everyone for an acceptance that cannot be had yet, which the portal
/// would take for every link to end.
#[test]
fn nothing_is_made_while_the_agreement_does_not_cover_the_portal() {
    let fixture = two_nodes();
    let users = user_ids(&fixture.deployment);
    let closed = PortalAgreement::since(None);
    let unaccepted = edited(&fixture.deployment, |parts| {
        for user in &mut parts.users {
            user.agreement = None;
        }
    });
    for deployment in [&fixture.deployment, &unaccepted] {
        let refused = profile_selection(deployment, &users, FIXTURE_NOW, closed).unwrap_err();
        assert_eq!(refused.kind(), ProfilesErrorKind::NotCovered);
        let refused =
            export_profiles(deployment, &fixture.secrets, &users, FIXTURE_NOW, closed).unwrap_err();
        assert_eq!(refused.kind(), ProfilesErrorKind::NotCovered);
        assert_eq!(
            refused.to_string(),
            format!(
                "agreement revision {}, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links",
                AgreementVersion::CURRENT
            )
        );
    }
    // The gate comes before the list.
    let refused = profile_selection(&fixture.deployment, &[], FIXTURE_NOW, closed).unwrap_err();
    assert_eq!(refused.kind(), ProfilesErrorKind::NotCovered);
}

/// The users named must be distinct users of the deployment: an empty
/// list, an id no user has and a user named twice are refused by the
/// selection and the bundle alike, so no bundle names fewer users than the
/// operator did. A withheld user counts as named.
#[test]
fn the_users_named_are_distinct_users_of_the_deployment() {
    let fixture = two_nodes();
    let users = user_ids(&fixture.deployment);
    let deployment = edited(&fixture.deployment, |parts| {
        parts.users[0].status = suspended(SuspendReason::Operator);
    });
    let unknown = UserId::parse("zzzzzzzzzz").unwrap();
    assert!(!deployment.users().contains_key(&unknown));
    for (named, error) in [
        (Vec::new(), NamedUsersError::NoUsers),
        (
            vec![users[1].clone(), unknown.clone()],
            NamedUsersError::UnknownUser { user: unknown },
        ),
        (
            vec![users[0].clone(), users[1].clone(), users[0].clone()],
            NamedUsersError::DuplicateUser {
                user: users[0].clone(),
            },
        ),
    ] {
        let refused = profile_selection(&deployment, &named, FIXTURE_NOW, open()).unwrap_err();
        assert!(
            matches!(&refused, ProfilesError::Named(found) if *found == error),
            "{refused:?}"
        );
        assert_eq!(refused.kind(), ProfilesErrorKind::Named);
        assert_eq!(refused.to_string(), error.to_string());
        let refused = export_profiles(&deployment, &fixture.secrets, &named, FIXTURE_NOW, open())
            .unwrap_err();
        assert!(
            matches!(&refused, ProfilesError::Named(found) if *found == error),
            "{refused:?}"
        );
    }
}

fn user_refusal(error: &ProfilesError) -> (&UserId, &ExportError) {
    match error {
        ProfilesError::User { user, source } => (user, source),
        other => panic!("not a user's refusal: {other:?}"),
    }
}

/// A user to be delivered whose file cannot be made refuses the whole
/// bundle, named with the export's own refusal: at the selection when a
/// node has not confirmed the current generation, and when making the
/// files when a secret is missing. A withheld user needs no file, so the
/// same fault does not refuse a bundle that only withholds.
#[test]
fn a_user_whose_file_cannot_be_made_refuses_the_bundle() {
    let fixture = two_nodes();
    let users = user_ids(&fixture.deployment);
    let stale = edited(&fixture.deployment, |parts| {
        parts.config_generation = ConfigGeneration::INITIAL.next().unwrap();
        parts.users[0].status = suspended(SuspendReason::Operator);
    });
    let refused = profile_selection(&stale, &users, FIXTURE_NOW, open()).unwrap_err();
    let (user, source) = user_refusal(&refused);
    assert_eq!(*user, users[1]);
    assert_eq!(source.kind(), ExportErrorKind::NodeNotApplied);
    assert_eq!(
        refused.to_string(),
        format!("user {}'s file cannot be made", users[1])
    );
    let refused =
        export_profiles(&stale, &fixture.secrets, &users, FIXTURE_NOW, open()).unwrap_err();
    assert_eq!(
        user_refusal(&refused).1.kind(),
        ExportErrorKind::NodeNotApplied
    );
    let only_withheld = &users[..1];
    let selection = profile_selection(&stale, only_withheld, FIXTURE_NOW, open()).unwrap();
    assert_eq!(
        selection.withheld(),
        [(users[0].clone(), Withheld::Suspended)]
    );
    assert!(selection.secret_refs().is_empty());
    assert!(
        export_profiles(
            &stale,
            &SecretSnapshot::new(),
            only_withheld,
            FIXTURE_NOW,
            open()
        )
        .is_ok()
    );
    // Every check passes, but the snapshot holds no secret.
    let refused = export_profiles(
        &fixture.deployment,
        &SecretSnapshot::new(),
        &users,
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
            ProfilesError::NotCovered(PortalNotCovered {
                current: AgreementVersion::CURRENT,
            }),
            ProfilesErrorKind::NotCovered,
        ),
        (
            ProfilesError::Named(NamedUsersError::NoUsers),
            ProfilesErrorKind::Named,
        ),
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
