// SPDX-License-Identifier: GPL-3.0-or-later

//! `user export-profiles` against a state file and an in-memory keychain
//! holding the fixture's secrets (design §9.5): the bundle it writes, the
//! users it names as left out, and the refusals that write nothing and
//! read no secret, the agreement's first.

use std::fs;

use mooring_export::export_profiles;
use mooring_fixtures::two_nodes_three_users;
use mooring_model::{
    AgreementVersion, PortalAgreement, SecretEntry, SecretRef, SuspendReason, UnixTime, UserId,
    UserStatus,
};
use mooring_store::SecretStore as _;

use super::export::{arg, exporting, mode};
use super::portal::closed_gate_refusal;
use super::support::{Harness, NOW};
use super::user::{fixture, harness_with, store};
use crate::error::EXIT_LOCAL;

fn open() -> PortalAgreement {
    PortalAgreement::since(Some(AgreementVersion::CURRENT))
}

fn run(harness: &mut Harness, out: &str) -> super::support::Outcome {
    harness.run(&["user", "export-profiles", "--out", out])
}

/// The file is the export crate's bundle at now, with mode 0600; a user
/// left out is named with the reason, and the output says where the file
/// goes and what the portal does with those left out.
#[test]
fn export_profiles_writes_the_bundle_of_every_user_to_be_served() {
    let deployment = fixture(|parts| {
        parts.users[0].status = UserStatus::Suspended {
            reason: SuspendReason::Operator,
            since: UnixTime::from_secs(NOW - 60),
        };
    });
    let left_out: UserId = deployment.users().keys().next().unwrap().clone();
    let (mut harness, folder) = exporting(deployment.clone());
    harness.portal_agreement = open();
    // The user left out needs no secret: none of theirs is read.
    for secret_ref in two_nodes_three_users().unwrap().secrets.refs() {
        if secret_ref.to_string().contains(left_out.as_str()) {
            harness.secrets.delete(&secret_ref).unwrap();
        }
    }
    let out = folder.join("profiles.json");
    let outcome = run(&mut harness, arg(&out));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let expected = export_profiles(
        &deployment,
        &two_nodes_three_users().unwrap().secrets,
        UnixTime::from_secs(NOW),
        open(),
    )
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), expected.expose_bytes());
    assert_eq!(mode(&out), 0o600);
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote {}: CFM profiles of 2 user(s), sing-box-json, mode 0600\nleft out: user {left_out} (suspended)\nimport it with `mooring-portal import-profiles` on the portal host, then delete it; the portal drops the profile of every user left out\n",
            out.display()
        )
    );
    // An export changes no state.
    assert_eq!(store(&harness).load().unwrap().deployment, deployment);
}

/// While the gate is closed nothing is written and no secret is read,
/// whatever the state and the keychain hold.
#[test]
fn export_profiles_is_refused_while_the_gate_is_closed() {
    let (mut harness, folder) = exporting(fixture(|_| {}));
    harness.portal_agreement = PortalAgreement::since(None);
    let out = folder.join("profiles.json");
    let outcome = run(&mut harness, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, closed_gate_refusal());
    assert!(!out.exists());
}

/// The gate comes before anything is read: with no state at all the
/// refusal is still the agreement's.
#[test]
fn export_profiles_checks_the_gate_before_reading_anything() {
    let mut bare = Harness::new(0);
    bare.portal_agreement = PortalAgreement::since(None);
    let out = bare.home.path().join("profiles.json");
    let outcome = run(&mut bare, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, closed_gate_refusal());
    assert!(!out.exists());
}

/// A user to be served whose file cannot be made refuses the bundle before
/// the keychain is read (it is empty here), with the export's own refusal.
#[test]
fn a_refused_bundle_writes_nothing_and_reads_no_secret() {
    let deployment = fixture(|parts| {
        parts.config_generation = parts.config_generation.next().unwrap();
    });
    let first = deployment.users().keys().next().unwrap().clone();
    let mut harness = harness_with(deployment);
    harness.portal_agreement = open();
    let out = harness.home.path().join("profiles.json");
    let outcome = run(&mut harness, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.starts_with(&format!(
            "mooringctl: no file was written: the profile bundle was refused\n  caused by: user {first}'s file cannot be made\n  caused by: node "
        )),
        "{}",
        outcome.stderr
    );
    assert!(!out.exists());
}

/// A file that exists already is never overwritten, and the keychain is
/// not read for it (it is empty here).
#[test]
fn export_profiles_never_overwrites_a_file() {
    let mut harness = harness_with(fixture(|_| {}));
    harness.portal_agreement = open();
    let out = harness.home.path().join("profiles.json");
    fs::write(&out, b"earlier\n").unwrap();
    let outcome = run(&mut harness, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: {} already exists; an export never overwrites a file\n",
            out.display()
        )
    );
    assert_eq!(fs::read(&out).unwrap(), b"earlier\n");
}

/// A secret of a user to be served missing from the keychain fails the
/// bundle and leaves no file.
#[test]
fn a_missing_secret_writes_no_bundle() {
    let deployment = fixture(|_| {});
    let last = deployment.users().keys().last().unwrap().clone();
    let (mut harness, folder) = exporting(deployment);
    harness.portal_agreement = open();
    let secrets = two_nodes_three_users().unwrap().secrets;
    let missing: SecretRef = secrets
        .refs()
        .into_iter()
        .find(|secret_ref| secret_ref.to_string().contains(last.as_str()))
        .unwrap();
    harness.secrets.delete(&missing).unwrap();
    let out = folder.join("profiles.json");
    let outcome = run(&mut harness, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: no file was written: reading the users' secrets from the keychain failed\n  caused by: secret {missing} is missing\n"
        )
    );
    assert!(!out.exists());
    // With the secret back the bundle is written.
    let material = secrets.material(&missing).unwrap();
    harness
        .secrets
        .put(SecretEntry::new(missing, material).unwrap())
        .unwrap();
    assert_eq!(run(&mut harness, arg(&out)).code, 0);
}
