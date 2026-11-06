// SPDX-License-Identifier: GPL-3.0-or-later

//! `user export-profiles` against a state file and an in-memory keychain
//! holding the fixture's secrets (design §9.5): the bundle it writes of the
//! users named, the users it names as withheld, and the refusals that
//! write nothing and read no secret, the agreement's first.

use std::fs;

use mooring_export::export_profiles;
use mooring_fixtures::two_nodes_three_users;
use mooring_model::{
    AgreementVersion, Deployment, PortalAgreement, SecretEntry, SecretRef, SuspendReason, UnixTime,
    UserId, UserStatus,
};
use mooring_store::SecretStore as _;

use super::export::{arg, exporting, mode};
use super::portal::closed_gate_refusal;
use super::support::{Harness, NOW};
use super::user::{fixture, harness_with, store};
use crate::cli::Cli;
use crate::error::EXIT_LOCAL;

fn open() -> PortalAgreement {
    PortalAgreement::since(Some(AgreementVersion::CURRENT))
}

fn ids(deployment: &Deployment) -> Vec<UserId> {
    deployment.users().keys().cloned().collect()
}

/// `user export-profiles --user <id>... --out <out>`.
fn run(harness: &mut Harness, users: &[UserId], out: &str) -> super::support::Outcome {
    let mut args = vec!["user", "export-profiles"];
    for user in users {
        args.extend(["--user", user.as_str()]);
    }
    args.extend(["--out", out]);
    harness.run(&args)
}

/// Deletes every secret of `user`'s own from `harness`'s keychain, so a
/// command that reads one fails.
fn forget_secrets(harness: &mut Harness, user: &UserId) {
    for secret_ref in two_nodes_three_users().unwrap().secrets.refs() {
        if secret_ref.to_string().contains(user.as_str()) {
            harness.secrets.delete(&secret_ref).unwrap();
        }
    }
}

/// The file is the export crate's bundle of the users named at now, with
/// mode 0600; each user withheld is named with the reason, and the output
/// says what the portal's import does to them and where the file goes.
/// Withheld for their status, not for an acceptance, they bring no warning.
#[test]
fn export_profiles_writes_the_bundle_of_the_users_named() {
    let deployment = fixture(|parts| {
        parts.users[0].status = UserStatus::Suspended {
            reason: SuspendReason::Operator,
            since: UnixTime::from_secs(NOW - 60),
        };
        parts.users[1].status = UserStatus::RevokePending;
    });
    let users = ids(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    harness.portal_agreement = open();
    // The users withheld need no secret: none of theirs is read.
    forget_secrets(&mut harness, &users[0]);
    forget_secrets(&mut harness, &users[1]);
    let out = folder.join("profiles.json");
    let outcome = run(&mut harness, &users, arg(&out));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let expected = export_profiles(
        &deployment,
        &two_nodes_three_users().unwrap().secrets,
        &users,
        UnixTime::from_secs(NOW),
        open(),
    )
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), expected.expose_bytes());
    assert_eq!(mode(&out), 0o600);
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote {}: CFM profiles of 1 user(s) and 2 withheld, sing-box-json, mode 0600\nwithheld: user {} (suspended)\nwithheld: user {} (being revoked)\nimporting it removes each withheld user's profile and ends their subscription link for good: once delivered again, they generate a new link\nimport it with `mooring-portal import-profiles` on the portal host, then delete it\n",
            out.display(),
            users[0],
            users[1]
        )
    );
    // An export changes no state.
    assert_eq!(store(&harness).load().unwrap().deployment, deployment);
}

/// Only the users named are in the bundle, and the others' secrets are not
/// read; with no one withheld the output says nothing of withholding.
#[test]
fn export_profiles_holds_only_the_users_named() {
    let deployment = fixture(|_| {});
    let users = ids(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    harness.portal_agreement = open();
    for other in [&users[0], &users[2]] {
        forget_secrets(&mut harness, other);
    }
    let named = &users[1..2];
    let out = folder.join("profiles.json");
    let outcome = run(&mut harness, named, arg(&out));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let expected = export_profiles(
        &deployment,
        &two_nodes_three_users().unwrap().secrets,
        named,
        UnixTime::from_secs(NOW),
        open(),
    )
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), expected.expose_bytes());
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote {}: CFM profiles of 1 user(s) and 0 withheld, sing-box-json, mode 0600\nimport it with `mooring-portal import-profiles` on the portal host, then delete it\n",
            out.display()
        )
    );
}

/// A bundle that withholds every user named is written, reading no secret
/// (the keychain is empty here): the portal stops serving them on import.
/// Users withheld for want of the current acceptance bring a warning,
/// since after a new revision such an export is most likely too early.
#[test]
fn a_bundle_withholding_everyone_is_written_without_reading_a_secret() {
    let deployment = fixture(|parts| {
        for user in &mut parts.users {
            user.agreement = None;
        }
    });
    let users = ids(&deployment);
    let mut harness = harness_with(deployment);
    harness.portal_agreement = open();
    let folder = harness.home.path().join("exports");
    fs::create_dir(&folder).unwrap();
    let out = folder.join("profiles.json");
    let outcome = run(&mut harness, &users[..2], arg(&out));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: warning: 2 user(s) named have not accepted agreement revision {}, the current one; importing this bundle ends their subscription links for good. To keep their links, delete the file and export again once they have accepted (docs/runbooks/delivery.md, section 11)\n",
            AgreementVersion::CURRENT
        )
    );
    assert!(
        outcome.stdout.contains(&format!(
            "CFM profiles of 0 user(s) and 2 withheld, sing-box-json, mode 0600\nwithheld: user {} (has not accepted agreement revision {}: no acceptance is recorded)\nwithheld: user {} (has not accepted agreement revision {}: no acceptance is recorded)\n",
            users[0],
            AgreementVersion::CURRENT,
            users[1],
            AgreementVersion::CURRENT
        )),
        "{}",
        outcome.stdout
    );
    assert!(
        fs::read_to_string(&out)
            .unwrap()
            .contains("\"profiles\": [],"),
    );
}

/// While the gate is closed nothing is written and no secret is read,
/// whatever the state and the keychain hold.
#[test]
fn export_profiles_is_refused_while_the_gate_is_closed() {
    let deployment = fixture(|_| {});
    let users = ids(&deployment);
    let (mut harness, folder) = exporting(deployment);
    harness.portal_agreement = PortalAgreement::since(None);
    let out = folder.join("profiles.json");
    let outcome = run(&mut harness, &users, arg(&out));
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
    let outcome = run(
        &mut bare,
        &[UserId::parse("aaaaaaaaaa").unwrap()],
        arg(&out),
    );
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, closed_gate_refusal());
    assert!(!out.exists());
}

/// A user named twice, or an id no user has, refuses the bundle: nothing
/// is written, and no secret is read (the keychain is empty here).
#[test]
fn an_unknown_or_repeated_user_refuses_the_bundle() {
    let deployment = fixture(|_| {});
    let users = ids(&deployment);
    let unknown = UserId::parse("zzzzzzzzzz").unwrap();
    assert!(!deployment.users().contains_key(&unknown));
    let mut harness = harness_with(deployment);
    harness.portal_agreement = open();
    let out = harness.home.path().join("profiles.json");
    for (named, cause) in [
        (
            vec![users[0].clone(), unknown.clone()],
            format!("unknown user {unknown}"),
        ),
        (
            vec![users[1].clone(), users[1].clone()],
            format!("user {} is named twice", users[1]),
        ),
    ] {
        let outcome = run(&mut harness, &named, arg(&out));
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stdout, "");
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: no file was written: the profile bundle was refused\n  caused by: {cause}\n"
            )
        );
        assert!(!out.exists());
    }
}

/// The command names its users: without one `--user` it is a usage error,
/// so no bundle of every user is ever made by default; and a public alias
/// is not a user id, so it is refused before anything runs.
#[test]
fn export_profiles_needs_at_least_one_user_id() {
    use clap::Parser as _;
    let error = Cli::try_parse_from(["mooringctl", "user", "export-profiles", "--out", "x.json"])
        .unwrap_err();
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    let error = Cli::try_parse_from([
        "mooringctl",
        "user",
        "export-profiles",
        "--user",
        "k7qd-m2xa",
        "--out",
        "x.json",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
}

/// A user to be delivered whose file cannot be made refuses the bundle
/// before the keychain is read (it is empty here), with the export's own
/// refusal.
#[test]
fn a_refused_bundle_writes_nothing_and_reads_no_secret() {
    let deployment = fixture(|parts| {
        parts.config_generation = parts.config_generation.next().unwrap();
    });
    let users = ids(&deployment);
    let mut harness = harness_with(deployment);
    harness.portal_agreement = open();
    let out = harness.home.path().join("profiles.json");
    let outcome = run(&mut harness, &users, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.starts_with(&format!(
            "mooringctl: no file was written: the profile bundle was refused\n  caused by: user {}'s file cannot be made\n  caused by: node ",
            users[0]
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
    let deployment = fixture(|_| {});
    let users = ids(&deployment);
    let mut harness = harness_with(deployment);
    harness.portal_agreement = open();
    let out = harness.home.path().join("profiles.json");
    fs::write(&out, b"earlier\n").unwrap();
    let outcome = run(&mut harness, &users, arg(&out));
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

/// A secret of a user to be delivered missing from the keychain fails the
/// bundle and leaves no file.
#[test]
fn a_missing_secret_writes_no_bundle() {
    let deployment = fixture(|_| {});
    let users = ids(&deployment);
    let last = users.last().unwrap().clone();
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
    let outcome = run(&mut harness, &users, arg(&out));
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
    assert_eq!(run(&mut harness, &users, arg(&out)).code, 0);
}
