// SPDX-License-Identifier: GPL-3.0-or-later

//! `user agree` against a state file in the harness's support directory
//! (design §7, §15.3, decision F9): the record it commits, the generation
//! and node confirmations it keeps, and the refusals that change nothing.

use std::fs;
use std::num::NonZeroU16;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use mooring_model::{
    AgreementRecord, AgreementVersion, CalendarDate, Deployment, DeploymentParts, RuntimeIntent,
    StateV2, UnixTime, UserId, UserStatus,
};
use mooring_store::Store;

use super::support::{Harness, NOW};
use crate::error::EXIT_LOCAL;

/// A harness whose support directory holds `deployment` as `state.json`,
/// encoded as the store writes it, with the exit disabled.
pub(crate) fn harness_with(deployment: Deployment) -> Harness {
    let harness = Harness::new(0);
    let dir = harness.support_dir();
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .unwrap();
    let state = StateV2 {
        deployment,
        runtime: RuntimeIntent::new(),
    };
    let mut bytes = serde_json::to_vec_pretty(&state).unwrap();
    bytes.push(b'\n');
    let path = dir.join("state.json");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    fs::write(&path, bytes).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    harness
}

/// The three-user fixture, edited.
pub(crate) fn fixture(edit: impl FnOnce(&mut DeploymentParts)) -> Deployment {
    let mut parts = mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .deployment
        .into_parts();
    edit(&mut parts);
    Deployment::try_from(parts).unwrap()
}

pub(crate) fn store(harness: &Harness) -> Store {
    Store::new(harness.support_dir())
}

pub(crate) fn state_bytes(harness: &Harness) -> Vec<u8> {
    fs::read(store(harness).state_path()).unwrap()
}

fn first_user(deployment: &Deployment) -> UserId {
    deployment.users().keys().next().unwrap().clone()
}

fn today() -> CalendarDate {
    CalendarDate::utc_of(UnixTime::from_secs(NOW)).unwrap()
}

#[test]
fn agree_records_the_current_revision_on_the_utc_day_and_keeps_every_confirmation() {
    let deployment = fixture(|parts| parts.users[0].agreement = None);
    let user = first_user(&deployment);
    let mut harness = harness_with(deployment.clone());
    let outcome = harness.run(&["user", "agree", user.as_str()]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        format!(
            "recorded: user {user} accepted agreement revision 1 on {} (UTC); no node apply is needed\n",
            today()
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(
        after.users()[&user].agreement,
        Some(AgreementRecord {
            version: AgreementVersion::CURRENT,
            accepted_on: today(),
        })
    );
    // A bookkeeping record: the generation and every node's confirmation
    // stay, so no node goes stale and the export needs no apply.
    assert_eq!(after.config_generation(), deployment.config_generation());
    assert_eq!(after.nodes(), deployment.nodes());
    let mut expected = deployment.into_parts();
    expected.users[0].agreement = after.users()[&user].agreement;
    assert_eq!(after, Deployment::try_from(expected).unwrap());
}

/// A record of the current revision is kept with its first day, and the
/// command says so; the state file is rewritten with the same content.
#[test]
fn agree_keeps_an_existing_record_of_the_current_revision() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    let recorded = deployment.users()[&user].agreement.unwrap();
    assert_ne!(recorded.accepted_on, today());
    let mut harness = harness_with(deployment.clone());
    let outcome = harness.run(&["user", "agree", user.as_str()]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "kept: user {user} already accepted agreement revision 1 on {}\n",
            recorded.accepted_on
        )
    );
    assert_eq!(store(&harness).load().unwrap().deployment, deployment);
}

/// Every refusal exits 1, names its cause, and leaves `state.json` byte
/// for byte as it was.
#[test]
fn agree_refuses_a_revoking_or_revoked_user_an_older_revision_and_an_unknown_user() {
    let revoking = fixture(|parts| parts.users[0].status = UserStatus::RevokePending);
    let revoked = fixture(|parts| {
        parts.users[0].status = UserStatus::Revoked;
        parts.users[0].per_node.clear();
    });
    let newer = fixture(|parts| {
        parts.users[0].agreement = Some(AgreementRecord {
            version: AgreementVersion::new(NonZeroU16::new(2).unwrap()),
            accepted_on: CalendarDate::parse("2026-11-02").unwrap(),
        });
    });
    let user = first_user(&revoking);
    let unknown = UserId::parse("zzzzzzzzzz").unwrap();
    for (deployment, target, cause) in [
        (
            revoking,
            &user,
            format!("user {user} is already pending revocation or revoked"),
        ),
        (
            revoked,
            &user,
            format!("user {user} is already pending revocation or revoked"),
        ),
        (
            newer,
            &user,
            format!(
                "user {user} accepted agreement revision 2; refusing to record the older revision 1"
            ),
        ),
        (fixture(|_| {}), &unknown, format!("unknown user {unknown}")),
    ] {
        let mut harness = harness_with(deployment);
        let before = state_bytes(&harness);
        let outcome = harness.run(&["user", "agree", target.as_str()]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stdout, "");
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: the state was not changed\n  caused by: the new or changed deployment is invalid\n  caused by: {cause}\n"
            )
        );
        assert_eq!(state_bytes(&harness), before);
    }
}

/// Without a state there is nothing to record into, whether the support
/// directory is missing or holds no `state.json`; the command says so and
/// creates neither the directory nor a state (an existing directory may
/// gain the store's own `state.lock`).
#[test]
fn every_user_command_without_a_state_says_there_is_no_deployment() {
    for make_dir in [false, true] {
        for args in [
            &["user", "agree", "abcdefghij"][..],
            &["user", "alias", "abcdefghij"][..],
            &["user", "add"][..],
            &[
                "user",
                "export",
                "abcdefghij",
                "--out",
                "/nonexistent/x.json",
            ][..],
        ] {
            let mut harness = Harness::new(0);
            let dir = harness.support_dir();
            if make_dir {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)
                    .unwrap();
            }
            let outcome = harness.run(args);
            assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
            assert_eq!(outcome.stdout, "");
            assert_eq!(
                outcome.stderr,
                format!(
                    "mooringctl: no state at {}: there is no deployment on this Mac yet (`exit init` creates it)\n",
                    dir.join("state.json").display()
                ),
                "{args:?}"
            );
            assert_eq!(dir.exists(), make_dir);
            assert!(!dir.join("state.json").exists());
        }
    }
}
