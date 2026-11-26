// SPDX-License-Identifier: GPL-3.0-or-later

//! `user export` against a state file and an in-memory keychain holding
//! the fixture's secrets (design §9.2, §9.4, §12, decision F9): the file it
//! writes, its warnings, and the refusals that write nothing.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mooring_export::{ExportFormat, export_user};
use mooring_model::{
    AbuseGuardAgreement, AgreementRecord, AgreementVersion, CalendarDate, Deployment, SecretEntry,
    SuspendReason, UnixTime, UserId, UserStatus,
};
use mooring_store::{InMemorySecretStore, SecretStore};

use super::support::{BackupAnswer, Harness, NOW};
use super::user::{fixture, harness_with, store};
use crate::error::EXIT_LOCAL;

/// A harness holding `deployment` and every secret of the three-user
/// fixture in its keychain, and an export folder `exports` in its home.
pub(crate) fn exporting(deployment: Deployment) -> (Harness, PathBuf) {
    let mut harness = harness_with(deployment);
    fill(&mut harness.secrets);
    let folder = harness.home.path().join("exports");
    fs::create_dir(&folder).unwrap();
    (harness, folder)
}

pub(crate) fn fill(secrets: &mut InMemorySecretStore) {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    for secret_ref in fixture.secrets.refs() {
        let material = fixture.secrets.material(&secret_ref).unwrap();
        secrets
            .put(SecretEntry::new(secret_ref, material).unwrap())
            .unwrap();
    }
}

fn first_user(deployment: &Deployment) -> UserId {
    deployment.users().keys().next().unwrap().clone()
}

/// What `export_user` makes of the fixture's secrets at the harness's now.
fn expected(deployment: &Deployment, user: &UserId, format: ExportFormat) -> Vec<u8> {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    export_user(
        deployment,
        &fixture.secrets,
        user,
        format,
        UnixTime::from_secs(NOW),
    )
    .unwrap()
    .expose_bytes()
    .to_vec()
}

pub(crate) fn arg(path: &Path) -> &str {
    path.to_str().unwrap()
}

pub(crate) fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The default format is sing-box JSON, written with mode 0600 into a
/// folder Time Machine excludes, with no warning.
#[test]
fn export_writes_sing_box_json_with_mode_0600() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    let out = folder.join("user.json");
    let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote {}: sing-box-json for user {user}, mode 0600\ndeliver it as docs/runbooks/delivery.md says, then delete it\n",
            out.display()
        )
    );
    assert_eq!(
        fs::read(&out).unwrap(),
        expected(&deployment, &user, ExportFormat::SingBoxJson)
    );
    assert_eq!(mode(&out), 0o600);
    assert_eq!(
        *harness.backups.asked.borrow(),
        vec![fs::canonicalize(&folder).unwrap()]
    );
    // An export changes no state.
    assert_eq!(store(&harness).load().unwrap().deployment, deployment);
}

#[test]
fn export_writes_clash_yaml_on_request() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    let out = folder.join("user.yaml");
    let outcome = harness.run(&[
        "user",
        "export",
        user.as_str(),
        "--format",
        "clash",
        "--out",
        arg(&out),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(outcome.stdout.contains(": clash-yaml for user "));
    assert_eq!(
        fs::read(&out).unwrap(),
        expected(&deployment, &user, ExportFormat::ClashYaml)
    );
}

/// Decision F9 and design §22 M5: without the agreement the export is
/// refused, before any secret is read (the keychain here is empty), with
/// the command that records it; after `user agree`, which keeps the
/// generation and every node's confirmation, the same export writes the
/// file with no node apply in between. That holds where the acceptance
/// leaves the abuse guard's coverage as it was, here under a closed gate;
/// the shipped gate makes the export wait for an apply
/// ([`an_acceptance_that_starts_the_abuse_guard_waits_for_an_apply`]).
#[test]
fn export_needs_the_agreement_and_user_agree_is_enough() {
    let deployment = fixture(|parts| parts.users[0].agreement = None);
    let user = first_user(&deployment);
    let mut harness = harness_with(deployment.clone());
    harness.abuse_guard = AbuseGuardAgreement::since(None);
    let folder = harness.home.path().join("exports");
    fs::create_dir(&folder).unwrap();
    let out = folder.join("user.json");
    let args = ["user", "export", user.as_str(), "--out", arg(&out)];
    let refused = harness.run(&args);
    assert_eq!(refused.code, EXIT_LOCAL);
    assert_eq!(refused.stdout, "");
    assert_eq!(
        refused.stderr,
        format!(
            "mooringctl: no file was written: record the user's acceptance with `mooringctl user agree {user}` once the user has accepted the agreement (docs/runbooks/user-agreement.md)\n  caused by: user {user} has not accepted agreement revision 1 or a later one: no acceptance is recorded\n"
        )
    );
    assert!(!out.exists());
    assert_eq!(harness.run(&["user", "agree", user.as_str()]).code, 0);
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.config_generation(), deployment.config_generation());
    assert_eq!(after.nodes(), deployment.nodes());
    fill(&mut harness.secrets);
    let written = harness.run(&args);
    assert_eq!(written.code, 0, "{}", written.stderr);
    assert_eq!(
        fs::read(&out).unwrap(),
        expected(&after, &user, ExportFormat::SingBoxJson)
    );
}

/// Under the shipped gate, open from revision 2, `user agree` brings a user
/// without an acceptance under the abuse guard, which changes every bundle
/// that serves them (design §11.8): the generation is bumped, so the export
/// is refused, and writes nothing, until the nodes the file names have
/// applied it.
#[test]
fn an_acceptance_that_starts_the_abuse_guard_waits_for_an_apply() {
    let deployment = fixture(|parts| parts.users[0].agreement = None);
    let user = first_user(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    assert_eq!(harness.abuse_guard, AbuseGuardAgreement::SHIPPED);
    let out = folder.join("user.json");
    assert_eq!(harness.run(&["user", "agree", user.as_str()]).code, 0);
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(
        after.config_generation(),
        deployment.config_generation().next().unwrap()
    );
    let refused = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(refused.code, EXIT_LOCAL);
    assert_eq!(refused.stdout, "");
    let stale = format!(
        " cannot be exported: it confirmed generation {}, the deployment is at {}\n",
        deployment.config_generation(),
        after.config_generation()
    );
    assert!(
        refused.stderr.starts_with(
            "mooringctl: no file was written: the export was refused\n  caused by: node "
        ) && refused.stderr.ends_with(&stale),
        "{}",
        refused.stderr
    );
    assert!(!out.exists());
}

/// A user added before their first payment (`user add --unpaid`) is
/// suspended at expiry and served nowhere, so their acceptance brings them
/// under the abuse guard in no bundle: under the shipped gate it is the
/// bookkeeping record, and their file is exported at once with no apply in
/// between, as the unpaid flow has it (design §9.6, §11.8). The resume
/// that serves them, a configuration change, covers them.
#[test]
fn an_unpaid_users_agreement_needs_no_apply_before_the_export() {
    let now = UnixTime::from_secs(NOW);
    let deployment = fixture(|parts| {
        parts.users[0].agreement = None;
        parts.users[0].status = UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: now,
        };
        parts.users[0].policy.expires_at = Some(now);
    });
    let user = first_user(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    assert_eq!(harness.abuse_guard, AbuseGuardAgreement::SHIPPED);
    let agreed = harness.run(&["user", "agree", user.as_str()]);
    assert_eq!(agreed.code, 0, "{}", agreed.stderr);
    assert_eq!(
        agreed.stdout,
        format!(
            "recorded: user {user} accepted agreement revision {} on {} (UTC); no node apply is needed\n",
            AgreementVersion::CURRENT,
            CalendarDate::utc_of(now).unwrap()
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.config_generation(), deployment.config_generation());
    assert_eq!(after.nodes(), deployment.nodes());
    let out = folder.join("user.json");
    let written = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(written.code, 0, "{}", written.stderr);
    assert_eq!(
        fs::read(&out).unwrap(),
        expected(&after, &user, ExportFormat::SingBoxJson)
    );
}

/// A user who accepted revision 1, as every pilot user did before revision
/// 2 (2026-11-06), gets their file without accepting again, and their
/// record stays as it was (the operator's decision of 2026-11-15).
#[test]
fn a_user_who_accepted_revision_1_gets_a_file_without_accepting_again() {
    let first = AgreementRecord {
        version: AgreementVersion::FIRST,
        accepted_on: CalendarDate::parse("2026-10-18").unwrap(),
    };
    assert!(first.version < AgreementVersion::CURRENT);
    let deployment = fixture(|parts| parts.users[0].agreement = Some(first));
    let user = first_user(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    let out = folder.join("user.json");
    let written = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(written.code, 0, "{}", written.stderr);
    assert_eq!(
        fs::read(&out).unwrap(),
        expected(&deployment, &user, ExportFormat::SingBoxJson)
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.users().get(&user).unwrap().agreement, Some(first));
}

/// Every other refusal the export makes before reading a secret is
/// reported as refused, with an empty keychain, and writes nothing.
#[test]
fn an_export_refusal_writes_nothing() {
    let deployment = fixture(|parts| {
        parts.config_generation = parts.config_generation.next().unwrap();
    });
    let user = first_user(&deployment);
    let mut harness = harness_with(deployment);
    let out = harness.home.path().join("user.json");
    let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.starts_with(
            "mooringctl: no file was written: the export was refused\n  caused by: node "
        ),
        "{}",
        outcome.stderr
    );
    assert!(!out.exists());
}

/// A file is never overwritten, and the keychain is not read for it.
#[test]
fn export_never_overwrites_a_file() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    let mut harness = harness_with(deployment);
    let out = harness.home.path().join("user.json");
    fs::write(&out, b"earlier\n").unwrap();
    let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
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

/// A folder that cannot be used fails the export before the keychain is
/// read (the keychain here is empty): no secret is read for a file that
/// cannot be written.
#[test]
fn export_into_a_missing_folder_fails_before_reading_the_keychain() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    let mut harness = harness_with(deployment);
    let out = harness.home.path().join("absent").join("user.json");
    let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.starts_with(&format!(
            "mooringctl: cannot use the folder of {}\n  caused by: ",
            out.display()
        )),
        "{}",
        outcome.stderr
    );
    assert!(!out.exists());
    // A path through a file cannot even be looked at.
    let file = harness.home.path().join("file");
    fs::write(&file, b"").unwrap();
    let out = file.join("user.json");
    let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: cannot use the folder of {}\n  caused by: Not a directory (os error 20)\n",
            out.display()
        )
    );
}

/// A folder that takes no new file fails the write after every check:
/// nothing of the file is left.
#[test]
fn export_into_a_folder_that_takes_no_file_leaves_nothing() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    let (mut harness, folder) = exporting(deployment);
    let out = folder.join("user.json");
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: cannot write the export to {}; no part of it is left\n  caused by: Permission denied (os error 13)\n",
            out.display()
        )
    );
    assert!(!out.exists());
}

/// A secret missing from the keychain fails the export and leaves no file.
#[test]
fn a_missing_secret_writes_nothing() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    let (mut harness, folder) = exporting(deployment.clone());
    let fixture_secrets = mooring_fixtures::two_nodes_three_users().unwrap().secrets;
    let user_ref = fixture_secrets
        .refs()
        .into_iter()
        .find(|secret_ref| secret_ref.to_string().contains(user.as_str()))
        .unwrap();
    harness.secrets.delete(&user_ref).unwrap();
    let out = folder.join("user.json");
    let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: no file was written: reading the user's secrets from the keychain failed\n  caused by: secret {user_ref} is missing\n"
        )
    );
    assert!(!out.exists());
}

/// A folder in the Desktop, in Documents or in iCloud Drive, or one Time
/// Machine backs up or cannot tell about, is warned about; the file is
/// written all the same.
#[test]
fn export_warns_about_synced_and_backed_up_folders() {
    let deployment = fixture(|_| {});
    let user = first_user(&deployment);
    for (place, relative) in [
        ("the Desktop", "Desktop"),
        ("Documents", "Documents/exports"),
        (
            "iCloud Drive",
            "Library/Mobile Documents/com~apple~CloudDocs",
        ),
    ] {
        let (mut harness, _) = exporting(deployment.clone());
        let folder = harness.home.path().join(relative);
        fs::create_dir_all(&folder).unwrap();
        let out = folder.join("user.json");
        let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: warning: {} is in {place}; keep exports in a folder outside iCloud Drive, the Desktop and Documents (docs/runbooks/delivery.md, section 0)\n",
                fs::canonicalize(&folder).unwrap().display()
            )
        );
        assert!(out.exists());
    }
    for (answer, warning) in [
        (
            BackupAnswer::Included,
            "Time Machine backs up {dir}; exclude it with `tmutil addexclusion {dir}`",
        ),
        (
            BackupAnswer::Unanswered,
            "cannot tell whether Time Machine excludes {dir}: tmutil reported neither excluded nor included",
        ),
    ] {
        let (mut harness, folder) = exporting(deployment.clone());
        harness.backups.answer = answer;
        let out = folder.join("user.json");
        let outcome = harness.run(&["user", "export", user.as_str(), "--out", arg(&out)]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        let dir = fs::canonicalize(&folder).unwrap();
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: warning: {}\n",
                warning.replace("{dir}", &dir.display().to_string())
            )
        );
        assert!(out.exists());
    }
}
