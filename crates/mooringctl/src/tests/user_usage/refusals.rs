// SPDX-License-Identifier: GPL-3.0-or-later

//! What `user usage` refuses: each with its message and causes on stderr,
//! nothing on stdout and no file written. The user is checked first, the
//! state before it, and only then is `usage/users.json` opened.

use std::fs;
use std::os::unix::fs::symlink;

use clap::Parser as _;
use mooring_agent_proto::UsageV1;
use mooring_daemon_core::usage::MAX_COLLECTED_USAGE_BYTES;
use mooring_model::{NodeId, UnixTime, UserId};
use mooring_store::{USAGE_DIRECTORY, USER_USAGE_FILE, write_sim_meter, write_user_usage};

use super::{collected, deployment, folder, holding, ids, lon1_october, run, wire};
use crate::cli::Cli;
use crate::error::{EXIT_LOCAL, EXIT_USAGE};
use crate::tests::export::arg;
use crate::tests::support::{Harness, NOW};
use crate::tests::user::harness_with;

/// The message a fault of the collected usage gives, then its cause.
fn fault(cause: &str) -> String {
    format!(
        "mooringctl: the usage the daemon collected (usage/users.json) cannot be read or is inconsistent: no history is shown or written\n  caused by: {cause}\n"
    )
}

/// Runs `user usage <user>` with `--out` into a fresh folder, and plainly:
/// both refuse with exit 1, print nothing and write no file; returns the
/// message.
fn refused(harness: &mut Harness, user: &UserId) -> String {
    let out = folder(harness).join("refused.json");
    let written = run(harness, user, &["--out", arg(&out)]);
    assert_eq!(written.code, EXIT_LOCAL, "{}", written.stderr);
    assert_eq!(written.stdout, "");
    assert!(!out.exists());
    let printed = run(harness, user, &[]);
    assert_eq!(printed.code, EXIT_LOCAL, "{}", printed.stderr);
    assert_eq!(printed.stdout, "");
    assert_eq!(printed.stderr, written.stderr);
    printed.stderr
}

/// An id the deployment does not hold is refused before the collected
/// usage is opened: a corrupt one there does not change the message.
#[test]
fn an_unknown_user_is_refused_before_the_usage_is_read() {
    let deployment = deployment(|_| {});
    let mut harness = harness_with(deployment);
    write_user_usage(&harness.support_dir(), b"not a ledger").unwrap();
    let stranger = UserId::from_low_bits(0x3_1415_9265);
    assert_eq!(
        refused(&mut harness, &stranger),
        format!("mooringctl: unknown user {stranger}\n")
    );
}

/// Without a deployment there is no user to read: the state is read first.
#[test]
fn without_a_state_it_is_refused() {
    let mut harness = Harness::new(0);
    let user = ids(&deployment(|_| {}))[0].clone();
    let state = harness.support_dir().join("state.json");
    assert_eq!(
        refused(&mut harness, &user),
        format!(
            "mooringctl: no state at {}: there is no deployment on this Mac yet (`exit init` creates it)\n",
            state.display()
        )
    );
}

/// No collected usage, with or without the usage folder, is its own
/// refusal naming the file: never a history with nothing in it.
#[test]
fn a_missing_document_is_refused() {
    let deployment = deployment(|_| {});
    let user = ids(&deployment)[0].clone();
    let mut harness = harness_with(deployment);
    let support = harness.support_dir();
    let message = format!(
        "mooringctl: no usage is collected at {}: the daemon writes it while it serves a deployment, and no history is shown without it\n",
        support
            .join(USAGE_DIRECTORY)
            .join(USER_USAGE_FILE)
            .display()
    );
    assert_eq!(refused(&mut harness, &user), message);
    // The SIM meter's file alone is no collected usage either.
    write_sim_meter(&support, b"{}").unwrap();
    assert_eq!(refused(&mut harness, &user), message);
}

/// What is planted where the collected usage belongs.
enum Planted {
    /// A file where the usage folder belongs.
    UsageFile,
    /// A folder where the document belongs.
    DocumentFolder,
    /// A link to a good document elsewhere where the document belongs.
    DocumentLink,
    /// A file of these bytes as the document.
    Document(Vec<u8>),
}

/// A usage path that is not a folder, a document that is a folder or a
/// link (to a good document, never followed), bytes that are no document,
/// another version, and one byte past the bound: each is refused with
/// its cause.
#[test]
fn an_unreadable_document_is_refused_with_its_cause() {
    let deployment = deployment(|_| {});
    let user = ids(&deployment)[0].clone();
    let good = collected(&deployment).encode().unwrap();
    let mut version_2: serde_json::Value = serde_json::from_slice(&good).unwrap();
    version_2["version"] = 2.into();
    let elsewhere = tempfile::tempdir().unwrap();
    let linked = elsewhere.path().join("users.json");
    fs::write(&linked, &good).unwrap();
    let invalid = "the collected usage ledger is invalid: ";
    for (planted, cause) in [
        (Planted::UsageFile, None),
        (Planted::DocumentFolder, None),
        (Planted::DocumentLink, None),
        (
            Planted::Document(b"{\"version\":".to_vec()),
            Some("EOF while parsing a value at line 1 column 11"),
        ),
        (
            Planted::Document(serde_json::to_vec(&version_2).unwrap()),
            Some("unsupported version 2"),
        ),
        (
            Planted::Document(vec![b' '; MAX_COLLECTED_USAGE_BYTES + 1]),
            Some("document exceeds 32 MiB"),
        ),
    ] {
        let mut harness = harness_with(deployment.clone());
        let support = harness.support_dir();
        let usage = support.join(USAGE_DIRECTORY);
        let document = usage.join(USER_USAGE_FILE);
        let cause = match planted {
            Planted::UsageFile => {
                fs::write(&usage, b"not a folder").unwrap();
                format!("{} is not a directory", usage.display())
            }
            Planted::DocumentFolder => {
                fs::create_dir_all(&document).unwrap();
                format!("{} is not a regular file", document.display())
            }
            Planted::DocumentLink => {
                fs::create_dir_all(&usage).unwrap();
                symlink(&linked, &document).unwrap();
                format!("{} is not a regular file", document.display())
            }
            Planted::Document(bytes) => {
                write_user_usage(&support, &bytes).unwrap();
                format!("{invalid}{}", cause.unwrap())
            }
        };
        assert_eq!(refused(&mut harness, &user), fault(&cause), "{cause}");
    }
    assert_eq!(fs::read(&linked).unwrap(), good);
}

/// A document that holds usage dated after now is inconsistent: refused
/// with the core's reason.
#[test]
fn an_inconsistent_document_is_refused_with_its_reason() {
    let deployment = deployment(|_| {});
    let user = ids(&deployment)[0].clone();
    let lon1 = NodeId::parse("lon1").unwrap();
    let mut future = collected(&deployment);
    let mut lon = future.node(&lon1).unwrap().clone();
    lon.record_month(
        &lon1,
        UsageV1 {
            month: "2026-10".parse().unwrap(),
            updated_at: wire(NOW + 60),
            traffic: lon1_october(&deployment).into_iter().collect(),
        },
        UnixTime::from_secs(NOW + 60),
    )
    .unwrap();
    future.set_node(lon1.clone(), lon);
    let mut harness = holding(deployment, &future);
    assert_eq!(
        refused(&mut harness, &user),
        fault(
            "the collected usage ledger is invalid: lon1 holds usage dated after now (the Mac's clock went back, or the document is corrupt)"
        )
    );
}

/// A malformed id is clap's usage error, and so are `--json` and `--out`
/// together: neither runs.
#[test]
fn a_malformed_id_and_both_outputs_are_usage_errors() {
    for (args, kind) in [
        (
            &["mooringctl", "user", "usage", "u99"][..],
            clap::error::ErrorKind::ValueValidation,
        ),
        (
            &["mooringctl", "user", "usage", "k7qd-m2xa"],
            clap::error::ErrorKind::ValueValidation,
        ),
        (
            &[
                "mooringctl",
                "user",
                "usage",
                "fxuseraaab",
                "--json",
                "--out",
                "x.json",
            ],
            clap::error::ErrorKind::ArgumentConflict,
        ),
        (
            &["mooringctl", "user", "usage"],
            clap::error::ErrorKind::MissingRequiredArgument,
        ),
    ] {
        let error = Cli::try_parse_from(args).unwrap_err();
        assert_eq!(error.kind(), kind, "{args:?}");
        assert_eq!(error.exit_code(), i32::from(EXIT_USAGE), "{args:?}");
    }
}
