// SPDX-License-Identifier: GPL-3.0-or-later

//! `portal export` against a state file and the daemon's collected usage
//! in the harness's support directory (design §9.5): the snapshot it
//! writes, what it says without usage, and the refusals that write
//! nothing, the agreement's first.

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    Inbound, OpaqueUserId, Principal, StatsEmail, Traffic, UsageMonth, UsageV1,
};
use mooring_daemon_core::payments::Entitlements;
use mooring_daemon_core::portal::snapshot;
use mooring_daemon_core::usage::{CollectedUsage, NodeUsageHistory};
use mooring_model::{AgreementVersion, Deployment, NodeId, PortalAgreement, UnixTime, UserId};
use mooring_store::write_user_usage;

use super::export::{arg, exporting, mode};
use super::support::{BackupAnswer, Harness, NOW};
use super::user::{fixture, harness_with, store};
use crate::cli::Cli;
use crate::error::EXIT_LOCAL;

fn open() -> PortalAgreement {
    PortalAgreement::since(Some(AgreementVersion::CURRENT))
}

/// What both portal commands print while the gate is closed.
pub(crate) fn closed_gate_refusal() -> String {
    format!(
        "mooringctl: no file was written: nothing goes to the portal before a revision of the user agreement covers it and the users accept that revision (docs/runbooks/user-agreement.md)\n  caused by: agreement revision {}, the one this build ships, does not cover the portal: it names neither the portal's host nor subscription links\n",
        AgreementVersion::CURRENT
    )
}

fn users(deployment: &Deployment) -> Vec<UserId> {
    deployment.users().keys().cloned().collect()
}

fn wire(at: u64) -> mooring_agent_proto::UnixTime {
    mooring_agent_proto::UnixTime::from_secs(at)
}

/// What the daemon would have collected by `at`: each node's month so far,
/// sampled at `at`, with `bytes` of REALITY downlink for `user` on lon1.
pub(super) fn collected(at: u64, user: &UserId, bytes: u64) -> CollectedUsage {
    let mut collected = CollectedUsage::default();
    for name in ["lon1", "ams1"] {
        let node = NodeId::parse(name).unwrap();
        let traffic = if name == "lon1" {
            BTreeMap::from([(
                StatsEmail {
                    principal: Principal::User(OpaqueUserId::new(user.as_str()).unwrap()),
                    inbound: Inbound::Reality,
                },
                Traffic {
                    uplink: 0,
                    downlink: bytes,
                },
            )])
        } else {
            BTreeMap::new()
        };
        let mut history = NodeUsageHistory::default();
        history
            .record_month(
                &node,
                UsageV1 {
                    month: UsageMonth::containing(wire(at)).unwrap(),
                    updated_at: wire(at),
                    traffic,
                },
                UnixTime::from_secs(at),
            )
            .unwrap();
        collected.set_node(node, history);
    }
    collected
}

pub(super) fn with_usage(harness: &Harness, collected: &CollectedUsage) {
    write_user_usage(&harness.support_dir(), &collected.encode().unwrap()).unwrap();
}

fn run(harness: &mut Harness, users: &[UserId], out: &str) -> super::support::Outcome {
    let mut args = vec!["portal", "export"];
    for user in users {
        args.extend(["--user", user.as_str()]);
    }
    args.extend(["--out", out]);
    harness.run(&args)
}

/// With the daemon's usage at hand the snapshot carries it: the file is
/// the core's snapshot at now of the users named, with mode 0600, and the
/// output says what it holds and where it goes.
#[test]
fn portal_export_writes_the_snapshot_of_the_users_named() {
    let deployment = fixture(|_| {});
    let named = users(&deployment)[..2].to_vec();
    let (mut harness, folder) = exporting(deployment.clone());
    harness.portal_agreement = open();
    let usage = collected(NOW - 60, &named[0], 7_000);
    with_usage(&harness, &usage);
    let out = folder.join("snapshot.json");
    let outcome = run(&mut harness, &named, arg(&out));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let now = UnixTime::from_secs(NOW);
    let report = usage.aggregate(&deployment, now).unwrap();
    let expected = snapshot(
        &deployment,
        Some(&report),
        &Entitlements::none(),
        &named,
        now,
        open(),
    )
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), expected.bytes());
    assert_eq!(mode(&out), 0o600);
    let cycle = expected.cycle();
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote {}: portal snapshot of 2 user(s), mode 0600\nusage counted through @{NOW}, billing cycle {} to {}\nimport it with `mooring-portal import` on the portal host, then delete it\n",
            out.display(),
            cycle.start(),
            cycle.next_start()
        )
    );
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(document["users"][0]["cycle_served_bytes"], 7_000);
    // An export changes no state.
    assert_eq!(store(&harness).load().unwrap().deployment, deployment);
}

/// When the collection is behind, because the daemon never wrote the store
/// or has not pulled a node's usage for more than three minutes, there is
/// no report: the snapshot holds no figures, and the warning says why.
#[test]
fn without_usage_the_snapshot_holds_no_figures_and_says_why() {
    let deployment = fixture(|_| {});
    let named = users(&deployment)[..1].to_vec();
    let stale = collected(NOW - 181, &named[0], 7_000);
    for (case, reason) in [
        // Nodes are taken in id order, so ams1 is the first found.
        (
            0,
            "(ams1 may have counted traffic, but no usage ledger is given for it)",
        ),
        (
            1,
            "(ams1's usage is recorded to @1791919019, before @1791919200)",
        ),
    ] {
        let (mut harness, folder) = exporting(deployment.clone());
        harness.portal_agreement = open();
        if case == 1 {
            with_usage(&harness, &stale);
        }
        let out = folder.join("snapshot.json");
        let outcome = run(&mut harness, &named, arg(&out));
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert!(
            outcome
                .stderr
                .starts_with("mooringctl: warning: the snapshot holds no usage figures (")
                && outcome.stderr.contains(reason)
                && outcome
                    .stderr
                    .ends_with("); the portal shows each user's usage as unknown\n"),
            "{case}: {}",
            outcome.stderr
        );
        assert!(
            outcome
                .stdout
                .contains("\nno usage figures, billing cycle "),
            "{}",
            outcome.stdout
        );
        let expected = snapshot(
            &deployment,
            None,
            &Entitlements::none(),
            &named,
            UnixTime::from_secs(NOW),
            open(),
        )
        .unwrap();
        assert_eq!(fs::read(&out).unwrap(), expected.bytes());
    }
}

/// Collected usage that cannot be read, does not decode or contradicts
/// itself is a fault, not usage that is behind: nothing is written, since
/// null figures at the portal would hide it.
#[test]
fn a_usage_fault_refuses_the_snapshot() {
    let deployment = fixture(|_| {});
    let named = users(&deployment)[..1].to_vec();
    let top = "mooringctl: no file was written: the usage the daemon collected (usage/users.json) cannot be read or is inconsistent\n  caused by: ";
    for (case, cause) in [
        (
            "undecodable",
            Some("the collected usage ledger is invalid: "),
        ),
        (
            "a sample after now",
            Some("the collected usage ledger is invalid: node accounting sample is in the future"),
        ),
        ("unreadable", None),
    ] {
        let (mut harness, folder) = exporting(deployment.clone());
        harness.portal_agreement = open();
        let support = harness.support_dir();
        match case {
            "undecodable" => write_user_usage(&support, b"not a ledger").unwrap(),
            "a sample after now" => with_usage(&harness, &collected(NOW + 60, &named[0], 1)),
            _ => fs::write(support.join("usage"), b"not a folder").unwrap(),
        }
        let out = folder.join("snapshot.json");
        let outcome = run(&mut harness, &named, arg(&out));
        assert_eq!(outcome.code, EXIT_LOCAL, "{case}");
        assert_eq!(outcome.stdout, "", "{case}");
        assert!(
            outcome.stderr.starts_with(top)
                && cause.is_none_or(|cause| outcome.stderr[top.len()..].starts_with(cause)),
            "{case}: {}",
            outcome.stderr
        );
        assert!(!out.exists(), "{case}");
    }
}

/// The snapshot's folder is checked as an export's is: one Time Machine
/// backs up is warned about, and the file is written all the same.
#[test]
fn portal_export_warns_about_a_backed_up_folder() {
    let deployment = fixture(|_| {});
    let named = users(&deployment)[..1].to_vec();
    let (mut harness, folder) = exporting(deployment.clone());
    harness.portal_agreement = open();
    with_usage(&harness, &collected(NOW, &named[0], 1));
    harness.backups.answer = BackupAnswer::Included;
    let out = folder.join("snapshot.json");
    let outcome = run(&mut harness, &named, arg(&out));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let dir = fs::canonicalize(&folder).unwrap();
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: warning: Time Machine backs up {dir}; exclude it with `tmutil addexclusion {dir}`\n",
            dir = dir.display()
        )
    );
    assert!(out.exists());
}

/// While the gate is closed nothing is written, whatever the state holds:
/// the gate is the first check, before even the state is read.
#[test]
fn portal_export_is_refused_while_the_gate_is_closed() {
    let deployment = fixture(|_| {});
    let named = users(&deployment);
    let (mut harness, folder) = exporting(deployment);
    harness.portal_agreement = PortalAgreement::since(None);
    let out = folder.join("snapshot.json");
    let outcome = run(&mut harness, &named, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, closed_gate_refusal());
    assert!(!out.exists());
    let mut bare = Harness::new(0);
    bare.portal_agreement = PortalAgreement::since(None);
    let out = bare.home.path().join("snapshot.json");
    let outcome = run(&mut bare, &named, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, closed_gate_refusal());
}

/// A refusal of the core writes nothing and comes before the file's own
/// checks: a user without the acceptance is named even when the file
/// exists already, which is then left as it was.
#[test]
fn a_refused_snapshot_writes_nothing() {
    let deployment = fixture(|parts| parts.users[1].agreement = None);
    let named = users(&deployment);
    let mut harness = harness_with(deployment);
    harness.portal_agreement = open();
    let out = harness.home.path().join("snapshot.json");
    fs::write(&out, b"earlier\n").unwrap();
    let outcome = run(&mut harness, &named, arg(&out));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: no file was written: the portal snapshot was refused\n  caused by: user {} has not accepted agreement revision {}: no acceptance is recorded\n",
            named[1],
            AgreementVersion::CURRENT
        )
    );
    assert_eq!(fs::read(&out).unwrap(), b"earlier\n");
    // Once the users are acceptable, the existing file is still never
    // overwritten.
    let outcome = run(&mut harness, &named[..1], arg(&out));
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

/// The command names its users: without one `--user` it is a usage error,
/// so no snapshot of every user is ever made by default; and a public
/// alias is not a user id, so it is refused before anything runs.
#[test]
fn portal_export_needs_at_least_one_user_id() {
    use clap::Parser as _;
    let error =
        Cli::try_parse_from(["mooringctl", "portal", "export", "--out", "x.json"]).unwrap_err();
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    let error = Cli::try_parse_from([
        "mooringctl",
        "portal",
        "export",
        "--user",
        "k7qd-m2xa",
        "--out",
        "x.json",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
}
