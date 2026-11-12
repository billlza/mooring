// SPDX-License-Identifier: GPL-3.0-or-later

//! Settling revocations (design §13.5): `node apply` and the apply job
//! record each revocation a node's confirmation settles, delete the user's
//! credentials on that node from the keychain only once that record is
//! committed, and report what still waits; a node that cannot be reached
//! keeps the user pending.

use std::collections::BTreeSet;

use mooring_agent_proto::{Generation, RequestKind, Response};
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::SecretRef;
use mooring_model::user::SuspendReason;
use mooring_model::{
    CalendarDate, ConfigGeneration, Deployment, DeploymentParts, NodeId, UnixTime, User, UserId,
    UserStatus,
};
use serde_json::Value;

use super::apply::{bundle_and_header_of, ready, run, script_hello_and_blobs, stand_in_engines};
use super::deployed::deployed_with;
use super::support::{Answered, COMMITTED, Expected, ExpectedRemote, Harness, NOW, Refusals};
use super::user::{fixture, store};
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;

const SECOND: &str = "fxuseraaac";
const THIRD: &str = "fxuseraaad";

fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

/// `user` in `parts`.
fn user<'p>(parts: &'p mut DeploymentParts, user: &str) -> &'p mut User {
    parts
        .users
        .iter_mut()
        .find(|candidate| candidate.id.as_str() == user)
        .unwrap()
}

/// The fixture at `generation` with `SECOND` pending revocation and each
/// node applied at the generation `applied` gives it.
fn revoking(generation: u64, applied: &[(&str, u64)]) -> Deployment {
    fixture(|parts| {
        parts.config_generation = ConfigGeneration::new(generation).unwrap();
        for found in &mut parts.nodes {
            let Some((_, at)) = applied.iter().find(|(id, _)| *id == found.id.as_str()) else {
                continue;
            };
            if let NodeLifecycle::Applied { applied, .. } = &mut found.lifecycle {
                applied.config_generation = ConfigGeneration::new(*at).unwrap();
            }
        }
        user(parts, SECOND).status = UserStatus::RevokePending;
    })
}

/// The keychain items `harness` holds of `user` on `node`.
fn user_items(harness: &Harness, user: &str, on: &str) -> BTreeSet<SecretRef> {
    harness
        .secrets
        .refs()
        .into_iter()
        .filter(|secret_ref| {
            matches!(secret_ref,
                SecretRef::UserVlessUuid(holder, held)
                | SecretRef::UserHy2Password(holder, held)
                | SecretRef::UserLoopUuid(holder, held)
                    if holder.as_str() == user && held.as_str() == on)
        })
        .collect()
}

/// Scripts `on`'s apply of `deployment`: its `Hello`, every blob present,
/// and the bundle served already at `generation`.
fn script_unchanged(
    harness: &Harness,
    engines: &std::path::Path,
    deployment: &Deployment,
    on: &str,
    generation: u64,
) {
    let (_, header) = bundle_and_header_of(harness, engines, deployment, on);
    script_hello_and_blobs(harness, header.blobs());
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(generation),
        })),
    );
}

/// The node's `Hello` fails as ssh does when it cannot be reached.
fn unreachable(harness: &Harness) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Hello,
        },
        Answered::Replied(Err(NodeError::Ssh {
            code: Some(255),
            stderr: "ssh: connect to the node: Operation timed out".to_owned(),
        })),
    );
}

fn node_apply(engines: &std::path::Path, on: &str) -> Vec<String> {
    [
        "node",
        "apply",
        on,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
    ]
    .map(str::to_owned)
    .to_vec()
}

fn status(harness: &Harness, text: &str) -> UserStatus {
    store(harness).load().unwrap().deployment.users()[&id(text)].status
}

/// `node apply` of a node behind records its confirmation, then the
/// revocation it settles: the user's credentials on that node leave the
/// state and then the keychain, and those on the other node stay while it
/// waits there. The second node's apply revokes the user, dated then.
#[test]
fn node_apply_commits_the_revocations_its_confirmation_settles() {
    let deployment = revoking(2, &[]);
    let (mut harness, engines) = ready(deployment.clone());
    assert_eq!(user_items(&harness, SECOND, "lon1").len(), 3);
    script_unchanged(&harness, &engines, &deployment, "lon1", 2);
    let outcome = run(&mut harness, &node_apply(&engines, "lon1"));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.ends_with(&format!(
            "applied: lon1 confirmed generation 2 (node generation 2); users holding it can be exported\n\
             revocation committed on lon1: {SECOND}, which still waits on ams1 (behind; its next apply commits it)\n"
        )),
        "{}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    let second = &after.users()[&id(SECOND)];
    assert_eq!(second.status, UserStatus::RevokePending);
    assert_eq!(second.per_node.keys().collect::<Vec<_>>(), [&node("ams1")]);
    assert_eq!(after.config_generation().get(), 2, "a record keeps it");
    assert!(user_items(&harness, SECOND, "lon1").is_empty());
    assert_eq!(user_items(&harness, SECOND, "ams1").len(), 3);
    assert_eq!(user_items(&harness, THIRD, "lon1").len(), 3);
    assert_eq!(harness.secrets.refs(), after.required_secrets());
    // ams1 applied an hour later: the user is revoked then.
    harness.now.set(NOW + 3600);
    script_unchanged(&harness, &engines, &after, "ams1", 2);
    let outcome = run(&mut harness, &node_apply(&engines, "ams1"));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.ends_with(&format!(
            "revocation committed on ams1: {SECOND}, now revoked; its credentials there are deleted from the keychain\n"
        )),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        status(&harness, SECOND),
        UserStatus::Revoked {
            since: at(NOW + 3600)
        }
    );
    assert!(user_items(&harness, SECOND, "ams1").is_empty());
    assert!(harness.nodes.script.borrow().is_empty());
}

/// `node apply` records the revocations of its own node only: one that
/// another node confirmed earlier waits for that node's next apply or the
/// job's next run, and the command says so.
#[test]
fn node_apply_records_its_own_nodes_revocations_only() {
    let deployment = revoking(2, &[("ams1", 2)]);
    let (mut harness, engines) = ready(deployment.clone());
    script_unchanged(&harness, &engines, &deployment, "lon1", 2);
    let outcome = run(&mut harness, &node_apply(&engines, "lon1"));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.ends_with(&format!(
            "revocation committed on lon1: {SECOND}, which still waits on ams1 (applied, not recorded yet; its next `node apply` or the apply job's next run records it)\n"
        )),
        "{}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(
        after.users()[&id(SECOND)]
            .per_node
            .keys()
            .collect::<Vec<_>>(),
        [&node("ams1")]
    );
}

/// A node that fails its apply commits nothing: the user stays pending
/// there, with its credentials.
#[test]
fn a_failed_apply_commits_nothing() {
    let deployment = revoking(2, &[]);
    let (mut harness, engines) = ready(deployment);
    unreachable(&harness);
    let outcome = run(&mut harness, &node_apply(&engines, "lon1"));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(!outcome.stdout.contains("revocation"), "{}", outcome.stdout);
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.users()[&id(SECOND)].per_node.len(), 2);
    assert_eq!(user_items(&harness, SECOND, "lon1").len(), 3);
}

/// A record committed whose keychain deletions were refused fails the
/// command after saying so: the node is applied, the user no longer holds
/// credentials there in the state, and the items are left for the
/// operator, as named.
#[test]
fn keychain_items_left_by_a_commit_fail_node_apply() {
    let deployment = revoking(2, &[]);
    let (mut harness, engines) = ready(deployment.clone());
    script_unchanged(&harness, &engines, &deployment, "lon1", 2);
    *harness.keychain.lock().unwrap() = Refusals {
        delete: Some(-25_308),
        ..Refusals::default()
    };
    let outcome = run(&mut harness, &node_apply(&engines, "lon1"));
    assert_eq!(outcome.code, EXIT_LOCAL);
    let committed = COMMITTED.trim_start_matches("mooringctl: ");
    assert!(
        outcome.stdout.contains(&format!(
            "revocation committed on lon1: {SECOND}, which still waits on ams1 (behind; its next apply commits it)\n\
             revocation committed on lon1: {SECOND}, but deleting its keychain items failed: {committed}: state committed at config generation 2, but deleting secrets failed: user/{SECOND}/lon1/vless-uuid: keychain delete failed with OSStatus -25308;"
        )),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stderr,
        "mooringctl: lon1 is applied, but 1 of the revocations it settled could not be recorded or left keychain items; the lines above say which\n"
    );
    let after = store(&harness).load().unwrap().deployment;
    assert!(
        !after.users()[&id(SECOND)]
            .per_node
            .contains_key(&node("lon1"))
    );
    assert_eq!(user_items(&harness, SECOND, "lon1").len(), 3, "left");
}

/// A harness for the job: the deployed daemon's, with stand-in engines in
/// the support directory.
fn job(deployment: Deployment) -> Harness {
    let mut harness = deployed_with(deployment);
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    stand_in_engines(&mut harness, &engines);
    harness
}

fn log(harness: &Harness) -> String {
    std::fs::read_to_string(
        harness
            .home
            .path()
            .join("Library/Logs/Mooring")
            .join("apply.log"),
    )
    .unwrap()
}

/// Both nodes behind, ams1 unreachable: the job applies lon1 and records
/// the revocation it settles, and reports the user still pending on ams1,
/// which it failed to apply. The next run, with ams1 reachable, revokes
/// the user. The log counts and names no user.
#[test]
fn the_job_commits_what_its_applies_settle_and_reports_what_waits() {
    let deployment = revoking(2, &[]);
    let mut harness = job(deployment.clone());
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    unreachable(&harness);
    script_unchanged(&harness, &engines, &deployment, "lon1", 2);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    let waits = "ams1 (behind; its next apply commits it)";
    assert!(
        outcome.stdout.ends_with(&format!(
            "lon1: applied\n\
             revocation committed on lon1: {SECOND}, which still waits on {waits}\n\
             revocation pending: {SECOND} waits on {waits}\n\
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 1 of 2 node(s) behind applied, 1 revocation(s) committed, 1 still pending; 1 failure(s)\n"
        )),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains("ams1: apply failed: the node could not be reached"),
        "{}",
        outcome.stdout
    );
    assert_eq!(status(&harness, SECOND), UserStatus::RevokePending);
    assert!(user_items(&harness, SECOND, "lon1").is_empty());
    assert_eq!(user_items(&harness, SECOND, "ams1").len(), 3);
    let first = log(&harness);
    assert!(
        first.contains(
            "mooringctl apply: revocations: 1 committed, 0 failed, 1 user(s) still pending\n"
        ),
        "{first}"
    );
    assert!(!first.contains("fxuser"), "{first}");
    // The next night ams1 answers.
    let after = store(&harness).load().unwrap().deployment;
    script_unchanged(&harness, &engines, &after, "ams1", 2);
    let outcome = harness.run(&["apply", "--now", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(
        value["revocations"],
        serde_json::json!({"done": {
            "committed": [{"user": SECOND, "node": "ams1", "revoked": true}],
            "failed": [],
            "pending": []
        }})
    );
    assert_eq!(
        status(&harness, SECOND),
        UserStatus::Revoked { since: at(NOW) }
    );
    assert!(user_items(&harness, SECOND, "ams1").is_empty());
    assert!(harness.nodes.script.borrow().is_empty());
}

/// A revocation a node confirmed earlier and a stopped run did not get to
/// record (the node is at the deployment's generation, the user still
/// pending there) is recorded by the next run without asking the node.
#[test]
fn the_job_records_a_revocation_confirmed_earlier() {
    let mut harness = job(revoking(2, &[("ams1", 2), ("lon1", 2)]));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.seen.borrow().is_empty(), "no node is asked");
    assert_eq!(
        outcome.stdout,
        format!(
            "revocation committed on ams1: {SECOND}\n\
             revocation committed on lon1: {SECOND}, now revoked; its credentials there are deleted from the keychain\n\
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 of 0 node(s) behind applied, 2 revocation(s) committed, 0 still pending; 0 failure(s)\n"
        )
    );
    assert_eq!(
        status(&harness, SECOND),
        UserStatus::Revoked { since: at(NOW) }
    );
}

/// A run that takes its clock for one that stepped back (a suspension for
/// quota dated after its time) records no revocation, as it makes no
/// removal: a record dates the revocation, and its removal 13 months later,
/// by that clock. What waits is still reported, and the next run records
/// it.
#[test]
fn a_clock_that_stepped_back_records_no_revocation() {
    let mut parts = revoking(2, &[("ams1", 2), ("lon1", 2)]).into_parts();
    user(&mut parts, THIRD).status = UserStatus::Suspended {
        reason: SuspendReason::QuotaExceeded {
            cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
        },
        since: at(NOW + 86_400),
    };
    let mut harness = job(Deployment::try_from(parts).unwrap());
    let before = store(&harness).load().unwrap().deployment;
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    let recorded =
        "applied, not recorded yet; its next `node apply` or the apply job's next run records it";
    assert!(
        outcome.stdout.contains(&format!(
            "removals skipped: the clock stepped back\n\
             revocations not recorded: the clock stepped back, and a record would date a revocation by it\n\
             revocation pending: {SECOND} waits on ams1 ({recorded}), lon1 ({recorded})\n"
        )),
        "{}",
        outcome.stdout
    );
    // The refused step is the one failure; what waits is counted.
    assert!(
        outcome.stdout.ends_with(
            ": 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 of 0 node(s) behind applied, 0 revocation(s) committed, 1 still pending; 1 failure(s)\n"
        ),
        "{}",
        outcome.stdout
    );
    assert_eq!(store(&harness).load().unwrap().deployment, before);
    assert_eq!(user_items(&harness, SECOND, "ams1").len(), 3);
    assert!(
        log(&harness).contains(
            "revocations not recorded: the clock stepped back; 1 user(s) still pending\n"
        ),
        "{}",
        log(&harness)
    );
    let json = harness.run(&["apply", "--now", "--json"]);
    let value: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(
        value["revocations"],
        serde_json::json!({"skipped": {"pending": [{"user": SECOND, "nodes": [
            {"node": "ams1", "waits_for": "record"},
            {"node": "lon1", "waits_for": "record"}
        ]}]}})
    );
}

/// A revocation the store fails to record (here every state write fails)
/// is reported and fails the run; the user stays pending on both nodes,
/// each now waiting only for the record, with its credentials.
#[test]
fn a_revocation_the_store_cannot_record_fails_the_run() {
    let mut harness = job(revoking(2, &[("ams1", 2), ("lon1", 2)]));
    let blocked = store(&harness).state_path().with_extension("json.tmp");
    std::fs::create_dir_all(blocked.join("keep")).unwrap();
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    let lines: Vec<&str> = outcome.stdout.lines().collect();
    assert!(
        lines[0].starts_with(&format!(
            "recording the revocation of {SECOND} on ams1 failed: the state was not changed: "
        )),
        "{}",
        outcome.stdout
    );
    assert!(lines[1].starts_with(&format!(
        "recording the revocation of {SECOND} on lon1 failed: "
    )));
    let record =
        "applied, not recorded yet; its next `node apply` or the apply job's next run records it";
    assert_eq!(
        lines[2],
        format!("revocation pending: {SECOND} waits on ams1 ({record}), lon1 ({record})")
    );
    assert!(lines[3].ends_with("0 revocation(s) committed, 1 still pending; 2 failure(s)"));
    assert_eq!(status(&harness, SECOND), UserStatus::RevokePending);
    assert_eq!(user_items(&harness, SECOND, "lon1").len(), 3);
    assert!(
        log(&harness).contains("revocations: 0 committed, 2 failed, 1 user(s) still pending\n"),
        "{}",
        log(&harness)
    );
}

/// A state that cannot be read once the node applies are done records no
/// revocation, and the run says so and fails.
#[test]
fn a_state_unreadable_after_the_applies_records_no_revocation() {
    let deployment = revoking(2, &[("ams1", 2)]);
    let mut harness = job(deployment.clone());
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    script_unchanged(&harness, &engines, &deployment, "lon1", 2);
    let state = store(&harness).state_path();
    *harness.nodes.meanwhile.borrow_mut() = Some((
        2,
        Box::new(move || std::fs::write(&state, b"not a state").unwrap()),
    ));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stdout
            .contains("\nrevocations not recorded: the state could not be read: "),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.ends_with("; 2 failure(s)\n"),
        "{}",
        outcome.stdout
    );
    assert!(
        log(&harness)
            .contains("mooringctl apply: revocations not recorded: the state could not be read\n"),
        "{}",
        log(&harness)
    );
}
