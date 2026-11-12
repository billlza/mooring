// SPDX-License-Identifier: GPL-3.0-or-later

//! Settling revocations (design §13.5): `node apply` and the apply job
//! record each revocation a node's confirmation settles, delete the user's
//! credentials on that node from the keychain only once that record is
//! committed, and report what still waits; a node that cannot be reached
//! keeps the user pending. And the job's revocations at expiry (design
//! §13.6; the agreement's clause 6 from revision 2): a user suspended at
//! expiry whose service was not renewed in three months is revoked, when
//! the agreement they accepted provides for it, and reported otherwise.

use std::collections::BTreeSet;

use mooring_agent_proto::{Generation, RequestKind, Response};
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::SecretRef;
use mooring_model::user::{SuspendReason, UserPolicy};
use mooring_model::{
    AgreementVersion, CalendarDate, ConfigGeneration, Deployment, DeploymentParts,
    ExpiryRevocation, NodeId, UnixTime, User, UserId, UserStatus,
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
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 1 of 2 node(s) behind applied, 0 revoked at expiry, 1 revocation(s) committed, 1 still pending; 1 failure(s)\n"
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
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 of 0 node(s) behind applied, 0 revoked at expiry, 2 revocation(s) committed, 0 still pending; 0 failure(s)\n"
        )
    );
    assert_eq!(
        status(&harness, SECOND),
        UserStatus::Revoked { since: at(NOW) }
    );
}

/// The fixture's nodes adopted, never applied, so that the job applies
/// none, with `SECOND` suspended at expiry, its service having expired
/// `days` days before the run.
fn unrenewed(days: u64) -> Deployment {
    fixture(|parts| {
        for found in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &found.lifecycle {
                found.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
        let second = user(parts, SECOND);
        let expired = at(NOW - days * 86_400);
        second.policy = UserPolicy {
            expires_at: Some(expired),
            quota: None,
        };
        second.status = UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: at(expired.as_secs() + 3600),
        };
    })
}

/// With an agreement that provides for it, a user suspended at expiry
/// whose service expired more than three months before is revoked at the
/// run, pending on the adopted nodes holding its credentials, whose first
/// apply is the operator's; the report says so, the log counts.
#[test]
fn the_job_revokes_a_user_three_months_after_its_expiry() {
    let mut harness = job(unrenewed(100));
    harness.expiry_revocation = ExpiryRevocation::since(Some(AgreementVersion::CURRENT));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let adopted = "adopted; its first `node apply` commits it";
    assert_eq!(
        outcome.stdout,
        format!(
            "revoked {SECOND}: suspended at expiry since 2026-07-05 20:20:00 UTC, its service expired at 2026-07-05 19:20:00 UTC and was not renewed in three months\n\
             revocation pending: {SECOND} waits on ams1 ({adopted}), lon1 ({adopted})\n\
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 of 0 node(s) behind applied, 1 revoked at expiry, 0 revocation(s) committed, 1 still pending; 0 failure(s)\n"
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.users()[&id(SECOND)].status, UserStatus::RevokePending);
    assert_eq!(after.config_generation().get(), 2);
    let log = log(&harness);
    assert!(
        log.contains("; 1 revoked three months after expiry\n"),
        "{log}"
    );
    assert!(!log.contains("fxuser"), "{log}");
}

/// The JSON outcome names the revocation with its expiry and suspension.
#[test]
fn the_json_outcome_names_a_revocation_at_expiry() {
    let mut harness = job(unrenewed(100));
    harness.expiry_revocation = ExpiryRevocation::since(Some(AgreementVersion::CURRENT));
    let outcome = harness.run(&["apply", "--now", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    let expired = NOW - 100 * 86_400;
    assert_eq!(
        value["policy"]["carried_out"]["revoked"],
        serde_json::json!([{
            "user": SECOND,
            "expired_at": expired,
            "due": NOW - 8 * 86_400,
            "since": expired + 3600
        }])
    );
    assert_eq!(
        value["revocations"]["done"]["pending"],
        serde_json::json!([{"user": SECOND, "nodes": [
            {"node": "ams1", "waits_for": "first_apply"},
            {"node": "lon1", "waits_for": "first_apply"}
        ]}])
    );
}

/// While the payment pull is set up, a revocation at expiry waits for a
/// pull that succeeded since it fell due, so that a renewal paid in time
/// and not pulled yet never ends in a revocation, which cannot be undone:
/// the user is reported, left suspended, and no failure. Once a pull has
/// succeeded at or after that instant, the next run revokes the user.
#[test]
fn a_revocation_at_expiry_waits_for_a_payment_pull_since_it_fell_due() {
    use super::payments::{connect, page};
    use crate::payments::pull::{Gate, Puller};

    let mut harness = job(unrenewed(100));
    harness.expiry_revocation = ExpiryRevocation::since(Some(AgreementVersion::CURRENT));
    connect(&mut harness, 1, false, 1);
    // Three calendar months after the expiry, 2026-07-05 19:20:00 UTC.
    let due = NOW - 8 * 86_400;
    let pull = |harness: &mut Harness, when: u64| {
        harness.portal.ok(&page(true, 0, Vec::new(), false));
        let mut puller = Puller::open(&harness.support_dir());
        let users = store(harness).load().unwrap().deployment.users().clone();
        let mut clear = || true;
        harness.with_env(|env| {
            puller.tick(
                env,
                &users,
                at(when),
                Gate {
                    room: Some(std::time::Duration::from_secs(10)),
                    network_clear: &mut clear,
                },
            );
        });
        let ledger = super::payments::ledger_on_disk(harness).unwrap();
        assert_eq!(ledger.pulled_at(), Some(at(when)));
    };
    let waiting = format!(
        "not revoked yet: {SECOND}, suspended at expiry since 2026-07-05 20:20:00 UTC, whose service expired at 2026-07-05 19:20:00 UTC and was not renewed in three months; that fell due at 2026-10-05 19:20:00 UTC, and the payment pull has not succeeded since, so a renewal paid by then may not be known yet: a later run revokes it once one has\n"
    );
    // No pull yet, then one a second before the revocation fell due.
    for pulled in [None, Some(due - 1)] {
        if let Some(when) = pulled {
            pull(&mut harness, when);
        }
        let outcome = harness.run(&["apply", "--now"]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert!(outcome.stdout.starts_with(&waiting), "{}", outcome.stdout);
        assert!(
            matches!(
                status(&harness, SECOND),
                UserStatus::Suspended {
                    reason: SuspendReason::Expired,
                    ..
                }
            ),
            "{pulled:?}"
        );
    }
    let json = harness.run(&["apply", "--now", "--json"]);
    let value: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(
        value["policy"]["carried_out"]["revocation_awaiting_pull"],
        serde_json::json!([{
            "user": SECOND,
            "expired_at": NOW - 100 * 86_400,
            "due": due,
            "since": NOW - 100 * 86_400 + 3600
        }])
    );
    assert!(
        log(&harness).contains("; 1 due for revocation waiting for a payment pull\n"),
        "{}",
        log(&harness)
    );
    // A pull that succeeded at the instant it fell due.
    pull(&mut harness, due);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with(&format!("revoked {SECOND}: ")),
        "{}",
        outcome.stdout
    );
    assert_eq!(status(&harness, SECOND), UserStatus::RevokePending);
}

/// A pull disconnected (`portal disconnect`) brings no payment any more, so
/// the records decide again: the user is revoked without waiting.
#[test]
fn a_disconnected_pull_lets_the_records_decide() {
    use super::payments::connect;

    let mut harness = job(unrenewed(100));
    harness.expiry_revocation = ExpiryRevocation::since(Some(AgreementVersion::CURRENT));
    connect(&mut harness, 1, false, 1);
    let disconnected = harness.run(&["portal", "disconnect"]);
    assert_eq!(disconnected.code, 0, "{}", disconnected.stderr);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with(&format!("revoked {SECOND}: ")),
        "{}",
        outcome.stdout
    );
    assert_eq!(status(&harness, SECOND), UserStatus::RevokePending);
}

/// While no revision the user accepted provides for it (a closed gate, as
/// this build's stays until it ships one that does), the user is left
/// suspended and reported, for the operator to decide; it is no failure.
/// Under three months, nothing is said.
#[test]
fn a_user_the_agreement_does_not_cover_is_reported_not_revoked() {
    let mut harness = job(unrenewed(100));
    harness.expiry_revocation = ExpiryRevocation::since(None);
    let before = store(&harness).load().unwrap().deployment;
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with(&format!(
            "not revoked: {SECOND}, suspended at expiry since 2026-07-05 20:20:00 UTC, whose service expired at 2026-07-05 19:20:00 UTC and was not renewed in three months; the agreement it accepted does not provide for revoking it, so that is yours to decide (`mooringctl user revoke {SECOND}`)\n"
        )),
        "{}",
        outcome.stdout
    );
    assert_eq!(store(&harness).load().unwrap().deployment, before);
    assert!(
        log(&harness).contains(
            "; 1 due for revocation that the agreement they accepted does not provide for\n"
        ),
        "{}",
        log(&harness)
    );
    // Two months on, no word of it.
    let mut harness = job(unrenewed(60));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(!outcome.stdout.contains("revoke"), "{}", outcome.stdout);
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
            ": 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 of 0 node(s) behind applied, 0 revoked at expiry, 0 revocation(s) committed, 1 still pending; 1 failure(s)\n"
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

/// A suspension for quota dated after the run's time (a clock that stepped
/// back) refuses the policy step whole: no one is revoked at expiry.
#[test]
fn a_clock_that_stepped_back_revokes_no_one_at_expiry() {
    let mut deployment = unrenewed(100).into_parts();
    user(&mut deployment, THIRD).status = UserStatus::Suspended {
        reason: SuspendReason::QuotaExceeded {
            cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
        },
        since: at(NOW + 86_400),
    };
    let mut harness = job(Deployment::try_from(deployment).unwrap());
    harness.expiry_revocation = ExpiryRevocation::since(Some(AgreementVersion::CURRENT));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stdout
            .starts_with("policy step not carried out: a suspension for quota is dated after now"),
        "{}",
        outcome.stdout
    );
    assert!(matches!(
        status(&harness, SECOND),
        UserStatus::Suspended {
            reason: SuspendReason::Expired,
            ..
        }
    ));
}

/// A revocation planned before the operator changed the user is not made:
/// a user resumed meanwhile, or suspended anew, is left as the operator
/// left it, and the failure is reported.
#[test]
fn a_user_changed_since_the_plan_is_not_revoked() {
    use mooring_daemon_core::apply::{PaymentsKnown, plan_policy, unrenewed as plan_unrenewed};
    use mooring_daemon_core::payments::Entitlements;

    use crate::apply::policy::carry_out;
    use crate::apply::report::Change;

    let harness = job(unrenewed(100));
    let read = store(&harness).load().unwrap().deployment;
    let plan = plan_policy(&read, &Entitlements::none(), None, at(NOW)).unwrap();
    let revocations = plan_unrenewed(
        &read,
        &Entitlements::none(),
        PaymentsKnown::NoPull,
        at(NOW),
        ExpiryRevocation::since(Some(AgreementVersion::CURRENT)),
    )
    .unwrap();
    assert_eq!(revocations.revoke.len(), 1);
    let operator = UserStatus::Suspended {
        reason: SuspendReason::Operator,
        since: at(NOW - 10),
    };
    let store = store(&harness);
    let changed = store
        .update_config::<(), _>(read.config_generation(), |mut parts| {
            user(&mut parts, SECOND).status = UserStatus::Active;
            Ok(parts)
        })
        .unwrap();
    store
        .update_config::<(), _>(changed.deployment.config_generation(), |mut parts| {
            user(&mut parts, SECOND).status = operator;
            Ok(parts)
        })
        .unwrap();
    let done = carry_out(&store, &plan, &revocations, None);
    assert!(done.revoked.is_empty());
    assert_eq!(done.failed.len(), 1);
    assert_eq!(done.failed[0].change, Change::Revoke);
    assert_eq!(
        done.failed[0].error,
        "the change was refused: the user's status changed since the run planned this"
    );
    assert_eq!(status(&harness, SECOND), operator);
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
