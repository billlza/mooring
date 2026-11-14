// SPDX-License-Identifier: GPL-3.0-or-later

//! The nightly apply job, `apply --pending | --now` (design §13.6, §15.7),
//! against the fixture deployment and scripted node sessions: the window,
//! the policy step's suspensions and resumes, the cap that holds a resume
//! back, a clock that stepped back, the 13-month removal's boundary, a
//! node that cannot be reached, and the log that names no user.

use std::fs::{self, OpenOptions, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use mooring_agent_proto::{Generation, LineRequest, RequestKind, Response};
use mooring_model::node::{AppliedConfig, NodeLifecycle};
use mooring_model::removal::ForgottenUser;
use mooring_model::secret::{SecretEntry, SecretRef, SecretSnapshot};
use mooring_model::user::SuspendReason;
use mooring_model::{
    CalendarDate, ConfigGeneration, Deployment, DeploymentParts, NodeId, SPARE_USERS, UnixTime,
    User, UserId, UserStatus,
};
use mooring_store::SecretStore;
use serde_json::Value;

use super::apply::{
    bundle_and_header, bundle_and_header_of, confirmed_as_rendered, script_hello_and_blobs,
    script_hello_and_blobs_at, script_transaction, stand_in_engines,
};
use super::deployed::deployed_with;
use super::support::{Answered, Expected, ExpectedRemote, Harness, NOW, Outcome, Refusals, Sent};
use super::user::{fixture, state_bytes, store};
use crate::apply::APPLY_LOCK_FILE;
use crate::apply::report::{Drift, DriftFailure, Regenerated, Spares, SparesFailure};
use crate::daemon::RunPaths;
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;

const FIRST: &str = "fxuseraaab";
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

/// The fixture after `edit`, with each node adopted but never applied, so
/// that no node is behind and the run asks none.
fn unapplied(edit: impl FnOnce(&mut DeploymentParts)) -> Deployment {
    fixture(|parts| {
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &node.lifecycle {
                node.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
        edit(parts);
    })
}

/// `user` in `parts`.
fn user<'p>(parts: &'p mut DeploymentParts, user: &str) -> &'p mut User {
    parts
        .users
        .iter_mut()
        .find(|candidate| candidate.id.as_str() == user)
        .unwrap()
}

/// `text` revoked at `since`, holding no node's credentials any more.
fn revoke(parts: &mut DeploymentParts, text: &str, since: UnixTime) {
    let found = user(parts, text);
    found.per_node.clear();
    found.status = UserStatus::Revoked { since };
}

/// A harness for the job: the deployed daemon's (the M7 pinned, the
/// egress resolving to lo0, the fixture's secrets) with stand-in engines
/// in the support directory, where the job takes them from, and the spare
/// users ready ([`with_ready_spares`]), so that the step that tops them up
/// has nothing to do.
fn job(deployment: Deployment) -> Harness {
    job_as_is(with_ready_spares(deployment))
}

/// [`job`] with `deployment` as it is, spare users and all.
fn job_as_is(deployment: Deployment) -> Harness {
    let mut harness = deployed_with(deployment);
    for secret_ref in spare_secrets().refs() {
        let material = spare_secrets().material(&secret_ref).unwrap();
        harness
            .secrets
            .put(SecretEntry::new(secret_ref, material).unwrap())
            .unwrap();
    }
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    stand_in_engines(&mut harness, &engines);
    harness
}

/// The fixture's secrets with those of its spare users
/// (`Fixture::with_spares`).
pub(crate) fn spare_secrets() -> SecretSnapshot {
    mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .with_spares(u8::try_from(SPARE_USERS).unwrap())
        .unwrap()
        .secrets
}

/// `deployment` with the fixture's [`SPARE_USERS`] spare users, each
/// holding credentials on the active nodes of `deployment`.
fn with_ready_spares(deployment: Deployment) -> Deployment {
    let spares = mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .with_spares(u8::try_from(SPARE_USERS).unwrap())
        .unwrap()
        .deployment
        .spares()
        .clone();
    let mut parts = deployment.into_parts();
    let active: Vec<NodeId> = parts
        .nodes
        .iter()
        .filter(|node| node.lifecycle.is_active())
        .map(|node| node.id.clone())
        .collect();
    parts.spares = spares
        .into_values()
        .map(|mut spare| {
            spare.per_node.retain(|node, _| active.contains(node));
            spare
        })
        .collect();
    Deployment::try_from(parts).unwrap()
}

fn deployment(harness: &Harness) -> Deployment {
    store(harness).load().unwrap().deployment
}

fn status(harness: &Harness, text: &str) -> UserStatus {
    deployment(harness).users()[&id(text)].status
}

fn log_path(harness: &Harness) -> PathBuf {
    harness
        .home
        .path()
        .join("Library/Logs/Mooring")
        .join("apply.log")
}

fn log(harness: &Harness) -> String {
    fs::read_to_string(log_path(harness)).unwrap()
}

/// The node's `Hello` fails as ssh does when the node cannot be reached.
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

/// A firing outside 19:15 to 19:45 UTC, as launchd delivers one late after
/// a sleep, does nothing: no state change, no node asked, no log; the
/// window's edges are 19:15:00 in and 19:45:00 out.
#[test]
fn a_firing_outside_the_window_does_nothing() {
    let mut harness = job(fixture(|parts| {
        user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
        parts.config_generation = ConfigGeneration::new(2).unwrap();
    }));
    let before = state_bytes(&harness);
    for (now, clock) in [
        (NOW + 3600, "20:20:00"),
        (NOW - 301, "19:14:59"),
        (NOW + 1500, "19:45:00"),
    ] {
        harness.now.set(now);
        let outcome = harness.run(&["apply", "--pending"]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(
            outcome.stdout,
            format!(
                "apply: 2026-10-13 {clock} UTC is outside the apply window (19:15 to 19:45 UTC); nothing done\n"
            )
        );
        let outcome = harness.run(&["apply", "--pending", "--json"]);
        assert_eq!(
            outcome.stdout,
            format!("{{\"version\":3,\"at\":{now},\"ran\":false}}\n")
        );
    }
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.nodes.seen.borrow().is_empty());
    assert!(!log_path(&harness).exists());
    assert!(
        !RunPaths::under(&harness.support_dir())
            .dir
            .join(APPLY_LOCK_FILE)
            .exists()
    );
    assert_eq!(harness.redirected.get(), 0);
    // At 19:15:00 the firing runs: the expired user is suspended then, and
    // standard error points at the job's log, as launchd keeps none.
    harness.now.set(NOW - 300);
    for _ in 0..2 {
        unreachable(&harness);
    }
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(harness.redirected.get(), 1);
    assert!(
        outcome
            .stdout
            .contains(&format!("suspended {FIRST}: expired")),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        status(&harness, FIRST),
        UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: at(NOW - 300)
        }
    );
}

/// Both nodes behind and neither reachable: the expired user is suspended
/// all the same, at the run's time; each node's failure is reported and
/// the run fails; the log counts and names no user.
#[test]
fn suspensions_go_while_no_node_can_be_reached() {
    let mut harness = job(fixture(|parts| {
        user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
        parts.config_generation = ConfigGeneration::new(2).unwrap();
    }));
    for _ in 0..2 {
        unreachable(&harness);
    }
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    // `--now` runs at the operator's terminal: standard error stays there.
    assert_eq!(harness.redirected.get(), 0);
    assert_eq!(
        status(&harness, FIRST),
        UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: at(NOW)
        }
    );
    assert_eq!(deployment(&harness).config_generation().get(), 3);
    assert_eq!(
        outcome.stdout,
        format!(
            "suspended {FIRST}: expired\n\
             spare users: 3 ready\n\
             no node that confirmed the configuration generation is on another build's bundle\n\
             ams1: apply failed: the node could not be reached or refused: ssh ended without a reply (exit status 255): / ssh: connect to the node: Operation timed out\n\
             lon1: apply failed: the node could not be reached or refused: ssh ended without a reply (exit status 255): / ssh: connect to the node: Operation timed out\n\
             apply at 2026-10-13 19:20:00 UTC: 1 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 spare user(s) drawn, 0 of 2 node(s) behind applied; 2 failure(s)\n"
        )
    );
    assert_eq!(
        outcome.stderr,
        "mooringctl: the apply job finished with 2 failure(s); the report above and apply.log say which\n"
    );
    assert!(harness.nodes.script.borrow().is_empty());
    let log = log(&harness);
    assert!(
        log.contains("mooringctl apply: policy: 1 suspended, 0 resumed, 0 held back by the cap, 0 kept suspended, 0 failed"),
        "{log}"
    );
    assert!(
        log.contains("mooringctl apply: lon1: apply failed"),
        "{log}"
    );
    assert!(
        log.contains("mooringctl apply: done: 2 failure(s)"),
        "{log}"
    );
    assert!(!log.contains("fxuser"), "{log}");
}

/// A lapsed suspension for quota that the cap leaves no room for is held
/// back and reported, not resumed, and is no failure; with room it is
/// resumed, the earliest suspension first.
#[test]
fn the_cap_holds_a_resume_back() {
    let lapsed = |parts: &mut DeploymentParts, text: &str, since: u64| {
        user(parts, text).status = UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded {
                cycle_start: CalendarDate::parse("2026-09-01").unwrap(),
            },
            since: at(since),
        };
    };
    let earlier = NOW - 40 * 86_400;
    let later = NOW - 35 * 86_400;
    let deployment_capped = |cap: u16| {
        unapplied(move |parts| {
            lapsed(parts, SECOND, later);
            lapsed(parts, THIRD, earlier);
            parts.capacity.max_active_users = std::num::NonZeroU16::new(cap);
        })
    };
    let mut harness = job(deployment_capped(1));
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "held back by the cap on active users: {THIRD}, suspended for quota in the billing cycle from 2026-09-01 since 2026-09-03 19:20:00 UTC: its billing cycle has ended; still suspended\n\
             held back by the cap on active users: {SECOND}, suspended for quota in the billing cycle from 2026-09-01 since 2026-09-08 19:20:00 UTC: its billing cycle has ended; still suspended\n\
             spare users: 3 ready\n\
             no node that confirmed the configuration generation is on another build's bundle\n\
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 2 held back, 0 kept suspended, 0 removed, 0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
        )
    );
    assert_eq!(state_bytes(&harness), before);
    // Room for one: the earliest suspension is resumed.
    let mut harness = job(deployment_capped(2));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(status(&harness, THIRD), UserStatus::Active);
    assert!(matches!(
        status(&harness, SECOND),
        UserStatus::Suspended { .. }
    ));
    assert!(
        outcome.stdout.starts_with(&format!(
            "resumed {THIRD}, suspended for quota in the billing cycle from 2026-09-01 since 2026-09-03 19:20:00 UTC: its billing cycle has ended\n\
             held back by the cap on active users: {SECOND}"
        )),
        "{}",
        outcome.stdout
    );
}

/// A suspension for quota dated after the run's time (a clock that stepped
/// back) refuses the policy step whole and skips the removals; the
/// expired user stays active, the user due for removal stays, and the node
/// behind is still applied.
#[test]
fn a_clock_that_stepped_back_carries_out_nothing_but_node_applies() {
    let mut harness = job(fixture(|parts| {
        user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
        user(parts, SECOND).status = UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded {
                cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
            },
            since: at(NOW + 86_400),
        };
        revoke(parts, THIRD, at(NOW - 500 * 86_400));
        parts.config_generation = ConfigGeneration::new(2).unwrap();
    }));
    for _ in 0..2 {
        unreachable(&harness);
    }
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert!(deployment(&harness).users().contains_key(&id(THIRD)));
    assert_eq!(deployment(&harness).config_generation().get(), 2);
    let mut lines = outcome.stdout.lines();
    assert_eq!(
        lines.next().unwrap(),
        format!(
            "policy step not carried out: a suspension for quota is dated after now: the clock stepped back, or a record is wrong: user {SECOND} was suspended for quota at @1792005600, after now (@1791919200)"
        )
    );
    assert_eq!(
        lines.next().unwrap(),
        "removals skipped: the clock stepped back"
    );
    assert_eq!(lines.next().unwrap(), "spare users: 3 ready");
    assert_eq!(
        lines.next().unwrap(),
        "no node that confirmed the configuration generation is on another build's bundle"
    );
    assert!(lines.next().unwrap().starts_with("ams1: apply failed: "));
    assert!(lines.next().unwrap().starts_with("lon1: apply failed: "));
    assert_eq!(harness.nodes.seen.borrow().len(), 2);
    let log = log(&harness);
    assert!(
        log.contains("mooringctl apply: policy step not carried out: a suspension for quota is dated after now"),
        "{log}"
    );
    assert!(!log.contains("fxuser"), "{log}");
}

/// A user revoked 13 calendar months ago to the second is removed, its id
/// not kept (its nodes' records expired long ago); one revoked a second
/// later stays. Neither is named in the log.
#[test]
fn a_user_is_removed_13_months_after_the_revocation_to_the_second() {
    // 2025-09-13 19:20:00 UTC: 13 months before the clock.
    let thirteen_months_ago = 1_757_791_200;
    let mut harness = job(unapplied(|parts| {
        revoke(parts, SECOND, at(thirteen_months_ago));
        revoke(parts, THIRD, at(thirteen_months_ago + 1));
    }));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let after = deployment(&harness);
    assert!(!after.users().contains_key(&id(SECOND)));
    assert!(after.users().contains_key(&id(THIRD)));
    assert!(after.forgotten().is_empty());
    assert_eq!(after.config_generation().get(), 1);
    assert_eq!(
        outcome.stdout,
        format!(
            "removed {SECOND}: revoked 13 months ago\n\
             spare users: 3 ready\n\
             no node that confirmed the configuration generation is on another build's bundle\n\
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 1 removed, 0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
        )
    );
    let log = log(&harness);
    assert!(
        log.contains("mooringctl apply: removals: 1 removed, 0 failed\n"),
        "{log}"
    );
    assert!(!log.contains("fxuser"), "{log}");
}

/// The id of a removed user is dropped once its nodes' records have
/// expired, and kept until then.
#[test]
fn a_kept_id_goes_once_its_records_expire() {
    let kept = |until: u64| {
        unapplied(move |parts| {
            parts
                .users
                .retain(|candidate| candidate.id.as_str() != THIRD);
            parts.forgotten = vec![ForgottenUser {
                user: id(THIRD),
                until: at(until),
            }];
        })
    };
    let mut harness = job(kept(NOW + 1));
    harness.run(&["apply", "--now"]);
    assert_eq!(deployment(&harness).forgotten().len(), 1);
    let mut harness = job(kept(NOW));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(deployment(&harness).forgotten().is_empty());
    assert!(
        outcome
            .stdout
            .starts_with("dropped the ids of removed users whose records have expired\n"),
        "{}",
        outcome.stdout
    );
}

/// A user suspended at expiry whose paid time covers the run again is
/// resumed; one suspended by the operator, or for an abuse review, is
/// not, paid or not.
#[test]
fn only_a_lapsed_suspension_at_expiry_is_resumed_once_paid() {
    use super::payments::{connect, grant, page};
    use crate::payments::pull::{Gate, Puller};

    let suspended = |parts: &mut DeploymentParts, text: &str, reason| {
        let found = user(parts, text);
        found.policy.expires_at = Some(at(NOW - 2 * 86_400));
        found.status = UserStatus::Suspended {
            reason,
            since: at(NOW - 86_400),
        };
    };
    let mut harness = job(unapplied(|parts| {
        suspended(parts, FIRST, SuspendReason::Expired);
        suspended(parts, SECOND, SuspendReason::Operator);
        suspended(parts, THIRD, SuspendReason::AbuseReview);
    }));
    connect(&mut harness, 1, false, 1);
    harness.portal.ok(&page(
        true,
        0,
        vec![
            grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST),
            grant(2, "bbbbbbbbbbbbbbbbbbbb", SECOND),
            grant(3, "cccccccccccccccccccc", THIRD),
        ],
        false,
    ));
    let mut puller = Puller::open(&harness.support_dir());
    let users = deployment(&harness).users().clone();
    let mut clear = || true;
    harness.with_env(|env| {
        puller.tick(
            env,
            &users,
            at(NOW),
            Gate {
                room: Some(std::time::Duration::from_secs(10)),
                network_clear: &mut clear,
            },
        )
    });
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert!(matches!(
        status(&harness, SECOND),
        UserStatus::Suspended {
            reason: SuspendReason::Operator,
            ..
        }
    ));
    assert!(matches!(
        status(&harness, THIRD),
        UserStatus::Suspended {
            reason: SuspendReason::AbuseReview,
            ..
        }
    ));
    assert!(
        outcome.stdout.starts_with(&format!(
            "resumed {FIRST}, suspended at expiry since 2026-10-12 19:20:00 UTC: its expiry is no longer past\n"
        )),
        "{}",
        outcome.stdout
    );
}

/// A paid month refunded in full counts until the time the portal recorded
/// the refund (design §9.6): the user's paid time ends there, and the job,
/// reading what the user may use as it always does, suspends them at
/// expiry. A user with nothing refunded stays.
#[test]
fn a_month_refunded_in_full_ends_at_the_refund() {
    use super::payments::{connect, grant, page, refund_in_full};
    use crate::payments::pull::{Gate, Puller};

    let mut harness = job(unapplied(|_| {}));
    connect(&mut harness, 1, false, 1);
    let first = grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST);
    harness.portal.ok(&page(
        true,
        0,
        vec![
            first.clone(),
            grant(2, "bbbbbbbbbbbbbbbbbbbb", SECOND),
            refund_in_full(&first, 3, NOW - 86_400),
        ],
        false,
    ));
    let mut puller = Puller::open(&harness.support_dir());
    let users = deployment(&harness).users().clone();
    let mut clear = || true;
    harness.with_env(|env| {
        puller.tick(
            env,
            &users,
            at(NOW - 2 * 86_400),
            Gate {
                room: Some(std::time::Duration::from_secs(10)),
                network_clear: &mut clear,
            },
        )
    });
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        status(&harness, FIRST),
        UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: at(NOW),
        }
    );
    assert_eq!(status(&harness, SECOND), UserStatus::Active);
}

/// The `--json` outcome: the run's time, each part, and the users by id.
#[test]
fn the_json_outcome_names_each_part() {
    let mut harness = job(unapplied(|parts| {
        user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
    }));
    let outcome = harness.run(&["apply", "--now", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "version": 3,
            "at": NOW,
            "ran": true,
            "policy": {"carried_out": {
                "suspended": [{"user": FIRST, "reason": "expired"}],
                "resumed": [],
                "held_back": [],
                "kept": [],
                "failed": [],
                "quotas_unchecked": [],
                "usage_behind": "ams1 may have counted traffic, but no usage ledger is given for it"
            }},
            "removals": {"done": {"removed": [], "kept_ids_dropped": false, "failed": []}},
            "spares": {"done": {"drawn": 0, "credentials": 0, "ready": 3}},
            "drift": "none_found",
            "nodes": []
        })
    );
    assert_eq!(outcome.stdout.lines().count(), 1);
}

/// A node behind is applied by the job, as `node apply` applies it; the
/// node up to date, at the deployment's generation and on the bundle this
/// build renders for it, is not asked.
#[test]
fn a_node_behind_is_applied() {
    let deployment = fixture(|parts| {
        parts.config_generation = ConfigGeneration::new(2).unwrap();
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { applied, .. } = &mut node.lifecycle
                && node.id.as_str() == "ams1"
            {
                applied.config_generation = ConfigGeneration::new(2).unwrap();
            }
        }
    });
    let deployment = confirmed_as_rendered(with_ready_spares(deployment), &spare_secrets());
    let mut harness = job_as_is(deployment);
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    let (_, header) = bundle_and_header(&harness, &engines, &self::deployment(&harness));
    script_hello_and_blobs(&harness, header.blobs());
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(2),
        })),
    );
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    let after = store(&harness).load().unwrap().deployment;
    let NodeLifecycle::Applied { applied, .. } = &after.nodes()[&node("lon1")].lifecycle else {
        panic!();
    };
    assert_eq!(applied.config_generation.get(), 2);
    assert!(
        outcome.stdout.ends_with(
            "lon1: applied\napply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 spare user(s) drawn, 1 of 1 node(s) behind applied; 0 failure(s)\n"
        ),
        "{}",
        outcome.stdout
    );
    assert!(outcome.stdout.starts_with("spare users: 3 ready\n"));
    assert!(log(&harness).contains("mooringctl apply: lon1: applied\n"));
}

/// While a run holds the job's lock, another does nothing and fails.
#[test]
fn two_runs_never_overlap() {
    let mut harness = job(unapplied(|parts| {
        user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
    }));
    let run_dir = RunPaths::under(&harness.support_dir()).dir;
    fs::create_dir_all(&run_dir).unwrap();
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(run_dir.join(APPLY_LOCK_FILE))
        .unwrap();
    held.try_lock().unwrap();
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: another apply job is running (it holds {}); nothing was done\n",
            run_dir.join(APPLY_LOCK_FILE).display()
        )
    );
    assert_eq!(state_bytes(&harness), before);
    drop(held);
    assert_eq!(harness.run(&["apply", "--now"]).code, 0);
}

/// `apply` needs `--pending` or `--now`, and not both.
#[test]
fn apply_takes_exactly_one_form() {
    use clap::Parser;

    for args in [
        &["mooringctl", "apply"][..],
        &["mooringctl", "apply", "--pending", "--now"],
        &["mooringctl", "apply", "--json"],
    ] {
        assert!(crate::cli::Cli::try_parse_from(args).is_err(), "{args:?}");
    }
    assert!(crate::cli::Cli::try_parse_from(["mooringctl", "apply", "--now", "--json"]).is_ok());
}

/// A plan made before the operator changed a user is not carried out over
/// that change: a user the operator suspended meanwhile is not suspended
/// again, and one whose suspension became another is not resumed. Each
/// such change fails and is reported; the state keeps the operator's.
#[test]
fn a_change_the_operator_made_since_the_plan_is_kept() {
    use mooring_daemon_core::apply::plan_policy;
    use mooring_daemon_core::payments::Entitlements;

    use crate::apply::policy::carry_out;
    use crate::apply::report::Change;

    let harness = job(unapplied(|parts| {
        user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
        user(parts, SECOND).status = UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded {
                cycle_start: CalendarDate::parse("2026-09-01").unwrap(),
            },
            since: at(NOW - 40 * 86_400),
        };
    }));
    let read = deployment(&harness);
    let plan = plan_policy(&read, &Entitlements::none(), None, at(NOW)).unwrap();
    assert_eq!(plan.suspensions.len(), 1);
    assert_eq!(plan.resumes.len(), 1);
    let store = store(&harness);
    let operator = UserStatus::Suspended {
        reason: SuspendReason::Operator,
        since: at(NOW - 10),
    };
    let review = UserStatus::Suspended {
        reason: SuspendReason::AbuseReview,
        since: at(NOW - 10),
    };
    // The operator suspends the first user, and resumes the second only to
    // suspend them again for an abuse review: a suspension changes only
    // through a resume.
    let changed = store
        .update_config::<(), _>(read.config_generation(), |mut parts| {
            user(&mut parts, FIRST).status = operator;
            user(&mut parts, SECOND).status = UserStatus::Active;
            Ok(parts)
        })
        .unwrap();
    store
        .update_config::<(), _>(changed.deployment.config_generation(), |mut parts| {
            user(&mut parts, SECOND).status = review;
            Ok(parts)
        })
        .unwrap();
    let done = carry_out(&store, &plan, None);
    assert!(done.suspended.is_empty() && done.resumed.is_empty());
    let failed: Vec<(String, Change)> = done
        .failed
        .iter()
        .map(|failed| (failed.user.to_string(), failed.change))
        .collect();
    assert_eq!(
        failed,
        [
            (FIRST.to_owned(), Change::Suspend),
            (SECOND.to_owned(), Change::Resume)
        ]
    );
    assert_eq!(
        done.failed[1].error,
        "the change was refused: the user's status changed since the run planned this"
    );
    assert_eq!(status(&harness, FIRST), operator);
    assert_eq!(status(&harness, SECOND), review);
}

/// A payment ledger that cannot be read refuses the policy step, since a
/// paid user would be read as unpaid and suspended; so does collected
/// usage that cannot be read. The rest of the run goes on, and it fails.
#[test]
fn unreadable_payments_or_usage_refuse_the_policy_step() {
    let expired = || {
        unapplied(|parts| {
            user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
        })
    };
    let mut harness = job(expired());
    let payments = harness
        .support_dir()
        .join(mooring_store::PAYMENTS_DIRECTORY);
    fs::create_dir(&payments).unwrap();
    fs::write(
        payments.join(mooring_store::PAYMENT_LEDGER_FILE),
        b"not a ledger",
    )
    .unwrap();
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert!(
        outcome.stdout.starts_with(
            "policy step not carried out: the payment ledger or the pull's settings cannot be read, and a paid user would be read as unpaid: "
        ),
        "{}",
        outcome.stdout
    );
    let mut harness = job(expired());
    let usage = harness.support_dir().join(mooring_store::USAGE_DIRECTORY);
    fs::create_dir(&usage).unwrap();
    fs::write(usage.join(mooring_store::USER_USAGE_FILE), b"not usage").unwrap();
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert!(
        outcome.stdout.starts_with(
            "policy step not carried out: the usage the daemon collected cannot be read or is inconsistent: "
        ),
        "{}",
        outcome.stdout
    );
}

/// While the collected usage is behind (here, none collected yet), a
/// user's quota is not checked, which is reported and is no failure.
#[test]
fn quotas_go_unchecked_while_usage_is_behind() {
    use mooring_model::{QuotaAction, UserQuota, WarnPercent};

    let mut harness = job(unapplied(|parts| {
        user(parts, FIRST).policy.quota = Some(UserQuota {
            cycle_served_bytes: std::num::NonZeroU64::new(1).unwrap(),
            warn_percent: WarnPercent::new(80).unwrap(),
            action: QuotaAction::Suspend,
        });
    }));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert!(
        outcome.stdout.starts_with(&format!(
            "quotas not checked for 1 user(s) ({FIRST}): ams1 may have counted traffic, but no usage ledger is given for it\n"
        )),
        "{}",
        outcome.stdout
    );
    let log = log(&harness);
    assert!(
        log.contains("; quotas not checked for 1 user(s)\n"),
        "{log}"
    );
    assert!(!log.contains("fxuser"), "{log}");
}

/// While the collected usage is behind (here none is collected), a pack
/// bought by a user suspended for quota this cycle lifts nothing: the job
/// cannot tell that it covers what the user used, so the suspension stands
/// until the usage is current again or the cycle ends.
#[test]
fn a_pack_lifts_nothing_while_the_usage_is_behind() {
    use mooring_model::{QuotaAction, UserQuota, WarnPercent};

    use super::payments::{connect, page};
    use crate::payments::pull::{Gate, Puller};

    let suspended = UserStatus::Suspended {
        reason: SuspendReason::QuotaExceeded {
            cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
        },
        since: at(NOW - 3600),
    };
    let mut harness = job(unapplied(|parts| {
        let found = user(parts, FIRST);
        found.policy.quota = Some(UserQuota {
            cycle_served_bytes: std::num::NonZeroU64::new(1).unwrap(),
            warn_percent: WarnPercent::new(80).unwrap(),
            action: QuotaAction::Suspend,
        });
        found.status = suspended;
    }));
    connect(&mut harness, 1, false, 1);
    harness.portal.ok(&page(
        true,
        0,
        vec![serde_json::json!({
            "seq": 1, "kind": "grant", "order": "aaaaaaaaaaaaaaaaaaaa", "user": FIRST,
            "plan": "traffic-50", "plan_kind": "traffic", "days": 30,
            "traffic_bytes": 50_000_000_000_u64, "amount": 500, "currency": "gbp",
            "paid_at": NOW - 120, "renewal_of": null,
            "amount_refunded": null, "refunded_in_full": null, "amount_disputed": null,
            "recorded_at": NOW - 60
        })],
        false,
    ));
    let mut puller = Puller::open(&harness.support_dir());
    let users = deployment(&harness).users().clone();
    let mut clear = || true;
    harness.with_env(|env| {
        puller.tick(
            env,
            &users,
            at(NOW),
            Gate {
                room: Some(std::time::Duration::from_secs(10)),
                network_clear: &mut clear,
            },
        )
    });
    assert_eq!(
        super::payments::ledger_on_disk(&harness)
            .unwrap()
            .orders()
            .len(),
        1
    );
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(status(&harness, FIRST), suspended);
    assert_eq!(
        outcome.stdout,
        "spare users: 3 ready\n\
         no node that confirmed the configuration generation is on another build's bundle\n\
         apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
}

/// The ids of `deployment`'s spare users.
fn spare_ids(deployment: &Deployment) -> Vec<UserId> {
    deployment.spares().keys().cloned().collect()
}

/// In the window the job draws the spare users `user add` takes, each with
/// credentials on every node planned, adopted or applied, in one
/// configuration change whose secrets the keychain holds; the report
/// counts them, and the log names none.
#[test]
fn the_job_draws_spare_users_in_the_window() {
    let mut harness = job_as_is(unapplied(|_| {}));
    let before = deployment(&harness);
    assert!(before.spares().is_empty());
    let keychain = harness.secrets.refs();
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let after = deployment(&harness);
    assert_eq!(
        after.config_generation(),
        before.config_generation().next().unwrap()
    );
    let spares = spare_ids(&after);
    assert_eq!(spares.len(), SPARE_USERS);
    for spare in after.spares().values() {
        let held: Vec<&str> = spare.per_node.keys().map(NodeId::as_str).collect();
        assert_eq!(held, ["ams1", "lon1"]);
        assert!(!before.users().contains_key(&spare.id));
    }
    assert_eq!(
        harness.secrets.refs(),
        keychain.union(&after.required_secrets()).cloned().collect()
    );
    assert_eq!(
        outcome.stdout,
        "spare users: 3 drawn, 0 credential set(s) given on nodes that lacked them; 3 ready\n\
         no node that confirmed the configuration generation is on another build's bundle\n\
         apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 3 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
    let log = log(&harness);
    assert!(
        log.contains("mooringctl apply: spare users: 3 drawn, 0 credential set(s) given"),
        "{log}"
    );
    for spare in &spares {
        assert!(!log.contains(spare.as_str()), "{log}");
    }
    // The next run has nothing to do, and changes nothing.
    let ready = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(outcome.stdout.starts_with("spare users: 3 ready\n"));
    assert_eq!(state_bytes(&harness), ready);
}

/// A spare without credentials on a node planned or adopted since it was
/// drawn gets them there; one short of the count is drawn.
#[test]
fn the_job_gives_spare_users_credentials_on_new_nodes() {
    let mut parts = with_ready_spares(unapplied(|_| {})).into_parts();
    parts.spares.pop();
    for spare in &mut parts.spares {
        spare.per_node.remove(&node("ams1"));
    }
    // The keychain still holds what the spares left behind; the new
    // credentials replace those items.
    let mut harness = job_as_is(Deployment::try_from(parts).unwrap());
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with(
            "spare users: 1 drawn, 2 credential set(s) given on nodes that lacked them; 3 ready\n"
        ),
        "{}",
        outcome.stdout
    );
    let after = deployment(&harness);
    assert_eq!(after.spares().len(), SPARE_USERS);
    for spare in after.spares().values() {
        let held: Vec<&str> = spare.per_node.keys().map(NodeId::as_str).collect();
        assert_eq!(held, ["ams1", "lon1"]);
    }
    let keychain = harness.secrets.refs();
    assert!(after.required_secrets().is_subset(&keychain));
}

/// The operator's `apply --now` outside the window leaves the spare users
/// as they are, so that no node restarts for them by day; that is no
/// failure.
#[test]
fn a_run_outside_the_window_leaves_the_spare_users() {
    let mut harness = job_as_is(unapplied(|_| {}));
    harness.now.set(NOW + 3600);
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "spare users left as they are: outside the apply window, where the restart they need is expected\n\
         nodes on another build's bundle left as they are: outside the apply window, where the restart they need is expected\n\
         apply at 2026-10-13 20:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
    assert_eq!(state_bytes(&harness), before);
    let outcome = harness.run(&["apply", "--now", "--json"]);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(value["spares"], "outside_window");
}

/// A top-up the keychain refuses changes nothing and is one failure of the
/// run. The report says why, naming the spare it drew; the log says which
/// part failed and names no spare, since a spare's id is a user's to come.
#[test]
fn a_top_up_the_keychain_refuses_is_a_failure_of_the_run() {
    let mut harness = job_as_is(unapplied(|_| {}));
    let before = state_bytes(&harness);
    let keychain = harness.secrets.refs();
    *harness.keychain.lock().unwrap() = Refusals {
        put: Some(-25308),
        ..Refusals::default()
    };
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    let (line, rest) = outcome.stdout.split_once('\n').unwrap();
    let (drift, summary) = rest.split_once('\n').unwrap();
    assert_eq!(
        drift,
        "no node that confirmed the configuration generation is on another build's bundle"
    );
    let first = refused_spare(line);
    assert_eq!(
        summary,
        "apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, \
         0 spare user(s) drawn, 0 of 0 node(s) behind applied; 1 failure(s)\n"
    );
    assert_eq!(state_bytes(&harness), before);
    assert_eq!(harness.secrets.refs(), keychain);
    let outcome = harness.run(&["apply", "--now", "--json"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(value["spares"]["failed"]["kind"], "change");
    let error = value["spares"]["failed"]["error"].as_str().unwrap();
    let second = refused_spare(&format!("spare users not topped up: {error}"));
    assert_eq!(state_bytes(&harness), before);
    let log = log(&harness);
    assert_eq!(
        log.matches(
            "mooringctl apply: spare users not topped up: \
             their credentials or the configuration change could not be written\n"
        )
        .count(),
        2,
        "{log}"
    );
    for drawn in [first, second] {
        assert!(!log.contains(drawn.as_str()), "{drawn} in {log}");
    }
}

/// A failed top-up's line in the report gives its error, which can name a
/// spare; its line in the log, and its kind in `--json`, only which part
/// failed.
#[test]
fn a_failed_top_up_is_logged_by_the_part_that_failed() {
    let error = "writing secret user/fxuserzzz1/lon1/vless-uuid failed".to_owned();
    for (kind, json, words) in [
        (SparesFailure::State, "state", "the state cannot be read"),
        (
            SparesFailure::Credentials,
            "credentials",
            "their ids or credentials could not be made",
        ),
        (
            SparesFailure::Change,
            "change",
            "their credentials or the configuration change could not be written",
        ),
    ] {
        let spares = Spares::Failed {
            kind,
            error: error.clone(),
        };
        assert_eq!(spares.line(), format!("spare users not topped up: {error}"));
        assert_eq!(
            spares.log_line(),
            format!("spare users not topped up: {words}")
        );
        assert_eq!(
            serde_json::to_value(&spares).unwrap(),
            serde_json::json!({"failed": {"kind": json, "error": error}})
        );
    }
}

/// The spare that the report's `line` says the keychain refused to hold.
fn refused_spare(line: &str) -> UserId {
    let id = line
        .strip_prefix("spare users not topped up: the state was not changed: writing secret user/")
        .and_then(|rest| {
            rest.strip_suffix(
                "/ams1/vless-uuid failed; the state is unchanged: keychain put failed with OSStatus -25308",
            )
        })
        .unwrap_or_else(|| panic!("{line}"));
    UserId::parse(id).unwrap()
}

/// The fixture with its spare users ready, at its first generation, which
/// each applied node confirmed: those named in `rendered` with the bundle
/// this build renders for them, every other with the fixture's, which
/// another build rendered.
fn at_generation(rendered: &[&str]) -> Deployment {
    let deployment = with_ready_spares(fixture(|_| {}));
    let confirmed = confirmed_as_rendered(deployment.clone(), &spare_secrets());
    let mut parts = deployment.into_parts();
    for entry in &mut parts.nodes {
        if rendered.contains(&entry.id.as_str()) {
            entry.lifecycle = confirmed.nodes()[&entry.id].lifecycle.clone();
        }
    }
    Deployment::try_from(parts).unwrap()
}

/// What `text` confirmed in `deployment`.
fn confirmed(deployment: &Deployment, text: &str) -> AppliedConfig {
    *deployment.nodes()[&node(text)].lifecycle.applied().unwrap()
}

/// A node that confirmed the deployment's generation, but a bundle another
/// build rendered, is given this build's in the window: the deployment
/// takes a new generation with nothing else changed, and every applied
/// node is applied, as `node apply` applies it. The node that confirmed
/// this build's bundle is sent that same bundle, which its agent answers
/// `Unchanged`, restarting nothing; the other runs a transaction. What
/// each node then confirmed is the bundle the step renders, so the next
/// night's run finds no node to apply and makes no generation.
#[test]
fn a_node_on_another_builds_bundle_is_applied_in_the_window() {
    let before = at_generation(&["ams1"]);
    let mut harness = job_as_is(before.clone());
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    let mut next = before.clone().into_parts();
    next.config_generation = ConfigGeneration::new(2).unwrap();
    let next = Deployment::try_from(next).unwrap();
    let ams1 = node("ams1");
    let (ams1_bundle, ams1_header) = bundle_and_header_of(&harness, &engines, &next, &ams1);
    // The digest leaves the generation out: at the new generation, ams1's
    // bundle is the one it confirmed.
    assert_eq!(ams1_bundle.digest(), confirmed(&before, "ams1").digest);
    script_hello_and_blobs_at(
        &harness,
        next.node_addresses()[&ams1].ipv4(),
        ams1_header.blobs(),
    );
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(1),
        })),
    );
    let (lon1_bundle, lon1_header) = bundle_and_header(&harness, &engines, &next);
    assert_ne!(lon1_bundle.digest(), confirmed(&before, "lon1").digest);
    script_hello_and_blobs(&harness, lon1_header.blobs());
    script_transaction(&harness, Generation::new(2));
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    let seen = harness.nodes.seen.borrow();
    let applies: Vec<&Sent> = seen
        .iter()
        .map(|(_, sent)| sent)
        .filter(|sent| matches!(sent, Sent::Request(LineRequest::Apply(_))))
        .collect();
    assert_eq!(
        applies,
        [
            &Sent::Request(LineRequest::Apply(Box::new(ams1_header))),
            &Sent::Request(LineRequest::Apply(Box::new(lon1_header))),
        ]
    );
    drop(seen);
    let mut expected = next.into_parts();
    for entry in &mut expected.nodes {
        if let NodeLifecycle::Applied { applied, .. } = &mut entry.lifecycle {
            applied.config_generation = ConfigGeneration::new(2).unwrap();
            if entry.id.as_str() == "lon1" {
                applied.digest = lon1_bundle.digest();
            }
        }
    }
    assert_eq!(
        deployment(&harness),
        Deployment::try_from(expected).unwrap()
    );
    let drift = "on another build's bundle: lon1; generation 2 made, so that the node applies below carry this build's";
    assert!(
        outcome
            .stdout
            .starts_with(&format!("spare users: 3 ready\n{drift}\n")),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.ends_with(
            "ams1: applied\nlon1: applied\napply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, \
             0 kept suspended, 0 removed, 0 spare user(s) drawn, 2 of 2 node(s) behind applied; 0 failure(s)\n"
        ),
        "{}",
        outcome.stdout
    );
    assert!(log(&harness).contains(&format!("mooringctl apply: {drift}\n")));

    let after = state_bytes(&harness);
    let asked = harness.nodes.seen.borrow().len();
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "spare users: 3 ready\n\
         no node that confirmed the configuration generation is on another build's bundle\n\
         apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, \
         0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
    assert_eq!(
        state_bytes(&harness),
        after,
        "the next night changes nothing"
    );
    assert_eq!(harness.nodes.seen.borrow().len(), asked, "and asks no node");
}

/// A run outside the window, the operator's `apply --now` by day, leaves a
/// node on another build's bundle: no new generation, no node asked.
#[test]
fn a_run_outside_the_window_leaves_a_node_on_another_builds_bundle() {
    let mut harness = job_as_is(at_generation(&["ams1"]));
    harness.now.set(NOW + 3600);
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "spare users left as they are: outside the apply window, where the restart they need is expected\n\
         nodes on another build's bundle left as they are: outside the apply window, where the restart they need is expected\n\
         apply at 2026-10-13 20:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, \
         0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
    let outcome = harness.run(&["apply", "--now", "--json"]);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(value["drift"], "outside_window");
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.nodes.seen.borrow().is_empty());
}

/// Nodes that confirmed the bundle this build renders for them are left
/// alone in the window: no new generation, no node asked.
#[test]
fn nodes_on_this_builds_bundle_are_not_applied() {
    let mut harness = job_as_is(at_generation(&["ams1", "lon1"]));
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "spare users: 3 ready\n\
         no node that confirmed the configuration generation is on another build's bundle\n\
         apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, \
         0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
    let outcome = harness.run(&["apply", "--now", "--json"]);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(value["drift"], "none_found");
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.nodes.seen.borrow().is_empty());
}

/// `apply --now`, then `apply --now --json`, on `harness`.
fn twice(harness: &mut Harness) -> [Outcome; 2] {
    [
        harness.run(&["apply", "--now"]),
        harness.run(&["apply", "--now", "--json"]),
    ]
}

/// Asserts that in `runs`, [`twice`] on `harness` from the state `before`,
/// only the drift step failed, as `kind` with the report's `error`: the
/// run fails, the state is as it was, no node was asked, and each run's
/// line in the log gives `words` and names no user.
fn assert_drift_failed(
    harness: &Harness,
    runs: &[Outcome; 2],
    before: &[u8],
    (kind, error, words): (&str, &str, &str),
) {
    let [text, json] = runs;
    assert_eq!(text.code, EXIT_LOCAL, "{}", text.stderr);
    assert_eq!(
        text.stdout,
        format!(
            "spare users: 3 ready\n\
             nodes on another build's bundle not handled: {error}\n\
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, \
             0 removed, 0 spare user(s) drawn, 0 of 0 node(s) behind applied; 1 failure(s)\n"
        )
    );
    assert_eq!(json.code, EXIT_LOCAL, "{}", json.stderr);
    let value: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(
        value["drift"],
        serde_json::json!({"failed": {"kind": kind, "error": error}})
    );
    assert_eq!(state_bytes(harness), before);
    assert!(harness.nodes.seen.borrow().is_empty());
    let log = log(harness);
    assert_eq!(
        log.matches(&format!(
            "mooringctl apply: nodes on another build's bundle not handled: {words}\n"
        ))
        .count(),
        2,
        "{log}"
    );
    assert!(!log.contains("fxuser"), "{log}");
}

/// Secrets the keychain will not give fail the drift step, which changes
/// nothing, and the run. They are read only when a node is at the
/// configuration generation: with none at it, the keychain is not asked,
/// and the step finds no node.
#[test]
fn secrets_the_keychain_refuses_fail_the_drift_step() {
    let refused = Refusals {
        get: Some(-25308),
        ..Refusals::default()
    };
    let mut harness = job_as_is(at_generation(&["ams1"]));
    let before = state_bytes(&harness);
    *harness.keychain.lock().unwrap() = refused;
    let runs = twice(&mut harness);
    assert_drift_failed(
        &harness,
        &runs,
        &before,
        (
            "secrets",
            "keychain get failed with OSStatus -25308",
            "the deployment's secrets cannot be read from the keychain",
        ),
    );

    let mut harness = job(unapplied(|_| {}));
    *harness.keychain.lock().unwrap() = refused;
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "spare users: 3 ready\n\
         no node that confirmed the configuration generation is on another build's bundle\n\
         apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, \
         0 spare user(s) drawn, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
}

/// An engine this build pins that it cannot read fails the drift step the
/// same way.
#[test]
fn engines_this_build_cannot_read_fail_the_drift_step() {
    let mut harness = job_as_is(at_generation(&["ams1"]));
    let before = state_bytes(&harness);
    harness.engine_pins = Vec::new();
    let error = format!(
        "no pinned engine file at {}",
        harness
            .support_dir()
            .join("engines/linux-amd64/xray")
            .display()
    );
    let runs = twice(&mut harness);
    assert_drift_failed(
        &harness,
        &runs,
        &before,
        (
            "engines",
            &error,
            "the engines this build pins cannot be read",
        ),
    );
}

/// A bundle that cannot be rendered fails the drift step: two users
/// holding one credential on lon1, which rendering refuses. The report
/// names the node and both users; the log only which part failed.
#[test]
fn a_bundle_that_cannot_be_rendered_fails_the_drift_step() {
    let mut harness = job_as_is(at_generation(&["ams1"]));
    let before = state_bytes(&harness);
    let lon1 = node("lon1");
    let shared = harness
        .secrets
        .get(&SecretRef::UserVlessUuid(id(FIRST), lon1.clone()))
        .unwrap();
    harness
        .secrets
        .put(SecretEntry::new(SecretRef::UserVlessUuid(id(SECOND), lon1), shared).unwrap())
        .unwrap();
    let runs = twice(&mut harness);
    assert_drift_failed(
        &harness,
        &runs,
        &before,
        (
            "render",
            "lon1: user fxuseraaab and user fxuseraaac share a credential on node lon1 (VlessUuid)",
            "a node's bundle could not be rendered",
        ),
    );
}

/// A new generation the store cannot write fails the drift step, which
/// leaves the state as it was: the support directory, which holds the
/// state, made read-only once the run directory is in it.
#[test]
fn a_generation_the_store_cannot_write_fails_the_drift_step() {
    let mut harness = job_as_is(at_generation(&["ams1"]));
    let before = state_bytes(&harness);
    let support = harness.support_dir();
    fs::create_dir_all(RunPaths::under(&support).dir).unwrap();
    fs::set_permissions(&support, Permissions::from_mode(0o500)).unwrap();
    let runs = twice(&mut harness);
    fs::set_permissions(&support, Permissions::from_mode(0o700)).unwrap();
    let error = format!(
        "the state was not changed: failed to create a temporary file at {}: \
         Permission denied (os error 13)",
        support.join("state.json.tmp").display()
    );
    assert_drift_failed(
        &harness,
        &runs,
        &before,
        (
            "change",
            &error,
            "the configuration change could not be written",
        ),
    );
}

/// Spare users drawn in the run make its one new generation: the drift
/// step, which follows, finds no node at it, and every node, behind it,
/// is applied with this build's bundle. In the other order a node on
/// another build's bundle would make a generation of its own, and the
/// spares a second.
#[test]
fn spares_drawn_in_the_run_make_its_one_new_generation() {
    let mut parts = at_generation(&["ams1"]).into_parts();
    parts.spares.pop().unwrap();
    let mut harness = job_as_is(Deployment::try_from(parts).unwrap());
    for _ in 0..2 {
        unreachable(&harness);
    }
    let outcome = harness.run(&["apply", "--now"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert_eq!(
        deployment(&harness).config_generation(),
        ConfigGeneration::new(2).unwrap()
    );
    assert!(
        outcome.stdout.starts_with(
            "spare users: 1 drawn, 0 credential set(s) given on nodes that lacked them; 3 ready\n\
             no node that confirmed the configuration generation is on another build's bundle\n"
        ),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .ends_with("1 spare user(s) drawn, 0 of 2 node(s) behind applied; 2 failure(s)\n"),
        "{}",
        outcome.stdout
    );
}

/// The drift step's lines: in the report a failure gives its error, which
/// can name a user; in the log, and in `--json` as its kind, only which
/// part failed. The nodes found are named in both, and the new generation
/// given.
#[test]
fn the_drift_step_is_logged_by_the_part_that_failed() {
    let regenerated = Drift::Regenerated(Regenerated {
        nodes: vec![node("ams1"), node("lon1")],
        generation: ConfigGeneration::new(7).unwrap(),
    });
    let line = "on another build's bundle: ams1, lon1; generation 7 made, \
                so that the node applies below carry this build's";
    assert_eq!(regenerated.line(), line);
    assert_eq!(regenerated.log_line(), line);
    assert_eq!(
        serde_json::to_value(&regenerated).unwrap(),
        serde_json::json!({"regenerated": {"nodes": ["ams1", "lon1"], "generation": 7}})
    );
    let error = "lon1: fxuseraaab and fxuseraaac share a credential".to_owned();
    for (kind, json, words) in [
        (DriftFailure::State, "state", "the state cannot be read"),
        (
            DriftFailure::Secrets,
            "secrets",
            "the deployment's secrets cannot be read from the keychain",
        ),
        (
            DriftFailure::Engines,
            "engines",
            "the engines this build pins cannot be read",
        ),
        (
            DriftFailure::Render,
            "render",
            "a node's bundle could not be rendered",
        ),
        (
            DriftFailure::Change,
            "change",
            "the configuration change could not be written",
        ),
    ] {
        let drift = Drift::Failed {
            kind,
            error: error.clone(),
        };
        assert_eq!(
            drift.line(),
            format!("nodes on another build's bundle not handled: {error}")
        );
        assert_eq!(
            drift.log_line(),
            format!("nodes on another build's bundle not handled: {words}")
        );
        assert_eq!(
            serde_json::to_value(&drift).unwrap(),
            serde_json::json!({"failed": {"kind": json, "error": error}})
        );
    }
}
