// SPDX-License-Identifier: GPL-3.0-or-later

//! The nightly apply job, `apply --pending | --now` (design §13.6, §15.7),
//! against the fixture deployment and scripted node sessions: the window,
//! the policy step's suspensions and resumes, the cap that holds a resume
//! back, a clock that stepped back, the 13-month removal's boundary, a
//! node that cannot be reached, and the log that names no user. The
//! hourly firings outside the window are `apply_hourly`'s.

use std::fs::{self, OpenOptions};
use std::path::PathBuf;

use mooring_agent_proto::{Generation, RequestKind, Response};
use mooring_model::node::NodeLifecycle;
use mooring_model::removal::ForgottenUser;
use mooring_model::user::SuspendReason;
use mooring_model::{
    CalendarDate, ConfigGeneration, Deployment, DeploymentParts, NodeId, UnixTime, User, UserId,
    UserStatus,
};
use serde_json::Value;

use super::apply::{bundle_and_header, stand_in_engines};
use super::deployed::deployed_with;
use super::support::{Answered, Expected, ExpectedRemote, Harness, NOW};
use super::user::{fixture, state_bytes, store};
use crate::apply::APPLY_LOCK_FILE;
use crate::daemon::RunPaths;
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;

pub(super) const FIRST: &str = "fxuseraaab";
pub(super) const SECOND: &str = "fxuseraaac";
pub(super) const THIRD: &str = "fxuseraaad";

fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

pub(super) fn at(secs: u64) -> UnixTime {
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
pub(super) fn user<'p>(parts: &'p mut DeploymentParts, user: &str) -> &'p mut User {
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
/// in the support directory, where the job takes them from.
pub(super) fn job(deployment: Deployment) -> Harness {
    let mut harness = deployed_with(deployment);
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    stand_in_engines(&mut harness, &engines);
    harness
}

pub(super) fn deployment(harness: &Harness) -> Deployment {
    store(harness).load().unwrap().deployment
}

pub(super) fn status(harness: &Harness, text: &str) -> UserStatus {
    deployment(harness).users()[&id(text)].status
}

fn log_path(harness: &Harness) -> PathBuf {
    harness
        .home
        .path()
        .join("Library/Logs/Mooring")
        .join("apply.log")
}

pub(super) fn log(harness: &Harness) -> String {
    fs::read_to_string(log_path(harness)).unwrap()
}

/// The node's `Hello` fails as ssh does when the node cannot be reached.
pub(super) fn unreachable(harness: &Harness) {
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

/// A firing outside 19:15 to 19:45 UTC that finds no suspension at expiry
/// lifted by a payment does nothing: no state change, no node asked, no
/// log, no lock; an active user whose expiry has passed is suspended only
/// by the night's run, and an unpaid user stays suspended. The window's
/// edges are 19:15:00 in and 19:45:00 out.
#[test]
fn a_firing_outside_the_window_does_nothing() {
    let mut harness = job(fixture(|parts| {
        user(parts, FIRST).policy.expires_at = Some(at(NOW - 86_400));
        added_unpaid(parts, SECOND, at(NOW - 86_400));
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
                "apply: 2026-10-13 {clock} UTC is outside the apply window (19:15 to 19:45 UTC), and no payment has lifted a suspension at expiry; nothing done\n"
            )
        );
        let outcome = harness.run(&["apply", "--pending", "--json"]);
        assert_eq!(
            outcome.stdout,
            format!("{{\"version\":2,\"at\":{now},\"ran\":false}}\n")
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
             ams1: apply failed: the node could not be reached or refused: ssh ended without a reply (exit status 255): / ssh: connect to the node: Operation timed out\n\
             lon1: apply failed: the node could not be reached or refused: ssh ended without a reply (exit status 255): / ssh: connect to the node: Operation timed out\n\
             apply at 2026-10-13 19:20:00 UTC: 1 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 of 2 node(s) behind applied; 2 failure(s)\n"
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
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 2 held back, 0 kept suspended, 0 removed, 0 of 0 node(s) behind applied; 0 failure(s)\n"
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
             apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 1 removed, 0 of 0 node(s) behind applied; 0 failure(s)\n"
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

/// `text` as `user add --unpaid` added it at `since`: suspended at expiry,
/// its expiry the time it was added.
pub(super) fn added_unpaid(parts: &mut DeploymentParts, text: &str, since: UnixTime) {
    let found = user(parts, text);
    found.policy.expires_at = Some(since);
    found.status = UserStatus::Suspended {
        reason: SuspendReason::Expired,
        since,
    };
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
            "version": 2,
            "at": NOW,
            "ran": true,
            "form": "full",
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
            "nodes": []
        })
    );
    assert_eq!(outcome.stdout.lines().count(), 1);
}

/// A node behind is applied by the job, as `node apply` applies it; the
/// node up to date is not asked.
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
    let mut harness = job(deployment.clone());
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    let (_, header) = bundle_and_header(&harness, &engines, &deployment);
    super::apply::script_hello_and_blobs(&harness, header.blobs());
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
            "lon1: applied\napply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 1 of 1 node(s) behind applied; 0 failure(s)\n"
        ),
        "{}",
        outcome.stdout
    );
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
        "apply at 2026-10-13 19:20:00 UTC: 0 suspended, 0 resumed, 0 held back, 0 kept suspended, 0 removed, 0 of 0 node(s) behind applied; 0 failure(s)\n"
    );
}
