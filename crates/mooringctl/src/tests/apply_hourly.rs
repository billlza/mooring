// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's hourly firings outside its window (design §13.6, the
//! operator's decision of 2026-11-14), against the fixture deployment and
//! scripted node sessions: only the resumes at expiry that a payment has
//! lifted, then the nodes behind and only after a resume; the cap that
//! holds such a resume back; and a firing that cannot tell whether anyone
//! is to be resumed, which runs and reports why. A firing with no one to
//! resume is `apply_job`'s `a_firing_outside_the_window_does_nothing`.

use std::fs;

use mooring_model::node::NodeLifecycle;
use mooring_model::user::SuspendReason;
use mooring_model::{CalendarDate, ConfigGeneration, DeploymentParts, UserStatus};
use serde_json::Value;

use super::apply_job::{
    FIRST, SECOND, THIRD, added_unpaid, at, deployment, job, log, status, unreachable, user,
};
use super::support::{Harness, NOW};
use super::user::{fixture, state_bytes};
use crate::error::EXIT_LOCAL;

/// The portal's grant of a month to `text`, pulled at `when`.
fn pay(harness: &mut Harness, text: &str, when: u64) {
    use super::payments::{connect, grant, page};
    use crate::payments::pull::{Gate, Puller};

    connect(harness, 1, false, 1);
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, "aaaaaaaaaaaaaaaaaaaa", text)],
        false,
    ));
    let mut puller = Puller::open(&harness.support_dir());
    let users = deployment(harness).users().clone();
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
        )
    });
}

/// Outside the window, a firing resumes the suspensions at expiry that a
/// payment has lifted, and then applies the nodes behind, so that a user
/// who pays is served within the hour (the operator's decision of
/// 2026-11-14). It suspends no one, lifts no suspension for quota and
/// removes no one: those wait for the night's run. The log counts and
/// names no user. A node whose apply failed waits for the night's run: the
/// next firing, with no one left to resume, asks no node.
#[test]
fn outside_the_window_a_firing_resumes_what_a_payment_lifted() {
    let mut harness = job(fixture(|parts| {
        // ams1 never applied, so that lon1 alone is behind once a user is
        // resumed.
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &node.lifecycle
                && node.id.as_str() == "ams1"
            {
                node.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
        added_unpaid(parts, FIRST, at(NOW - 86_400));
        user(parts, SECOND).policy.expires_at = Some(at(NOW - 3600));
        user(parts, THIRD).status = UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded {
                cycle_start: CalendarDate::parse("2026-09-01").unwrap(),
            },
            since: at(NOW - 40 * 86_400),
        };
    }));
    pay(&mut harness, FIRST, NOW + 1800);
    harness.now.set(NOW + 3600);
    unreachable(&harness);
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert_eq!(status(&harness, SECOND), UserStatus::Active);
    assert!(matches!(
        status(&harness, THIRD),
        UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded { .. },
            ..
        }
    ));
    assert_eq!(
        outcome.stdout,
        format!(
            "resumed {FIRST}, suspended at expiry since 2026-10-12 19:20:00 UTC: its expiry is no longer past\n\
             lon1: apply failed: the node could not be reached or refused: ssh ended without a reply (exit status 255): / ssh: connect to the node: Operation timed out\n\
             apply at 2026-10-13 20:20:00 UTC, outside the window: 1 resumed at expiry, 0 held back, 0 kept suspended, 0 of 1 node(s) behind applied; 1 failure(s)\n"
        )
    );
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(harness.redirected.get(), 1);
    let log = log(&harness);
    for line in [
        "mooringctl apply: run (--pending, outside the window: resumes at expiry only)\n",
        "mooringctl apply: policy: 0 suspended, 1 resumed, 0 held back by the cap, 0 kept suspended, 0 failed\n",
        "mooringctl apply: lon1: apply failed: ",
        "mooringctl apply: done: 1 failure(s)\n",
    ] {
        assert!(log.contains(line), "{line}: {log}");
    }
    assert!(!log.contains("removals"), "{log}");
    assert!(!log.contains("fxuser"), "{log}");
    // An hour later no one is left to resume: lon1, still behind, waits
    // for the night's run.
    let asked = harness.nodes.seen.borrow().len();
    let before = state_bytes(&harness);
    harness.now.set(NOW + 7200);
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "apply: 2026-10-13 21:20:00 UTC is outside the apply window (19:15 to 19:45 UTC), and no payment has lifted a suspension at expiry; nothing done\n"
    );
    assert_eq!(harness.nodes.seen.borrow().len(), asked);
    assert_eq!(state_bytes(&harness), before);
}

/// An hourly firing whose resume the cap holds back changes nothing and
/// asks no node, though both are behind. With `--json` it says that it ran
/// outside the window, made no removals and tried no node.
#[test]
fn an_hourly_resume_the_cap_holds_back_asks_no_node() {
    let mut harness = job(fixture(|parts| {
        added_unpaid(parts, FIRST, at(NOW - 86_400));
        parts.capacity.max_active_users = std::num::NonZeroU16::new(2);
        parts.config_generation = ConfigGeneration::new(2).unwrap();
    }));
    pay(&mut harness, FIRST, NOW + 1800);
    harness.now.set(NOW + 3600);
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--pending", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "version": 2,
            "at": NOW + 3600,
            "ran": true,
            "form": "expiry_resumes",
            "policy": {"carried_out": {
                "suspended": [],
                "resumed": [],
                "held_back": [{
                    "user": FIRST,
                    "reason": "expired",
                    "since": NOW - 86_400,
                    "why": "no_longer_expired"
                }],
                "kept": [],
                "failed": [],
                "quotas_unchecked": [],
                "usage_behind": "ams1 may have counted traffic, but no usage ledger is given for it"
            }},
            "removals": null,
            "nodes": null
        })
    );
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.nodes.seen.borrow().is_empty());
    let log = log(&harness);
    for line in [
        "mooringctl apply: run (--pending, outside the window: resumes at expiry only)\n",
        "mooringctl apply: policy: 0 suspended, 0 resumed, 1 held back by the cap, 0 kept suspended, 0 failed\n",
        "mooringctl apply: done: 0 failure(s)\n",
    ] {
        assert!(log.contains(line), "{line}: {log}");
    }
}

/// Outside the window, a firing that cannot tell whether a payment lifted
/// a suspension at expiry runs and reports why, rather than read that as
/// no one to resume: a payment ledger that cannot be read, a suspension for
/// quota dated after the firing (a clock that stepped back) and a state
/// that cannot be read each fail it. It changes nothing and applies no
/// node, though both are behind.
#[test]
fn outside_the_window_a_firing_that_cannot_tell_reports_why() {
    let behind = |edit: fn(&mut DeploymentParts)| {
        let harness = job(fixture(|parts| {
            added_unpaid(parts, FIRST, at(NOW - 86_400));
            parts.config_generation = ConfigGeneration::new(2).unwrap();
            edit(parts);
        }));
        harness.now.set(NOW + 3600);
        harness
    };
    let mut harness = behind(|_| {});
    let payments = harness
        .support_dir()
        .join(mooring_store::PAYMENTS_DIRECTORY);
    fs::create_dir(&payments).unwrap();
    fs::write(
        payments.join(mooring_store::PAYMENT_LEDGER_FILE),
        b"not a ledger",
    )
    .unwrap();
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    let lines: Vec<&str> = outcome.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{}", outcome.stdout);
    assert!(
        lines[0].starts_with(
            "policy step not carried out: the payment ledger or the pull's settings cannot be read, and a paid user would be read as unpaid: "
        ),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        lines[1],
        "apply at 2026-10-13 20:20:00 UTC, outside the window: 0 resumed at expiry, 0 held back, 0 kept suspended, no node applied, as no one was resumed; 1 failure(s)"
    );
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.nodes.seen.borrow().is_empty());
    let log = log(&harness);
    for line in [
        "mooringctl apply: run (--pending, outside the window: resumes at expiry only)\n",
        "mooringctl apply: policy step not carried out: the payment ledger or the pull's settings cannot be read, and a paid user would be read as unpaid\n",
        "mooringctl apply: done: 1 failure(s)\n",
    ] {
        assert!(log.contains(line), "{line}: {log}");
    }
    let mut harness = behind(|parts| {
        user(parts, SECOND).status = UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded {
                cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
            },
            since: at(NOW + 86_400),
        };
    });
    let before = state_bytes(&harness);
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert!(
        outcome.stdout.starts_with(&format!(
            "policy step not carried out: a suspension for quota is dated after now: the clock stepped back, or a record is wrong: user {SECOND} was suspended for quota at @1792005600, after now (@1791922800)\n"
        )),
        "{}",
        outcome.stdout
    );
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.nodes.seen.borrow().is_empty());
    let mut harness = behind(|_| {});
    fs::write(harness.support_dir().join(mooring_store::STATE_FILE), b"{}").unwrap();
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert_eq!(outcome.stdout, "");
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state could not be read\n  caused by: state file "),
        "{}",
        outcome.stderr
    );
    assert!(harness.nodes.seen.borrow().is_empty());
}
