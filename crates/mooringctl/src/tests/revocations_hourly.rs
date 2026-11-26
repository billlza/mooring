// SPDX-License-Identifier: GPL-3.0-or-later

//! The apply job's revocations in its hourly form outside the window
//! (design §13.6): a firing that resumed a user records, after its node
//! applies, the revocations they settled, as the night's run does; and it
//! revokes no one at expiry, which waits for the night's run.

use mooring_model::node::NodeLifecycle;
use mooring_model::user::SuspendReason;
use mooring_model::{AgreementVersion, ConfigGeneration, Deployment, ExpiryRevocation, UserStatus};
use serde_json::Value;

use super::apply_hourly::pay;
use super::apply_job::{FIRST, SECOND, added_unpaid, at, job, log, status, unreachable, user};
use super::revocations::{script_unchanged, user_items};
use super::support::NOW;
use super::user::fixture;
use crate::daemon::deployed::ENGINES_DIRECTORY;
use crate::error::EXIT_LOCAL;

/// An hourly firing that resumed a user applies the nodes behind and then
/// records the revocations those applies settled: the user being revoked
/// leaves ams1, which applied, and still waits on lon1, which could not be
/// reached. The log counts and names no user.
#[test]
fn an_hourly_firing_records_the_revocations_its_applies_settle() {
    let before = fixture(|parts| {
        parts.config_generation = ConfigGeneration::new(2).unwrap();
        added_unpaid(parts, FIRST, at(NOW - 86_400));
        user(parts, SECOND).status = UserStatus::RevokePending;
    });
    // The deployment once the firing has resumed FIRST.
    let resumed = {
        let mut parts = before.clone().into_parts();
        user(&mut parts, FIRST).resume().unwrap();
        parts.config_generation = parts.config_generation.next().unwrap();
        Deployment::try_from(parts).unwrap()
    };
    let mut harness = job(before);
    pay(&mut harness, FIRST, NOW + 1800);
    harness.now.set(NOW + 3600);
    let engines = harness.support_dir().join(ENGINES_DIRECTORY);
    script_unchanged(&harness, &engines, &resumed, "ams1", 3);
    unreachable(&harness);
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert_eq!(status(&harness, SECOND), UserStatus::RevokePending);
    assert!(user_items(&harness, SECOND, "ams1").is_empty());
    assert_eq!(user_items(&harness, SECOND, "lon1").len(), 3);
    let waits = "lon1 (behind; its next apply commits it)";
    assert!(
        outcome.stdout.ends_with(&format!(
            "revocation committed on ams1: {SECOND}, which still waits on {waits}\n\
             revocation pending: {SECOND} waits on {waits}\n\
             apply at 2026-10-13 20:20:00 UTC, outside the window: 1 resumed at expiry, 0 held back, 0 kept suspended, 1 of 2 node(s) behind applied, 1 revocation(s) committed, 1 still pending; 1 failure(s)\n"
        )),
        "{}",
        outcome.stdout
    );
    assert!(harness.nodes.script.borrow().is_empty());
    let log = log(&harness);
    assert!(
        log.contains(
            "mooringctl apply: revocations: 1 committed, 0 failed, 1 user(s) still pending\n"
        ),
        "{log}"
    );
    assert!(!log.contains("fxuser"), "{log}");
}

/// An hourly firing revokes no one at expiry, though a user is due and the
/// agreement they accepted provides for it: a revocation cannot be undone,
/// so it waits for the night's run, which makes it. The firing's `--json`
/// outcome holds its applies' revocations, none here.
#[test]
fn an_hourly_firing_revokes_no_one_at_expiry() {
    let expired = at(NOW - 100 * 86_400);
    let mut harness = job(fixture(|parts| {
        // Adopted, never applied: no node is behind, and none is asked.
        for found in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &found.lifecycle {
                found.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
        added_unpaid(parts, FIRST, at(NOW - 86_400));
        let second = user(parts, SECOND);
        second.policy.expires_at = Some(expired);
        second.status = UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: expired,
        };
    }));
    harness.expiry_revocation = ExpiryRevocation::since(Some(AgreementVersion::CURRENT));
    pay(&mut harness, FIRST, NOW + 1800);
    harness.now.set(NOW + 3600);
    let outcome = harness.run(&["apply", "--pending", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let value: Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(value["form"], "expiry_resumes");
    let done = &value["policy"]["carried_out"];
    assert_eq!(done["resumed"][0]["user"], FIRST);
    for field in [
        "revoked",
        "revocation_awaiting_pull",
        "revocation_not_covered",
    ] {
        assert_eq!(done[field], serde_json::json!([]), "{field}");
    }
    assert_eq!(value["nodes"], serde_json::json!([]));
    assert_eq!(
        value["revocations"],
        serde_json::json!({"done": {"committed": [], "failed": [], "pending": []}})
    );
    assert_eq!(
        status(&harness, SECOND),
        UserStatus::Suspended {
            reason: SuspendReason::Expired,
            since: expired,
        }
    );
    // The night's run revokes them: the pull that granted FIRST's month
    // succeeded after SECOND's revocation fell due.
    harness.now.set(NOW + 86_400);
    let outcome = harness.run(&["apply", "--pending"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .contains(&format!("revoked {SECOND}: suspended at expiry since ")),
        "{}",
        outcome.stdout
    );
    assert_eq!(status(&harness, SECOND), UserStatus::RevokePending);
}
