// SPDX-License-Identifier: GPL-3.0-or-later

//! `user revoke <uid> [--yes]` (design §13.5, §15.3): an active or
//! suspended user becomes `RevokePending` on the nodes holding its
//! credentials, a configuration change that every node then applies, or is
//! revoked at once when it holds none; it says first what it does and asks,
//! since it cannot be undone; and a user unknown, being revoked or revoked
//! is refused before anything is asked.

use mooring_model::user::SuspendReason;
use mooring_model::{CalendarDate, Deployment, PublicAlias, UnixTime, UserId, UserStatus};

use super::support::{MOVED, NOW, change_the_configuration_meanwhile};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::EXIT_LOCAL;
use crate::prompt::Answer;

const SECOND: &str = "fxuseraaac";

fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

/// The fixture with `SECOND` edited.
fn with_second(edit: impl FnOnce(&mut mooring_model::User)) -> Deployment {
    fixture(|parts| {
        let second = parts
            .users
            .iter_mut()
            .find(|user| user.id.as_str() == SECOND)
            .unwrap();
        edit(second);
    })
}

const BOTH_BEHIND: &str =
    "ams1 (behind; its next apply commits it), lon1 (behind; its next apply commits it)";

/// An active user holding credentials on both nodes becomes pending on
/// both, at a new generation, which puts both nodes behind: nothing is
/// applied, no node is asked, and the credentials stay until each node
/// commits. The command says what it does first, naming the alias.
#[test]
fn revoke_starts_the_revocation_on_the_nodes_holding_the_user() {
    let alias = PublicAlias::from_random_bytes([0x9b, 0x18, 0x6d, 0x0e, 0x55]);
    let deployment = with_second(|user| user.alias = Some(alias.clone()));
    let mut harness = harness_with(deployment.clone());
    let outcome = harness.run(&["user", "revoke", SECOND, "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "user {SECOND} (alias {alias}): active; credentials on ams1, lon1\n\
             revoking it ends its service for good: no node serves it from the configuration this makes, and no file or portal profile is made for it again\n\
             it waits on {BOTH_BEHIND}: each node commits the revocation once it applies a configuration without the user, and then its credentials there are deleted from the keychain; with none left it is revoked, and its records here go 13 months later, or at once with `mooringctl user forget {SECOND}`\n\
             this cannot be undone; the Stripe and portal steps that follow it are in docs/runbooks/revoke.md, section 3\n\
             revocation started for {SECOND} (configuration generation 2): it waits on {BOTH_BEHIND}\n\
             next: `mooringctl apply --now` applies every applied node behind now, or the nightly apply job does at 19:20 UTC; it records each node's commit\n"
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    let user = &after.users()[&id(SECOND)];
    assert_eq!(user.status, UserStatus::RevokePending);
    assert_eq!(
        user.per_node,
        deployment.users()[&id(SECOND)].per_node,
        "the credentials stay until each node commits"
    );
    assert_eq!(after.config_generation().get(), 2);
    assert_eq!(after.nodes(), deployment.nodes());
    // Only that user changed.
    let mut expected = deployment.into_parts();
    for user in &mut expected.users {
        if user.id.as_str() == SECOND {
            user.status = UserStatus::RevokePending;
        }
    }
    expected.config_generation = after.config_generation();
    assert_eq!(after, Deployment::try_from(expected).unwrap());
    assert!(harness.console.asked.is_empty());
    assert!(harness.nodes.seen.borrow().is_empty());
}

/// A suspended user is revoked like an active one, whatever the reason,
/// and the command names the suspension.
#[test]
fn a_suspended_user_is_revoked_like_an_active_one() {
    let since = UnixTime::from_secs(NOW - 86_400);
    let mut harness = harness_with(with_second(|user| {
        user.status = UserStatus::Suspended {
            reason: SuspendReason::QuotaExceeded {
                cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
            },
            since,
        };
    }));
    let outcome = harness.run(&["user", "revoke", SECOND, "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with(&format!(
            "user {SECOND}: suspended for quota in the billing cycle from 2026-10-01 since 2026-10-12 19:20:00 UTC; credentials on ams1, lon1\n"
        )),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        store(&harness).load().unwrap().deployment.users()[&id(SECOND)].status,
        UserStatus::RevokePending
    );
}

/// A user holding credentials on no node is revoked at once, dated now,
/// and the command says when its records go: 13 months on.
#[test]
fn a_user_holding_no_credentials_is_revoked_at_once() {
    let mut harness = harness_with(with_second(|user| {
        user.per_node.clear();
        user.status = UserStatus::Suspended {
            reason: SuspendReason::Operator,
            since: UnixTime::from_secs(NOW - 3600),
        };
    }));
    let outcome = harness.run(&["user", "revoke", SECOND, "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let records = format!(
        ": its records here go 13 months later, on 2027-11-13 19:20:00 UTC, or at once with `mooringctl user forget {SECOND}`"
    );
    assert_eq!(
        outcome.stdout,
        format!(
            "user {SECOND}: suspended by the operator since 2026-10-13 18:20:00 UTC; credentials on no node\n\
             revoking it ends its service for good: no node serves it from the configuration this makes, and no file or portal profile is made for it again\n\
             it holds credentials on no node, so it is revoked at once{records}\n\
             this cannot be undone; the Stripe and portal steps that follow it are in docs/runbooks/revoke.md, section 3\n\
             revoked {SECOND} (configuration generation 2){records}\n"
        )
    );
    assert_eq!(
        store(&harness).load().unwrap().deployment.users()[&id(SECOND)].status,
        UserStatus::Revoked {
            since: UnixTime::from_secs(NOW)
        }
    );
}

/// Without `--yes` it asks; anything but yes changes nothing, and so does
/// a state that changed while the question waited.
#[test]
fn revoke_asks_first() {
    let mut harness = harness_with(fixture(|_| {}));
    let before = state_bytes(&harness);
    harness.console.answers.push_back(Answer::No);
    let outcome = harness.run(&["user", "revoke", SECOND]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(harness.console.asked, ["Revoke this user?"]);
    assert_eq!(state_bytes(&harness), before);
    harness.console.answers.push_back(Answer::NoTerminal);
    assert_eq!(harness.run(&["user", "revoke", SECOND]).code, EXIT_LOCAL);
    assert_eq!(state_bytes(&harness), before);
    change_the_configuration_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["user", "revoke", SECOND]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, MOVED);
    assert_eq!(
        store(&harness).load().unwrap().deployment.users()[&id(SECOND)].status,
        UserStatus::Active
    );
}

/// A user being revoked or revoked, and an id no user has, are refused
/// before anything is said or asked, and the state is left as it was.
#[test]
fn revoke_refuses_a_user_already_revoking_or_revoked_and_an_unknown_user() {
    let revoking = with_second(|user| user.status = UserStatus::RevokePending);
    let revoked = with_second(|user| {
        user.per_node.clear();
        user.status = UserStatus::Revoked {
            since: UnixTime::from_secs(NOW - 86_400),
        };
    });
    let started = format!(
        "mooringctl: the state was not changed\n  caused by: the new or changed deployment is invalid\n  caused by: user {SECOND} is already pending revocation or revoked\n"
    );
    for (deployment, user, stderr) in [
        (revoking, SECOND, started.clone()),
        (revoked, SECOND, started),
        (
            fixture(|_| {}),
            "zzzzzzzzzz",
            "mooringctl: unknown user zzzzzzzzzz\n".to_owned(),
        ),
    ] {
        let mut harness = harness_with(deployment);
        let before = state_bytes(&harness);
        let outcome = harness.run(&["user", "revoke", user]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{user}");
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, stderr);
        assert!(harness.console.asked.is_empty());
        assert_eq!(state_bytes(&harness), before);
    }
}
