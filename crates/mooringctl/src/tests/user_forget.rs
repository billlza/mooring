// SPDX-License-Identifier: GPL-3.0-or-later

//! `user forget <uid> [--yes]` (design §15.3, §15.7): a revoked user is
//! removed at once with its bare id kept while a node may still name it,
//! after a question; any other user is refused, and so is a state that
//! changed while the question waited; and the daemon then deletes the
//! user's payment orders.

use mooring_model::{Deployment, UnixTime, UserId, UserStatus};

use super::deployed::{CARRIER, deployed_with, shared, statuses, with_exit_on};
use super::payments::{FIRST, SECOND, connect, grant, ledger_on_disk, page};
use super::support::{MOVED, NOW, change_the_configuration_meanwhile};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::daemon::Intervals;
use crate::error::EXIT_LOCAL;
use crate::prompt::Answer;

fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

/// The fixture with `SECOND` revoked `days` days before the clock.
fn revoked(days: u64) -> Deployment {
    fixture(|parts| {
        for user in &mut parts.users {
            if user.id.as_str() == SECOND {
                user.per_node.clear();
                user.status = UserStatus::Revoked {
                    since: UnixTime::from_secs(NOW - days * 86_400),
                };
            }
        }
    })
}

/// A user revoked yesterday is removed at once, with its label; its bare
/// id stays until 7 days after the end of the month it was revoked in, a
/// day to spare. The record keeps the generation: no node needs an apply.
#[test]
fn forget_removes_a_revoked_user_and_keeps_its_bare_id() {
    let deployment = revoked(1);
    let label = deployment.users()[&id(SECOND)].label.to_string();
    let mut harness = harness_with(deployment);
    assert!(
        String::from_utf8(state_bytes(&harness))
            .unwrap()
            .contains(&label)
    );
    let outcome = harness.run(&["user", "forget", SECOND, "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "user {SECOND}, revoked since 2026-10-12 19:20:00 UTC: its label, alias and agreement record leave state.json now, and the daemon then deletes its usage history and its payment orders\n\
             its bare id stays until 2026-11-09 00:00:00 UTC, while a node may still name it, so that a node's late reply is dropped, not stored again\n\
             this cannot be undone\n\
             removed {SECOND}: the daemon deletes its usage history and payment orders at its next tick, or when it next starts\n"
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    assert!(!after.users().contains_key(&id(SECOND)));
    assert_eq!(
        after.forgotten().get(&id(SECOND)),
        Some(&UnixTime::from_secs(1_794_182_400))
    );
    assert_eq!(after.config_generation().get(), 1);
    assert!(
        !String::from_utf8(state_bytes(&harness))
            .unwrap()
            .contains(&label)
    );
    assert!(harness.console.asked.is_empty());
}

/// Revoked long enough ago, nothing of the user is kept.
#[test]
fn forget_keeps_no_id_once_the_nodes_records_expired() {
    let mut harness = harness_with(revoked(100));
    let outcome = harness.run(&["user", "forget", SECOND, "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .contains("\nno id is kept: the nodes' records of it have expired\n"),
        "{}",
        outcome.stdout
    );
    assert!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .forgotten()
            .is_empty()
    );
}

/// Without `--yes` it asks; anything but yes removes nothing, and so does
/// a state that changed while the question waited.
#[test]
fn forget_asks_first() {
    let mut harness = harness_with(revoked(1));
    let before = state_bytes(&harness);
    harness.console.answers.push_back(Answer::No);
    let outcome = harness.run(&["user", "forget", SECOND]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(harness.console.asked, ["Remove this user now?"]);
    assert_eq!(state_bytes(&harness), before);
    change_the_configuration_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["user", "forget", SECOND]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, MOVED);
    assert!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .users()
            .contains_key(&id(SECOND))
    );
}

/// A user not revoked, and an id the deployment does not hold, are
/// refused before anything is asked.
#[test]
fn forget_refuses_a_user_not_revoked() {
    let mut harness = harness_with(revoked(1));
    let before = state_bytes(&harness);
    for user in [FIRST, "fxuseraazz"] {
        let outcome = harness.run(&["user", "forget", user]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{user}");
        assert!(outcome.stdout.is_empty(), "{}", outcome.stdout);
    }
    let outcome = harness.run(&["user", "forget", FIRST]);
    assert!(
        outcome
            .stderr
            .contains(&format!("user {FIRST} is not revoked")),
        "{}",
        outcome.stderr
    );
    assert!(harness.console.asked.is_empty());
    assert_eq!(state_bytes(&harness), before);
}

/// The payment orders of a forgotten user: the daemon, started again
/// after `user forget`, deletes them on its first tick, and keeps the
/// other users' orders.
#[test]
fn the_daemon_deletes_a_forgotten_users_orders() {
    let mut harness = deployed_with(revoked(1));
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    connect(&mut harness, 1, false, 1);
    harness.portal.ok(&page(
        true,
        0,
        vec![
            grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST),
            grant(2, "bbbbbbbbbbbbbbbbbbbb", SECOND),
        ],
        false,
    ));
    let (control, _retries) = shared();
    with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        for _ in 0..4 {
            exit.tick(&control, log, false).unwrap();
        }
    });
    assert_eq!(ledger_on_disk(&harness).unwrap().orders().len(), 2);
    let outcome = harness.run(&["user", "forget", SECOND, "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    let log = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        exit.tick(&control, log, false).unwrap();
        String::from_utf8(log.clone()).unwrap()
    });
    let orders: Vec<String> = ledger_on_disk(&harness)
        .unwrap()
        .orders()
        .keys()
        .map(ToString::to_string)
        .collect();
    assert_eq!(orders, ["aaaaaaaaaaaaaaaaaaaa"], "{log}");
    assert!(
        log.contains("payment ledger: deleted 1 order(s) of 1 removed user(s)"),
        "{log}"
    );
}
