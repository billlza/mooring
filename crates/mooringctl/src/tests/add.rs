// SPDX-License-Identifier: GPL-3.0-or-later

//! `user add` against a state file and an in-memory keychain (design §7,
//! §9.4, §15.3): the user it adds, the credentials it writes before the
//! state that references them, and the refusals that change nothing.

use std::collections::BTreeSet;
use std::num::NonZeroU16;

use mooring_export::{ExportErrorKind, export_secret_refs};
use mooring_model::{
    Capability, ClientLine, Deployment, NodeId, NodeLifecycle, SecretRef, UnixTime, User, UserId,
    UserPolicy, UserStatus,
};
use mooring_store::SecretStore;

use super::support::{Harness, NOW};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::EXIT_LOCAL;

const LABEL: &str = "Cousin in Chengdu";

fn node(id: &str) -> NodeId {
    NodeId::parse(id).unwrap()
}

/// A harness holding `deployment`, with `label` typed at the prompt.
fn adding(deployment: Deployment, label: Option<&str>) -> Harness {
    let mut harness = harness_with(deployment);
    harness
        .console
        .lines
        .push_back(label.map(|label| label.as_bytes().to_vec()));
    harness
}

/// The one user `after` holds that `before` does not.
fn added(before: &Deployment, after: &Deployment) -> User {
    let mut new: Vec<&User> = after
        .users()
        .values()
        .filter(|user| !before.users().contains_key(&user.id))
        .collect();
    assert_eq!(new.len(), 1);
    new.remove(0).clone()
}

fn user_refs(user: &UserId, nodes: &[&str]) -> BTreeSet<SecretRef> {
    nodes
        .iter()
        .flat_map(|id| {
            [
                SecretRef::UserVlessUuid(user.clone(), node(id)),
                SecretRef::UserHy2Password(user.clone(), node(id)),
                SecretRef::UserLoopUuid(user.clone(), node(id)),
            ]
        })
        .collect()
}

/// The new user is active on a CFM 0.5 client, holds credentials on every
/// active node, and has no alias and no agreement record; the keychain
/// gains exactly its credentials; the generation is bumped, so every node
/// must be applied before the user's file can be exported.
#[test]
fn add_creates_an_active_user_with_credentials_on_every_node() {
    let before = fixture(|_| {});
    let mut harness = adding(before.clone(), Some(LABEL));
    let outcome = harness.run(&["user", "add"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        harness.console.asked,
        ["Label for this user (kept on this Mac only): "]
    );
    let after = store(&harness).load().unwrap().deployment;
    let user = added(&before, &after);
    assert_eq!(user.label.as_str(), LABEL);
    assert!(
        !outcome.stdout.contains(LABEL),
        "the label is never printed"
    );
    assert_eq!(user.client.line, ClientLine::Cfm05);
    assert!(user.client.capabilities.is_empty());
    assert_eq!(user.status, UserStatus::Active);
    assert_eq!(user.policy, UserPolicy::NONE);
    assert_eq!(user.alias, None);
    assert_eq!(user.agreement, None);
    let held: Vec<&str> = user.per_node.keys().map(NodeId::as_str).collect();
    assert_eq!(held, ["ams1", "lon1"]);
    assert_eq!(
        harness.secrets.refs(),
        user_refs(&user.id, &["ams1", "lon1"])
    );
    for secret_ref in harness.secrets.refs() {
        let material = harness.secrets.get(&secret_ref).unwrap();
        assert_eq!(material.kind(), secret_ref.kind());
    }
    assert_eq!(
        after.config_generation(),
        before.config_generation().next().unwrap()
    );
    assert_eq!(
        outcome.stdout,
        format!(
            "added user {}: CFM 0.5, credentials on ams1, lon1\nnext: `mooringctl user alias {}`, then `node apply` each of those nodes, then `user agree` and `user export`\n",
            user.id, user.id
        )
    );
    // No node has confirmed the new generation yet: each is stale until
    // `node apply`, and the export refuses the user until then.
    for node in after.nodes().values() {
        let applied = node.lifecycle.applied().unwrap();
        assert!(applied.config_generation < after.config_generation());
    }
    let refusal = export_secret_refs(&after, &user.id, UnixTime::from_secs(NOW)).unwrap_err();
    assert_eq!(refusal.kind(), ExportErrorKind::AgreementNotAccepted);
}

#[test]
fn add_takes_the_client_line_and_the_mlkem_opt_in() {
    for (args, line, capabilities) in [
        (
            &["user", "add", "--client", "cfm04"][..],
            ClientLine::Cfm04,
            vec![],
        ),
        (
            &["user", "add", "--mlkem"][..],
            ClientLine::Cfm05,
            vec![Capability::RealityMlkemOptIn],
        ),
    ] {
        let before = fixture(|_| {});
        let mut harness = adding(before.clone(), Some(LABEL));
        let outcome = harness.run(args);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        let user = added(&before, &store(&harness).load().unwrap().deployment);
        assert_eq!(user.client.line, line);
        assert_eq!(
            user.client.capabilities.into_iter().collect::<Vec<_>>(),
            capabilities
        );
    }
}

/// A retiring node is on its way out: a new user gets no credentials there.
#[test]
fn add_skips_a_retiring_node() {
    let before = fixture(|parts| {
        for user in &mut parts.users {
            user.per_node.remove(&node("ams1"));
        }
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|candidate| candidate.id == node("ams1"))
            .unwrap();
        let site = ams1.lifecycle.site().unwrap().clone();
        ams1.lifecycle = NodeLifecycle::Retiring { site };
    });
    let mut harness = adding(before.clone(), Some(LABEL));
    assert_eq!(harness.run(&["user", "add"]).code, 0);
    let user = added(&before, &store(&harness).load().unwrap().deployment);
    let held: Vec<&str> = user.per_node.keys().map(NodeId::as_str).collect();
    assert_eq!(held, ["lon1"]);
    assert_eq!(harness.secrets.refs(), user_refs(&user.id, &["lon1"]));
}

/// Every refusal exits 1, leaves `state.json` byte for byte as it was and
/// writes nothing to the keychain.
#[test]
fn add_refusals_change_nothing() {
    let full = fixture(|parts| parts.capacity.max_active_users = NonZeroU16::new(3));
    let cases: [(Deployment, Option<&str>, &[&str], &str); 5] = [
        (
            fixture(|_| {}),
            Some(LABEL),
            &["user", "add", "--client", "cfm04", "--mlkem"],
            "mooringctl: CFM 0.4 does not accept the ML-KEM opt-in; drop --mlkem or use --client cfm05\n",
        ),
        (
            fixture(|_| {}),
            None,
            &["user", "add"],
            "mooringctl: no terminal to ask for the label (it is never taken from an argument)\n",
        ),
        (
            fixture(|_| {}),
            Some(""),
            &["user", "add"],
            "mooringctl: the label was not accepted\n  caused by: label must be 1-64 characters, without control characters or surrounding whitespace\n",
        ),
        (
            fixture(|_| {}),
            Some(&"x".repeat(300)),
            &["user", "add"],
            "mooringctl: the label was not accepted\n  caused by: label must be 1-64 characters, without control characters or surrounding whitespace\n",
        ),
        (
            full,
            Some(LABEL),
            &["user", "add"],
            "mooringctl: the state was not changed\n  caused by: the new or changed deployment is invalid\n  caused by: 4 users are active, more than the cap of 3\n",
        ),
    ];
    for (deployment, label, args, stderr) in cases {
        let mut harness = adding(deployment, label);
        let before = state_bytes(&harness);
        let outcome = harness.run(args);
        assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
        assert_eq!(outcome.stdout, "");
        assert_eq!(outcome.stderr, stderr, "{args:?}");
        assert_eq!(state_bytes(&harness), before);
        assert!(harness.secrets.is_empty(), "{args:?}");
    }
}

/// `user alias` gives a user without one a random alias; it is a
/// configuration change, so the generation is bumped.
#[test]
fn alias_gives_a_user_a_random_alias_once() {
    let before = fixture(|_| {});
    let user = before.users().keys().next().unwrap().clone();
    assert_eq!(before.users()[&user].alias, None);
    let mut harness = harness_with(before.clone());
    let outcome = harness.run(&["user", "alias", user.as_str()]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let after = store(&harness).load().unwrap().deployment;
    let alias = after.users()[&user].alias.clone().unwrap();
    assert_eq!(
        outcome.stdout,
        format!(
            "user {user} has the alias {alias}; every node it holds needs `node apply` before its next export\n"
        )
    );
    assert_eq!(
        after.config_generation(),
        before.config_generation().next().unwrap()
    );
    // Nothing else changed.
    let mut expected = before.into_parts();
    expected.users[0].alias = Some(alias.clone());
    expected.config_generation = after.config_generation();
    assert_eq!(after, Deployment::try_from(expected).unwrap());
    // An alias is never replaced, and an unknown user has none to get.
    let bytes = state_bytes(&harness);
    let again = harness.run(&["user", "alias", user.as_str()]);
    assert_eq!(again.code, EXIT_LOCAL);
    assert_eq!(
        again.stderr,
        format!("mooringctl: user {user} already has the alias {alias}\n")
    );
    let unknown = harness.run(&["user", "alias", "zzzzzzzzzz"]);
    assert_eq!(unknown.code, EXIT_LOCAL);
    assert_eq!(unknown.stderr, "mooringctl: unknown user zzzzzzzzzz\n");
    assert_eq!(state_bytes(&harness), bytes);
}
