// SPDX-License-Identifier: GPL-3.0-or-later

//! An answer that waited (design §13.2). `node cancel`, `node repin` and
//! `node adopt` read the state again once their question is answered, and
//! stop unless its deployment is the one they read; adoption also checks
//! its interface again. Each command's own tests hold the first case of
//! its second read (`tests::cancel`, `tests::repin`, `tests::adopt`).
//! These hold what that read compares, the whole deployment and nothing
//! else, what follows when it cannot be made, and adoption's second look
//! at its interface.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::fs;

use mooring_model::deployment::Bookkeeping;
use mooring_model::iface::InterfaceIndex;
use mooring_model::node::{AppliedConfig, NodeLifecycle, SshPin};
use mooring_model::{Ed25519Pub, NodeId};
use mooring_store::Store;

use super::cancel::{cancelled_and_stopped, lon1_dir, new_host_key, script_bootstrap};
use super::export::exporting;
use super::node::{
    adopt_args, agent_file, host_key_file, planned, root_key, script_after_bootstrap,
};
use super::support::{Answered, Expected, Harness, MOVED, OTHER, Outcome, PINNED, lo0};
use super::user::{fixture, store};
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;
use crate::node::dial::M7Egress;
use crate::prompt::Answer;

fn lon1() -> NodeId {
    NodeId::parse("lon1").unwrap()
}

/// Runs `node adopt lon1` with the operator's root key and no `--yes`, and
/// answers yes.
fn adopt_and_answer_yes(harness: &mut Harness) -> Outcome {
    harness.console.answers.push_back(Answer::Yes);
    let agent = agent_file(harness);
    let root = root_key(harness);
    let args: Vec<&str> = adopt_args(agent.to_str().unwrap(), Some(root.to_str().unwrap()))
        .into_iter()
        .filter(|arg| *arg != "--yes")
        .collect();
    harness.run(&args)
}

/// Scripts an upload that fails, so that a session opened against a test's
/// expectation shows in what the sessions recorded, not as the fake's
/// panic over a step nobody scripted.
fn script_a_refused_upload(harness: &Harness) {
    harness.nodes.expect(
        Expected::Run {
            identity: "root_ed25519",
            command_prefix: "umask 077",
        },
        Answered::Ran(Err(NodeError::Ssh {
            code: Some(255),
            stderr: "Connection refused".to_owned(),
        })),
    );
}

/// Replaces `state.json` with bytes that are no state while the question
/// waits.
fn damage_the_state_meanwhile(harness: &mut Harness) {
    let state = store(harness).state_path();
    harness.console.meanwhile = Some(Box::new(move || fs::write(state, b"{").unwrap()));
}

/// Enables the exit while the question waits, as `exit enable` in another
/// terminal does: `state.json` is rewritten with the same deployment and a
/// new runtime revision.
fn enable_the_exit_meanwhile(harness: &mut Harness) {
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let revision = store.load().unwrap().runtime.revision;
        store.set_exit_enabled(revision, true).unwrap();
    }));
}

/// Adoption checks that its interface faces the pinned M7 before it asks,
/// and again once the question is answered. The gateway may be another
/// device by then, as after a cable was moved, and the upload with the
/// operator's root key and `Bootstrap` would leave through it.
#[test]
fn an_adoption_answered_after_the_interface_stopped_facing_the_m7_opens_no_session() {
    let (mut harness, _) = planned();
    let looked = harness.link.neighbour_calls.get();
    harness.link.neighbours = RefCell::new(VecDeque::from([Ok(PINNED), Ok(OTHER)]));
    script_a_refused_upload(&harness);
    let outcome = adopt_and_answer_yes(&mut harness);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the gateway of lo0 is 02:00:5e:99:99:99, not the pinned M7 (02:00:5e:10:20:30): give the interface that faces the M7\n"
    );
    assert_eq!(harness.console.asked, ["Hand this VPS to Mooring?"]);
    assert_eq!(harness.link.neighbour_calls.get(), looked + 2);
    assert!(harness.nodes.seen.borrow().is_empty());
    assert_eq!(
        store(&harness).load().unwrap().deployment.nodes()[&lon1()].lifecycle,
        NodeLifecycle::Planned
    );
}

/// The sessions after the answer bind to the interface as the check made
/// then found it. An adapter unplugged and plugged in again while the
/// question waited comes back under another index, and the index checked
/// before the question may be another interface's by then.
#[test]
fn an_adoption_binds_its_sessions_to_the_interface_as_it_is_once_answered() {
    let (mut harness, _) = planned();
    let replugged = InterfaceIndex::new(lo0().get() + 40).unwrap();
    harness.link.indexes = RefCell::new(VecDeque::from([lo0(), replugged]));
    harness
        .link
        .routes
        .insert(replugged.get(), (harness.link.gateway, Ok(PINNED)));
    script_bootstrap(&harness, &new_host_key());
    script_after_bootstrap(&harness, 13);
    let outcome = adopt_and_answer_yes(&mut harness);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let seen = harness.nodes.seen.borrow();
    assert_eq!(seen.len(), 5);
    for (target, sent) in seen.iter() {
        assert_eq!(target.egress, M7Egress::for_tests(replugged), "{sent:?}");
    }
}

/// A re-pin while adoption's question waits: the answer was about the old
/// pin, which `known_hosts` already holds, so no session is opened. The
/// node is still planned, so a second read that looked only for that would
/// let the session check the key the operator has just replaced.
#[test]
fn an_adoption_answered_after_a_repin_opens_no_session() {
    let (mut harness, pinned) = planned();
    let other: Ed25519Pub = new_host_key();
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let generation = store.load().unwrap().deployment.config_generation();
        store
            .update_config(generation, |mut parts| {
                parts.nodes[0].ssh = SshPin {
                    host_ed25519: other,
                };
                Ok::<_, Infallible>(parts)
            })
            .unwrap();
    }));
    script_a_refused_upload(&harness);
    let outcome = adopt_and_answer_yes(&mut harness);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, MOVED);
    assert!(harness.console.meanwhile.is_none());
    assert!(harness.nodes.seen.borrow().is_empty());
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.nodes()[&lon1()].ssh.host_ed25519, other);
    assert_ne!(other, pinned);
    assert_eq!(after.nodes()[&lon1()].lifecycle, NodeLifecycle::Planned);
}

/// A state that cannot be read again when the answer comes is no state to
/// act on: the adoption opens no session, and the files a stopped cancel
/// left stay. For these two answers no later write would catch it.
#[test]
fn an_answer_is_not_acted_on_when_the_state_cannot_be_read_again() {
    // `node adopt`.
    let (mut harness, _) = planned();
    damage_the_state_meanwhile(&mut harness);
    script_a_refused_upload(&harness);
    let outcome = adopt_and_answer_yes(&mut harness);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state could not be read\n"),
        "{}",
        outcome.stderr
    );
    assert_eq!(harness.console.asked, ["Hand this VPS to Mooring?"]);
    assert!(harness.console.meanwhile.is_none());
    assert!(harness.nodes.seen.borrow().is_empty());

    // `node cancel` for the files a stopped cancel left.
    let mut harness = cancelled_and_stopped();
    let dir = lon1_dir(&harness);
    let held = fs::read_dir(&dir).unwrap().count();
    assert!(held > 0);
    damage_the_state_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state could not be read\n"),
        "{}",
        outcome.stderr
    );
    assert_eq!(harness.console.asked, ["Remove these files?"]);
    assert!(harness.console.meanwhile.is_none());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), held);
}

/// The answer to the question about a stopped cancel's files removes
/// nothing once the state is another one, whatever changed in it: here a
/// configuration change that plans no node, so the id is still free.
#[test]
fn the_leftover_answer_removes_nothing_after_any_change_of_the_state() {
    let mut harness = cancelled_and_stopped();
    let dir = lon1_dir(&harness);
    let held = fs::read_dir(&dir).unwrap().count();
    assert!(held > 0);
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let generation = store.load().unwrap().deployment.config_generation();
        store
            .update_config(generation, Ok::<_, Infallible>)
            .unwrap();
    }));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert_eq!(outcome.stderr, MOVED);
    assert_eq!(harness.console.asked, ["Remove these files?"]);
    assert!(harness.console.meanwhile.is_none());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), held);
    assert!(
        !store(&harness)
            .load()
            .unwrap()
            .deployment
            .nodes()
            .contains_key(&lon1())
    );
}

/// A record that keeps the generation and the planned node stops the
/// re-pin all the same: `node apply lon1` finishes while the re-pin of
/// par1 asks, and the line about the applied nodes that the answer was
/// given to is then out of date.
#[test]
fn a_repin_answered_after_another_nodes_apply_is_refused() {
    let lon1_only = fixture(|parts| {
        parts.nodes.retain(|node| node.id == lon1());
        for user in &mut parts.users {
            user.per_node.retain(|node, _| *node == lon1());
        }
    });
    let (mut harness, _) = exporting(lon1_only);
    let (path, _) = host_key_file(&harness, "par1.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "par1",
        "--role",
        "standby",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let par1 = NodeId::parse("par1").unwrap();
    let pinned = store(&harness).load().unwrap().deployment.nodes()[&par1]
        .ssh
        .host_ed25519;
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let deployment = store.load().unwrap().deployment;
        let generation = deployment.config_generation();
        let digest = deployment.nodes()[&lon1()]
            .lifecycle
            .applied()
            .unwrap()
            .digest;
        store
            .record(
                generation,
                Bookkeeping::Applied {
                    node: lon1(),
                    applied: AppliedConfig {
                        config_generation: generation,
                        digest,
                    },
                },
            )
            .unwrap();
    }));
    harness.console.answers.push_back(Answer::Yes);
    let (path, _) = host_key_file(&harness, "reinstalled.pub");
    let outcome = harness.run(&[
        "node",
        "repin",
        "par1",
        "--host-key",
        path.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert_eq!(outcome.stderr, MOVED);
    assert!(harness.console.meanwhile.is_none());
    assert!(
        outcome
            .stdout
            .contains("every applied node (lon1) then needs `node apply`"),
        "{}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.nodes()[&par1].ssh.host_ed25519, pinned);
}

/// Only the deployment is compared. `exit enable` while a question waits
/// rewrites the whole document, and the deployment read back from it is
/// the one read before, so none of the four answers is refused.
#[test]
fn the_exit_enabled_while_a_question_waited_stops_no_command() {
    // `node cancel`.
    let (mut harness, _) = planned();
    enable_the_exit_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, 0, "cancel: {}", outcome.stderr);
    assert!(harness.console.meanwhile.is_none());
    let state = store(&harness).load().unwrap();
    assert!(state.runtime.exit_enabled);
    assert!(state.deployment.nodes().is_empty());

    // `node cancel` for the files a stopped cancel left.
    let mut harness = cancelled_and_stopped();
    enable_the_exit_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, 0, "leftover: {}", outcome.stderr);
    assert!(harness.console.meanwhile.is_none());
    assert_eq!(harness.console.asked, ["Remove these files?"]);
    assert!(store(&harness).load().unwrap().runtime.exit_enabled);
    assert!(!lon1_dir(&harness).exists());

    // `node repin`.
    let (mut harness, _) = planned();
    let (path, key) = host_key_file(&harness, "reinstalled.pub");
    enable_the_exit_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&[
        "node",
        "repin",
        "lon1",
        "--host-key",
        path.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "repin: {}", outcome.stderr);
    assert!(harness.console.meanwhile.is_none());
    let state = store(&harness).load().unwrap();
    assert!(state.runtime.exit_enabled);
    assert_eq!(state.deployment.nodes()[&lon1()].ssh.host_ed25519, key);

    // `node adopt`.
    let (mut harness, _) = planned();
    script_bootstrap(&harness, &new_host_key());
    script_after_bootstrap(&harness, 13);
    enable_the_exit_meanwhile(&mut harness);
    let outcome = adopt_and_answer_yes(&mut harness);
    assert_eq!(outcome.code, 0, "adopt: {}", outcome.stderr);
    assert!(harness.console.meanwhile.is_none());
    assert!(harness.nodes.script.borrow().is_empty());
    let state = store(&harness).load().unwrap();
    assert!(state.runtime.exit_enabled);
    assert!(matches!(
        state.deployment.nodes()[&lon1()].lifecycle,
        NodeLifecycle::Adopted { .. }
    ));
}
