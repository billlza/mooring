// SPDX-License-Identifier: GPL-3.0-or-later

//! `node target check|set`'s report of a target that failed (design
//! §11.7): what the node found when nothing resolved, no TLS connection or
//! handshake was made and no HTTP answer came; a reply to another request
//! than the check; and output that fails partway through `set`, which then
//! stores nothing.

use std::collections::BTreeSet;
use std::path::Path;

use mooring_agent_proto::{HttpProbe, RequestKind, Response, TlsProbe};
use mooring_model::NodeId;

use super::apply::{HOST, good_facts, ready, script_measure};
use super::support::{
    Answered, Expected, ExpectedRemote, FailingLog, Harness, change_the_configuration_meanwhile,
    changed_since,
};
use super::user::{fixture, state_bytes, store};
use crate::error::EXIT_LOCAL;
use crate::prompt::Answer;

fn check(harness: &mut Harness, engines: &Path) -> super::support::Outcome {
    harness.run(&[
        "node",
        "target",
        "check",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
    ])
}

#[test]
fn the_report_says_what_the_node_could_not_reach() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    let mut facts = good_facts();
    facts.resolved = BTreeSet::new();
    facts.tls = TlsProbe::ConnectFailed;
    facts.http = HttpProbe::Failed;
    script_measure(&harness, true, facts);
    let outcome = check(&mut harness, &engines);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with(&format!(
            "{HOST}: resolves to nothing\nTLS: no connection on 443\nHTTP: no answer\n"
        )),
        "{}",
        outcome.stdout
    );
    assert!(outcome.stdout.contains("\nrefused: "), "{}", outcome.stdout);
    let mut facts = good_facts();
    facts.tls = TlsProbe::HandshakeFailed;
    script_measure(&harness, true, facts);
    let outcome = check(&mut harness, &engines);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains("\nTLS: the handshake failed\n"),
        "{}",
        outcome.stdout
    );
}

/// A node that answers the check with another reply is refused, and
/// nothing is reported as measured.
#[test]
fn a_reply_to_another_request_than_the_check_is_refused() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    script_measure(&harness, true, good_facts());
    // The check's own answer is replaced by another reply.
    harness.nodes.script.borrow_mut().pop_back();
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::TargetCheck,
        },
        Answered::Replied(Ok(Response::BootstrapRevoked)),
    );
    let outcome = check(&mut harness, &engines);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        "mooringctl: the node could not be reached or refused\n  caused by: the agent answered TargetCheck with BootstrapRevoked\n"
    );
    // A node that answers the question which blobs it holds with another
    // reply is refused before anything is uploaded or measured.
    let (mut harness, engines) = ready(fixture(|_| {}));
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::HaveBlobs,
        },
        Answered::Replied(Ok(Response::BootstrapRevoked)),
    );
    let outcome = check(&mut harness, &engines);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the node could not be reached or refused\n  caused by: the agent answered HaveBlobs with BootstrapRevoked\n"
    );
    assert_eq!(harness.nodes.seen.borrow().len(), 1);
}

/// An adopted node without a target gets the qualified one; nothing is
/// said to be replaced.
#[test]
fn a_first_target_replaces_nothing() {
    let (mut harness, engines) = ready(fixture(|parts| {
        let lon1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id.as_str() == "lon1")
            .unwrap();
        let site = lon1.lifecycle.site().unwrap().clone();
        lon1.lifecycle = mooring_model::node::NodeLifecycle::Adopted { site };
        lon1.reality.target = None;
    }));
    script_measure(&harness, true, good_facts());
    let outcome = harness.run(&[
        "node",
        "target",
        "set",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
        "--same-asn",
        "--not-cdn",
        "--evidence",
        "https://bgp.example.net/AS0",
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        !outcome.stdout.contains("this replaces"),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome
            .stdout
            .contains(&format!("stored {HOST} as lon1's target")),
        "{}",
        outcome.stdout
    );
}

/// The answer may have waited. A configuration change that another
/// command made meanwhile refuses the target: it is one write for the
/// generation `set` read before it measured, and the store finds another.
#[test]
fn a_configuration_change_while_the_question_waits_stores_no_target() {
    let deployment = fixture(|_| {});
    let read = deployment.config_generation().get();
    let (mut harness, engines) = ready(deployment.clone());
    script_measure(&harness, true, good_facts());
    change_the_configuration_meanwhile(&mut harness);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&[
        "node",
        "target",
        "set",
        "lon1",
        HOST,
        "--interface",
        "lo0",
        "--engines",
        engines.to_str().unwrap(),
        "--same-asn",
        "--not-cdn",
        "--evidence",
        "https://bgp.example.net/AS0",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, changed_since(read));
    assert_eq!(harness.console.asked, ["Store this target?"]);
    assert!(harness.console.meanwhile.is_none());
    assert!(!outcome.stdout.contains("stored "), "{}", outcome.stdout);
    let after = store(&harness).load().unwrap().deployment;
    let lon1 = NodeId::parse("lon1").unwrap();
    assert_eq!(
        after.nodes()[&lon1].reality.target,
        deployment.nodes()[&lon1].reality.target
    );
    assert_eq!(after.config_generation().get(), read + 1);
}

/// `set` writes the facts and what the target replaces before it asks;
/// output that fails there stops it, and nothing is stored.
#[test]
fn output_that_fails_before_the_question_stores_nothing() {
    let (mut harness, engines) = ready(fixture(|_| {}));
    script_measure(&harness, true, good_facts());
    let before = state_bytes(&harness);
    let mut out = FailingLog::at("this replaces");
    let mut err = Vec::new();
    let code = harness.run_to(
        &[
            "node",
            "target",
            "set",
            "lon1",
            HOST,
            "--interface",
            "lo0",
            "--engines",
            engines.to_str().unwrap(),
            "--same-asn",
            "--not-cdn",
            "--evidence",
            "https://bgp.example.net/AS0",
            "--yes",
        ],
        &mut out,
        &mut err,
    );
    assert_eq!(code, EXIT_LOCAL);
    assert!(out.failed());
    assert!(
        String::from_utf8(err)
            .unwrap()
            .starts_with("mooringctl: writing the output failed\n"),
    );
    assert_eq!(state_bytes(&harness), before);
}
