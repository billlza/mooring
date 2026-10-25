// SPDX-License-Identifier: GPL-3.0-or-later

//! `node upgrade-agent` against the fixture deployment and scripted node
//! sessions (design §11.2): the upload, the activation, the `Confirm` the
//! new agent serves, and the `Hello` that shows which agent runs.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{
    AgentError, Generation, LineRequest, RequestKind, Response, Sha256Hex, StderrTail,
};
use mooring_model::Sha256Digest;

use super::support::{Answered, Expected, ExpectedRemote, Harness, Outcome, PINNED, Sent};
use super::user::{fixture, harness_with, state_bytes};
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;

const NEW_AGENT: &[u8] = b"\x7fELF the new static agent";

/// The agent lon1 runs before the upgrade (the `Hello` fixture's).
const OLD: Sha256Hex = Sha256Hex::from_bytes([7; 32]);

/// lon1 deployed, the M7 pinned, and the new agent's file and digest.
fn ready() -> (Harness, PathBuf, Sha256Hex) {
    let mut harness = harness_with(fixture(|_| {}));
    harness.pin(PINNED);
    let path = harness.home.path().join("mooring-agent");
    fs::write(&path, NEW_AGENT).unwrap();
    let sha = Sha256Hex::from_bytes(*Sha256Digest::of(NEW_AGENT).as_bytes());
    (harness, path, sha)
}

/// lon1's `Hello` while it runs agent `sha`.
fn hello_running(sha: Sha256Hex) -> Response {
    let Response::Hello(mut info) = super::node::hello_at(Ipv4Addr::new(45, 67, 89, 10)) else {
        unreachable!()
    };
    info.agent_sha = sha;
    Response::Hello(info)
}

fn expect(harness: &Harness, kind: RequestKind, reply: Result<Response, NodeError>) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind,
        },
        Answered::Replied(reply),
    );
}

fn run(harness: &mut Harness, agent: &Path) -> Outcome {
    harness.run(&[
        "node",
        "upgrade-agent",
        "lon1",
        "--interface",
        "lo0",
        "--agent",
        agent.to_str().unwrap(),
    ])
}

/// A whole upgrade before lon1's first apply (node generation 0): the
/// agent uploaded, activated, confirmed, and then the one that runs.
#[test]
fn an_upgrade_uploads_activates_and_confirms_the_new_agent() {
    let (mut harness, agent, sha) = ready();
    let before = state_bytes(&harness);
    let generation = Generation::ZERO;
    expect(&harness, RequestKind::Hello, Ok(hello_running(OLD)));
    expect(
        &harness,
        RequestKind::HaveBlobs,
        Ok(Response::Blobs {
            present: BTreeSet::new(),
        }),
    );
    harness.nodes.expect(
        Expected::PutBlob {
            identity: "ops_ed25519",
        },
        Answered::Replied(Ok(Response::BlobStored { sha256: sha })),
    );
    expect(
        &harness,
        RequestKind::ActivateAgent,
        Ok(Response::AwaitingConfirm { generation }),
    );
    expect(
        &harness,
        RequestKind::Confirm,
        Ok(Response::Confirmed { generation }),
    );
    expect(&harness, RequestKind::Hello, Ok(hello_running(sha)));
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(
        outcome.stdout,
        format!(
            "lon1: runs agent {OLD}; agent {sha}, 1 blob(s) uploaded\nupgraded: lon1 runs agent {sha} (node generation 0)\n"
        )
    );
    let seen = harness.nodes.seen.borrow();
    assert_eq!(
        seen[3].1,
        Sent::Request(LineRequest::ActivateAgent { sha }),
        "the activation names the uploaded agent"
    );
    assert_eq!(
        seen[4].1,
        Sent::Request(LineRequest::Confirm { generation }),
        "the confirm names the activation's generation"
    );
    drop(seen);
    assert_eq!(state_bytes(&harness), before, "an upgrade changes no state");
}

#[test]
fn an_agent_the_node_runs_already_is_not_activated_again() {
    let (mut harness, agent, sha) = ready();
    expect(&harness, RequestKind::Hello, Ok(hello_running(sha)));
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(outcome.stdout, format!("lon1 already runs agent {sha}\n"));
}

/// A new agent that fails its self-test stays inactive, and the node's
/// error is the command's.
#[test]
fn a_refused_activation_is_the_error() {
    let (mut harness, agent, sha) = ready();
    expect(&harness, RequestKind::Hello, Ok(hello_running(OLD)));
    expect(
        &harness,
        RequestKind::HaveBlobs,
        Ok(Response::Blobs {
            present: BTreeSet::from([sha]),
        }),
    );
    expect(
        &harness,
        RequestKind::ActivateAgent,
        Err(NodeError::Agent(AgentError::AgentSelfTestFailed {
            stderr_tail: StderrTail::scrubbed(b"exec format error\n", &[]),
        })),
    );
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(harness.nodes.script.borrow().is_empty());
    assert!(
        outcome.stderr.contains("new agent failed its self-test"),
        "{}",
        outcome.stderr
    );
}

/// After the confirm the node must run the new agent; one that still runs
/// another is refused, not reported upgraded.
#[test]
fn a_node_that_runs_another_agent_after_the_confirm_is_refused() {
    let (mut harness, agent, sha) = ready();
    let generation = Generation::ZERO;
    expect(&harness, RequestKind::Hello, Ok(hello_running(OLD)));
    expect(
        &harness,
        RequestKind::HaveBlobs,
        Ok(Response::Blobs {
            present: BTreeSet::from([sha]),
        }),
    );
    expect(
        &harness,
        RequestKind::ActivateAgent,
        Ok(Response::AwaitingConfirm { generation }),
    );
    expect(
        &harness,
        RequestKind::Confirm,
        Ok(Response::Confirmed { generation }),
    );
    expect(&harness, RequestKind::Hello, Ok(hello_running(OLD)));
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(harness.nodes.script.borrow().is_empty());
    assert!(
        outcome.stderr.contains(&format!(
            "lon1 runs agent {OLD} after the confirm, not {sha}"
        )),
        "{}",
        outcome.stderr
    );
}
