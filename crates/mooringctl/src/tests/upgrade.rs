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
    expect(
        &harness,
        RequestKind::WatchRuntime,
        Ok(watch_inspected(OLD)),
    );
    expect(&harness, RequestKind::RefreshWatch, Ok(watch_running(sha)));
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(
        outcome.stdout,
        format!(
            "lon1: runs agent {OLD}; agent {sha}, 1 blob(s) uploaded\nupgraded: lon1 runs agent {sha} (node generation 0)\nbefore refresh: lon1 watch {OLD} (pid 42, start ticks 1000)\nverified: lon1 watch runs {sha} (pid 42, start ticks 1000)\n"
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
    expect(
        &harness,
        RequestKind::WatchRuntime,
        Ok(watch_inspected(OLD)),
    );
    expect(&harness, RequestKind::RefreshWatch, Ok(watch_running(sha)));
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(
        outcome.stdout,
        format!(
            "lon1 already runs agent {sha}\nbefore refresh: lon1 watch {OLD} (pid 42, start ticks 1000)\nverified: lon1 watch runs {sha} (pid 42, start ticks 1000)\n"
        )
    );
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

/// A reply to another request at any step stops the upgrade there, naming
/// the request and the reply; nothing more is sent.
#[test]
fn a_reply_to_another_request_stops_the_upgrade() {
    let generation = Generation::ZERO;
    let blobs = |sha| {
        Ok(Response::Blobs {
            present: BTreeSet::from([sha]),
        })
    };
    for (step, said) in [
        (0, "the agent answered Hello with BootstrapRevoked"),
        (1, "the agent answered ActivateAgent with BootstrapRevoked"),
        (2, "the agent answered Confirm with AwaitingConfirm"),
    ] {
        let (mut harness, agent, sha) = ready();
        if step == 0 {
            expect(&harness, RequestKind::Hello, Ok(Response::BootstrapRevoked));
        } else {
            expect(&harness, RequestKind::Hello, Ok(hello_running(OLD)));
            expect(&harness, RequestKind::HaveBlobs, blobs(sha));
            if step == 1 {
                expect(
                    &harness,
                    RequestKind::ActivateAgent,
                    Ok(Response::BootstrapRevoked),
                );
            } else {
                expect(
                    &harness,
                    RequestKind::ActivateAgent,
                    Ok(Response::AwaitingConfirm { generation }),
                );
                expect(
                    &harness,
                    RequestKind::Confirm,
                    Ok(Response::AwaitingConfirm { generation }),
                );
            }
        }
        let outcome = run(&mut harness, &agent);
        assert_eq!(outcome.code, EXIT_LOCAL, "{said}");
        assert_eq!(
            outcome.stderr,
            format!("mooringctl: the node could not be reached or refused\n  caused by: {said}\n")
        );
        assert!(harness.nodes.script.borrow().is_empty(), "{said}");
    }
}

/// Only an adopted or applied node is upgraded: an unknown node and one
/// not adopted yet are refused before any session.
#[test]
fn only_a_deployed_node_is_upgraded() {
    let (mut harness, agent, _) = ready();
    let outcome = harness.run(&[
        "node",
        "upgrade-agent",
        "zzz1",
        "--interface",
        "lo0",
        "--agent",
        agent.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, "mooringctl: unknown node zzz1\n");
    let (mut planned, _) = super::node::planned();
    let agent = super::node::agent_file(&planned);
    let outcome = run(&mut planned, &agent);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: node lon1 is Planned; it must be adopted first\n"
    );
    assert!(planned.nodes.seen.borrow().is_empty());
}

fn watch_running(sha: Sha256Hex) -> Response {
    Response::WatchRefreshed(mooring_agent_proto::WatchRuntime {
        at: mooring_agent_proto::UnixTime::from_secs(1000),
        agent_sha: sha,
        watch: Some(mooring_agent_proto::WatchProcess {
            pid: std::num::NonZeroU32::new(42).unwrap(),
            start_ticks: 1000,
            executable_sha: sha,
        }),
    })
}

#[test]
fn an_already_updated_agent_with_an_old_watch_is_not_a_success() {
    let (mut harness, agent, sha) = ready();
    expect(&harness, RequestKind::Hello, Ok(hello_running(sha)));
    expect(
        &harness,
        RequestKind::WatchRuntime,
        Ok(watch_inspected(OLD)),
    );
    expect(&harness, RequestKind::RefreshWatch, Ok(watch_running(OLD)));
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(outcome.stderr.contains("watch executable"));
    assert!(!outcome.stdout.contains("verified:"));
    assert!(harness.nodes.script.borrow().is_empty());
}

#[test]
fn a_refused_watch_restart_is_reported_after_the_control_upgrade() {
    let (mut harness, agent, sha) = ready();
    expect(&harness, RequestKind::Hello, Ok(hello_running(sha)));
    expect(
        &harness,
        RequestKind::WatchRuntime,
        Ok(watch_inspected(OLD)),
    );
    expect(
        &harness,
        RequestKind::RefreshWatch,
        Err(NodeError::Agent(AgentError::WatchNotUpdated {
            expected: sha,
        })),
    );
    let outcome = run(&mut harness, &agent);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(outcome.stderr.contains("watch did not run"));
    assert!(!outcome.stdout.contains("verified:"));
}

fn watch_inspected(sha: Sha256Hex) -> Response {
    let Response::WatchRefreshed(runtime) = watch_running(sha) else {
        unreachable!()
    };
    Response::WatchRuntime(runtime)
}

#[test]
fn runtime_inspection_prints_actual_process_evidence_or_explicit_absence() {
    let (mut harness, _, _) = ready();
    expect(
        &harness,
        RequestKind::WatchRuntime,
        Ok(watch_inspected(OLD)),
    );
    let outcome = harness.run(&["node", "runtime", "lon1", "--interface", "lo0", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let runtime: mooring_agent_proto::WatchRuntime = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(runtime.watch.unwrap().executable_sha, OLD);
    let Response::WatchRuntime(mut runtime) = watch_inspected(OLD) else {
        unreachable!()
    };
    runtime.watch = None;
    expect(
        &harness,
        RequestKind::WatchRuntime,
        Ok(Response::WatchRuntime(runtime)),
    );
    let outcome = harness.run(&["node", "runtime", "lon1", "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!("lon1: control agent {OLD}\nwatch: no main process\n")
    );
    expect(
        &harness,
        RequestKind::WatchRuntime,
        Ok(watch_inspected(OLD)),
    );
    let outcome = harness.run(&["node", "runtime", "lon1", "--interface", "lo0"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(outcome.stdout.contains("pid 42, start ticks 1000"));
    expect(&harness, RequestKind::WatchRuntime, Ok(watch_running(OLD)));
    let outcome = harness.run(&["node", "runtime", "lon1", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(outcome.stderr.contains("WatchRuntime with WatchRefreshed"));
}
