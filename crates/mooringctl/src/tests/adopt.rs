// SPDX-License-Identifier: GPL-3.0-or-later

//! `node adopt`'s refusals and failures (design §13.2 step 3) beyond the
//! upload: an unknown node, an agent binary that cannot be read or is
//! empty, and a failure or a reply to another request at each step after
//! the upload. Each is reported with its step and leaves the node planned.

use std::fs;

use mooring_agent_proto::{AgentError, RequestKind, Response};
use mooring_model::NodeId;
use mooring_model::node::NodeLifecycle;

use super::node::{ADDRESS, adopt_args, agent_file, hello, planned, root_key};
use super::support::{Answered, Expected, ExpectedRemote, Harness};
use super::user::store;
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;

fn lon1_lifecycle(harness: &Harness) -> NodeLifecycle {
    store(harness).load().unwrap().deployment.nodes()[&NodeId::parse("lon1").unwrap()]
        .lifecycle
        .clone()
}

/// The empty request that checks the operations key's forced command.
fn forced_check(harness: &Harness, answer: Result<Response, NodeError>) {
    harness.nodes.expect(
        Expected::Empty {
            identity: "ops_ed25519",
            command: "true",
        },
        Answered::Replied(answer),
    );
}

fn agent_request(harness: &Harness, kind: RequestKind, answer: Result<Response, NodeError>) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind,
        },
        Answered::Replied(answer),
    );
}

fn forced_command_answers(harness: &Harness) {
    forced_check(harness, Err(NodeError::Agent(AgentError::UnknownRequest)));
}

/// What a case scripts on the harness's node sessions.
type Script = fn(&Harness);

/// A failure, or a reply to another request, at each step after the
/// upload (here resumed, so the steps start at the forced command's
/// check) stops the adoption there, naming the step.
#[test]
fn a_failure_after_the_upload_stops_the_adoption_at_its_step() {
    let cases: [(Script, &str); 5] = [
        (
            |harness| forced_check(harness, Err(NodeError::Pipe)),
            "mooringctl: adoption stopped at the operations key's forced command\n  caused by: the ssh session's pipes failed\n",
        ),
        (
            |harness| forced_check(harness, Ok(hello(ADDRESS.parse().unwrap(), 13))),
            "mooringctl: adoption stopped at the operations key's forced command\n  caused by: the agent answered Hello with Hello\n",
        ),
        (
            |harness| {
                forced_command_answers(harness);
                agent_request(harness, RequestKind::Hello, Err(NodeError::Pipe));
            },
            "mooringctl: adoption stopped at Hello\n  caused by: the ssh session's pipes failed\n",
        ),
        (
            |harness| {
                forced_command_answers(harness);
                agent_request(harness, RequestKind::Hello, Ok(Response::BootstrapRevoked));
            },
            "mooringctl: adoption stopped at Hello\n  caused by: the agent answered Hello with BootstrapRevoked\n",
        ),
        (
            |harness| {
                forced_command_answers(harness);
                agent_request(
                    harness,
                    RequestKind::Hello,
                    Ok(hello(ADDRESS.parse().unwrap(), 13)),
                );
                agent_request(harness, RequestKind::RevokeBootstrap, Err(NodeError::Pipe));
            },
            "mooringctl: adoption stopped at RevokeBootstrap\n  caused by: the ssh session's pipes failed\n",
        ),
    ];
    for (script, stderr) in cases {
        let (mut harness, _) = planned();
        let agent = agent_file(&harness);
        script(&harness);
        let outcome = harness.run(&adopt_args(agent.to_str().unwrap(), None));
        assert_eq!(outcome.code, EXIT_LOCAL, "{stderr}");
        assert_eq!(outcome.stderr, stderr);
        assert!(harness.nodes.script.borrow().is_empty(), "{stderr}");
        assert_eq!(lon1_lifecycle(&harness), NodeLifecycle::Planned);
    }
}

/// A `Bootstrap` that fails is reported as that step's failure, after the
/// upload.
#[test]
fn a_failed_bootstrap_stops_the_adoption_at_its_step() {
    let (mut harness, _) = planned();
    let agent = agent_file(&harness);
    let root = root_key(&harness);
    harness.nodes.expect(
        Expected::Run {
            identity: "root_ed25519",
            command_prefix: "umask 077",
        },
        Answered::Ran(Ok(())),
    );
    harness.nodes.expect(
        Expected::Request {
            identity: "root_ed25519",
            remote: ExpectedRemote::Command("/root/.mooring-agent-"),
            kind: RequestKind::Bootstrap,
        },
        Answered::Replied(Err(NodeError::Pipe)),
    );
    let outcome = harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: adoption stopped at Bootstrap\n  caused by: the ssh session's pipes failed\n"
    );
    assert!(harness.nodes.script.borrow().is_empty());
    assert_eq!(lon1_lifecycle(&harness), NodeLifecycle::Planned);
}

/// An unknown node, and an agent binary that cannot be read or is empty,
/// are refused before any session.
#[test]
fn an_unknown_node_or_an_unusable_agent_is_refused_before_any_session() {
    let (mut harness, _) = planned();
    let agent = agent_file(&harness);
    let outcome = harness.run(&[
        "node",
        "adopt",
        "zzz1",
        "--address",
        ADDRESS,
        "--interface",
        "lo0",
        "--agent",
        agent.to_str().unwrap(),
        "--resume",
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, "mooringctl: unknown node zzz1\n");

    let missing = harness.home.path().join("no-agent");
    let outcome = harness.run(&adopt_args(missing.to_str().unwrap(), None));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: cannot read the agent binary {}\n  caused by: No such file or directory (os error 2)\n",
            missing.display()
        )
    );

    let empty = harness.home.path().join("empty-agent");
    fs::write(&empty, b"").unwrap();
    let outcome = harness.run(&adopt_args(empty.to_str().unwrap(), None));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: {} is empty or larger than 64 MiB; give the release build of mooring-agent\n",
            empty.display()
        )
    );
    assert!(harness.nodes.seen.borrow().is_empty());
    assert_eq!(lon1_lifecycle(&harness), NodeLifecycle::Planned);
}
