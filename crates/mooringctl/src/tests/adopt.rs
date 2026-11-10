// SPDX-License-Identifier: GPL-3.0-or-later

//! `node adopt`'s refusals and failures (design §13.2 step 3) beyond the
//! upload: an unknown node, an agent binary that cannot be read or is
//! empty, a failure or a reply to another request at each step after the
//! upload, and a host that ran Mooring before. Each is reported with its
//! step and leaves the node planned. A key `Bootstrap` made that cannot
//! be recorded as the pin is reported with the key.

use std::convert::Infallible;
use std::fs;

use mooring_agent_proto::{AgentError, PriorState, RequestKind, Response};
use mooring_keys::SshPublicKey;
use mooring_model::NodeId;
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::SecretRef;
use mooring_store::{SecretStore, Store};

use super::cancel::{
    adopt as adopt_with_the_root_key, lon1_dir, new_host_key, partially_adopted, script_bootstrap,
};
use super::node::{
    ADDRESS, adopt_args, agent_file, hello, planned, root_key, script_after_bootstrap,
};
use super::support::{Answered, Expected, ExpectedRemote, Harness, Refusals};
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

/// A `Bootstrap` that finds the host ran Mooring before stops the adoption
/// at that step, naming what it found and what to do. The agent changed
/// nothing on the VPS, so the node stays planned with its pin, and its
/// bootstrap key stays for the next attempt.
#[test]
fn a_host_that_ran_mooring_before_stops_the_adoption_at_bootstrap() {
    let (mut harness, pinned) = planned();
    let generation = store(&harness)
        .load()
        .unwrap()
        .deployment
        .config_generation();
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
        Answered::Replied(Err(NodeError::Agent(AgentError::HostRanMooring {
            found: PriorState::Usage,
        }))),
    );
    let outcome = harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: adoption stopped at Bootstrap\n  caused by: the agent refused the request\n  caused by: the host ran Mooring before (Usage at /var/lib/mooring/usage); Bootstrap changed nothing: reinstall the VPS, check its new host key's fingerprint on the provider's console, pin that key (node repin), and adopt it again\n"
    );
    assert!(harness.nodes.script.borrow().is_empty());
    let lon1 = NodeId::parse("lon1").unwrap();
    let state = store(&harness).load().unwrap();
    let node = &state.deployment.nodes()[&lon1];
    assert_eq!(node.lifecycle, NodeLifecycle::Planned);
    assert_eq!(node.ssh.host_ed25519, pinned);
    assert_eq!(state.deployment.config_generation(), generation);
    assert!(
        harness
            .secrets
            .get(&SecretRef::NodeSshBootstrapPrivate(lon1))
            .is_ok()
    );
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

/// The final record of an adoption drops the bootstrap key's keychain item;
/// when that deletion fails, the node is adopted all the same: the key's
/// file goes, the adoption is reported, and the failure says the change is
/// committed rather than that nothing changed.
#[test]
fn an_adoption_whose_bootstrap_key_cannot_be_deleted_is_adopted_and_says_so() {
    let (mut harness, _) = partially_adopted();
    let bootstrap = SecretRef::NodeSshBootstrapPrivate(NodeId::parse("lon1").unwrap());
    script_after_bootstrap(&harness, 13);
    *harness.keychain.lock().unwrap() = Refusals {
        delete: Some(-25_308),
        ..Refusals::default()
    };
    let agent = agent_file(&harness);
    let outcome = harness.run(&adopt_args(agent.to_str().unwrap(), None));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stdout.contains("adopted lon1: Debian 13"),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stderr.lines().next().unwrap(),
        "mooringctl: the change is committed, but some keychain items it no longer references could not be deleted; nothing uses them, and they can be deleted by hand"
    );
    assert!(matches!(
        lon1_lifecycle(&harness),
        NodeLifecycle::Adopted { .. }
    ));
    assert!(!lon1_dir(&harness).join("bootstrap_ed25519").exists());
    assert!(
        harness.secrets.get(&bootstrap).is_ok(),
        "the refused deletion left it"
    );
    assert!(harness.nodes.script.borrow().is_empty());
}

/// What stops the key `Bootstrap` made from being recorded as the pin.
#[derive(Debug, Clone, Copy)]
enum Unrecorded {
    /// Another command changes the configuration while `Bootstrap` runs.
    ConfigurationChanged,
    /// `known_hosts` cannot be replaced.
    KnownHostsBlocked,
}

/// `Bootstrap` ran, so the VPS holds its new host key and lets in only
/// Mooring's keys, but the Mac cannot record that key as the pin. The
/// adoption stops with the key in its error and the node planned on its
/// old pin; pinning the key the error names lets `--resume` finish.
#[test]
fn an_adoption_that_cannot_record_bootstraps_key_names_it_and_resumes_after_a_repin() {
    for case in [
        Unrecorded::ConfigurationChanged,
        Unrecorded::KnownHostsBlocked,
    ] {
        let (mut harness, old_host) = planned();
        let lon1 = NodeId::parse("lon1").unwrap();
        let support = harness.support_dir();
        let dir = lon1_dir(&harness);
        let partial = dir.join("known_hosts.partial");
        let blocked = partial.clone();
        *harness.nodes.meanwhile.borrow_mut() = Some((
            1,
            Box::new(move || match case {
                Unrecorded::ConfigurationChanged => {
                    let store = Store::new(support);
                    let generation = store.load().unwrap().deployment.config_generation();
                    store
                        .update_config(generation, Ok::<_, Infallible>)
                        .unwrap();
                }
                Unrecorded::KnownHostsBlocked => fs::create_dir(&blocked).unwrap(),
            }),
        ));
        let bootstrapped = SshPublicKey::from(new_host_key());
        script_bootstrap(&harness, &bootstrapped.key());
        let outcome = adopt_with_the_root_key(&mut harness);
        assert_eq!(outcome.code, EXIT_LOCAL, "{case:?}");
        assert!(harness.nodes.script.borrow().is_empty(), "{case:?}");
        let mut lines = outcome.stderr.lines();
        let first = lines.next().unwrap();
        assert_eq!(
            first,
            format!(
                "mooringctl: Bootstrap ran, so node lon1's VPS now holds host key {} and lets in only Mooring's keys, but that key was not recorded as the node's pin: if the node is still planned, save `{}` to a file, pin it with `node repin lon1 --host-key <file>`, then run `node adopt lon1 --resume`; if it was cancelled, reinstall the VPS or delete it from the provider's console",
                bootstrapped.fingerprint(),
                bootstrapped.authorized_key()
            ),
            "{case:?}"
        );
        let causes: Vec<&str> = lines.collect();
        let (generation, known_hosts) = match case {
            Unrecorded::ConfigurationChanged => {
                assert_eq!(
                    causes,
                    [
                        "  caused by: the state was not changed",
                        "  caused by: config generation is 3, expected 2; re-read the state and retry"
                    ]
                );
                (3, bootstrapped)
            }
            Unrecorded::KnownHostsBlocked => {
                assert_eq!(
                    causes[0],
                    format!("  caused by: cannot use {}", partial.display())
                );
                assert_eq!(causes.len(), 2, "{causes:?}");
                (2, SshPublicKey::from(old_host))
            }
        };
        assert!(
            !outcome.stdout.contains("bootstrapped lon1"),
            "{case:?}: {}",
            outcome.stdout
        );
        let deployment = store(&harness).load().unwrap().deployment;
        assert_eq!(deployment.config_generation().get(), generation, "{case:?}");
        assert_eq!(deployment.nodes()[&lon1].lifecycle, NodeLifecycle::Planned);
        assert_eq!(deployment.nodes()[&lon1].ssh.host_ed25519, old_host);
        assert_eq!(
            fs::read_to_string(dir.join("known_hosts")).unwrap(),
            format!(
                "{}\n",
                known_hosts.known_hosts_line(ADDRESS.parse().unwrap())
            ),
            "{case:?}"
        );

        if matches!(case, Unrecorded::KnownHostsBlocked) {
            fs::remove_dir(&partial).unwrap();
        }
        // The key is taken from the error, as the operator takes it.
        let named = first.split('`').nth(1).unwrap();
        let file = harness.home.path().join("bootstrapped.pub");
        fs::write(&file, format!("{named}\n")).unwrap();
        let outcome = harness.run(&[
            "node",
            "repin",
            "lon1",
            "--host-key",
            file.to_str().unwrap(),
            "--yes",
        ]);
        assert_eq!(outcome.code, 0, "{case:?}: {}", outcome.stderr);
        script_after_bootstrap(&harness, 13);
        let agent = agent_file(&harness);
        let outcome = harness.run(&adopt_args(agent.to_str().unwrap(), None));
        assert_eq!(outcome.code, 0, "{case:?}: {}", outcome.stderr);
        assert!(harness.nodes.script.borrow().is_empty(), "{case:?}");
        let deployment = store(&harness).load().unwrap().deployment;
        assert!(
            matches!(
                deployment.nodes()[&lon1].lifecycle,
                NodeLifecycle::Adopted { .. }
            ),
            "{case:?}"
        );
        assert_eq!(
            deployment.nodes()[&lon1].ssh.host_ed25519,
            bootstrapped.key()
        );
        assert_eq!(
            fs::read_to_string(dir.join("known_hosts")).unwrap(),
            format!(
                "{}\n",
                bootstrapped.known_hosts_line(ADDRESS.parse().unwrap())
            ),
            "{case:?}"
        );
    }
}
