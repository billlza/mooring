// SPDX-License-Identifier: GPL-3.0-or-later

//! `node repin` (design §13.2) against the harness's support directory: a
//! planned node's pinned host key is replaced, after the fingerprints are
//! shown and the question answered, as a configuration change; a node past
//! `Planned`, an unknown one, a file that holds no single key, and the key
//! already pinned change nothing. The next adoption checks the new key.

use std::fs;
use std::process::Command;

use mooring_keys::SshPublicKey;
use mooring_model::deployment::Bookkeeping;
use mooring_model::node::{LifecycleStage, SshPin};
use mooring_model::secret::SecretRef;
use mooring_model::{Ed25519Pub, NodeId};
use mooring_store::{SecretStore, record_with_secrets};

use super::cancel::{lon1_dir, partially_adopted};
use super::node::{ADDRESS, adopt_args, agent_file, host_key_file, planned};
use super::support::{Answered, Expected, FailingLog, Harness, Refusals};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::{EXIT_LOCAL, LocalError};
use crate::node::NodeError;
use crate::node::planned::{PlannedAction, pin_in_state};
use crate::prompt::Answer;

fn node_id(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn fingerprint(key: Ed25519Pub) -> String {
    SshPublicKey::from(key).fingerprint().to_string()
}

/// The fixture's lon1, applied, and par1 planned through `node new`; the
/// pinned key of par1.
fn applied_lon1_and_planned_par1() -> (Harness, Ed25519Pub) {
    let mut harness = harness_with(fixture(|parts| {
        parts.nodes.retain(|node| node.id == node_id("lon1"));
        for user in &mut parts.users {
            user.per_node.retain(|node, _| *node == node_id("lon1"));
        }
    }));
    let (path, key) = host_key_file(&harness, "par1.pub");
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
    (harness, key)
}

#[test]
fn repin_replaces_only_the_planned_nodes_host_key() {
    let (mut harness, pinned) = applied_lon1_and_planned_par1();
    let before = store(&harness).load().unwrap().deployment;
    let refs = harness.secrets.refs();
    let (path, key) = host_key_file(&harness, "reinstalled.pub");
    let outcome = harness.run(&[
        "node",
        "repin",
        "par1",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let next = before.config_generation().get() + 1;
    assert_eq!(
        outcome.stdout,
        format!(
            "node par1: planned, host key {} pinned; {} holds {}\n\
             `node adopt par1` logs in as root with your own key to whichever host holds the new key: compare it with the fingerprint the provider's console shows (on the VPS, `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), since a key read over the network, by ssh-keyscan or a first ssh, is no check\n\
             re-pinned node par1 to host key {} (configuration generation {next}); next: `mooringctl node adopt par1`\n",
            fingerprint(pinned),
            path.display(),
            fingerprint(key),
            fingerprint(key),
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    let mut expected = before.nodes()[&node_id("par1")].clone();
    expected.ssh = SshPin { host_ed25519: key };
    assert_eq!(after.nodes()[&node_id("par1")], expected);
    assert_eq!(
        after.nodes()[&node_id("lon1")],
        before.nodes()[&node_id("lon1")]
    );
    assert_eq!(after.users(), before.users());
    assert_eq!(after.config_generation().get(), next);
    assert_eq!(harness.secrets.refs(), refs);
    assert!(harness.console.asked.is_empty());
    // Nothing is written for the node but its pin: no ssh directory.
    assert!(!harness.support_dir().join("ssh").join("par1").exists());
}

#[test]
fn repin_asks_first_and_a_declined_or_unanswerable_repin_changes_nothing() {
    let (mut harness, _) = planned();
    let before = state_bytes(&harness);
    let (path, key) = host_key_file(&harness, "reinstalled.pub");
    let args = [
        "node",
        "repin",
        "lon1",
        "--host-key",
        path.to_str().unwrap(),
    ];
    for (answer, why) in [
        (Answer::No, "the answer was not yes"),
        (
            Answer::NoTerminal,
            "no terminal to ask and --yes was not given",
        ),
    ] {
        harness.console.answers.push_back(answer);
        let outcome = harness.run(&args);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stderr, format!("mooringctl: not recorded: {why}\n"));
        assert!(outcome.stdout.starts_with("node lon1: planned, host key "));
        assert_eq!(state_bytes(&harness), before);
    }
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&args);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(harness.console.asked, ["Pin the new host key?"; 3]);
    assert_eq!(
        store(&harness).load().unwrap().deployment.nodes()[&node_id("lon1")]
            .ssh
            .host_ed25519,
        key
    );
}

/// An unknown node and one past `Planned` are refused before the key file
/// is read, so a missing file is not what is reported.
#[test]
fn repin_refuses_an_unknown_node_or_one_past_planned_before_reading_the_key() {
    let (mut harness, _) = planned();
    let missing = harness.home.path().join("missing.pub");
    let outcome = harness.run(&[
        "node",
        "repin",
        "zzz1",
        "--host-key",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, "mooringctl: unknown node zzz1\n");
    let mut applied = harness_with(fixture(|_| {}));
    let before = state_bytes(&applied);
    let outcome = applied.run(&[
        "node",
        "repin",
        "lon1",
        "--host-key",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: node lon1 is Applied; only a planned node is re-pinned\n"
    );
    assert_eq!(state_bytes(&applied), before);
}

#[test]
fn repin_to_the_key_already_pinned_writes_nothing_and_asks_nothing() {
    let (mut harness, pinned) = planned();
    let before = state_bytes(&harness);
    let path = harness.home.path().join("lon1_host.pub");
    let outcome = harness.run(&[
        "node",
        "repin",
        "lon1",
        "--host-key",
        path.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "node lon1 pins host key {} already; nothing was written\n",
            fingerprint(pinned)
        )
    );
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.console.asked.is_empty());
}

/// A file that holds no single Ed25519 key line, or is no regular file, is
/// refused naming it, and the state stays as it was. A FIFO does not hold
/// the command, and a private key's lines are never echoed.
#[test]
fn repin_refuses_a_file_that_holds_no_single_host_key() {
    let (mut harness, _) = planned();
    let before = state_bytes(&harness);
    let (good, key) = host_key_file(&harness, "good.pub");
    let line = fs::read_to_string(&good).unwrap();
    let (other, _) = host_key_file(&harness, "other.pub");
    let two = format!("{line}{}", fs::read_to_string(&other).unwrap());
    let known_hosts = format!("{ADDRESS} {}\n", key.ssh_authorized_key());
    let private = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    let long = format!("{} {}\n", key.ssh_authorized_key(), "c".repeat(4096));
    let malformed: [(&str, &[u8]); 7] = [
        ("rsa.pub", b"ssh-rsa AAAAB3NzaC1yc2E root@lon1\n"),
        ("empty.pub", b""),
        ("one-word.pub", b"ssh-ed25519\n"),
        ("known_hosts", known_hosts.as_bytes()),
        ("two.pub", two.as_bytes()),
        ("id_ed25519", private.as_bytes()),
        ("long.pub", long.as_bytes()),
    ];
    for (name, bytes) in malformed {
        let path = harness.home.path().join(name);
        fs::write(&path, bytes).unwrap();
        let outcome = harness.run(&[
            "node",
            "repin",
            "lon1",
            "--host-key",
            path.to_str().unwrap(),
        ]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{name}");
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: {} does not hold exactly one Ed25519 host key as OpenSSH writes it (`ssh-ed25519 <base64> [comment]`, one line)\n",
                path.display()
            ),
            "{name}"
        );
        assert!(!outcome.stderr.contains("b3BlbnNzaC1rZXktdjEAAAAA"));
        assert_eq!(state_bytes(&harness), before, "{name}");
    }
    let fifo = harness.home.path().join("fifo.pub");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    for path in [harness.home.path().to_path_buf(), fifo] {
        let outcome = harness.run(&[
            "node",
            "repin",
            "lon1",
            "--host-key",
            path.to_str().unwrap(),
        ]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: {} is not a regular file; give the host key's .pub file\n",
                path.display()
            )
        );
    }
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.console.asked.is_empty());
}

/// After an adoption that ran `Bootstrap`, a re-pin replaces the key
/// `Bootstrap` made and changes no file of the node's; the next adoption
/// writes `known_hosts` from the new pin and checks the host against it.
#[test]
fn repin_after_a_partial_adoption_is_the_key_the_next_adoption_checks() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    let known_hosts = fs::read(dir.join("known_hosts")).unwrap();
    let ops = fs::read(dir.join("ops_ed25519.pub")).unwrap();
    let (path, key) = host_key_file(&harness, "reinstalled.pub");
    let outcome = harness.run(&[
        "node",
        "repin",
        "lon1",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains(
            "`node adopt lon1` ran on this Mac: if its Bootstrap ran and the VPS was not reinstalled since, the only key to pin is the one Bootstrap made (adoption pins it itself, or says that it could not), and `node adopt lon1 --resume` goes on from there; after a reinstall, pin the reinstalled VPS's key and adopt it with --root-identity\n"
        ),
        "{}",
        outcome.stdout
    );
    let deployment = store(&harness).load().unwrap().deployment;
    assert_eq!(deployment.config_generation().get(), 4);
    assert_eq!(deployment.nodes()[&node_id("lon1")].ssh.host_ed25519, key);
    assert_eq!(fs::read(dir.join("known_hosts")).unwrap(), known_hosts);
    assert_eq!(fs::read(dir.join("ops_ed25519.pub")).unwrap(), ops);
    assert!(
        harness
            .secrets
            .get(&SecretRef::NodeSshBootstrapPrivate(node_id("lon1")))
            .is_ok()
    );
    harness.nodes.expect(
        Expected::Empty {
            identity: "ops_ed25519",
            command: "true",
        },
        Answered::Replied(Err(NodeError::Ssh {
            code: Some(255),
            stderr: "Host key verification failed.".to_owned(),
        })),
    );
    let agent = agent_file(&harness);
    let outcome = harness.run(&adopt_args(agent.to_str().unwrap(), None));
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: adoption stopped at the operations key's forced command\n"),
        "{}",
        outcome.stderr
    );
    assert_eq!(
        fs::read_to_string(dir.join("known_hosts")).unwrap(),
        format!(
            "{}\n",
            SshPublicKey::from(key).known_hosts_line(ADDRESS.parse().unwrap())
        )
    );
}

/// The pin finds the node again under the lock: a cancel in between keeps
/// the generation, so the compare-and-swap passes, and the pin refuses the
/// node gone; a node past `Planned` is refused the same way.
#[test]
fn the_pin_refuses_a_node_cancelled_or_past_planned_since_it_was_read() {
    let (mut harness, _) = planned();
    let store = store(&harness);
    let generation = store.load().unwrap().deployment.config_generation();
    record_with_secrets(
        &store,
        &mut harness.secrets,
        generation,
        Bookkeeping::PlanCancelled {
            node: node_id("lon1"),
        },
    )
    .unwrap();
    let before = state_bytes(&harness);
    let (_, key) = host_key_file(&harness, "late.pub");
    let error = pin_in_state(
        &store,
        &node_id("lon1"),
        generation,
        key,
        PlannedAction::Repinned,
    )
    .unwrap_err();
    assert!(
        matches!(&error, LocalError::UnknownNode { node } if *node == node_id("lon1")),
        "{error:?}"
    );
    assert_eq!(state_bytes(&harness), before);
    let applied = harness_with(fixture(|_| {}));
    let store = super::user::store(&applied);
    let before = state_bytes(&applied);
    let generation = store.load().unwrap().deployment.config_generation();
    let error = pin_in_state(
        &store,
        &node_id("lon1"),
        generation,
        key,
        PlannedAction::Repinned,
    )
    .unwrap_err();
    assert!(
        matches!(
            &error,
            LocalError::NodeNotPlanned { node, stage: LifecycleStage::Applied, action: PlannedAction::Repinned }
                if *node == node_id("lon1")
        ),
        "{error:?}"
    );
    assert_eq!(state_bytes(&applied), before);
}

/// A re-pin neither reads nor writes the keychain.
#[test]
fn repin_reads_and_writes_no_secret() {
    let (mut harness, _) = planned();
    *harness.keychain.lock().unwrap() = Refusals {
        get: Some(-25_308),
        put: Some(-25_308),
        delete: Some(-25_308),
    };
    let (path, key) = host_key_file(&harness, "reinstalled.pub");
    let outcome = harness.run(&[
        "node",
        "repin",
        "lon1",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        store(&harness).load().unwrap().deployment.nodes()[&node_id("lon1")]
            .ssh
            .host_ed25519,
        key
    );
}

/// A pin that cannot be committed leaves the state as it was, and says so.
#[test]
fn a_repin_that_cannot_be_committed_leaves_the_pin() {
    let (mut harness, _) = planned();
    let before = state_bytes(&harness);
    let stale = harness.support_dir().join("state.json.tmp");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("keep"), b"").unwrap();
    let (path, _) = host_key_file(&harness, "new.pub");
    let outcome = harness.run(&[
        "node",
        "repin",
        "lon1",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state was not changed\n"),
        "{}",
        outcome.stderr
    );
    assert!(
        !outcome.stdout.contains("re-pinned node"),
        "{}",
        outcome.stdout
    );
    assert_eq!(state_bytes(&harness), before);
}

/// What the re-pin says before it commits is written first, so output that
/// fails there pins nothing, whether or not the lines after it could be
/// written; output that fails after the commit leaves the new pin. The
/// key already pinned has one line to write, and no commit.
#[test]
fn output_that_fails_before_the_commit_pins_nothing_and_after_it_keeps_the_pin() {
    let failed = |harness: &mut Harness, file: &str, mut out: FailingLog| {
        let mut err = Vec::new();
        let code = harness.run_to(
            &["node", "repin", "lon1", "--host-key", file, "--yes"],
            &mut out,
            &mut err,
        );
        assert_eq!(code, EXIT_LOCAL, "{out:?}");
        assert!(out.failed(), "{out:?}");
        let report = String::from_utf8(err).unwrap();
        assert!(
            report.starts_with("mooringctl: writing the output failed\n"),
            "{out:?}: {report}"
        );
    };
    // The first line is the last before the commit on a node no adoption
    // touched, and the adoption's note is the last after one.
    let fresh: fn() -> (Harness, Ed25519Pub) = planned;
    for (needle, harness, committed) in [
        ("is no check", fresh, false),
        ("is no check", partially_adopted, false),
        ("ran on this Mac", partially_adopted, false),
        ("re-pinned node", fresh, true),
    ] {
        for out in [FailingLog::at(needle), FailingLog::only_at(needle)] {
            let (mut harness, _) = harness();
            let before = state_bytes(&harness);
            let (path, key) = host_key_file(&harness, "new.pub");
            failed(&mut harness, path.to_str().unwrap(), out);
            let deployment = store(&harness).load().unwrap().deployment;
            assert_eq!(
                deployment.nodes()[&node_id("lon1")].ssh.host_ed25519 == key,
                committed,
                "{needle}"
            );
            assert_eq!(state_bytes(&harness) == before, !committed, "{needle}");
        }
    }
    let (mut harness, _) = planned();
    let before = state_bytes(&harness);
    let pinned = harness.home.path().join("lon1_host.pub");
    failed(
        &mut harness,
        pinned.to_str().unwrap(),
        FailingLog::at("nothing was written"),
    );
    assert_eq!(state_bytes(&harness), before);
}
