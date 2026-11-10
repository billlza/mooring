// SPDX-License-Identifier: GPL-3.0-or-later

//! `node cancel` (design §13.2) against the harness's support directory: a
//! planned node leaves the state with every credential on it while the
//! generation stays, its keychain items go after the commit and its ssh
//! files after them, and anything else is refused before the question. An
//! adoption whose node is cancelled meanwhile stops instead of writing an
//! empty change.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{RequestKind, Response, SshEd25519Key};
use mooring_export::{ExportFormat, export_user};
use mooring_keys::{SshKeyPair, SshPublicKey};
use mooring_model::deployment::Bookkeeping;
use mooring_model::node::NodeLifecycle;
use mooring_model::secret::{SecretEntry, SecretRef};
use mooring_model::{AlertSettings, Ed25519Pub, NodeId, UnixTime, UserStatus};
use mooring_store::{InMemorySecretStore, SecretStore, Store, StoreError, record_with_secrets};

use super::export::exporting;
use super::node::{
    adopt_args, agent_file, host_key_file, planned, root_key, script_after_bootstrap,
};
use super::support::{Answered, Expected, ExpectedRemote, FailingLog, Harness, NOW, Refusals};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;
use crate::prompt::Answer;

fn node_id(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// `ssh/lon1` in the harness's support directory.
pub(crate) fn lon1_dir(harness: &Harness) -> PathBuf {
    harness.support_dir().join("ssh").join("lon1")
}

/// A fresh Ed25519 host key.
pub(crate) fn new_host_key() -> Ed25519Pub {
    let (_, public) = SshKeyPair::generate().unwrap().into_parts();
    Ed25519Pub::parse_ssh_authorized_key(&public.authorized_key()).unwrap()
}

/// Scripts an upload and a `Bootstrap` that makes `host`.
pub(crate) fn script_bootstrap(harness: &Harness, host: &Ed25519Pub) {
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
        Answered::Replied(Ok(Response::BootstrapDone {
            host_pubkey: SshEd25519Key::new(host.ssh_authorized_key()).unwrap(),
        })),
    );
}

/// Runs `node adopt lon1` with the operator's root key.
pub(crate) fn adopt(harness: &mut Harness) -> super::support::Outcome {
    let agent = agent_file(harness);
    let root = root_key(harness);
    harness.run(&adopt_args(
        agent.to_str().unwrap(),
        Some(root.to_str().unwrap()),
    ))
}

/// `planned()` after an adoption that ran `Bootstrap` and stopped at the
/// forced-command check: the state pins the key `Bootstrap` made, which is
/// returned, at generation 3; the bootstrap key is still in the keychain;
/// and `ssh/lon1/` holds the bootstrap and operations keys and
/// `known_hosts`.
pub(crate) fn partially_adopted() -> (Harness, Ed25519Pub) {
    let (mut harness, _) = planned();
    let bootstrapped = new_host_key();
    script_bootstrap(&harness, &bootstrapped);
    harness.nodes.expect(
        Expected::Empty {
            identity: "ops_ed25519",
            command: "true",
        },
        Answered::Replied(Err(NodeError::Ssh {
            code: Some(0),
            stderr: String::new(),
        })),
    );
    let outcome = adopt(&mut harness);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stderr);
    assert!(
        outcome.stderr.contains("forced command is not active"),
        "{}",
        outcome.stderr
    );
    let deployment = store(&harness).load().unwrap().deployment;
    assert_eq!(deployment.config_generation().get(), 3);
    assert_eq!(
        deployment.nodes()[&node_id("lon1")].ssh.host_ed25519,
        bootstrapped
    );
    assert_eq!(
        names(&lon1_dir(&harness)),
        [
            "bootstrap_ed25519",
            "known_hosts",
            "ops_ed25519",
            "ops_ed25519.pub"
        ]
    );
    (harness, bootstrapped)
}

/// The entries of `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The entries of `dir` with their bytes, sorted.
fn contents(dir: &Path) -> Vec<(String, Vec<u8>)> {
    names(dir)
        .into_iter()
        .map(|name| {
            let bytes = fs::read(dir.join(&name)).unwrap();
            (name, bytes)
        })
        .collect()
}

#[test]
fn cancel_removes_a_planned_node_with_its_keys_and_keeps_the_generation() {
    let (mut harness, pinned) = planned();
    let before = store(&harness).load().unwrap().deployment;
    assert!(!harness.secrets.is_empty());
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        format!(
            "node lon1: planned, tunnel 10.77.1.0/30, host key {} pinned; users with credentials on it: none\n\
             cancelling removes it from the state and deletes its keys, and those users' credentials on it, from the keychain; no VPS is contacted\n\
             cancelled node lon1: the configuration generation stays 2, so the cancel needs no `node apply`, and the id may be planned again\n",
            SshPublicKey::from(pinned).fingerprint()
        )
    );
    let after = store(&harness).load().unwrap().deployment;
    assert!(after.nodes().is_empty());
    assert_eq!(after.config_generation(), before.config_generation());
    assert_eq!(after.next_wg_index(), before.next_wg_index());
    assert!(harness.secrets.is_empty());
    assert!(harness.console.asked.is_empty());
    assert!(!lon1_dir(&harness).exists());
}

#[test]
fn cancel_asks_first_and_a_declined_or_unanswerable_cancel_changes_nothing() {
    let (mut harness, _) = planned();
    let before = state_bytes(&harness);
    let refs = harness.secrets.refs();
    for (answer, why) in [
        (Answer::No, "the answer was not yes"),
        (
            Answer::NoTerminal,
            "no terminal to ask and --yes was not given",
        ),
    ] {
        harness.console.answers.push_back(answer);
        let outcome = harness.run(&["node", "cancel", "lon1"]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stderr, format!("mooringctl: not recorded: {why}\n"));
        assert!(
            outcome
                .stdout
                .starts_with("node lon1: planned, tunnel 10.77.1.0/30, "),
            "{}",
            outcome.stdout
        );
        assert!(!outcome.stdout.contains("cancelled node"));
        assert_eq!(state_bytes(&harness), before);
        assert_eq!(harness.secrets.refs(), refs);
    }
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(harness.console.asked, ["Cancel this planned node?"; 3]);
    assert!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .nodes()
            .is_empty()
    );
}

/// An unknown node and one past `Planned` are refused before anything is
/// asked or written; the harness's console panics if asked.
#[test]
fn cancel_refuses_an_unknown_node_and_one_past_planned_before_asking() {
    let (mut harness, _) = planned();
    let before = state_bytes(&harness);
    let outcome = harness.run(&["node", "cancel", "zzz1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, "mooringctl: unknown node zzz1\n");
    assert_eq!(outcome.stdout, "");
    assert_eq!(state_bytes(&harness), before);
    let adopted = fixture(|parts| {
        let lon1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id("lon1"))
            .unwrap();
        let site = lon1.lifecycle.site().unwrap().clone();
        lon1.lifecycle = NodeLifecycle::Adopted { site };
    });
    for (deployment, stage) in [(adopted, "Adopted"), (fixture(|_| {}), "Applied")] {
        let mut harness = harness_with(deployment);
        let before = state_bytes(&harness);
        let outcome = harness.run(&["node", "cancel", "lon1"]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(
            outcome.stderr,
            format!("mooringctl: node lon1 is {stage}; only a planned node is cancelled\n")
        );
        assert_eq!(state_bytes(&harness), before);
        assert!(harness.console.asked.is_empty());
    }
}

#[test]
fn cancel_after_a_partial_adoption_deletes_the_bootstrap_key_and_the_node_files() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    let ops = fs::read(dir.join("ops_ed25519.pub")).unwrap();
    assert!(
        harness
            .secrets
            .get(&SecretRef::NodeSshBootstrapPrivate(node_id("lon1")))
            .is_ok()
    );
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    for line in [
        format!(
            "from the keychain, then {}; no VPS is contacted\n",
            dir.display()
        ),
        "`node adopt lon1` ran on this Mac: if its Bootstrap ran, the VPS lets in only the Mooring keys this deletes, not your own root key, so reinstall it or delete it from the provider's console\n".to_owned(),
        "the configuration generation stays 3".to_owned(),
    ] {
        assert!(outcome.stdout.contains(&line), "{}", outcome.stdout);
    }
    assert!(!dir.exists());
    assert!(harness.support_dir().join("ssh").is_dir());
    assert!(harness.secrets.is_empty());
    assert_eq!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .config_generation()
            .get(),
        3
    );
    // Planned again, the id's next adoption makes a new operations key.
    let (path, _) = host_key_file(&harness, "again.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
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
    assert_eq!(adopt(&mut harness).code, EXIT_LOCAL);
    assert_ne!(fs::read(dir.join("ops_ed25519.pub")).unwrap(), ops);
}

/// The fixture's lon1 alone, applied, with par1 planned beside it through
/// `node new`: the plan moved the generation on, so lon1 is behind it.
fn planned_par1_beside_applied_lon1() -> Harness {
    let lon1_only = fixture(|parts| {
        parts.nodes.retain(|node| node.id == node_id("lon1"));
        for user in &mut parts.users {
            user.per_node.retain(|node, _| *node == node_id("lon1"));
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
    harness
}

/// The users' credentials on the cancelled node go from the state and the
/// keychain; their credentials on the other node stay.
#[test]
fn cancel_deletes_the_users_credentials_on_the_node_and_keeps_the_rest() {
    let mut harness = planned_par1_beside_applied_lon1();
    let users: Vec<String> = store(&harness)
        .load()
        .unwrap()
        .deployment
        .users()
        .keys()
        .map(|user| user.as_str().to_owned())
        .collect();
    let lon1_refs: Vec<SecretRef> = harness
        .secrets
        .refs()
        .into_iter()
        .filter(|secret_ref| secret_ref.node() == Some(&node_id("lon1")))
        .collect();
    let generation = store(&harness)
        .load()
        .unwrap()
        .deployment
        .config_generation()
        .get();
    let outcome = harness.run(&["node", "cancel", "par1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .starts_with("node par1: planned, tunnel 10.77.3.0/30, host key "),
        "{}",
        outcome.stdout
    );
    // The plan bumped the generation, so lon1 is behind it, whatever the
    // cancel does: that is named.
    for line in [
        format!("users with credentials on it: {}\n", users.join(", ")),
        format!(
            "applied nodes behind generation {generation} since an earlier change: lon1; `node apply` them before exporting users\n"
        ),
    ] {
        assert!(outcome.stdout.contains(&line), "{}", outcome.stdout);
    }
    let after = store(&harness).load().unwrap().deployment;
    for user in after.users().values() {
        let held: Vec<&str> = user.per_node.keys().map(NodeId::as_str).collect();
        assert_eq!(held, ["lon1"], "{}", user.id);
    }
    assert!(
        harness
            .secrets
            .refs()
            .iter()
            .all(|secret_ref| secret_ref.node() != Some(&node_id("par1")))
    );
    for secret_ref in lon1_refs {
        assert!(harness.secrets.get(&secret_ref).is_ok(), "{secret_ref}");
    }
}

/// The question names what the cancel settles besides the node: the
/// revocations that wait only on it, and its alert channels. Declined, it
/// changes nothing.
#[test]
fn cancel_names_the_revocations_it_settles_and_the_alert_channels_it_drops() {
    let (mut harness, third) = planned_ams1_with_a_revocation_and_channels();
    let before = state_bytes(&harness);
    harness.console.answers.push_back(Answer::No);
    let outcome = harness.run(&["node", "cancel", "ams1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    for line in [
        format!("revoked once it is gone, since their revocation waits only on it: {third}\n"),
        "its alert channels go with it\n".to_owned(),
    ] {
        assert!(outcome.stdout.contains(&line), "{}", outcome.stdout);
    }
    assert_eq!(state_bytes(&harness), before);
}

/// The fixture with ams1 planned, a revocation that waits only on it (the
/// third user's, whose id is returned) and its alert channels.
fn planned_ams1_with_a_revocation_and_channels() -> (Harness, String) {
    let deployment = fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
        // The third user's revocation waits only on ams1, the second's on
        // lon1 too.
        for (index, nodes) in [(1, &["lon1", "ams1"][..]), (2, &["ams1"][..])] {
            let user = &mut parts.users[index];
            user.per_node
                .retain(|node, _| nodes.contains(&node.as_str()));
            user.status = UserStatus::RevokePending;
        }
        parts.alerting = Some(AlertSettings {
            channels: [node_id("ams1")].into_iter().collect(),
            ..AlertSettings::pilot()
        });
    });
    let third = deployment.users().keys().nth(2).unwrap().to_string();
    (harness_with(deployment), third)
}

/// Everything the cancel says before it commits is written before the
/// commit. Output that fails at any of those lines stops it, whether or
/// not the lines after it could be written: the state, the keychain and
/// the node's files are as they were.
#[test]
fn output_that_fails_before_the_commit_cancels_nothing() {
    for needle in [
        "users with credentials on it",
        "revoked once it is gone",
        "its alert channels go with it",
        "cancelling removes it from the state",
        "ran on this Mac",
    ] {
        for mut out in [FailingLog::at(needle), FailingLog::only_at(needle)] {
            let (mut harness, _) = planned_ams1_with_a_revocation_and_channels();
            let dir = harness.support_dir().join("ssh").join("ams1");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("known_hosts"), b"pinned\n").unwrap();
            let before = state_bytes(&harness);
            let refs = harness.secrets.refs();
            let mut err = Vec::new();
            let code = harness.run_to(&["node", "cancel", "ams1", "--yes"], &mut out, &mut err);
            assert_eq!(code, EXIT_LOCAL, "{out:?}");
            assert!(out.failed(), "{out:?}");
            let report = String::from_utf8(err).unwrap();
            assert!(
                report.starts_with("mooringctl: writing the output failed\n"),
                "{out:?}: {report}"
            );
            assert_eq!(state_bytes(&harness), before, "{out:?}");
            assert_eq!(harness.secrets.refs(), refs, "{out:?}");
            assert_eq!(
                fs::read(dir.join("known_hosts")).unwrap(),
                b"pinned\n",
                "{out:?}"
            );
        }
    }
}

/// A commit that fails leaves everything as it was: the files are only
/// touched after the state no longer names the node.
#[test]
fn a_cancel_that_cannot_be_committed_deletes_no_key_and_no_file() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    let files = contents(&dir);
    let refs = harness.secrets.refs();
    let before = state_bytes(&harness);
    let stale = harness.support_dir().join("state.json.tmp");
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("keep"), b"").unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the state was not changed\n"),
        "{}",
        outcome.stderr
    );
    assert!(!outcome.stdout.contains("cancelled node"));
    assert_eq!(state_bytes(&harness), before);
    assert_eq!(harness.secrets.refs(), refs);
    assert_eq!(contents(&dir), files);
}

/// Keychain deletions that fail after the commit leave the node cancelled:
/// its files go all the same, the failure says the change is committed,
/// and a later plan of the id replaces the orphaned items.
#[test]
fn a_failed_keychain_deletion_is_reported_and_the_files_still_go() {
    let (mut harness, _) = partially_adopted();
    let refs = harness.secrets.refs();
    let reality = SecretRef::NodeRealityPrivate(node_id("lon1"));
    let old = harness.secrets.get(&reality).unwrap();
    *harness.keychain.lock().unwrap() = Refusals {
        delete: Some(-25_308),
        ..Refusals::default()
    };
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stdout.contains("cancelled node lon1: "),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stderr.lines().next().unwrap(),
        "mooringctl: the change is committed, but some keychain items it no longer references could not be deleted; nothing uses them, and they can be deleted by hand"
    );
    assert!(
        outcome
            .stderr
            .contains("state committed at config generation 3, but deleting secrets failed"),
        "{}",
        outcome.stderr
    );
    assert!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .nodes()
            .is_empty()
    );
    assert!(!lon1_dir(&harness).exists());
    assert_eq!(harness.secrets.refs(), refs, "every deletion was refused");
    *harness.keychain.lock().unwrap() = Refusals::default();
    let (path, _) = host_key_file(&harness, "again.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_ne!(harness.secrets.get(&reality).unwrap(), old);
}

/// When the keychain deletions and the directory's removal both fail after
/// the commit, the node is cancelled all the same: the directory is named
/// on the output, and the failure reported is the keychain's, as
/// committed.
#[test]
fn a_cancel_whose_keychain_deletions_and_file_removal_both_fail_names_both() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    *harness.keychain.lock().unwrap() = Refusals {
        delete: Some(-25_308),
        ..Refusals::default()
    };
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stdout.contains("cancelled node lon1: "),
        "{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.ends_with(&format!(
            "{} could not be removed (Permission denied (os error 13)); remove it by hand, or `node new lon1` refuses\n",
            dir.display()
        )),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stderr.lines().next().unwrap(),
        "mooringctl: the change is committed, but some keychain items it no longer references could not be deleted; nothing uses them, and they can be deleted by hand"
    );
    assert!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .nodes()
            .is_empty()
    );
    assert_eq!(names(&dir).len(), 4, "nothing could be removed");
}

/// Output that fails after the commit leaves the node cancelled and its
/// files removed: the failure is the output's.
#[test]
fn output_that_fails_after_the_commit_leaves_the_node_cancelled() {
    let cancelled = |harness: &mut Harness, node: &str, needle: &'static str| {
        let mut out = FailingLog::at(needle);
        let mut err = Vec::new();
        let code = harness.run_to(&["node", "cancel", node, "--yes"], &mut out, &mut err);
        assert_eq!(code, EXIT_LOCAL, "{needle}");
        assert!(out.failed(), "{needle}");
        let report = String::from_utf8(err).unwrap();
        assert!(
            report.starts_with("mooringctl: writing the output failed\n"),
            "{needle}: {report}"
        );
        let deployment = store(harness).load().unwrap().deployment;
        assert!(!deployment.nodes().contains_key(&node_id(node)), "{needle}");
    };
    let (mut harness, _) = partially_adopted();
    cancelled(&mut harness, "lon1", "cancelled node");
    assert!(!lon1_dir(&harness).exists());
    assert!(harness.secrets.is_empty());
    let mut harness = planned_par1_beside_applied_lon1();
    cancelled(&mut harness, "par1", "behind generation");
}

/// A node directory that cannot be examined or listed is a failure, not an
/// absent or an empty one: the cancel stops before the question, and
/// `node new` does not take an id whose directory it cannot rule out.
#[test]
fn a_node_directory_that_cannot_be_examined_stops_cancel_and_new() {
    let (mut harness, _) = planned();
    let ssh = harness.support_dir().join("ssh");
    let before = state_bytes(&harness);
    // `ssh` is a file, so nothing under it can be examined.
    fs::write(&ssh, b"").unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: cannot use {}\n  caused by: Not a directory (os error 20)\n",
            ssh.join("lon1").display()
        )
    );
    assert_eq!(outcome.stdout, "");
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
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: cannot use {}\n  caused by: Not a directory (os error 20)\n",
            ssh.join("par1").display()
        )
    );
    fs::remove_file(&ssh).unwrap();
    // The directory is there, but cannot be listed.
    let dir = ssh.join("lon1");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o300)).unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: cannot use {}\n  caused by: Permission denied (os error 13)\n",
            dir.display()
        )
    );
    assert_eq!(state_bytes(&harness), before);
    assert!(harness.console.asked.is_empty());
}

/// A directory that cannot be emptied after the commit is named, and
/// `node new` refuses the id while it is there.
#[test]
fn node_files_that_cannot_be_removed_after_the_commit_are_named() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed; remove it by hand, or `node new lon1` refuses\n  caused by: Permission denied (os error 13)\n",
            dir.display()
        )
    );
    assert!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .nodes()
            .is_empty()
    );
    assert!(harness.secrets.is_empty());
    let (path, _) = host_key_file(&harness, "again.pub");
    let before = state_bytes(&harness);
    let outcome = harness.run(&[
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: {} exists already: it holds the ssh files of an earlier node with this id; remove it, then plan the node again\n",
            dir.display()
        )
    );
    assert_eq!(state_bytes(&harness), before);
}

/// Nothing Mooring does not keep for the node is removed, or followed:
/// it is refused before the question, and another node's directory stays.
#[test]
fn cancel_refuses_what_mooring_does_not_keep_for_the_node_before_asking() {
    let (mut harness, _) = planned();
    let ssh = harness.support_dir().join("ssh");
    let dir = ssh.join("lon1");
    let before = state_bytes(&harness);
    let refused = |harness: &mut Harness, path: &Path| {
        let outcome = harness.run(&["node", "cancel", "lon1"]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: {} is not what Mooring keeps for the node; move it away, then cancel the node again\n",
                path.display()
            )
        );
        assert_eq!(outcome.stdout, "");
    };
    let outside = harness.home.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("known_hosts"), b"kept\n").unwrap();
    fs::create_dir_all(&ssh).unwrap();
    symlink(&outside, &dir).unwrap();
    refused(&mut harness, &dir);
    fs::remove_file(&dir).unwrap();
    fs::write(&dir, b"").unwrap();
    refused(&mut harness, &dir);
    fs::remove_file(&dir).unwrap();
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("notes.txt"), b"mine\n").unwrap();
    refused(&mut harness, &dir.join("notes.txt"));
    fs::remove_file(dir.join("notes.txt")).unwrap();
    fs::create_dir(dir.join("known_hosts")).unwrap();
    refused(&mut harness, &dir.join("known_hosts"));
    fs::remove_dir(dir.join("known_hosts")).unwrap();
    fs::write(dir.join("relay-1-0.sock"), b"").unwrap();
    refused(&mut harness, &dir.join("relay-1-0.sock"));
    fs::remove_file(dir.join("relay-1-0.sock")).unwrap();
    // A socket is Mooring's only under a relay socket's whole name.
    for name in ["other.sock", "relay-1-0"] {
        let bound = harness.home.path().join("s.sock");
        drop(UnixListener::bind(&bound).unwrap());
        fs::rename(&bound, dir.join(name)).unwrap();
        refused(&mut harness, &dir.join(name));
        fs::remove_file(dir.join(name)).unwrap();
    }
    assert_eq!(state_bytes(&harness), before);
    assert_eq!(fs::read(outside.join("known_hosts")).unwrap(), b"kept\n");
    assert!(harness.console.asked.is_empty());
    // A relay socket a session left behind is Mooring's, and goes with the
    // directory; another node's directory stays. (The socket is bound at a
    // shorter path, within the limit on a socket's path, and moved there.)
    let bound = harness.home.path().join("r.sock");
    drop(UnixListener::bind(&bound).unwrap());
    fs::rename(&bound, dir.join("relay-1-0.sock")).unwrap();
    let ams1 = ssh.join("ams1");
    fs::create_dir(&ams1).unwrap();
    fs::write(ams1.join("keep"), b"").unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(!dir.exists());
    assert!(ams1.join("keep").exists());
}

#[test]
fn a_cancelled_id_is_planned_again_on_a_new_tunnel_with_new_keys() {
    let (mut harness, _) = planned();
    let first = store(&harness).load().unwrap().deployment.nodes()[&node_id("lon1")].clone();
    let reality = SecretRef::NodeRealityPrivate(node_id("lon1"));
    let old = harness.secrets.get(&reality).unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let (path, _) = host_key_file(&harness, "again.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "lon1",
        "--role",
        "primary",
        "--host-key",
        path.to_str().unwrap(),
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .starts_with("node lon1: primary, tunnel 10.77.2.0/30, "),
        "{}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    let again = &after.nodes()[&node_id("lon1")];
    assert_eq!(again.wg_index.get(), 2);
    assert_eq!(after.next_wg_index().get(), 3);
    assert_ne!(again.reality.public_key, first.reality.public_key);
    assert_ne!(harness.secrets.get(&reality).unwrap(), old);
    assert_eq!(after.config_generation().get(), 3);
}

/// A planned node counts towards the node limit until it is cancelled.
#[test]
fn cancelling_a_planned_node_frees_its_place() {
    let (mut harness, _) = planned();
    let plan = |harness: &mut Harness, id: &str| {
        let (path, _) = host_key_file(harness, &format!("{id}.pub"));
        harness.run(&[
            "node",
            "new",
            id,
            "--role",
            "standby",
            "--host-key",
            path.to_str().unwrap(),
            "--yes",
        ])
    };
    assert_eq!(plan(&mut harness, "ams1").code, 0);
    let refused = plan(&mut harness, "par1");
    assert_eq!(refused.code, EXIT_LOCAL);
    assert!(
        refused
            .stderr
            .contains("at most 2 active nodes are supported"),
        "{}",
        refused.stderr
    );
    let outcome = harness.run(&["node", "cancel", "ams1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(plan(&mut harness, "par1").code, 0);
}

/// While a user holds credentials on a planned node, no export of it can
/// be made; cancelling the node keeps the generation, so the export can be
/// made at once, without another apply.
#[test]
fn cancelling_a_planned_node_lets_its_users_be_exported_without_an_apply() {
    let deployment = fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
    });
    let (mut harness, folder) = exporting(deployment);
    let (seed, _) = SshKeyPair::generate().unwrap().into_parts();
    harness
        .secrets
        .put(SecretEntry::NodeSshBootstrapPrivate(node_id("ams1"), seed))
        .unwrap();
    let user = store(&harness)
        .load()
        .unwrap()
        .deployment
        .users()
        .keys()
        .next()
        .unwrap()
        .clone();
    let out = folder.join("user.json");
    let args = [
        "user",
        "export",
        user.as_str(),
        "--out",
        out.to_str().unwrap(),
    ];
    let refused = harness.run(&args);
    assert_eq!(refused.code, EXIT_LOCAL);
    assert!(refused.stderr.contains("ams1"), "{}", refused.stderr);
    let generation = store(&harness)
        .load()
        .unwrap()
        .deployment
        .config_generation();
    let outcome = harness.run(&["node", "cancel", "ams1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        !outcome.stdout.contains("behind generation"),
        "{}",
        outcome.stdout
    );
    let cancelled = store(&harness).load().unwrap().deployment;
    assert_eq!(cancelled.config_generation(), generation);
    let outcome = harness.run(&args);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let expected = export_user(
        &cancelled,
        &fixture.secrets,
        &user,
        ExportFormat::SingBoxJson,
        UnixTime::from_secs(NOW),
    )
    .unwrap();
    assert_eq!(fs::read(&out).unwrap(), expected.expose_bytes());
}

/// Another command cancels the node while `node adopt` runs. A cancel
/// keeps the generation, so adoption's compare-and-swap still passes: each
/// of its writes finds the node gone instead, and changes nothing. The
/// first of them, which records the key `Bootstrap` made, says that the
/// VPS holds that key by then.
#[test]
fn an_adoption_whose_node_is_cancelled_meanwhile_stops_and_writes_nothing() {
    for (steps_before, after_bootstrap) in [(0, false), (4, true)] {
        let (mut harness, _) = planned();
        let support = harness.support_dir();
        *harness.nodes.meanwhile.borrow_mut() = Some((
            steps_before,
            Box::new(move || {
                let store = Store::new(support);
                let generation = store.load().unwrap().deployment.config_generation();
                let cancelled = record_with_secrets(
                    &store,
                    &mut InMemorySecretStore::new(),
                    generation,
                    Bookkeeping::PlanCancelled {
                        node: node_id("lon1"),
                    },
                );
                // Its keychain is not this one: the commit stands.
                assert!(
                    matches!(cancelled, Err(StoreError::SecretCleanup { .. })),
                    "{cancelled:?}"
                );
            }),
        ));
        let bootstrapped = SshPublicKey::from(new_host_key());
        script_bootstrap(&harness, &bootstrapped.key());
        if after_bootstrap {
            script_after_bootstrap(&harness, 13);
        }
        let outcome = adopt(&mut harness);
        assert_eq!(outcome.code, EXIT_LOCAL);
        let expected = if after_bootstrap {
            "mooringctl: unknown node lon1\n".to_owned()
        } else {
            format!(
                "mooringctl: Bootstrap ran, so node lon1's VPS now holds host key {} and lets in only Mooring's keys, but that key was not recorded as the node's pin: if the node is still planned, save `{}` to a file, pin it with `node repin lon1 --host-key <file>`, then run `node adopt lon1 --resume`; if it was cancelled, reinstall the VPS or delete it from the provider's console\n  caused by: unknown node lon1\n",
                bootstrapped.fingerprint(),
                bootstrapped.authorized_key()
            )
        };
        assert_eq!(outcome.stderr, expected);
        assert!(
            !outcome.stdout.contains("adopted lon1"),
            "{}",
            outcome.stdout
        );
        assert_eq!(
            outcome.stdout.contains("bootstrapped lon1"),
            after_bootstrap,
            "{}",
            outcome.stdout
        );
        let after = store(&harness).load().unwrap().deployment;
        assert!(after.nodes().is_empty());
        let generation = if after_bootstrap { 3 } else { 2 };
        assert_eq!(after.config_generation().get(), generation);
        assert!(harness.nodes.script.borrow().is_empty());
    }
}
