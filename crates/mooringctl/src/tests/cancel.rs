// SPDX-License-Identifier: GPL-3.0-or-later

//! `node cancel` (design §13.2) against the harness's support directory: a
//! planned node leaves the state with every credential on it while the
//! generation stays, its keychain items go after the commit and its ssh
//! files after them, and anything else is refused before the question. An
//! adoption whose node is cancelled meanwhile stops instead of writing an
//! empty change.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{Generation, RequestKind, Response, SshEd25519Key};
use mooring_export::{ExportFormat, export_user};
use mooring_keys::{SshKeyPair, SshPublicKey};
use mooring_model::deployment::Bookkeeping;
use mooring_model::node::{AppliedConfig, NodeLifecycle};
use mooring_model::secret::{SecretEntry, SecretRef};
use mooring_model::{AlertSettings, Ed25519Pub, NodeId, SuspendReason, UnixTime, UserStatus};
use mooring_store::{InMemorySecretStore, SecretStore, Store, StoreError, record_with_secrets};

use super::apply::{
    apply_args, bundle_and_header, ready, run as apply_run, script_hello_and_blobs,
};
use super::export::exporting;
use super::node::{
    adopt_args, agent_file, host_key_file, planned, root_key, script_after_bootstrap,
};
use super::support::{
    Answered, COMMITTED, Expected, ExpectedRemote, FailingLog, Harness, MOVED, NOW, Refusals,
};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::error::EXIT_LOCAL;
use crate::node::NodeError;
use crate::node::files::NodeFiles;
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
        // Whatever its directory holds, the node is refused for its stage.
        let dir = lon1_dir(&harness);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("notes.txt"), b"mine\n").unwrap();
        let before = state_bytes(&harness);
        let outcome = harness.run(&["node", "cancel", "lon1"]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(
            outcome.stderr,
            format!("mooringctl: node lon1 is {stage}; only a planned node is cancelled\n")
        );
        assert_eq!(outcome.stdout, "");
        assert_eq!(state_bytes(&harness), before);
        assert!(harness.console.asked.is_empty());
        assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"mine\n");
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
    assert_eq!(after.users().len(), 3);
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
    assert!(!lon1_refs.is_empty());
    for secret_ref in lon1_refs {
        assert!(harness.secrets.get(&secret_ref).is_ok(), "{secret_ref}");
    }
}

/// The question names what the cancel settles besides the node: the
/// revocations that wait only on it, and its alert channels. Declined, it
/// changes nothing.
#[test]
fn cancel_names_the_revocations_it_settles_and_the_alert_channels_it_drops() {
    // The alert topic goes with the last node that has channels, and
    // stays while another has them.
    for (channels, alert_line) in [
        (
            &["ams1"][..],
            "its alert channels go with it, and the alert topic with them, as no other node has channels",
        ),
        (&["lon1", "ams1"][..], "its alert channels go with it"),
    ] {
        let (mut harness, third) = planned_ams1_with_a_revocation_and_channels(channels);
        let before = state_bytes(&harness);
        harness.console.answers.push_back(Answer::No);
        let outcome = harness.run(&["node", "cancel", "ams1"]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        let lines: Vec<&str> = outcome.stdout.lines().collect();
        assert_eq!(lines.len(), 4, "{}", outcome.stdout);
        assert_eq!(
            lines[1],
            format!("revoked once it is gone, since their revocation waits only on it: {third}")
        );
        assert_eq!(lines[2], alert_line);
        assert_eq!(state_bytes(&harness), before);
    }
}

/// The fixture with ams1 planned, a revocation that waits only on it (the
/// third user's, whose id is returned), and alert channels on `channels`.
fn planned_ams1_with_a_revocation_and_channels(channels: &[&str]) -> (Harness, String) {
    let deployment = fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
        // The first user was revoked before; the third user's revocation
        // waits only on ams1, the second's on lon1 too.
        parts.users[0].per_node.clear();
        parts.users[0].status = UserStatus::Revoked;
        for (index, nodes) in [(1, &["lon1", "ams1"][..]), (2, &["ams1"][..])] {
            let user = &mut parts.users[index];
            user.per_node
                .retain(|node, _| nodes.contains(&node.as_str()));
            user.status = UserStatus::RevokePending;
        }
        parts.alerting = Some(AlertSettings {
            channels: channels.iter().copied().map(node_id).collect(),
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
            let (mut harness, _) = planned_ams1_with_a_revocation_and_channels(&["ams1"]);
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
    assert_eq!(outcome.stderr.lines().next().unwrap(), COMMITTED);
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
/// the commit, the node is cancelled all the same, and one failure names
/// both: the directory that stays, with why, and the keychain items. The
/// directory stays because of a file that appeared in it while the
/// question waited, which the removal does not take, so no file mode is
/// involved.
#[test]
fn a_cancel_whose_keychain_items_and_files_both_stay_names_both() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    let refs = harness.secrets.refs();
    *harness.keychain.lock().unwrap() = Refusals {
        delete: Some(-25_308),
        ..Refusals::default()
    };
    let added = dir.join("added-since");
    harness.console.meanwhile = Some(Box::new(move || fs::write(added, b"").unwrap()));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    // The id is not said to be free while its directory stays.
    assert_eq!(
        outcome.stdout.lines().last().unwrap(),
        "cancelled node lon1: the configuration generation stays 3, so the cancel needs no `node apply`"
    );
    let mut report = outcome.stderr.lines();
    assert_eq!(
        report.next().unwrap(),
        format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed (Directory not empty (os error 66)); until it is removed, by `node cancel lon1` again or by hand, `node new lon1` refuses; deleting the keychain items the state no longer references failed too, for those named below; nothing uses them, and any that is still there can be deleted by hand",
            dir.display()
        )
    );
    assert!(
        report.next().unwrap().starts_with(
            "  caused by: state committed at config generation 3, but deleting secrets failed: "
        ),
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
    assert_eq!(harness.secrets.refs(), refs, "every deletion was refused");
    // Every entry the cancel listed went; what was added since stays.
    assert_eq!(names(&dir), ["added-since"]);
}

/// With the keychain's deletions done, a directory that stays is the
/// failure: here too because of a file added while the question waited.
#[test]
fn a_file_added_while_the_question_waited_keeps_the_directory_and_is_named() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    let added = dir.join("added-since");
    harness.console.meanwhile = Some(Box::new(move || fs::write(added, b"").unwrap()));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stdout.lines().last().unwrap(),
        "cancelled node lon1: the configuration generation stays 3, so the cancel needs no `node apply`"
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed; until it is removed, by `node cancel lon1` again or by hand, `node new lon1` refuses\n  caused by: Directory not empty (os error 66)\n",
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
    assert_eq!(names(&dir), ["added-since"]);
}

/// A directory that was not there when the cancel looked and is there when
/// the answer comes, as when an adoption started in another terminal
/// meanwhile, is not taken for gone. Nothing in it was examined, so it
/// stays and is the failure, the closing line does not call the id free,
/// and running the cancel again removes it after its own examination.
#[test]
fn a_directory_made_while_the_question_waited_is_kept_and_named() {
    let (mut harness, _) = planned();
    let dir = lon1_dir(&harness);
    assert!(!dir.exists());
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        // What `node adopt lon1` writes before it asks.
        let files = NodeFiles::of(&support, &node_id("lon1"));
        files.create_dir().unwrap();
        files.ops_public(&node_id("lon1")).unwrap();
    }));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
    assert_eq!(
        outcome.stdout.lines().last().unwrap(),
        "cancelled node lon1: the configuration generation stays 2, so the cancel needs no `node apply`"
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed; until it is removed, by `node cancel lon1` again or by hand, `node new lon1` refuses\n  caused by: Directory not empty (os error 66)\n",
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
    assert_eq!(names(&dir), ["ops_ed25519", "ops_ed25519.pub"]);

    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(!dir.exists());
}

/// What a cancel left behind after its commit is the failure reported even
/// when its closing lines cannot be written: the keychain items, or the
/// directory, not only that a write to standard output failed.
#[test]
fn a_cancel_whose_closing_line_cannot_be_written_still_reports_what_it_left() {
    let (mut harness, _) = partially_adopted();
    *harness.keychain.lock().unwrap() = Refusals {
        delete: Some(-25_308),
        ..Refusals::default()
    };
    let mut out = FailingLog::at("cancelled node");
    let mut err = Vec::new();
    let code = harness.run_to(&["node", "cancel", "lon1", "--yes"], &mut out, &mut err);
    assert_eq!(code, EXIT_LOCAL);
    assert!(out.failed());
    let report = String::from_utf8(err).unwrap();
    assert_eq!(report.lines().next().unwrap(), COMMITTED, "{report}");
    assert!(
        store(&harness)
            .load()
            .unwrap()
            .deployment
            .nodes()
            .is_empty()
    );

    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    let added = dir.join("added-since");
    harness.console.meanwhile = Some(Box::new(move || fs::write(added, b"").unwrap()));
    harness.console.answers.push_back(Answer::Yes);
    let mut out = FailingLog::at("cancelled node");
    let mut err = Vec::new();
    let code = harness.run_to(&["node", "cancel", "lon1"], &mut out, &mut err);
    assert_eq!(code, EXIT_LOCAL);
    assert!(out.failed());
    assert_eq!(
        String::from_utf8(err).unwrap(),
        format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed; until it is removed, by `node cancel lon1` again or by hand, `node new lon1` refuses\n  caused by: Directory not empty (os error 66)\n",
            dir.display()
        )
    );

    // Both at once.
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    *harness.keychain.lock().unwrap() = Refusals {
        delete: Some(-25_308),
        ..Refusals::default()
    };
    let added = dir.join("added-since");
    harness.console.meanwhile = Some(Box::new(move || fs::write(added, b"").unwrap()));
    harness.console.answers.push_back(Answer::Yes);
    let mut out = FailingLog::at("cancelled node");
    let mut err = Vec::new();
    let code = harness.run_to(&["node", "cancel", "lon1"], &mut out, &mut err);
    assert_eq!(code, EXIT_LOCAL);
    assert!(out.failed());
    let report = String::from_utf8(err).unwrap();
    assert!(
        report.starts_with(&format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed (Directory not empty (os error 66)); until it is removed, by `node cancel lon1` again or by hand, `node new lon1` refuses; deleting the keychain items the state no longer references failed too, ",
            dir.display()
        )),
        "{report}"
    );
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
        outcome.stdout.lines().last().unwrap(),
        "cancelled node lon1: the configuration generation stays 3, so the cancel needs no `node apply`"
    );
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed; until it is removed, by `node cancel lon1` again or by hand, `node new lon1` refuses\n  caused by: Permission denied (os error 13)\n",
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
            "mooringctl: {} exists already: an earlier node with this id left it; `node cancel lon1` removes the ssh files Mooring kept there, then plan the node again\n",
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
    assert_eq!(
        refused.stderr,
        "mooringctl: no file was written: the export was refused\n  caused by: node ams1 cannot be exported: its stage is Planned\n"
    );
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

/// Runs `node new <id> --role standby --host-key <file> --yes`.
fn plan(harness: &mut Harness, id: &str, host_key: &Path) -> super::support::Outcome {
    harness.run(&[
        "node",
        "new",
        id,
        "--role",
        "standby",
        "--host-key",
        host_key.to_str().unwrap(),
        "--yes",
    ])
}

/// The question names exactly the users who hold credentials on the node,
/// and as revoked once it is gone only a user whose revocation waits on it
/// alone: not an active user who holds credentials nowhere else, and no
/// user who holds none on it.
#[test]
fn cancel_names_only_the_users_who_hold_credentials_on_the_node() {
    let mut ids = Vec::new();
    let deployment = fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
        // The first user holds credentials on lon1 alone; the second on
        // both, suspended; the third on ams1 alone, active.
        parts.users[0].per_node.remove(&node_id("ams1"));
        parts.users[1].status = UserStatus::Suspended {
            reason: SuspendReason::Operator,
            since: UnixTime::from_secs(1),
        };
        parts.users[2].per_node.remove(&node_id("lon1"));
        ids = parts.users.iter().map(|user| user.id.clone()).collect();
    });
    let mut holders = [ids[1].as_str(), ids[2].as_str()];
    holders.sort_unstable();
    let pinned = deployment.nodes()[&node_id("ams1")].ssh.host_ed25519;
    let mut harness = harness_with(deployment);
    let before = state_bytes(&harness);
    harness.console.answers.push_back(Answer::No);
    let outcome = harness.run(&["node", "cancel", "ams1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stdout,
        format!(
            "node ams1: planned, tunnel 10.77.2.0/30, host key {} pinned; users with credentials on it: {}\n\
             cancelling removes it from the state and deletes its keys, and those users' credentials on it, from the keychain; no VPS is contacted\n",
            SshPublicKey::from(pinned).fingerprint(),
            holders.join(", ")
        )
    );
    assert_eq!(state_bytes(&harness), before);
}

/// Through the command, the cancel settles the revocation that waited only
/// on the node, in the state and in the keychain, and leaves the one that
/// waits on another node pending with its credentials there.
#[test]
fn cancel_settles_the_revocation_that_waited_only_on_the_node() {
    let mut ids = Vec::new();
    let deployment = fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
        for (index, nodes) in [(1, &["lon1", "ams1"][..]), (2, &["ams1"][..])] {
            let user = &mut parts.users[index];
            user.per_node
                .retain(|node, _| nodes.contains(&node.as_str()));
            user.status = UserStatus::RevokePending;
        }
        ids = parts.users.iter().map(|user| user.id.clone()).collect();
    });
    let (mut harness, _) = exporting(deployment);
    let (seed, _) = SshKeyPair::generate().unwrap().into_parts();
    harness
        .secrets
        .put(SecretEntry::NodeSshBootstrapPrivate(node_id("ams1"), seed))
        .unwrap();
    // The keychain holds every item of the fixture: the ones this
    // deployment never referenced stay whatever the cancel does.
    let before = store(&harness).load().unwrap().deployment;
    let unreferenced: BTreeSet<SecretRef> = harness
        .secrets
        .refs()
        .difference(&before.required_secrets())
        .cloned()
        .collect();
    let outcome = harness.run(&["node", "cancel", "ams1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let after = store(&harness).load().unwrap().deployment;
    let held = |index: usize| -> Vec<&str> {
        after.users()[&ids[index]]
            .per_node
            .keys()
            .map(NodeId::as_str)
            .collect()
    };
    assert_eq!(after.users()[&ids[1]].status, UserStatus::RevokePending);
    assert_eq!(held(1), ["lon1"]);
    assert_eq!(after.users()[&ids[2]].status, UserStatus::Revoked);
    assert!(held(2).is_empty());
    assert_eq!(after.users()[&ids[0]].status, UserStatus::Active);
    assert_eq!(held(0), ["lon1"]);
    // Of the items the state referenced, exactly those it still does stay.
    let kept: BTreeSet<SecretRef> = harness
        .secrets
        .refs()
        .difference(&unreferenced)
        .cloned()
        .collect();
    assert_eq!(kept, after.required_secrets());
    assert!(after.required_secrets().len() < before.required_secrets().len());
    assert!(
        harness
            .secrets
            .get(&SecretRef::UserVlessUuid(ids[1].clone(), node_id("lon1")))
            .is_ok()
    );
}

/// Users who held credentials on a cancelled node get new ones when its id
/// is planned again: a new short id in the state and new items in the
/// keychain, on a new tunnel; their credentials on the other node stay.
#[test]
fn users_get_new_credentials_when_a_cancelled_id_is_planned_again() {
    let mut harness = planned_par1_beside_applied_lon1();
    let par1 = node_id("par1");
    let first = store(&harness).load().unwrap().deployment;
    let user = first.users().keys().next().unwrap().clone();
    let vless = SecretRef::UserVlessUuid(user.clone(), par1.clone());
    let on_lon1 = SecretRef::UserVlessUuid(user.clone(), node_id("lon1"));
    let old_secret = harness.secrets.get(&vless).unwrap();
    let kept_secret = harness.secrets.get(&on_lon1).unwrap();
    let old_short = first.users()[&user].per_node[&par1].short_id;
    let outcome = harness.run(&["node", "cancel", "par1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.secrets.get(&vless).is_err());
    let (path, _) = host_key_file(&harness, "par1-again.pub");
    let outcome = plan(&mut harness, "par1", &path);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .starts_with("node par1: standby, tunnel 10.77.4.0/30, "),
        "{}",
        outcome.stdout
    );
    let again = store(&harness).load().unwrap().deployment;
    assert_ne!(again.users()[&user].per_node[&par1].short_id, old_short);
    assert_ne!(harness.secrets.get(&vless).unwrap(), old_secret);
    assert_eq!(harness.secrets.get(&on_lon1).unwrap(), kept_secret);
    assert_eq!(
        again.users()[&user].per_node[&node_id("lon1")],
        first.users()[&user].per_node[&node_id("lon1")]
    );
    assert!(!again.required_secrets().is_empty());
    for secret_ref in again.required_secrets() {
        assert!(harness.secrets.get(&secret_ref).is_ok(), "{secret_ref}");
    }
}

/// What the operator answered is what is done: the state is read again
/// when the answer comes, and a configuration change made while the
/// question waited stops the cancel, which deletes no key and no file.
#[test]
fn a_cancel_answered_after_another_change_is_refused() {
    let (mut harness, _) = partially_adopted();
    let dir = lon1_dir(&harness);
    let files = contents(&dir);
    let refs = harness.secrets.refs();
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
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, MOVED);
    assert!(harness.console.meanwhile.is_none());
    assert!(!outcome.stdout.contains("cancelled node"));
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.config_generation().get(), 4);
    assert_eq!(
        after.nodes()[&node_id("lon1")].lifecycle,
        NodeLifecycle::Planned
    );
    assert_eq!(harness.secrets.refs(), refs);
    assert_eq!(contents(&dir), files);
}

/// A record another command writes keeps the generation, so no
/// compare-and-swap would notice it, and it can change what the cancel
/// does or says. The cancel stops on it all the same, and run again it
/// says what is then true.
///
/// First `node apply lon1` finishes while the cancel of par1 asks: the
/// closing line would call lon1 behind the generation it has confirmed by
/// then. Then a revocation that waited on lon1 and on planned ams1 is
/// committed on lon1: the cancel of ams1 would settle it without having
/// named it.
#[test]
fn a_cancel_answered_after_another_record_is_refused() {
    let mut harness = planned_par1_beside_applied_lon1();
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let deployment = store.load().unwrap().deployment;
        let generation = deployment.config_generation();
        let digest = deployment.nodes()[&node_id("lon1")]
            .lifecycle
            .applied()
            .unwrap()
            .digest;
        store
            .record(
                generation,
                Bookkeeping::Applied {
                    node: node_id("lon1"),
                    applied: AppliedConfig {
                        config_generation: generation,
                        digest,
                    },
                },
            )
            .unwrap();
    }));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "par1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, MOVED);
    assert!(harness.console.meanwhile.is_none());
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(
        after.nodes()[&node_id("par1")].lifecycle,
        NodeLifecycle::Planned
    );
    let outcome = harness.run(&["node", "cancel", "par1", "--yes"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        !outcome.stdout.contains("behind generation"),
        "{}",
        outcome.stdout
    );

    let (mut harness, third) = planned_ams1_with_a_revocation_and_channels(&[]);
    let second = store(&harness)
        .load()
        .unwrap()
        .deployment
        .users()
        .keys()
        .nth(1)
        .unwrap()
        .clone();
    let (support, user) = (harness.support_dir(), second.clone());
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let generation = store.load().unwrap().deployment.config_generation();
        let committed = record_with_secrets(
            &store,
            &mut InMemorySecretStore::new(),
            generation,
            Bookkeeping::RevocationCommitted {
                user,
                node: node_id("lon1"),
            },
        );
        // Its keychain is not the harness's: the commit stands.
        assert!(
            matches!(committed, Err(StoreError::SecretCleanup { .. })),
            "{committed:?}"
        );
    }));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "ams1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stderr, MOVED);
    assert!(
        !outcome.stdout.contains(&format!(", {second}")),
        "the question did not name {second} as revoked: {}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(
        after.nodes()[&node_id("ams1")].lifecycle,
        NodeLifecycle::Planned
    );
    assert_eq!(after.users()[&second].status, UserStatus::RevokePending);
    let outcome = harness.run(&["node", "cancel", "ams1", "--yes"]);
    assert!(
        outcome.stdout.contains(&format!(
            "revoked once it is gone, since their revocation waits only on it: {second}, {third}\n"
        )),
        "{}",
        outcome.stdout
    );
    let after = store(&harness).load().unwrap().deployment;
    assert_eq!(after.users()[&second].status, UserStatus::Revoked);
}

/// `partially_adopted()` after a cancel that committed and stopped there,
/// as when its process ended before it deleted anything: the state holds
/// no lon1, and the keychain items and `ssh/lon1/` are as they were.
fn cancelled_and_stopped() -> Harness {
    let (harness, _) = partially_adopted();
    cancel_and_stop(&harness);
    harness
}

/// Commits lon1's cancel and stops there: the keychain items and the
/// node's files stay.
fn cancel_and_stop(harness: &Harness) {
    let store = store(harness);
    let generation = store.load().unwrap().deployment.config_generation();
    let cancelled = record_with_secrets(
        &store,
        &mut InMemorySecretStore::new(),
        generation,
        Bookkeeping::PlanCancelled {
            node: node_id("lon1"),
        },
    );
    // Its keychain is not the harness's: the commit stands, the items stay.
    assert!(
        matches!(cancelled, Err(StoreError::SecretCleanup { .. })),
        "{cancelled:?}"
    );
}

/// A cancel that committed and stopped before it removed the node's files
/// is finished by running it again: the state no longer holds the node,
/// `node new` refuses the id over the files, and the cancel removes them,
/// after a question, changing nothing else. The id is then planned again,
/// and the keychain items the first cancel left are replaced.
#[test]
fn a_cancel_that_stopped_after_its_commit_is_finished_by_running_it_again() {
    let mut harness = cancelled_and_stopped();
    let dir = lon1_dir(&harness);
    let files = contents(&dir);
    let before = state_bytes(&harness);
    let refs = harness.secrets.refs();
    let reality = SecretRef::NodeRealityPrivate(node_id("lon1"));
    let old = harness.secrets.get(&reality).unwrap();
    let (path, _) = host_key_file(&harness, "again.pub");
    let refused = plan(&mut harness, "lon1", &path);
    assert_eq!(refused.code, EXIT_LOCAL);
    assert!(
        refused.stderr.contains(" exists already: "),
        "{}",
        refused.stderr
    );
    let described = format!(
        "node lon1 is not in the state, but {dir} still holds the ssh files Mooring kept for a node of that id: a cancel committed and did not get to remove them\n\
         removing them lets the id be planned again; the state is not changed, no VPS is contacted, and keychain items that cancel did not get to delete stay, which nothing uses\n\
         `node adopt lon1` ran on this Mac: if its Bootstrap ran, the VPS lets in only the Mooring keys this deletes, not your own root key, so reinstall it or delete it from the provider's console\n",
        dir = dir.display()
    );
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
        assert_eq!(outcome.stdout, described);
        assert_eq!(contents(&dir), files);
    }
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "{described}removed {}: the id may be planned again\n",
            dir.display()
        )
    );
    assert_eq!(harness.console.asked, ["Remove these files?"; 3]);
    assert!(!dir.exists());
    assert!(harness.support_dir().join("ssh").is_dir());
    assert_eq!(state_bytes(&harness), before, "the state is not changed");
    assert_eq!(harness.secrets.refs(), refs, "no keychain item is touched");

    let outcome = plan(&mut harness, "lon1", &path);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_ne!(harness.secrets.get(&reality).unwrap(), old);
    // With nothing left of it, a cancelled node is unknown.
    let outcome = harness.run(&["node", "cancel", "zzz1", "--yes"]);
    assert_eq!(outcome.stderr, "mooringctl: unknown node zzz1\n");
}

/// What a cancel left is removed by the same rules as before a cancel:
/// anything Mooring does not keep there is refused before the question,
/// and an entry added while the question waits keeps the directory, which
/// is then the failure.
#[test]
fn files_left_by_a_cancel_are_removed_only_if_they_are_moorings_own() {
    let mut harness = cancelled_and_stopped();
    let dir = lon1_dir(&harness);
    let notes = dir.join("notes.txt");
    fs::write(&notes, b"mine\n").unwrap();
    let outcome = harness.run(&["node", "cancel", "lon1", "--yes"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: {} is not what Mooring keeps for the node; move it away, then cancel the node again\n",
            notes.display()
        )
    );
    assert_eq!(outcome.stdout, "");
    assert_eq!(names(&dir).len(), 5);
    fs::remove_file(&notes).unwrap();

    let added = dir.join("added-since");
    harness.console.meanwhile = Some(Box::new(move || fs::write(added, b"").unwrap()));
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&["node", "cancel", "lon1"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: node lon1 is cancelled, but {} could not be removed; until it is removed, by `node cancel lon1` again or by hand, `node new lon1` refuses\n  caused by: Directory not empty (os error 66)\n",
            dir.display()
        )
    );
    assert!(!outcome.stdout.contains("removed "), "{}", outcome.stdout);
    assert_eq!(names(&dir), ["added-since"]);
}

/// What the operator answered is what is done here too, where no write
/// guards the files: the answer removes them only if the state is still
/// the one read when it comes. While the question waited, another terminal
/// removed the files a cancel left and planned the id again (the state
/// holds lon1 as it did before the cancel), and in the second round
/// adopted it as far as its new operations key. The answer then removes
/// nothing, and says why.
#[test]
fn an_id_planned_again_while_the_leftover_question_waited_keeps_its_files() {
    for adopted_again in [false, true] {
        let (mut harness, _) = partially_adopted();
        let planned_again = state_bytes(&harness);
        cancel_and_stop(&harness);
        let dir = lon1_dir(&harness);
        let (state, files, bytes) = (
            store(&harness).state_path(),
            dir.clone(),
            planned_again.clone(),
        );
        harness.console.meanwhile = Some(Box::new(move || {
            fs::remove_dir_all(&files).unwrap();
            fs::write(state, bytes).unwrap();
            if adopted_again {
                fs::create_dir(&files).unwrap();
                fs::write(files.join("ops_ed25519"), b"the new node's key").unwrap();
            }
        }));
        harness.console.answers.push_back(Answer::Yes);
        let outcome = harness.run(&["node", "cancel", "lon1"]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{}", outcome.stdout);
        assert_eq!(outcome.stderr, MOVED);
        assert!(harness.console.meanwhile.is_none());
        assert_eq!(harness.console.asked, ["Remove these files?"]);
        assert!(!outcome.stdout.contains("removed "), "{}", outcome.stdout);
        assert_eq!(state_bytes(&harness), planned_again);
        if adopted_again {
            assert_eq!(
                contents(&dir),
                [("ops_ed25519".to_owned(), b"the new node's key".to_vec())]
            );
        } else {
            assert!(!dir.exists());
        }
    }
}

/// Output that fails while the leftover files are described removes
/// nothing; output that fails once they are gone is the failure, and they
/// stay gone.
#[test]
fn output_that_fails_before_the_leftover_files_go_removes_nothing() {
    for (needle, removed) in [
        ("is not in the state", false),
        ("ran on this Mac", false),
        ("removed ", true),
    ] {
        for mut out in [FailingLog::at(needle), FailingLog::only_at(needle)] {
            let mut harness = cancelled_and_stopped();
            let dir = lon1_dir(&harness);
            let mut err = Vec::new();
            let code = harness.run_to(&["node", "cancel", "lon1", "--yes"], &mut out, &mut err);
            assert_eq!(code, EXIT_LOCAL, "{out:?}");
            assert!(out.failed(), "{out:?}");
            let report = String::from_utf8(err).unwrap();
            assert!(
                report.starts_with("mooringctl: writing the output failed\n"),
                "{out:?}: {report}"
            );
            assert_eq!(dir.exists(), !removed, "{out:?}");
        }
    }
}

/// `node apply lon1` renders lon1's bundle from the deployment it loaded,
/// and records it once the node confirms. A cancel of planned ams1 in
/// between keeps the generation, so the record passes: the digest it
/// records is still the digest of lon1's bundle as the deployment now
/// renders it, so nothing is recorded that the node does not serve.
#[test]
fn an_apply_recorded_after_another_node_was_cancelled_is_the_bundle_now_rendered() {
    let deployment = fixture(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|node| node.id == node_id("ams1"))
            .unwrap();
        ams1.lifecycle = NodeLifecycle::Planned;
    });
    let generation = deployment.config_generation();
    let (mut harness, engines) = ready(deployment.clone());
    let (seed, _) = SshKeyPair::generate().unwrap().into_parts();
    harness
        .secrets
        .put(SecretEntry::NodeSshBootstrapPrivate(node_id("ams1"), seed))
        .unwrap();
    let (bundle, header) = bundle_and_header(&harness, &engines, &deployment);
    script_hello_and_blobs(&harness, header.blobs());
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind: RequestKind::Apply,
        },
        Answered::Replied(Ok(Response::Unchanged {
            generation: Generation::new(generation.get()),
        })),
    );
    let support = harness.support_dir();
    *harness.nodes.meanwhile.borrow_mut() = Some((
        2,
        Box::new(move || {
            let store = Store::new(support);
            let cancelled = record_with_secrets(
                &store,
                &mut InMemorySecretStore::new(),
                generation,
                Bookkeeping::PlanCancelled {
                    node: node_id("ams1"),
                },
            );
            // Its keychain is not the harness's: the commit stands.
            assert!(
                matches!(cancelled, Err(StoreError::SecretCleanup { .. })),
                "{cancelled:?}"
            );
        }),
    ));
    let outcome = apply_run(&mut harness, &apply_args(&engines));
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.nodes.script.borrow().is_empty());
    let after = store(&harness).load().unwrap().deployment;
    assert!(!after.nodes().contains_key(&node_id("ams1")));
    assert_eq!(after.config_generation(), generation);
    let applied = after.nodes()[&node_id("lon1")].lifecycle.applied().unwrap();
    assert_eq!(applied.config_generation, generation);
    assert_eq!(applied.digest, bundle.digest());
    let (now_rendered, _) = bundle_and_header(&harness, &engines, &after);
    assert_eq!(applied.digest, now_rendered.digest());
}

/// `node new` answered after another planned node was cancelled takes the
/// place the cancel freed: its closure pushes the node on the deployment
/// as it is under the lock, with the next tunnel index and credentials for
/// the users it listed, and nothing of the cancelled node comes back.
#[test]
fn a_node_planned_while_another_was_cancelled_takes_the_freed_place() {
    let mut harness = planned_par1_beside_applied_lon1();
    let before = store(&harness).load().unwrap().deployment;
    let generation = before.config_generation();
    let support = harness.support_dir();
    harness.console.meanwhile = Some(Box::new(move || {
        let store = Store::new(support);
        let cancelled = record_with_secrets(
            &store,
            &mut InMemorySecretStore::new(),
            generation,
            Bookkeeping::PlanCancelled {
                node: node_id("par1"),
            },
        );
        // Its keychain is not the harness's: the commit stands.
        assert!(
            matches!(cancelled, Err(StoreError::SecretCleanup { .. })),
            "{cancelled:?}"
        );
    }));
    harness.console.answers.push_back(Answer::Yes);
    let (path, _) = host_key_file(&harness, "ams1.pub");
    let outcome = harness.run(&[
        "node",
        "new",
        "ams1",
        "--role",
        "standby",
        "--host-key",
        path.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let after = store(&harness).load().unwrap().deployment;
    let nodes: Vec<&str> = after.nodes().keys().map(NodeId::as_str).collect();
    assert_eq!(nodes, ["ams1", "lon1"]);
    assert_eq!(after.config_generation().get(), generation.get() + 1);
    assert_eq!(
        after.nodes()[&node_id("ams1")].wg_index,
        before.next_wg_index()
    );
    for user in after.users().values() {
        let held: Vec<&str> = user.per_node.keys().map(NodeId::as_str).collect();
        assert_eq!(held, ["ams1", "lon1"], "{}", user.id);
    }
    for secret_ref in after.required_secrets() {
        assert!(harness.secrets.get(&secret_ref).is_ok(), "{secret_ref}");
    }
}
