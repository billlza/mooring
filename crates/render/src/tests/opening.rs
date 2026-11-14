// SPDX-License-Identifier: GPL-3.0-or-later

//! Opening a user without restarting the engines (design §13.6): taking a
//! spare user, or resuming a suspended one, changes a node's bundle only in
//! Xray's clients, which the running engine takes, and in the watch's
//! emails, which the watch reads at each tick. Every file an engine reads
//! only at start is byte for byte the same, and `xray.json` gains exactly
//! the opened user's two clients. The agent relies on exactly this to add
//! the users to the running Xray instead of restarting it.

use mooring_agent_proto::ManagedFile;
use mooring_fixtures::{FIXTURE_NOW, Fixture};
use mooring_model::user::SuspendReason;
use mooring_model::{Deployment, NodeId, UserId};
use serde_json::Value;

use crate::tests::support::{add_spare, edit, engines, node, taken};
use crate::vps::bundle;

/// The inbounds whose clients the running Xray takes, by position.
const CLIENT_INBOUNDS: [(usize, &str, &str); 2] =
    [(0, "reality-in", "reality"), (1, "hy2-loop-in", "hy2")];

fn file(fixture: &Fixture, deployment: &Deployment, node: &NodeId, file: ManagedFile) -> Vec<u8> {
    bundle(deployment, node, &fixture.secrets, &engines())
        .unwrap()
        .file(file)
        .expose_bytes()
        .to_vec()
}

/// Checks that `after` renders every node of `before` as the agent's
/// users-only change from `before`: every file the same but `xray.json`,
/// which differs only by `user`'s two clients added among the clients the
/// node had, and `watch.json`, which gains `user`'s two emails.
fn assert_opens_without_a_restart(
    fixture: &Fixture,
    before: &Deployment,
    after: &Deployment,
    user: &UserId,
) {
    for node in before.nodes().keys() {
        for managed in ManagedFile::ALL {
            let (old, new) = (
                file(fixture, before, node, *managed),
                file(fixture, after, node, *managed),
            );
            match managed {
                ManagedFile::XrayConfig => {
                    let (mut old, mut new): (Value, Value) = (
                        serde_json::from_slice(&old).unwrap(),
                        serde_json::from_slice(&new).unwrap(),
                    );
                    for (position, tag, inbound) in CLIENT_INBOUNDS {
                        assert_eq!(old["inbounds"][position]["tag"], tag);
                        let clients = format!("/inbounds/{position}/settings/clients");
                        let had = old.pointer_mut(&clients).unwrap().take();
                        let has = new.pointer_mut(&clients).unwrap().take();
                        let had = had.as_array().unwrap();
                        let has = has.as_array().unwrap();
                        let added: Vec<&Value> =
                            has.iter().filter(|client| !had.contains(client)).collect();
                        assert_eq!(has.len(), had.len() + 1, "{node} {tag}");
                        assert!(
                            had.iter().all(|client| has.contains(client)),
                            "{node} {tag}"
                        );
                        assert_eq!(
                            added[0]["email"],
                            format!("{user}@{inbound}"),
                            "{node} {tag}"
                        );
                    }
                    assert_eq!(old, new, "{node}: only the clients differ");
                }
                ManagedFile::WatchConfig => {
                    let text = String::from_utf8(new).unwrap();
                    assert!(text.contains(&format!("{user}@reality")), "{node}");
                    assert!(!String::from_utf8(old).unwrap().contains(user.as_str()));
                }
                _ => assert!(old == new, "{node}: {managed:?} changed"),
            }
        }
    }
}

/// `user add` taking a spare user: the user keeps the spare's id and
/// credentials, so each node's sing-box users, outbounds and route rules
/// and its REALITY short ids stay as they were.
#[test]
fn taking_a_spare_changes_only_the_clients_and_the_watch() {
    let mut fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let spare = add_spare(&mut fixture);
    let other = add_spare(&mut fixture);
    let before = fixture.deployment.clone();
    let after = edit(&before, |parts| {
        let taken_spare = parts.take_spare(&spare).unwrap();
        parts
            .users
            .push(taken(taken_spare.id, taken_spare.per_node));
    });
    assert_eq!(after.spares().keys().collect::<Vec<_>>(), [&other]);
    assert_opens_without_a_restart(&fixture, &before, &after, &spare);
}

/// Resuming a suspended user, as the apply job does at a payment.
#[test]
fn resuming_a_user_changes_only_the_clients_and_the_watch() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let user = fixture.deployment.users().keys().nth(1).unwrap().clone();
    let before = edit(&fixture.deployment, |parts| {
        parts.users[1]
            .suspend(SuspendReason::Expired, FIXTURE_NOW)
            .unwrap();
    });
    assert_opens_without_a_restart(&fixture, &before, &fixture.deployment, &user);
}

/// A spare is kept only on the nodes it holds credentials on: a node
/// planned after it was drawn renders as if it had not been, until the
/// nightly job gives it credentials there.
#[test]
fn a_spare_is_kept_only_where_it_holds_credentials() {
    let mut fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let without = fixture.deployment.clone();
    let spare = add_spare(&mut fixture);
    let (lon1, ams1) = (node("lon1"), node("ams1"));
    let on_lon1 = edit(&fixture.deployment, |parts| {
        parts.spares[0].per_node.remove(&ams1);
    });
    for managed in ManagedFile::ALL {
        assert!(
            file(&fixture, &on_lon1, &ams1, *managed) == file(&fixture, &without, &ams1, *managed),
            "{managed:?}"
        );
    }
    let hy2 = file(&fixture, &on_lon1, &lon1, ManagedFile::Hy2Config);
    assert!(String::from_utf8(hy2).unwrap().contains(spare.as_str()));
}

/// A user added with fresh credentials, as with no spare left, changes the
/// files an engine reads at start: that node's engines restart.
#[test]
fn a_user_with_fresh_credentials_changes_the_start_time_files() {
    let mut fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let before = fixture.deployment.clone();
    let spare = add_spare(&mut fixture);
    let after = edit(&before, |parts| {
        let fresh = fixture.deployment.spares()[&spare].clone();
        parts.users.push(taken(fresh.id, fresh.per_node));
    });
    for node in before.nodes().keys() {
        assert_ne!(
            file(&fixture, &before, node, ManagedFile::Hy2Config),
            file(&fixture, &after, node, ManagedFile::Hy2Config),
            "{node}"
        );
    }
}
