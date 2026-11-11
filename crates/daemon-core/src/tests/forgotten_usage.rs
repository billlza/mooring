// SPDX-License-Identifier: GPL-3.0-or-later

//! A removed user's kept id (design §15.3, `user forget`): while the
//! deployment keeps it, the Mac drops a node's entries naming it on
//! receipt and reads its history without it, where an unknown user's
//! entries are refused; the prune then deletes what the history held of
//! it.

use std::collections::BTreeMap;

use mooring_agent_proto::Inbound;
use mooring_model::{Bookkeeping, Deployment, UnixTime, UserStatus};

use super::collected_usage::today_history;
use super::support::{at, email, node, traffic, user_ids};
use crate::error::UsageError;

/// The fixture billed on day 1 with its first user revoked on
/// 2026-11-04 and then removed on 2026-11-05: its id is kept until
/// 2026-12-09.
fn forgotten() -> Deployment {
    let id = user_ids()[0].clone();
    let deployment = super::support::edited(|parts| {
        let sim = &parts.exit.sim;
        parts.exit.sim = mooring_model::SimPolicy::new(
            mooring_model::CycleRule::Monthly {
                bill_day: mooring_model::BillDay::new(1).unwrap(),
            },
            sim.plan().unwrap().clone(),
            sim.warn_bytes(),
            sim.stop(),
        )
        .unwrap();
        for user in &mut parts.users {
            if user.id == id {
                user.per_node.clear();
                user.status = UserStatus::Revoked {
                    since: at("2026-11-04", 0),
                };
            }
        }
    });
    let removed = deployment
        .record(Bookkeeping::RevokedUserRemoved {
            user: id.clone(),
            at: at("2026-11-05", 0),
        })
        .unwrap();
    assert!(removed.forgotten().contains_key(&id));
    removed
}

/// A node's reply naming the kept id loses those entries and keeps the
/// rest; an id neither a user's nor kept is still refused.
#[test]
fn a_nodes_entries_naming_a_kept_id_are_dropped_on_receipt() {
    let deployment = forgotten();
    let (history, now) = today_history();
    let gone = user_ids()[0].clone();
    let kept = user_ids()[1].clone();
    let mut reply = BTreeMap::from([
        (email(&gone, Inbound::Reality), traffic(1, 2)),
        (email(&gone, Inbound::Hy2), traffic(3, 4)),
        (email(&kept, Inbound::Reality), traffic(5, 6)),
    ]);
    history
        .retain_counter_users(&node("lon1"), &mut reply, &deployment, now)
        .unwrap();
    assert_eq!(
        reply,
        BTreeMap::from([(email(&kept, Inbound::Reality), traffic(5, 6))])
    );
    // Once the id is no longer kept, an entry naming it is an unknown
    // user's, as before.
    let expired = deployment
        .clone()
        .record(Bookkeeping::ForgottenExpired {
            at: at("2026-12-09", 0),
        })
        .unwrap();
    let mut late = BTreeMap::from([(email(&gone, Inbound::Reality), traffic(1, 2))]);
    assert!(matches!(
        history.retain_counter_users(&node("lon1"), &mut late, &expired, now),
        Err(UsageError::UnknownUser { .. })
    ));
}

/// A history that still holds the removed user's bins reads without them
/// until the prune deletes them, which it then does everywhere.
#[test]
fn a_history_naming_a_kept_id_reads_without_it_and_the_prune_deletes_it() {
    let deployment = forgotten();
    let (mut history, now) = today_history();
    let gone = user_ids()[0].clone();
    history
        .node(&node("lon1"))
        .unwrap()
        .validate_users(&node("lon1"), &deployment)
        .unwrap();
    let report = history.aggregate(&deployment, now).unwrap();
    assert!(!report.users.contains_key(&gone));
    assert!(
        String::from_utf8(history.encode().unwrap())
            .unwrap()
            .contains(gone.as_str()),
        "the bins are still held before the prune"
    );
    history.prune(&deployment, now).unwrap();
    assert!(
        !String::from_utf8(history.encode().unwrap())
            .unwrap()
            .contains(gone.as_str()),
        "the prune deletes every bin and total naming it"
    );
    // The same history without the kept id is an unknown user's.
    let (unpruned, _) = today_history();
    let bare = deployment
        .record(Bookkeeping::ForgottenExpired {
            at: UnixTime::from_secs(u64::from(u32::MAX)),
        })
        .unwrap();
    assert!(matches!(
        unpruned
            .node(&node("lon1"))
            .unwrap()
            .validate_users(&node("lon1"), &bare),
        Err(UsageError::UnknownUser { .. })
    ));
}
