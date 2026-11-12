// SPDX-License-Identifier: GPL-3.0-or-later

//! The ledger's prune where it cannot be made: nothing is pruned while the
//! ledger cannot be read, and a pruned ledger that cannot be written is
//! said, not kept, and tried again only a while later. (The daemon's prune
//! that succeeds is in `tests::payments::daemon`.)

use std::fs;

use mooring_model::{Bookkeeping, Deployment, UnixTime, UserId, UserStatus};
use mooring_store::{PAYMENT_LEDGER_FILE, PAYMENTS_DIRECTORY};

use super::super::support::NOW;
use super::super::user::fixture;
use super::{FIRST, SECOND, connect, grant, harness, ledger_on_disk, page};
use crate::payments::pull::Puller;

/// The fixture with `SECOND` revoked a day before the clock and removed at
/// it.
fn second_removed() -> Deployment {
    fixture(|parts| {
        for user in &mut parts.users {
            if user.id.as_str() == SECOND {
                user.per_node.clear();
                user.status = UserStatus::Revoked {
                    since: UnixTime::from_secs(NOW - 86_400),
                };
            }
        }
    })
    .record(Bookkeeping::RevokedUserRemoved {
        user: UserId::parse(SECOND).unwrap(),
        at: UnixTime::from_secs(NOW),
    })
    .unwrap()
}

/// While the ledger cannot be read, the prune neither reads nor writes it.
#[test]
fn nothing_is_pruned_while_the_ledger_cannot_be_read() {
    let harness = harness();
    let dir = harness.support_dir().join(PAYMENTS_DIRECTORY);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(PAYMENT_LEDGER_FILE), b"not a ledger").unwrap();
    let mut puller = Puller::open(&harness.support_dir());
    assert!(puller.fault().is_some());
    assert!(puller.prune(&second_removed()).is_empty());
    assert_eq!(
        fs::read(dir.join(PAYMENT_LEDGER_FILE)).unwrap(),
        b"not a ledger"
    );
}

/// A pruned ledger that cannot be written is said, counting users only;
/// the ledger on disk keeps the orders, and the prune is not tried again
/// at once, even once the write could succeed.
#[test]
fn a_prune_that_cannot_be_written_is_said_and_tried_again_later() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    harness.portal.ok(&page(
        true,
        0,
        vec![
            grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST),
            grant(2, "bbbbbbbbbbbbbbbbbbbb", SECOND),
        ],
        false,
    ));
    let mut puller = Puller::open(&harness.support_dir());
    let users = fixture(|_| {}).users().clone();
    let mut clear = || true;
    harness.with_env(|env| {
        puller.tick(
            env,
            &users,
            UnixTime::from_secs(NOW),
            crate::payments::pull::Gate {
                room: Some(std::time::Duration::from_secs(10)),
                network_clear: &mut clear,
            },
            &|| None,
        )
    });
    assert_eq!(ledger_on_disk(&harness).unwrap().orders().len(), 2);
    let dir = harness.support_dir().join(PAYMENTS_DIRECTORY);
    let aside = harness.support_dir().join("payments-aside");
    fs::rename(&dir, &aside).unwrap();
    fs::write(&dir, b"not a directory").unwrap();
    let said = puller.prune(&second_removed());
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0]
            .starts_with("payment ledger: the orders of 1 removed user(s) could not be deleted ("),
        "{said:?}"
    );
    assert!(said[0].ends_with("); trying again in 60 s"), "{said:?}");
    assert!(!said[0].contains(SECOND), "{said:?}");
    fs::remove_file(&dir).unwrap();
    fs::rename(&aside, &dir).unwrap();
    assert!(puller.prune(&second_removed()).is_empty());
    assert_eq!(ledger_on_disk(&harness).unwrap().orders().len(), 2);
}
