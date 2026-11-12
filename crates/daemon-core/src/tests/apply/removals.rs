// SPDX-License-Identifier: GPL-3.0-or-later

//! Removals (design §15.7): a user revoked 13 calendar months ago is due,
//! one revoked a second less is not, and a removed user's kept id goes once
//! its nodes' records have expired.

use mooring_model::removal::removal_due;
use mooring_model::user::UserPolicy;
use mooring_model::{Bookkeeping, UnixTime, UserStatus};

use super::super::support::at;
use super::{active, holding, id, user};
use crate::apply::{forgotten_expired, removals_due};

fn revoked(n: u64, since: UnixTime) -> mooring_model::User {
    user(n, UserStatus::Revoked { since }, UserPolicy::NONE)
}

/// A revocation 13 calendar months ago is due at that instant, and not a
/// second before; users who are not revoked are never due.
#[test]
fn a_user_revoked_13_months_ago_is_due_and_one_revoked_later_is_not() {
    let since = at("2025-10-13", 19 * 3600);
    let due = removal_due(since).unwrap();
    assert_eq!(due, at("2026-11-13", 19 * 3600));
    let deployment = holding(
        vec![
            revoked(1, since),
            revoked(2, UnixTime::from_secs(since.as_secs() + 1)),
            revoked(3, at("2025-01-01", 0)),
            active(4),
        ],
        None,
    );
    assert_eq!(removals_due(&deployment, due).unwrap(), [id(1), id(3)]);
    let second_before = UnixTime::from_secs(due.as_secs() - 1);
    assert_eq!(removals_due(&deployment, second_before).unwrap(), [id(3)]);
    // A day less than 13 months: kept.
    assert_eq!(
        removals_due(&deployment, at("2026-11-12", 19 * 3600)).unwrap(),
        [id(3)]
    );
}

/// A removed user's kept id has expired records once the nodes' records of
/// it have expired, at that instant.
#[test]
fn a_kept_id_expires_with_its_nodes_records() {
    let since = at("2026-10-20", 0);
    let removed = holding(vec![revoked(1, since), active(2)], None)
        .record(Bookkeeping::RevokedUserRemoved {
            user: id(1),
            at: at("2026-10-21", 0),
        })
        .unwrap();
    let until = removed.forgotten()[&id(1)];
    assert_eq!(until, at("2026-11-09", 0));
    assert!(!forgotten_expired(
        &removed,
        UnixTime::from_secs(until.as_secs() - 1)
    ));
    assert!(forgotten_expired(&removed, until));
    assert!(!forgotten_expired(&holding(vec![active(2)], None), until));
}
