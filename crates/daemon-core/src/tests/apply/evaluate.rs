// SPDX-License-Identifier: GPL-3.0-or-later

//! `evaluate` without the cycle's usage (design §13.6): an expiry is still
//! proposed, and a quota is reported unchecked, never read as within it.

use mooring_model::user::{SuspendReason, UserPolicy};
use mooring_model::{UnixTime, UserStatus};

use super::{GB, active, holding, id, now, quota, usage, user};
use crate::error::PolicyError;
use crate::payments::Entitlements;
use crate::policy::{
    PolicyAction, PolicyWarning, UserAction, evaluate, quota_suspension_holds_at, user_alerts,
};

/// With no report, the expiry is proposed and each quota reported
/// unchecked; a user whose figure alone is unknown is unchecked while the
/// others are checked; a user the report leaves out is an error, as before.
#[test]
fn a_quota_without_usage_is_unchecked_and_an_expiry_is_still_proposed() {
    let past = UnixTime::from_secs(now().as_secs() - 1);
    let deployment = holding(
        vec![
            user(
                1,
                UserStatus::Active,
                UserPolicy {
                    expires_at: Some(past),
                    quota: Some(quota(10 * GB)),
                },
            ),
            user(
                2,
                UserStatus::Active,
                UserPolicy {
                    expires_at: None,
                    quota: Some(quota(10 * GB)),
                },
            ),
            user(
                3,
                UserStatus::Active,
                UserPolicy {
                    expires_at: None,
                    quota: Some(quota(10 * GB)),
                },
            ),
            active(4),
        ],
        None,
    );
    let unchecked = |n| UserAction {
        user: id(n),
        action: PolicyAction::Warn(PolicyWarning::QuotaUnchecked {
            quota_bytes: 10 * GB,
        }),
    };
    let expired = UserAction {
        user: id(1),
        action: PolicyAction::Suspend(SuspendReason::Expired),
    };
    let actions = evaluate(&deployment, &Entitlements::none(), None, now()).unwrap();
    assert_eq!(actions, [expired.clone(), unchecked(2), unchecked(3)]);
    // An unchecked quota raises no alert of its own.
    assert!(user_alerts(deployment.users(), &[unchecked(2)]).is_empty());
    let mut report = usage(&deployment, now(), &[(3, 10 * GB)]);
    report.served.insert(id(2), None);
    let actions = evaluate(&deployment, &Entitlements::none(), Some(&report), now()).unwrap();
    assert_eq!(
        actions,
        [
            expired,
            unchecked(2),
            UserAction {
                user: id(3),
                action: PolicyAction::Suspend(SuspendReason::QuotaExceeded {
                    cycle_start: mooring_model::CalendarDate::parse("2026-11-01").unwrap()
                }),
            },
        ]
    );
    report.served.remove(&id(2));
    assert_eq!(
        evaluate(&deployment, &Entitlements::none(), Some(&report), now()),
        Err(PolicyError::UsageMissing { user: id(2) })
    );
}

/// The public predicate is the automatic quota's: held from the cycle's
/// start, lapsed before it, an error after `now`.
#[test]
fn the_public_predicate_holds_a_suspension_from_the_cycles_start() {
    let deployment = holding(vec![active(1)], None);
    let start = super::super::support::at("2026-11-01", 0);
    let holds = |since: UnixTime| quota_suspension_holds_at(&deployment, &id(1), since, now());
    assert_eq!(holds(start), Ok(true));
    assert_eq!(holds(UnixTime::from_secs(start.as_secs() - 1)), Ok(false));
    assert_eq!(holds(now()), Ok(true));
    let ahead = UnixTime::from_secs(now().as_secs() + 1);
    assert_eq!(
        holds(ahead),
        Err(PolicyError::QuotaSuspensionAfterNow {
            user: id(1),
            since: ahead,
            now: now(),
        })
    );
}
