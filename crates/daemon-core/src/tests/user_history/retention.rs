// SPDX-License-Identifier: GPL-3.0-or-later

//! A read applies the prune's retention at its own instant (F7, design
//! §11.5, §15.7): a document the daemon last pruned long ago still yields
//! only what the daemon would keep now. A revoked user's history is kept
//! until 13 months after the daemon last saw it not revoked, and then
//! nothing of it is shown.

use mooring_agent_proto::UsageMonth;
use mooring_model::{Deployment, UnixTime, UserStatus};

use super::{
    Reality, bin, bytes, deployment, detail, email, monthly, node, now, range, served, subject,
    traffic,
};
use crate::tests::support::{at, edited};
use crate::usage::history::{Folded, MonthTotal, Retention, UsageScope, UserState};
use crate::usage::{CollectedUsage, NodeUsageHistory};

/// lon1 as the daemon last wrote it on 2026-10-02, and ams1 empty:
/// - the full days of 2025-10-04 and 2025-10-05, and of 2026-09-30 and
///   2026-10-01, in detail, so in hours and days too;
/// - the months 2025-09, 2025-10, 2026-09 and 2026-10, the first three
///   final.
///
/// The subject has bytes in each day and month.
fn stale() -> CollectedUsage {
    let subject = subject();
    let mut lon = NodeUsageHistory::default();
    for (day, reality) in [
        ("2025-10-04", (1, 0)),
        ("2025-10-05", (2, 0)),
        ("2026-09-30", (4, 0)),
        ("2026-10-01", (8, 0)),
    ] {
        detail(
            &mut lon,
            "lon1",
            at(day, 0),
            at(day, 86_400),
            &[(
                at(day, 13 * 3600),
                vec![(email(&subject, Reality), traffic(reality.0, reality.1))],
            )],
        );
    }
    for (name, updated, received, reality) in [
        (
            "2025-09",
            at("2025-09-30", 86_340),
            at("2025-10-01", 60),
            16,
        ),
        ("2025-10", at("2025-10-31", 86_340), at("2025-11-01", 60), 3),
        ("2026-09", at("2026-09-30", 86_340), at("2026-10-01", 60), 4),
        (
            "2026-10",
            at("2026-10-01", 86_340),
            at("2026-10-02", 300),
            8,
        ),
    ] {
        monthly(
            &mut lon,
            "lon1",
            name,
            updated,
            received,
            vec![(email(&subject, Reality), traffic(reality, 0))],
        );
    }
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), lon);
    collected.set_node(node("ams1"), NodeUsageHistory::default());
    collected
        .prune(&deployment(), at("2026-10-02", 300))
        .unwrap();
    collected
}

fn month(name: &str) -> UsageMonth {
    name.parse().unwrap()
}

/// Read on 2026-11-05 12:00 from a document last pruned on 2026-10-02: an
/// hour is kept while it ends within 35 days, so 2026-10-01 11:00 is gone
/// and 12:00 kept; a day while it ended less than 13 months ago, so
/// 2025-10-04 (ended 2025-10-05 00:00) is gone and 2025-10-05 kept; and
/// September 2025 is folded into one total, no longer a month of its own.
#[test]
fn a_read_applies_the_retention_the_prune_would_at_its_own_instant() {
    let stored = stale();
    let history = stored
        .user_history(&deployment(), &subject(), now(), UsageScope::All)
        .unwrap();
    let lon = &history.nodes()[1];
    assert_eq!(lon.node, node("lon1"));
    // An hour is kept while it ends within 35 days: that of 2026-10-01
    // 12:00 ends at 13:00, 35 days before 2026-11-05 13:00.
    assert_eq!(
        lon.hourly.held,
        [range(at("2026-10-01", 12 * 3600), at("2026-10-02", 0))]
    );
    assert_eq!(
        lon.hourly.bins,
        [bin(at("2026-10-01", 13 * 3600), bytes((8, 0), (0, 0)))]
    );
    assert_eq!(
        lon.daily.held,
        [
            range(at("2025-10-05", 0), at("2025-10-06", 0)),
            range(at("2026-09-30", 0), at("2026-10-02", 0)),
        ]
    );
    assert_eq!(
        lon.daily.bins,
        [
            bin(at("2025-10-05", 0), bytes((2, 0), (0, 0))),
            bin(at("2026-09-30", 0), bytes((4, 0), (0, 0))),
            bin(at("2026-10-01", 0), bytes((8, 0), (0, 0))),
        ]
    );
    let totals = lon.totals.as_ref().unwrap();
    let total = |name, counted_through, is_final, reality| MonthTotal {
        month: month(name),
        counted_through,
        is_final,
        bytes: bytes((reality, 0), (0, 0)),
    };
    assert_eq!(
        totals.months,
        [
            total("2025-10", at("2025-10-31", 86_340), true, 3),
            total("2026-09", at("2026-09-30", 86_340), true, 4),
            // Received on 2026-10-02, so never final.
            total("2026-10", at("2026-10-01", 86_340), false, 8),
        ]
    );
    // The node's origin was never recorded, so the folded total may lack
    // months it never held: a lower bound.
    assert_eq!(
        totals.folded,
        Some(Folded {
            before: month("2025-10"),
            complete: false,
            bytes: bytes((16, 0), (0, 0)),
        })
    );
    assert_eq!(totals.lifetime, None);
    // The stored document still holds what the read left out.
    let mut pruned = stored.clone();
    pruned.prune(&deployment(), now()).unwrap();
    assert_ne!(pruned, stored);
    assert_eq!(
        stored
            .user_history(&deployment(), &subject(), now(), UsageScope::All)
            .unwrap(),
        pruned
            .user_history(&deployment(), &subject(), now(), UsageScope::All)
            .unwrap()
    );
}

/// The fixture with the subject revoked on every node.
fn revoked() -> Deployment {
    let subject = subject();
    edited(|parts| {
        for user in &mut parts.users {
            if user.id == subject {
                user.status = UserStatus::Revoked;
                user.per_node.clear();
            }
        }
    })
}

/// The subject's history as the daemon kept it: pruned at `now` while the
/// subject was still active, so last seen not revoked then.
fn seen_active() -> CollectedUsage {
    let mut collected = served();
    collected.prune(&deployment(), now()).unwrap();
    collected
}

/// 13 months after `now`, as the calendar counts them.
fn deadline() -> UnixTime {
    at("2027-12-05", 12 * 3600)
}

/// A revoked user's history is shown until its deadline, 13 months after
/// the daemon last saw it not revoked, with the deadline named, its tiers
/// still expiring on their own meanwhile; from the deadline's own second,
/// nothing is shown and the history is erased.
#[test]
fn a_revoked_users_history_is_kept_until_its_deadline_and_then_erased() {
    let collected = seen_active();
    let revoked = revoked();
    let read = |at: UnixTime| {
        collected
            .user_history(&revoked, &subject(), at, UsageScope::All)
            .unwrap()
    };
    let spring = read(at("2027-03-01", 0));
    assert_eq!(spring.status(), UserState::Revoked);
    assert_eq!(spring.retention(), Retention::Until(deadline()));
    let lon = &spring.nodes()[1];
    // Its hours are gone by then; its days and month are not.
    assert_eq!(lon.hourly.held, []);
    assert_eq!(
        lon.daily.bins,
        [bin(at("2026-11-04", 0), bytes((100, 1000), (20, 200)))]
    );
    let november = MonthTotal {
        month: month("2026-11"),
        counted_through: at("2026-11-05", 11 * 3600 + 58 * 60),
        is_final: false,
        bytes: bytes((1400, 35_200), (25, 207)),
    };
    assert_eq!(lon.totals.as_ref().unwrap().months, [november]);
    // A second before the deadline the month is still there, the day of
    // 2026-11-04 gone since midnight.
    let last = read(UnixTime::from_secs(deadline().as_secs() - 1));
    assert_eq!(last.retention(), Retention::Until(deadline()));
    let lon = &last.nodes()[1];
    assert_eq!(lon.daily.held, []);
    assert_eq!(lon.totals.as_ref().unwrap().months, [november]);
    let gone = read(deadline());
    assert_eq!(gone.retention(), Retention::Erased);
    assert_eq!(gone.nodes(), []);
    assert_eq!(gone.status(), UserState::Revoked);
}

/// A revoked user the daemon never saw before its revocation has no
/// deadline to keep it by: its history reads as erased at once, and the
/// other users' are untouched.
#[test]
fn a_revoked_user_never_seen_active_is_erased_at_once() {
    let collected = served();
    let history = collected
        .user_history(&revoked(), &subject(), now(), UsageScope::All)
        .unwrap();
    assert_eq!(history.retention(), Retention::Erased);
    assert_eq!(history.nodes(), []);
    let theirs = collected
        .user_history(&revoked(), &super::other(), now(), UsageScope::All)
        .unwrap();
    assert_eq!(theirs.retention(), Retention::Tiered);
    assert_eq!(
        theirs.nodes()[1].hourly.bins,
        [bin(at("2026-11-05", 9 * 3600), bytes((999, 9_999), (0, 0)))]
    );
}

/// A user being revoked keeps its deadline as a revoked one does.
#[test]
fn a_user_being_revoked_has_the_same_deadline() {
    let subject = subject();
    let pending = edited(|parts| {
        for user in &mut parts.users {
            if user.id == subject {
                user.status = UserStatus::RevokePending;
            }
        }
    });
    let history = seen_active()
        .user_history(&pending, &subject, at("2027-03-01", 0), UsageScope::All)
        .unwrap();
    assert_eq!(history.status(), UserState::RevokePending);
    assert_eq!(history.retention(), Retention::Until(deadline()));
    let gone = seen_active()
        .user_history(&pending, &subject, deadline(), UsageScope::All)
        .unwrap();
    assert_eq!(gone.retention(), Retention::Erased);
    assert_eq!(gone.nodes(), []);
}

/// A user the deployment does not hold has no retention left: its counters
/// are erased, as the prune and a node's replay treat them.
#[test]
fn a_user_the_deployment_does_not_hold_is_erased() {
    let stranger = mooring_model::UserId::from_low_bits(0x3_1415_9265);
    assert_eq!(
        seen_active().erased(&deployment(), &stranger, now()),
        Ok(true)
    );
    assert_eq!(
        seen_active().erased(&deployment(), &subject(), now()),
        Ok(false)
    );
}

/// A user suspended is not revoked: its history is kept by tier.
#[test]
fn a_suspended_users_history_is_kept_by_tier() {
    let subject = subject();
    let suspended = edited(|parts| {
        for user in &mut parts.users {
            if user.id == subject {
                user.status = UserStatus::Suspended {
                    reason: mooring_model::SuspendReason::AbuseReview,
                    since: at("2026-11-05", 3600),
                };
            }
        }
    });
    let history = served()
        .user_history(&suspended, &subject, now(), UsageScope::All)
        .unwrap();
    assert_eq!(history.retention(), Retention::Tiered);
    assert_eq!(
        history.status(),
        UserState::Suspended {
            reason: crate::usage::history::SuspendedFor::AbuseReview,
            since: at("2026-11-05", 3600),
        }
    );
    let active = served()
        .user_history(&deployment(), &subject, now(), UsageScope::All)
        .unwrap();
    assert_eq!(history.nodes(), active.nodes());
}

/// A month folded before it was final leaves the folded total a lower
/// bound, even on a node whose origin is recorded. Here it is August 2025,
/// received a minute before it ended and folded once its retention ended
/// on 2026-10-01.
#[test]
fn a_month_folded_before_it_was_final_leaves_a_lower_bound() {
    let subject = subject();
    let mut planned = CollectedUsage::default();
    planned.observe_unserved(node("lon1"), at("2025-08-01", 0));
    let mut lon = planned.node(&node("lon1")).unwrap().clone();
    monthly(
        &mut lon,
        "lon1",
        "2025-08",
        at("2025-08-31", 86_280),
        at("2025-08-31", 86_340),
        vec![(email(&subject, Reality), traffic(10, 20))],
    );
    monthly(
        &mut lon,
        "lon1",
        "2026-11",
        at("2026-11-05", 11 * 3600 + 58 * 60),
        at("2026-11-05", 11 * 3600 + 59 * 60),
        vec![],
    );
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), lon);
    let history = collected
        .user_history(&deployment(), &subject, now(), UsageScope::All)
        .unwrap();
    let totals = history.nodes()[1].totals.as_ref().unwrap();
    assert_eq!(
        totals.folded,
        Some(Folded {
            before: month("2025-09"),
            complete: false,
            bytes: bytes((10, 20), (0, 0)),
        })
    );
    assert_eq!(totals.lifetime, None);
}
