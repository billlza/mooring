// SPDX-License-Identifier: GPL-3.0-or-later

//! Make-ups (design §9.6; the agreement's clauses 1 and 3): the service
//! time or traffic the operator gives a user without a payment. Days extend
//! the user's live paid time with the quota of their live period that ends
//! last; traffic counts in its billing cycle as a pack does; both always
//! count and nothing takes them back, but a refund in full moves a
//! make-up's period as it moves any period that follows the time it takes
//! back. The ledger numbers them, keeps them in its file and lets them go
//! with their user; the daemon decides them against the deployment.

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use mooring_model::quota::AutoQuotaPolicy;
use mooring_model::{CalendarDate, Deployment, SuspendReason, UnixTime, User, UserStatus};
use serde_json::{Value, json};

use super::refunds::{A, B, GB, HOUR, cycle, quota, recorded, step, users};
use super::{DAY, NOW, Terms, id, order, secs, user};
use crate::make_up::decide;
use crate::payments::{
    Granted, LedgerError, LedgerEvent, MadeUp, MakeUpAsk, MakeUpGift, MakeUpNumber, MakeUpReason,
    MakeUpRecord, MakeUpRefusal, PaidPack, PaidPeriod, PaymentLedger, Pruned, RefundEffect,
    TimeTakenBack,
};
use crate::policy::effective_policy;

const C: &str = "cccccccccccccccccccc";
const D: &str = "dddddddddddddddddddd";

/// The last second of the calendar, 9999-12-31T23:59:59Z.
const LAST_SECOND: u64 = 253_402_300_799;

fn days(count: u32) -> MakeUpAsk {
    MakeUpAsk::Days(NonZeroU32::new(count).unwrap())
}

fn traffic(gigabytes: u64) -> MakeUpAsk {
    MakeUpAsk::TrafficBytes(bytes(gigabytes))
}

fn bytes(gigabytes: u64) -> NonZeroU64 {
    NonZeroU64::new(gigabytes * GB).unwrap()
}

fn number(value: u64) -> MakeUpNumber {
    MakeUpNumber::new(NonZeroU64::new(value).unwrap())
}

/// A make-up's period from `from` until `until` with a quota of
/// `gigabytes`.
fn period(from: u64, until: u64, gigabytes: u64) -> MakeUpGift {
    MakeUpGift::Period {
        from: secs(from),
        until: secs(until),
        quota_bytes: bytes(gigabytes),
    }
}

fn span(from: u64, until: u64) -> Option<(UnixTime, UnixTime)> {
    Some((secs(from), secs(until)))
}

/// Pilot user a: active, without an expiry or a quota of their own.
fn user_a() -> User {
    users()[&id("pilotusera")].clone()
}

/// Pilot user b, as user a.
fn user_b() -> User {
    users()[&id("pilotuserb")].clone()
}

/// The make-up `ask` gives `who` at `at`, for an outage, on a copy of
/// `ledger`.
fn make_up(
    ledger: &PaymentLedger,
    who: &User,
    ask: MakeUpAsk,
    at: u64,
) -> Result<MadeUp, MakeUpRefusal> {
    ledger.make_up(who, ask, MakeUpReason::Outage, secs(at))
}

/// How `ledger`'s make-up `value` counts after the refunds in full.
fn made_up_span(ledger: &PaymentLedger, value: u64) -> Option<(UnixTime, UnixTime)> {
    ledger
        .take_backs()
        .make_up_period(&ledger.make_ups()[&number(value)])
}

/// How the period of `ledger`'s order `text` counts after the refunds in
/// full.
fn order_span(ledger: &PaymentLedger, text: &str) -> Option<(UnixTime, UnixTime)> {
    ledger.take_backs().period(&ledger.orders()[&order(text)])
}

/// `ledger` with `entry` applied at `at` from a page of Stripe's test
/// mode, while the operator rehearses.
fn rehearse(ledger: &PaymentLedger, entry: Value, at: u64) -> PaymentLedger {
    let page = super::decode(
        &super::document(false, ledger.cursor(), vec![entry], false),
        ledger.cursor(),
    )
    .unwrap();
    ledger
        .apply(&page, &users(), secs(at), true)
        .unwrap()
        .ledger
}

/// The fixture deployment holding `held`.
fn holding(held: Vec<User>) -> Deployment {
    super::super::support::edited(|parts| parts.users = held)
}

/// A month of `gigabytes` for pilot user a.
fn month_of(text: &'static str, gigabytes: u64) -> Terms {
    Terms {
        gigabytes,
        ..Terms::month(text, "pilotusera")
    }
}

/// Days of service extend the user's live paid time: from its end, for the
/// days asked, with the quota of their last period. They count as a live
/// order's period, whatever the rehearsal, and a month bought afterwards
/// follows them. The ledger asked is left as it was.
#[test]
fn days_extend_the_paid_time_with_the_last_periods_quota() {
    let now = NOW.as_secs();
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let made = make_up(&ledger, &user_a(), days(7), now + DAY).unwrap();
    let record = MakeUpRecord {
        number: number(1),
        user: id("pilotusera"),
        reason: MakeUpReason::Outage,
        granted_at: secs(now + DAY),
        after: 1,
        gift: period(now + 30 * DAY, now + 37 * DAY, 100),
    };
    assert_eq!(made.record, record);
    assert_eq!(made.suspended, None);
    assert!(ledger.make_ups().is_empty());
    assert_eq!(ledger.last_make_up(), 0);
    let ledger = made.ledger;
    assert_eq!(ledger.make_ups().values().collect::<Vec<_>>(), [&record]);
    assert_eq!(ledger.last_make_up(), 1);
    let inside = now + 31 * DAY;
    for rehearsal in [false, true] {
        let paid = ledger.entitlements(rehearsal);
        let own = paid.user(&id("pilotusera")).unwrap();
        assert_eq!(own.paid_until(), Some(secs(now + 37 * DAY)));
        assert_eq!(
            own.period_at(secs(inside)),
            Some(&PaidPeriod {
                granted: Granted::MakeUp(number(1)),
                from: secs(now + 30 * DAY),
                until: secs(now + 37 * DAY),
                quota_bytes: bytes(100),
                livemode: true,
            })
        );
        let policy = effective_policy(
            &user_a(),
            None,
            &paid,
            cycle(secs(inside)),
            secs(inside),
            None,
        );
        assert_eq!(policy.expires_at, Some(secs(now + 37 * DAY)));
        assert_eq!(
            policy.quota.map(|quota| quota.cycle_served_bytes),
            Some(bytes(100))
        );
    }
    // A month bought afterwards follows the make-up.
    let (ledger, _) = step(&ledger, Terms::month(B, "pilotusera").grant(2), now + DAY);
    assert_eq!(order_span(&ledger, B), span(now + 37 * DAY, now + 67 * DAY));
}

/// Days for a user whose paid time has ended start at the make-up; a later
/// expiry of the user's own record is where they start, as a live grant's
/// period would, and one that has passed is not.
#[test]
fn days_start_at_the_make_up_or_at_a_later_own_expiry() {
    let now = NOW.as_secs();
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let later = now + 40 * DAY;
    for (expires_at, from) in [
        (None, later),
        (Some(now + 50 * DAY), now + 50 * DAY),
        (Some(now + 35 * DAY), later),
    ] {
        let own = user("pilotusera", UserStatus::Active, expires_at);
        assert_eq!(
            make_up(&ledger, &own, days(3), later).unwrap().record.gift,
            period(from, from + 3 * DAY, 100),
            "{expires_at:?}"
        );
    }
}

/// The quota is that of the user's live period that ends last, as the
/// refunds in full leave the periods: a month whose time was all taken
/// back gave no service and is passed over, a rehearsal's month never
/// counts, and another user's periods are theirs.
#[test]
fn the_quota_is_that_of_the_users_live_period_that_ends_last() {
    let now = NOW.as_secs();
    let a = user_a();
    let (ledger, _) = step(&PaymentLedger::new(), month_of(A, 100).grant(1), now);
    let (ledger, _) = step(&ledger, month_of(B, 200).grant(2), now);
    assert_eq!(
        make_up(&ledger, &a, days(7), now).unwrap().record.gift,
        period(now + 60 * DAY, now + 67 * DAY, 200)
    );
    // A month of 300 GB, refunded in full before it began, ends where the
    // 200 GB month does, and later in the ledger's order.
    let largest = month_of(C, 300);
    let (ledger, _) = step(&ledger, largest.grant(3), now);
    let (ledger, _) = step(&ledger, recorded(largest.refund(4, 800, true), now), now);
    assert_eq!(order_span(&ledger, C), span(now + 60 * DAY, now + 60 * DAY));
    // A rehearsal's month of 400 GB after them all.
    let ledger = rehearse(&ledger, month_of(D, 400).grant(5), now);
    assert_eq!(
        ledger
            .entitlements(true)
            .user(&id("pilotusera"))
            .unwrap()
            .paid_until(),
        Some(secs(now + 90 * DAY))
    );
    assert_eq!(
        make_up(&ledger, &a, days(7), now).unwrap().record.gift,
        period(now + 60 * DAY, now + 67 * DAY, 200)
    );
    // User b's month of 500 GB and their make-up after it end later.
    let other = Terms {
        gigabytes: 500,
        days: 90,
        ..Terms::month("eeeeeeeeeeeeeeeeeeee", "pilotuserb")
    };
    let (ledger, _) = step(&ledger, other.grant(6), now);
    let ledger = make_up(&ledger, &user_b(), days(90), now).unwrap().ledger;
    assert_eq!(
        made_up_span(&ledger, 1),
        span(now + 90 * DAY, now + 180 * DAY)
    );
    assert_eq!(
        make_up(&ledger, &a, days(7), now).unwrap().record.gift,
        period(now + 60 * DAY, now + 67 * DAY, 200)
    );
}

/// Without a live period there is no paid time to extend: no order, only
/// a pack, only a rehearsal's month, a month all taken back, or traffic
/// made up. A user being revoked, or revoked, is refused first. Traffic
/// needs no period.
#[test]
fn days_without_a_live_period_are_refused() {
    let now = NOW.as_secs();
    let a = user_a();
    let none = PaymentLedger::new();
    let (pack, _) = step(&none, Terms::pack(A, "pilotusera").grant(1), now);
    let rehearsed = rehearse(&none, Terms::month(A, "pilotusera").grant(1), now);
    let month = Terms::month(A, "pilotusera");
    let (taken, _) = step(&none, month.grant(1), now);
    let (taken, _) = step(&taken, recorded(month.refund(2, 800, true), now), now);
    assert_eq!(order_span(&taken, A), span(now, now));
    let traffic_only = make_up(&none, &a, traffic(5), now).unwrap().ledger;
    for ledger in [none, pack, rehearsed, taken, traffic_only] {
        assert_eq!(
            make_up(&ledger, &a, days(7), now + HOUR),
            Err(MakeUpRefusal::NoPaidPeriod)
        );
        assert!(make_up(&ledger, &a, traffic(5), now + HOUR).is_ok());
        let revoked = user("pilotusera", UserStatus::RevokePending, None);
        assert_eq!(
            make_up(&ledger, &revoked, days(7), now + HOUR),
            Err(MakeUpRefusal::UserRevoked)
        );
    }
}

/// A user being revoked, or revoked, is given nothing; a suspended user's
/// make-up is recorded with why they are suspended, which tells the
/// operator whether it resumes them.
#[test]
fn a_revoked_user_is_refused_and_a_suspended_ones_suspension_is_told() {
    let now = NOW.as_secs();
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    for status in [
        UserStatus::RevokePending,
        UserStatus::Revoked { since: secs(now) },
    ] {
        let revoked = user("pilotusera", status, None);
        for ask in [days(7), traffic(5)] {
            assert_eq!(
                make_up(&ledger, &revoked, ask, now),
                Err(MakeUpRefusal::UserRevoked),
                "{status:?} {ask:?}"
            );
        }
    }
    for reason in [
        SuspendReason::Operator,
        SuspendReason::Expired,
        SuspendReason::AbuseReview,
        SuspendReason::QuotaExceeded {
            cycle_start: CalendarDate::parse("2026-12-01").unwrap(),
        },
    ] {
        let suspended = user(
            "pilotusera",
            UserStatus::Suspended {
                reason,
                since: secs(now),
            },
            None,
        );
        let made = make_up(&ledger, &suspended, days(7), now + HOUR).unwrap();
        assert_eq!(made.suspended, Some(reason));
        assert_eq!(
            made.record.gift,
            period(now + 30 * DAY, now + 37 * DAY, 100)
        );
    }
}

/// A period that would end after 9999-12-31 is refused; one that ends at
/// its last second is recorded, and read back.
#[test]
fn a_period_beyond_the_calendar_is_refused() {
    let now = NOW.as_secs();
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let edge = user("pilotusera", UserStatus::Active, Some(LAST_SECOND - DAY));
    let made = make_up(&ledger, &edge, days(1), now).unwrap();
    assert_eq!(
        made.record.gift,
        period(LAST_SECOND - DAY, LAST_SECOND, 100)
    );
    let bytes = made.ledger.encode().unwrap();
    assert_eq!(PaymentLedger::decode(&bytes).unwrap(), made.ledger);
    let past = user(
        "pilotusera",
        UserStatus::Active,
        Some(LAST_SECOND - DAY + 1),
    );
    assert_eq!(
        make_up(&ledger, &past, days(1), now),
        Err(MakeUpRefusal::BeyondCalendar)
    );
    assert_eq!(
        make_up(&ledger, &user_a(), MakeUpAsk::Days(NonZeroU32::MAX), now),
        Err(MakeUpRefusal::BeyondCalendar)
    );
}

/// Make-ups are numbered from 1, one more for each, across users; a number
/// is never given again, not even once its make-up went with its user; and
/// a ledger that has given the last number there is gives no other.
#[test]
fn each_make_up_is_numbered_once() {
    let now = NOW.as_secs();
    let (a, b) = (user_a(), user_b());
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::pack(A, "pilotusera").grant(1),
        now,
    );
    let first = make_up(&ledger, &a, traffic(1), now).unwrap();
    let second = make_up(&first.ledger, &b, traffic(2), now).unwrap();
    let third = make_up(&second.ledger, &a, traffic(3), now).unwrap();
    assert_eq!(
        [
            first.record.number,
            second.record.number,
            third.record.number
        ],
        [number(1), number(2), number(3)]
    );
    // User a goes, and their order and make-ups with them.
    let (pruned, counts) = third
        .ledger
        .without_removed_users(&holding(vec![b.clone()]))
        .unwrap();
    assert_eq!(
        counts,
        Pruned {
            users: 1,
            orders: 1,
            make_ups: 2,
        }
    );
    assert_eq!(
        pruned.make_ups().keys().copied().collect::<Vec<_>>(),
        [number(2)]
    );
    assert!(pruned.orders().is_empty());
    assert_eq!(pruned.last_make_up(), 3);
    assert_eq!(
        pruned.without_removed_users(&holding(vec![b.clone()])),
        None
    );
    assert_eq!(
        third
            .ledger
            .without_removed_users(&holding(vec![a, b.clone()])),
        None
    );
    let fourth = make_up(&pruned, &b, traffic(4), now).unwrap();
    assert_eq!(fourth.record.number, number(4));
    // A make-up alone goes with its user too.
    assert_eq!(
        second
            .ledger
            .without_removed_users(&holding(vec![user_a()]))
            .unwrap()
            .1,
        Pruned {
            users: 1,
            orders: 0,
            make_ups: 1,
        }
    );
    // The last number there is.
    let mut file: Value = serde_json::from_slice(&pruned.encode().unwrap()).unwrap();
    file["last_make_up"] = json!(u64::MAX - 1);
    let one_left = PaymentLedger::decode(&serde_json::to_vec(&file).unwrap()).unwrap();
    let last = make_up(&one_left, &b, traffic(4), now).unwrap();
    assert_eq!(last.record.number.get(), u64::MAX);
    assert_eq!(last.ledger.last_make_up(), u64::MAX);
    assert_eq!(
        make_up(&last.ledger, &b, traffic(4), now),
        Err(MakeUpRefusal::NumbersSpent)
    );
}

/// Traffic counts in the billing cycle it is given in and in no other, on
/// top of the quota that applies, as a pack does; whatever the rehearsal.
#[test]
fn traffic_counts_in_its_billing_cycle_alone() {
    let now = NOW.as_secs();
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let made = make_up(&ledger, &user_a(), traffic(20), now + HOUR).unwrap();
    assert_eq!(made.record.gift, MakeUpGift::Traffic { bytes: bytes(20) });
    assert_eq!(made.ledger.take_backs().make_up_period(&made.record), None);
    // The next cycle starts on 2027-01-01, within the month.
    let next = cycle(NOW).ends_at().as_secs();
    assert!(next < now + 30 * DAY);
    for rehearsal in [false, true] {
        let paid = made.ledger.entitlements(rehearsal);
        assert_eq!(
            paid.user(&id("pilotusera")).unwrap().packs(),
            [PaidPack {
                granted: Granted::MakeUp(number(1)),
                granted_at: secs(now + HOUR),
                bytes: bytes(20),
                livemode: true,
                refund: None,
            }]
        );
        let quota_at = |at: u64| {
            effective_policy(&user_a(), None, &paid, cycle(secs(at)), secs(at), None)
                .quota
                .map(|quota| quota.cycle_served_bytes.get())
        };
        assert_eq!(quota_at(now + HOUR), Some(120 * GB));
        assert_eq!(quota_at(next - 1), Some(120 * GB));
        assert_eq!(quota_at(next), Some(100 * GB));
    }
}

/// A refund in full moves a make-up's period earlier as it moves any
/// period that follows the time it takes back, and the periods that follow
/// the make-up with it; the next make-up builds on the moved ones, with the
/// quota of the period that ends last, which may be a make-up's.
#[test]
fn a_refund_in_full_moves_a_make_up_and_what_follows_it() {
    let now = NOW.as_secs();
    let a = user_a();
    let (first, second) = (month_of(A, 100), month_of(B, 200));
    let (ledger, _) = step(&PaymentLedger::new(), first.grant(1), now);
    let (ledger, _) = step(&ledger, second.grant(2), now);
    let ledger = make_up(&ledger, &a, days(7), now + HOUR).unwrap().ledger;
    assert_eq!(
        made_up_span(&ledger, 1),
        span(now + 60 * DAY, now + 67 * DAY)
    );
    // The 200 GB month is refunded in full before it began: the make-up
    // that followed it moves to where it would have begun.
    let (ledger, event) = step(
        &ledger,
        recorded(second.refund(3, 800, true), now + 2 * HOUR),
        now + 2 * HOUR,
    );
    assert_eq!(
        event,
        LedgerEvent::Refunded {
            order: order(B),
            amount_refunded: 800,
            in_full: true,
            granted: true,
            effect: RefundEffect::Time(TimeTakenBack {
                from: secs(now + 30 * DAY),
                until: secs(now + 60 * DAY),
                moved: vec![Granted::MakeUp(number(1))],
            }),
        }
    );
    assert_eq!(
        made_up_span(&ledger, 1),
        span(now + 30 * DAY, now + 37 * DAY)
    );
    // The next make-up follows it, with its quota.
    let made = make_up(&ledger, &a, days(2), now + 3 * HOUR).unwrap();
    assert_eq!(made.record.after, 3);
    assert_eq!(
        made.record.gift,
        period(now + 37 * DAY, now + 39 * DAY, 200)
    );
    // The first month is refunded in full ten days in: the refunded month,
    // both make-ups and what follows them move as much earlier.
    let (ledger, _) = step(&made.ledger, month_of(C, 100).grant(4), now + 3 * HOUR);
    assert_eq!(order_span(&ledger, C), span(now + 39 * DAY, now + 69 * DAY));
    let (ledger, event) = step(
        &ledger,
        recorded(first.refund(5, 800, true), now + 10 * DAY),
        now + 10 * DAY,
    );
    assert_eq!(
        event,
        LedgerEvent::Refunded {
            order: order(A),
            amount_refunded: 800,
            in_full: true,
            granted: true,
            effect: RefundEffect::Time(TimeTakenBack {
                from: secs(now + 10 * DAY),
                until: secs(now + 30 * DAY),
                moved: vec![
                    Granted::Order(order(B)),
                    Granted::Order(order(C)),
                    Granted::MakeUp(number(1)),
                    Granted::MakeUp(number(2)),
                ],
            }),
        }
    );
    assert_eq!(
        made_up_span(&ledger, 1),
        span(now + 10 * DAY, now + 17 * DAY)
    );
    assert_eq!(
        made_up_span(&ledger, 2),
        span(now + 17 * DAY, now + 19 * DAY)
    );
    assert_eq!(order_span(&ledger, C), span(now + 19 * DAY, now + 49 * DAY));
    let paid = ledger.entitlements(false);
    let own = paid.user(&id("pilotusera")).unwrap();
    assert_eq!(own.paid_until(), Some(secs(now + 49 * DAY)));
    assert_eq!(
        own.period_at(secs(now + 18 * DAY)).unwrap().granted,
        Granted::MakeUp(number(2))
    );
}

/// A make-up made after a refund stays where it was made, even where it
/// starts at the refunded period's old end: it followed the user's own
/// expiry, which the refund leaves as it was. A rehearsal's refund never
/// moves a make-up.
#[test]
fn a_make_up_after_the_refund_or_behind_a_rehearsal_stays() {
    let now = NOW.as_secs();
    let month = Terms::month(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), month.grant(1), now);
    let (ledger, _) = step(
        &ledger,
        recorded(month.refund(2, 800, true), now + 5 * DAY),
        now + 5 * DAY,
    );
    assert_eq!(order_span(&ledger, A), span(now, now + 5 * DAY));
    let own = user("pilotusera", UserStatus::Active, Some(now + 30 * DAY));
    let ledger = make_up(&ledger, &own, days(7), now + 6 * DAY)
        .unwrap()
        .ledger;
    assert_eq!(
        made_up_span(&ledger, 1),
        span(now + 30 * DAY, now + 37 * DAY)
    );
    // A rehearsal's month that ends where a make-up starts, refunded in
    // full: the make-up stays, as a live period does.
    let rehearsed = Terms::month(B, "pilotuserb");
    let ledger = rehearse(&ledger, rehearsed.grant(3), now);
    assert_eq!(order_span(&ledger, B), span(now, now + 30 * DAY));
    let (ledger, _) = step(&ledger, Terms::month(C, "pilotuserb").grant(4), now);
    assert_eq!(order_span(&ledger, C), span(now, now + 30 * DAY));
    let other = user("pilotuserb", UserStatus::Active, Some(now + 30 * DAY));
    let ledger = make_up(&ledger, &other, days(7), now + DAY).unwrap().ledger;
    assert_eq!(
        made_up_span(&ledger, 2),
        span(now + 30 * DAY, now + 37 * DAY)
    );
    let ledger = rehearse(
        &ledger,
        recorded(rehearsed.refund(5, 800, true), now + 2 * DAY),
        now + 2 * DAY,
    );
    assert_eq!(order_span(&ledger, B), span(now, now + 2 * DAY));
    assert_eq!(
        made_up_span(&ledger, 2),
        span(now + 30 * DAY, now + 37 * DAY)
    );
}

/// The ledger's file keeps each make-up as it was recorded, and the number
/// of the last; each of the make-ups' rules refuses a file that breaks it.
#[test]
fn the_ledger_file_keeps_make_ups_and_their_rules() {
    let now = NOW.as_secs();
    let a = user_a();
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let ledger = ledger
        .make_up(&a, days(7), MakeUpReason::MistakenBan, secs(now))
        .unwrap()
        .ledger;
    let ledger = ledger
        .make_up(&a, traffic(5), MakeUpReason::Unrefundable, secs(now + 60))
        .unwrap()
        .ledger;
    let written = ledger.encode().unwrap();
    assert_eq!(PaymentLedger::decode(&written).unwrap(), ledger);
    let value: Value = serde_json::from_slice(&written).unwrap();
    assert_eq!(
        value["make_ups"],
        json!([
            {
                "number": 1,
                "user": "pilotusera",
                "reason": "mistaken_ban",
                "granted_at": now,
                "after": 1,
                "gift": {"period": {
                    "from": now + 30 * DAY,
                    "until": now + 37 * DAY,
                    "quota_bytes": 100 * GB,
                }},
            },
            {
                "number": 2,
                "user": "pilotusera",
                "reason": "unrefundable",
                "granted_at": now + 60,
                "after": 1,
                "gift": {"traffic": {"bytes": 5 * GB}},
            },
        ])
    );
    assert_eq!(value["last_make_up"], json!(2));
    let unordered = "make-ups are not in number order, each once";
    let backwards = "a make-up's period does not end after it starts";
    let edits: Vec<(&str, Edit, Option<&str>)> = vec![
        (
            "order",
            Box::new(|value| value["make_ups"].as_array_mut().unwrap().swap(0, 1)),
            Some(unordered),
        ),
        (
            "twice",
            Box::new(|value| {
                let first = value["make_ups"][0].clone();
                value["make_ups"].as_array_mut().unwrap().insert(0, first);
            }),
            Some(unordered),
        ),
        (
            "after the last",
            Box::new(|value| value["last_make_up"] = json!(1)),
            Some("a make-up is numbered after the last one"),
        ),
        (
            "after the cursor",
            Box::new(|value| value["make_ups"][1]["after"] = json!(2)),
            Some("a make-up follows an entry after the cursor"),
        ),
        (
            "backwards",
            Box::new(|value| {
                value["make_ups"][0]["gift"]["period"]["until"] =
                    value["make_ups"][0]["gift"]["period"]["from"].clone();
            }),
            Some(backwards),
        ),
        (
            "past the calendar",
            Box::new(|value| {
                value["make_ups"][0]["gift"]["period"]["until"] = json!(LAST_SECOND + 1);
            }),
            Some(backwards),
        ),
        (
            "number zero",
            Box::new(|value| value["make_ups"][0]["number"] = json!(0)),
            None,
        ),
        (
            "quota zero",
            Box::new(|value| value["make_ups"][0]["gift"]["period"]["quota_bytes"] = json!(0)),
            None,
        ),
        (
            "traffic zero",
            Box::new(|value| value["make_ups"][1]["gift"]["traffic"]["bytes"] = json!(0)),
            None,
        ),
        (
            "unknown reason",
            Box::new(|value| value["make_ups"][0]["reason"] = json!("goodwill")),
            None,
        ),
        (
            "unknown gift",
            Box::new(|value| value["make_ups"][1]["gift"] = json!({"days": {"days": 3}})),
            None,
        ),
        (
            "unknown key",
            Box::new(|value| value["make_ups"][0]["note"] = json!(1)),
            None,
        ),
        (
            "unknown key of a gift",
            Box::new(|value| value["make_ups"][1]["gift"]["traffic"]["note"] = json!(1)),
            None,
        ),
        (
            "missing key",
            Box::new(|value| {
                value["make_ups"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("after");
            }),
            None,
        ),
        (
            "no last number",
            Box::new(|value| {
                value.as_object_mut().unwrap().remove("last_make_up");
            }),
            None,
        ),
        (
            "no make-ups",
            Box::new(|value| {
                value.as_object_mut().unwrap().remove("make_ups");
            }),
            None,
        ),
    ];
    for (name, edit, rule) in edits {
        let mut broken = value.clone();
        edit(&mut broken);
        let refused = PaymentLedger::decode(&serde_json::to_vec(&broken).unwrap());
        match rule {
            Some(rule) => assert!(
                matches!(refused, Err(LedgerError::Inconsistent { what }) if what == rule),
                "{name}: {refused:?}"
            ),
            None => assert!(
                matches!(refused, Err(LedgerError::Decode(_))),
                "{name}: {refused:?}"
            ),
        }
    }
}

/// An edit of a ledger document.
type Edit = Box<dyn Fn(&mut Value)>;

/// A reason is written as its own name, and a make-up and what gave a
/// period are named as the operator reads them.
#[test]
fn reasons_and_names_are_fixed() {
    let reasons = [
        MakeUpReason::Outage,
        MakeUpReason::MistakenCut,
        MakeUpReason::Unrefundable,
        MakeUpReason::MistakenBan,
    ];
    assert_eq!(
        reasons.map(MakeUpReason::as_str),
        ["outage", "mistaken_cut", "unrefundable", "mistaken_ban"]
    );
    for reason in reasons {
        assert_eq!(
            serde_json::to_value(reason).unwrap(),
            json!(reason.as_str())
        );
    }
    assert_eq!(number(12).to_string(), "12");
    assert_eq!(Granted::MakeUp(number(12)).to_string(), "make-up 12");
    assert_eq!(Granted::Order(order(A)).to_string(), format!("order {A}"));
}

/// The daemon decides a make-up against the deployment: a user it does not
/// hold is unknown, and the ledger's refusals come next. Traffic goes only
/// to a user who has a quota now: their own, their paid period's, a
/// rehearsal's period's while the operator rehearses, or the automatic
/// one; it is refused when the quota cannot be computed. Days need no
/// quota now.
#[test]
fn the_daemon_decides_a_make_up_against_the_deployment() {
    let now = NOW.as_secs();
    let decided = |ledger: &PaymentLedger,
                   deployment: &Deployment,
                   rehearsal: bool,
                   ask: MakeUpAsk,
                   at: u64| {
        decide(
            ledger,
            deployment,
            rehearsal,
            &id("pilotusera"),
            ask,
            MakeUpReason::MistakenCut,
            secs(at),
        )
    };
    let none = PaymentLedger::new();
    let plain = holding(vec![user_a(), user_b()]);
    // A user the deployment does not hold.
    assert_eq!(
        decided(&none, &holding(vec![user_b()]), false, traffic(5), now),
        Err(MakeUpRefusal::UnknownUser)
    );
    // The ledger's refusals, before the quota is looked at.
    let revoked = holding(vec![user(
        "pilotusera",
        UserStatus::Revoked { since: secs(now) },
        None,
    )]);
    assert_eq!(
        decided(&none, &revoked, false, traffic(5), now),
        Err(MakeUpRefusal::UserRevoked)
    );
    assert_eq!(
        decided(&none, &plain, false, days(7), now),
        Err(MakeUpRefusal::NoPaidPeriod)
    );
    // No quota now: none of their own, no paid period, no automatic one.
    assert_eq!(
        decided(&none, &plain, false, traffic(5), now),
        Err(MakeUpRefusal::NoQuota)
    );
    // Their own quota.
    let mut own = user_a();
    own.policy.quota = Some(quota(50));
    let made = decided(&none, &holding(vec![own.clone()]), false, traffic(5), now).unwrap();
    assert_eq!(
        made,
        none.make_up(&own, traffic(5), MakeUpReason::MistakenCut, NOW)
            .unwrap()
    );
    // A paid period's, until it ends.
    let (paid, _) = step(&none, Terms::month(A, "pilotusera").grant(1), now);
    assert!(decided(&paid, &plain, false, traffic(5), now).is_ok());
    assert!(decided(&paid, &plain, false, days(7), now).is_ok());
    assert_eq!(
        decided(&paid, &plain, false, traffic(5), now + 30 * DAY),
        Err(MakeUpRefusal::NoQuota)
    );
    // A rehearsal's period's, while the operator rehearses.
    let rehearsed = rehearse(&none, Terms::month(A, "pilotusera").grant(1), now);
    assert_eq!(
        decided(&rehearsed, &plain, false, traffic(5), now),
        Err(MakeUpRefusal::NoQuota)
    );
    assert!(decided(&rehearsed, &plain, true, traffic(5), now).is_ok());
    // The automatic quota, from one user sharing the budget.
    let from_one = AutoQuotaPolicy {
        from_active_users: NonZeroU16::MIN,
        ..AutoQuotaPolicy::PILOT
    };
    let automatic = super::super::support::edited(|parts| {
        parts.users = vec![user_a(), user_b()];
        parts.auto_quota = Some(from_one);
    });
    assert!(decided(&none, &automatic, false, traffic(5), now).is_ok());
    // A quota that cannot be computed: a suspension for quota after now.
    let unknown = super::super::support::edited(|parts| {
        let since = secs(now + 1);
        let reason = SuspendReason::QuotaExceeded {
            cycle_start: cycle(since).start(),
        };
        parts.users = vec![
            user_a(),
            user("pilotuserb", UserStatus::Suspended { reason, since }, None),
        ];
        parts.auto_quota = Some(from_one);
    });
    assert_eq!(
        decided(&none, &unknown, false, traffic(5), now),
        Err(MakeUpRefusal::QuotaUnknown)
    );
    // Nor in the last month of the calendar, whose cycle ends beyond it.
    assert_eq!(
        decided(
            &none,
            &holding(vec![own]),
            false,
            traffic(5),
            LAST_SECOND - DAY
        ),
        Err(MakeUpRefusal::QuotaUnknown)
    );
}
