// SPDX-License-Identifier: GPL-3.0-or-later

//! What a refund in full takes back (design §9.6; the operator's decision
//! of 2026-11-12): from the time the portal recorded it, the time and the
//! traffic the order gave that the user had not used yet. A period stops
//! there and the periods that followed it move as much earlier. A pack's
//! refund waits for the usage, the pack counting in full meanwhile; once
//! the usage tells the user's use at the refund's time, the pack keeps only
//! what the user had used of it beyond the rest of their quota, and when
//! its cycle ends first nothing is taken back. A partial refund takes
//! nothing; the ledger's earlier versions are lifted.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::num::NonZeroU64;

use mooring_model::{
    BillDay, CycleRule, QuotaAction, UnixTime, User, UserId, UserQuota, UserStatus, WarnPercent,
};
use serde_json::{Value, json};

use super::{DAY, NOW, Terms, by_id, id, live, order, secs, user};
use crate::payments::{
    LedgerError, LedgerEvent, PackRefund, PackUse, PaymentLedger, RefundEffect, Settlement,
    TimeTakenBack,
};
use crate::period::BillingCycle;
use crate::policy::effective_policy;

const GB: u64 = 1_000_000_000;
const HOUR: u64 = 3600;
const A: &str = "aaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccc";
const D: &str = "dddddddddddddddddddd";
const E: &str = "eeeeeeeeeeeeeeeeeeee";

/// The billing cycle `at` is in, on monthly cycles from the 1st: NOW's
/// runs to 2027-01-01.
fn cycle(at: UnixTime) -> BillingCycle {
    BillingCycle::of_instant(
        CycleRule::Monthly {
            bill_day: BillDay::new(1).unwrap(),
        },
        at,
    )
    .unwrap()
}

/// A quota of `gigabytes` that suspends.
fn quota(gigabytes: u64) -> UserQuota {
    UserQuota {
        cycle_served_bytes: NonZeroU64::new(gigabytes * GB).unwrap(),
        warn_percent: WarnPercent::new(80).unwrap(),
        action: QuotaAction::Suspend,
    }
}

/// `entry`, recorded by the portal at `at`.
fn recorded(mut entry: Value, at: u64) -> Value {
    entry["recorded_at"] = json!(at);
    entry
}

fn users() -> BTreeMap<UserId, User> {
    by_id(vec![
        user("pilotusera", UserStatus::Active, None),
        user("pilotuserb", UserStatus::Active, None),
    ])
}

/// `ledger` with `entry` applied at `at`, live, for `users`; and what the
/// entry did.
fn step_for(
    ledger: &PaymentLedger,
    users: &BTreeMap<UserId, User>,
    entry: Value,
    at: u64,
) -> (PaymentLedger, LedgerEvent) {
    let mut applied = ledger
        .apply(&live(ledger.cursor(), vec![entry]), users, secs(at), false)
        .unwrap();
    (applied.ledger, applied.events.remove(0))
}

/// [`step_for`] for [`users`].
fn step(ledger: &PaymentLedger, entry: Value, at: u64) -> (PaymentLedger, LedgerEvent) {
    step_for(ledger, &users(), entry, at)
}

/// What settling `ledger` at `at` records when the usage tells that every
/// user asked about had served `served` GB by the instant asked about
/// (`None`: it cannot tell).
fn settle(ledger: &PaymentLedger, at: u64, served: Option<u64>) -> Option<Settlement> {
    ledger.settle(secs(at), cycle(secs(at)), &|_, _| {
        served.map(|gigabytes| gigabytes * GB)
    })
}

/// `ledger` settled at `at` with `served` GB told ([`settle`]).
fn settled(ledger: &PaymentLedger, at: u64, served: u64) -> PaymentLedger {
    settle(ledger, at, Some(served)).unwrap().ledger
}

/// A use of `gigabytes` GB, learned at `at`.
fn served(gigabytes: u64, at: u64) -> PackUse {
    PackUse::Served {
        bytes: gigabytes * GB,
        learned_at: secs(at),
    }
}

fn refunded(text: &str, amount: u64, in_full: bool, effect: RefundEffect) -> LedgerEvent {
    LedgerEvent::Refunded {
        order: order(text),
        amount_refunded: amount,
        in_full,
        granted: true,
        effect,
    }
}

fn taken(from: u64, until: u64, moved: &[&str]) -> RefundEffect {
    RefundEffect::Time(TimeTakenBack {
        from: secs(from),
        until: secs(until),
        moved: moved.iter().map(|text| order(text)).collect(),
    })
}

fn span(from: u64, until: u64) -> Option<(UnixTime, UnixTime)> {
    Some((secs(from), secs(until)))
}

/// How the period of `ledger`'s order `text` counts after the refunds in
/// full.
fn counted(ledger: &PaymentLedger, text: &str) -> Option<(UnixTime, UnixTime)> {
    ledger.take_backs().period(&ledger.orders()[&order(text)])
}

/// A refund in full takes back the rest of a running period from the time
/// the portal recorded it: the period ends then, its quota with it, and the
/// user, who had no expiry of their own, expires then. A partial refund
/// before it, and a second refund in full after it, take nothing.
#[test]
fn a_refund_in_full_takes_back_the_rest_of_a_running_period() {
    let now = NOW.as_secs();
    let month = Terms::month(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), month.grant(1), now);
    let (ledger, partial) = step(
        &ledger,
        recorded(month.refund(2, 300, false), now + DAY),
        now + DAY + 60,
    );
    assert_eq!(partial, refunded(A, 300, false, RefundEffect::Nothing));
    assert_eq!(counted(&ledger, A), span(now, now + 30 * DAY));
    let (ledger, full) = step(
        &ledger,
        recorded(month.refund(3, 800, true), now + 10 * DAY),
        now + 10 * DAY + 60,
    );
    assert_eq!(
        full,
        refunded(A, 800, true, taken(now + 10 * DAY, now + 30 * DAY, &[]))
    );
    assert_eq!(
        ledger.take_backs().effect(3),
        taken(now + 10 * DAY, now + 30 * DAY, &[])
    );
    assert_eq!(ledger.take_backs().effect(2), RefundEffect::Nothing);
    let paid = ledger.entitlements(false);
    let a = paid.user(&id("pilotusera")).unwrap();
    assert_eq!(a.paid_until(), Some(secs(now + 10 * DAY)));
    assert!(a.period_at(secs(now + 10 * DAY - 1)).is_some());
    assert!(a.period_at(secs(now + 10 * DAY)).is_none());
    // The automatic quota applies again, and the user expires at the
    // refund's time.
    let automatic = quota(19);
    let pilot = &users()[&id("pilotusera")];
    let later = secs(now + 11 * DAY);
    let policy = effective_policy(pilot, Some(automatic), &paid, cycle(later), later);
    assert_eq!(policy.quota, Some(automatic));
    assert_eq!(policy.expires_at, Some(secs(now + 10 * DAY)));
    let (_, again) = step(
        &ledger,
        recorded(month.refund(4, 900, true), now + 12 * DAY),
        now + 12 * DAY,
    );
    assert_eq!(again, refunded(A, 900, true, RefundEffect::Nothing));
}

/// The periods that followed a refunded period move as much earlier, so no
/// gap opens: the renewal stacked on it, and the one stacked on that. Another
/// user's period that starts where it ended stays, and a new period follows
/// the moved ones.
#[test]
fn the_periods_that_followed_a_refunded_period_move_as_much_earlier() {
    let now = NOW.as_secs();
    let mut users = users();
    // User b's own expiry is where a's first month ends: b's month starts
    // there.
    users.get_mut(&id("pilotuserb")).unwrap().policy.expires_at = Some(secs(now + 30 * DAY));
    let mut ledger = PaymentLedger::new();
    for (seq, (text, buyer, at)) in [
        (A, "pilotusera", now),
        (B, "pilotusera", now + DAY),
        (C, "pilotusera", now + 2 * DAY),
        (D, "pilotuserb", now + 3 * DAY),
    ]
    .into_iter()
    .enumerate()
    {
        let seq = u64::try_from(seq).unwrap() + 1;
        ledger = step_for(&ledger, &users, Terms::month(text, buyer).grant(seq), at).0;
    }
    assert_eq!(counted(&ledger, B), span(now + 30 * DAY, now + 60 * DAY));
    assert_eq!(counted(&ledger, D), span(now + 30 * DAY, now + 60 * DAY));
    let (ledger, event) = step_for(
        &ledger,
        &users,
        recorded(
            Terms::month(A, "pilotusera").refund(5, 800, true),
            now + 10 * DAY,
        ),
        now + 10 * DAY + 60,
    );
    assert_eq!(
        event,
        refunded(A, 800, true, taken(now + 10 * DAY, now + 30 * DAY, &[B, C]))
    );
    assert_eq!(counted(&ledger, A), span(now, now + 10 * DAY));
    assert_eq!(counted(&ledger, B), span(now + 10 * DAY, now + 40 * DAY));
    assert_eq!(counted(&ledger, C), span(now + 40 * DAY, now + 70 * DAY));
    assert_eq!(counted(&ledger, D), span(now + 30 * DAY, now + 60 * DAY));
    let paid = ledger.entitlements(false);
    assert_eq!(
        paid.user(&id("pilotusera")).unwrap().paid_until(),
        Some(secs(now + 70 * DAY))
    );
    // A month bought after the refund follows the moved ones.
    let (ledger, _) = step_for(
        &ledger,
        &users,
        Terms::month(E, "pilotusera").grant(6),
        now + 11 * DAY,
    );
    assert_eq!(counted(&ledger, E), span(now + 70 * DAY, now + 100 * DAY));
}

/// A period granted after the refund stays where it was granted, even
/// where it starts at the refunded period's old end: it followed the
/// user's own expiry, which the refund leaves as it was.
#[test]
fn a_period_granted_after_the_refund_stays() {
    let now = NOW.as_secs();
    let mut users = users();
    let (ledger, _) = step_for(
        &PaymentLedger::new(),
        &users,
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let (ledger, _) = step_for(
        &ledger,
        &users,
        recorded(
            Terms::month(A, "pilotusera").refund(2, 800, true),
            now + 5 * DAY,
        ),
        now + 5 * DAY + 60,
    );
    users.get_mut(&id("pilotusera")).unwrap().policy.expires_at = Some(secs(now + 30 * DAY));
    let (ledger, _) = step_for(
        &ledger,
        &users,
        Terms::month(B, "pilotusera").grant(3),
        now + 6 * DAY,
    );
    assert_eq!(counted(&ledger, A), span(now, now + 5 * DAY));
    assert_eq!(counted(&ledger, B), span(now + 30 * DAY, now + 60 * DAY));
}

/// A period that had ended before the refund loses nothing; one refunded
/// before it began loses all of its time, still ends the user's paid time
/// where it would have begun, and the period that followed it moves to its
/// start.
#[test]
fn a_period_ended_loses_nothing_and_one_not_begun_loses_all() {
    let now = NOW.as_secs();
    let (ledger, _) = step(
        &PaymentLedger::new(),
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let (ledger, event) = step(
        &ledger,
        recorded(
            Terms::month(A, "pilotusera").refund(2, 800, true),
            now + 31 * DAY,
        ),
        now + 31 * DAY,
    );
    assert_eq!(
        event,
        refunded(A, 800, true, taken(now + 30 * DAY, now + 30 * DAY, &[]))
    );
    assert_eq!(counted(&ledger, A), span(now, now + 30 * DAY));
    // User b: a month, a renewal queued after it, and one after that; the
    // first renewal is refunded in full before it begins.
    let (ledger, _) = step(&ledger, Terms::month(B, "pilotuserb").grant(3), now);
    let (ledger, _) = step(&ledger, Terms::month(C, "pilotuserb").grant(4), now + DAY);
    let (ledger, _) = step(
        &ledger,
        Terms::month(D, "pilotuserb").grant(5),
        now + 2 * DAY,
    );
    let (ledger, event) = step(
        &ledger,
        recorded(
            Terms::month(C, "pilotuserb").refund(6, 800, true),
            now + 5 * DAY,
        ),
        now + 5 * DAY,
    );
    assert_eq!(
        event,
        refunded(C, 800, true, taken(now + 30 * DAY, now + 60 * DAY, &[D]))
    );
    assert_eq!(counted(&ledger, C), span(now + 30 * DAY, now + 30 * DAY));
    assert_eq!(counted(&ledger, D), span(now + 30 * DAY, now + 60 * DAY));
    // A user's only month refunded before Mooring granted it: no time, and
    // the user, with no expiry of their own, is on paid time that has
    // ended, never on unlimited time.
    let (ledger, _) = step(
        &ledger,
        Terms::month(E, "pilotusera").grant(7),
        now + 40 * DAY,
    );
    let (ledger, event) = step(
        &ledger,
        recorded(
            Terms::month(E, "pilotusera").refund(8, 800, true),
            now + 39 * DAY,
        ),
        now + 40 * DAY + 60,
    );
    assert_eq!(
        event,
        refunded(E, 800, true, taken(now + 40 * DAY, now + 70 * DAY, &[]))
    );
    let paid = ledger.entitlements(false);
    let pilot = &users()[&id("pilotusera")];
    let later = secs(now + 41 * DAY);
    assert_eq!(
        effective_policy(pilot, None, &paid, cycle(later), later).expires_at,
        Some(secs(now + 40 * DAY))
    );
}

/// A test-mode period may follow a live one, so it moves with it; a live
/// period never builds on a test-mode one, so a rehearsal's refund never
/// moves real time, even where a live period starts at the test-mode one's
/// end.
#[test]
fn a_rehearsals_refund_never_moves_real_time() {
    let now = NOW.as_secs();
    let mut users = users();
    let rehearse =
        |ledger: &PaymentLedger, users: &BTreeMap<UserId, User>, entry: Value, at: u64| {
            let page = super::decode(
                &super::document(false, ledger.cursor(), vec![entry], false),
                ledger.cursor(),
            )
            .unwrap();
            ledger.apply(&page, users, secs(at), true).unwrap().ledger
        };
    // User a: a live month, then a rehearsal's month after it.
    let (ledger, _) = step_for(
        &PaymentLedger::new(),
        &users,
        Terms::month(A, "pilotusera").grant(1),
        now,
    );
    let ledger = rehearse(
        &ledger,
        &users,
        Terms::month(B, "pilotusera").grant(2),
        now + DAY,
    );
    // User b: a rehearsal's month, then a live one that starts at its end
    // because b's own expiry is there.
    let ledger = rehearse(&ledger, &users, Terms::month(C, "pilotuserb").grant(3), now);
    users.get_mut(&id("pilotuserb")).unwrap().policy.expires_at = Some(secs(now + 30 * DAY));
    let (ledger, _) = step_for(
        &ledger,
        &users,
        Terms::month(D, "pilotuserb").grant(4),
        now + DAY,
    );
    assert_eq!(counted(&ledger, D), span(now + 30 * DAY, now + 60 * DAY));
    // The live month's refund moves the rehearsal's month after it.
    let (ledger, event) = step_for(
        &ledger,
        &users,
        recorded(
            Terms::month(A, "pilotusera").refund(5, 800, true),
            now + 10 * DAY,
        ),
        now + 10 * DAY,
    );
    assert_eq!(
        event,
        refunded(A, 800, true, taken(now + 10 * DAY, now + 30 * DAY, &[B]))
    );
    // The rehearsal's refund leaves the live month where it is.
    let mut refund = Terms::month(C, "pilotuserb").refund(6, 800, true);
    refund["recorded_at"] = json!(now + 10 * DAY);
    let ledger = rehearse(&ledger, &users, refund, now + 10 * DAY);
    let take_backs = ledger.take_backs();
    assert_eq!(counted(&ledger, C), span(now, now + 10 * DAY));
    assert_eq!(counted(&ledger, D), span(now + 30 * DAY, now + 60 * DAY));
    assert_eq!(
        take_backs.effect(6),
        taken(now + 10 * DAY, now + 30 * DAY, &[])
    );
}

/// The ledger with user a's 50 GB pack granted at `granted` and refunded in
/// full, recorded at `refunded_at` and applied a minute later; and what the
/// refund did.
fn pack_refunded(granted: u64, refunded_at: u64) -> (PaymentLedger, LedgerEvent) {
    let pack = Terms::pack(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), granted);
    step(
        &ledger,
        recorded(pack.refund(2, 800, true), refunded_at),
        refunded_at + 60,
    )
}

/// The use each refund of `ledger`'s order `text` records.
fn uses(ledger: &PaymentLedger, text: &str) -> Vec<Option<PackUse>> {
    ledger.orders()[&order(text)]
        .refunds
        .iter()
        .map(|refund| refund.pack_use)
        .collect()
}

/// User a's quota at `at` (GB), with an automatic quota of 100 GB and what
/// `ledger` gives.
fn quota_at(ledger: &PaymentLedger, at: u64) -> u64 {
    let pilot = &users()[&id("pilotusera")];
    let at = secs(at);
    effective_policy(
        pilot,
        Some(quota(100)),
        &ledger.entitlements(false),
        cycle(at),
        at,
    )
    .quota
    .unwrap()
    .cycle_served_bytes
    .get()
        / GB
}

/// A refund in full of a pack waits for the usage: the ledger records it
/// so, and the pack counts in full while it waits, before the refund's time
/// and after it, so that nothing the user used is taken back. A partial
/// refund, a second refund in full and a month's refund record no use, and
/// settling leaves them as they are.
#[test]
fn a_refund_in_full_of_a_pack_waits_for_the_usage() {
    let now = NOW.as_secs();
    let refund = now + 2 * HOUR;
    let (ledger, event) = pack_refunded(now, refund);
    assert_eq!(
        event,
        refunded(A, 800, true, RefundEffect::Pack(PackUse::Awaiting))
    );
    assert_eq!(uses(&ledger, A), [Some(PackUse::Awaiting)]);
    assert_eq!(
        ledger.take_backs().effect(2),
        RefundEffect::Pack(PackUse::Awaiting)
    );
    let waiting: Vec<_> = ledger
        .awaiting_usage()
        .map(|record| record.order.clone())
        .collect();
    assert_eq!(waiting, [order(A)]);
    let paid = ledger.entitlements(false);
    let pack = &paid.users()[&id("pilotusera")].packs()[0];
    assert_eq!(
        pack.refund,
        Some(PackRefund {
            at: secs(refund),
            used: PackUse::Awaiting
        })
    );
    assert_eq!(pack.taken_back_by(secs(refund + DAY)), None);
    for at in [
        refund - 1,
        refund,
        refund + 60,
        refund + 3 * HOUR,
        now + 20 * DAY,
    ] {
        assert_eq!(quota_at(&ledger, at), 150, "{at}");
    }
    // Only the first refund in full, of a pack, records a use.
    let pack = Terms::pack(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), now);
    let (ledger, partial) = step(&ledger, pack.refund(2, 300, false), now + HOUR);
    assert_eq!(partial, refunded(A, 300, false, RefundEffect::Nothing));
    let (ledger, _) = step(&ledger, pack.refund(3, 800, true), now + HOUR);
    let (ledger, again) = step(&ledger, pack.refund(4, 900, true), now + HOUR);
    assert_eq!(again, refunded(A, 900, true, RefundEffect::Nothing));
    let month = Terms::month(B, "pilotusera");
    let (ledger, _) = step(&ledger, month.grant(5), now);
    let (ledger, _) = step(&ledger, month.refund(6, 800, true), now + HOUR);
    assert_eq!(uses(&ledger, A), [None, Some(PackUse::Awaiting), None]);
    assert_eq!(uses(&ledger, B), [None]);
    let ledger = settled(&ledger, now + 2 * HOUR, 120);
    assert_eq!(
        uses(&ledger, A),
        [None, Some(served(120, now + 2 * HOUR)), None]
    );
    assert_eq!(uses(&ledger, B), [None]);
}

/// Once the usage tells the user's use at the refund's time, the ledger
/// records it with when Mooring learned it, and from then on the pack keeps
/// only what the user had used of it beyond the rest of their quota
/// (100 GB): 20 GB of 50 for 120 GB used, none for 80, 100 or nothing, all
/// of it for 200. Until then it counts in full. The usage is asked once,
/// about the pack's user at the time the portal recorded the refund; while
/// it cannot tell, nothing is recorded.
#[test]
fn the_use_at_the_refund_is_recorded_once_the_usage_tells_it() {
    let now = NOW.as_secs();
    let refund = now + 2 * HOUR;
    let learned = refund + 3 * HOUR;
    let (ledger, _) = pack_refunded(now, refund);
    assert_eq!(settle(&ledger, refund + 60, None), None);
    for (used, after) in [(120, 120), (80, 100), (100, 100), (200, 150), (0, 100)] {
        let asked = RefCell::new(Vec::new());
        let settlement = ledger
            .settle(secs(learned), cycle(secs(learned)), &|user, at| {
                asked.borrow_mut().push((user.clone(), at));
                Some(used * GB)
            })
            .unwrap();
        assert_eq!(asked.into_inner(), [(id("pilotusera"), secs(refund))]);
        assert_eq!(
            settlement.events,
            [LedgerEvent::Settled {
                order: order(A),
                used: served(used, learned)
            }]
        );
        let ledger = settlement.ledger;
        assert_eq!(uses(&ledger, A), [Some(served(used, learned))]);
        assert_eq!(
            ledger.take_backs().effect(2),
            RefundEffect::Pack(served(used, learned))
        );
        assert_eq!(ledger.awaiting_usage().count(), 0);
        assert_eq!(settle(&ledger, learned + HOUR, Some(999)), None);
        assert_eq!(quota_at(&ledger, refund - 1), 150, "{used}");
        assert_eq!(quota_at(&ledger, learned - 1), 150, "{used}");
        assert_eq!(quota_at(&ledger, learned), after, "{used}");
        assert_eq!(quota_at(&ledger, learned + 3 * HOUR), after, "{used}");
        let paid = ledger.entitlements(false);
        let pack = &paid.users()[&id("pilotusera")].packs()[0];
        assert_eq!(pack.taken_back_by(secs(learned - 1)), None);
        assert_eq!(
            pack.taken_back_by(secs(learned)),
            Some((secs(refund), used * GB))
        );
    }
}

/// A use is never recorded as learned before its refund was applied: when
/// the clock has stepped back since, it is learned when the refund was
/// applied, and the ledger reads back.
#[test]
fn a_use_is_learned_no_earlier_than_its_refund_was_applied() {
    let now = NOW.as_secs();
    let refund = now + 2 * HOUR;
    let (ledger, _) = pack_refunded(now, refund);
    let ledger = settled(&ledger, refund + 30, 120);
    assert_eq!(uses(&ledger, A), [Some(served(120, refund + 60))]);
    assert_eq!(
        PaymentLedger::decode(&ledger.encode().unwrap()).unwrap(),
        ledger
    );
    assert_eq!(quota_at(&ledger, refund + 59), 150);
    assert_eq!(quota_at(&ledger, refund + 60), 120);
}

/// A refund still waiting when its pack's billing cycle has ended takes
/// nothing back: the ledger records the cycle's end without asking the
/// usage, and the pack counted in full to the end of its cycle. In a cycle
/// before the pack's (a clock that stepped back) nothing is settled.
#[test]
fn a_refund_that_waits_past_its_cycle_takes_nothing_back() {
    let now = NOW.as_secs();
    let refund = now + 2 * HOUR;
    let (ledger, _) = pack_refunded(now, refund);
    let never = |_: &UserId, _: UnixTime| -> Option<u64> { panic!("the usage is not asked about") };
    let next_cycle = secs(now + 30 * DAY);
    let settlement = ledger
        .settle(next_cycle, cycle(next_cycle), &never)
        .unwrap();
    assert_eq!(
        settlement.events,
        [LedgerEvent::Settled {
            order: order(A),
            used: PackUse::CycleEnded
        }]
    );
    let ended = settlement.ledger;
    assert_eq!(uses(&ended, A), [Some(PackUse::CycleEnded)]);
    assert_eq!(ended.awaiting_usage().count(), 0);
    let paid = ended.entitlements(false);
    let pack = &paid.users()[&id("pilotusera")].packs()[0];
    assert_eq!(pack.taken_back_by(next_cycle), None);
    for at in [refund, refund + 3 * HOUR, now + 20 * DAY] {
        assert_eq!(quota_at(&ended, at), 150, "{at}");
    }
    // A pack counts in its own cycle only.
    assert_eq!(quota_at(&ended, now + 30 * DAY), 100);
    let earlier = secs(now - 40 * DAY);
    assert_eq!(ledger.settle(earlier, cycle(earlier), &never), None);
}

/// A pack bought later in the cycle never pays for what the user had used
/// of a refunded one. User a, on 100 GB, had used 120 GB when pack X
/// (50 GB) was refunded and the usage could not tell. While the refund
/// waits, X counts in full beside pack Y (50 GB), bought an hour later.
/// Once the usage tells the 120 GB, X keeps the 20 GB the user had used of
/// it, and Y adds all of its own.
#[test]
fn a_later_pack_never_pays_for_what_the_user_had_used_of_a_refunded_one() {
    let now = NOW.as_secs();
    let x = Terms::pack(A, "pilotusera");
    let y = Terms::pack(B, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), x.grant(1), now);
    let (ledger, event) = step(
        &ledger,
        recorded(x.refund(2, 800, true), now + 2 * HOUR),
        now + 2 * HOUR + 60,
    );
    assert_eq!(
        event,
        refunded(A, 800, true, RefundEffect::Pack(PackUse::Awaiting))
    );
    assert_eq!(quota_at(&ledger, now + 2 * HOUR + 60), 150);
    let (ledger, _) = step(&ledger, y.grant(3), now + 3 * HOUR);
    assert_eq!(quota_at(&ledger, now + 3 * HOUR), 200);
    let ledger = settled(&ledger, now + 5 * HOUR, 120);
    assert_eq!(quota_at(&ledger, now + 5 * HOUR - 1), 200);
    assert_eq!(quota_at(&ledger, now + 5 * HOUR), 170);
}

/// The rest of the quota a refunded pack is set against holds the cycle's
/// other packs granted by the refund, as they counted then; a pack granted
/// after it adds in full. Refunds count in the order they were recorded.
#[test]
fn the_rest_of_the_quota_holds_the_packs_granted_by_the_refund() {
    let now = NOW.as_secs();
    let x = Terms::pack(A, "pilotusera");
    let mut y = Terms::pack(B, "pilotusera");
    y.gigabytes = 30;
    let mut z = Terms::pack(C, "pilotusera");
    z.gigabytes = 40;
    let (ledger, _) = step(&PaymentLedger::new(), x.grant(1), now);
    let (ledger, _) = step(&ledger, y.grant(2), now + HOUR);
    // X refunded with 160 GB used: the rest is 100 + 30, so X keeps 30.
    let (ledger, _) = step(
        &ledger,
        recorded(x.refund(3, 800, true), now + 2 * HOUR),
        now + 2 * HOUR,
    );
    let ledger = settled(&ledger, now + 2 * HOUR, 160);
    assert_eq!(quota_at(&ledger, now + 2 * HOUR), 160);
    let (ledger, _) = step(&ledger, z.grant(4), now + 3 * HOUR);
    assert_eq!(quota_at(&ledger, now + 3 * HOUR), 200);
    // Y refunded with 170 GB used: the rest is 100 + X's 30 + Z's 40.
    let (ledger, _) = step(
        &ledger,
        recorded(y.refund(5, 800, true), now + 4 * HOUR),
        now + 4 * HOUR,
    );
    let ledger = settled(&ledger, now + 4 * HOUR, 170);
    assert_eq!(quota_at(&ledger, now + 4 * HOUR), 170);
    // Before Y's use was learned, X still kept its 30.
    assert_eq!(quota_at(&ledger, now + 4 * HOUR - 1), 200);
}

/// The refund that takes a pack back carries the use in the file: awaited,
/// or the bytes with when Mooring learned them. A ledger without one there,
/// with one on another refund, with a use learned before its refund was
/// applied, or with a use as version 2 wrote it, is refused.
#[test]
fn the_use_is_recorded_on_the_refund_that_takes_a_pack_back_and_no_other() {
    let now = NOW.as_secs();
    let pack = Terms::pack(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), now);
    let (ledger, _) = step(&ledger, pack.refund(2, 300, false), now + HOUR);
    let (ledger, _) = step(&ledger, pack.refund(3, 800, true), now + HOUR);
    let (ledger, _) = step(&ledger, pack.refund(4, 900, true), now + HOUR);
    let waiting = ledger.encode().unwrap();
    assert_eq!(PaymentLedger::decode(&waiting).unwrap(), ledger);
    let value: Value = serde_json::from_slice(&waiting).unwrap();
    assert_eq!(
        value["orders"][0]["refunds"][1]["pack_use"],
        json!("awaiting")
    );
    let ledger = settled(&ledger, now + 2 * HOUR, 120);
    let bytes = ledger.encode().unwrap();
    assert_eq!(PaymentLedger::decode(&bytes).unwrap(), ledger);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["orders"][0]["refunds"][1]["pack_use"],
        json!({"served": {"bytes": 120 * GB, "learned_at": now + 2 * HOUR}})
    );
    assert_eq!(value["orders"][0]["refunds"][0]["pack_use"], Value::Null);
    for (index, pack_use) in [
        (1, Value::Null),
        (0, json!("awaiting")),
        (2, json!("cycle_ended")),
        // Learned a second before the refund was applied.
        (
            1,
            json!({"served": {"bytes": 5, "learned_at": now + HOUR - 1}}),
        ),
    ] {
        let mut broken = value.clone();
        broken["orders"][0]["refunds"][index]["pack_use"] = pack_use.clone();
        assert!(
            matches!(
                PaymentLedger::decode(&serde_json::to_vec(&broken).unwrap()),
                Err(LedgerError::Inconsistent { .. })
            ),
            "{index} {pack_use}"
        );
    }
    // Learned as the refund was applied is the earliest there is.
    let mut earliest = value.clone();
    earliest["orders"][0]["refunds"][1]["pack_use"] =
        json!({"served": {"bytes": 5, "learned_at": now + HOUR}});
    assert!(PaymentLedger::decode(&serde_json::to_vec(&earliest).unwrap()).is_ok());
    for pack_use in [json!("unknown"), json!({"served": {"bytes": 5}})] {
        let mut old = value.clone();
        old["orders"][0]["refunds"][1]["pack_use"] = pack_use.clone();
        assert!(
            matches!(
                PaymentLedger::decode(&serde_json::to_vec(&old).unwrap()),
                Err(LedgerError::Decode(_))
            ),
            "{pack_use}"
        );
    }
}

/// A ledger of version 1 or 2 is read, and written as version 3. Version 1
/// recorded no use, and version 2 took a pack back whole when the usage
/// could not tell: both such refunds wait for the usage, so their packs
/// count in full again. A use version 2 recorded was learned when its
/// refund was applied, or at the refund's own time were that later; a cycle
/// that had ended stays so. Refunds in full of periods take back what they
/// do now. No other version is read.
#[test]
fn earlier_versions_of_the_ledger_are_lifted() {
    let now = NOW.as_secs();
    let pack = Terms::pack(A, "pilotusera");
    let month = Terms::month(B, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), now);
    let (ledger, _) = step(&ledger, month.grant(2), now);
    let (ledger, _) = step(&ledger, pack.refund(3, 300, false), now + HOUR);
    let (ledger, _) = step(
        &ledger,
        recorded(pack.refund(4, 800, true), now + HOUR),
        now + HOUR + 60,
    );
    let (ledger, _) = step(
        &ledger,
        recorded(month.refund(5, 800, true), now + DAY),
        now + DAY,
    );
    let current: Value = serde_json::from_slice(&ledger.encode().unwrap()).unwrap();
    let read = |value: &Value| PaymentLedger::decode(&serde_json::to_vec(value).unwrap());
    // The same ledger as version 1 wrote it: no use anywhere.
    let mut version_1 = current.clone();
    version_1["version"] = json!(1);
    for record in version_1["orders"].as_array_mut().unwrap() {
        for refund in record["refunds"].as_array_mut().unwrap() {
            refund.as_object_mut().unwrap().remove("pack_use");
        }
    }
    let lifted = read(&version_1).unwrap();
    assert_eq!(lifted, ledger);
    assert_eq!(uses(&lifted, A), [None, Some(PackUse::Awaiting)]);
    assert_eq!(uses(&lifted, B), [None]);
    assert_eq!(counted(&lifted, B), span(now, now + DAY));
    assert_eq!(quota_at(&lifted, now + 2 * HOUR), 150);
    // And as version 2 wrote it, with each use it could record.
    let mut version_2 = current.clone();
    version_2["version"] = json!(2);
    for (recorded_use, lifted_use) in [
        (json!("unknown"), PackUse::Awaiting),
        (
            json!({"served": {"bytes": 120 * GB}}),
            served(120, now + HOUR + 60),
        ),
        (json!("cycle_ended"), PackUse::CycleEnded),
    ] {
        version_2["orders"][0]["refunds"][1]["pack_use"] = recorded_use;
        let lifted = read(&version_2).unwrap();
        assert_eq!(uses(&lifted, A), [None, Some(lifted_use)]);
        assert_eq!(uses(&lifted, B), [None]);
        assert_eq!(counted(&lifted, B), span(now, now + DAY));
        let written = String::from_utf8(lifted.encode().unwrap()).unwrap();
        assert!(written.starts_with("{\n  \"version\": 3,"), "{written}");
        assert_eq!(PaymentLedger::decode(written.as_bytes()).unwrap(), lifted);
    }
    // A refund the portal dated after Mooring applied it: the use counts
    // from the refund's time, as version 2 counted it.
    version_2["orders"][0]["refunds"][1]["pack_use"] = json!({"served": {"bytes": 120 * GB}});
    version_2["orders"][0]["refunds"][1]["recorded_at"] = json!(now + 2 * HOUR);
    let lifted = read(&version_2).unwrap();
    assert_eq!(uses(&lifted, A), [None, Some(served(120, now + 2 * HOUR))]);
    assert_eq!(quota_at(&lifted, now + 2 * HOUR - 1), 150);
    assert_eq!(quota_at(&lifted, now + 2 * HOUR), 120);
    // Version 2 knew no refund that waits, and no time a use was learned.
    for pack_use in [
        json!("awaiting"),
        json!({"served": {"bytes": 5, "learned_at": now + HOUR + 60}}),
    ] {
        version_2["orders"][0]["refunds"][1]["pack_use"] = pack_use.clone();
        assert!(
            matches!(read(&version_2), Err(LedgerError::Decode(_))),
            "{pack_use}"
        );
    }
    let mut version_4 = current;
    version_4["version"] = json!(4);
    assert!(matches!(
        read(&version_4),
        Err(LedgerError::UnknownVersion { found: 4 })
    ));
}

/// Settling records what the usage can tell and leaves the rest waiting:
/// of two packs refunded in full, only the one whose user's use is told is
/// recorded; both at once come in the order of their orders' ids. A
/// rehearsal's refund is settled as a live one is.
#[test]
fn settling_records_what_the_usage_tells_and_leaves_the_rest_waiting() {
    let now = NOW.as_secs();
    let users = users();
    let live_pack = Terms::pack(B, "pilotusera");
    let test_pack = Terms::pack(A, "pilotuserb");
    let rehearse = |ledger: &PaymentLedger, entry: Value, at: u64| {
        let page = super::decode(
            &super::document(false, ledger.cursor(), vec![entry], false),
            ledger.cursor(),
        )
        .unwrap();
        ledger.apply(&page, &users, secs(at), true).unwrap().ledger
    };
    let (ledger, _) = step(&PaymentLedger::new(), live_pack.grant(1), now);
    let ledger = rehearse(&ledger, test_pack.grant(2), now);
    let (ledger, _) = step(
        &ledger,
        recorded(live_pack.refund(3, 800, true), now + HOUR),
        now + HOUR,
    );
    let ledger = rehearse(
        &ledger,
        recorded(test_pack.refund(4, 800, true), now + 2 * HOUR),
        now + 2 * HOUR,
    );
    assert_eq!(ledger.awaiting_usage().count(), 2);
    let at = now + 3 * HOUR;
    let only = |told: &'static str| {
        ledger
            .settle(secs(at), cycle(secs(at)), &|user, _| {
                (*user == id(told)).then_some(7 * GB)
            })
            .unwrap()
    };
    let rehearsal = only("pilotuserb");
    assert_eq!(
        rehearsal.events,
        [LedgerEvent::Settled {
            order: order(A),
            used: served(7, at)
        }]
    );
    assert_eq!(uses(&rehearsal.ledger, A), [Some(served(7, at))]);
    assert_eq!(uses(&rehearsal.ledger, B), [Some(PackUse::Awaiting)]);
    let live_one = only("pilotusera");
    assert_eq!(uses(&live_one.ledger, A), [Some(PackUse::Awaiting)]);
    assert_eq!(uses(&live_one.ledger, B), [Some(served(7, at))]);
    // Each refund is asked about at its own time.
    let both = ledger
        .settle(secs(at), cycle(secs(at)), &|_, refunded_at| {
            Some((refunded_at.as_secs() - now) / HOUR * GB)
        })
        .unwrap();
    assert_eq!(
        both.events,
        [
            LedgerEvent::Settled {
                order: order(A),
                used: served(2, at)
            },
            LedgerEvent::Settled {
                order: order(B),
                used: served(1, at)
            },
        ]
    );
    assert_eq!(both.ledger.awaiting_usage().count(), 0);
}

/// Refunds in full replay in the order of their entries, whatever their
/// orders' ids: the first month's refund moves the renewal earlier, and
/// the renewal's refund then cuts it where it has moved to.
#[test]
fn period_refunds_replay_in_the_order_of_their_entries() {
    let now = NOW.as_secs();
    let first = Terms::month("zzzzzzzzzzzzzzzzzzzz", "pilotusera");
    let renewal = Terms::month(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), first.grant(1), now);
    let (ledger, _) = step(&ledger, renewal.grant(2), now + DAY);
    let (ledger, _) = step(
        &ledger,
        recorded(first.refund(3, 800, true), now + 10 * DAY),
        now + 10 * DAY,
    );
    let (ledger, event) = step(
        &ledger,
        recorded(renewal.refund(4, 800, true), now + 20 * DAY),
        now + 20 * DAY,
    );
    assert_eq!(
        event,
        refunded(A, 800, true, taken(now + 20 * DAY, now + 40 * DAY, &[]))
    );
    assert_eq!(counted(&ledger, A), span(now + 10 * DAY, now + 20 * DAY));
}

/// Refunded packs count in the order their refunds were recorded, whatever
/// their orders' ids and whenever their uses were learned. Pack Q (50 GB),
/// refunded first with 120 GB used, was set against the 100 GB quota alone,
/// since pack P (30 GB) was granted after that refund, and keeps 20; P,
/// refunded later with 170 GB used, is set against 100 and Q's 20, and
/// keeps all of its 30. With both packs granted before either refund, and
/// both uses learned at once, Q is set against 100 and P's 30 and keeps
/// none, and P then keeps all of its own.
#[test]
fn refunded_packs_count_in_the_order_their_refunds_were_recorded() {
    let now = NOW.as_secs();
    let q = Terms::pack(B, "pilotusera");
    let mut p = Terms::pack(A, "pilotusera");
    p.gigabytes = 30;
    let (ledger, _) = step(&PaymentLedger::new(), q.grant(1), now);
    let (ledger, _) = step(
        &ledger,
        recorded(q.refund(2, 800, true), now + HOUR / 2),
        now + HOUR / 2,
    );
    let ledger = settled(&ledger, now + HOUR / 2, 120);
    let (ledger, _) = step(&ledger, p.grant(3), now + HOUR);
    let (ledger, _) = step(
        &ledger,
        recorded(p.refund(4, 800, true), now + 2 * HOUR),
        now + 2 * HOUR,
    );
    let ledger = settled(&ledger, now + 2 * HOUR, 170);
    assert_eq!(quota_at(&ledger, now + 2 * HOUR), 150);
    // Both granted first, then both refunded, their uses learned together.
    let (ledger, _) = step(&PaymentLedger::new(), q.grant(1), now);
    let (ledger, _) = step(&ledger, p.grant(2), now);
    let (ledger, _) = step(
        &ledger,
        recorded(q.refund(3, 800, true), now + HOUR),
        now + HOUR,
    );
    let (ledger, _) = step(
        &ledger,
        recorded(p.refund(4, 800, true), now + 2 * HOUR),
        now + 2 * HOUR,
    );
    let at = now + 3 * HOUR;
    let ledger = ledger
        .settle(secs(at), cycle(secs(at)), &|_, refunded_at| {
            Some(if refunded_at == secs(now + HOUR) {
                120 * GB
            } else {
                170 * GB
            })
        })
        .unwrap()
        .ledger;
    assert_eq!(quota_at(&ledger, at - 1), 180);
    assert_eq!(quota_at(&ledger, at), 130);
}
