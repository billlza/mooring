// SPDX-License-Identifier: GPL-3.0-or-later

//! What a refund in full takes back (design §9.6; the operator's decision
//! of 2026-11-12): from the time the portal recorded it, the time and the
//! traffic the order gave that the user had not used yet. A period stops
//! there and the periods that followed it move as much earlier; a pack
//! keeps only what the user had used of it beyond the rest of their quota,
//! by the usage the daemon reported when it applied the refund. A partial
//! refund takes nothing; a version-1 ledger is lifted.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use mooring_model::{
    BillDay, CycleRule, QuotaAction, UnixTime, User, UserId, UserQuota, UserStatus, WarnPercent,
};
use serde_json::{Value, json};

use super::{DAY, NOW, Terms, by_id, id, live, order, secs, user};
use crate::payments::{
    LedgerError, LedgerEvent, PackRefund, PackUse, PaymentLedger, RefundEffect, TimeTakenBack,
};
use crate::period::BillingCycle;
use crate::policy::effective_policy;
use crate::usage::CycleUsage;

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

/// `ledger` with `entry` applied at `at`, live, for `users`, with the
/// daemon's `usage` report; and what the entry did.
fn step_for(
    ledger: &PaymentLedger,
    users: &BTreeMap<UserId, User>,
    entry: Value,
    at: u64,
    usage: Option<&CycleUsage>,
) -> (PaymentLedger, LedgerEvent) {
    let mut applied = ledger
        .apply(
            &live(ledger.cursor(), vec![entry]),
            users,
            secs(at),
            false,
            usage,
        )
        .unwrap();
    (applied.ledger, applied.events.remove(0))
}

/// [`step_for`] for [`users`], with no usage report.
fn step(ledger: &PaymentLedger, entry: Value, at: u64) -> (PaymentLedger, LedgerEvent) {
    step_for(ledger, &users(), entry, at, None)
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
        ledger = step_for(
            &ledger,
            &users,
            Terms::month(text, buyer).grant(seq),
            at,
            None,
        )
        .0;
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
        None,
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
        None,
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
        None,
    );
    let (ledger, _) = step_for(
        &ledger,
        &users,
        recorded(
            Terms::month(A, "pilotusera").refund(2, 800, true),
            now + 5 * DAY,
        ),
        now + 5 * DAY + 60,
        None,
    );
    users.get_mut(&id("pilotusera")).unwrap().policy.expires_at = Some(secs(now + 30 * DAY));
    let (ledger, _) = step_for(
        &ledger,
        &users,
        Terms::month(B, "pilotusera").grant(3),
        now + 6 * DAY,
        None,
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
            ledger
                .apply(&page, users, secs(at), true, None)
                .unwrap()
                .ledger
        };
    // User a: a live month, then a rehearsal's month after it.
    let (ledger, _) = step_for(
        &PaymentLedger::new(),
        &users,
        Terms::month(A, "pilotusera").grant(1),
        now,
        None,
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
        None,
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
        None,
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
/// full, recorded at `refunded_at`, applied with the daemon's `usage`.
fn pack_refunded(
    granted: u64,
    refunded_at: u64,
    usage: Option<&CycleUsage>,
) -> (PaymentLedger, LedgerEvent) {
    let pack = Terms::pack(A, "pilotusera");
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), granted);
    step_for(
        &ledger,
        &users(),
        recorded(pack.refund(2, 800, true), refunded_at),
        refunded_at + 60,
        usage,
    )
}

/// The daemon's report of `at`'s billing cycle, with `served` GB for user a
/// (`None`: unknown) and 1 GB for user b.
fn report(at: u64, served: Option<u64>) -> CycleUsage {
    CycleUsage {
        cycle: cycle(secs(at)),
        through: secs(at),
        served: BTreeMap::from([
            (id("pilotusera"), served.map(|gigabytes| gigabytes * GB)),
            (id("pilotuserb"), Some(GB)),
        ]),
    }
}

/// The ledger records what the daemon's report said of the user's use when
/// it applied the refund that takes a pack back: the user's bytes served in
/// the pack's cycle, unknown when there was no report or no figure for the
/// user, and the cycle's end when the report was of a later cycle. A partial
/// refund, a second refund in full and a month's refund record none.
#[test]
fn the_refund_that_takes_a_pack_back_records_the_use() {
    let now = NOW.as_secs();
    let applied = now + 2 * HOUR + 60;
    for (usage, recorded_use) in [
        (
            Some(report(applied, Some(120))),
            PackUse::Served { bytes: 120 * GB },
        ),
        (Some(report(applied, None)), PackUse::Unknown),
        (None, PackUse::Unknown),
        (Some(report(now + 30 * DAY, Some(5))), PackUse::CycleEnded),
    ] {
        let (ledger, event) = pack_refunded(now, now + 2 * HOUR, usage.as_ref());
        assert_eq!(
            event,
            refunded(A, 800, true, RefundEffect::Pack(recorded_use))
        );
        let record = &ledger.orders()[&order(A)];
        assert_eq!(record.refunds[0].pack_use, Some(recorded_use));
        let paid = ledger.entitlements(false);
        assert_eq!(
            paid.users()[&id("pilotusera")].packs()[0].refund,
            Some(PackRefund {
                at: secs(now + 2 * HOUR),
                used: recorded_use
            })
        );
    }
    // A report from before the pack's cycle (the clock stepped back)
    // cannot tell.
    let (ledger, _) = pack_refunded(now, now + 2 * HOUR, Some(&report(now - 40 * DAY, Some(5))));
    assert_eq!(
        ledger.orders()[&order(A)].refunds[0].pack_use,
        Some(PackUse::Unknown)
    );
    // Only the first refund in full, of a pack, records a use.
    let pack = Terms::pack(A, "pilotusera");
    let usage = report(now + HOUR, Some(120));
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), now);
    let (ledger, partial) = step_for(
        &ledger,
        &users(),
        pack.refund(2, 300, false),
        now + HOUR,
        Some(&usage),
    );
    assert_eq!(partial, refunded(A, 300, false, RefundEffect::Nothing));
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        pack.refund(3, 800, true),
        now + HOUR,
        Some(&usage),
    );
    let (ledger, again) = step_for(
        &ledger,
        &users(),
        pack.refund(4, 900, true),
        now + HOUR,
        Some(&usage),
    );
    assert_eq!(again, refunded(A, 900, true, RefundEffect::Nothing));
    let uses: Vec<Option<PackUse>> = ledger.orders()[&order(A)]
        .refunds
        .iter()
        .map(|refund| refund.pack_use)
        .collect();
    assert_eq!(
        uses,
        [None, Some(PackUse::Served { bytes: 120 * GB }), None]
    );
    let month = Terms::month(B, "pilotusera");
    let (ledger, _) = step(&ledger, month.grant(5), now);
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        month.refund(6, 800, true),
        now + HOUR,
        Some(&usage),
    );
    assert_eq!(ledger.orders()[&order(B)].refunds[0].pack_use, None);
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

/// A pack refunded in full keeps, from the refund on, only what the user
/// had used of it beyond the rest of their quota (100 GB): 20 GB of 50 for
/// 120 GB used, none for 80, all of it for 200. Unknown use takes it back
/// whole; a cycle that had ended takes nothing. Before the refund's time it
/// counts whole.
#[test]
fn a_refunded_pack_keeps_only_what_the_user_had_used_of_it() {
    let now = NOW.as_secs();
    let refund = now + 2 * HOUR;
    let applied = refund + 60;
    for (usage, before, after) in [
        (Some(report(applied, Some(120))), 150, 120),
        (Some(report(applied, Some(80))), 150, 100),
        (Some(report(applied, Some(200))), 150, 150),
        (Some(report(applied, Some(100))), 150, 100),
        (Some(report(applied, None)), 150, 100),
        (None, 150, 100),
        (Some(report(now + 30 * DAY, Some(5))), 150, 150),
    ] {
        let (ledger, _) = pack_refunded(now, refund, usage.as_ref());
        assert_eq!(quota_at(&ledger, refund - 1), before, "{usage:?}");
        assert_eq!(quota_at(&ledger, refund), after, "{usage:?}");
        assert_eq!(quota_at(&ledger, refund + 3 * HOUR), after, "{usage:?}");
    }
}

/// The rest of the quota a refunded pack is set against holds the cycle's
/// other packs granted by the refund, as they counted then; a pack granted
/// after it adds in full, and pays for none of what the user had used.
/// Refunds count in the order they were recorded.
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
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        recorded(x.refund(3, 800, true), now + 2 * HOUR),
        now + 2 * HOUR,
        Some(&report(now + 2 * HOUR, Some(160))),
    );
    assert_eq!(quota_at(&ledger, now + 2 * HOUR), 160);
    let (ledger, _) = step(&ledger, z.grant(4), now + 3 * HOUR);
    assert_eq!(quota_at(&ledger, now + 3 * HOUR), 200);
    // Y refunded with 170 GB used: the rest is 100 + X's 30 + Z's 40.
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        recorded(y.refund(5, 800, true), now + 4 * HOUR),
        now + 4 * HOUR,
        Some(&report(now + 4 * HOUR, Some(170))),
    );
    assert_eq!(quota_at(&ledger, now + 4 * HOUR), 170);
    // Before Y's refund, X still kept its 30.
    assert_eq!(quota_at(&ledger, now + 4 * HOUR - 1), 200);
}

/// The refund that takes a pack back carries its use in the file: a
/// version-2 ledger without it there, or with one on any other refund, is
/// refused.
#[test]
fn the_use_is_recorded_on_the_refund_that_takes_a_pack_back_and_no_other() {
    let now = NOW.as_secs();
    let pack = Terms::pack(A, "pilotusera");
    let usage = report(now + HOUR, Some(120));
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), now);
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        pack.refund(2, 300, false),
        now + HOUR,
        Some(&usage),
    );
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        pack.refund(3, 800, true),
        now + HOUR,
        Some(&usage),
    );
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        pack.refund(4, 900, true),
        now + HOUR,
        Some(&usage),
    );
    let bytes = ledger.encode().unwrap();
    assert_eq!(PaymentLedger::decode(&bytes).unwrap(), ledger);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["orders"][0]["refunds"][1]["pack_use"],
        json!({"served": {"bytes": 120 * GB}})
    );
    assert_eq!(value["orders"][0]["refunds"][0]["pack_use"], Value::Null);
    for (index, pack_use) in [
        (1, Value::Null),
        (0, json!("unknown")),
        (2, json!("cycle_ended")),
    ] {
        let mut broken = value.clone();
        broken["orders"][0]["refunds"][index]["pack_use"] = pack_use;
        assert!(
            matches!(
                PaymentLedger::decode(&serde_json::to_vec(&broken).unwrap()),
                Err(LedgerError::Inconsistent { .. })
            ),
            "{index}"
        );
    }
}

/// A version-1 ledger, from before a refund took anything back, is read and
/// written as version 2: the refund that takes a pack back gets a use not
/// known, so the pack is taken back whole, and its refunds in full of
/// periods take back what they would now.
#[test]
fn a_version_1_ledger_is_lifted() {
    let now = NOW.as_secs();
    let pack = Terms::pack(A, "pilotusera");
    let month = Terms::month(B, "pilotusera");
    let usage = report(now + HOUR, Some(120));
    let (ledger, _) = step(&PaymentLedger::new(), pack.grant(1), now);
    let (ledger, _) = step(&ledger, month.grant(2), now);
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        pack.refund(3, 300, false),
        now + HOUR,
        Some(&usage),
    );
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        recorded(pack.refund(4, 800, true), now + HOUR),
        now + HOUR,
        Some(&usage),
    );
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        recorded(month.refund(5, 800, true), now + DAY),
        now + DAY,
        Some(&usage),
    );
    // The same ledger as version 1 wrote it: no use anywhere.
    let mut version_1: Value = serde_json::from_slice(&ledger.encode().unwrap()).unwrap();
    version_1["version"] = json!(1);
    for record in version_1["orders"].as_array_mut().unwrap() {
        for refund in record["refunds"].as_array_mut().unwrap() {
            refund.as_object_mut().unwrap().remove("pack_use");
        }
    }
    let lifted = PaymentLedger::decode(&serde_json::to_vec(&version_1).unwrap()).unwrap();
    let uses: Vec<Option<PackUse>> = lifted.orders()[&order(A)]
        .refunds
        .iter()
        .map(|refund| refund.pack_use)
        .collect();
    assert_eq!(uses, [None, Some(PackUse::Unknown)]);
    assert_eq!(lifted.orders()[&order(B)].refunds[0].pack_use, None);
    assert_eq!(counted(&lifted, B), span(now, now + DAY));
    assert_eq!(quota_at(&lifted, now + 2 * HOUR), 100);
    let written = String::from_utf8(lifted.encode().unwrap()).unwrap();
    assert!(written.starts_with("{\n  \"version\": 2,"), "{written}");
    assert_eq!(PaymentLedger::decode(written.as_bytes()).unwrap(), lifted);
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
/// their orders' ids: pack Q (50 GB), refunded first with 120 GB used, was
/// set against the 100 GB quota alone, since pack P (30 GB) was granted
/// after that refund, and keeps 20; P, refunded later with 170 GB used, is
/// set against 100 and Q's 20, and keeps all of its 30.
#[test]
fn refunded_packs_count_in_the_order_their_refunds_were_recorded() {
    let now = NOW.as_secs();
    let q = Terms::pack(B, "pilotusera");
    let mut p = Terms::pack(A, "pilotusera");
    p.gigabytes = 30;
    let (ledger, _) = step(&PaymentLedger::new(), q.grant(1), now);
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        recorded(q.refund(2, 800, true), now + HOUR / 2),
        now + HOUR / 2,
        Some(&report(now + HOUR / 2, Some(120))),
    );
    let (ledger, _) = step(&ledger, p.grant(3), now + HOUR);
    let (ledger, _) = step_for(
        &ledger,
        &users(),
        recorded(p.refund(4, 800, true), now + 2 * HOUR),
        now + 2 * HOUR,
        Some(&report(now + 2 * HOUR, Some(170))),
    );
    assert_eq!(quota_at(&ledger, now + 2 * HOUR), 150);
}
