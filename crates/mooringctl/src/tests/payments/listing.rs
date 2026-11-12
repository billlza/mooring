// SPDX-License-Identifier: GPL-3.0-or-later

//! What `portal payments` prints and the lines the pull logs, for every
//! kind of order, outcome and stop.

use std::collections::BTreeMap;

use mooring_daemon_core::payments::{
    FeedPage, GrantOutcome, HeldReason, LedgerEvent, OrderId, PackUse, PaymentLedger, PortalOrigin,
    PullSettings, RefundEffect, Stop, StopReason, TimeTakenBack,
};
use mooring_daemon_core::period::BillingCycle;
use mooring_model::user::SuspendReason;
use mooring_model::{BillDay, CalendarDate, CycleRule, UnixTime, UserId};
use serde_json::{Value, json};

use super::super::support::NOW;
use super::{FIRST, grant, pack, page, refund_in_full};
use crate::payments::listing::{json_line, text};
use crate::payments::notes::{describe, stamp};

fn users() -> BTreeMap<UserId, mooring_model::User> {
    mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .deployment
        .users()
        .clone()
}

fn applied(ledger: &PaymentLedger, body: &[u8], rehearsal: bool) -> PaymentLedger {
    let page = FeedPage::decode(body, ledger.cursor()).unwrap();
    ledger
        .apply(&page, &users(), UnixTime::from_secs(NOW), rehearsal)
        .unwrap()
        .ledger
}

fn entry(value: Value, edits: &[(&str, Value)]) -> Value {
    let mut value = value;
    for (key, edit) in edits {
        value[*key] = edit.clone();
    }
    value
}

/// A ledger with one order of each kind of record: a month granted with a
/// refund in full and a dispute, a pack, a held grant and an order known
/// only from its refund; then a rehearsal's grant.
fn every_kind() -> PaymentLedger {
    let pack = entry(
        grant(2, "bbbbbbbbbbbbbbbbbbbb", FIRST),
        &[
            ("plan", json!("pack-50")),
            ("plan_kind", json!("traffic")),
            ("traffic_bytes", json!(50_000_000_000_u64)),
        ],
    );
    let refund = entry(
        grant(4, "aaaaaaaaaaaaaaaaaaaa", FIRST),
        &[
            ("kind", json!("refund")),
            ("amount_refunded", json!(800)),
            ("refunded_in_full", json!(true)),
        ],
    );
    let dispute = entry(
        grant(5, "aaaaaaaaaaaaaaaaaaaa", FIRST),
        &[("kind", json!("dispute")), ("amount_disputed", json!(800))],
    );
    let orphan = entry(
        grant(6, "dddddddddddddddddddd", FIRST),
        &[
            ("kind", json!("refund")),
            ("amount_refunded", json!(100)),
            ("refunded_in_full", json!(false)),
        ],
    );
    let live = applied(
        &PaymentLedger::new(),
        &page(
            true,
            0,
            vec![
                grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST),
                pack,
                grant(3, "cccccccccccccccccccc", "nobodyhere"),
                refund,
                dispute,
                orphan,
            ],
            false,
        ),
        false,
    );
    applied(
        &live,
        &page(
            false,
            6,
            vec![grant(7, "eeeeeeeeeeeeeeeeeeee", FIRST)],
            false,
        ),
        true,
    )
}

/// Every order and record is listed, the rehearsal's marked, with what
/// each refund took back: the month's refund in full, recorded before
/// Mooring granted it, takes all of its time back, so the test-mode month
/// granted after it starts at once.
#[test]
fn every_kind_of_order_is_listed() {
    let ledger = every_kind();
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let settings = PullSettings::connected(3, origin, true);
    let at = stamp(UnixTime::from_secs(NOW));
    let until = stamp(UnixTime::from_secs(NOW + 30 * 86_400));
    assert_eq!(
        text(Some(&settings), Some(&ledger)),
        format!(
            "payment pull: https://portal.example.org (settings revision 3)\n\
             \x20 rehearsal: on: Stripe test-mode payments are granted and count\n\
             payment ledger: cursor 7; last pull {at}\n\
             orders: 5 (1 held, 2 refunded, 1 disputed)\n\
             \x20 aaaaaaaaaaaaaaaaaaaa user fxuseraaab plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
             \x20   grant, entry 1, applied {at}: service from {at} until {until}; a refund in full took all of it back\n\
             \x20   refund, entry 4: 800 gbp so far, in full; its service from {at} until {until} is taken back\n\
             \x20   dispute, entry 5: 800 gbp; changes nothing\n\
             \x20 bbbbbbbbbbbbbbbbbbbb user fxuseraaab plan pack-50 (traffic, 30 days, 50000000000 bytes, 800 gbp)\n\
             \x20   grant, entry 2, applied {at}: traffic pack for the billing cycle of {at}\n\
             \x20 cccccccccccccccccccc user nobodyhere plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
             \x20   grant, entry 3, applied {at}: held, not granted (unknown_user): settle it at Stripe\n\
             \x20 dddddddddddddddddddd user fxuseraaab plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
             \x20   no grant: known only from a refund or dispute\n\
             \x20   refund, entry 6: 100 gbp so far; nothing is taken back\n\
             \x20 eeeeeeeeeeeeeeeeeeee user fxuseraaab plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp) [Stripe test mode]\n\
             \x20   grant, entry 7, applied {at}: service from {at} until {until}\n"
        )
    );
}

/// The settings when the pull is disconnected or has never pulled, and
/// each stop, are said as they are.
#[test]
fn the_settings_and_every_stop_are_said() {
    assert_eq!(
        text(Some(&PullSettings::disconnected(4)), None),
        "payment pull: disconnected (settings revision 4)\n  rehearsal: off\npayment ledger: none yet; nothing has been pulled\n"
    );
    assert_eq!(
        text(None, Some(&PaymentLedger::new())),
        "payment pull: not set up (`mooringctl portal connect`)\npayment ledger: cursor 0; last pull never\norders: 0 (0 held, 0 refunded, 0 disputed)\n"
    );
    let at = UnixTime::from_secs(NOW);
    for (reason, why) in [
        (
            StopReason::Conflict,
            "409, the portal's journal ends before the cursor",
        ),
        (StopReason::Unauthorized, "401, the token was refused"),
        (
            StopReason::BadRequest,
            "400, the portal refused the request",
        ),
        (StopReason::Inconsistent, "a page did not fit the ledger"),
    ] {
        let stopped = PaymentLedger::new().with_stop(Some(Stop {
            reason,
            at,
            settings_revision: 2,
        }));
        let listed = text(None, Some(&stopped));
        assert!(
            listed.contains(&format!(
                "\n  stopped since {} ({why}) under settings revision 2: it pulls again once the settings change\n",
                stamp(at)
            )),
            "{listed}"
        );
        // Settings changed since the stop: it is over, and the listing says
        // so before the daemon has recorded its end.
        let changed = text(Some(&PullSettings::disconnected(3)), Some(&stopped));
        assert!(
            changed.contains("under settings revision 2: the settings have changed since, and the daemon pulls again at its next tick\n"),
            "{changed}"
        );
        let same = text(Some(&PullSettings::disconnected(2)), Some(&stopped));
        assert!(
            same.contains("it pulls again once the settings change"),
            "{same}"
        );
    }
}

/// `--json` is the two files as they hold them, as one line.
#[test]
fn the_json_line_is_the_two_files() {
    let ledger = every_kind();
    let settings = PullSettings::disconnected(4);
    let line = json_line(Some(&settings), Some(&ledger)).unwrap();
    assert!(line.ends_with("}\n"));
    assert_eq!(line.lines().count(), 1);
    let value: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        value["settings"],
        serde_json::from_slice::<Value>(&settings.encode().unwrap()).unwrap()
    );
    assert_eq!(
        value["ledger"],
        serde_json::from_slice::<Value>(&ledger.encode().unwrap()).unwrap()
    );
    assert_eq!(
        json_line(None, None).unwrap(),
        "{\"settings\":null,\"ledger\":null}\n"
    );
}

/// Each event of an applied page has its line, by order and user id; a
/// refund's by order only, with what it took back.
#[test]
fn every_event_has_its_line() {
    let order = OrderId::parse("aaaaaaaaaaaaaaaaaaaa").unwrap();
    let user = UserId::parse(FIRST).unwrap();
    let at = UnixTime::from_secs(NOW);
    let granted = |outcome, livemode, suspended| LedgerEvent::Granted {
        order: order.clone(),
        user: user.clone(),
        outcome,
        livemode,
        suspended,
    };
    let refunded = |effect| LedgerEvent::Refunded {
        order: order.clone(),
        amount_refunded: 800,
        in_full: true,
        granted: true,
        effect,
    };
    let lines = [
        (
            granted(
                GrantOutcome::Period {
                    from: at,
                    until: UnixTime::from_secs(NOW + 86_400),
                },
                true,
                None,
            ),
            format!(
                "payment: order {order} granted user {user} service from {} until {}",
                stamp(at),
                stamp(UnixTime::from_secs(NOW + 86_400))
            ),
        ),
        (
            granted(GrantOutcome::Pack, false, Some(SuspendReason::Operator)),
            format!(
                "payment: order {order} granted user {user} a traffic pack for this billing cycle (rehearsal, Stripe test mode); the user is suspended, and only the operator resumes them"
            ),
        ),
        (
            granted(GrantOutcome::Pack, true, Some(SuspendReason::AbuseReview)),
            format!(
                "payment: order {order} granted user {user} a traffic pack for this billing cycle; the user is suspended, and only the operator resumes them"
            ),
        ),
        (
            granted(GrantOutcome::Pack, true, Some(SuspendReason::Expired)),
            format!(
                "payment: order {order} granted user {user} a traffic pack for this billing cycle; the user is suspended at expiry, and the nightly apply job resumes them once their paid time covers it, while the cap on active users leaves room"
            ),
        ),
        (
            granted(
                GrantOutcome::Pack,
                true,
                Some(SuspendReason::QuotaExceeded {
                    cycle_start: CalendarDate::parse("2026-10-01").unwrap(),
                }),
            ),
            format!(
                "payment: order {order} granted user {user} a traffic pack for this billing cycle; the user is suspended for quota, and the nightly apply job resumes them once their quota covers what they used this cycle, or in the next billing cycle"
            ),
        ),
        (
            granted(
                GrantOutcome::Held {
                    reason: HeldReason::BeyondCalendar,
                },
                true,
                None,
            ),
            format!("payment: order {order} granted user {user} nothing (beyond_calendar)"),
        ),
        (
            LedgerEvent::Held {
                order: order.clone(),
                user: user.clone(),
                reason: HeldReason::UserRevoked,
            },
            format!(
                "payment: order {order} for user {user} is held, not granted (user_revoked); settle it at Stripe"
            ),
        ),
        (
            LedgerEvent::Refunded {
                order: order.clone(),
                amount_refunded: 800,
                in_full: true,
                granted: false,
                effect: RefundEffect::Nothing,
            },
            format!(
                "payment: order {order} refunded 800 so far, in full (an order Mooring never granted); nothing is taken back"
            ),
        ),
        (
            LedgerEvent::Refunded {
                order: order.clone(),
                amount_refunded: 300,
                in_full: false,
                granted: true,
                effect: RefundEffect::Nothing,
            },
            format!("payment: order {order} refunded 300 so far; nothing is taken back"),
        ),
        (
            refunded(RefundEffect::Time(TimeTakenBack {
                from: at,
                until: UnixTime::from_secs(NOW + 86_400),
                moved: vec![
                    OrderId::parse("bbbbbbbbbbbbbbbbbbbb").unwrap(),
                    OrderId::parse("cccccccccccccccccccc").unwrap(),
                ],
            })),
            format!(
                "payment: order {order} refunded 800 so far, in full; its service from {} until {} is taken back, and the periods of orders bbbbbbbbbbbbbbbbbbbb, cccccccccccccccccccc that followed it move as much earlier",
                stamp(at),
                stamp(UnixTime::from_secs(NOW + 86_400))
            ),
        ),
        (
            refunded(RefundEffect::Time(TimeTakenBack {
                from: at,
                until: UnixTime::from_secs(NOW + 86_400),
                moved: vec![OrderId::parse("bbbbbbbbbbbbbbbbbbbb").unwrap()],
            })),
            format!(
                "payment: order {order} refunded 800 so far, in full; its service from {} until {} is taken back, and the period of order bbbbbbbbbbbbbbbbbbbb that followed it moves as much earlier",
                stamp(at),
                stamp(UnixTime::from_secs(NOW + 86_400))
            ),
        ),
        (
            refunded(RefundEffect::Time(TimeTakenBack {
                from: at,
                until: at,
                moved: Vec::new(),
            })),
            format!(
                "payment: order {order} refunded 800 so far, in full; its service had ended, so nothing is taken back"
            ),
        ),
        (
            refunded(RefundEffect::Pack(PackUse::Awaiting)),
            format!(
                "payment: order {order} refunded 800 so far, in full; it waits for the usage: its pack counts in full until the usage collected covers the refund's time, or the pack's billing cycle ends"
            ),
        ),
        (
            LedgerEvent::Settled {
                order: order.clone(),
                used: PackUse::Served {
                    bytes: 70_000_000_000,
                    learned_at: UnixTime::from_secs(NOW + 90),
                },
            },
            format!(
                "payment: order {order}'s refund in full no longer waits for the usage; its pack counts from 2026-10-13 19:21:30 UTC on only what the user had used of it beyond the rest of their quota: 70000000000 bytes served this cycle by the refund's time"
            ),
        ),
        (
            LedgerEvent::Settled {
                order: order.clone(),
                used: PackUse::CycleEnded,
            },
            format!(
                "payment: order {order}'s refund in full no longer waits for the usage; its pack's billing cycle has ended, so nothing is taken back"
            ),
        ),
        (
            LedgerEvent::Disputed {
                order: order.clone(),
                user: user.clone(),
                amount_disputed: 800,
                granted: true,
            },
            format!(
                "payment: order {order} of user {user} disputed (800); recorded, nothing changed"
            ),
        ),
        (
            LedgerEvent::Disputed {
                order: order.clone(),
                user: user.clone(),
                amount_disputed: 800,
                granted: false,
            },
            format!(
                "payment: order {order} of user {user} disputed (800) (an order Mooring never granted); recorded, nothing changed"
            ),
        ),
        (
            LedgerEvent::Repeated {
                seq: 9,
                order: order.clone(),
            },
            format!("payment: entry 9 of order {order} is in the ledger already; skipped"),
        ),
    ];
    for (event, line) in lines {
        assert_eq!(describe(&event), line);
    }
    // An instant past the calendar, which only a clock gone wrong gives, is
    // said in seconds.
    assert_eq!(stamp(UnixTime::from_secs(253_402_300_800)), "@253402300800");
}

/// What each refund in full took back is listed: the month cut at the
/// refund's time, the month that followed it moved as much earlier, and
/// the pack's refund as it stands: waiting for the usage, which the
/// summary counts and `--json` carries; then with the user's use at the
/// refund's time and when Mooring learned it; or with nothing taken back,
/// its cycle over.
#[test]
fn what_refunds_in_full_took_back_is_listed() {
    let month = grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST);
    let next = grant(2, "bbbbbbbbbbbbbbbbbbbb", FIRST);
    let traffic = pack(3, "cccccccccccccccccccc", FIRST);
    let day = 86_400;
    let entries = vec![
        month.clone(),
        next,
        traffic.clone(),
        refund_in_full(&month, 4, NOW + 10 * day),
        refund_in_full(&traffic, 5, NOW + 3600),
    ];
    let cycle_at = |secs: u64| {
        BillingCycle::of_instant(
            CycleRule::Monthly {
                bill_day: BillDay::new(1).unwrap(),
            },
            UnixTime::from_secs(secs),
        )
        .unwrap()
    };
    let page = FeedPage::decode(&page(true, 0, entries, false), 0).unwrap();
    let waiting = PaymentLedger::new()
        .apply(&page, &users(), UnixTime::from_secs(NOW), false)
        .unwrap()
        .ledger;
    let summary = "  1 refund(s) in full of traffic packs wait for the usage: the daemon records the user's use at the refund once the usage collected covers its time\n";
    let listed = text(None, Some(&waiting));
    assert!(
        listed.contains(&format!(
            "orders: 3 (0 held, 2 refunded, 0 disputed)\n{summary}"
        )),
        "{listed}"
    );
    assert!(
        listed.contains("    refund, entry 5: 800 gbp so far, in full; it waits for the usage: its pack counts in full until the usage collected covers the refund's time, or the pack's billing cycle ends\n"),
        "{listed}"
    );
    assert!(
        json_line(None, Some(&waiting))
            .unwrap()
            .contains("\"pack_use\":\"awaiting\""),
    );
    let next_cycle = NOW + 40 * day;
    let ended = waiting
        .settle(
            UnixTime::from_secs(next_cycle),
            cycle_at(next_cycle),
            &|_, _| None,
        )
        .unwrap()
        .ledger;
    let listed = text(None, Some(&ended));
    assert!(!listed.contains("wait for the usage"), "{listed}");
    assert!(
        listed.contains("    refund, entry 5: 800 gbp so far, in full; its pack's billing cycle has ended, so nothing is taken back\n"),
        "{listed}"
    );
    let ledger = waiting
        .settle(
            UnixTime::from_secs(NOW + 2 * 3600),
            cycle_at(NOW),
            &|_, _| Some(120_000_000_000),
        )
        .unwrap()
        .ledger;
    let listed = text(None, Some(&ledger));
    assert!(!listed.contains("wait for the usage"), "{listed}");
    let on = |days: u64| stamp(UnixTime::from_secs(NOW + days * day));
    for line in [
        format!(
            "    grant, entry 1, applied {}: service from {} until {}; after refunds in full it counts from {} until {}",
            on(0),
            on(0),
            on(30),
            on(0),
            on(10)
        ),
        format!(
            "    refund, entry 4: 800 gbp so far, in full; its service from {} until {} is taken back, and the period of order bbbbbbbbbbbbbbbbbbbb that followed it moves as much earlier",
            on(10),
            on(30)
        ),
        format!(
            "    grant, entry 2, applied {}: service from {} until {}; after refunds in full it counts from {} until {}",
            on(0),
            on(30),
            on(60),
            on(10),
            on(40)
        ),
        "    refund, entry 5: 800 gbp so far, in full; its pack counts from 2026-10-13 21:20:00 UTC on only what the user had used of it beyond the rest of their quota: 120000000000 bytes served this cycle by the refund's time".to_owned(),
    ] {
        assert!(listed.contains(&format!("{line}\n")), "{line}\n{listed}");
    }
}
