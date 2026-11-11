// SPDX-License-Identifier: GPL-3.0-or-later

//! What `portal payments` prints and the lines the pull logs, for every
//! kind of order, outcome and stop.

use mooring_daemon_core::payments::{
    FeedPage, GrantOutcome, HeldReason, LedgerEvent, OrderId, PaymentLedger, PortalOrigin,
    PullSettings, Stop, StopReason,
};
use mooring_model::{UnixTime, UserId};
use serde_json::{Value, json};

use super::super::support::NOW;
use super::{FIRST, grant, page};
use crate::payments::listing::{json_line, text};
use crate::payments::notes::{describe, stamp};

fn users() -> std::collections::BTreeMap<UserId, mooring_model::User> {
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

/// Every order and record is listed, the rehearsal's marked.
#[test]
fn every_kind_of_order_is_listed() {
    let ledger = every_kind();
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let settings = PullSettings::connected(3, origin, true);
    let at = stamp(UnixTime::from_secs(NOW));
    let until = stamp(UnixTime::from_secs(NOW + 30 * 86_400));
    let after = stamp(UnixTime::from_secs(NOW + 60 * 86_400));
    assert_eq!(
        text(Some(&settings), Some(&ledger)),
        format!(
            "payment pull: https://portal.example.org (settings revision 3)\n\
             \x20 rehearsal: on: Stripe test-mode payments are granted and count\n\
             payment ledger: cursor 7; last pull {at}\n\
             orders: 5 (1 held, 2 refunded, 1 disputed)\n\
             \x20 aaaaaaaaaaaaaaaaaaaa user fxuseraaab plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
             \x20   grant, entry 1, applied {at}: service from {at} until {until}\n\
             \x20   refund, entry 4: 800 gbp so far, in full; changes nothing\n\
             \x20   dispute, entry 5: 800 gbp; changes nothing\n\
             \x20 bbbbbbbbbbbbbbbbbbbb user fxuseraaab plan pack-50 (traffic, 30 days, 50000000000 bytes, 800 gbp)\n\
             \x20   grant, entry 2, applied {at}: traffic pack for the billing cycle of {at}\n\
             \x20 cccccccccccccccccccc user nobodyhere plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
             \x20   grant, entry 3, applied {at}: held, not granted (unknown_user): settle it at Stripe\n\
             \x20 dddddddddddddddddddd user fxuseraaab plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
             \x20   no grant: known only from a refund or dispute\n\
             \x20   refund, entry 6: 100 gbp so far; changes nothing\n\
             \x20 eeeeeeeeeeeeeeeeeeee user fxuseraaab plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp) [Stripe test mode]\n\
             \x20   grant, entry 7, applied {at}: service from {until} until {after}\n"
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

/// Each event of an applied page has its line, by order and user id.
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
    let lines = [
        (
            granted(
                GrantOutcome::Period {
                    from: at,
                    until: UnixTime::from_secs(NOW + 86_400),
                },
                true,
                false,
            ),
            format!(
                "payment: order {order} granted user {user} service from {} until {}",
                stamp(at),
                stamp(UnixTime::from_secs(NOW + 86_400))
            ),
        ),
        (
            granted(GrantOutcome::Pack, false, true),
            format!(
                "payment: order {order} granted user {user} a traffic pack for this billing cycle (rehearsal, Stripe test mode); the user is suspended, and only the operator resumes them"
            ),
        ),
        (
            granted(
                GrantOutcome::Held {
                    reason: HeldReason::BeyondCalendar,
                },
                true,
                false,
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
                user: user.clone(),
                amount_refunded: 800,
                in_full: true,
                granted: false,
            },
            format!(
                "payment: order {order} of user {user} refunded 800 so far, in full (an order Mooring never granted); recorded, nothing changed"
            ),
        ),
        (
            LedgerEvent::Refunded {
                order: order.clone(),
                user: user.clone(),
                amount_refunded: 300,
                in_full: false,
                granted: true,
            },
            format!(
                "payment: order {order} of user {user} refunded 300 so far; recorded, nothing changed"
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
