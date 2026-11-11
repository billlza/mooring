// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment ledger: what a page grants, holds and records, the rules
//! that keep an order from being granted twice, test mode and rehearsals,
//! and the file's own rules.

use mooring_model::{SuspendReason, UserStatus};
use serde_json::{Value, json};

use super::{
    DAY, NOW, PILOT, Terms, by_id, decode, document, id, live, order, pilot_users, pilot_value,
    secs, user,
};
use crate::payments::{
    ApplyRefusal, Contradiction, FeedPage, GrantOutcome, HeldReason, LedgerError, LedgerEvent,
    MAX_LEDGER_BYTES, PaymentLedger, Stop, StopReason,
};

const A: &str = "0123456789abcdefghjk";
const B: &str = "zzzzzzzzzzzzzzzzzzzz";
const RENEWAL: &str = "sbc7dxq3cceajeb9ncge";

fn pilot_page() -> FeedPage {
    FeedPage::decode(PILOT.as_bytes(), 0).unwrap()
}

fn period(from: u64, until: u64) -> GrantOutcome {
    GrantOutcome::Period {
        from: secs(from),
        until: secs(until),
    }
}

/// A rehearsal grants `pilot.json`: user a's month from now; user b's
/// renewing month from now and its renewal after it, so paying early loses
/// nothing; the refunds and the dispute are recorded and change nothing.
#[test]
fn a_rehearsal_grants_the_pilot_golden() {
    let applied = PaymentLedger::new()
        .apply(&pilot_page(), &pilot_users(), NOW, true)
        .unwrap();
    let now = NOW.as_secs();
    assert_eq!(
        applied.events,
        [
            LedgerEvent::Granted {
                order: order(A),
                user: id("pilotusera"),
                outcome: period(now, now + 30 * DAY),
                livemode: false,
                suspended: false,
            },
            LedgerEvent::Granted {
                order: order(B),
                user: id("pilotuserb"),
                outcome: period(now, now + 30 * DAY),
                livemode: false,
                suspended: false,
            },
            LedgerEvent::Refunded {
                order: order(A),
                user: id("pilotusera"),
                amount_refunded: 300,
                in_full: false,
                granted: true,
            },
            LedgerEvent::Granted {
                order: order(RENEWAL),
                user: id("pilotuserb"),
                outcome: period(now + 30 * DAY, now + 60 * DAY),
                livemode: false,
                suspended: false,
            },
            LedgerEvent::Disputed {
                order: order(A),
                user: id("pilotusera"),
                amount_disputed: 800,
                granted: true,
            },
            LedgerEvent::Refunded {
                order: order(RENEWAL),
                user: id("pilotuserb"),
                amount_refunded: 800,
                in_full: true,
                granted: true,
            },
        ]
    );
    let ledger = applied.ledger;
    assert_eq!(ledger.cursor(), 7);
    assert_eq!(ledger.pulled_at(), Some(NOW));
    assert_eq!(ledger.stopped(), None);
    assert_eq!(ledger.orders().len(), 3);
    let a = &ledger.orders()[&order(A)];
    assert!(!a.livemode);
    assert_eq!(a.grant.unwrap().seq, 1);
    assert_eq!(a.grant.unwrap().applied_at, NOW);
    assert_eq!(a.grant.unwrap().recorded_at, secs(1_794_355_261));
    assert_eq!(a.refunds.len(), 1);
    assert_eq!(a.dispute.unwrap().amount_disputed, 800);
    assert_eq!(a.dispute.unwrap().seq, 6);
    assert!(ledger.orders()[&order(RENEWAL)].refunds[0].refunded_in_full);
}

/// A page of Stripe's test mode grants nothing unless the operator
/// rehearses, and leaves the ledger as it was; a live page needs no
/// rehearsal.
#[test]
fn test_mode_grants_nothing_unless_rehearsing() {
    let ledger = PaymentLedger::new();
    assert_eq!(
        ledger.apply(&pilot_page(), &pilot_users(), NOW, false),
        Err(ApplyRefusal::TestMode)
    );
    let mut empty_test = pilot_value();
    empty_test["entries"] = json!([]);
    empty_test["next"] = json!(0);
    empty_test["more"] = json!(false);
    let page = decode(&empty_test, 0).unwrap();
    assert_eq!(
        ledger.apply(&page, &pilot_users(), NOW, false),
        Err(ApplyRefusal::TestMode)
    );
    let month = Terms::month(A, "pilotusera");
    let applied = ledger
        .apply(&live(0, vec![month.grant(1)]), &pilot_users(), NOW, false)
        .unwrap();
    assert_eq!(applied.ledger.cursor(), 1);
    assert!(applied.ledger.orders()[&order(A)].livemode);
}

/// A page must follow the ledger's cursor.
#[test]
fn a_page_must_follow_the_cursor() {
    let month = Terms::month(A, "pilotusera");
    let ledger = PaymentLedger::new()
        .apply(&live(0, vec![month.grant(1)]), &pilot_users(), NOW, false)
        .unwrap()
        .ledger;
    let other = Terms::month(B, "pilotusera");
    assert_eq!(
        ledger.apply(&live(3, vec![other.grant(4)]), &pilot_users(), NOW, false),
        Err(ApplyRefusal::CursorMoved {
            after: 3,
            cursor: 1
        })
    );
}

/// The empty golden moves nothing but the time of the last pull.
#[test]
fn the_empty_golden_changes_nothing_but_the_time_of_the_pull() {
    let month = Terms::month(A, "pilotusera");
    let mut entries: Vec<Value> = vec![month.grant(1)];
    for seq in 2..=6 {
        let mut grant = Terms::month(A, "pilotusera").grant(seq);
        grant["order"] = json!(format!("{seq:0>20}"));
        entries.push(grant);
    }
    let ledger = PaymentLedger::new()
        .apply(&live(0, entries), &pilot_users(), NOW, false)
        .unwrap()
        .ledger;
    let empty = FeedPage::decode(super::EMPTY.as_bytes(), 6).unwrap();
    let later = secs(NOW.as_secs() + 300);
    let applied = ledger.apply(&empty, &pilot_users(), later, false).unwrap();
    assert!(applied.events.is_empty());
    assert_eq!(applied.ledger.cursor(), 6);
    assert_eq!(applied.ledger.orders(), ledger.orders());
    assert_eq!(applied.ledger.pulled_at(), Some(later));
}

/// Entries the ledger holds already are skipped: a grant of an order
/// granted, whatever its number; a refund of the same cumulative amount and
/// flag; a dispute of the same amount (contract §5.2). Nothing is granted
/// twice, and only the cursor and the time move.
#[test]
fn an_entry_again_changes_nothing() {
    let month = Terms::month(A, "pilotusera");
    let first = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    month.grant(1),
                    month.refund(2, 300, false),
                    month.dispute(3, 800),
                ],
            ),
            &pilot_users(),
            NOW,
            false,
        )
        .unwrap()
        .ledger;
    let later = secs(NOW.as_secs() + DAY);
    let again = first
        .apply(
            &live(
                3,
                vec![
                    month.grant(4),
                    month.refund(5, 300, false),
                    month.dispute(6, 800),
                ],
            ),
            &pilot_users(),
            later,
            false,
        )
        .unwrap();
    assert_eq!(
        again.events,
        [
            LedgerEvent::Repeated {
                seq: 4,
                order: order(A)
            },
            LedgerEvent::Repeated {
                seq: 5,
                order: order(A)
            },
            LedgerEvent::Repeated {
                seq: 6,
                order: order(A)
            },
        ]
    );
    assert_eq!(again.ledger.orders(), first.orders());
    assert_eq!(again.ledger.cursor(), 6);
    assert_eq!(again.ledger.entitlements(false), first.entitlements(false));
}

/// A refund of a larger cumulative amount, or the same amount newly in
/// full, is a new refund.
#[test]
fn a_refund_is_new_by_its_amount_and_flag() {
    let month = Terms::month(A, "pilotusera");
    let applied = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    month.grant(1),
                    month.refund(2, 300, false),
                    month.refund(3, 800, false),
                    month.refund(4, 800, true),
                ],
            ),
            &pilot_users(),
            NOW,
            false,
        )
        .unwrap();
    let refunds = &applied.ledger.orders()[&order(A)].refunds;
    assert_eq!(
        refunds
            .iter()
            .map(|refund| (refund.seq, refund.amount_refunded, refund.refunded_in_full))
            .collect::<Vec<_>>(),
        [(2, 300, false), (3, 800, false), (4, 800, true)]
    );
}

/// An entry that contradicts what the ledger holds refuses the whole page:
/// nothing of it is applied (contract §1, §6).
#[test]
fn a_contradiction_refuses_the_whole_page() {
    let month = Terms::month(A, "pilotusera");
    let ledger = PaymentLedger::new()
        .apply(
            &live(0, vec![month.grant(1), month.dispute(2, 800)]),
            &pilot_users(),
            NOW,
            false,
        )
        .unwrap()
        .ledger;
    let fresh = Terms::month(B, "pilotuserb");
    let mut other_user = month.clone();
    other_user.user = "pilotuserb";
    let mut other_days = month.clone();
    other_days.days = 31;
    let refused = |entries: Vec<Value>| {
        let mut all = vec![fresh.grant(3)];
        all.extend(entries);
        ledger.apply(&live(2, all), &pilot_users(), NOW, false)
    };
    for (entries, contradiction) in [
        (
            vec![other_user.refund(4, 1, false)],
            Contradiction::TermsDiffer,
        ),
        (vec![other_days.grant(4)], Contradiction::TermsDiffer),
        (vec![month.dispute(4, 799)], Contradiction::SecondDispute),
    ] {
        assert_eq!(
            refused(entries),
            Err(ApplyRefusal::Contradicted {
                seq: 4,
                order: order(A),
                contradiction
            })
        );
    }
    // The same order in the other mode.
    let mut rehearsal = document(false, 2, vec![month.refund(3, 1, false)], false);
    rehearsal["entries"][0]["seq"] = json!(3);
    assert_eq!(
        ledger.apply(&decode(&rehearsal, 2).unwrap(), &pilot_users(), NOW, true),
        Err(ApplyRefusal::Contradicted {
            seq: 3,
            order: order(A),
            contradiction: Contradiction::ModeDiffers
        })
    );
    // A grant of an order known only from its refund.
    let orphan = PaymentLedger::new()
        .apply(
            &live(0, vec![fresh.refund(1, 100, false)]),
            &pilot_users(),
            NOW,
            false,
        )
        .unwrap();
    assert_eq!(
        orphan.events,
        [LedgerEvent::Refunded {
            order: order(B),
            user: id("pilotuserb"),
            amount_refunded: 100,
            in_full: false,
            granted: false
        }]
    );
    assert_eq!(
        orphan
            .ledger
            .apply(&live(1, vec![fresh.grant(2)]), &pilot_users(), NOW, false),
        Err(ApplyRefusal::Contradicted {
            seq: 2,
            order: order(B),
            contradiction: Contradiction::GrantAfterOtherEntries
        })
    );
    // A dispute known before its order's grant is recorded and reported.
    let disputed = PaymentLedger::new()
        .apply(
            &live(0, vec![fresh.dispute(1, 800)]),
            &pilot_users(),
            NOW,
            false,
        )
        .unwrap();
    assert_eq!(
        disputed.events,
        [LedgerEvent::Disputed {
            order: order(B),
            user: id("pilotuserb"),
            amount_disputed: 800,
            granted: false
        }]
    );
}

/// A grant for a user the deployment does not hold, or one being revoked
/// or revoked, is held: the cursor moves past it, and it gives nothing. A
/// suspended user is granted, and the event says so.
#[test]
fn grants_for_unknown_or_revoked_users_are_held() {
    let users = by_id(vec![
        user("pilotuserb", UserStatus::RevokePending, None),
        user("pilotuserc", UserStatus::Revoked, None),
        user(
            "pilotuserd",
            UserStatus::Suspended {
                reason: SuspendReason::Expired,
                since: secs(1_796_000_000),
            },
            None,
        ),
    ]);
    let applied = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
                    Terms::month("bbbbbbbbbbbbbbbbbbbb", "pilotuserb").grant(2),
                    Terms::pack("cccccccccccccccccccc", "pilotuserc").grant(3),
                    Terms::month("dddddddddddddddddddd", "pilotuserd").grant(4),
                ],
            ),
            &users,
            NOW,
            false,
        )
        .unwrap();
    let now = NOW.as_secs();
    assert_eq!(
        applied.events,
        [
            LedgerEvent::Held {
                order: order("aaaaaaaaaaaaaaaaaaaa"),
                user: id("pilotusera"),
                reason: HeldReason::UnknownUser
            },
            LedgerEvent::Held {
                order: order("bbbbbbbbbbbbbbbbbbbb"),
                user: id("pilotuserb"),
                reason: HeldReason::UserRevoked
            },
            LedgerEvent::Held {
                order: order("cccccccccccccccccccc"),
                user: id("pilotuserc"),
                reason: HeldReason::UserRevoked
            },
            LedgerEvent::Granted {
                order: order("dddddddddddddddddddd"),
                user: id("pilotuserd"),
                outcome: period(now, now + 30 * DAY),
                livemode: true,
                suspended: true
            },
        ]
    );
    assert_eq!(applied.ledger.cursor(), 4);
    let entitlements = applied.ledger.entitlements(false);
    assert_eq!(entitlements.users().len(), 1);
    assert!(entitlements.user(&id("pilotuserd")).is_some());
    assert_eq!(HeldReason::UnknownUser.as_str(), "unknown_user");
    assert_eq!(HeldReason::UserRevoked.as_str(), "user_revoked");
    assert_eq!(HeldReason::BeyondCalendar.as_str(), "beyond_calendar");
}

/// A period starts at the later of now and the user's paid expiry: a
/// lapsed user starts now, an early renewal stacks after the period it
/// follows, and the user's own later expiry is kept. A pack is granted now
/// whatever the user's periods.
#[test]
fn a_period_follows_the_users_expiry_or_starts_now() {
    let now = NOW.as_secs();
    let users = by_id(vec![
        user("pilotusera", UserStatus::Active, Some(now - DAY)),
        user("pilotuserb", UserStatus::Active, Some(now + 10 * DAY)),
        user("pilotuserc", UserStatus::Active, None),
    ]);
    let applied = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
                    Terms::month("bbbbbbbbbbbbbbbbbbbb", "pilotuserb").grant(2),
                    Terms::month("cccccccccccccccccccc", "pilotuserc").grant(3),
                    Terms::pack("dddddddddddddddddddd", "pilotuserc").grant(4),
                    Terms::month("eeeeeeeeeeeeeeeeeeee", "pilotuserc").grant(5),
                ],
            ),
            &users,
            NOW,
            false,
        )
        .unwrap();
    let outcome = |text| applied.ledger.orders()[&order(text)].grant.unwrap().outcome;
    assert_eq!(outcome("aaaaaaaaaaaaaaaaaaaa"), period(now, now + 30 * DAY));
    assert_eq!(
        outcome("bbbbbbbbbbbbbbbbbbbb"),
        period(now + 10 * DAY, now + 40 * DAY)
    );
    assert_eq!(outcome("cccccccccccccccccccc"), period(now, now + 30 * DAY));
    assert_eq!(outcome("dddddddddddddddddddd"), GrantOutcome::Pack);
    assert_eq!(
        outcome("eeeeeeeeeeeeeeeeeeee"),
        period(now + 30 * DAY, now + 60 * DAY)
    );
}

/// A period that would end after 9999-12-31 is held; one that ends on it
/// is granted.
#[test]
fn a_period_past_the_calendar_is_held() {
    let last = 253_402_300_799_u64;
    let users = by_id(vec![
        user("pilotusera", UserStatus::Active, Some(last - 30 * DAY)),
        user("pilotuserb", UserStatus::Active, Some(last - 30 * DAY + 1)),
    ]);
    let applied = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
                    Terms::month("bbbbbbbbbbbbbbbbbbbb", "pilotuserb").grant(2),
                ],
            ),
            &users,
            NOW,
            false,
        )
        .unwrap();
    assert_eq!(
        applied.ledger.orders()[&order("aaaaaaaaaaaaaaaaaaaa")]
            .grant
            .unwrap()
            .outcome,
        period(last - 30 * DAY, last)
    );
    assert_eq!(
        applied.events[1],
        LedgerEvent::Held {
            order: order("bbbbbbbbbbbbbbbbbbbb"),
            user: id("pilotuserb"),
            reason: HeldReason::BeyondCalendar
        }
    );
}

/// A live grant never builds on a rehearsal's period, and a rehearsal's
/// counts only while the rehearsal is on.
#[test]
fn a_rehearsal_never_moves_real_time() {
    let now = NOW.as_secs();
    let rehearsed = PaymentLedger::new()
        .apply(&pilot_page(), &pilot_users(), NOW, true)
        .unwrap()
        .ledger;
    let later = now + DAY;
    let live_grant = Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotuserb");
    let applied = rehearsed
        .apply(
            &live(7, vec![live_grant.grant(8)]),
            &pilot_users(),
            secs(later),
            false,
        )
        .unwrap();
    assert_eq!(
        applied.events[0],
        LedgerEvent::Granted {
            order: order("aaaaaaaaaaaaaaaaaaaa"),
            user: id("pilotuserb"),
            outcome: period(later, later + 30 * DAY),
            livemode: true,
            suspended: false,
        }
    );
    let off = applied.ledger.entitlements(false);
    let b = off.user(&id("pilotuserb")).unwrap();
    assert_eq!(b.periods().len(), 1);
    assert_eq!(b.paid_until(), Some(secs(later + 30 * DAY)));
    assert!(off.user(&id("pilotusera")).is_none());
    let on = applied.ledger.entitlements(true);
    assert_eq!(on.user(&id("pilotuserb")).unwrap().periods().len(), 3);
    assert_eq!(
        on.user(&id("pilotuserb")).unwrap().paid_until(),
        Some(secs(now + 60 * DAY))
    );
    // While both count, the live period covering an instant is the one
    // that applies.
    assert!(
        on.user(&id("pilotuserb"))
            .unwrap()
            .period_at(secs(later + DAY))
            .unwrap()
            .livemode
    );
}

/// The ledger's file: a round trip keeps everything, the version and the
/// shape are its own, and each of its rules refuses a file that breaks it.
#[test]
fn the_ledger_file_round_trips_and_keeps_its_rules() {
    let applied = PaymentLedger::new()
        .apply(&pilot_page(), &pilot_users(), NOW, true)
        .unwrap();
    let stopped = applied.ledger.with_stop(Some(Stop {
        reason: StopReason::Conflict,
        at: NOW,
        settings_revision: 3,
    }));
    for ledger in [
        PaymentLedger::new(),
        applied.ledger.clone(),
        stopped.clone(),
    ] {
        let bytes = ledger.encode().unwrap();
        assert!(bytes.ends_with(b"}\n"));
        assert_eq!(PaymentLedger::decode(&bytes).unwrap(), ledger);
    }
    assert_eq!(stopped.stopped().unwrap().reason, StopReason::Conflict);
    assert_eq!(stopped.with_stop(None), applied.ledger);
    let text = String::from_utf8(applied.ledger.encode().unwrap()).unwrap();
    assert!(
        text.starts_with("{\n  \"version\": 1,\n  \"cursor\": 7,"),
        "{text}"
    );
    let value: Value = serde_json::from_str(&text).unwrap();
    let edits: Vec<(&str, Edit)> = vec![
        ("version", Box::new(|value| value["version"] = json!(2))),
        (
            "order",
            Box::new(|value| {
                let orders = value["orders"].as_array_mut().unwrap();
                orders.swap(0, 1);
            }),
        ),
        (
            "twice",
            Box::new(|value| {
                let first = value["orders"][0].clone();
                value["orders"].as_array_mut().unwrap().insert(0, first);
            }),
        ),
        ("cursor", Box::new(|value| value["cursor"] = json!(6))),
        (
            "zero",
            Box::new(|value| value["orders"][0]["grant"]["seq"] = json!(0)),
        ),
        (
            "before grant",
            Box::new(|value| value["orders"][0]["refunds"][0]["seq"] = json!(1)),
        ),
        (
            "dispute before grant",
            Box::new(|value| value["orders"][0]["dispute"]["seq"] = json!(1)),
        ),
        (
            "period backwards",
            Box::new(|value| {
                value["orders"][0]["grant"]["outcome"]["period"]["until"] =
                    value["orders"][0]["grant"]["outcome"]["period"]["from"].clone();
            }),
        ),
        (
            "period past calendar",
            Box::new(|value| {
                value["orders"][0]["grant"]["outcome"]["period"]["until"] =
                    json!(253_402_300_800_u64);
            }),
        ),
        (
            "period of a pack",
            Box::new(|value| value["orders"][0]["terms"]["plan_kind"] = json!("traffic")),
        ),
        (
            "pack of a month",
            Box::new(|value| value["orders"][0]["grant"]["outcome"] = json!("pack")),
        ),
        (
            "refund twice",
            Box::new(|value| {
                let refund = value["orders"][0]["refunds"][0].clone();
                let mut again = refund.clone();
                again["seq"] = json!(7);
                value["orders"][0]["refunds"]
                    .as_array_mut()
                    .unwrap()
                    .push(again);
            }),
        ),
        (
            "unknown key",
            Box::new(|value| value["orders"][0]["note"] = json!(1)),
        ),
        (
            "missing key",
            Box::new(|value| {
                value["orders"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("dispute");
            }),
        ),
    ];
    for (name, edit) in edits {
        let mut broken = value.clone();
        edit(&mut broken);
        let refused = PaymentLedger::decode(&serde_json::to_vec(&broken).unwrap());
        assert!(refused.is_err(), "{name}");
        if name == "version" {
            assert!(matches!(
                refused,
                Err(LedgerError::UnknownVersion { found: 2 })
            ));
        }
    }
    let mut big = text.into_bytes();
    big.resize(MAX_LEDGER_BYTES + 1, b' ');
    assert!(matches!(
        PaymentLedger::decode(&big),
        Err(LedgerError::TooLarge)
    ));
    assert_eq!(StopReason::Conflict.as_str(), "conflict");
    assert_eq!(StopReason::Unauthorized.as_str(), "unauthorized");
    assert_eq!(StopReason::BadRequest.as_str(), "bad_request");
    assert_eq!(StopReason::Inconsistent.as_str(), "inconsistent");
}

/// An edit of a ledger document.
type Edit = Box<dyn Fn(&mut Value)>;

/// A ledger too large to read back is not written.
#[test]
fn a_ledger_too_large_to_read_back_is_not_written() {
    let mut entries = Vec::new();
    let mut ledger = PaymentLedger::new();
    let mut seq = 0_u64;
    while ledger.encode().is_ok() {
        entries.clear();
        for _ in 0..200 {
            seq += 1;
            let mut grant = Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(seq);
            grant["order"] = json!(format!("{seq:0>20}"));
            entries.push(grant);
        }
        let page = live(seq - 200, entries.clone());
        ledger = ledger
            .apply(&page, &pilot_users(), NOW, false)
            .unwrap()
            .ledger;
        assert!(seq < 20_000, "the ledger never grew past its bound");
    }
    assert!(matches!(ledger.encode(), Err(LedgerError::TooLarge)));
}

/// An order known only from its refund is kept, read back as it was
/// written, and gives nothing.
#[test]
fn an_order_known_only_from_its_refund_gives_nothing() {
    let month = Terms::month(A, "pilotusera");
    let ledger = PaymentLedger::new()
        .apply(
            &live(0, vec![month.refund(1, 800, true), month.dispute(2, 800)]),
            &pilot_users(),
            NOW,
            false,
        )
        .unwrap()
        .ledger;
    let record = &ledger.orders()[&order(A)];
    assert_eq!(record.grant, None);
    assert_eq!(record.refunds.len(), 1);
    assert!(record.dispute.is_some());
    let bytes = ledger.encode().unwrap();
    assert_eq!(PaymentLedger::decode(&bytes).unwrap(), ledger);
    assert!(ledger.entitlements(false).users().is_empty());
    assert!(ledger.entitlements(true).users().is_empty());
}

/// A new period follows the later of the user's last period and their own
/// expiry: their own when it is later, the last period's end otherwise.
#[test]
fn a_new_period_follows_the_later_of_the_last_period_and_the_own_expiry() {
    let now = NOW.as_secs();
    let users = by_id(vec![
        user("pilotusera", UserStatus::Active, Some(now + 5 * DAY)),
        user("pilotuserb", UserStatus::Active, Some(now + 100 * DAY)),
    ]);
    let applied = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
                    Terms::month("bbbbbbbbbbbbbbbbbbbb", "pilotusera").grant(2),
                ],
            ),
            &users,
            NOW,
            false,
        )
        .unwrap();
    let outcome = |text| applied.ledger.orders()[&order(text)].grant.unwrap().outcome;
    assert_eq!(
        outcome("aaaaaaaaaaaaaaaaaaaa"),
        period(now + 5 * DAY, now + 35 * DAY)
    );
    assert_eq!(
        outcome("bbbbbbbbbbbbbbbbbbbb"),
        period(now + 35 * DAY, now + 65 * DAY)
    );
    // The user's own expiry later than the last period: the next period
    // follows it.
    let later = by_id(vec![user(
        "pilotusera",
        UserStatus::Active,
        Some(now + 200 * DAY),
    )]);
    let next = applied
        .ledger
        .apply(
            &live(
                2,
                vec![Terms::month("cccccccccccccccccccc", "pilotusera").grant(3)],
            ),
            &later,
            NOW,
            false,
        )
        .unwrap();
    assert_eq!(
        next.ledger.orders()[&order("cccccccccccccccccccc")]
            .grant
            .unwrap()
            .outcome,
        period(now + 200 * DAY, now + 230 * DAY)
    );
}

/// A refund or dispute of an order whose grant was held says the order was
/// never granted, as for one known only from its refund.
#[test]
fn a_refund_of_a_held_order_says_it_was_never_granted() {
    let held = Terms::month(A, "pilotuserz");
    let applied = PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    held.grant(1),
                    held.refund(2, 800, true),
                    held.dispute(3, 800),
                ],
            ),
            &pilot_users(),
            NOW,
            false,
        )
        .unwrap();
    assert!(!applied.ledger.orders()[&order(A)].granted());
    assert_eq!(
        applied.events[1],
        LedgerEvent::Refunded {
            order: order(A),
            user: id("pilotuserz"),
            amount_refunded: 800,
            in_full: true,
            granted: false,
        }
    );
    assert_eq!(
        applied.events[2],
        LedgerEvent::Disputed {
            order: order(A),
            user: id("pilotuserz"),
            amount_disputed: 800,
            granted: false,
        }
    );
    let month = Terms::month(B, "pilotusera");
    let granted = PaymentLedger::new()
        .apply(&live(0, vec![month.grant(1)]), &pilot_users(), NOW, false)
        .unwrap()
        .ledger;
    assert!(granted.orders()[&order(B)].granted());
}
