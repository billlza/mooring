// SPDX-License-Identifier: GPL-3.0-or-later

//! The ledger with the check against Stripe on (design §9.6): which grants
//! Stripe must confirm, a page applied as Stripe said, and what the ledger
//! records of it.

use std::collections::BTreeMap;
use std::iter;

use mooring_model::{SuspendReason, User, UserId, UserStatus};
use serde_json::{Value, json};

use super::{DAY, NOW, PILOT, Terms, by_id, id, live, order, pilot_users, secs, user};
use crate::payments::{
    Applied, ApplyRefusal, Checked, Confirmable, Contradiction, Difference, FeedPage, GrantOutcome,
    HeldReason, LedgerError, LedgerEvent, OrderTerms, PaymentLedger, Refusal, Verdict, Verdicts,
};

/// A renewing month's first order, for pilotusera.
const MONTH: &str = "aaaaaaaaaaaaaaaaaaaa";
/// A pack, for pilotuserb.
const PACK: &str = "bbbbbbbbbbbbbbbbbbbb";
/// A month for a user the deployment does not hold.
const STRANGER: &str = "cccccccccccccccccccc";
/// The renewal of [`MONTH`].
const RENEWAL: &str = "dddddddddddddddddddd";
/// A renewal of an order Mooring never recorded, for pilotuserb.
const ORPHAN: &str = "eeeeeeeeeeeeeeeeeeee";
/// The order [`ORPHAN`] renews.
const NEVER_SEEN: &str = "ffffffffffffffffffff";

/// A renewing month for `user`: the first order when `renewal_of` is
/// `None`.
const fn month_auto(
    order: &'static str,
    user: &'static str,
    renewal_of: Option<&'static str>,
) -> Terms {
    Terms {
        kind: "month_auto",
        renewal_of,
        ..Terms::month(order, user)
    }
}

/// A page of every kind of entry the check sees: a first order, a pack, a
/// grant for a stranger, a refund, a renewal of the first order, and a
/// renewal of an order never seen.
fn mixed_entries() -> Vec<Value> {
    vec![
        month_auto(MONTH, "pilotusera", None).grant(1),
        Terms::pack(PACK, "pilotuserb").grant(2),
        Terms::month(STRANGER, "pilotuserz").grant(3),
        Terms::pack(PACK, "pilotuserb").refund(4, 300, false),
        month_auto(RENEWAL, "pilotusera", Some(MONTH)).grant(5),
        month_auto(ORPHAN, "pilotuserb", Some(NEVER_SEEN)).grant(6),
    ]
}

/// The terms of `order` on `page`.
fn terms_on(page: &FeedPage, text: &str) -> OrderTerms {
    page.entries()
        .iter()
        .find(|entry| entry.order == order(text))
        .unwrap()
        .terms
        .clone()
}

fn period(from: u64, until: u64) -> GrantOutcome {
    GrantOutcome::Period {
        from: secs(from),
        until: secs(until),
    }
}

/// `pairs` as verdicts.
fn verdicts(pairs: Vec<(&str, Verdict)>) -> Verdicts {
    pairs
        .into_iter()
        .map(|(text, verdict)| (order(text), verdict))
        .collect()
}

/// Every grant of [`mixed_entries`] that needs a verdict, confirmed.
fn every_confirmed() -> Verdicts {
    verdicts(vec![
        (MONTH, Verdict::Confirmed),
        (PACK, Verdict::Confirmed),
        (RENEWAL, Verdict::Confirmed),
        (ORPHAN, Verdict::Confirmed),
    ])
}

/// The grants Stripe must still be asked about when `ledger` applies
/// `page` at [`NOW`] with `said`, in order; none once it applies it.
fn unconfirmed(
    ledger: &PaymentLedger,
    page: &FeedPage,
    users: &BTreeMap<UserId, User>,
    said: &Verdicts,
) -> Vec<Confirmable> {
    match ledger.apply_checked(page, users, NOW, false, said).unwrap() {
        Checked::Applied(_) => Vec::new(),
        Checked::Unconfirmed { next, rest } => iter::once(*next).chain(rest).collect(),
    }
}

/// The page `checked` applied.
fn applied(checked: Result<Checked, ApplyRefusal>) -> Applied {
    match checked {
        Ok(Checked::Applied(applied)) => applied,
        other => panic!("not applied: {other:?}"),
    }
}

/// Stripe must confirm each live grant that would give a period or a pack,
/// in the page's order: a renewal with its first order's terms when the
/// page or the ledger holds that order. A grant held before Stripe is
/// asked (a stranger's), a refund, and a grant with a verdict need none.
#[test]
fn stripe_must_confirm_each_live_grant_that_would_give() {
    let page = live(0, mixed_entries());
    let users = pilot_users();
    let month_terms = terms_on(&page, MONTH);
    assert_eq!(
        unconfirmed(&PaymentLedger::new(), &page, &users, &Verdicts::new()),
        [
            Confirmable {
                order: order(MONTH),
                terms: month_terms.clone(),
                first: None,
            },
            Confirmable {
                order: order(PACK),
                terms: terms_on(&page, PACK),
                first: None,
            },
            Confirmable {
                order: order(RENEWAL),
                terms: terms_on(&page, RENEWAL),
                first: Some(month_terms.clone()),
            },
            Confirmable {
                order: order(ORPHAN),
                terms: terms_on(&page, ORPHAN),
                first: None,
            },
        ]
    );
    // A grant with a verdict is not asked about again.
    let given = verdicts(vec![
        (MONTH, Verdict::Confirmed),
        (ORPHAN, Verdict::Refused(Refusal::NoFirstOrder)),
    ]);
    let rest = unconfirmed(&PaymentLedger::new(), &page, &users, &given);
    let rest: Vec<&str> = rest.iter().map(|target| target.order.as_str()).collect();
    assert_eq!(rest, [PACK, RENEWAL]);
    // A renewal whose first order the ledger holds from an earlier page.
    let first = PaymentLedger::new()
        .apply(
            &live(0, vec![month_auto(MONTH, "pilotusera", None).grant(1)]),
            &users,
            NOW,
            false,
        )
        .unwrap()
        .ledger;
    let renewal = live(
        1,
        vec![month_auto(RENEWAL, "pilotusera", Some(MONTH)).grant(2)],
    );
    let listed = unconfirmed(&first, &renewal, &users, &Verdicts::new());
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].first, Some(month_terms));
}

/// A page is applied as Stripe said: a grant confirmed is granted and
/// recorded so; one refused is held for Stripe's reason, gives nothing,
/// and its event says what Stripe said. The rest are applied as without
/// the check.
#[test]
fn a_page_is_applied_as_stripe_said() {
    let page = live(0, mixed_entries());
    let differs = Refusal::Differs(Difference::Amount { found: Some(1) });
    let said = verdicts(vec![
        (MONTH, Verdict::Confirmed),
        (PACK, Verdict::Refused(Refusal::Unpaid)),
        (RENEWAL, Verdict::Refused(differs.clone())),
        (ORPHAN, Verdict::Refused(Refusal::NoFirstOrder)),
    ]);
    let applied =
        applied(PaymentLedger::new().apply_checked(&page, &pilot_users(), NOW, false, &said));
    let now = NOW.as_secs();
    assert_eq!(
        applied.events[0],
        LedgerEvent::Granted {
            order: order(MONTH),
            user: id("pilotusera"),
            outcome: period(now, now + 30 * DAY),
            livemode: true,
            suspended: None,
            confirmed: true,
        }
    );
    assert_eq!(
        applied.events[1],
        LedgerEvent::Held {
            order: order(PACK),
            user: id("pilotuserb"),
            reason: HeldReason::StripeUnpaid,
            refusal: Some(Refusal::Unpaid),
        }
    );
    assert_eq!(
        applied.events[2],
        LedgerEvent::Held {
            order: order(STRANGER),
            user: id("pilotuserz"),
            reason: HeldReason::UnknownUser,
            refusal: None,
        }
    );
    assert!(matches!(
        applied.events[3],
        LedgerEvent::Refunded { granted: false, .. }
    ));
    assert_eq!(
        applied.events[4],
        LedgerEvent::Held {
            order: order(RENEWAL),
            user: id("pilotusera"),
            reason: HeldReason::StripeDiffers,
            refusal: Some(differs),
        }
    );
    assert_eq!(
        applied.events[5],
        LedgerEvent::Held {
            order: order(ORPHAN),
            user: id("pilotuserb"),
            reason: HeldReason::StripeNoPayment,
            refusal: Some(Refusal::NoFirstOrder),
        }
    );
    let ledger = &applied.ledger;
    assert_eq!(ledger.cursor(), 6);
    let grant = |text: &str| ledger.orders()[&order(text)].grant.unwrap();
    assert!(grant(MONTH).confirmed);
    assert_eq!(grant(MONTH).outcome, period(now, now + 30 * DAY));
    for (text, reason) in [
        (PACK, HeldReason::StripeUnpaid),
        (STRANGER, HeldReason::UnknownUser),
        (RENEWAL, HeldReason::StripeDiffers),
        (ORPHAN, HeldReason::StripeNoPayment),
    ] {
        assert!(!grant(text).confirmed, "{text}");
        assert_eq!(grant(text).outcome, GrantOutcome::Held { reason }, "{text}");
    }
    // Only the confirmed month counts.
    let entitlements = ledger.entitlements(false);
    let a = entitlements.user(&id("pilotusera")).unwrap();
    assert!(a.period_at(secs(now + 30 * DAY - 1)).is_some());
    assert!(a.period_at(secs(now + 30 * DAY)).is_none());
    assert!(entitlements.user(&id("pilotuserb")).is_none());
    // What Stripe confirmed is kept on disk.
    let bytes = ledger.encode().unwrap();
    assert_eq!(&PaymentLedger::decode(&bytes).unwrap(), ledger);
}

/// With the check on, a page waits until Stripe has said what it knows of
/// every grant that needs it; verdicts of orders the page does not hold,
/// or of grants that need none, change nothing.
#[test]
fn a_page_waits_until_stripe_has_said_of_every_grant() {
    let page = live(0, mixed_entries());
    let users = pilot_users();
    let partial = verdicts(vec![(MONTH, Verdict::Confirmed)]);
    let Checked::Unconfirmed { next, rest } = PaymentLedger::new()
        .apply_checked(&page, &users, NOW, false, &partial)
        .unwrap()
    else {
        panic!("applied without every verdict");
    };
    assert_eq!(next.order, order(PACK));
    let rest: Vec<&str> = rest.iter().map(|target| target.order.as_str()).collect();
    assert_eq!(rest, [RENEWAL, ORPHAN]);
    let mut beyond = every_confirmed();
    beyond.insert(order(NEVER_SEEN), Verdict::Refused(Refusal::NoCheckout));
    beyond.insert(order(STRANGER), Verdict::Refused(Refusal::Unpaid));
    assert_eq!(
        PaymentLedger::new().apply_checked(&page, &users, NOW, false, &beyond),
        PaymentLedger::new().apply_checked(&page, &users, NOW, false, &every_confirmed())
    );
}

/// With the check off, every grant is applied as the portal lists it and
/// none is recorded as confirmed; with it on and every grant confirmed,
/// the ledger differs only in that record.
#[test]
fn with_the_check_off_nothing_is_confirmed() {
    let page = live(0, mixed_entries());
    let users = pilot_users();
    let off = PaymentLedger::new()
        .apply(&page, &users, NOW, false)
        .unwrap();
    let on =
        applied(PaymentLedger::new().apply_checked(&page, &users, NOW, false, &every_confirmed()));
    for (record, checked) in off
        .ledger
        .orders()
        .values()
        .zip(on.ledger.orders().values())
    {
        let (record, checked) = (record.grant.unwrap(), checked.grant.unwrap());
        assert!(!record.confirmed);
        assert_eq!(record.outcome, checked.outcome);
        let gave = !matches!(checked.outcome, GrantOutcome::Held { .. });
        assert_eq!(checked.confirmed, gave);
    }
    for event in &off.events {
        if let LedgerEvent::Granted { confirmed, .. } = event {
            assert!(!confirmed);
        }
    }
    assert_eq!(
        off.ledger.entitlements(false),
        on.ledger.entitlements(false)
    );
}

/// A rehearsal's test-mode grants are never checked: the page is applied
/// as without the check. A page the ledger would refuse is refused before
/// Stripe is asked anything, and a grant the ledger holds already is
/// repeated without a verdict.
#[test]
fn a_rehearsal_is_not_checked_and_a_page_refused_is_never_asked_about() {
    let pilot = FeedPage::decode(PILOT.as_bytes(), 0).unwrap();
    let users = pilot_users();
    let none = Verdicts::new();
    let ledger = PaymentLedger::new();
    assert_eq!(
        ledger.apply_checked(&pilot, &users, NOW, true, &none),
        Ok(Checked::Applied(
            ledger.apply(&pilot, &users, NOW, true).unwrap()
        ))
    );
    assert_eq!(
        ledger.apply_checked(&pilot, &users, NOW, false, &none),
        Err(ApplyRefusal::TestMode)
    );
    let elsewhere = live(3, vec![Terms::month(MONTH, "pilotusera").grant(4)]);
    assert_eq!(
        ledger.apply_checked(&elsewhere, &users, NOW, false, &none),
        Err(ApplyRefusal::CursorMoved {
            after: 3,
            cursor: 0
        })
    );
    let first = ledger
        .apply(
            &live(0, vec![Terms::month(MONTH, "pilotusera").grant(1)]),
            &users,
            NOW,
            false,
        )
        .unwrap()
        .ledger;
    let changed = live(1, vec![Terms::pack(MONTH, "pilotusera").grant(2)]);
    assert_eq!(
        first.apply_checked(&changed, &users, NOW, false, &none),
        Err(ApplyRefusal::Contradicted {
            seq: 2,
            order: order(MONTH),
            contradiction: Contradiction::TermsDiffer,
        })
    );
    let repeated = live(1, vec![Terms::month(MONTH, "pilotusera").grant(2)]);
    assert_eq!(
        first.apply_checked(&repeated, &users, NOW, false, &none),
        Ok(Checked::Applied(
            first.apply(&repeated, &users, NOW, false).unwrap()
        ))
    );
}

/// A user being revoked is held before Stripe is asked; a suspended user's
/// grant is checked, and its event says both.
#[test]
fn the_user_s_status_comes_before_the_check() {
    let users = by_id(vec![
        user("pilotusera", UserStatus::RevokePending, None),
        user(
            "pilotuserb",
            UserStatus::Suspended {
                reason: SuspendReason::Expired,
                since: secs(1_796_000_000),
            },
            None,
        ),
    ]);
    let page = live(
        0,
        vec![
            Terms::month(MONTH, "pilotusera").grant(1),
            Terms::month(PACK, "pilotuserb").grant(2),
        ],
    );
    let listed = unconfirmed(&PaymentLedger::new(), &page, &users, &Verdicts::new());
    let listed: Vec<&str> = listed.iter().map(|target| target.order.as_str()).collect();
    assert_eq!(listed, [PACK]);
    let applied = applied(PaymentLedger::new().apply_checked(
        &page,
        &users,
        NOW,
        false,
        &verdicts(vec![(PACK, Verdict::Confirmed)]),
    ));
    let now = NOW.as_secs();
    assert_eq!(
        applied.events,
        [
            LedgerEvent::Held {
                order: order(MONTH),
                user: id("pilotusera"),
                reason: HeldReason::UserRevoked,
                refusal: None,
            },
            LedgerEvent::Granted {
                order: order(PACK),
                user: id("pilotuserb"),
                outcome: period(now, now + 30 * DAY),
                livemode: true,
                suspended: Some(SuspendReason::Expired),
                confirmed: true,
            },
        ]
    );
}

/// The ledger's file keeps what Stripe confirmed, and refuses a grant
/// recorded as confirmed that gave nothing.
#[test]
fn only_a_live_grant_that_gave_is_recorded_as_confirmed() {
    let page = live(
        0,
        vec![
            Terms::month(MONTH, "pilotusera").grant(1),
            Terms::month(STRANGER, "pilotuserz").grant(2),
        ],
    );
    let applied = applied(PaymentLedger::new().apply_checked(
        &page,
        &pilot_users(),
        NOW,
        false,
        &verdicts(vec![(MONTH, Verdict::Confirmed)]),
    ));
    let mut value: Value = serde_json::from_slice(&applied.ledger.encode().unwrap()).unwrap();
    assert_eq!(value["orders"][0]["grant"]["confirmed"], json!(true));
    assert_eq!(value["orders"][1]["grant"]["confirmed"], json!(false));
    value["orders"][1]["grant"]["confirmed"] = json!(true);
    assert!(matches!(
        PaymentLedger::decode(&serde_json::to_vec(&value).unwrap()),
        Err(LedgerError::Inconsistent { .. })
    ));
}
