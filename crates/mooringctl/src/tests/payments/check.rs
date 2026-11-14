// SPDX-License-Identifier: GPL-3.0-or-later

//! The check against Stripe in the daemon's pull, tick by tick, against a
//! scripted portal that answers Stripe's requests too: a page waits until
//! Stripe has said what it knows of its grants, one request a tick through
//! the pull's gate; what Stripe's answers come to; and what the log and
//! `portal payments` say of it. Every object of Stripe's here is
//! synthetic.

use std::fs;
use std::time::Duration;

use mooring_daemon_core::payments::{
    CHECKOUT_AFTER, CHECKOUT_BEFORE, GrantOutcome, HeldReason, PortalOrigin, PullSettings,
    StopReason,
};
use mooring_model::secret::SecretEntry;
use mooring_model::{StripeReadKey, UserId, UserStatus};
use mooring_store::{PAYMENT_PULL_FILE, SecretStore, update_payment_pull};
use serde_json::{Value, json};

use super::super::support::{Harness, NOW};
use super::pull::{OPEN, Opening, URL, answer, requests, tick, tick_for, users};
use super::{FIRST, SECOND, connect, grant, harness, ledger_on_disk, page};
use crate::payments::curl::{FetchFailure, PortalAnswer};
use crate::payments::judge::{PULL_EVERY, StripeJudged, judge_stripe};
use crate::payments::pull::{Puller, RETRY_FIRST};

const A: &str = "aaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbb";

/// The renewal paid by the invoice `in_1SynthCycle`: the portal's id for it.
const RENEWAL: &str = "sbc7dxq3cceajeb9ncge";

/// The key the tests store, synthetic.
fn key(fill: char) -> StripeReadKey {
    StripeReadKey::parse(&format!("rk_live_{}", fill.to_string().repeat(99))).unwrap()
}

/// Connects the pull at `revision` with the check against Stripe on, and
/// stores key `fill`; without a fill, no key.
fn check_on(harness: &mut Harness, revision: u64, fill: Option<char>) {
    connect(harness, revision, false, 1);
    if let Some(fill) = fill {
        harness
            .secrets
            .put(SecretEntry::StripeReadKey(key(fill)))
            .unwrap();
    }
    write_settings(harness, &with_check(revision, true));
}

/// The settings the tests connect with, the check on or off.
fn with_check(revision: u64, on: bool) -> PullSettings {
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    PullSettings::connected(revision, origin, false, on)
}

fn write_settings(harness: &Harness, settings: &PullSettings) {
    update_payment_pull::<()>(&harness.support_dir(), 4096, |_| {
        Ok(Some(settings.encode().unwrap()))
    })
    .unwrap();
}

/// A paid live checkout of a payment of £8.00 that names `order`, with a
/// field the check never reads.
fn checkout(id: &str, order: &str) -> Value {
    json!({
        "id": id,
        "object": "checkout.session",
        "client_reference_id": order,
        "payment_status": "paid",
        "mode": "payment",
        "amount_total": 800,
        "currency": "gbp",
        "livemode": true,
        "subscription": null,
        "payment_link": null,
        "customer_details": {"email": "payer@example.org"},
    })
}

/// Stripe's page of `data`.
fn stripe_page(data: Vec<Value>, has_more: bool) -> Vec<u8> {
    serde_json::to_vec(&json!({"object": "list", "data": data, "has_more": has_more})).unwrap()
}

/// The checkouts' address for an order paid at the tests' `paid_at`.
fn checkouts_url(after: Option<&str>) -> String {
    let paid_at = NOW - 60;
    format!(
        "https://api.stripe.com/v1/checkout/sessions?status=complete&created%5Bgte%5D={}&created%5Blte%5D={}&limit=20{}",
        paid_at - CHECKOUT_BEFORE,
        paid_at + CHECKOUT_AFTER,
        after.map_or_else(String::new, |after| format!("&starting_after={after}"))
    )
}

/// What the pull says while a page waits for Stripe about `order`.
fn asking(order: &str, left: usize) -> String {
    format!(
        "payment pull: asking Stripe about the payment of order {order} ({left} grant(s) of the page wait for the check against Stripe)"
    )
}

const GRANTED_UNTIL: &str = "service from 2026-10-13 19:20:00 UTC until 2026-11-12 19:20:00 UTC";

/// A live grant waits for Stripe: the portal's page is held in memory,
/// nothing is written, and Stripe is asked on the next tick with the read
/// key, for the week of checkouts before the payment. Once Stripe confirms
/// it, the page is applied whole and the grant recorded as confirmed; no
/// note and no file holds the key.
#[test]
fn a_live_grant_waits_for_stripe_and_is_granted_once_confirmed() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    harness.portal.ok(&stripe_page(
        vec![checkout("cs_live_1", B), checkout("cs_live_2", A)],
        false,
    ));
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 1)]);
    assert_eq!(ledger_on_disk(&harness), None);
    assert!(format!("{puller:?}").contains("waits_for_stripe: true"));
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        notes,
        [
            format!(
                "payment: order {A} granted user {FIRST} {GRANTED_UNTIL}; Stripe confirmed its payment"
            ),
            "payment pull: pulling; the cursor is at 1".to_owned(),
        ]
    );
    let made = harness.portal.requests.borrow().clone();
    assert_eq!(made.len(), 2);
    assert_eq!(made[0].url, format!("{URL}0"));
    assert_eq!(made[0].peer, "the portal");
    assert_eq!(made[1].url, checkouts_url(None));
    assert_eq!(made[1].peer, "Stripe");
    assert_eq!(made[1].token, key('K').expose_str());
    assert_eq!(made[1].within, Duration::from_secs(10));
    let ledger = ledger_on_disk(&harness).unwrap();
    assert_eq!(ledger.cursor(), 1);
    let grant = ledger.orders().values().next().unwrap().grant.unwrap();
    assert!(grant.confirmed);
    let first = UserId::parse(FIRST).unwrap();
    assert!(puller.entitlements().user(&first).is_some());
    // The next page is due in five minutes, as without the check.
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    assert_eq!(harness.portal.requests.borrow().len(), 2);
    assert!(!format!("{puller:?}").contains(key('K').expose_str()));
    let listed = harness.run(&["portal", "payments"]);
    assert!(
        listed
            .stdout
            .contains("\n  check against Stripe: on: each live payment is confirmed at Stripe before it is granted\n"),
        "{}",
        listed.stdout
    );
    assert!(
        listed
            .stdout
            .contains(&format!("{GRANTED_UNTIL}; confirmed at Stripe\n")),
        "{}",
        listed.stdout
    );
    assert!(!listed.stdout.contains(key('K').expose_str()));
}

/// A grant Stripe does not confirm is held, gives nothing, and the log
/// says what Stripe said.
#[test]
fn a_grant_stripe_does_not_confirm_is_held_with_why() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    let mut unpaid = checkout("cs_live_1", A);
    unpaid["payment_status"] = json!("unpaid");
    harness.portal.ok(&stripe_page(vec![unpaid], false));
    tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        tick(&mut harness, &mut puller, OPEN),
        [
            format!(
                "payment: order {A} for user {FIRST} is held, not granted (stripe_unpaid: its payment at Stripe is not paid); settle it at Stripe"
            ),
            "payment pull: pulling; the cursor is at 1".to_owned(),
        ]
    );
    let ledger = ledger_on_disk(&harness).unwrap();
    let grant = ledger.orders().values().next().unwrap().grant.unwrap();
    assert_eq!(
        grant.outcome,
        GrantOutcome::Held {
            reason: HeldReason::StripeUnpaid
        }
    );
    assert!(!grant.confirmed);
    let first = UserId::parse(FIRST).unwrap();
    assert!(puller.entitlements().user(&first).is_none());
}

/// With plans kept, Stripe confirms a grant only on its plan's Payment
/// Link: a checkout on another link is held for that link, one on the
/// plan's is granted; a grant of a plan not kept is held before Stripe is
/// asked.
#[test]
fn with_plans_kept_a_checkout_must_be_on_its_plan_s_link() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let kept = super::plans::book(super::plans::sold());
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    write_settings(
        &harness,
        &PullSettings::connected(3, origin, false, true).planning(3, kept),
    );
    let mut puller = Puller::open(&harness.support_dir());
    let mut unsold = grant(3, "cccccccccccccccccccc", SECOND);
    unsold["plan"] = json!("month-gift");
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, A, FIRST), grant(2, B, SECOND), unsold],
        false,
    ));
    let mut elsewhere = checkout("cs_live_1", A);
    elsewhere["payment_link"] = json!("plink_1Pack");
    harness.portal.ok(&stripe_page(vec![elsewhere], false));
    let mut on_its_link = checkout("cs_live_2", B);
    on_its_link["payment_link"] = json!("plink_1Month");
    harness.portal.ok(&stripe_page(vec![on_its_link], false));
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 2)]);
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(B, 1)]);
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        notes,
        [
            format!(
                "payment: order {A} for user {FIRST} is held, not granted (stripe_differs: what Stripe says was paid differs from the order: its checkout was on Payment Link plink_1Pack, not one of its plan's); settle it at Stripe"
            ),
            format!(
                "payment: order {B} granted user {SECOND} {GRANTED_UNTIL}; Stripe confirmed its payment"
            ),
            format!(
                "payment: order cccccccccccccccccccc for user {SECOND} is held, not granted (plan_unknown: the plans kept on the Mac have none of its plan's id; if the portal sells it, keep the portal's plan file first (`mooringctl portal plans set`)); settle it at Stripe"
            ),
            "payment pull: pulling; the cursor is at 3".to_owned(),
        ]
    );
}

/// A lookup reads Stripe's pages one request a tick, each after the last
/// checkout of the page before, and the grants of a page one after the
/// other; the note names each grant once.
#[test]
fn a_lookup_goes_page_by_page_one_request_a_tick() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, A, FIRST), grant(2, B, SECOND)],
        false,
    ));
    harness.portal.ok(&stripe_page(
        vec![checkout("cs_live_1", "zzzzzzzzzzzzzzzzzzzz")],
        true,
    ));
    harness
        .portal
        .ok(&stripe_page(vec![checkout("cs_live_2", A)], false));
    harness
        .portal
        .ok(&stripe_page(vec![checkout("cs_live_3", B)], false));
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 2)]);
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(B, 1)]);
    assert_eq!(ledger_on_disk(&harness), None);
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes.len(), 3, "{notes:?}");
    assert!(notes[0].ends_with("; Stripe confirmed its payment"));
    assert!(notes[1].ends_with("; Stripe confirmed its payment"));
    assert_eq!(
        requests(&harness),
        [
            format!("{URL}0"),
            checkouts_url(None),
            checkouts_url(Some("cs_live_1")),
            checkouts_url(None),
        ]
    );
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 2);
}

/// A page refused without the check is refused the same with it, and
/// Stripe is not asked: a page of Stripe's test mode while no rehearsal is
/// on.
#[test]
fn a_page_refused_without_the_check_is_refused_with_it() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(false, 0, vec![grant(1, A, FIRST)], false));
    assert_eq!(
        tick(&mut harness, &mut puller, OPEN),
        [
            "payment pull: the portal's payments are of Stripe's test mode and no rehearsal is on; nothing is granted and the cursor stays"
        ]
    );
    assert_eq!(requests(&harness), [format!("{URL}0")]);
    assert_eq!(ledger_on_disk(&harness), None);
    assert!(format!("{puller:?}").contains("waits_for_stripe: false"));
}

/// A page whose last grant waiting for Stripe needs it no more, its user
/// revoked meanwhile, is applied at the next tick without asking.
#[test]
fn a_page_that_needs_stripe_no_more_is_applied_without_asking() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 1)]);
    let mut users = users();
    users
        .get_mut(&UserId::parse(FIRST).unwrap())
        .unwrap()
        .status = UserStatus::RevokePending;
    assert_eq!(
        tick_for(&mut harness, &mut puller, OPEN, &users),
        [
            format!(
                "payment: order {A} for user {FIRST} is held, not granted (user_revoked); settle it at Stripe"
            ),
            "payment pull: pulling; the cursor is at 1".to_owned(),
        ]
    );
    assert_eq!(requests(&harness), [format!("{URL}0")]);
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
}

/// What to ask is worked out again each tick: a user revoked while
/// Stripe's pages are read for their grant is held without asking Stripe
/// more of it, and the lookup goes on to the page's next grant.
#[test]
fn a_lookup_whose_grant_needs_none_any_more_is_dropped() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, A, FIRST), grant(2, B, SECOND)],
        false,
    ));
    harness.portal.ok(&stripe_page(
        vec![checkout("cs_live_1", "zzzzzzzzzzzzzzzzzzzz")],
        true,
    ));
    harness
        .portal
        .ok(&stripe_page(vec![checkout("cs_live_3", B)], false));
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 2)]);
    // Stripe has more checkouts than the first page, and the user of the
    // first grant is being revoked by the next tick.
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    let mut users = users();
    users
        .get_mut(&UserId::parse(FIRST).unwrap())
        .unwrap()
        .status = UserStatus::RevokePending;
    let notes = tick_for(&mut harness, &mut puller, OPEN, &users);
    assert_eq!(notes.len(), 3, "{notes:?}");
    assert_eq!(
        notes[0],
        format!(
            "payment: order {A} for user {FIRST} is held, not granted (user_revoked); settle it at Stripe"
        )
    );
    assert!(
        notes[1].starts_with(&format!("payment: order {B} granted user {SECOND} "))
            && notes[1].ends_with("; Stripe confirmed its payment"),
        "{notes:?}"
    );
    assert_eq!(notes[2], "payment pull: pulling; the cursor is at 2");
    // Nothing more was asked of the first grant's checkouts.
    assert_eq!(
        requests(&harness),
        [format!("{URL}0"), checkouts_url(None), checkouts_url(None)]
    );
}

/// A renewal is confirmed through its first order: that order's checkout
/// gives the subscription, whose paid invoices hold the renewal's.
#[test]
fn a_renewal_is_confirmed_through_its_subscription() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    let mut first = grant(1, A, FIRST);
    first["plan_kind"] = json!("month_auto");
    let mut renewal = first.clone();
    renewal["seq"] = json!(2);
    renewal["order"] = json!(RENEWAL);
    renewal["renewal_of"] = json!(A);
    harness
        .portal
        .ok(&page(true, 0, vec![first, renewal], false));
    let mut began = checkout("cs_live_1", A);
    began["mode"] = json!("subscription");
    began["subscription"] = json!("sub_1Synth");
    // The first order's lookup, then the renewal's: checkouts, invoices.
    harness.portal.ok(&stripe_page(vec![began.clone()], false));
    harness.portal.ok(&stripe_page(vec![began], false));
    harness.portal.ok(&stripe_page(
        vec![json!({
            "id": "in_1SynthCycle",
            "object": "invoice",
            "status": "paid",
            "amount_paid": 800,
            "currency": "gbp",
            "billing_reason": "subscription_cycle",
            "livemode": true,
        })],
        false,
    ));
    for _ in 0..4 {
        tick(&mut harness, &mut puller, OPEN);
    }
    assert_eq!(
        requests(&harness)[3],
        "https://api.stripe.com/v1/invoices?subscription=sub_1Synth&status=paid&limit=20"
    );
    let ledger = ledger_on_disk(&harness).unwrap();
    assert_eq!(ledger.cursor(), 2);
    assert!(
        ledger
            .orders()
            .values()
            .all(|record| record.grant.unwrap().confirmed)
    );
}

/// A page that needs nothing of Stripe is applied at once, without a key:
/// a grant held before Stripe is asked, a refund, a renewal whose first
/// order Mooring does not hold, and a rehearsal's test-mode page.
#[test]
fn a_page_that_needs_nothing_of_stripe_is_applied_at_once() {
    let mut harness = harness();
    check_on(&mut harness, 2, None);
    let mut puller = Puller::open(&harness.support_dir());
    let mut orphan = grant(2, B, SECOND);
    orphan["plan_kind"] = json!("month_auto");
    orphan["renewal_of"] = json!("zzzzzzzzzzzzzzzzzzzz");
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, A, "nobodyhere"), orphan],
        false,
    ));
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        notes,
        [
            format!(
                "payment: order {A} for user nobodyhere is held, not granted (unknown_user); settle it at Stripe"
            ),
            format!(
                "payment: order {B} for user {SECOND} is held, not granted (stripe_no_first_order: Mooring holds no record of the order whose subscription it renews); settle it at Stripe"
            ),
            "payment pull: pulling; the cursor is at 2".to_owned(),
        ]
    );
    assert_eq!(requests(&harness), [format!("{URL}0")]);
    // A rehearsal's test-mode page is not checked.
    let mut rehearsing = harness_with_check_and_rehearsal();
    let mut puller = Puller::open(&rehearsing.support_dir());
    rehearsing
        .portal
        .ok(&page(false, 0, vec![grant(1, A, FIRST)], false));
    let notes = tick(&mut rehearsing, &mut puller, OPEN);
    assert_eq!(
        notes[0],
        format!(
            "payment: order {A} granted user {FIRST} {GRANTED_UNTIL} (rehearsal, Stripe test mode)"
        )
    );
    assert_eq!(requests(&rehearsing).len(), 1);
}

/// A harness whose pull rehearses with the check on, and holds no key.
fn harness_with_check_and_rehearsal() -> Harness {
    let mut harness = harness();
    connect(&mut harness, 1, true, 1);
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    write_settings(&harness, &PullSettings::connected(2, origin, true, true));
    harness
}

/// Stripe is asked only where the pull may ask: while the Mac is on no
/// foreign network and the probe round leaves room.
#[test]
fn stripe_is_asked_only_through_the_pull_s_gate() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    harness
        .portal
        .ok(&stripe_page(vec![checkout("cs_live_1", A)], false));
    tick(&mut harness, &mut puller, OPEN);
    let foreign = Opening {
        room: Some(Duration::from_secs(10)),
        clear: false,
    };
    assert_eq!(
        tick(&mut harness, &mut puller, foreign),
        [
            "payment pull: waiting while the Mac is on a network other than the M7 and the declared own networks"
        ]
    );
    let no_room = Opening {
        room: Some(Duration::from_millis(999)),
        clear: true,
    };
    assert!(tick(&mut harness, &mut puller, no_room).is_empty());
    assert_eq!(requests(&harness).len(), 1);
    tick(&mut harness, &mut puller, OPEN);
    assert_eq!(requests(&harness).len(), 2);
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
}

/// Stripe's 400, 401, 403 and 404 stop the pull, with what Stripe said:
/// nothing of the page is kept, and once the settings change the page is
/// asked for again.
#[test]
fn stripe_s_refusals_stop_the_pull_until_the_settings_change() {
    let stops = [
        (
            401,
            StopReason::StripeUnauthorized,
            "Stripe answered 401: the read key is wrong or was revoked; make a new restricted key and give it to `mooringctl portal stripe-check on`",
        ),
        (
            403,
            StopReason::StripeForbidden,
            "Stripe answered 403: the read key may not read checkouts or invoices; give it Read on Checkout Sessions and Invoices, or make a new one",
        ),
        (
            400,
            StopReason::StripeBadRequest,
            "Stripe answered 400 or 404: it says the check's request is wrong",
        ),
        (
            404,
            StopReason::StripeBadRequest,
            "Stripe answered 400 or 404: it says the check's request is wrong",
        ),
    ];
    for (status, reason, why) in stops {
        let mut harness = harness();
        check_on(&mut harness, 2, Some('K'));
        let mut puller = Puller::open(&harness.support_dir());
        harness
            .portal
            .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
        answer(
            &harness,
            status,
            None,
            br#"{"error": {"type": "invalid_request_error", "code": "api_key_expired", "message": "Expired API Key provided: rk_live_****ZZZZ"}}"#,
        );
        tick(&mut harness, &mut puller, OPEN);
        assert_eq!(
            tick(&mut harness, &mut puller, OPEN),
            [format!(
                "payment pull: stopped: {why} (invalid_request_error: api_key_expired); it pulls again once its settings change (`mooringctl portal stripe-check on` with a key, or `portal stripe-check off`)"
            )],
            "{status}"
        );
        let ledger = ledger_on_disk(&harness).unwrap();
        assert_eq!(ledger.cursor(), 0);
        assert!(ledger.orders().is_empty());
        let stop = ledger.stopped().unwrap();
        assert_eq!((stop.reason, stop.settings_revision), (reason, 2));
        // The page that waited is dropped with the stop.
        assert!(format!("{puller:?}").contains("waits_for_stripe: false"));
        assert_eq!(
            tick(&mut harness, &mut puller, OPEN),
            [format!(
                "payment pull: stopped ({}) since 2026-10-13 19:20:00 UTC, until its settings change",
                reason.as_str()
            )]
        );
        // The check off: the page is asked for again, and applied as listed.
        write_settings(&harness, &with_check(3, false));
        harness
            .portal
            .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
        let notes = tick(&mut harness, &mut puller, OPEN);
        assert_eq!(
            notes[0],
            format!(
                "payment pull: its settings changed since it stopped ({}); pulling again",
                reason.as_str()
            )
        );
        assert_eq!(
            notes[1],
            format!("payment: order {A} granted user {FIRST} {GRANTED_UNTIL}")
        );
        assert_eq!(requests(&harness)[2], format!("{URL}0"));
    }
}

/// Stripe's 429 waits for its `Retry-After`; its other failures, an
/// answer that cannot be read and no answer wait as the portal's do, a
/// minute at first. The page waits with them, and Stripe is asked the same
/// again.
#[test]
fn stripe_s_failures_wait_and_the_page_waits_with_them() {
    let failures: Vec<(Result<PortalAnswer, FetchFailure>, &str, Duration)> = vec![
        (
            Ok(PortalAnswer {
                status: 429,
                retry_after: Some("30".to_owned()),
                body: Vec::new(),
            }),
            "payment pull: Stripe answered 429 (Retry-After: 30); asking again in 30 s",
            Duration::from_secs(30),
        ),
        (
            Ok(PortalAnswer {
                status: 500,
                retry_after: None,
                body: br#"{"error": {"type": "api_error"}}"#.to_vec(),
            }),
            "payment pull: Stripe answered 500 (api_error); the page waits, and Stripe is asked again",
            RETRY_FIRST,
        ),
        (
            Ok(PortalAnswer {
                status: 402,
                retry_after: None,
                body: b"payment required\n".to_vec(),
            }),
            "payment pull: Stripe answered 402 (an answer of 17 bytes that is not Stripe's error document); the page waits, and Stripe is asked again",
            RETRY_FIRST,
        ),
        (
            Ok(PortalAnswer {
                status: 200,
                retry_after: None,
                body: b"<html>".to_vec(),
            }),
            "payment pull: Stripe's answer does not decode as a list of checkout.session; the page waits, and Stripe is asked again",
            RETRY_FIRST,
        ),
        (
            Err(FetchFailure::TimedOut),
            "payment pull: no answer from Stripe: the request took longer than its slot",
            RETRY_FIRST,
        ),
    ];
    for (failure, expected, wait) in failures {
        let mut harness = harness();
        check_on(&mut harness, 2, Some('K'));
        let mut puller = Puller::open(&harness.support_dir());
        harness
            .portal
            .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
        harness.portal.answer(failure);
        harness
            .portal
            .ok(&stripe_page(vec![checkout("cs_live_1", A)], false));
        tick(&mut harness, &mut puller, OPEN);
        assert_eq!(tick(&mut harness, &mut puller, OPEN), [expected]);
        // It waits, as long as said.
        let due_in = puller.due_in().unwrap();
        assert!(
            due_in <= wait && due_in + Duration::from_secs(5) > wait,
            "{expected}: {due_in:?}"
        );
        assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
        assert_eq!(requests(&harness).len(), 2);
        assert_eq!(ledger_on_disk(&harness), None);
        // Once the wait has passed, the same request again.
        puller.due_now();
        let notes = tick(&mut harness, &mut puller, OPEN);
        assert!(
            notes[0].ends_with("; Stripe confirmed its payment"),
            "{notes:?}"
        );
        let made = requests(&harness);
        assert_eq!(made[1], made[2]);
    }
}

/// A key that cannot be read holds the page and says so, as a token that
/// cannot be read does; once it is stored, Stripe is asked.
#[test]
fn a_key_that_cannot_be_read_holds_the_page() {
    let mut harness = harness();
    check_on(&mut harness, 2, None);
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    harness
        .portal
        .ok(&stripe_page(vec![checkout("cs_live_1", A)], false));
    tick(&mut harness, &mut puller, OPEN);
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0].starts_with(
            "payment pull: the check against Stripe is on, and its read key cannot be read: "
        ),
        "{notes:?}"
    );
    assert!(notes[0].ends_with("; the page waits"));
    assert_eq!(requests(&harness).len(), 1);
    harness
        .secrets
        .put(SecretEntry::StripeReadKey(key('L')))
        .unwrap();
    puller.due_now();
    tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        harness.portal.requests.borrow()[1].token,
        key('L').expose_str()
    );
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
}

/// The read key is kept for the settings' revision, and read again when
/// that revision comes back after the settings file was lost.
#[test]
fn the_key_is_read_again_when_its_revision_comes_back() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    answer(&harness, 500, None, br#"{"error": {"type": "api_error"}}"#);
    tick(&mut harness, &mut puller, OPEN);
    tick(&mut harness, &mut puller, OPEN);
    assert_eq!(requests(&harness).len(), 2);
    // The file goes, and comes back at the same revision with another key.
    fs::remove_file(harness.support_dir().join(PAYMENT_PULL_FILE)).unwrap();
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    harness
        .secrets
        .put(SecretEntry::StripeReadKey(key('M')))
        .unwrap();
    write_settings(&harness, &with_check(2, true));
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    harness
        .portal
        .ok(&stripe_page(vec![checkout("cs_live_1", A)], false));
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 1)]);
    tick(&mut harness, &mut puller, OPEN);
    let made = harness.portal.requests.borrow().clone();
    assert_eq!(made.len(), 4);
    assert_eq!(made[1].token, key('K').expose_str());
    assert_eq!(made[3].token, key('M').expose_str());
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
}

/// A change of the settings drops the page that waits: it is asked for
/// again under the new settings, and the key is read again.
#[test]
fn a_change_of_the_settings_drops_the_page_that_waits() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    harness
        .portal
        .ok(&stripe_page(vec![checkout("cs_live_1", A)], false));
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 1)]);
    harness
        .secrets
        .put(SecretEntry::StripeReadKey(key('M')))
        .unwrap();
    write_settings(&harness, &with_check(3, true));
    // Asked for again, and waiting again.
    assert_eq!(tick(&mut harness, &mut puller, OPEN), [asking(A, 1)]);
    tick(&mut harness, &mut puller, OPEN);
    let made = harness.portal.requests.borrow().clone();
    assert_eq!(made[0].url, format!("{URL}0"));
    assert_eq!(made[1].url, format!("{URL}0"));
    assert_eq!(made[2].token, key('M').expose_str());
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
}

/// What Stripe's answer to a lookup comes to: its page, a stop, a wait or
/// a failure; a note keeps Stripe's error type and code and nothing else of
/// its answer: never its message, and of a body of another shape only its
/// length.
#[test]
fn stripe_s_answers_come_to_a_page_a_stop_a_wait_or_a_failure() {
    let answered = |status: u16, retry_after: Option<&str>, body: &[u8]| {
        judge_stripe(PortalAnswer {
            status,
            retry_after: retry_after.map(str::to_owned),
            body: body.to_vec(),
        })
    };
    assert_eq!(
        answered(200, None, b"{}"),
        StripeJudged::Page(b"{}".to_vec())
    );
    let error = br#"{"error": {"type": "invalid_request_error", "code": "parameter_unknown", "message": "Received unknown parameter: acct_1Synth"}}"#;
    for (status, reason) in [
        (400, StopReason::StripeBadRequest),
        (401, StopReason::StripeUnauthorized),
        (403, StopReason::StripeForbidden),
        (404, StopReason::StripeBadRequest),
    ] {
        assert_eq!(
            answered(status, None, error),
            StripeJudged::Stop {
                reason,
                text: "invalid_request_error: parameter_unknown".to_owned()
            }
        );
    }
    assert_eq!(
        answered(429, Some("12"), b""),
        StripeJudged::Throttled {
            wait: Duration::from_secs(12),
            stated: Some("12".to_owned())
        }
    );
    assert_eq!(
        answered(429, None, b""),
        StripeJudged::Throttled {
            wait: PULL_EVERY,
            stated: None
        }
    );
    for status in [402, 409, 500, 503, 302] {
        assert_eq!(
            answered(
                status,
                None,
                br#"{"error": {"code": "lock_timeout", "message": "try later"}}"#
            ),
            StripeJudged::Failed {
                status,
                text: "lock_timeout".to_owned()
            }
        );
    }
    // Type and code are escaped and cut, as any text of a peer's.
    assert_eq!(
        answered(
            500,
            None,
            format!(
                r#"{{"error": {{"type": "api\nerror", "code": "{}"}}}}"#,
                "x".repeat(300)
            )
            .as_bytes()
        ),
        StripeJudged::Failed {
            status: 500,
            text: format!("api\\u{{a}}error: {}", "x".repeat(185)),
        }
    );
    assert_eq!(
        answered(
            500,
            None,
            br#"{"error": {"message": "Invalid API Key provided: rk_live_****Synth"}}"#
        ),
        StripeJudged::Failed {
            status: 500,
            text: "an error without a type or code".to_owned()
        }
    );
    // Not Stripe's error document: its length alone, whatever it says.
    for body in [
        &b"<html>bad gateway</html>"[..],
        br#"{"error": "Invalid API Key provided: rk_live_****Synth"}"#,
        br#"{"error": {"type": 7, "message": "Invalid API Key provided: rk_live_****Synth"}}"#,
        b"",
    ] {
        assert_eq!(
            answered(502, None, body),
            StripeJudged::Failed {
                status: 502,
                text: format!(
                    "an answer of {} bytes that is not Stripe's error document",
                    body.len()
                ),
            }
        );
        assert_eq!(
            answered(401, None, body),
            StripeJudged::Stop {
                reason: StopReason::StripeUnauthorized,
                text: format!(
                    "an answer of {} bytes that is not Stripe's error document",
                    body.len()
                ),
            }
        );
    }
}

/// A grant held because no checkout at Stripe names its order is listed as
/// any hold is, by its reason.
#[test]
fn a_hold_for_what_stripe_said_is_listed_as_any_hold() {
    let mut harness = harness();
    check_on(&mut harness, 2, Some('K'));
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    harness.portal.ok(&stripe_page(Vec::new(), false));
    tick(&mut harness, &mut puller, OPEN);
    tick(&mut harness, &mut puller, OPEN);
    let listed = harness.run(&["portal", "payments"]);
    assert!(
        listed.stdout.contains(
            "applied 2026-10-13 19:20:00 UTC: held, not granted (stripe_no_payment): settle it at Stripe\n"
        ),
        "{}",
        listed.stdout
    );
}
