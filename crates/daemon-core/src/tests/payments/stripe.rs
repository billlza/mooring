// SPDX-License-Identifier: GPL-3.0-or-later

//! The check against Stripe's lookups (design §9.6): the renewal order ids
//! the portal derives, what each lookup asks Stripe, and what Stripe's
//! answers come to. Every object here is synthetic.

use serde_json::{Value, json};

use super::{DAY, Terms, live};
use crate::payments::{
    CHECKOUT_AFTER, CHECKOUT_BEFORE, Confirmable, Difference, HeldReason, Lookup, MAX_PAGES,
    MAX_STRIPE_ID_CHARS, Next, NotAStripeId, OrderId, OrderTerms, PAGE_LIMIT, PortalPlanKind,
    Refusal, STRIPE_API, STRIPE_VERSION, StripeAnswerError, StripeId, Verdict,
};

/// The first order, a month.
const FIRST: &str = "0123456789abcdefghjk";

/// The invoice that paid the renewal, and the renewal's order id, which
/// the portal derives from it (the ledger tests' renewal too).
const INVOICE: &str = "in_1SynthCycle";
const RENEWAL: &str = "sbc7dxq3cceajeb9ncge";

/// The subscription the first order's checkout began.
const SUBSCRIPTION: &str = "sub_1SynthMonthly";

/// The subscription a second checkout of the first order began.
const AGAIN: &str = "sub_1SynthTwice";

/// When the tests' orders were paid (`Terms`).
const PAID_AT: u64 = 1_796_990_000;

/// The portal derives a renewal's order id from the invoice that paid it:
/// the first 100 bits of BLAKE2s-256 of its domain and the invoice's id,
/// in Crockford's lower-case base 32. These are the portal's own vectors.
#[test]
fn a_renewal_s_order_id_is_the_portal_s() {
    for (invoice, id) in [
        (INVOICE, RENEWAL),
        ("in_1SynthCycld", "15k0jjqr0e1qsbc19nsv"),
        ("in_1SynthFirst", "xs1pa60bdhq2325vgh67"),
    ] {
        let derived = OrderId::for_renewal(invoice);
        assert_eq!(derived.as_str(), id, "{invoice}");
        assert_eq!(OrderId::parse(id).unwrap(), derived);
    }
}

/// A Stripe id is 1 to 255 letters, digits and underscores, so it is safe
/// in a query; anything else is refused without being echoed.
#[test]
fn a_stripe_id_is_letters_digits_and_underscores() {
    let longest = "a".repeat(MAX_STRIPE_ID_CHARS);
    for good in [
        "cs_live_a1B2",
        "in_1SynthCycle",
        "sub_1",
        "x",
        longest.as_str(),
    ] {
        assert_eq!(StripeId::parse(good).unwrap().as_str(), good);
        assert_eq!(
            serde_json::from_value::<StripeId>(json!(good)).unwrap(),
            StripeId::parse(good).unwrap()
        );
    }
    let too_long = "a".repeat(MAX_STRIPE_ID_CHARS + 1);
    for bad in [
        "",
        "cs-1",
        "cs 1",
        "cs_1&limit=1",
        "in_é",
        "cs/1",
        too_long.as_str(),
    ] {
        assert_eq!(StripeId::parse(bad), Err(NotAStripeId), "{bad:?}");
        assert!(serde_json::from_value::<StripeId>(json!(bad)).is_err());
    }
    assert!(!NotAStripeId.to_string().contains("limit"));
}

/// The terms of `entry`, a grant, as a live page holds them.
fn terms(entry: Value) -> OrderTerms {
    live(0, vec![entry]).entries()[0].terms.clone()
}

/// A renewing month: the first order when `renewal_of` is `None`.
const fn month_auto(order: &'static str, renewal_of: Option<&'static str>) -> Terms {
    Terms {
        kind: "month_auto",
        renewal_of,
        ..Terms::month(order, "pilotusera")
    }
}

/// The check of the first order `terms` (a month, a pack or a renewing
/// month's first).
fn first_order(order: &'static str, terms_of: &Terms) -> Confirmable {
    Confirmable {
        order: OrderId::parse(order).unwrap(),
        terms: terms(terms_of.grant(1)),
        first: None,
    }
}

/// The check of the renewal paid by [`INVOICE`] a month after its first
/// order, which the ledger holds.
fn renewal() -> Confirmable {
    let mut renewed = month_auto(RENEWAL, Some(FIRST)).grant(1);
    renewed["paid_at"] = json!(PAID_AT + 30 * DAY);
    renewed["recorded_at"] = json!(PAID_AT + 30 * DAY + 100);
    Confirmable {
        order: OrderId::parse(RENEWAL).unwrap(),
        terms: terms(renewed),
        first: Some(terms(month_auto(FIRST, None).grant(1))),
    }
}

/// A checkout as Stripe lists it: complete, paid, live, a payment of
/// £8.00 that names `reference`, with fields the check never reads, the
/// payer's among them.
fn checkout(id: &str, reference: Option<&str>) -> Value {
    json!({
        "id": id,
        "object": "checkout.session",
        "amount_subtotal": 800,
        "amount_total": 800,
        "client_reference_id": reference,
        "created": PAID_AT - 60,
        "currency": "gbp",
        "customer_details": {"email": "payer@example.org", "name": "A Payer", "address": null},
        "livemode": true,
        "mode": "payment",
        "payment_status": "paid",
        "status": "complete",
        "subscription": null,
    })
}

/// The first order's checkout, which began [`SUBSCRIPTION`].
fn subscription_checkout(id: &str) -> Value {
    let mut began = checkout(id, Some(FIRST));
    began["mode"] = json!("subscription");
    began["subscription"] = json!(SUBSCRIPTION);
    began
}

/// An invoice as Stripe lists it: a paid live renewal of £8.00.
fn invoice(id: &str) -> Value {
    json!({
        "id": id,
        "object": "invoice",
        "amount_due": 800,
        "amount_paid": 800,
        "billing_reason": "subscription_cycle",
        "currency": "gbp",
        "customer_email": "payer@example.org",
        "livemode": true,
        "status": "paid",
    })
}

/// A page of a list.
fn list(data: Vec<Value>, has_more: bool) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "object": "list",
        "url": "/v1/checkout/sessions",
        "has_more": has_more,
        "data": data,
    }))
    .unwrap()
}

/// The lookup `next` asks again with.
fn ask(next: Next) -> Lookup {
    match next {
        Next::Ask(lookup) => lookup,
        Next::Done(verdict) => panic!("done too early: {verdict:?}"),
    }
}

/// The verdict `next` is done with.
fn done(next: Next) -> Verdict {
    match next {
        Next::Done(verdict) => verdict,
        Next::Ask(lookup) => panic!("asks again: {}", lookup.url()),
    }
}

/// The checkouts' address, after `after`.
fn checkouts_url(paid_at: u64, after: Option<&str>) -> String {
    format!(
        "{STRIPE_API}/v1/checkout/sessions?status=complete&created%5Bgte%5D={}&created%5Blte%5D={}&limit={PAGE_LIMIT}{}",
        paid_at - CHECKOUT_BEFORE,
        paid_at + CHECKOUT_AFTER,
        after.map_or_else(String::new, |after| format!("&starting_after={after}"))
    )
}

/// The invoices' address for `subscription`, after `after`.
fn invoices_url(subscription: &str, after: Option<&str>) -> String {
    format!(
        "{STRIPE_API}/v1/invoices?subscription={subscription}&status=paid&limit={PAGE_LIMIT}{}",
        after.map_or_else(String::new, |after| format!("&starting_after={after}"))
    )
}

/// The API's address and release, and the window around a payment.
#[test]
fn the_lookups_ask_stripe_s_api_at_one_release() {
    assert_eq!(STRIPE_API, "https://api.stripe.com");
    assert_eq!(STRIPE_VERSION, "2026-10-28.endive");
    assert_eq!(PAGE_LIMIT, 20);
    assert_eq!(MAX_PAGES, 100);
    assert_eq!(CHECKOUT_BEFORE, 7 * DAY);
    assert_eq!(CHECKOUT_AFTER, 300);
}

/// A first order is looked for among the completed checkouts created from a
/// week before its payment to five minutes after, and is confirmed by a
/// paid live checkout that names it, of the plan's mode, currency and
/// amount, whatever else the page lists.
#[test]
fn a_first_order_is_confirmed_by_its_checkout() {
    for terms_of in [
        Terms::month(FIRST, "pilotusera"),
        Terms::pack(FIRST, "pilotusera"),
        month_auto(FIRST, None),
    ] {
        let lookup = ask(Lookup::start(first_order(FIRST, &terms_of)));
        assert_eq!(lookup.target().order.as_str(), FIRST);
        assert_eq!(lookup.url(), checkouts_url(PAID_AT, None));
        let mut paying = checkout("cs_live_2", Some(FIRST));
        if terms_of.kind == "month_auto" {
            paying["mode"] = json!("subscription");
            paying["subscription"] = json!(SUBSCRIPTION);
        }
        let page = list(
            vec![
                checkout("cs_live_1", None),
                checkout("cs_live_3", Some("zzzzzzzzzzzzzzzzzzzz")),
                paying,
            ],
            true,
        );
        assert_eq!(
            done(lookup.read(&page).unwrap()),
            Verdict::Confirmed,
            "{}",
            terms_of.kind
        );
    }
}

/// A checkout that names the order and does not pay it is refused for
/// how: not paid, of test mode, of another mode than the plan's, or in
/// another currency or amount. A value of Stripe's in a refusal is
/// escaped and cut to 40 characters.
#[test]
fn a_checkout_that_names_the_order_and_does_not_pay_it_is_refused_for_how() {
    let month = first_order(FIRST, &Terms::month(FIRST, "pilotusera"));
    let renewing = first_order(FIRST, &month_auto(FIRST, None));
    let cases: [(&Confirmable, &str, Value, Refusal); 9] = [
        (&month, "payment_status", json!("unpaid"), Refusal::Unpaid),
        (
            &month,
            "payment_status",
            json!("no_payment_required"),
            Refusal::Unpaid,
        ),
        (
            &month,
            "livemode",
            json!(false),
            Refusal::Differs(Difference::TestMode),
        ),
        (
            &month,
            "mode",
            json!("subscription"),
            Refusal::Differs(Difference::Mode {
                found: "subscription".to_owned(),
                wanted: "payment",
            }),
        ),
        (
            &renewing,
            "mode",
            json!("payment"),
            Refusal::Differs(Difference::Mode {
                found: "payment".to_owned(),
                wanted: "subscription",
            }),
        ),
        (
            &month,
            "currency",
            json!("eur"),
            Refusal::Differs(Difference::Currency {
                found: "eur".to_owned(),
            }),
        ),
        (
            &month,
            "currency",
            Value::Null,
            Refusal::Differs(Difference::Currency {
                found: "none".to_owned(),
            }),
        ),
        (
            &month,
            "amount_total",
            json!(700),
            Refusal::Differs(Difference::Amount { found: Some(700) }),
        ),
        (
            &month,
            "amount_total",
            Value::Null,
            Refusal::Differs(Difference::Amount { found: None }),
        ),
    ];
    for (target, key, value, refusal) in cases {
        let mut differing = checkout("cs_live_1", Some(FIRST));
        if target.terms.plan_kind == PortalPlanKind::MonthAuto {
            differing["mode"] = json!("subscription");
            differing["subscription"] = json!(SUBSCRIPTION);
        }
        differing[key] = value.clone();
        let lookup = ask(Lookup::start(target.clone()));
        assert_eq!(
            done(lookup.read(&list(vec![differing], false)).unwrap()),
            Verdict::Refused(refusal),
            "{key} {value}"
        );
    }
    let mut forged = checkout("cs_live_1", Some(FIRST));
    forged["mode"] = json!(format!("x\n{}", "y".repeat(100)));
    let Verdict::Refused(Refusal::Differs(Difference::Mode { found, .. })) = done(
        ask(Lookup::start(month))
            .read(&list(vec![forged], false))
            .unwrap(),
    ) else {
        panic!("not a mode that differs");
    };
    assert!(found.starts_with("x\\u{a}yyy"), "{found}");
    assert_eq!(found.chars().count(), 40);
}

/// The closest refusal over every checkout that names the order is kept,
/// page after page: one that differs over one not paid, over none; the
/// earlier on a tie. A paying checkout on a later page confirms.
#[test]
fn the_closest_refusal_is_kept_page_after_page() {
    let target = first_order(FIRST, &Terms::month(FIRST, "pilotusera"));
    let mut unpaid = checkout("cs_live_1", Some(FIRST));
    unpaid["payment_status"] = json!("unpaid");
    let mut cheaper = checkout("cs_live_3", Some(FIRST));
    cheaper["amount_total"] = json!(1);
    let mut dearer = checkout("cs_live_4", Some(FIRST));
    dearer["amount_total"] = json!(2);
    let first_page = list(vec![unpaid.clone(), checkout("cs_live_2", None)], true);
    let lookup = ask(Lookup::start(target.clone()));
    let second = ask(lookup.read(&first_page).unwrap());
    assert_eq!(second.url(), checkouts_url(PAID_AT, Some("cs_live_2")));
    // Unpaid, then two that differ: the first that differs.
    let third = ask(second.clone().read(&list(vec![cheaper], true)).unwrap());
    assert_eq!(third.url(), checkouts_url(PAID_AT, Some("cs_live_3")));
    assert_eq!(
        done(
            third
                .read(&list(vec![dearer, unpaid.clone()], false))
                .unwrap()
        ),
        Verdict::Refused(Refusal::Differs(Difference::Amount { found: Some(1) }))
    );
    // Unpaid on the first page, nothing on the last: unpaid.
    assert_eq!(
        done(second.clone().read(&list(Vec::new(), false)).unwrap()),
        Verdict::Refused(Refusal::Unpaid)
    );
    // Unpaid on the first page, paid on the second: confirmed.
    assert_eq!(
        done(
            second
                .read(&list(vec![checkout("cs_live_5", Some(FIRST))], false))
                .unwrap()
        ),
        Verdict::Confirmed
    );
}

/// No checkout that names the order: no payment, whose hold is
/// `stripe_no_payment`.
#[test]
fn no_checkout_that_names_the_order_is_no_payment() {
    let target = first_order(FIRST, &Terms::pack(FIRST, "pilotusera"));
    let page = list(
        vec![
            checkout("cs_live_1", None),
            checkout("cs_live_2", Some("zzzzzzzzzzzzzzzzzzzz")),
        ],
        false,
    );
    let verdict = done(ask(Lookup::start(target)).read(&page).unwrap());
    assert_eq!(verdict, Verdict::Refused(Refusal::NoCheckout));
}

/// A lookup reads at most 100 pages, and is then over with what it found.
#[test]
fn a_lookup_reads_at_most_its_pages() {
    let target = first_order(FIRST, &Terms::month(FIRST, "pilotusera"));
    let mut unpaid = checkout("cs_live_0", Some(FIRST));
    unpaid["payment_status"] = json!("unpaid");
    let mut next = Lookup::start(target);
    let mut asked = 0;
    while let Next::Ask(lookup) = next {
        asked += 1;
        assert!(asked <= MAX_PAGES, "asked for page {asked}");
        let data = if asked == 1 {
            vec![unpaid.clone()]
        } else {
            vec![checkout(&format!("cs_live_{asked}"), None)]
        };
        next = lookup.read(&list(data, true)).unwrap();
    }
    assert_eq!(asked, MAX_PAGES);
    assert_eq!(next, Next::Done(Verdict::Refused(Refusal::Unpaid)));
}

/// An answer that is not a list of what was asked is refused: not JSON, a
/// key read missing or of another type, an id that is not Stripe's, an
/// object of another kind, or more said to follow an empty page.
#[test]
fn an_answer_that_is_not_a_list_of_what_was_asked_is_refused() {
    let lookup = ask(Lookup::start(first_order(
        FIRST,
        &Terms::month(FIRST, "pilotusera"),
    )));
    let read = |body: &[u8]| lookup.clone().read(body);
    assert!(matches!(
        read(b"<html>"),
        Err(StripeAnswerError::Decode {
            what: "checkout.session",
            ..
        })
    ));
    for key in [
        "id",
        "object",
        "client_reference_id",
        "payment_status",
        "mode",
        "amount_total",
        "currency",
        "livemode",
        "subscription",
    ] {
        let mut missing = checkout("cs_live_1", Some(FIRST));
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            matches!(
                read(&list(vec![missing], false)),
                Err(StripeAnswerError::Decode { .. })
            ),
            "{key}"
        );
    }
    let mut negative = checkout("cs_live_1", Some(FIRST));
    negative["amount_total"] = json!(-800);
    assert!(matches!(
        read(&list(vec![negative], false)),
        Err(StripeAnswerError::Decode { .. })
    ));
    let mut forged_id = checkout("cs_live_1", Some(FIRST));
    forged_id["id"] = json!("cs_1&created[gte]=0");
    assert!(matches!(
        read(&list(vec![forged_id], true)),
        Err(StripeAnswerError::Decode { .. })
    ));
    let mut other_kind = checkout("cs_live_1", Some(FIRST));
    other_kind["object"] = json!("invoice");
    assert!(matches!(
        read(&list(vec![other_kind], false)),
        Err(StripeAnswerError::Object {
            what: "checkout.session"
        })
    ));
    let mut not_a_list: Value = serde_json::from_slice(&list(Vec::new(), false)).unwrap();
    not_a_list["object"] = json!("search_result");
    assert!(matches!(
        read(&serde_json::to_vec(&not_a_list).unwrap()),
        Err(StripeAnswerError::Object { .. })
    ));
    assert!(matches!(
        read(&list(Vec::new(), true)),
        Err(StripeAnswerError::EmptyPage {
            what: "checkout.session"
        })
    ));
}

/// A renewal is looked for through its first order: every paid checkout
/// of it that began a subscription, in the week before its payment, all
/// pages of them; then the subscription's paid invoices, page by page, for
/// the invoice whose derived id is the renewal's.
#[test]
fn a_renewal_is_confirmed_by_its_subscription_s_invoice() {
    let lookup = ask(Lookup::start(renewal()));
    assert_eq!(lookup.target().order.as_str(), RENEWAL);
    // The first order's window, a month before the renewal was paid.
    assert_eq!(lookup.url(), checkouts_url(PAID_AT, None));
    let more = ask(lookup
        .read(&list(
            vec![
                checkout("cs_live_1", None),
                subscription_checkout("cs_live_2"),
            ],
            true,
        ))
        .unwrap());
    assert_eq!(more.url(), checkouts_url(PAID_AT, Some("cs_live_2")));
    let invoices = ask(more
        .read(&list(vec![checkout("cs_live_3", None)], false))
        .unwrap());
    assert_eq!(invoices.url(), invoices_url(SUBSCRIPTION, None));
    let later = ask(invoices
        .read(&list(vec![invoice("in_1SynthCycld")], true))
        .unwrap());
    assert_eq!(
        later.url(),
        invoices_url(SUBSCRIPTION, Some("in_1SynthCycld"))
    );
    assert_eq!(
        done(
            later
                .read(&list(
                    vec![invoice("in_1SynthFirst"), invoice(INVOICE)],
                    true
                ))
                .unwrap()
        ),
        Verdict::Confirmed
    );
}

/// A first order paid twice began two subscriptions, and the portal kept
/// one of them: the renewal's invoice is looked for in each, in the order
/// their checkouts were listed, and is no payment only when neither holds
/// it.
#[test]
fn a_renewal_of_an_order_paid_twice_is_looked_for_in_both_subscriptions() {
    let mut twice = subscription_checkout("cs_live_2");
    twice["subscription"] = json!(AGAIN);
    let checkouts = list(vec![twice, subscription_checkout("cs_live_1")], false);
    let again = ask(ask(Lookup::start(renewal())).read(&checkouts).unwrap());
    assert_eq!(again.url(), invoices_url(AGAIN, None));
    let later = ask(again
        .read(&list(vec![invoice("in_1SynthFirst")], true))
        .unwrap());
    assert_eq!(later.url(), invoices_url(AGAIN, Some("in_1SynthFirst")));
    let kept = ask(later.read(&list(Vec::new(), false)).unwrap());
    assert_eq!(kept.url(), invoices_url(SUBSCRIPTION, None));
    assert_eq!(
        done(kept.read(&list(vec![invoice(INVOICE)], false)).unwrap()),
        Verdict::Confirmed
    );
    let again = ask(ask(Lookup::start(renewal())).read(&checkouts).unwrap());
    let kept = ask(again
        .read(&list(vec![invoice("in_1SynthFirst")], false))
        .unwrap());
    assert_eq!(
        done(kept.read(&list(Vec::new(), false)).unwrap()),
        Verdict::Refused(Refusal::NoInvoice)
    );
}

/// A renewal's lookup reads at most 100 pages in all, checkouts and
/// invoices together, and is then over with what it found: no
/// subscription, or no invoice in those it found.
#[test]
fn a_renewal_s_lookup_reads_at_most_its_pages_in_all() {
    for (first_page, refusal) in [
        (
            vec![checkout("cs_live_0", Some(FIRST))],
            Refusal::NoSubscription,
        ),
        (vec![subscription_checkout("cs_live_0")], Refusal::NoInvoice),
    ] {
        let mut next = Lookup::start(renewal());
        let mut asked = 0;
        while let Next::Ask(lookup) = next {
            asked += 1;
            assert!(asked <= MAX_PAGES, "asked for page {asked}");
            let data = if asked == 1 {
                first_page.clone()
            } else {
                vec![checkout(&format!("cs_live_{asked}"), None)]
            };
            next = lookup.read(&list(data, true)).unwrap();
        }
        assert_eq!(asked, MAX_PAGES);
        assert_eq!(next, Next::Done(Verdict::Refused(refusal)));
    }
    // Checkouts of one page, then invoices to the end.
    let mut next = ask(Lookup::start(renewal()))
        .read(&list(vec![subscription_checkout("cs_live_1")], false))
        .unwrap();
    let mut asked = 1;
    while let Next::Ask(lookup) = next {
        asked += 1;
        assert!(asked <= MAX_PAGES, "asked for page {asked}");
        assert!(lookup.url().starts_with(&invoices_url(SUBSCRIPTION, None)));
        next = lookup
            .read(&list(vec![invoice(&format!("in_1Synth{asked:04}"))], true))
            .unwrap();
    }
    assert_eq!(asked, MAX_PAGES);
    assert_eq!(next, Next::Done(Verdict::Refused(Refusal::NoInvoice)));
}

/// A renewal whose first order Mooring does not hold is refused without
/// asking Stripe.
#[test]
fn a_renewal_without_its_first_order_is_not_asked_about() {
    let unknown_first = Confirmable {
        first: None,
        ..renewal()
    };
    assert_eq!(
        Lookup::start(unknown_first),
        Next::Done(Verdict::Refused(Refusal::NoFirstOrder))
    );
}

/// The renewal's invoice that does not pay it is refused for how: not
/// paid, of test mode, not a renewal of the subscription, or in another
/// currency or amount.
#[test]
fn a_renewal_s_invoice_that_does_not_pay_it_is_refused_for_how() {
    let cases: [(&str, Value, Refusal); 6] = [
        ("status", json!("open"), Refusal::Unpaid),
        (
            "livemode",
            json!(false),
            Refusal::Differs(Difference::TestMode),
        ),
        (
            "billing_reason",
            json!("subscription_create"),
            Refusal::Differs(Difference::Reason {
                found: "subscription_create".to_owned(),
            }),
        ),
        (
            "billing_reason",
            Value::Null,
            Refusal::Differs(Difference::Reason {
                found: "none".to_owned(),
            }),
        ),
        (
            "currency",
            json!("usd"),
            Refusal::Differs(Difference::Currency {
                found: "usd".to_owned(),
            }),
        ),
        (
            "amount_paid",
            json!(799),
            Refusal::Differs(Difference::Amount { found: Some(799) }),
        ),
    ];
    for (key, value, refusal) in cases {
        let invoices = ask(ask(Lookup::start(renewal()))
            .read(&list(vec![subscription_checkout("cs_live_1")], false))
            .unwrap());
        let mut differing = invoice(INVOICE);
        differing[key] = value.clone();
        assert_eq!(
            done(invoices.read(&list(vec![differing], false)).unwrap()),
            Verdict::Refused(refusal),
            "{key} {value}"
        );
    }
}

/// No paid live checkout of the first order that began a subscription, or
/// no invoice of it that is the renewal's: no payment.
#[test]
fn a_renewal_without_its_subscription_or_invoice_is_no_payment() {
    let mut unpaid = subscription_checkout("cs_live_1");
    unpaid["payment_status"] = json!("unpaid");
    let mut test_mode = subscription_checkout("cs_live_2");
    test_mode["livemode"] = json!(false);
    let mut one_off = subscription_checkout("cs_live_3");
    one_off["mode"] = json!("payment");
    let mut no_subscription = subscription_checkout("cs_live_4");
    no_subscription["subscription"] = Value::Null;
    let other_order = {
        let mut other = subscription_checkout("cs_live_5");
        other["client_reference_id"] = json!("zzzzzzzzzzzzzzzzzzzz");
        other
    };
    let lookup = ask(Lookup::start(renewal()));
    let second = ask(lookup
        .read(&list(vec![unpaid, test_mode, one_off], true))
        .unwrap());
    assert_eq!(second.url(), checkouts_url(PAID_AT, Some("cs_live_3")));
    assert_eq!(
        done(
            second
                .read(&list(vec![no_subscription, other_order], false))
                .unwrap()
        ),
        Verdict::Refused(Refusal::NoSubscription)
    );
    let invoices = ask(ask(Lookup::start(renewal()))
        .read(&list(vec![subscription_checkout("cs_live_1")], false))
        .unwrap());
    assert_eq!(
        done(
            invoices
                .read(&list(vec![invoice("in_1SynthFirst")], false))
                .unwrap()
        ),
        Verdict::Refused(Refusal::NoInvoice)
    );
}

/// Each refusal holds its grant for one of three reasons, and says why
/// without a value of Stripe's beyond what it carries.
#[test]
fn each_refusal_holds_for_its_reason() {
    let differs = Refusal::Differs(Difference::Amount { found: Some(700) });
    for (refusal, reason, text) in [
        (
            Refusal::NoCheckout,
            HeldReason::StripeNoPayment,
            "no completed checkout at Stripe names the order",
        ),
        (
            Refusal::NoFirstOrder,
            HeldReason::StripeNoFirstOrder,
            "Mooring holds no record of the order whose subscription it renews",
        ),
        (
            Refusal::NoSubscription,
            HeldReason::StripeNoPayment,
            "no paid checkout of its first order began a subscription at Stripe",
        ),
        (
            Refusal::NoInvoice,
            HeldReason::StripeNoPayment,
            "no paid invoice of its subscription at Stripe is the renewal's",
        ),
        (
            Refusal::Unpaid,
            HeldReason::StripeUnpaid,
            "its payment at Stripe is not paid",
        ),
        (
            differs,
            HeldReason::StripeDiffers,
            "what Stripe says was paid differs from the order: 700 was paid",
        ),
    ] {
        assert_eq!(refusal.held_reason(), reason, "{refusal:?}");
        assert_eq!(refusal.to_string(), text);
    }
    for (difference, text) in [
        (Difference::TestMode, "it was paid in Stripe's test mode"),
        (
            Difference::Mode {
                found: "setup".to_owned(),
                wanted: "payment",
            },
            "its checkout is of mode setup, and the plan's is payment",
        ),
        (
            Difference::Currency {
                found: "none".to_owned(),
            },
            "it was paid in none",
        ),
        (Difference::Amount { found: None }, "no amount was paid"),
        (
            Difference::Reason {
                found: "manual".to_owned(),
            },
            "its invoice's billing reason is manual, not subscription_cycle",
        ),
    ] {
        assert_eq!(difference.to_string(), text);
    }
    assert_eq!(HeldReason::StripeNoPayment.as_str(), "stripe_no_payment");
    assert_eq!(
        HeldReason::StripeNoFirstOrder.as_str(),
        "stripe_no_first_order"
    );
    assert_eq!(HeldReason::StripeUnpaid.as_str(), "stripe_unpaid");
    assert_eq!(HeldReason::StripeDiffers.as_str(), "stripe_differs");
}
