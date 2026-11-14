// SPDX-License-Identifier: GPL-3.0-or-later

//! The plans on the Mac (design §9.6): the portal's plan file as the Mac
//! reads it, the plans it keeps from file to file, what a grant's terms
//! come to against them, and the grants the ledger holds for them. Every
//! plan here is synthetic.
//!
//! `contract/portal-fixtures/payments/demo.json` is a byte-for-byte copy of
//! the portal repository's `contract/fixtures/payments/demo.json` at its
//! commit 8b7c170, where its reader (`crates/core/src/payment/catalogue.rs`)
//! is the one these tests mirror.

use std::iter;

use serde_json::{Value, json};

use super::{DAY, NOW, Terms, decode, document, id, live, order, pilot_users, secs};
use crate::payments::{
    Applied, Checked, GrantOutcome, HeldReason, LedgerError, LedgerEvent, LinkTaken,
    MAX_FILE_PLANS, MAX_PLAN_FILE_BYTES, MAX_STORED_PLANS, OrderTerms, PaymentLedger, PlanBook,
    PlanBookError, PlanFile, PlanFileError, PlanId, PlanVerdict, Refusal, Stored, StoredPlan,
    StripeId, Verdict, Verdicts,
};

/// The portal's sample plan file, of Stripe's test mode.
const DEMO: &str = include_str!("../../../../../contract/portal-fixtures/payments/demo.json");

/// A month, for pilotusera.
const MONTH: &str = "aaaaaaaaaaaaaaaaaaaa";
/// A pack, for pilotusera.
const PACK: &str = "bbbbbbbbbbbbbbbbbbbb";
/// A month at another price, for pilotuserb.
const DEARER: &str = "cccccccccccccccccccc";
/// A month of other days, for pilotuserb.
const LONGER: &str = "dddddddddddddddddddd";
/// A pack for a user the deployment does not hold.
const STRANGER: &str = "eeeeeeeeeeeeeeeeeeee";
/// A renewing month's first order, for pilotusera.
const FIRST: &str = "ffffffffffffffffffff";
/// The renewal of [`FIRST`].
const RENEWAL: &str = "gggggggggggggggggggg";

/// A plan as the portal's file lists it, of 30 days, on the Payment Link
/// `link` (`https://buy.stripe.com/<link>`, `plink_<link>`).
pub(super) fn listed(id: &str, kind: &str, traffic_gb: u64, amount: u64, link: &str) -> Value {
    json!({
        "id": id,
        "kind": kind,
        "days": 30,
        "traffic_gb": traffic_gb,
        "amount": amount,
        "payment_link": format!("https://buy.stripe.com/{link}"),
        "payment_link_id": format!("plink_{link}"),
    })
}

/// What the tests' grants buy ([`Terms`]): a month, a renewing month and a
/// pack, each of 30 days and 800 hundredths of a pound.
pub(super) fn sold() -> Vec<Value> {
    vec![
        listed("plan-month", "month", 100, 800, "1Month"),
        listed("plan-month-auto", "month_auto", 100, 800, "1Auto"),
        listed("plan-traffic", "traffic", 50, 800, "1Pack"),
    ]
}

/// The portal's live plan file of `plans`, in pounds.
pub(super) fn file_of(plans: Vec<Value>) -> Value {
    json!({
        "format": "mooring-portal-payments",
        "version": 1,
        "livemode": true,
        "currency": "gbp",
        "plans": plans,
        "manage_subscription_url": "https://billing.stripe.com/p/login/1Manage",
    })
}

/// `value` read as a plan file.
pub(super) fn parse(value: &Value) -> Result<PlanFile, PlanFileError> {
    PlanFile::parse(&serde_json::to_vec(value).unwrap())
}

/// The plans of the live file of `plans`, kept where none were.
pub(super) fn book_of(plans: Vec<Value>) -> PlanBook {
    PlanBook::default()
        .stored(&parse(&file_of(plans)).unwrap())
        .unwrap()
        .0
}

/// The Payment Link `plink_<text>`.
pub(super) fn plink(text: &str) -> StripeId {
    StripeId::parse(&format!("plink_{text}")).unwrap()
}

/// The terms of the grant `entry`.
fn terms_of(entry: Value) -> OrderTerms {
    live(0, vec![entry]).entries()[0].terms.clone()
}

/// Each kept plan's id, amount and whether it is current, in order.
fn kept(book: &PlanBook) -> Vec<(String, u64, bool)> {
    book.plans()
        .iter()
        .map(|plan| (plan.id.to_string(), plan.amount.get(), plan.current))
        .collect()
}

/// `text` as a plan id.
fn plan_id(text: &str) -> PlanId {
    PlanId::parse(text).unwrap()
}

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

/// The hold of `text`'s grant for `user`, for `reason`.
fn held(text: &str, user: &str, reason: HeldReason) -> LedgerEvent {
    LedgerEvent::Held {
        order: order(text),
        user: id(user),
        reason,
        refusal: None,
    }
}

/// The portal's sample is of test mode, which the Mac does not keep; as a
/// live file it is read with every plan, in its currency, each current.
#[test]
fn the_portal_s_sample_is_read_as_a_live_file() {
    assert!(matches!(
        PlanFile::parse(DEMO.as_bytes()),
        Err(PlanFileError::TestMode)
    ));
    let mut sample: Value = serde_json::from_str(DEMO).unwrap();
    sample["livemode"] = json!(true);
    let file = parse(&sample).unwrap();
    assert_eq!(
        serde_json::to_value(file.plans()).unwrap(),
        json!([
            {"id": "month-100", "kind": "month", "days": 30, "traffic_gb": 100, "amount": 800, "currency": "gbp", "payment_link_id": "plink_1SynthMonth", "current": true},
            {"id": "month-100-auto", "kind": "month_auto", "days": 30, "traffic_gb": 100, "amount": 800, "currency": "gbp", "payment_link_id": "plink_1SynthAuto", "current": true},
            {"id": "pack-50", "kind": "traffic", "days": 90, "traffic_gb": 50, "amount": 300, "currency": "gbp", "payment_link_id": "plink_1SynthPack", "current": true},
        ])
    );
}

/// Every live file the portal reads, the Mac reads: each bound at its end,
/// each currency, the most plans, the largest file, a page's and a link's
/// longest word, the test mode's keys absent, `null` or `false`, and,
/// with no renewing plan, no page to cancel one.
#[test]
fn every_live_file_the_portal_reads_is_read() {
    let longest = "a".repeat(128);
    let mut edges = file_of(vec![listed("a", "traffic", 100_000, 10_000_000, &longest)]);
    edges["plans"][0]["days"] = json!(3660);
    edges["plans"][0]["renewal_amount"] = json!(null);
    edges["plans"][0]["introductory"] = json!(false);
    edges["manage_subscription_url"] = json!(format!(
        "https://billing.stripe.com/p/login/{}_",
        "a".repeat(127)
    ));
    let edge_file = parse(&edges).unwrap();
    let plan = &edge_file.plans()[0];
    assert_eq!(
        (plan.days.get(), plan.traffic_gb.get(), plan.amount.get()),
        (3660, 100_000, 10_000_000)
    );
    assert_eq!(plan.payment_link_id, plink(&longest));
    let mut lowest = file_of(vec![listed("1", "month", 1, 1, "x_y")]);
    lowest["plans"][0]["days"] = json!(1);
    lowest["plans"][0]["payment_link_id"] = json!("plink_1");
    assert!(parse(&lowest).is_ok());
    for currency in ["aud", "cad", "cny", "eur", "gbp", "hkd", "sgd", "usd"] {
        let mut priced = file_of(sold());
        priced["currency"] = json!(currency);
        let file = parse(&priced).unwrap();
        assert!(
            file.plans()
                .iter()
                .all(|plan| plan.currency.as_str() == currency)
        );
    }
    let most: Vec<Value> = (0..MAX_FILE_PLANS)
        .map(|at| listed(&format!("plan-{at}"), "month", 100, 800, &format!("L{at}")))
        .collect();
    assert_eq!(parse(&file_of(most)).unwrap().plans().len(), MAX_FILE_PLANS);
    let mut no_renewal = file_of(vec![listed("plan-month", "month", 100, 800, "1Month")]);
    no_renewal
        .as_object_mut()
        .unwrap()
        .remove("manage_subscription_url");
    assert!(parse(&no_renewal).is_ok());
    no_renewal["manage_subscription_url"] = json!(null);
    assert!(parse(&no_renewal).is_ok());
    let mut largest = serde_json::to_vec(&file_of(sold())).unwrap();
    largest.resize(MAX_PLAN_FILE_BYTES, b' ');
    assert_eq!(PlanFile::parse(&largest).unwrap().plans().len(), 3);
    largest.push(b' ');
    assert!(matches!(
        PlanFile::parse(&largest),
        Err(PlanFileError::TooLarge)
    ));
}

/// A file of another shape, format, version, mode or currency, or of too
/// few or too many plans, is refused for why: the format first, and test
/// mode before anything a live file could not hold.
#[test]
fn a_plan_file_the_mac_does_not_keep_is_refused_for_why() {
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut value = file_of(sold());
        edit(&mut value);
        parse(&value)
    };
    assert!(matches!(
        PlanFile::parse(b"not json"),
        Err(PlanFileError::Decode(_))
    ));
    let shapes: Vec<(&str, Edit)> = vec![
        (
            "a key of no file",
            Box::new(|value| value["token"] = json!("x")),
        ),
        ("no format", Box::new(|value| remove(value, "format"))),
        ("no version", Box::new(|value| remove(value, "version"))),
        ("no mode", Box::new(|value| remove(value, "livemode"))),
        ("no currency", Box::new(|value| remove(value, "currency"))),
        ("no plans", Box::new(|value| remove(value, "plans"))),
        (
            "a version in words",
            Box::new(|value| value["version"] = json!("1")),
        ),
        (
            "a mode in words",
            Box::new(|value| value["livemode"] = json!("true")),
        ),
        (
            "an upper-case currency",
            Box::new(|value| value["currency"] = json!("GBP")),
        ),
        (
            "a page that is a number",
            Box::new(|value| value["manage_subscription_url"] = json!(5)),
        ),
        (
            "a plan's key of no plan",
            Box::new(|value| value["plans"][0]["price"] = json!(800)),
        ),
        (
            "a plan without its link id",
            Box::new(|value| remove(&mut value["plans"][0], "payment_link_id")),
        ),
        (
            "a plan without its link",
            Box::new(|value| remove(&mut value["plans"][0], "payment_link")),
        ),
        (
            "a plan without days",
            Box::new(|value| remove(&mut value["plans"][0], "days")),
        ),
        (
            "no days",
            Box::new(|value| value["plans"][0]["days"] = json!(0)),
        ),
        (
            "no traffic",
            Box::new(|value| value["plans"][0]["traffic_gb"] = json!(0)),
        ),
        (
            "no amount",
            Box::new(|value| value["plans"][0]["amount"] = json!(0)),
        ),
        (
            "a kind of no plan",
            Box::new(|value| value["plans"][0]["kind"] = json!("year")),
        ),
        (
            "an upper-case id",
            Box::new(|value| value["plans"][0]["id"] = json!("Plan-Month")),
        ),
        (
            "an id that begins with -",
            Box::new(|value| value["plans"][0]["id"] = json!("-month")),
        ),
        (
            "an id too long",
            Box::new(|value| value["plans"][0]["id"] = json!("m".repeat(33))),
        ),
        (
            "a link id of no Stripe id",
            Box::new(|value| value["plans"][0]["payment_link_id"] = json!("plink-1Month")),
        ),
        (
            "a renewal amount in words",
            Box::new(|value| value["plans"][0]["renewal_amount"] = json!("800")),
        ),
        (
            "an offer in words",
            Box::new(|value| value["plans"][0]["introductory"] = json!("no")),
        ),
    ];
    for (name, edit) in shapes {
        assert!(
            matches!(edited(&*edit), Err(PlanFileError::Decode(_))),
            "{name}"
        );
    }
    assert!(matches!(
        edited(&|value| value["format"] = json!("mooring-portal-entitlements")),
        Err(PlanFileError::Format)
    ));
    assert!(matches!(
        edited(&|value| {
            value["format"] = json!("mooring-portal-entitlements");
            value["version"] = json!(2);
        }),
        Err(PlanFileError::Format)
    ));
    for found in [0, 2] {
        assert!(matches!(
            edited(&|value| value["version"] = json!(found)),
            Err(PlanFileError::Version { found: read }) if read == found
        ));
    }
    assert!(matches!(
        edited(&|value| {
            value["livemode"] = json!(false);
            value["plans"][1]["renewal_amount"] = json!(1350);
            value["plans"][1]["introductory"] = json!(true);
        }),
        Err(PlanFileError::TestMode)
    ));
    for currency in ["jpy", "xxx"] {
        assert!(matches!(
            edited(&|value| value["currency"] = json!(currency)),
            Err(PlanFileError::Currency)
        ));
    }
    let most: Vec<Value> = (0..=MAX_FILE_PLANS)
        .map(|at| listed(&format!("plan-{at}"), "month", 100, 800, &format!("L{at}")))
        .collect();
    for plans in [Vec::new(), most] {
        let found = plans.len();
        assert!(matches!(
            parse(&file_of(plans)),
            Err(PlanFileError::PlanCount { found: read }) if read == found
        ));
    }
}

/// A change to a plan file.
type Edit = Box<dyn Fn(&mut Value)>;

/// `key` out of `value`.
fn remove(value: &mut Value, key: &str) {
    value.as_object_mut().unwrap().remove(key).unwrap();
}

/// A plan the portal would refuse is refused by its id and for why, and
/// nothing else of the file is quoted.
#[test]
fn a_plan_the_portal_would_refuse_is_refused_by_its_id() {
    let days = "its days must be between 1 and 3660";
    let traffic = "its traffic_gb must be between 1 and 100000";
    let amount = "its amount must be between 1 and 10000000 hundredths";
    let link_id = "its payment_link_id must be plink_ and 1 to 128 letters or digits";
    let renewal = "a live plan has no renewal_amount";
    let offer = "a live plan is not introductory";
    let page = "its payment_link must be https://buy.stripe.com/ and 1 to 128 letters, digits or _";
    let twice = "it is listed twice";
    let shared = "its Payment Link is another plan's";
    let too_long = "a".repeat(129);
    let cases = [
        ("days", json!(3661), days),
        ("traffic_gb", json!(100_001), traffic),
        ("amount", json!(10_000_001), amount),
        ("payment_link_id", json!("price_1Auto"), link_id),
        ("payment_link_id", json!("plink_"), link_id),
        ("payment_link_id", json!("plink_1_Auto"), link_id),
        (
            "payment_link_id",
            json!(format!("plink_{too_long}")),
            link_id,
        ),
        ("renewal_amount", json!(1350), renewal),
        ("renewal_amount", json!(0), renewal),
        ("introductory", json!(true), offer),
        ("payment_link", json!("http://buy.stripe.com/1Auto"), page),
        ("payment_link", json!("https://buy.stripe.com/"), page),
        (
            "payment_link",
            json!("https://buy.stripe.com/1Auto?prefilled_email=planted"),
            page,
        ),
        (
            "payment_link",
            json!("https://buy.stripe.com/1Auto#planted"),
            page,
        ),
        (
            "payment_link",
            json!("https://buy.stripe.com/a/planted"),
            page,
        ),
        (
            "payment_link",
            json!("https://buy.stripe.com.planted/1Auto"),
            page,
        ),
        ("payment_link", json!("https://buy.stripe.com/1-Auto"), page),
        (
            "payment_link",
            json!(format!("https://buy.stripe.com/{too_long}")),
            page,
        ),
        ("id", json!("plan-month"), twice),
        (
            "payment_link",
            json!("https://buy.stripe.com/1Month"),
            shared,
        ),
        ("payment_link_id", json!("plink_1Month"), shared),
    ];
    for (key, value, why) in cases {
        let mut file = file_of(sold());
        file["plans"][1][key] = value.clone();
        let refused = parse(&file).unwrap_err();
        let PlanFileError::Plan { plan, why: read } = &refused else {
            panic!("{key} {value}: {refused:?}");
        };
        let named = if key == "id" {
            "plan-month"
        } else {
            "plan-month-auto"
        };
        assert_eq!(*plan, plan_id(named), "{key} {value}");
        assert_eq!(*read, why, "{key} {value}");
        let text = refused.to_string();
        assert_eq!(text, format!("plan {named}: {why}"));
        assert!(!text.contains("planted"), "{text}");
    }
}

/// The page where a user cancels a renewal must be Stripe's customer
/// portal whenever it is named, and must be named when a plan renews.
#[test]
fn the_page_to_cancel_a_renewal_is_stripe_s() {
    for page in [
        json!("https://billing.stripe.com/p/login/"),
        json!("http://billing.stripe.com/p/login/1Manage"),
        json!("https://billing.stripe.com/p/login/1Manage?x=1"),
        json!("https://billing.stripe.com/p/login/1-Manage"),
        json!(format!(
            "https://billing.stripe.com/p/login/{}",
            "a".repeat(129)
        )),
    ] {
        for plans in [
            sold(),
            vec![listed("plan-month", "month", 100, 800, "1Month")],
        ] {
            let mut file = file_of(plans);
            file["manage_subscription_url"] = page.clone();
            assert!(
                matches!(parse(&file), Err(PlanFileError::ManageUrl)),
                "{page}"
            );
        }
    }
    let mut unnamed = file_of(sold());
    unnamed["manage_subscription_url"] = json!(null);
    assert!(matches!(parse(&unnamed), Err(PlanFileError::NoManageUrl)));
    remove(&mut unnamed, "manage_subscription_url");
    assert!(matches!(parse(&unnamed), Err(PlanFileError::NoManageUrl)));
}

/// A file's plans are kept as the current ones, after those of the files
/// before it: one the Mac knew is moved to the end, at its terms and link
/// whatever its flag, and one at new terms or on a new link is new.
#[test]
fn the_plans_kept_are_the_file_s_after_the_earlier_ones() {
    let first = parse(&file_of(sold())).unwrap();
    let (book, stored) = PlanBook::default().stored(&first).unwrap();
    assert_eq!(
        stored,
        Stored {
            listed: 3,
            new: 3,
            earlier: 0,
            dropped: 0
        }
    );
    assert_eq!(book.plans(), first.plans());
    assert_eq!(
        book.stored(&first),
        Ok((
            book.clone(),
            Stored {
                listed: 3,
                new: 0,
                earlier: 0,
                dropped: 0
            }
        ))
    );
    // The month dearer on a new link, the renewing month as it was, and no
    // pack.
    let second = parse(&file_of(vec![
        listed("plan-month", "month", 100, 900, "2Month"),
        listed("plan-month-auto", "month_auto", 100, 800, "1Auto"),
    ]))
    .unwrap();
    let (changed, stored) = book.stored(&second).unwrap();
    assert_eq!(
        stored,
        Stored {
            listed: 2,
            new: 1,
            earlier: 2,
            dropped: 0
        }
    );
    let entry = |id: &str, amount: u64, current: bool| (id.to_owned(), amount, current);
    assert_eq!(
        kept(&changed),
        [
            entry("plan-month", 800, false),
            entry("plan-traffic", 800, false),
            entry("plan-month", 900, true),
            entry("plan-month-auto", 800, true),
        ]
    );
    // The first file again: its plans come back, none new.
    let (again, stored) = changed.stored(&first).unwrap();
    assert_eq!(
        stored,
        Stored {
            listed: 3,
            new: 0,
            earlier: 1,
            dropped: 0
        }
    );
    assert_eq!(
        kept(&again),
        [
            entry("plan-month", 900, false),
            entry("plan-month", 800, true),
            entry("plan-month-auto", 800, true),
            entry("plan-traffic", 800, true),
        ]
    );
    // The same terms on another link are another plan.
    let moved = parse(&file_of(vec![listed(
        "plan-month",
        "month",
        100,
        800,
        "3Month",
    )]))
    .unwrap();
    assert_eq!(again.stored(&moved).unwrap().1.new, 1);
}

/// A Payment Link is kept for one plan: a file that lists other terms on
/// the link of a plan kept, current or earlier, under that plan's id or
/// another, is refused, naming its plan, the link and the plan kept on it.
/// New terms on a new link are kept, and so is any file where no plan is.
#[test]
fn a_file_that_puts_other_terms_on_a_kept_plan_s_link_is_refused() {
    let book = book_of(sold());
    let taken = |plan: &str, link: &str, kept: &str| {
        Err(LinkTaken {
            plan: plan_id(plan),
            link: plink(link),
            kept: plan_id(kept),
        })
    };
    let mut longer = listed("plan-month", "month", 100, 800, "1Month");
    longer["days"] = json!(31);
    for (other, kept) in [
        (longer, "plan-month"),
        (
            listed("plan-month", "month", 80, 800, "1Month"),
            "plan-month",
        ),
        (
            listed("plan-month", "month", 100, 900, "1Month"),
            "plan-month",
        ),
        (
            listed("plan-month", "month_auto", 100, 800, "1Month"),
            "plan-month",
        ),
        (
            listed("plan-year", "month", 100, 800, "1Month"),
            "plan-month",
        ),
        (
            listed("plan-month", "month", 100, 800, "1Pack"),
            "plan-traffic",
        ),
    ] {
        let file = parse(&file_of(vec![
            listed("plan-month-auto", "month_auto", 100, 800, "1Auto"),
            other.clone(),
        ]))
        .unwrap();
        let plan = &file.plans()[1];
        assert_eq!(
            book.stored(&file),
            taken(
                &plan.id.to_string(),
                &plan.payment_link_id.as_str()["plink_".len()..],
                kept
            ),
            "{other}"
        );
    }
    let mut euros = file_of(vec![listed("plan-month", "month", 100, 800, "1Month")]);
    euros["currency"] = json!("eur");
    assert_eq!(
        book.stored(&parse(&euros).unwrap()),
        taken("plan-month", "1Month", "plan-month")
    );
    // The link of a plan of an earlier file.
    let (later, _) = book
        .stored(
            &parse(&file_of(vec![listed(
                "plan-month",
                "month",
                100,
                900,
                "2Month",
            )]))
            .unwrap(),
        )
        .unwrap();
    assert!(!later.plans()[0].current);
    let fewer = parse(&file_of(vec![listed(
        "plan-month",
        "month",
        80,
        800,
        "1Month",
    )]))
    .unwrap();
    let refused = later.stored(&fewer);
    assert_eq!(refused, taken("plan-month", "1Month", "plan-month"));
    assert_eq!(
        refused.unwrap_err().to_string(),
        "plan plan-month is sold on plink_1Month, the Payment Link of plan plan-month kept at other terms; new terms need a new Payment Link"
    );
    let moved = parse(&file_of(vec![listed(
        "plan-month",
        "month",
        80,
        800,
        "3Month",
    )]))
    .unwrap();
    assert_eq!(later.stored(&moved).unwrap().1.new, 1);
    assert_eq!(PlanBook::default().stored(&fewer).unwrap().1.new, 1);
}

/// Past [`MAX_STORED_PLANS`], the plans no file has listed for longest are
/// dropped first; a file listed again is listed most recently.
#[test]
fn the_plans_listed_least_recently_are_dropped_first() {
    let file = |number: usize| {
        let plans = (0..MAX_FILE_PLANS)
            .map(|at| {
                listed(
                    &format!("p{number}-{at}"),
                    "month",
                    100,
                    800,
                    &format!("F{number}x{at}"),
                )
            })
            .collect();
        parse(&file_of(plans)).unwrap()
    };
    let mut book = PlanBook::default();
    for number in 0..4 {
        let (next, stored) = book.stored(&file(number)).unwrap();
        assert_eq!(
            stored,
            Stored {
                listed: MAX_FILE_PLANS,
                new: MAX_FILE_PLANS,
                earlier: number * MAX_FILE_PLANS,
                dropped: 0
            }
        );
        book = next;
    }
    assert_eq!(book.plans().len(), MAX_STORED_PLANS);
    let (relisted, stored) = book.stored(&file(0)).unwrap();
    assert_eq!(
        stored,
        Stored {
            listed: MAX_FILE_PLANS,
            new: 0,
            earlier: 72,
            dropped: 0
        }
    );
    let (fifth, stored) = relisted.stored(&file(4)).unwrap();
    assert_eq!(
        stored,
        Stored {
            listed: MAX_FILE_PLANS,
            new: MAX_FILE_PLANS,
            earlier: 72,
            dropped: MAX_FILE_PLANS
        }
    );
    let files: Vec<String> = fifth
        .plans()
        .iter()
        .step_by(MAX_FILE_PLANS)
        .map(|plan| plan.id.to_string())
        .collect();
    assert_eq!(files, ["p2-0", "p3-0", "p0-0", "p4-0"]);
    assert!(fifth.plans()[..72].iter().all(|plan| !plan.current));
    assert!(fifth.plans()[72..].iter().all(|plan| plan.current));
}

/// A grant's terms come to the links of the kept plans that sell them:
/// none kept is the check off; no plan of its id is unknown; plans of its
/// id at other terms differ, whichever term, even at another kept plan's
/// terms; the same terms on two links are sold on both.
#[test]
fn a_grant_s_terms_are_judged_by_the_plans_kept() {
    let month = Terms::month(MONTH, "pilotusera").grant(1);
    let terms = terms_of(month.clone());
    assert_eq!(PlanBook::default().judge(&terms), PlanVerdict::Off);
    assert_eq!(PlanBook::default().links_for(&terms), []);
    let book = book_of(sold());
    assert_eq!(
        book.judge(&terms),
        PlanVerdict::Sells {
            links: vec![plink("1Month")]
        }
    );
    assert_eq!(book.links_for(&terms), [plink("1Month")]);
    let mut unknown = month.clone();
    unknown["plan"] = json!("plan-year");
    assert_eq!(book.judge(&terms_of(unknown.clone())), PlanVerdict::Unknown);
    assert_eq!(book.links_for(&terms_of(unknown)), []);
    for (key, value) in [
        ("plan_kind", json!("traffic")),
        ("days", json!(31)),
        ("traffic_bytes", json!(100_000_000_001_u64)),
        ("traffic_bytes", json!(99_999_999_999_u64)),
        ("amount", json!(799)),
        ("currency", json!("eur")),
    ] {
        let mut other = month.clone();
        other[key] = value.clone();
        let other = terms_of(other);
        assert_eq!(book.judge(&other), PlanVerdict::Differs, "{key} {value}");
        assert_eq!(book.links_for(&other), [], "{key} {value}");
    }
    // The pack's terms under the month's id are not the pack's.
    let mut packed = month.clone();
    packed["plan_kind"] = json!("traffic");
    packed["traffic_bytes"] = json!(50_000_000_000_u64);
    assert_eq!(book.judge(&terms_of(packed)), PlanVerdict::Differs);
    let moved = book
        .stored(
            &parse(&file_of(vec![listed(
                "plan-month",
                "month",
                100,
                800,
                "2Month",
            )]))
            .unwrap(),
        )
        .unwrap()
        .0;
    assert_eq!(
        moved.judge(&terms),
        PlanVerdict::Sells {
            links: vec![plink("1Month"), plink("2Month")]
        }
    );
    assert_eq!(
        moved.judge(&terms_of(Terms::pack(PACK, "pilotusera").grant(1))),
        PlanVerdict::Sells {
            links: vec![plink("1Pack")]
        }
    );
}

/// A kept plan as the settings file holds it.
fn kept_plan(id: &str, link: &str, current: bool) -> Value {
    json!({
        "id": id,
        "kind": "month",
        "days": 30,
        "traffic_gb": 100,
        "amount": 800,
        "currency": "gbp",
        "payment_link_id": format!("plink_{link}"),
        "current": current,
    })
}

/// `plans` as the kept plans' list.
fn plans_of(plans: Vec<Value>) -> Vec<StoredPlan> {
    serde_json::from_value(Value::Array(plans)).unwrap()
}

/// The kept plans are a list of plans, each as a file lists it with its
/// currency and flag; a list no file could have left is refused: too many
/// plans, one the portal would refuse, or two on one Payment Link, one
/// plan twice among them. The same terms on two links are two plans.
#[test]
fn the_plans_kept_read_back_and_refuse_what_no_file_leaves() {
    let book = book_of(sold());
    let written = serde_json::to_value(&book).unwrap();
    assert_eq!(written, serde_json::to_value(book.plans()).unwrap());
    assert_eq!(serde_json::from_value::<PlanBook>(written).unwrap(), book);
    let most: Vec<Value> = (0..MAX_STORED_PLANS)
        .map(|at| kept_plan(&format!("plan-{at}"), &format!("L{at}"), false))
        .collect();
    assert_eq!(
        PlanBook::try_from(plans_of(most.clone()))
            .unwrap()
            .plans()
            .len(),
        MAX_STORED_PLANS
    );
    let mut too_many = most;
    too_many.push(kept_plan("plan-more", "More", true));
    assert_eq!(
        PlanBook::try_from(plans_of(too_many.clone())),
        Err(PlanBookError::TooMany)
    );
    assert!(serde_json::from_value::<PlanBook>(Value::Array(too_many)).is_err());
    for (key, value) in [
        ("days", json!(3661)),
        ("traffic_gb", json!(100_001)),
        ("amount", json!(10_000_001)),
        ("currency", json!("jpy")),
        ("payment_link_id", json!("price_1")),
        ("payment_link_id", json!("plink_1_2")),
    ] {
        let mut plan = kept_plan("plan-month", "1Month", true);
        plan[key] = value.clone();
        assert_eq!(
            PlanBook::try_from(plans_of(vec![plan])),
            Err(PlanBookError::OutOfBounds),
            "{key} {value}"
        );
    }
    let mut dearer = kept_plan("plan-month", "1Month", true);
    dearer["amount"] = json!(900);
    for other in [
        kept_plan("plan-month", "1Month", true),
        kept_plan("plan-month", "1Month", false),
        dearer,
        kept_plan("plan-year", "1Month", true),
    ] {
        let shared = vec![kept_plan("plan-month", "1Month", false), other.clone()];
        assert_eq!(
            PlanBook::try_from(plans_of(shared)),
            Err(PlanBookError::SharedLink),
            "{other}"
        );
    }
    assert_eq!(
        PlanBook::try_from(plans_of(vec![
            kept_plan("plan-month", "1Month", false),
            kept_plan("plan-month", "2Month", true),
        ]))
        .unwrap()
        .plans()
        .len(),
        2
    );
    let mut unknown_key = kept_plan("plan-month", "1Month", true);
    unknown_key["payment_link"] = json!("https://buy.stripe.com/1Month");
    assert!(serde_json::from_value::<StoredPlan>(unknown_key).is_err());
}

/// While the Mac keeps plans, a live grant that would give a period or a
/// pack is held when no kept plan sells its terms: none of its id, or none
/// at its kind, days, traffic, amount or currency. One held for its user
/// keeps that reason; a rehearsal's grants are not checked; and with no
/// plans kept a page is applied as the portal lists it.
#[test]
fn a_live_grant_is_held_when_no_plan_kept_sells_its_terms() {
    let users = pilot_users();
    let book = book_of(vec![listed("plan-month", "month", 100, 800, "1Month")]);
    let mut dearer = Terms::month(DEARER, "pilotuserb").grant(3);
    dearer["amount"] = json!(900);
    let entries = vec![
        Terms::month(MONTH, "pilotusera").grant(1),
        Terms::pack(PACK, "pilotusera").grant(2),
        dearer,
        Terms {
            days: 31,
            ..Terms::month(LONGER, "pilotuserb")
        }
        .grant(4),
        Terms::pack(STRANGER, "pilotuserz").grant(5),
    ];
    let page = live(0, entries.clone());
    let applied = PaymentLedger::new()
        .apply_planned(&page, &users, NOW, false, &book)
        .unwrap();
    let now = NOW.as_secs();
    assert_eq!(
        applied.events,
        [
            LedgerEvent::Granted {
                order: order(MONTH),
                user: id("pilotusera"),
                outcome: GrantOutcome::Period {
                    from: NOW,
                    until: secs(now + 30 * DAY),
                },
                livemode: true,
                suspended: None,
                confirmed: false,
            },
            held(PACK, "pilotusera", HeldReason::PlanUnknown),
            held(DEARER, "pilotuserb", HeldReason::PlanDiffers),
            held(LONGER, "pilotuserb", HeldReason::PlanDiffers),
            held(STRANGER, "pilotuserz", HeldReason::UnknownUser),
        ]
    );
    let ledger = &applied.ledger;
    for (text, reason) in [
        (PACK, HeldReason::PlanUnknown),
        (DEARER, HeldReason::PlanDiffers),
        (LONGER, HeldReason::PlanDiffers),
    ] {
        let grant = ledger.orders()[&order(text)].grant.unwrap();
        assert_eq!(grant.outcome, GrantOutcome::Held { reason }, "{text}");
        assert!(!grant.confirmed, "{text}");
    }
    // Nothing held counts.
    let entitlements = ledger.entitlements(false);
    let a = entitlements.user(&id("pilotusera")).unwrap();
    assert_eq!(a.periods().len(), 1);
    assert!(a.packs().is_empty());
    assert!(entitlements.user(&id("pilotuserb")).is_none());
    // A rehearsal's page is applied as listed.
    let rehearsed = decode(&document(false, 0, entries, false), 0).unwrap();
    let applied = PaymentLedger::new()
        .apply_planned(&rehearsed, &users, NOW, true, &book)
        .unwrap();
    let granted = |applied: &Applied| {
        applied
            .events
            .iter()
            .filter(|event| matches!(event, LedgerEvent::Granted { .. }))
            .count()
    };
    assert_eq!(granted(&applied), 4);
    // No plans kept: the check is off.
    let as_listed = PaymentLedger::new()
        .apply(&page, &users, NOW, false)
        .unwrap();
    assert_eq!(granted(&as_listed), 4);
    assert_eq!(
        PaymentLedger::new()
            .apply_planned(&page, &users, NOW, false, &PlanBook::default())
            .unwrap(),
        as_listed
    );
}

/// With the check against Stripe on, a grant held for its plan is held
/// before Stripe is asked, whatever Stripe said of it; the others are
/// asked about on the Payment Links of the plans at their own terms, a
/// renewal's as a first order's.
#[test]
fn stripe_is_asked_about_a_grant_on_its_plan_s_links() {
    // The renewing month became dearer on a new link. A renewal is asked
    // about on the links of the plans at its own terms: the portal lists one
    // at its first order's, so one listed at the dearer terms is confirmed
    // only in a subscription begun on the new link.
    let book = book_of(sold())
        .stored(
            &parse(&file_of(vec![
                listed("plan-month", "month", 100, 800, "1Month"),
                listed("plan-month-auto", "month_auto", 100, 900, "2Auto"),
            ]))
            .unwrap(),
        )
        .unwrap()
        .0;
    let mut dearer_renewal = month_auto(RENEWAL, "pilotusera", Some(FIRST)).grant(4);
    dearer_renewal["amount"] = json!(900);
    let mut unsold = Terms::pack(PACK, "pilotuserb").grant(2);
    unsold["plan"] = json!("plan-gift");
    let page = live(
        0,
        vec![
            month_auto(FIRST, "pilotusera", None).grant(1),
            unsold,
            Terms::month(MONTH, "pilotuserb").grant(3),
            dearer_renewal,
        ],
    );
    let users = pilot_users();
    let check = |said: &Verdicts| {
        PaymentLedger::new()
            .apply_checked(&page, &users, NOW, false, &book, said)
            .unwrap()
    };
    let Checked::Unconfirmed { next, rest } = check(&Verdicts::new()) else {
        panic!("applied without Stripe");
    };
    let asked: Vec<(String, Vec<StripeId>)> = iter::once(*next)
        .chain(rest)
        .map(|target| (target.order.to_string(), target.payment_links))
        .collect();
    assert_eq!(
        asked,
        [
            (FIRST.to_owned(), vec![plink("1Auto")]),
            (MONTH.to_owned(), vec![plink("1Month")]),
            (RENEWAL.to_owned(), vec![plink("2Auto")]),
        ]
    );
    let said: Verdicts = [
        (FIRST, Verdict::Confirmed),
        (PACK, Verdict::Refused(Refusal::Unpaid)),
        (MONTH, Verdict::Confirmed),
        (RENEWAL, Verdict::Confirmed),
    ]
    .into_iter()
    .map(|(text, verdict)| (order(text), verdict))
    .collect();
    let Checked::Applied(applied) = check(&said) else {
        panic!("not applied");
    };
    assert_eq!(
        applied.events[1],
        held(PACK, "pilotuserb", HeldReason::PlanUnknown)
    );
    for at in [0, 2, 3] {
        assert!(
            matches!(
                applied.events[at],
                LedgerEvent::Granted {
                    confirmed: true,
                    ..
                }
            ),
            "{at}: {:?}",
            applied.events[at]
        );
    }
}

/// A grant held for its plan was added by version 5 of the ledger: a
/// version-4 file that holds one is refused, and one that holds another
/// hold is read as written.
#[test]
fn a_grant_held_for_its_plan_is_of_version_5() {
    let users = pilot_users();
    let book = book_of(vec![listed("plan-month", "month", 100, 800, "1Month")]);
    let mut dearer = Terms::month(DEARER, "pilotuserb").grant(1);
    dearer["amount"] = json!(900);
    let read = |value: &Value| PaymentLedger::decode(&serde_json::to_vec(value).unwrap());
    for (entry, for_plan) in [
        (Terms::pack(PACK, "pilotusera").grant(1), true),
        (dearer, true),
        (Terms::month(STRANGER, "pilotuserz").grant(1), false),
    ] {
        let ledger = PaymentLedger::new()
            .apply_planned(&live(0, vec![entry]), &users, NOW, false, &book)
            .unwrap()
            .ledger;
        let mut written: Value = serde_json::from_slice(&ledger.encode().unwrap()).unwrap();
        assert_eq!(written["version"], json!(5));
        assert_eq!(read(&written).unwrap(), ledger);
        written["version"] = json!(4);
        let as_4 = read(&written);
        if for_plan {
            assert!(
                matches!(as_4, Err(LedgerError::Inconsistent { .. })),
                "{as_4:?}"
            );
        } else {
            assert_eq!(as_4.unwrap(), ledger);
        }
    }
}
