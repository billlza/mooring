// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal's document: both goldens decode to what they say, and every
//! departure from the contract, or from Mooring's own checks, refuses the
//! whole document.

use std::num::{NonZeroU32, NonZeroU64};

use serde_json::{Value, json};

use super::{EMPTY, PILOT, Terms, decode, document, id, order, pilot_value, secs};
use crate::payments::{
    Currency, EntryEvent, EntryFault, FeedEntry, FeedError, FeedPage, MAX_FEED_BYTES,
    MAX_FEED_ENTRIES, OrderTerms, PlanId, PortalPlanKind, printable,
};

fn terms(
    user: &str,
    plan: &str,
    kind: PortalPlanKind,
    paid_at: u64,
    renewal_of: Option<&str>,
) -> OrderTerms {
    OrderTerms {
        user: id(user),
        plan: PlanId::parse(plan).unwrap(),
        plan_kind: kind,
        days: NonZeroU32::new(30).unwrap(),
        traffic_bytes: NonZeroU64::new(100_000_000_000).unwrap(),
        amount: NonZeroU64::new(800).unwrap(),
        currency: Currency::parse("gbp").unwrap(),
        paid_at: secs(paid_at),
        renewal_of: renewal_of.map(order),
    }
}

/// `pilot.json` decodes to its six entries, every field as written: a
/// month and a renewing month granted, a partial refund, the renewal, a
/// dispute and a refund in full, in test mode, with more to come.
#[test]
fn the_pilot_golden_decodes_to_its_six_entries() {
    let page = FeedPage::decode(PILOT.as_bytes(), 0).unwrap();
    assert_eq!(page.generated_at(), secs(1_797_000_000));
    assert!(!page.livemode());
    assert_eq!(page.after(), 0);
    assert_eq!(page.next(), 7);
    assert!(page.more());
    let month = terms(
        "pilotusera",
        "month-100",
        PortalPlanKind::Month,
        1_794_355_260,
        None,
    );
    let first = terms(
        "pilotuserb",
        "month-100-auto",
        PortalPlanKind::MonthAuto,
        1_794_355_262,
        None,
    );
    let renewal = terms(
        "pilotuserb",
        "month-100-auto",
        PortalPlanKind::MonthAuto,
        1_796_947_263,
        Some("zzzzzzzzzzzzzzzzzzzz"),
    );
    let entry = |seq, order_text, terms: &OrderTerms, event, recorded_at| FeedEntry {
        seq,
        order: order(order_text),
        terms: terms.clone(),
        event,
        recorded_at: secs(recorded_at),
    };
    assert_eq!(
        page.entries(),
        [
            entry(
                1,
                "0123456789abcdefghjk",
                &month,
                EntryEvent::Grant,
                1_794_355_261
            ),
            entry(
                2,
                "zzzzzzzzzzzzzzzzzzzz",
                &first,
                EntryEvent::Grant,
                1_794_355_265
            ),
            entry(
                4,
                "0123456789abcdefghjk",
                &month,
                EntryEvent::Refund {
                    amount_refunded: 300,
                    in_full: false
                },
                1_794_400_001
            ),
            entry(
                5,
                "sbc7dxq3cceajeb9ncge",
                &renewal,
                EntryEvent::Grant,
                1_796_947_265
            ),
            entry(
                6,
                "0123456789abcdefghjk",
                &month,
                EntryEvent::Dispute {
                    amount_disputed: 800
                },
                1_796_999_999
            ),
            entry(
                7,
                "sbc7dxq3cceajeb9ncge",
                &renewal,
                EntryEvent::Refund {
                    amount_refunded: 800,
                    in_full: true
                },
                1_797_000_000
            ),
        ]
    );
}

/// `empty.json` is the answer after entry 6 when nothing newer exists: in
/// live mode, no entry, the same cursor, no more.
#[test]
fn the_empty_golden_decodes_as_no_new_entry() {
    let page = FeedPage::decode(EMPTY.as_bytes(), 6).unwrap();
    assert!(page.livemode());
    assert_eq!(page.after(), 6);
    assert!(page.entries().is_empty());
    assert_eq!(page.next(), 6);
    assert!(!page.more());
}

/// The portal sends the goldens without their whitespace; both forms are
/// the same document.
#[test]
fn the_compact_form_decodes_alike() {
    for (golden, asked) in [(PILOT, 0), (EMPTY, 6)] {
        let compact = serde_json::to_vec(&serde_json::from_str::<Value>(golden).unwrap()).unwrap();
        assert_eq!(
            FeedPage::decode(&compact, asked),
            FeedPage::decode(golden.as_bytes(), asked)
        );
    }
}

/// A document answering another cursor than the one asked with is refused:
/// it is not the answer to this pull.
#[test]
fn a_document_must_answer_the_cursor_asked_with() {
    assert_eq!(
        FeedPage::decode(PILOT.as_bytes(), 1),
        Err(FeedError::AfterMismatch { asked: 1, found: 0 })
    );
    assert_eq!(
        FeedPage::decode(EMPTY.as_bytes(), 0),
        Err(FeedError::AfterMismatch { asked: 0, found: 6 })
    );
}

/// Another format or version is named as such, before any other key is
/// looked at.
#[test]
fn another_format_or_version_is_named_first() {
    let mut other = pilot_value();
    other["format"] = json!("mooring-portal-snapshot");
    other["extra"] = json!(1);
    assert_eq!(decode(&other, 0), Err(FeedError::WrongFormat));
    let mut missing = pilot_value();
    missing.as_object_mut().unwrap().remove("format");
    assert_eq!(decode(&missing, 0), Err(FeedError::WrongFormat));
    for (version, found) in [
        (json!(2), Some(2)),
        (json!(0), Some(0)),
        (json!("1"), None),
        (json!(1.0), None),
    ] {
        let mut value = pilot_value();
        value["version"] = version;
        assert_eq!(decode(&value, 0), Err(FeedError::WrongVersion { found }));
    }
    let mut without_version = pilot_value();
    without_version.as_object_mut().unwrap().remove("version");
    assert_eq!(
        decode(&without_version, 0),
        Err(FeedError::WrongVersion { found: None })
    );
    assert_eq!(
        FeedError::WrongVersion { found: Some(2) }.to_string(),
        "the document's version is 2, and this build reads version 1"
    );
}

fn malformed(result: Result<FeedPage, FeedError>) -> String {
    match result {
        Err(FeedError::Malformed { detail }) => detail,
        other => panic!("not malformed: {other:?}"),
    }
}

/// Every key of the document and of each entry is required, none other is
/// read, none may come twice, and each is of its type; anything else is
/// refused whole (contract §5.5).
#[test]
fn every_key_is_required_once_with_its_type_and_no_other_is_read() {
    let keys = pilot_value()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 8);
    for key in keys
        .iter()
        .filter(|key| !["format", "version"].contains(&key.as_str()))
    {
        let mut value = pilot_value();
        value.as_object_mut().unwrap().remove(key);
        assert!(
            malformed(decode(&value, 0)).contains(&format!("missing field `{key}`")),
            "{key}"
        );
    }
    let entry_keys = pilot_value()["entries"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(entry_keys.len(), 16);
    for key in &entry_keys {
        let mut value = pilot_value();
        value["entries"][3].as_object_mut().unwrap().remove(key);
        assert!(
            malformed(decode(&value, 0)).contains(&format!("missing field `{key}`")),
            "{key}"
        );
    }
    let mut extra = pilot_value();
    extra["note"] = json!(null);
    assert!(malformed(decode(&extra, 0)).contains("unknown field `note`"));
    let mut extra_entry = pilot_value();
    extra_entry["entries"][1]["note"] = json!("x");
    assert!(malformed(decode(&extra_entry, 0)).contains("unknown field `note`"));
    for (key, wrong) in [
        ("generated_at", json!("1797000000")),
        ("livemode", json!(0)),
        ("after", json!(-1)),
        ("entries", json!({})),
        ("next", json!(7.5)),
        ("more", json!("true")),
    ] {
        let mut value = pilot_value();
        value[key] = wrong;
        let _ = malformed(decode(&value, 0));
    }
    for (key, wrong) in [
        ("seq", json!("1")),
        ("days", json!(-30)),
        ("traffic_bytes", json!(1e11)),
        ("amount", json!(null)),
        ("renewal_of", json!(7)),
        ("amount_refunded", json!("300")),
        ("refunded_in_full", json!(1)),
        ("amount_disputed", json!(false)),
        ("user", json!(7)),
    ] {
        let mut value = pilot_value();
        value["entries"][0][key] = wrong;
        let _ = malformed(decode(&value, 0));
    }
    let twice = PILOT.replacen("\"more\": true", "\"more\": true,\n  \"more\": true", 1);
    assert_ne!(twice, PILOT);
    assert!(malformed(FeedPage::decode(twice.as_bytes(), 0)).contains("duplicate field `more`"));
    let entry_twice = PILOT.replacen("\"seq\": 1,", "\"seq\": 1,\n      \"seq\": 1,", 1);
    assert!(
        malformed(FeedPage::decode(entry_twice.as_bytes(), 0)).contains("duplicate field `seq`")
    );
    for not_a_document in ["", "\"mooring-portal-entitlements\"", "{", "null", "7"] {
        let _ = malformed(FeedPage::decode(not_a_document.as_bytes(), 0));
    }
    // An array is never an object: serde reads a struct from one by
    // position, so an empty one has no format, and one long enough to be
    // read as a document is longer than the two keys read first.
    assert_eq!(FeedPage::decode(b"[]", 0), Err(FeedError::WrongFormat));
    let positional = br#"["mooring-portal-entitlements", 1, 1797000000, true, 0, [], 0, false]"#;
    let _ = malformed(FeedPage::decode(positional, 0));
    let _ = malformed(FeedPage::decode(
        br#"["mooring-portal-entitlements", 1]"#,
        0,
    ));
}

/// The numbering: every entry above the cursor and the one before it,
/// `next` at the last, `more` only with an entry, at most 200 entries, and
/// the document's time within the calendar.
#[test]
fn the_entries_are_numbered_upwards_and_next_and_more_agree() {
    let month = Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera");
    let other = Terms::month("bbbbbbbbbbbbbbbbbbbb", "pilotusera");
    let at_cursor = document(true, 5, vec![month.grant(5)], false);
    assert_eq!(
        decode(&at_cursor, 5),
        Err(FeedError::SeqNotAscending { seq: 5, after: 5 })
    );
    let backwards = document(true, 0, vec![month.grant(3), other.grant(2)], false);
    assert_eq!(
        decode(&backwards, 0),
        Err(FeedError::SeqNotAscending { seq: 2, after: 3 })
    );
    let repeated = document(true, 0, vec![month.grant(3), other.grant(3)], false);
    assert_eq!(
        decode(&repeated, 0),
        Err(FeedError::SeqNotAscending { seq: 3, after: 3 })
    );
    for (next, expected) in [(4, 3), (2, 3), (0, 3)] {
        let mut value = document(true, 0, vec![month.grant(3)], false);
        value["next"] = json!(next);
        assert_eq!(
            decode(&value, 0),
            Err(FeedError::NextMismatch { next, expected })
        );
    }
    let mut empty_next = document(true, 9, Vec::new(), false);
    empty_next["next"] = json!(10);
    assert_eq!(
        decode(&empty_next, 9),
        Err(FeedError::NextMismatch {
            next: 10,
            expected: 9
        })
    );
    assert_eq!(
        decode(&document(true, 9, Vec::new(), true), 9),
        Err(FeedError::MoreWithoutEntries)
    );
    let full: Vec<Value> = (1..=200_u64)
        .map(|seq| {
            let mut entry = month.grant(seq);
            entry["order"] = json!(format!("{seq:0>20}"));
            entry
        })
        .collect();
    assert_eq!(full.len(), MAX_FEED_ENTRIES);
    let page = decode(&document(true, 0, full.clone(), true), 0).unwrap();
    assert_eq!(page.entries().len(), 200);
    let mut over = full;
    let mut extra = month.grant(201);
    extra["order"] = json!(format!("{:0>20}", 201));
    over.push(extra);
    assert_eq!(
        decode(&document(true, 0, over, true), 0),
        Err(FeedError::TooManyEntries { count: 201 })
    );
    let mut late = pilot_value();
    late["generated_at"] = json!(253_402_300_800_u64);
    assert_eq!(decode(&late, 0), Err(FeedError::GeneratedOutOfRange));
    late["generated_at"] = json!(253_402_300_799_u64);
    assert!(decode(&late, 0).is_ok());
}

/// Each entry's values are checked against the contract; a fault names the
/// entry by its number.
#[test]
fn every_entry_value_is_checked() {
    let cases: Vec<(&str, Value, EntryFault)> = vec![
        ("kind", json!("grants"), EntryFault::Kind),
        ("kind", json!("Grant"), EntryFault::Kind),
        ("order", json!("0123456789abcdefghji"), EntryFault::Order),
        ("order", json!("0123456789abcdefghj"), EntryFault::Order),
        ("order", json!("0123456789ABCDEFGHJK"), EntryFault::Order),
        ("user", json!("pilotuser"), EntryFault::User),
        ("user", json!("PILOTUSERA"), EntryFault::User),
        ("plan", json!(""), EntryFault::Plan),
        ("plan", json!("-month"), EntryFault::Plan),
        ("plan", json!("month-"), EntryFault::Plan),
        ("plan", json!("Month"), EntryFault::Plan),
        ("plan", json!("month\n100"), EntryFault::Plan),
        ("plan", json!("a".repeat(33)), EntryFault::Plan),
        ("plan_kind", json!("year"), EntryFault::PlanKind),
        ("days", json!(0), EntryFault::Days),
        ("days", json!(4_294_967_296_u64), EntryFault::Days),
        ("traffic_bytes", json!(0), EntryFault::TrafficBytes),
        ("amount", json!(0), EntryFault::Amount),
        ("currency", json!("GBP"), EntryFault::Currency),
        ("currency", json!("gb"), EntryFault::Currency),
        ("currency", json!("gbpp"), EntryFault::Currency),
        ("paid_at", json!(253_402_300_800_u64), EntryFault::PaidAt),
        (
            "recorded_at",
            json!(253_402_300_800_u64),
            EntryFault::RecordedAt,
        ),
        ("renewal_of", json!("zzz"), EntryFault::RenewalOf),
        (
            "renewal_of",
            json!("zzzzzzzzzzzzzzzzzzzz"),
            EntryFault::RenewalOfAnotherKind,
        ),
        ("amount_refunded", json!(1), EntryFault::Amounts),
        ("refunded_in_full", json!(false), EntryFault::Amounts),
        ("amount_disputed", json!(1), EntryFault::Amounts),
    ];
    for (key, value, fault) in cases {
        let mut document = pilot_value();
        document["entries"][0][key] = value.clone();
        assert_eq!(
            decode(&document, 0),
            Err(FeedError::Entry { seq: 1, fault }),
            "{key} = {value}"
        );
    }
    let mut itself = pilot_value();
    itself["entries"][3]["renewal_of"] = json!("sbc7dxq3cceajeb9ncge");
    assert_eq!(
        decode(&itself, 0),
        Err(FeedError::Entry {
            seq: 5,
            fault: EntryFault::RenewalOfItself
        })
    );
    // A refund without its flag, or with a dispute's amount, and a dispute
    // with a refund's amounts.
    for (index, key, value) in [
        (2, "refunded_in_full", json!(null)),
        (2, "amount_refunded", json!(null)),
        (2, "amount_disputed", json!(300)),
        (4, "amount_disputed", json!(null)),
        (4, "amount_refunded", json!(800)),
        (4, "refunded_in_full", json!(true)),
    ] {
        let mut document = pilot_value();
        document["entries"][index][key] = value;
        let seq = document["entries"][index]["seq"].as_u64().unwrap();
        assert_eq!(
            decode(&document, 0),
            Err(FeedError::Entry {
                seq,
                fault: EntryFault::Amounts
            }),
            "entry {index} {key}"
        );
    }
    // The extremes the contract allows are taken.
    let mut extremes = pilot_value();
    extremes["entries"][0]["days"] = json!(4_294_967_295_u64);
    extremes["entries"][0]["paid_at"] = json!(0);
    extremes["entries"][2]["amount_refunded"] = json!(0);
    extremes["entries"][4]["amount_disputed"] = json!(0);
    extremes["entries"][0]["plan"] = json!("a".repeat(32));
    for later in [2, 4] {
        extremes["entries"][later]["days"] = json!(4_294_967_295_u64);
        extremes["entries"][later]["paid_at"] = json!(0);
        extremes["entries"][later]["plan"] = json!("a".repeat(32));
    }
    let page = decode(&extremes, 0).unwrap();
    assert_eq!(page.entries()[0].terms.days.get(), u32::MAX);
}

/// The decoder's message quotes the document, so it is kept printable and
/// short: a key with a line break cannot break or forge a line of the
/// daemon's log.
#[test]
fn a_message_quoting_the_document_is_printable_and_bounded() {
    let mut value = pilot_value();
    value["bad\nkey\u{1b}[31m"] = json!(1);
    let detail = malformed(decode(&value, 0));
    assert!(detail.contains("bad\\u{a}key\\u{1b}[31m"), "{detail}");
    assert!(!detail.contains('\n'));
    assert!(
        detail
            .chars()
            .all(|character| (' '..='~').contains(&character))
    );
    let long = "x".repeat(1_000);
    let kept = printable(&long);
    assert_eq!(kept.chars().count(), 201);
    assert!(kept.ends_with('…'));
    assert_eq!(printable("plain text"), "plain text");
    assert_eq!(printable("é\t"), "\\u{e9}\\u{9}");
}

/// A document past a mebibyte is refused before it is parsed.
#[test]
fn a_document_past_a_mebibyte_is_refused_unread() {
    let mut body = PILOT.as_bytes().to_vec();
    body.resize(MAX_FEED_BYTES + 1, b' ');
    assert_eq!(FeedPage::decode(&body, 0), Err(FeedError::TooLarge));
    body.truncate(MAX_FEED_BYTES);
    assert!(FeedPage::decode(&body, 0).is_ok());
}

/// The kinds of plan, their text and what they sell.
#[test]
fn plan_kinds_are_the_contracts_three() {
    assert_eq!(
        PortalPlanKind::ALL.map(PortalPlanKind::as_str),
        ["month", "month_auto", "traffic"]
    );
    assert!(PortalPlanKind::Month.buys_service());
    assert!(PortalPlanKind::MonthAuto.buys_service());
    assert!(!PortalPlanKind::Traffic.buys_service());
    for kind in PortalPlanKind::ALL {
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(kind.as_str()));
    }
}
