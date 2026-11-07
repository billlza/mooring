// SPDX-License-Identifier: GPL-3.0-or-later

//! What refuses a user's history: never an empty history in its place.

use mooring_model::{ModelError, UnixTime, UserId};

use super::{
    Hy2, Reality, deployment, detail, email, later, later_than_midnight, monthly, node, now,
    served, subject, traffic,
};
use crate::error::{UsageError, UsageErrorKind};
use crate::tests::support::{at, edited};
use crate::usage::history::UsageScope;
use crate::usage::{CollectedUsage, NodeUsageHistory};

fn refusal(collected: &CollectedUsage, at: UnixTime) -> UsageError {
    collected
        .user_history(&deployment(), &subject(), at, UsageScope::All)
        .unwrap_err()
}

/// A user the deployment does not hold has no history: it is the model's
/// `UnknownUser`, never an empty one.
#[test]
fn an_unknown_user_is_refused() {
    let stranger = UserId::from_low_bits(0x3_1415_9265);
    assert!(!deployment().users().contains_key(&stranger));
    assert_eq!(
        served().user_history(&deployment(), &stranger, now(), UsageScope::All),
        Err(UsageError::Model(ModelError::UnknownUser { id: stranger }))
    );
}

/// The refusal a document dated after now gets, naming `node`.
fn dated_after_now(node: &str) -> UsageError {
    UsageError::LedgerCorrupt {
        message: format!(
            "{node} holds usage dated after now (the Mac's clock went back, or the document is corrupt)"
        ),
    }
}

/// `collected` with `edit` made to its stored form, read back as the CLI
/// reads it: what a document no collector writes holds.
fn edited_document(
    collected: &CollectedUsage,
    edit: impl FnOnce(&mut serde_json::Value),
) -> CollectedUsage {
    let mut value: serde_json::Value =
        serde_json::from_slice(&collected.encode().unwrap()).unwrap();
    edit(&mut value);
    CollectedUsage::decode(&serde_json::to_vec(&value).unwrap()).unwrap()
}

/// Usage dated after now, a month received, a bin of any tier that ends,
/// or an origin recorded after it, only a clock that went back or a
/// corrupt document leaves; it is refused, not shown, to the second.
#[test]
fn usage_dated_after_now_is_refused() {
    let mut future_month = served();
    let mut lon = future_month.node(&node("lon1")).unwrap().clone();
    let (subject, other) = (subject(), super::other());
    monthly(
        &mut lon,
        "lon1",
        "2026-11",
        later(60),
        later(60),
        vec![
            (email(&subject, Reality), traffic(1400, 35_200)),
            (email(&subject, Hy2), traffic(25, 207)),
            (email(&other, Reality), traffic(999, 9_999)),
            (super::probe(Reality), traffic(0, 500)),
            (super::probe(Hy2), traffic(0, 600)),
        ],
    );
    future_month.set_node(node("lon1"), lon);
    for at in [now(), later(59)] {
        assert_eq!(refusal(&future_month, at), dated_after_now("lon1"));
    }
    // From the second it was received, the month is not in the future.
    let read = future_month
        .user_history(&deployment(), &subject, later(60), UsageScope::All)
        .unwrap();
    assert_eq!(
        read.nodes()[1].totals.as_ref().unwrap().months[0].counted_through,
        later(60)
    );
    let mut future_bin = served();
    let mut ams = future_bin.node(&node("ams1")).unwrap().clone();
    detail(&mut ams, "ams1", now(), later(300), &[]);
    future_bin.set_node(node("ams1"), ams);
    for at in [now(), later(299)] {
        assert_eq!(refusal(&future_bin, at), dated_after_now("ams1"));
    }
    // From the second the bin ends it is held, and alone it makes no hour.
    let read = future_bin
        .user_history(&deployment(), &subject, later(300), UsageScope::All)
        .unwrap();
    let held = served()
        .user_history(&deployment(), &subject, later(300), UsageScope::All)
        .unwrap();
    assert_eq!(read.nodes(), held.nodes());
    // An hour or a day that ends after now, which only a document no
    // collector wrote holds, and an origin after now.
    let hour = at("2026-11-05", 12 * 3600).as_secs().to_string();
    let day = at("2026-11-05", 0).as_secs().to_string();
    for (tier, start, ends) in [
        ("hour", &hour, later(3600)),
        ("day", &day, later(12 * 3600)),
    ] {
        let document = edited_document(&served(), |value| {
            value["nodes"]["ams1"][tier][start.as_str()] = serde_json::json!({});
        });
        assert_eq!(
            refusal(&document, UnixTime::from_secs(ends.as_secs() - 1)),
            dated_after_now("ams1"),
            "{tier}"
        );
    }
    let mut early = served();
    early.observe_unserved(node("par1"), later(1));
    assert_eq!(refusal(&early, now()), dated_after_now("par1"));
}

/// The refusals come in their order: the user before anything of the
/// document, and usage dated after now before the users the document
/// names.
#[test]
fn the_refusals_come_in_their_order() {
    let mut future = served();
    let mut ams = future.node(&node("ams1")).unwrap().clone();
    detail(&mut ams, "ams1", now(), later(300), &[]);
    future.set_node(node("ams1"), ams);
    let stranger = UserId::from_low_bits(0x3_1415_9265);
    assert_eq!(
        future.user_history(&deployment(), &stranger, now(), UsageScope::All),
        Err(UsageError::Model(ModelError::UnknownUser { id: stranger }))
    );
    // lon1 names a user this deployment does not hold, which is refused
    // only once nothing is dated after now.
    let removed = super::other();
    let without = edited(|parts| parts.users.retain(|user| user.id != removed));
    assert_eq!(
        future.user_history(&without, &subject(), now(), UsageScope::All),
        Err(dated_after_now("ams1"))
    );
    assert_eq!(
        served().user_history(&without, &subject(), now(), UsageScope::All),
        Err(UsageError::UnknownUser {
            node: node("lon1"),
            user: removed,
        })
    );
}

/// A month received after now is refused even when its sample was taken
/// before now: the receipt dates it, not the sample.
#[test]
fn a_month_received_after_now_is_refused_whenever_it_was_sampled() {
    let (subject, other) = (subject(), super::other());
    let mut future = served();
    let mut lon = future.node(&node("lon1")).unwrap().clone();
    monthly(
        &mut lon,
        "lon1",
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later(60),
        vec![
            (email(&subject, Reality), traffic(1400, 35_200)),
            (email(&subject, Hy2), traffic(25, 207)),
            (email(&other, Reality), traffic(999, 9_999)),
            (super::probe(Reality), traffic(0, 500)),
            (super::probe(Hy2), traffic(0, 600)),
        ],
    );
    future.set_node(node("lon1"), lon);
    assert_eq!(refusal(&future, now()), dated_after_now("lon1"));
}

/// What ends or was recorded at the read's own second is not after it: a
/// day that ends then is held, and an origin recorded then is no refusal.
#[test]
fn what_ends_or_was_recorded_at_the_read_is_not_after_it() {
    let midnight = at("2026-11-05", 0);
    let mut lon = NodeUsageHistory::default();
    detail(&mut lon, "lon1", at("2026-11-04", 0), midnight, &[]);
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), lon);
    let read = collected
        .user_history(&deployment(), &subject(), midnight, UsageScope::All)
        .unwrap();
    assert_eq!(
        read.nodes()[1].daily.held,
        [super::range(at("2026-11-04", 0), midnight)]
    );
    let mut planned = served();
    planned.observe_unserved(node("par1"), now());
    assert!(
        planned
            .user_history(&deployment(), &subject(), now(), UsageScope::All)
            .is_ok()
    );
}

/// A user last seen not revoked after now would push the user's deadline
/// out once it is revoked. Only a clock that went back or a corrupt
/// document records one, and it is refused to the second.
#[test]
fn a_user_seen_after_now_is_refused() {
    let seen = edited_document(&served(), |value| {
        value["last_nonrevoked"][subject().as_str()] = serde_json::json!(later(1).as_secs());
    });
    assert_eq!(
        refusal(&seen, now()),
        UsageError::LedgerCorrupt {
            message: "a user was last seen not revoked after now (the Mac's clock went back, or the document is corrupt)"
                .to_owned(),
        }
    );
    assert!(
        seen.user_history(&deployment(), &subject(), later(1), UsageScope::All)
            .is_ok()
    );
}

/// An accounting email whose principal is no user id was not rendered by
/// Mooring: refused as the aggregate refuses it, never dropped.
#[test]
fn a_principal_that_is_no_user_id_is_refused() {
    let document = edited_document(&served(), |value| {
        let month = &mut value["nodes"]["lon1"]["months"]["2026-11"]["sample"]["traffic"];
        month["zz9@hy2"] = serde_json::json!({"uplink": 1, "downlink": 1});
    });
    assert_eq!(
        refusal(&document, now()).kind(),
        UsageErrorKind::PrincipalNotAUser
    );
}

/// A month total below the detail it covers contradicts it: the history is
/// refused as the aggregate refuses it.
#[test]
fn a_month_that_contradicts_its_detail_is_refused() {
    let mut collected = served();
    let mut lon = NodeUsageHistory::default();
    detail(
        &mut lon,
        "lon1",
        at("2026-11-05", 0),
        now(),
        &[(
            at("2026-11-05", 3600),
            vec![(email(&subject(), Hy2), traffic(100, 100))],
        )],
    );
    monthly(
        &mut lon,
        "lon1",
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later_than_midnight(11 * 3600 + 59 * 60),
        vec![(email(&subject(), Hy2), traffic(100, 99))],
    );
    collected.set_node(node("lon1"), lon);
    assert_eq!(
        refusal(&collected, now()),
        UsageError::MonthlyInconsistent { node: node("lon1") }
    );
}

/// A total that does not fit 64 bits, two months folded together or a
/// lifetime summed, is an error, never a wrapped or clipped figure.
#[test]
fn an_overflowing_total_is_refused() {
    let mut collected = served();
    let mut ams = collected.node(&node("ams1")).unwrap().clone();
    for (name, updated, received) in [
        ("2025-08", at("2025-08-31", 86_340), at("2025-09-01", 60)),
        ("2025-09", at("2025-09-30", 86_340), at("2025-10-01", 60)),
    ] {
        monthly(
            &mut ams,
            "ams1",
            name,
            updated,
            received,
            vec![(email(&subject(), Reality), traffic(u64::MAX / 2 + 1, 0))],
        );
    }
    collected.set_node(node("ams1"), ams);
    assert_eq!(refusal(&collected, now()), UsageError::CounterOverflow);
    // lon1 observed before it served, so with a lifetime to sum.
    let mut scratch = CollectedUsage::default();
    scratch.observe_unserved(node("lon1"), at("2026-10-01", 0));
    let mut lon = scratch.node(&node("lon1")).unwrap().clone();
    for (name, updated, received) in [
        ("2026-10", at("2026-10-31", 86_340), at("2026-11-01", 60)),
        (
            "2026-11",
            later_than_midnight(11 * 3600 + 58 * 60),
            later_than_midnight(11 * 3600 + 59 * 60),
        ),
    ] {
        monthly(
            &mut lon,
            "lon1",
            name,
            updated,
            received,
            vec![(email(&subject(), Hy2), traffic(0, u64::MAX / 2 + 1))],
        );
    }
    let mut lifetime = served();
    lifetime.set_node(node("lon1"), lon);
    assert_eq!(refusal(&lifetime, now()), UsageError::CounterOverflow);
}

/// The document names a user the deployment does not hold: it is not the
/// document of this deployment, so nothing of it is shown, as the
/// aggregate refuses it, rather than dropped.
#[test]
fn a_document_naming_a_user_the_deployment_does_not_hold_is_refused() {
    let removed = super::other();
    let without = edited(|parts| parts.users.retain(|user| user.id != removed));
    assert_eq!(
        served().user_history(&without, &subject(), now(), UsageScope::All),
        Err(UsageError::UnknownUser {
            node: node("lon1"),
            user: removed,
        })
    );
}

/// Past the year 9999 there is no month to count in.
#[test]
fn a_clock_past_the_calendar_is_refused() {
    let error = refusal(&served(), at("9999-12-31", 86_400));
    assert_eq!(error.kind(), UsageErrorKind::LedgerCorrupt);
    assert_eq!(
        error.to_string(),
        "the collected usage ledger is invalid: current month outside calendar"
    );
}
