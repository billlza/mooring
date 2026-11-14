// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's payment pull, tick by tick, against a scripted portal:
//! when it asks, what each answer comes to, what it writes and when it
//! stops.

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use mooring_daemon_core::payments::{FeedError, StopReason};
use mooring_model::{UnixTime, User, UserId};
use mooring_store::{PAYMENT_LEDGER_FILE, PAYMENTS_DIRECTORY};

use super::super::support::{Harness, NOW};
use super::{
    FIRST, SECOND, block_the_ledger, connect, grant, harness, ledger_on_disk, page, token,
};
use crate::payments::curl::{FetchFailure, PortalAnswer};
use crate::payments::judge::{Judged, RETRY_AFTER_MOST, judge, retry_after};
use crate::payments::pull::{Gate, PULL_EVERY, Puller};

const A: &str = "aaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccc";

/// A tick on which the request may be made: room for it and no foreign
/// network.
pub(super) const OPEN: Opening = Opening {
    room: Some(Duration::from_secs(10)),
    clear: true,
};

/// What a tick's [`Gate`] says: the room, and what the network check
/// answers right before the request.
#[derive(Debug, Clone, Copy)]
pub(super) struct Opening {
    pub(super) room: Option<Duration>,
    pub(super) clear: bool,
}

pub(super) fn users() -> BTreeMap<UserId, User> {
    mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .deployment
        .users()
        .clone()
}

/// One tick of `puller` on `harness` through `opening`; the notes it
/// logged.
pub(super) fn tick(harness: &mut Harness, puller: &mut Puller, opening: Opening) -> Vec<String> {
    tick_for(harness, puller, opening, &users())
}

/// [`tick`] with the deployment's users as `users`.
pub(super) fn tick_for(
    harness: &mut Harness,
    puller: &mut Puller,
    opening: Opening,
    users: &BTreeMap<UserId, User>,
) -> Vec<String> {
    ticked(harness, puller, opening, users).0
}

/// [`tick_for`], and how many times the network check was asked.
fn ticked(
    harness: &mut Harness,
    puller: &mut Puller,
    opening: Opening,
    users: &BTreeMap<UserId, User>,
) -> (Vec<String>, u32) {
    let mut asked = 0;
    let mut check = || {
        asked += 1;
        opening.clear
    };
    let notes = harness.with_env(|env| {
        puller.tick(
            env,
            users,
            UnixTime::from_secs(NOW),
            Gate {
                room: opening.room,
                network_clear: &mut check,
            },
        )
    });
    (notes, asked)
}

pub(super) fn requests(harness: &Harness) -> Vec<String> {
    harness
        .portal
        .requests
        .borrow()
        .iter()
        .map(|request| request.url.clone())
        .collect()
}

pub(super) fn answer(harness: &Harness, status: u16, retry_after: Option<&str>, body: &[u8]) {
    harness.portal.answer(Ok(PortalAnswer {
        status,
        retry_after: retry_after.map(str::to_owned),
        body: body.to_vec(),
    }));
}

pub(super) const URL: &str = "https://portal.example.org/api/mooring/entitlements?after=";

/// Nothing is asked until the pull is connected; a disconnected pull asks
/// nothing either, and says so once.
#[test]
fn nothing_is_asked_until_the_pull_is_connected() {
    let mut harness = harness();
    let mut puller = Puller::open(&harness.support_dir());
    assert_eq!(puller.fault(), None);
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    let support = harness.support_dir();
    mooring_store::update_payment_pull::<()>(&support, 4096, |_| {
        Ok(Some(
            mooring_daemon_core::payments::PullSettings::disconnected(3, false)
                .encode()
                .unwrap(),
        ))
    })
    .unwrap();
    assert_eq!(
        tick(&mut harness, &mut puller, OPEN),
        ["payment pull: disconnected"]
    );
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    assert!(requests(&harness).is_empty());
    assert_eq!(ledger_on_disk(&harness), None);
}

/// A page is written with its cursor before it is kept; a page saying
/// `more` is followed at once, and the last one in five minutes. The
/// request bears the stored token, and the users' entitlements follow the
/// ledger.
#[test]
fn a_page_is_written_with_its_cursor_and_more_is_asked_at_once() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 0x42);
    let mut puller = Puller::open(&harness.support_dir());
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, A, FIRST), grant(2, B, SECOND)],
        true,
    ));
    harness
        .portal
        .ok(&page(true, 2, vec![grant(5, C, FIRST)], false));
    let notes = tick(&mut harness, &mut puller, OPEN);
    let now = NOW;
    assert_eq!(
        notes,
        [
            format!(
                "payment: order {A} granted user {FIRST} service from 2026-10-13 19:20:00 UTC until 2026-11-12 19:20:00 UTC"
            ),
            format!(
                "payment: order {B} granted user {SECOND} service from 2026-10-13 19:20:00 UTC until 2026-11-12 19:20:00 UTC"
            ),
            "payment pull: pulling; the cursor is at 2".to_owned(),
        ]
    );
    let on_disk = ledger_on_disk(&harness).unwrap();
    assert_eq!(on_disk.cursor(), 2);
    assert_eq!(on_disk.pulled_at(), Some(UnixTime::from_secs(now)));
    let first = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        first[0],
        format!(
            "payment: order {C} granted user {FIRST} service from 2026-11-12 19:20:00 UTC until 2026-12-12 19:20:00 UTC"
        )
    );
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 5);
    // The last page said no more: the next request is five minutes away.
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    assert_eq!(requests(&harness), [format!("{URL}0"), format!("{URL}2")]);
    let made = harness.portal.requests.borrow();
    assert!(
        made.iter()
            .all(|request| request.token == token(0x42).expose_str())
    );
    assert!(
        made.iter()
            .all(|request| request.within == Duration::from_secs(10))
    );
    drop(made);
    let entitlements = puller.entitlements();
    let first_user = entitlements.user(&UserId::parse(FIRST).unwrap()).unwrap();
    assert_eq!(first_user.periods().len(), 2);
    assert_eq!(
        first_user.paid_until(),
        Some(UnixTime::from_secs(now + 60 * 86_400))
    );
    assert_eq!(PULL_EVERY, Duration::from_secs(300));
}

/// The pull waits while the Mac is on a foreign network, saying so once,
/// and while the tick leaves less than a second.
#[test]
fn the_pull_waits_on_a_foreign_network_and_for_room() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
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
    assert!(tick(&mut harness, &mut puller, foreign).is_empty());
    for room in [None, Some(Duration::from_millis(999))] {
        let gate = Opening { room, clear: true };
        assert!(tick(&mut harness, &mut puller, gate).is_empty());
    }
    assert!(requests(&harness).is_empty());
    harness.portal.ok(&page(true, 0, Vec::new(), false));
    tick(&mut harness, &mut puller, OPEN);
    assert_eq!(requests(&harness), [format!("{URL}0")]);
}

/// A 409 stops the pull: the stop is recorded with the settings' revision,
/// survives a restart, and ends when the settings change; the cursor is
/// never lowered.
#[test]
fn a_conflict_stops_the_pull_until_the_settings_change() {
    let mut harness = harness();
    connect(&mut harness, 4, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(3, A, FIRST)], false));
    tick(&mut harness, &mut puller, OPEN);
    // Ask again at once: a new revision of the same settings.
    connect(&mut harness, 5, false, 1);
    answer(
        &harness,
        409,
        None,
        b"the cursor is beyond this journal's last entry\n",
    );
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0].starts_with("payment pull: stopped: the portal answered 409"),
        "{notes:?}"
    );
    assert!(notes[0].contains("(the cursor is beyond this journal's last entry)"));
    let stopped = ledger_on_disk(&harness).unwrap();
    assert_eq!(stopped.cursor(), 3);
    let stop = stopped.stopped().unwrap();
    assert_eq!(stop.reason, StopReason::Conflict);
    assert_eq!(stop.settings_revision, 5);
    assert_eq!(
        tick(&mut harness, &mut puller, OPEN),
        [
            "payment pull: stopped (conflict) since 2026-10-13 19:20:00 UTC, until its settings change"
        ]
    );
    // A restart keeps the stop.
    let mut restarted = Puller::open(&harness.support_dir());
    tick(&mut harness, &mut restarted, OPEN);
    assert_eq!(requests(&harness).len(), 2);
    // A change of the settings ends it; the cursor is where it was.
    connect(&mut harness, 6, false, 1);
    harness.portal.ok(&page(true, 3, Vec::new(), false));
    let notes = tick(&mut harness, &mut restarted, OPEN);
    assert_eq!(
        notes[0],
        "payment pull: its settings changed since it stopped (conflict); pulling again"
    );
    assert_eq!(requests(&harness).last().unwrap(), &format!("{URL}3"));
    assert_eq!(ledger_on_disk(&harness).unwrap().stopped(), None);
}

/// 401 and 400 stop the pull too; after a 401 the token is read from the
/// keychain again, so a new one is used once the settings change.
#[test]
fn unauthorized_and_bad_requests_stop_the_pull() {
    for (status, reason) in [
        (401, StopReason::Unauthorized),
        (400, StopReason::BadRequest),
    ] {
        let mut harness = harness();
        connect(&mut harness, 1, false, 1);
        let mut puller = Puller::open(&harness.support_dir());
        answer(&harness, status, None, b"refused\n");
        let notes = tick(&mut harness, &mut puller, OPEN);
        assert!(
            notes[0].starts_with(&format!(
                "payment pull: stopped: the portal answered {status}"
            )),
            "{notes:?}"
        );
        assert_eq!(
            ledger_on_disk(&harness).unwrap().stopped().unwrap().reason,
            reason
        );
        connect(&mut harness, 2, false, 2);
        harness.portal.ok(&page(true, 0, Vec::new(), false));
        tick(&mut harness, &mut puller, OPEN);
        let made = harness.portal.requests.borrow();
        assert_eq!(made.len(), 2);
        assert_eq!(made[1].token, token(2).expose_str());
    }
}

/// Failures that may pass leave the cursor and the ledger as they were,
/// and the pull waits before asking again; each is named.
#[test]
fn failures_that_may_pass_keep_the_cursor_and_wait() {
    let cases: Vec<(Result<PortalAnswer, FetchFailure>, &str)> = vec![
        (
            Ok(PortalAnswer {
                status: 404,
                retry_after: None,
                body: b"not found\n".to_vec(),
            }),
            "payment pull: the portal answered 404: it sells nothing (it runs without its catalogue)",
        ),
        (
            Ok(PortalAnswer {
                status: 503,
                retry_after: None,
                body: b"busy\n".to_vec(),
            }),
            "payment pull: the portal failed (503: busy); the cursor stays",
        ),
        (
            Ok(PortalAnswer {
                status: 302,
                retry_after: None,
                body: Vec::new(),
            }),
            "payment pull: the portal answered 302, which the contract has no meaning for (); the cursor stays",
        ),
        (
            Ok(PortalAnswer {
                status: 200,
                retry_after: None,
                body: b"{\"format\":\"other\"}".to_vec(),
            }),
            "payment pull: the portal's document was refused, and the cursor stays: the document is not of the format mooring-portal-entitlements",
        ),
        (
            Err(FetchFailure::TimedOut),
            "payment pull: no answer from the portal: the request took longer than its slot",
        ),
    ];
    for (reply, expected) in cases {
        let mut harness = harness();
        connect(&mut harness, 1, false, 1);
        let mut puller = Puller::open(&harness.support_dir());
        harness.portal.answer(reply);
        assert_eq!(tick(&mut harness, &mut puller, OPEN), [expected]);
        assert_eq!(ledger_on_disk(&harness), None);
        // It waits: the next tick asks nothing.
        assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
        assert_eq!(requests(&harness).len(), 1);
    }
}

/// A 429 waits for its `Retry-After`, bounded.
#[test]
fn a_429_waits_for_its_retry_after() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    answer(&harness, 429, Some("3600"), b"too many requests\n");
    assert_eq!(
        tick(&mut harness, &mut puller, OPEN),
        ["payment pull: the portal answered 429 (Retry-After: 3600); asking again in 3600 s"]
    );
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    assert_eq!(retry_after(None), PULL_EVERY);
    assert_eq!(retry_after(Some("")), PULL_EVERY);
    assert_eq!(retry_after(Some("0")), Duration::from_secs(1));
    assert_eq!(retry_after(Some("120")), Duration::from_secs(120));
    assert_eq!(retry_after(Some("99999999")), RETRY_AFTER_MOST);
    assert_eq!(retry_after(Some("99999999999999999999999")), PULL_EVERY);
    assert_eq!(retry_after(Some("1.5")), PULL_EVERY);
    assert_eq!(retry_after(Some("-1")), PULL_EVERY);
    assert_eq!(
        retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
        PULL_EVERY
    );
}

/// What each status comes to.
#[test]
fn each_status_comes_to_its_outcome() {
    let reply = |status, body: &[u8]| PortalAnswer {
        status,
        retry_after: None,
        body: body.to_vec(),
    };
    assert!(matches!(
        judge(reply(200, &page(true, 0, Vec::new(), false)), 0),
        Judged::Page(_)
    ));
    assert!(matches!(
        judge(reply(200, b"[]"), 0),
        Judged::Refused(FeedError::WrongFormat)
    ));
    assert!(matches!(
        judge(reply(200, &page(true, 0, Vec::new(), false)), 1),
        Judged::Refused(FeedError::AfterMismatch { asked: 1, found: 0 })
    ));
    for (status, reason) in [
        (400, StopReason::BadRequest),
        (401, StopReason::Unauthorized),
        (409, StopReason::Conflict),
    ] {
        assert!(
            matches!(judge(reply(status, b"x"), 0), Judged::Stop { reason: found, .. } if found == reason)
        );
    }
    assert!(matches!(judge(reply(404, b""), 0), Judged::NotSelling));
    for status in [500, 502, 599] {
        assert!(matches!(
            judge(reply(status, b""), 0),
            Judged::PortalFailed { .. }
        ));
    }
    for status in [201, 204, 301, 302, 403, 418] {
        assert!(matches!(
            judge(reply(status, b""), 0),
            Judged::Unexpected { .. }
        ));
    }
    // The portal's text is kept escaped and short.
    let long = format!("line one\nline two {}", "x".repeat(400));
    let Judged::PortalFailed { text, .. } = judge(reply(500, long.as_bytes()), 0) else {
        panic!()
    };
    assert!(text.starts_with("line one\\u{a}line two"), "{text}");
    assert!(text.chars().count() <= 200);
}

/// A page of Stripe's test mode is waited on unless the operator
/// rehearses; turning the rehearsal on grants the same entries.
#[test]
fn test_mode_is_waited_on_unless_rehearsing() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    let test_page = page(false, 0, vec![grant(1, A, FIRST)], false);
    harness.portal.ok(&test_page);
    assert_eq!(
        tick(&mut harness, &mut puller, OPEN),
        [
            "payment pull: the portal's payments are of Stripe's test mode and no rehearsal is on; nothing is granted and the cursor stays"
        ]
    );
    assert_eq!(ledger_on_disk(&harness), None);
    connect(&mut harness, 2, true, 1);
    harness.portal.ok(&test_page);
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert!(
        notes[0].ends_with("(rehearsal, Stripe test mode)"),
        "{notes:?}"
    );
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
    assert_eq!(puller.entitlements().users().len(), 1);
    // Off again, the rehearsal's grant counts no more.
    connect(&mut harness, 3, false, 1);
    harness.portal.ok(&page(true, 1, Vec::new(), false));
    tick(&mut harness, &mut puller, OPEN);
    assert!(puller.entitlements().users().is_empty());
}

/// A page that contradicts the ledger is not applied, and stops the pull.
#[test]
fn a_contradiction_stops_the_pull() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    tick(&mut harness, &mut puller, OPEN);
    connect(&mut harness, 2, false, 1);
    let mut other = grant(2, A, FIRST);
    other["kind"] = serde_json::json!("refund");
    other["amount_refunded"] = serde_json::json!(800);
    other["refunded_in_full"] = serde_json::json!(true);
    other["days"] = serde_json::json!(31);
    harness.portal.ok(&page(true, 1, vec![other], false));
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert!(
        notes[0].starts_with("payment pull: stopped: a page does not fit the payment ledger (entry 2 of order aaaaaaaaaaaaaaaaaaaa: it gives the order other terms than recorded)"),
        "{notes:?}"
    );
    let on_disk = ledger_on_disk(&harness).unwrap();
    assert_eq!(on_disk.cursor(), 1);
    assert_eq!(on_disk.stopped().unwrap().reason, StopReason::Inconsistent);
    assert_eq!(on_disk.stopped().unwrap().settings_revision, 2);
    assert!(
        on_disk
            .orders()
            .values()
            .all(|record| record.refunds.is_empty())
    );
}

/// A ledger that cannot be written keeps nothing of the page: the cursor
/// stays and the same page is asked for again.
#[test]
fn a_ledger_that_cannot_be_written_keeps_nothing() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    // Blocked after the start: at the start it would be a ledger that
    // cannot be read, which stops the pull (below).
    block_the_ledger(&harness);
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0].starts_with("payment pull: the payment ledger could not be written"),
        "{notes:?}"
    );
    assert!(puller.entitlements().users().is_empty());
    fs::remove_file(harness.support_dir().join(PAYMENTS_DIRECTORY)).unwrap();
    connect(&mut harness, 2, false, 1);
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, FIRST)], false));
    tick(&mut harness, &mut puller, OPEN);
    assert_eq!(requests(&harness), [format!("{URL}0"), format!("{URL}0")]);
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
}

/// A ledger that cannot be read at the start stops the pull until the
/// daemon starts again: it is never read as an empty one.
#[test]
fn a_ledger_that_cannot_be_read_stops_the_pull() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let dir = harness.support_dir().join(PAYMENTS_DIRECTORY);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(PAYMENT_LEDGER_FILE), b"{\"version\": 1}").unwrap();
    let mut puller = Puller::open(&harness.support_dir());
    let fault = puller.fault().unwrap();
    assert!(
        fault.starts_with(
            "payment pull: the payment ledger cannot be read (the payment ledger does not decode)"
        ),
        "{fault}"
    );
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    assert!(requests(&harness).is_empty());
    assert!(puller.entitlements().users().is_empty());
    // Something other than a directory where `payments/` belongs is a
    // ledger that cannot be read, too.
    fs::remove_dir_all(&dir).unwrap();
    block_the_ledger(&harness);
    let blocked = Puller::open(&harness.support_dir());
    assert!(
        blocked
            .fault()
            .unwrap()
            .starts_with("payment pull: the payment ledger cannot be read"),
        "{:?}",
        blocked.fault()
    );
}

/// Settings that cannot be read stop the pull until they can, said once.
#[test]
fn settings_that_cannot_be_read_are_said_once() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let path = harness.support_dir().join(mooring_store::PAYMENT_PULL_FILE);
    fs::write(&path, b"{}").unwrap();
    let mut puller = Puller::open(&harness.support_dir());
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0].starts_with(
            "payment pull: its settings cannot be read (the payment pull's settings do not decode)"
        ),
        "{notes:?}"
    );
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    connect(&mut harness, 2, false, 1);
    harness.portal.ok(&page(true, 0, Vec::new(), false));
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes[0], "payment pull: its settings can be read again");
    assert_eq!(requests(&harness).len(), 1);
}

/// A token missing from the keychain is reported and waited on.
#[test]
fn a_missing_token_is_reported() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    {
        use mooring_store::SecretStore;
        harness
            .secrets
            .delete(&mooring_model::secret::SecretRef::PortalPullToken)
            .unwrap();
    }
    let mut puller = Puller::open(&harness.support_dir());
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0].starts_with("payment pull: the pull token cannot be read"),
        "{notes:?}"
    );
    assert!(requests(&harness).is_empty());
}

/// A grant for a user the deployment does not hold is held, and the
/// cursor moves past it.
#[test]
fn a_grant_for_an_unknown_user_is_held() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(1, A, "nobodyhere")], false));
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        notes[0],
        format!(
            "payment: order {A} for user nobodyhere is held, not granted (unknown_user); settle it at Stripe"
        )
    );
    assert_eq!(ledger_on_disk(&harness).unwrap().cursor(), 1);
    assert!(puller.entitlements().users().is_empty());
}

/// The pull's `Debug` names its cursor and schedule, never the token.
#[test]
fn the_pulls_debug_never_holds_the_token() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 0x7e);
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![grant(4, A, FIRST)], false));
    tick(&mut harness, &mut puller, OPEN);
    let shown = format!("{puller:?}");
    assert!(shown.contains("cursor: 4"), "{shown}");
    assert!(!shown.contains(token(0x7e).expose_str()), "{shown}");
    assert!(!shown.contains("7e7e"), "{shown}");
}

/// A stop that cannot be recorded still holds, until the daemon starts
/// again, and says so.
#[test]
fn a_stop_that_cannot_be_recorded_still_holds() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    block_the_ledger(&harness);
    answer(&harness, 409, None, b"conflict\n");
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(notes[0].starts_with("payment pull: stopped: the portal answered 409"));
    assert!(
        notes[1].starts_with("payment pull: the stop could not be recorded in the payment ledger"),
        "{notes:?}"
    );
    assert_eq!(
        tick(&mut harness, &mut puller, OPEN),
        [
            "payment pull: stopped (conflict) since 2026-10-13 19:20:00 UTC, until its settings change"
        ]
    );
    assert_eq!(requests(&harness).len(), 1);
}

/// The network check is asked right before a request, and only then: not
/// while the pull is not set up, not due, or left no room.
#[test]
fn the_network_is_checked_right_before_the_request_only() {
    let mut harness = harness();
    let mut puller = Puller::open(&harness.support_dir());
    assert_eq!(
        ticked(&mut harness, &mut puller, OPEN, &users()),
        (Vec::new(), 0)
    );
    connect(&mut harness, 1, false, 1);
    let no_room = Opening {
        room: None,
        clear: true,
    };
    assert_eq!(ticked(&mut harness, &mut puller, no_room, &users()).1, 0);
    harness.portal.ok(&page(true, 0, Vec::new(), false));
    assert_eq!(ticked(&mut harness, &mut puller, OPEN, &users()).1, 1);
    // Not due for five minutes.
    assert_eq!(ticked(&mut harness, &mut puller, OPEN, &users()).1, 0);
    assert_eq!(requests(&harness).len(), 1);
}

/// A change of the settings reads the token again, even one that comes
/// back at a revision seen before (the file was lost and made again).
#[test]
fn a_change_of_the_settings_reads_the_token_again() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    harness.portal.ok(&page(true, 0, Vec::new(), false));
    tick(&mut harness, &mut puller, OPEN);
    fs::remove_file(harness.support_dir().join(mooring_store::PAYMENT_PULL_FILE)).unwrap();
    assert!(tick(&mut harness, &mut puller, OPEN).is_empty());
    connect(&mut harness, 1, false, 2);
    harness.portal.ok(&page(true, 0, Vec::new(), false));
    tick(&mut harness, &mut puller, OPEN);
    let made = harness.portal.requests.borrow();
    assert_eq!(made.len(), 2);
    assert_eq!(made[0].token, token(1).expose_str());
    assert_eq!(made[1].token, token(2).expose_str());
}

/// The end of a stop is recorded as soon as the settings move past it,
/// whatever the request then comes to.
#[test]
fn the_end_of_a_stop_is_recorded_at_once() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    answer(&harness, 401, None, b"no\n");
    tick(&mut harness, &mut puller, OPEN);
    assert!(ledger_on_disk(&harness).unwrap().stopped().is_some());
    connect(&mut harness, 2, false, 1);
    // No answer is scripted: the request fails.
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        notes[0],
        "payment pull: its settings changed since it stopped (unauthorized); pulling again"
    );
    assert!(notes[1].starts_with("payment pull: no answer from the portal"));
    assert_eq!(ledger_on_disk(&harness).unwrap().stopped(), None);
}
