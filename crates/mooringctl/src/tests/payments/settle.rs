// SPDX-License-Identifier: GPL-3.0-or-later

//! The refunds in full of traffic packs that wait for the usage (design
//! §9.6), on the daemon's puller: a refund is recorded as waiting; the
//! usage is asked about it at most every minute; what it tells is written
//! before it is kept; and the log names orders only.

use std::cell::RefCell;
use std::fs;
use std::time::{Duration, Instant};

use mooring_daemon_core::error::UsageErrorKind;
use mooring_daemon_core::payments::{OrderId, PackRefund, PackUse};
use mooring_daemon_core::period::BillingCycle;
use mooring_model::{BillDay, CycleRule, UnixTime, UserId};
use mooring_store::{PAYMENT_LEDGER_FILE, PAYMENTS_DIRECTORY};

use super::super::support::{Harness, NOW};
use super::{
    FIRST, SECOND, block_the_ledger, connect, grant, harness, ledger_on_disk, pack, page,
    refund_in_full,
};
use crate::payments::pull::{Gate, Puller, SETTLE_EVERY, UseTold};

const A: &str = "aaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbb";
const GB: u64 = 1_000_000_000;
const DAY: u64 = 86_400;

/// When the portal recorded the refunds below: 2026-10-13 19:21:00 UTC.
const REFUNDED: u64 = NOW + 60;

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

/// The billing cycle `secs` is in, billed on the 1st.
fn cycle(secs: u64) -> BillingCycle {
    BillingCycle::of_instant(
        CycleRule::Monthly {
            bill_day: BillDay::new(1).unwrap(),
        },
        at(secs),
    )
    .unwrap()
}

/// One tick of `puller` at [`NOW`] through an open gate; the lines it
/// logged.
pub(super) fn tick(harness: &mut Harness, puller: &mut Puller) -> Vec<String> {
    let users = mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .deployment
        .users()
        .clone();
    let mut clear = || true;
    harness.with_env(|env| {
        puller.tick(
            env,
            &users,
            at(NOW),
            Gate {
                room: Some(Duration::from_secs(10)),
                network_clear: &mut clear,
            },
        )
    })
}

/// A puller that has pulled `granted` as order [`A`] of user [`FIRST`] and
/// then its refund in full, recorded at [`REFUNDED`]; and the lines the
/// refund's tick logged.
fn refunded(harness: &mut Harness, granted: &serde_json::Value) -> (Puller, Vec<String>) {
    connect(harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    harness
        .portal
        .ok(&page(true, 0, vec![granted.clone()], true));
    harness.portal.ok(&page(
        true,
        1,
        vec![refund_in_full(granted, 2, REFUNDED)],
        false,
    ));
    tick(harness, &mut puller);
    let notes = tick(harness, &mut puller);
    (puller, notes)
}

/// [`refunded`] for a traffic pack.
fn pack_refunded(harness: &mut Harness) -> (Puller, Vec<String>) {
    refunded(harness, &pack(1, A, FIRST))
}

/// The use the ledger on disk records on order [`A`]'s refund.
fn recorded(harness: &Harness) -> Option<PackUse> {
    ledger_on_disk(harness).unwrap().orders()[&OrderId::parse(A).unwrap()].refunds[0].pack_use
}

/// The refund of user [`FIRST`]'s pack as `puller` holds it in memory.
fn held(puller: &Puller) -> Option<PackRefund> {
    puller.entitlements().users()[&UserId::parse(FIRST).unwrap()].packs()[0].refund
}

/// The questions the usage was asked, and a usage that answers each with
/// `answer`.
type Asked = RefCell<Vec<(UserId, UnixTime)>>;

fn usage(asked: &Asked, answer: UseTold) -> impl Fn(&UserId, UnixTime) -> UseTold + '_ {
    move |user, instant| {
        asked.borrow_mut().push((user.clone(), instant));
        answer
    }
}

/// The line a fault of kind `kind` is logged with.
fn fault_line(kind: &str) -> String {
    format!(
        "payment ledger: the usage collected cannot tell the use at the refund(s) of traffic packs that wait for it ({kind}); they wait on"
    )
}

/// A refund in full of a traffic pack is recorded as waiting for the
/// usage, and logged so, by its order and without the user.
#[test]
fn a_refund_in_full_of_a_pack_is_recorded_as_waiting() {
    let mut harness = harness();
    let (puller, notes) = pack_refunded(&mut harness);
    assert_eq!(recorded(&harness), Some(PackUse::Awaiting));
    assert_eq!(
        held(&puller),
        Some(PackRefund {
            at: at(REFUNDED),
            used: PackUse::Awaiting
        })
    );
    assert!(
        notes.contains(&format!(
            "payment: order {A} refunded 800 so far, in full; it waits for the usage: its pack counts in full until the usage collected covers the refund's time, or the pack's billing cycle ends"
        )),
        "{notes:?}"
    );
    assert!(notes.iter().all(|note| !note.contains(FIRST)), "{notes:?}");
}

/// The usage is asked about a waiting refund, by its user and the time
/// the portal recorded it, at most every minute: not a second before the
/// minute has passed, and again once it has, from when the minute starts
/// anew. A puller opened anew (the daemon started again) asks at once.
/// While the usage cannot tell, nothing is logged and the refund goes on
/// waiting.
#[test]
fn the_usage_is_asked_about_a_waiting_refund_at_most_every_minute() {
    assert_eq!(SETTLE_EVERY, Duration::from_secs(60));
    let mut harness = harness();
    let (mut puller, _) = pack_refunded(&mut harness);
    let asked = Asked::default();
    let silent = usage(&asked, Ok(None));
    let question = (UserId::parse(FIRST).unwrap(), at(REFUNDED));
    let began = Instant::now();
    let second = Duration::from_secs(1);
    let mut look = |tick: Instant| puller.settle(tick, at(NOW + 90), cycle(NOW), &silent);
    assert!(look(began).is_empty());
    assert_eq!(asked.borrow().as_slice(), std::slice::from_ref(&question));
    assert!(look(began + SETTLE_EVERY - second).is_empty());
    assert_eq!(asked.borrow().len(), 1);
    assert!(look(began + SETTLE_EVERY).is_empty());
    assert_eq!(asked.borrow().len(), 2);
    assert!(look(began + SETTLE_EVERY * 2 - second).is_empty());
    assert_eq!(asked.borrow().len(), 2);
    assert_eq!(recorded(&harness), Some(PackUse::Awaiting));
    let mut again = Puller::open(&harness.support_dir());
    assert!(
        again
            .settle(began, at(NOW + 95), cycle(NOW), &silent)
            .is_empty()
    );
    assert_eq!(
        *asked.borrow(),
        [question.clone(), question.clone(), question]
    );
}

/// A refund the usage could not tell of at first is settled at a later
/// asking, a minute on, once the usage tells: the use is learned then.
#[test]
fn a_refund_the_usage_could_not_tell_of_is_settled_at_a_later_asking() {
    let mut harness = harness();
    let (mut puller, _) = pack_refunded(&mut harness);
    let asked = Asked::default();
    let began = Instant::now();
    assert!(
        puller
            .settle(began, at(NOW + 90), cycle(NOW), &usage(&asked, Ok(None)))
            .is_empty()
    );
    let notes = puller.settle(
        began + SETTLE_EVERY,
        at(NOW + 150),
        cycle(NOW),
        &usage(&asked, Ok(Some(70 * GB))),
    );
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains("no longer waits for the usage"),
        "{notes:?}"
    );
    assert_eq!(
        recorded(&harness),
        Some(PackUse::Served {
            bytes: 70 * GB,
            learned_at: at(NOW + 150)
        })
    );
}

/// A look while no refund waits does not start the minute's wait: a
/// refund recorded right after it is asked about at once.
#[test]
fn a_refund_recorded_while_none_waited_is_asked_about_at_once() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    let granted = pack(1, A, FIRST);
    harness
        .portal
        .ok(&page(true, 0, vec![granted.clone()], true));
    harness.portal.ok(&page(
        true,
        1,
        vec![refund_in_full(&granted, 2, REFUNDED)],
        false,
    ));
    let asked = Asked::default();
    let silent = usage(&asked, Ok(None));
    let began = Instant::now();
    tick(&mut harness, &mut puller);
    assert!(
        puller
            .settle(began, at(NOW), cycle(NOW), &silent)
            .is_empty()
    );
    assert!(asked.borrow().is_empty());
    tick(&mut harness, &mut puller);
    assert!(
        puller
            .settle(began, at(NOW), cycle(NOW), &silent)
            .is_empty()
    );
    assert_eq!(asked.borrow().len(), 1);
}

/// Once the usage tells the user's use at the refund's time, it is written
/// to the ledger with when it was learned, kept, and logged by the order,
/// without the user. Nothing waits then, and the usage is not asked again.
#[test]
fn once_the_usage_tells_the_use_is_written_and_logged_by_order() {
    let mut harness = harness();
    let (mut puller, _) = pack_refunded(&mut harness);
    let asked = Asked::default();
    let began = Instant::now();
    let notes = puller.settle(
        began,
        at(NOW + 90),
        cycle(NOW),
        &usage(&asked, Ok(Some(70 * GB))),
    );
    assert_eq!(
        notes,
        [format!(
            "payment: order {A}'s refund in full no longer waits for the usage; its pack counts from 2026-10-13 19:21:30 UTC on only what the user had used of it beyond the rest of their quota: 70000000000 bytes served this cycle by the refund's time"
        )]
    );
    let learned = PackUse::Served {
        bytes: 70 * GB,
        learned_at: at(NOW + 90),
    };
    assert_eq!(recorded(&harness), Some(learned));
    assert_eq!(
        held(&puller),
        Some(PackRefund {
            at: at(REFUNDED),
            used: learned
        })
    );
    assert_eq!(asked.borrow().len(), 1);
    let mut anew = Puller::open(&harness.support_dir());
    for puller in [&mut puller, &mut anew] {
        assert!(
            puller
                .settle(
                    began + SETTLE_EVERY,
                    at(NOW + 200),
                    cycle(NOW),
                    &usage(&asked, Ok(Some(GB)))
                )
                .is_empty()
        );
    }
    assert_eq!(asked.borrow().len(), 1);
    assert_eq!(recorded(&harness), Some(learned));
}

/// A refund still waiting when its pack's billing cycle has ended takes
/// nothing back: that is written and logged, and the usage is not asked.
#[test]
fn a_refund_still_waiting_when_its_cycle_ends_takes_nothing_back() {
    let mut harness = harness();
    let (mut puller, _) = pack_refunded(&mut harness);
    let asked = Asked::default();
    let later = NOW + 40 * DAY;
    let notes = puller.settle(
        Instant::now(),
        at(later),
        cycle(later),
        &usage(&asked, Ok(Some(70 * GB))),
    );
    assert_eq!(
        notes,
        [format!(
            "payment: order {A}'s refund in full no longer waits for the usage; its pack's billing cycle has ended, so nothing is taken back"
        )]
    );
    assert!(asked.borrow().is_empty());
    assert_eq!(recorded(&harness), Some(PackUse::CycleEnded));
}

/// A use that cannot be written is not kept: the failure is logged with a
/// count and no order or user, and the refund goes on waiting in memory
/// and on disk. It is tried again a minute later, not before, and is
/// recorded then.
#[test]
fn a_use_that_cannot_be_written_is_not_kept() {
    let mut harness = harness();
    let (mut puller, _) = pack_refunded(&mut harness);
    let asked = Asked::default();
    let telling = usage(&asked, Ok(Some(70 * GB)));
    let began = Instant::now();
    // Something other than a directory where `payments/` belongs: nothing
    // can be written there. The ledger waits aside meanwhile.
    let directory = harness.support_dir().join(PAYMENTS_DIRECTORY);
    let aside = harness.support_dir().join("payments.aside");
    fs::rename(&directory, &aside).unwrap();
    block_the_ledger(&harness);
    let notes = puller.settle(began, at(NOW + 90), cycle(NOW), &telling);
    fs::remove_file(&directory).unwrap();
    fs::rename(&aside, &directory).unwrap();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with(
            "payment ledger: the use at 1 refund(s) of traffic packs could not be recorded ("
        ) && notes[0].ends_with("); trying again in 60 s"),
        "{notes:?}"
    );
    assert!(
        !notes[0].contains(FIRST) && !notes[0].contains(A),
        "{notes:?}"
    );
    assert_eq!(recorded(&harness), Some(PackUse::Awaiting));
    assert_eq!(
        held(&puller).map(|refund| refund.used),
        Some(PackUse::Awaiting)
    );
    let early = began + SETTLE_EVERY - Duration::from_secs(1);
    assert!(
        puller
            .settle(early, at(NOW + 149), cycle(NOW), &telling)
            .is_empty()
    );
    assert_eq!(recorded(&harness), Some(PackUse::Awaiting));
    assert_eq!(
        puller
            .settle(began + SETTLE_EVERY, at(NOW + 150), cycle(NOW), &telling)
            .len(),
        1
    );
    assert_eq!(
        recorded(&harness),
        Some(PackUse::Served {
            bytes: 70 * GB,
            learned_at: at(NOW + 150)
        })
    );
}

/// A fault of the usage leaves the refund waiting and is logged by its
/// kind, with no order and no user, once while it lasts: not at the next
/// asking with the same fault, again when the fault is another, and again
/// after an asking without one. Usage that only cannot tell yet is not
/// logged.
#[test]
fn a_fault_of_the_usage_is_logged_once_while_it_lasts() {
    let mut harness = harness();
    let (mut puller, _) = pack_refunded(&mut harness);
    let asked = Asked::default();
    let began = Instant::now();
    let mut look = |nth: u32, answer: UseTold| {
        puller.settle(
            began + SETTLE_EVERY * nth,
            at(NOW + 90),
            cycle(NOW),
            &usage(&asked, answer),
        )
    };
    assert_eq!(
        look(0, Err(UsageErrorKind::MonthlyInconsistent)),
        [fault_line("MonthlyInconsistent")]
    );
    assert!(look(1, Err(UsageErrorKind::MonthlyInconsistent)).is_empty());
    assert_eq!(
        look(2, Err(UsageErrorKind::LedgerCorrupt)),
        [fault_line("LedgerCorrupt")]
    );
    assert!(look(3, Ok(None)).is_empty());
    assert_eq!(
        look(4, Err(UsageErrorKind::LedgerCorrupt)),
        [fault_line("LedgerCorrupt")]
    );
    assert_eq!(asked.borrow().len(), 5);
    assert_eq!(recorded(&harness), Some(PackUse::Awaiting));
    for kind in ["MonthlyInconsistent", "LedgerCorrupt"] {
        let line = fault_line(kind);
        assert!(!line.contains(FIRST) && !line.contains(A), "{line}");
    }
}

/// Two packs' refunds wait, of two users. A fault at one does not keep the
/// other from being settled: the fault is logged, and then the use that
/// was learned. Of two faults at one asking the first is the one logged,
/// in the order of the orders.
#[test]
fn a_fault_at_one_refund_does_not_keep_another_from_being_settled() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let mut puller = Puller::open(&harness.support_dir());
    let (first, second) = (pack(1, A, FIRST), pack(2, B, SECOND));
    harness
        .portal
        .ok(&page(true, 0, vec![first.clone(), second.clone()], true));
    harness.portal.ok(&page(
        true,
        2,
        vec![
            refund_in_full(&first, 3, REFUNDED),
            refund_in_full(&second, 4, REFUNDED),
        ],
        false,
    ));
    tick(&mut harness, &mut puller);
    tick(&mut harness, &mut puller);
    let of_second = UserId::parse(SECOND).unwrap();
    let began = Instant::now();
    let two_faults = |user: &UserId, _: UnixTime| {
        Err(if *user == of_second {
            UsageErrorKind::LedgerCorrupt
        } else {
            UsageErrorKind::MonthlyInconsistent
        })
    };
    assert_eq!(
        puller.settle(began, at(NOW + 90), cycle(NOW), &two_faults),
        [fault_line("MonthlyInconsistent")]
    );
    let one_fault = |user: &UserId, _: UnixTime| {
        if *user == of_second {
            Ok(Some(70 * GB))
        } else {
            Err(UsageErrorKind::LedgerCorrupt)
        }
    };
    let notes = puller.settle(began + SETTLE_EVERY, at(NOW + 150), cycle(NOW), &one_fault);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert_eq!(notes[0], fault_line("LedgerCorrupt"));
    assert!(
        notes[1].starts_with(&format!(
            "payment: order {B}'s refund in full no longer waits for the usage"
        )),
        "{notes:?}"
    );
    let orders = ledger_on_disk(&harness).unwrap();
    let use_of = |order: &str| orders.orders()[&OrderId::parse(order).unwrap()].refunds[0].pack_use;
    assert_eq!(use_of(A), Some(PackUse::Awaiting));
    assert_eq!(
        use_of(B),
        Some(PackUse::Served {
            bytes: 70 * GB,
            learned_at: at(NOW + 150)
        })
    );
}

/// While no refund waits, the usage is not asked and nothing is written:
/// with no ledger, with a pack not refunded, with a month refunded in full
/// (which takes its time back at once), and with a ledger that cannot be
/// read, whose file is left as it is.
#[test]
fn the_usage_is_not_asked_while_no_refund_waits() {
    let asked = Asked::default();
    let telling = usage(&asked, Ok(Some(70 * GB)));
    let began = Instant::now();
    let mut harness = harness();
    let mut puller = Puller::open(&harness.support_dir());
    assert!(
        puller
            .settle(began, at(NOW), cycle(NOW), &telling)
            .is_empty()
    );
    assert!(ledger_on_disk(&harness).is_none());
    connect(&mut harness, 1, false, 1);
    harness
        .portal
        .ok(&page(true, 0, vec![pack(1, A, FIRST)], false));
    tick(&mut harness, &mut puller);
    let pulled = ledger_on_disk(&harness).unwrap();
    assert!(
        puller
            .settle(began, at(NOW), cycle(NOW), &telling)
            .is_empty()
    );
    assert_eq!(ledger_on_disk(&harness).unwrap(), pulled);

    let mut month = self::harness();
    let (mut puller, notes) = refunded(&mut month, &grant(1, A, FIRST));
    assert!(
        notes.iter().any(|note| note.contains("is taken back")),
        "{notes:?}"
    );
    assert_eq!(recorded(&month), None);
    assert!(
        puller
            .settle(began, at(NOW), cycle(NOW), &telling)
            .is_empty()
    );

    let unread = self::harness();
    let directory = unread.support_dir().join(PAYMENTS_DIRECTORY);
    fs::create_dir(&directory).unwrap();
    let file = directory.join(PAYMENT_LEDGER_FILE);
    fs::write(&file, b"{\"version\": 1}").unwrap();
    let mut puller = Puller::open(&unread.support_dir());
    assert!(puller.fault().is_some());
    assert!(
        puller
            .settle(began, at(NOW), cycle(NOW), &telling)
            .is_empty()
    );
    assert_eq!(fs::read(&file).unwrap(), b"{\"version\": 1}");
    assert!(asked.borrow().is_empty());
}
