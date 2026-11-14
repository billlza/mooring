// SPDX-License-Identifier: GPL-3.0-or-later

//! `portal plans set | off` and the plans kept in the daemon's pull: the
//! file read and checked before anything is written, its plans kept with
//! those of earlier files and by every other command of the pull, and a
//! live grant of a plan not kept held, with why. Every plan here is
//! synthetic.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use mooring_daemon_core::payments::{
    GrantOutcome, HeldReason, MAX_PLAN_FILE_BYTES, PlanBook, PlanFile, PortalOrigin, PullSettings,
};
use mooring_store::{PAYMENT_PULL_FILE, update_payment_pull};
use serde_json::{Value, json};

use super::super::support::{Harness, Outcome};
use super::command::settings;
use super::pull::{OPEN, tick};
use super::{FIRST, SECOND, connect, grant, harness, ledger_on_disk, pack, page, token};
use crate::error::LocalError;
use crate::payments::plans::read_plan_file;
use crate::payments::pull::Puller;

const A: &str = "aaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbb";

/// A plan of 30 days as the portal's file lists it, on the Payment Link
/// `link` (`https://buy.stripe.com/<link>`, `plink_<link>`).
pub(super) fn plan(id: &str, kind: &str, traffic_gb: u64, amount: u64, link: &str) -> Value {
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

/// What the tests' grants buy: the month and the pack of `grant` and
/// `pack`.
pub(super) fn sold() -> Vec<Value> {
    vec![
        plan("month-100", "month", 100, 800, "1Month"),
        plan("pack-50", "traffic", 50, 800, "1Pack"),
    ]
}

/// The portal's live plan file of `plans`, in pounds.
pub(super) fn plan_file(plans: Vec<Value>) -> Value {
    json!({
        "format": "mooring-portal-payments",
        "version": 1,
        "livemode": true,
        "currency": "gbp",
        "plans": plans,
        "manage_subscription_url": "https://billing.stripe.com/p/login/1Manage",
    })
}

/// The plans of the live file of `plans`, kept where none were.
pub(super) fn book(plans: Vec<Value>) -> PlanBook {
    let file = PlanFile::parse(&serde_json::to_vec(&plan_file(plans)).unwrap()).unwrap();
    PlanBook::default().stored(&file).unwrap().0
}

/// `bytes` written as `name` beside the support directory.
fn written(harness: &Harness, name: &str, bytes: &[u8]) -> PathBuf {
    let path = harness.home.path().join(name);
    fs::write(&path, bytes).unwrap();
    path
}

/// `portal plans set <path>`.
fn set(harness: &mut Harness, path: &Path) -> Outcome {
    harness.run(&["portal", "plans", "set", path.to_str().unwrap()])
}

const SOLD_LINES: &str = "  month-100 (current): month, 30 days, 100 GB (100000000000 bytes), 800 gbp, Payment Link plink_1Month\n  pack-50 (current): traffic, 30 days, 50 GB (50000000000 bytes), 800 gbp, Payment Link plink_1Pack\n";

const KEPT: &str = "a live grant is granted only at the terms of a plan kept and, with the check against Stripe, only when it was paid on that plan's Payment Link; any other is held";

const NONE: &str = "plans kept: none: grants are applied at the terms the portal lists (`mooringctl portal plans set <file>` keeps the portal's live plan file)";

/// `set` keeps the file's plans, before the pull is connected, so that no
/// live grant is applied unchecked; `connect`, `rehearsal`,
/// `stripe-check` and `disconnect` keep them, and `portal payments` lists
/// them.
#[test]
fn set_keeps_the_file_s_plans_and_the_pull_s_commands_keep_them() {
    let mut harness = harness();
    let file = written(
        &harness,
        "catalogue-live.json",
        &serde_json::to_vec_pretty(&plan_file(sold())).unwrap(),
    );
    let outcome = set(&mut harness, &file);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "the plan file's 2 plan(s) are kept as the current ones (2 new), with 0 of earlier files (settings revision 1)\n{SOLD_LINES}plans kept: 2 current, 0 of earlier files: {KEPT}\n"
        )
    );
    let kept = book(sold());
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(1, false).planning(1, kept.clone()))
    );
    harness.stdin = Cursor::new(token(3).expose_str().as_bytes().to_vec());
    let connected = harness.run(&[
        "portal",
        "connect",
        "--origin",
        "https://portal.example.org",
        "--stdin",
    ]);
    assert_eq!(connected.code, 0, "{}", connected.stderr);
    assert!(
        connected.stdout.ends_with(&format!(
            "plans kept: 2 current, 0 of earlier files: {KEPT}\n"
        )),
        "{}",
        connected.stdout
    );
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let mut expected = PullSettings::connected(2, origin, false, false).planning(2, kept.clone());
    assert_eq!(settings(&harness), Some(expected.clone()));
    assert_eq!(harness.run(&["portal", "rehearsal", "on"]).code, 0);
    expected = expected.rehearsing(3, true);
    assert_eq!(settings(&harness), Some(expected.clone()));
    harness.stdin = Cursor::new(format!("rk_live_{}", "K".repeat(99)).into_bytes());
    assert_eq!(
        harness
            .run(&["portal", "stripe-check", "on", "--stdin"])
            .code,
        0
    );
    expected = expected.checking(4, true);
    assert_eq!(settings(&harness), Some(expected.clone()));
    let listed = harness.run(&["portal", "payments"]);
    assert!(
        listed.stdout.contains(&format!(
            "  plans kept: 2 current, 0 of earlier files: {KEPT}\n    month-100 (current): month"
        )),
        "{}",
        listed.stdout
    );
    assert_eq!(harness.run(&["portal", "stripe-check", "off"]).code, 0);
    assert_eq!(harness.run(&["portal", "disconnect"]).code, 0);
    let after = settings(&harness).unwrap();
    assert_eq!(after.revision(), 6);
    assert_eq!(after.origin(), None);
    assert_eq!(after.plans(), &kept);
    // The same file again changes nothing.
    let again = set(&mut harness, &file);
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert!(
        again.stdout.starts_with(
            "unchanged; the plan file's 2 plan(s) are kept as the current ones (0 new), with 0 of earlier files (settings revision 6)\n"
        ),
        "{}",
        again.stdout
    );
    assert_eq!(settings(&harness).unwrap().revision(), 6);
}

/// A new file's plans are the current ones, after the plans of the files
/// before it, which are kept for the orders paid on them.
#[test]
fn a_new_file_keeps_the_plans_of_the_files_before_it() {
    let mut harness = harness();
    let first = written(
        &harness,
        "first.json",
        &serde_json::to_vec(&plan_file(sold())).unwrap(),
    );
    assert_eq!(set(&mut harness, &first).code, 0);
    let dearer = written(
        &harness,
        "dearer.json",
        &serde_json::to_vec(&plan_file(vec![plan(
            "month-100",
            "month",
            100,
            1500,
            "2Month",
        )]))
        .unwrap(),
    );
    let outcome = set(&mut harness, &dearer);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "the plan file's 1 plan(s) are kept as the current ones (1 new), with 2 of earlier files (settings revision 2)\n\
             \x20 month-100 (earlier): month, 30 days, 100 GB (100000000000 bytes), 800 gbp, Payment Link plink_1Month\n\
             \x20 pack-50 (earlier): traffic, 30 days, 50 GB (50000000000 bytes), 800 gbp, Payment Link plink_1Pack\n\
             \x20 month-100 (current): month, 30 days, 100 GB (100000000000 bytes), 1500 gbp, Payment Link plink_2Month\n\
             plans kept: 1 current, 2 of earlier files: {KEPT}\n"
        )
    );
    assert_eq!(settings(&harness).unwrap().plans().plans().len(), 3);
}

/// Past the most plans kept, those no file has listed for longest are
/// forgotten, and `set` says how many, one as well as many.
#[test]
fn set_says_how_many_plans_of_earlier_files_it_forgets() {
    let mut harness = harness();
    for number in 0..5 {
        let plans = (0..24)
            .map(|at| {
                plan(
                    &format!("p{number}-{at}"),
                    "month",
                    100,
                    800,
                    &format!("F{number}x{at}"),
                )
            })
            .collect();
        let file = written(
            &harness,
            &format!("file-{number}.json"),
            &serde_json::to_vec(&plan_file(plans)).unwrap(),
        );
        let outcome = set(&mut harness, &file);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        let first = outcome.stdout.lines().next().unwrap().to_owned();
        let expected = if number < 4 {
            format!(
                "the plan file's 24 plan(s) are kept as the current ones (24 new), with {} of earlier files (settings revision {})",
                number * 24,
                number + 1
            )
        } else {
            "the plan file's 24 plan(s) are kept as the current ones (24 new), with 72 of earlier files; 24 plan(s) of earlier files no file has listed for longest are forgotten (settings revision 5)".to_owned()
        };
        assert_eq!(first, expected);
    }
    let one = written(
        &harness,
        "file-5.json",
        &serde_json::to_vec(&plan_file(vec![plan("p5-0", "month", 100, 800, "F5x0")])).unwrap(),
    );
    let outcome = set(&mut harness, &one);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout.lines().next().unwrap(),
        "the plan file's 1 plan(s) are kept as the current ones (1 new), with 95 of earlier files; 1 plan(s) of earlier files no file has listed for longest are forgotten (settings revision 6)"
    );
}

/// `off` forgets every plan, and leaves settings without plans, or no
/// settings, as they are.
#[test]
fn off_forgets_every_plan() {
    let mut harness = harness();
    let none = harness.run(&["portal", "plans", "off"]);
    assert_eq!(none.code, 0, "{}", none.stderr);
    assert_eq!(none.stdout, format!("unchanged; {NONE}\n"));
    assert!(!harness.support_dir().join(PAYMENT_PULL_FILE).exists());
    let file = written(
        &harness,
        "plans.json",
        &serde_json::to_vec(&plan_file(sold())).unwrap(),
    );
    assert_eq!(set(&mut harness, &file).code, 0);
    let off = harness.run(&["portal", "plans", "off"]);
    assert_eq!(off.code, 0, "{}", off.stderr);
    assert_eq!(off.stdout, format!("{NONE}\n"));
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(2, false))
    );
    let again = harness.run(&["portal", "plans", "off"]);
    assert_eq!(again.stdout, format!("unchanged; {NONE}\n"));
    assert_eq!(settings(&harness).unwrap().revision(), 2);
}

/// A Payment Link is kept for one plan: a file that lists other terms on
/// the link of a plan kept, current or of an earlier file, is refused and
/// writes nothing, so that the link a payment was made on decides what it
/// buys. Once `off` has forgotten every plan, the file is kept.
#[test]
fn a_file_that_puts_other_terms_on_a_kept_link_writes_nothing() {
    let mut harness = harness();
    let first = written(
        &harness,
        "first.json",
        &serde_json::to_vec(&plan_file(sold())).unwrap(),
    );
    assert_eq!(set(&mut harness, &first).code, 0);
    let refused = |harness: &mut Harness, name: &str, plans: Vec<Value>, why: &str| {
        let kept = settings(harness);
        let path = written(
            harness,
            name,
            &serde_json::to_vec(&plan_file(plans)).unwrap(),
        );
        let outcome = set(harness, &path);
        assert_eq!(outcome.code, 1, "{}", outcome.stdout);
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: {} puts a plan on the Payment Link of a plan kept at other terms\n  caused by: {why}\n",
                path.display()
            )
        );
        assert_eq!(settings(harness), kept);
        path
    };
    let fewer = refused(
        &mut harness,
        "fewer.json",
        vec![plan("month-100", "month", 80, 800, "1Month")],
        "plan month-100 is sold on plink_1Month, the Payment Link of plan month-100 kept at other terms; new terms need a new Payment Link",
    );
    let dearer = written(
        &harness,
        "dearer.json",
        &serde_json::to_vec(&plan_file(vec![plan(
            "month-100",
            "month",
            100,
            1500,
            "2Month",
        )]))
        .unwrap(),
    );
    assert_eq!(set(&mut harness, &dearer).code, 0);
    refused(
        &mut harness,
        "renamed.json",
        vec![plan("pack-big", "traffic", 50, 800, "1Pack")],
        "plan pack-big is sold on plink_1Pack, the Payment Link of plan pack-50 kept at other terms; new terms need a new Payment Link",
    );
    assert_eq!(harness.run(&["portal", "plans", "off"]).code, 0);
    let outcome = set(&mut harness, &fewer);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(settings(&harness).unwrap().plans().plans().len(), 1);
}

/// A file that cannot be read, is not a regular file, or is not a live
/// plan file the portal would read writes nothing, and says why; so do
/// settings that cannot be read, for `set` and `off`. The command line
/// takes one file.
#[test]
fn a_file_that_is_not_kept_writes_nothing() {
    let mut harness = harness();
    let missing = harness.home.path().join("missing.json");
    let outcome = set(&mut harness, &missing);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome.stderr.starts_with(&format!(
            "mooringctl: cannot read the plan file {}\n  caused by: ",
            missing.display()
        )),
        "{}",
        outcome.stderr
    );
    let directory = harness.home.path().to_path_buf();
    let outcome = set(&mut harness, &directory);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: {} is not a regular file, so no plans were read from it\n",
            directory.display()
        )
    );
    let mut test_mode = plan_file(sold());
    test_mode["livemode"] = json!(false);
    let mut shared = plan_file(sold());
    shared["plans"][1]["payment_link_id"] = json!("plink_1Month");
    let mut largest = serde_json::to_vec(&plan_file(sold())).unwrap();
    largest.resize(MAX_PLAN_FILE_BYTES + 1, b' ');
    for (bytes, why) in [
        (
            serde_json::to_vec(&test_mode).unwrap(),
            "the plan file is of Stripe's test mode; the Mac keeps the live plan file only, since a rehearsal's grants are not checked",
        ),
        (
            serde_json::to_vec(&shared).unwrap(),
            "plan pack-50: its Payment Link is another plan's",
        ),
        (largest, "the plan file is larger than 65536 bytes"),
    ] {
        let path = written(&harness, "refused.json", &bytes);
        let outcome = set(&mut harness, &path);
        assert_eq!(outcome.code, 1);
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: {} is not a live plan file the portal would read\n  caused by: {why}\n",
                path.display()
            )
        );
    }
    assert!(!harness.support_dir().join(PAYMENT_PULL_FILE).exists());
    fs::write(harness.support_dir().join(PAYMENT_PULL_FILE), b"{").unwrap();
    let file = written(
        &harness,
        "plans.json",
        &serde_json::to_vec(&plan_file(sold())).unwrap(),
    );
    let set_outcome = set(&mut harness, &file);
    let off_outcome = harness.run(&["portal", "plans", "off"]);
    for outcome in [set_outcome, off_outcome] {
        assert_eq!(outcome.code, 1);
        assert!(
            outcome
                .stderr
                .starts_with("mooringctl: the payment pull's files failed\n"),
            "{}",
            outcome.stderr
        );
    }
    assert_eq!(
        fs::read(harness.support_dir().join(PAYMENT_PULL_FILE)).unwrap(),
        b"{"
    );
    for args in [
        &["mooringctl", "portal", "plans"][..],
        &["mooringctl", "portal", "plans", "set"],
        &["mooringctl", "portal", "plans", "set", "a.json", "b.json"],
        &["mooringctl", "portal", "plans", "off", "a.json"],
        &["mooringctl", "portal", "plans", "on"],
    ] {
        assert!(
            <crate::cli::Cli as clap::Parser>::try_parse_from(args).is_err(),
            "{args:?}"
        );
    }
}

/// A FIFO does not hold the read: with nothing writing to it the file is
/// refused at once, where a blocking open would never return. The wait
/// bounds the test, so a regression fails it instead of hanging the run.
#[test]
fn a_fifo_is_refused_without_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("plans.json");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (done, refused) = mpsc::channel();
    let path = fifo.clone();
    thread::spawn(move || {
        let read = read_plan_file(&path);
        let refused =
            matches!(&read, Err(LocalError::PlanFileNotAFile { path: named }) if *named == path);
        // The receiver is gone if the wait below ran out.
        let _ = done.send(refused);
    });
    assert_eq!(refused.recv_timeout(Duration::from_secs(10)), Ok(true));
}

/// With plans kept, the daemon's pull holds a live grant of a plan not
/// kept, or at other terms, and says why; one of a plan kept is granted.
#[test]
fn the_pull_holds_a_grant_of_a_plan_not_kept() {
    let mut harness = harness();
    connect(&mut harness, 1, false, 1);
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let kept = book(vec![plan("month-100", "month", 100, 800, "1Month")]);
    let planned = PullSettings::connected(2, origin, false, false).planning(2, kept);
    update_payment_pull::<()>(&harness.support_dir(), 8192, |_| {
        Ok(Some(planned.encode().unwrap()))
    })
    .unwrap();
    let mut dearer = grant(3, "cccccccccccccccccccc", SECOND);
    dearer["amount"] = json!(900);
    harness.portal.ok(&page(
        true,
        0,
        vec![grant(1, A, FIRST), pack(2, B, SECOND), dearer],
        false,
    ));
    let mut puller = Puller::open(&harness.support_dir());
    let notes = tick(&mut harness, &mut puller, OPEN);
    assert_eq!(
        notes[1..3],
        [
            format!(
                "payment: order {B} for user {SECOND} is held, not granted (plan_unknown: the plans kept on the Mac have none of its plan's id; if the portal sells it, keep the portal's plan file first (`mooringctl portal plans set`)); settle it at Stripe"
            ),
            format!(
                "payment: order cccccccccccccccccccc for user {SECOND} is held, not granted (plan_differs: no plan kept on the Mac of its plan's id is at its kind, days, traffic, amount and currency); settle it at Stripe"
            ),
        ],
        "{notes:?}"
    );
    assert!(
        notes[0].starts_with(&format!("payment: order {A} granted user {FIRST} service")),
        "{notes:?}"
    );
    let ledger = ledger_on_disk(&harness).unwrap();
    let outcome = |order: &str| {
        ledger.orders()[&mooring_daemon_core::payments::OrderId::parse(order).unwrap()]
            .grant
            .unwrap()
            .outcome
    };
    assert!(matches!(outcome(A), GrantOutcome::Period { .. }));
    assert_eq!(
        outcome(B),
        GrantOutcome::Held {
            reason: HeldReason::PlanUnknown
        }
    );
    let listed = harness.run(&["portal", "payments"]);
    assert!(
        listed.stdout.contains(
            "held, not granted (plan_differs: no plan kept on the Mac of its plan's id is at its kind, days, traffic, amount and currency): settle it at Stripe"
        ),
        "{}",
        listed.stdout
    );
}
