// SPDX-License-Identifier: GPL-3.0-or-later

//! `portal stripe-check on | off`: the key read and checked before
//! anything is written, stored before the settings use it and deleted after
//! they stop, and the check kept across the pull's other commands. Every
//! key here is synthetic.

use std::fs;
use std::io::Cursor;

use mooring_daemon_core::payments::{PaymentLedger, PortalOrigin, PullSettings, Stop, StopReason};
use mooring_model::UnixTime;
use mooring_model::secret::{SecretMaterial, SecretRef};
use mooring_store::{PAYMENT_PULL_FILE, SecretStore, write_payment_ledger};

use super::super::support::{Harness, NOW, Outcome};
use super::command::{ORIGIN, settings, stored_token};
use super::{harness, token};

/// A restricted live key of 99 characters after its prefix, as Stripe
/// makes them.
fn key(fill: char) -> String {
    format!("rk_live_{}", fill.to_string().repeat(99))
}

/// The key the keychain holds, if any.
fn stored_key(harness: &Harness) -> Option<String> {
    match harness.secrets.get(&SecretRef::StripeReadKey) {
        Ok(SecretMaterial::StripeReadKey(key)) => Some(key.expose_str().to_owned()),
        Ok(other) => panic!("{other:?}"),
        Err(_) => None,
    }
}

/// `portal stripe-check on --stdin` with `input` on stdin.
fn on_with_stdin(harness: &mut Harness, input: &[u8]) -> Outcome {
    harness.stdin = Cursor::new(input.to_vec());
    harness.run(&["portal", "stripe-check", "on", "--stdin"])
}

const ON: &str = "check against Stripe on: a live payment is granted only once Stripe confirms it, and one Stripe does not confirm is held\n";

const OFF: &str = "check against Stripe off: payments are granted as the portal lists them (`mooringctl portal stripe-check on` confirms each at Stripe first)";

/// `on` stores the key, then turns the check on: before the pull is
/// connected, so that no live payment is granted unchecked. `connect`,
/// `rehearsal` and `disconnect` keep the check and its key.
#[test]
fn on_stores_the_key_then_turns_the_check_on_and_the_pull_keeps_it() {
    let mut harness = harness();
    let outcome = on_with_stdin(&mut harness, format!(" {}\r\n", key('A')).as_bytes());
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!("the read key is stored as stripe/read-key (settings revision 1)\n{ON}")
    );
    assert_eq!(stored_key(&harness), Some(key('A')));
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(1, true))
    );
    // `connect` keeps the check, and says so.
    harness.stdin = Cursor::new(token(3).expose_str().as_bytes().to_vec());
    let connected = harness.run(&["portal", "connect", "--origin", ORIGIN, "--stdin"]);
    assert_eq!(connected.code, 0, "{}", connected.stderr);
    assert!(
        connected.stdout.ends_with(&format!("{ON}plans kept: none: grants are applied at the terms the portal lists (`mooringctl portal plans set <file>` keeps the portal's live plan file)\n")),
        "{}",
        connected.stdout
    );
    let origin = PortalOrigin::parse(ORIGIN).unwrap();
    assert_eq!(
        settings(&harness),
        Some(PullSettings::connected(2, origin.clone(), false, true))
    );
    let rehearsal = harness.run(&["portal", "rehearsal", "on"]);
    assert_eq!(rehearsal.code, 0, "{}", rehearsal.stderr);
    assert_eq!(
        settings(&harness),
        Some(PullSettings::connected(3, origin, true, true))
    );
    let disconnected = harness.run(&["portal", "disconnect"]);
    assert_eq!(disconnected.code, 0, "{}", disconnected.stderr);
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(4, true))
    );
    assert_eq!(stored_token(&harness), None);
    assert_eq!(stored_key(&harness), Some(key('A')));
    // The key is in no file of the support directory.
    for entry in fs::read_dir(harness.support_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = fs::read(&path).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&key('A')),
                "{}",
                path.display()
            );
        }
    }
}

/// A key that is not a restricted live key is refused, for why, before
/// anything is written, and is never echoed: a secret key, which could
/// move money, a test-mode key, a publishable key, and anything else.
#[test]
fn a_key_that_is_not_a_restricted_live_key_writes_nothing() {
    let secret = format!("sk_live_{}", "S".repeat(99));
    let secret_test = format!("sk_test_{}", "S".repeat(99));
    let test_mode = format!("rk_test_{}", "T".repeat(99));
    let publishable = format!("pk_live_{}", "P".repeat(99));
    let short = format!("rk_live_{}", "A".repeat(15));
    let long = format!("rk_live_{}", "A".repeat(201));
    // The longest key, and one byte more than a CR and a LF after it.
    let flooded = format!("rk_live_{}\n\n\n", "A".repeat(200));
    let mut punctuated = key('A');
    punctuated.push('-');
    let cases: [(&[u8], &str); 10] = [
        (
            secret.as_bytes(),
            "this is a secret key (sk_...), which can move money",
        ),
        (
            secret_test.as_bytes(),
            "this is a secret key (sk_...), which can move money",
        ),
        (
            test_mode.as_bytes(),
            "this is a test-mode key (rk_test_...), which cannot read live payments",
        ),
        (publishable.as_bytes(), "not a restricted live key"),
        (short.as_bytes(), "not a restricted live key"),
        (long.as_bytes(), "not a restricted live key"),
        (flooded.as_bytes(), "not a restricted live key"),
        (punctuated.as_bytes(), "not a restricted live key"),
        (b"rk_live_\xff\xfe", "not a restricted live key"),
        (b"", "not a restricted live key"),
    ];
    for (input, cause) in cases {
        let mut harness = harness();
        let outcome = on_with_stdin(&mut harness, input);
        assert_eq!(outcome.code, 1, "{}", String::from_utf8_lossy(input));
        assert!(
            outcome
                .stderr
                .starts_with("mooringctl: the Stripe key was refused\n  caused by: "),
            "{}",
            outcome.stderr
        );
        assert!(outcome.stderr.contains(cause), "{}", outcome.stderr);
        let typed = String::from_utf8_lossy(input);
        if typed.trim().len() > "rk_live_".len() {
            assert!(!outcome.stderr.contains(typed.trim()), "{}", outcome.stderr);
        }
        assert_eq!(stored_key(&harness), None);
        assert_eq!(settings(&harness), None);
    }
}

/// At the terminal the key is asked once, without echo.
#[test]
fn on_asks_the_terminal_once() {
    let mut harness = harness();
    harness.console.passwords.push_back(key('B').into_bytes());
    let outcome = harness.run(&["portal", "stripe-check", "on"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        harness.console.asked,
        ["Stripe restricted key (rk_live_..., Read on Checkout Sessions and Invoices only): "]
    );
    assert_eq!(stored_key(&harness), Some(key('B')));
}

/// `on` again takes the new key and raises the revision even when the
/// check was on, above the ledger's stop: a stop for Stripe's 401 ends.
#[test]
fn on_again_takes_a_new_key_and_ends_a_stop() {
    let mut harness = harness();
    assert_eq!(on_with_stdin(&mut harness, key('A').as_bytes()).code, 0);
    let stopped = PaymentLedger::new().with_stop(Some(Stop {
        reason: StopReason::StripeUnauthorized,
        at: UnixTime::from_secs(NOW),
        settings_revision: 6,
    }));
    write_payment_ledger(&harness.support_dir(), &stopped.encode().unwrap()).unwrap();
    let again = on_with_stdin(&mut harness, key('C').as_bytes());
    assert_eq!(again.code, 0, "{}", again.stderr);
    assert_eq!(
        again.stdout,
        format!("the read key is stored as stripe/read-key (settings revision 7)\n{ON}")
    );
    assert_eq!(stored_key(&harness), Some(key('C')));
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(7, true))
    );
}

/// `off` turns the check off, then deletes the key; off again, or with
/// no settings, changes nothing and says so, and still deletes a key left
/// behind.
#[test]
fn off_turns_the_check_off_then_deletes_the_key() {
    let mut harness = harness();
    let none = harness.run(&["portal", "stripe-check", "off"]);
    assert_eq!(none.code, 0, "{}", none.stderr);
    assert_eq!(
        none.stdout,
        format!("unchanged; {OFF}; the read key is deleted\n")
    );
    assert!(!harness.support_dir().join(PAYMENT_PULL_FILE).exists());
    assert_eq!(on_with_stdin(&mut harness, key('A').as_bytes()).code, 0);
    let off = harness.run(&["portal", "stripe-check", "off"]);
    assert_eq!(off.code, 0, "{}", off.stderr);
    assert_eq!(off.stdout, format!("{OFF}; the read key is deleted\n"));
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(2, false))
    );
    assert_eq!(stored_key(&harness), None);
    // A key left behind by hand goes, and the settings stay.
    use mooring_model::secret::SecretEntry;
    harness
        .secrets
        .put(SecretEntry::StripeReadKey(
            mooring_model::StripeReadKey::parse(&key('D')).unwrap(),
        ))
        .unwrap();
    let again = harness.run(&["portal", "stripe-check", "off"]);
    assert_eq!(
        again.stdout,
        format!("unchanged; {OFF}; the read key is deleted\n")
    );
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(2, false))
    );
    assert_eq!(stored_key(&harness), None);
}

/// A key the keychain will not store turns nothing on: the settings stay
/// as they were.
#[test]
fn a_key_the_keychain_will_not_store_turns_nothing_on() {
    let mut harness = harness();
    harness.keychain.lock().unwrap().put = Some(-25_293);
    let outcome = on_with_stdin(&mut harness, key('A').as_bytes());
    assert_eq!(outcome.code, 1);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the keychain failed\n"),
        "{}",
        outcome.stderr
    );
    assert_eq!(outcome.stdout, "");
    assert_eq!(settings(&harness), None);
}

/// A key the keychain will not delete is named, after the check is off.
#[test]
fn a_key_the_keychain_keeps_is_named_after_the_check_is_off() {
    let mut harness = harness();
    assert_eq!(on_with_stdin(&mut harness, key('A').as_bytes()).code, 0);
    harness.keychain.lock().unwrap().delete = Some(-25_293);
    let outcome = harness.run(&["portal", "stripe-check", "off"]);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the keychain failed\n"),
        "{}",
        outcome.stderr
    );
    assert_eq!(
        settings(&harness),
        Some(PullSettings::disconnected(2, false))
    );
    harness.keychain.lock().unwrap().delete = None;
    assert_eq!(stored_key(&harness), Some(key('A')));
}

/// Without a terminal and without `--stdin` the key is not asked, and
/// nothing is stored.
#[test]
fn without_a_terminal_nothing_is_stored() {
    let mut harness = harness();
    let outcome = harness.run(&["portal", "stripe-check", "on"]);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: no terminal to ask for the password (use --stdin)"),
        "{}",
        outcome.stderr
    );
    assert_eq!(stored_key(&harness), None);
    assert_eq!(settings(&harness), None);
}

/// Files that cannot be read are reported before the key is asked for,
/// and nothing is stored; `off` reads no key, and `on` or `off` must be
/// named.
#[test]
fn files_that_cannot_be_read_and_usage_errors_store_nothing() {
    let mut harness = harness();
    fs::write(harness.support_dir().join(PAYMENT_PULL_FILE), b"{").unwrap();
    let outcome = on_with_stdin(&mut harness, key('A').as_bytes());
    assert_eq!(outcome.code, 1);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the payment pull's files failed\n"),
        "{}",
        outcome.stderr
    );
    assert_eq!(stored_key(&harness), None);
    for args in [
        &["mooringctl", "portal", "stripe-check", "off", "--stdin"][..],
        &["mooringctl", "portal", "stripe-check"],
        &["mooringctl", "portal", "stripe-check", "maybe"],
    ] {
        assert!(
            <crate::cli::Cli as clap::Parser>::try_parse_from(args).is_err(),
            "{args:?}"
        );
    }
}
