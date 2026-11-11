// SPDX-License-Identifier: GPL-3.0-or-later

//! `portal connect | rehearsal | disconnect | payments`, and the portal
//! snapshot's paid expiry and quota.

use std::fs;
use std::io::Cursor;

use mooring_daemon_core::payments::{
    MAX_SETTINGS_BYTES, PaymentLedger, PullSettings, Stop, StopReason,
};
use mooring_model::secret::{SecretMaterial, SecretRef};
use mooring_model::{AgreementVersion, PortalAgreement, UnixTime};
use mooring_store::{
    PAYMENT_LEDGER_FILE, PAYMENT_PULL_FILE, PAYMENTS_DIRECTORY, SecretStore, read_payment_pull,
    write_payment_ledger,
};
use serde_json::Value;

use super::super::support::{Harness, NOW};
use super::{FIRST, grant, harness, ledger_on_disk, page, token};
use crate::payments::pull::Puller;

fn settings(harness: &Harness) -> Option<PullSettings> {
    read_payment_pull(&harness.support_dir(), MAX_SETTINGS_BYTES + 1)
        .unwrap()
        .map(|bytes| PullSettings::decode(&bytes).unwrap())
}

fn stored_token(harness: &Harness) -> Option<String> {
    match harness.secrets.get(&SecretRef::PortalPullToken) {
        Ok(SecretMaterial::PortalPullToken(token)) => Some(token.expose_str().to_owned()),
        Ok(other) => panic!("{other:?}"),
        Err(_) => None,
    }
}

const ORIGIN: &str = "https://portal.example.org";

fn connect_with_stdin(harness: &mut Harness, input: &[u8]) -> super::super::support::Outcome {
    harness.stdin = Cursor::new(input.to_vec());
    harness.run(&["portal", "connect", "--origin", ORIGIN, "--stdin"])
}

/// `connect` reads the token from stdin, stores it, then writes the
/// settings at revision 1; whitespace around the token is ignored.
#[test]
fn connect_stores_the_token_and_points_the_pull() {
    let mut harness = harness();
    let input = format!(" {}\n", token(7).expose_str());
    let outcome = connect_with_stdin(&mut harness, input.as_bytes());
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "the payment pull reads {ORIGIN} with the token stored as portal/pull-token (settings revision 1); the daemon asks within five minutes, while the Mac is on no foreign network\n\
             rehearsal off: payments of Stripe's test mode are not granted, and a portal in test mode is waited on\n"
        )
    );
    assert_eq!(
        stored_token(&harness),
        Some(token(7).expose_str().to_owned())
    );
    let written = settings(&harness).unwrap();
    assert_eq!(written.revision(), 1);
    assert_eq!(written.origin().unwrap().to_string(), ORIGIN);
    assert!(!written.rehearsal());
    let path = harness.support_dir().join(PAYMENT_PULL_FILE);
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions())
            & 0o777,
        0o600
    );
    // The token is in no file of the support directory.
    for entry in fs::read_dir(harness.support_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = fs::read(&path).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(token(7).expose_str()),
                "{}",
                path.display()
            );
        }
    }
}

/// A token that is not one is refused before anything is written, and is
/// never echoed.
#[test]
fn a_token_that_is_not_one_writes_nothing() {
    let short = "ab".repeat(31);
    let upper = "AB".repeat(32);
    let long = format!("{}\n\n\n", "ab".repeat(32));
    for bad in [short.as_str(), upper.as_str(), long.as_str(), ""] {
        let mut harness = harness();
        let outcome = connect_with_stdin(&mut harness, bad.as_bytes());
        assert_eq!(outcome.code, 1);
        assert!(
            outcome.stderr.contains(
                "the pull token is not the 64 lower-case hexadecimal characters `mooring-portal pull-token` printed"
            ),
            "{}",
            outcome.stderr
        );
        if !bad.trim().is_empty() {
            assert!(!outcome.stderr.contains(bad.trim()));
        }
        assert_eq!(stored_token(&harness), None);
        assert_eq!(settings(&harness), None);
    }
    // An origin that is not one is clap's usage error, before anything runs.
    for origin in [
        "http://portal.example.org",
        "https://192.0.2.1",
        "https://p.example/x",
    ] {
        let refused = <crate::cli::Cli as clap::Parser>::try_parse_from([
            "mooringctl",
            "portal",
            "connect",
            "--origin",
            origin,
        ])
        .unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("the portal's address must be https://"),
            "{refused}"
        );
    }
}

/// At the terminal the token is asked once, without echo.
#[test]
fn connect_asks_the_terminal_once() {
    let mut harness = harness();
    harness
        .console
        .passwords
        .push_back(token(9).expose_str().as_bytes().to_vec());
    let outcome = harness.run(&["portal", "connect", "--origin", ORIGIN]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        harness.console.asked,
        ["Pull token (from `mooring-portal pull-token`): "]
    );
    assert_eq!(
        stored_token(&harness),
        Some(token(9).expose_str().to_owned())
    );
}

/// A connect raises the revision above the ledger's stop and keeps the
/// rehearsal as it was; `rehearsal` changes the mode alone.
#[test]
fn the_revision_rises_above_the_stop_and_the_rehearsal_is_kept() {
    let mut harness = harness();
    let stopped = PaymentLedger::new().with_stop(Some(Stop {
        reason: StopReason::Conflict,
        at: UnixTime::from_secs(NOW),
        settings_revision: 9,
    }));
    write_payment_ledger(&harness.support_dir(), &stopped.encode().unwrap()).unwrap();
    let outcome = harness.run(&["portal", "rehearsal", "on"]);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome
            .stderr
            .contains("the payment pull is not connected: `mooringctl portal connect` first"),
        "{}",
        outcome.stderr
    );
    connect_with_stdin(&mut harness, token(1).expose_str().as_bytes());
    assert_eq!(settings(&harness).unwrap().revision(), 10);
    let outcome = harness.run(&["portal", "rehearsal", "on"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.starts_with("rehearsal on: "),
        "{}",
        outcome.stdout
    );
    let on = settings(&harness).unwrap();
    assert_eq!((on.revision(), on.rehearsal()), (11, true));
    let again = harness.run(&["portal", "rehearsal", "on"]);
    assert!(
        again.stdout.starts_with("unchanged; rehearsal on: "),
        "{}",
        again.stdout
    );
    assert_eq!(settings(&harness).unwrap().revision(), 11);
    connect_with_stdin(&mut harness, token(2).expose_str().as_bytes());
    let reconnected = settings(&harness).unwrap();
    assert_eq!(
        (reconnected.revision(), reconnected.rehearsal()),
        (12, true)
    );
    let off = harness.run(&["portal", "rehearsal", "off"]);
    assert!(off.stdout.starts_with("rehearsal off: "), "{}", off.stdout);
    assert_eq!(settings(&harness).unwrap().revision(), 13);
    // The ledger is never written by the commands.
    assert_eq!(ledger_on_disk(&harness), Some(stopped));
}

/// `disconnect` keeps the settings without an origin, at a new revision,
/// then deletes the token; the ledger stays. Twice is fine.
#[test]
fn disconnect_stops_the_pull_and_keeps_the_ledger() {
    let mut harness = harness();
    connect_with_stdin(&mut harness, token(1).expose_str().as_bytes());
    let ledger = PaymentLedger::new();
    write_payment_ledger(&harness.support_dir(), &ledger.encode().unwrap()).unwrap();
    for _ in 0..2 {
        let outcome = harness.run(&["portal", "disconnect"]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(
            outcome.stdout,
            "the payment pull is disconnected and its token deleted; the payment ledger stays, and what it granted still counts\n"
        );
    }
    let after = settings(&harness).unwrap();
    assert_eq!((after.revision(), after.origin()), (2, None));
    assert_eq!(stored_token(&harness), None);
    assert_eq!(ledger_on_disk(&harness), Some(ledger));
}

/// A ledger that cannot be read refuses `connect` before the token is
/// asked for, and `payments` too: it is never read as no ledger.
#[test]
fn a_ledger_that_cannot_be_read_is_reported() {
    let mut harness = harness();
    let dir = harness.support_dir().join(PAYMENTS_DIRECTORY);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(PAYMENT_LEDGER_FILE), b"not json").unwrap();
    let outcome = connect_with_stdin(&mut harness, token(1).expose_str().as_bytes());
    assert_eq!(outcome.code, 1);
    assert!(
        outcome.stderr.contains("the payment pull's files failed"),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome
            .stderr
            .contains("payments/ledger.json is not a payment ledger this build reads"),
        "{}",
        outcome.stderr
    );
    assert_eq!(stored_token(&harness), None);
    assert_eq!(settings(&harness), None);
    assert_eq!(harness.run(&["portal", "payments"]).code, 1);
}

/// `payments` prints the settings, the ledger and every order, or the
/// files as one JSON line.
#[test]
fn payments_lists_the_pull_and_every_order() {
    let mut harness = harness();
    let empty = harness.run(&["portal", "payments"]);
    assert_eq!(
        empty.stdout,
        "payment pull: not set up (`mooringctl portal connect`)\npayment ledger: none yet; nothing has been pulled\n"
    );
    connect_with_stdin(&mut harness, token(1).expose_str().as_bytes());
    let mut puller = Puller::open(&harness.support_dir());
    let mut refund = grant(2, "aaaaaaaaaaaaaaaaaaaa", FIRST);
    refund["kind"] = serde_json::json!("refund");
    refund["amount_refunded"] = serde_json::json!(300);
    refund["refunded_in_full"] = serde_json::json!(false);
    harness.portal.ok(&page(
        true,
        0,
        vec![
            grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST),
            refund,
            grant(3, "bbbbbbbbbbbbbbbbbbbb", "nobodyhere"),
        ],
        false,
    ));
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
            UnixTime::from_secs(NOW),
            crate::payments::pull::Gate {
                room: Some(std::time::Duration::from_secs(10)),
                network_clear: &mut clear,
            },
        )
    });
    let listed = harness.run(&["portal", "payments"]);
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    assert_eq!(
        listed.stdout,
        "payment pull: https://portal.example.org (settings revision 1)\n\
         \x20 rehearsal: off\n\
         payment ledger: cursor 3; last pull 2026-10-13 19:20:00 UTC\n\
         orders: 2 (1 held, 1 refunded, 0 disputed)\n\
         \x20 aaaaaaaaaaaaaaaaaaaa user fxuseraaab plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
         \x20   grant, entry 1, applied 2026-10-13 19:20:00 UTC: service from 2026-10-13 19:20:00 UTC until 2026-11-12 19:20:00 UTC\n\
         \x20   refund, entry 2: 300 gbp so far; changes nothing\n\
         \x20 bbbbbbbbbbbbbbbbbbbb user nobodyhere plan month-100 (month, 30 days, 100000000000 bytes, 800 gbp)\n\
         \x20   grant, entry 3, applied 2026-10-13 19:20:00 UTC: held, not granted (unknown_user): settle it at Stripe\n"
    );
    let json = harness.run(&["portal", "payments", "--json"]);
    assert_eq!(json.code, 0);
    assert_eq!(json.stdout.lines().count(), 1);
    let value: Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(value["settings"]["revision"], 1);
    assert_eq!(value["settings"]["origin"], ORIGIN);
    assert_eq!(value["ledger"]["cursor"], 3);
    assert_eq!(
        value["ledger"]["orders"][1]["grant"]["outcome"]["held"]["reason"],
        "unknown_user"
    );
    assert!(!json.stdout.contains(token(1).expose_str()));
}

/// The portal snapshot shows a paid user the end of their paid time and
/// their paid quota; a ledger that cannot be read refuses the snapshot.
#[test]
fn the_portal_snapshot_carries_the_paid_policy() {
    let mut harness = harness();
    harness.portal_agreement = PortalAgreement::since(Some(AgreementVersion::CURRENT));
    connect_with_stdin(&mut harness, token(1).expose_str().as_bytes());
    let users = mooring_fixtures::two_nodes_three_users()
        .unwrap()
        .deployment
        .users()
        .clone();
    let page = mooring_daemon_core::payments::FeedPage::decode(
        &page(
            true,
            0,
            vec![grant(1, "aaaaaaaaaaaaaaaaaaaa", FIRST)],
            false,
        ),
        0,
    )
    .unwrap();
    let ledger = PaymentLedger::new()
        .apply(&page, &users, UnixTime::from_secs(NOW), false)
        .unwrap()
        .ledger;
    write_payment_ledger(&harness.support_dir(), &ledger.encode().unwrap()).unwrap();
    let out = harness.home.path().join("snapshot.json");
    let outcome = harness.run(&[
        "portal",
        "export",
        "--user",
        FIRST,
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let document: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(document["users"][0]["expires_at"], NOW + 30 * 86_400);
    assert_eq!(
        document["users"][0]["quota"]["cycle_served_bytes"],
        100_000_000_000_u64
    );
    fs::remove_file(&out).unwrap();
    fs::write(
        harness
            .support_dir()
            .join(PAYMENTS_DIRECTORY)
            .join(PAYMENT_LEDGER_FILE),
        b"[]",
    )
    .unwrap();
    let refused = harness.run(&[
        "portal",
        "export",
        "--user",
        FIRST,
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(refused.code, 1);
    assert!(
        refused.stderr.contains("the payment pull's files failed"),
        "{}",
        refused.stderr
    );
    assert!(!out.exists());
}

/// The token from stdin: bytes that are not UTF-8 are refused unechoed, an
/// interrupted read is read again, and a read that fails is named.
#[test]
fn the_token_is_read_from_stdin_strictly() {
    use std::io::{self, Read};

    use crate::payments::command::stdin_token;

    struct Interrupted {
        once: bool,
        rest: Cursor<Vec<u8>>,
    }
    impl Read for Interrupted {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.once {
                self.once = false;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.rest.read(buffer)
        }
    }
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    let mut interrupted = Interrupted {
        once: true,
        rest: Cursor::new(token(3).expose_str().as_bytes().to_vec()),
    };
    assert_eq!(
        stdin_token(&mut interrupted).unwrap().expose_str(),
        token(3).expose_str()
    );
    assert!(matches!(
        stdin_token(&mut Failing),
        Err(crate::error::LocalError::Stdin(_))
    ));
    let mut harness = harness();
    let mut bytes = token(3).expose_str().as_bytes().to_vec();
    bytes[10] = 0xff;
    let outcome = connect_with_stdin(&mut harness, &bytes);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome
            .stderr
            .contains("the pull token is not the 64 lower-case hexadecimal characters"),
        "{}",
        outcome.stderr
    );
    assert_eq!(stored_token(&harness), None);
}

/// Settings that cannot be read or written are named, never read as none:
/// a directory where the file belongs, a link to nothing, a file of
/// another shape.
#[test]
fn settings_that_cannot_be_read_or_written_are_named() {
    let mut harness = harness();
    let path = harness.support_dir().join(PAYMENT_PULL_FILE);
    fs::create_dir(&path).unwrap();
    let listed = harness.run(&["portal", "payments"]);
    assert_eq!(listed.code, 1);
    assert!(
        listed
            .stderr
            .contains("payment-pull.json cannot be read or written"),
        "{}",
        listed.stderr
    );
    fs::remove_dir(&path).unwrap();
    std::os::unix::fs::symlink(harness.support_dir().join("nothing"), &path).unwrap();
    let connected = connect_with_stdin(&mut harness, token(1).expose_str().as_bytes());
    assert_eq!(connected.code, 1);
    assert!(
        connected
            .stderr
            .contains("payment-pull.json cannot be read or written"),
        "{}",
        connected.stderr
    );
    // Refused before the token is asked for or stored.
    assert_eq!(stored_token(&harness), None);
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"{\"version\": 1}").unwrap();
    for args in [
        &["portal", "rehearsal", "on"][..],
        &["portal", "disconnect"][..],
        &["portal", "payments"][..],
    ] {
        let refused = harness.run(args);
        assert_eq!(refused.code, 1, "{args:?}");
        assert!(
            refused
                .stderr
                .contains("payment-pull.json is not the payment pull's settings"),
            "{args:?}: {}",
            refused.stderr
        );
    }
}

/// A token the keychain will not delete is named, after the settings
/// stopped using it.
#[test]
fn a_token_the_keychain_keeps_is_named() {
    let mut harness = harness();
    connect_with_stdin(&mut harness, token(1).expose_str().as_bytes());
    harness.keychain.lock().unwrap().delete = Some(-25_293);
    let outcome = harness.run(&["portal", "disconnect"]);
    assert_eq!(outcome.code, 1);
    assert!(
        outcome.stderr.contains("the keychain failed"),
        "{}",
        outcome.stderr
    );
    assert_eq!(settings(&harness).unwrap().origin(), None);
}

/// A closed output is named, not taken as written.
#[test]
fn a_closed_output_is_named() {
    let mut harness = harness();
    let mut err = Vec::new();
    for args in [
        &["portal", "payments"][..],
        &["portal", "payments", "--json"][..],
        &["portal", "disconnect"][..],
    ] {
        err.clear();
        let code = harness.run_to(args, &mut super::super::support::Refusing, &mut err);
        assert_eq!(code, 1, "{args:?}");
    }
    harness.stdin = Cursor::new(token(1).expose_str().as_bytes().to_vec());
    let code = harness.run_to(
        &["portal", "connect", "--origin", ORIGIN, "--stdin"],
        &mut super::super::support::Refusing,
        &mut err,
    );
    assert_eq!(code, 1);
    let code = harness.run_to(
        &["portal", "rehearsal", "on"],
        &mut super::super::support::Refusing,
        &mut err,
    );
    assert_eq!(code, 1);
}
