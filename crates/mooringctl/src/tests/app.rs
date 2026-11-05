// SPDX-License-Identifier: GPL-3.0-or-later

//! What every command shares (design §14): output that cannot be written
//! is the command's failure, after whatever it did before; an error report
//! that cannot be written still leaves the exit code; the system clock;
//! and the hidden `ssh-relay`'s dispatch.

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

use mooring_model::secret::SecretRef;
use mooring_store::{ROUTER_PIN_FILE, SecretStore};

use super::support::{Harness, PINNED, Refusals, Refusing};
use super::user::{fixture, harness_with, store};
use crate::app::system_clock;
use crate::error::EXIT_LOCAL;

/// What a command wrote to its error stream.
fn report(err: Vec<u8>) -> String {
    String::from_utf8(err).unwrap()
}

/// The system clock is the time now, in whole seconds since the epoch.
#[test]
fn the_system_clock_reads_whole_seconds_since_the_epoch() {
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let read = system_clock().unwrap().as_secs();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((before..=after).contains(&read), "{before} {read} {after}");
}

/// Output that cannot be written (a closed pipe) is a local failure,
/// reported on the error stream; what the command did before it stands:
/// the password is stored, the exit enabled.
#[test]
fn output_that_cannot_be_written_fails_the_command_after_its_work() {
    let mut harness = Harness::new(9);
    harness.stdin = Cursor::new(b"p@ss w&rd\n".to_vec());
    let mut err = Vec::new();
    let code = harness.run_to(
        &["router", "set-password", "--stdin"],
        &mut Refusing,
        &mut err,
    );
    assert_eq!(code, EXIT_LOCAL);
    assert_eq!(
        report(err),
        "mooringctl: writing the output failed\n  caused by: broken pipe\n"
    );
    assert!(harness.secrets.get(&SecretRef::RouterAdmin).is_ok());

    let mut harness = harness_with(fixture(|_| {}));
    let mut err = Vec::new();
    let code = harness.run_to(&["exit", "enable"], &mut Refusing, &mut err);
    assert_eq!(code, EXIT_LOCAL);
    assert!(report(err).starts_with("mooringctl: writing the output failed\n"));
    assert!(store(&harness).load().unwrap().runtime.exit_enabled);

    let mut err = Vec::new();
    let code = harness.run_to(&["router", "history"], &mut Refusing, &mut err);
    assert_eq!(code, EXIT_LOCAL);
    assert!(report(err).starts_with("mooringctl: writing the output failed\n"));
}

/// `router status --json` prints its reading even when the M7 could not be
/// read; when that reading cannot be written either, both failures are
/// reported, and the exit code is the router's.
#[test]
fn a_reading_that_cannot_be_written_is_reported_with_the_router_s_failure() {
    let mut harness = Harness::new(9);
    let mut err = Vec::new();
    let code = harness.run_to(
        &["router", "status", "--interface", "lo0", "--json"],
        &mut Refusing,
        &mut err,
    );
    assert_eq!(code, 3, "not configured");
    let report = report(err);
    assert!(
        report.starts_with("mooringctl: writing the output failed\n  caused by: broken pipe\nmooringctl: the router adapter is not set up: "),
        "{report}"
    );
}

/// An error report that cannot be written leaves the exit code.
#[test]
fn a_report_that_cannot_be_written_leaves_the_exit_code() {
    let mut harness = Harness::new(9);
    let mut out = Vec::new();
    let code = harness.run_to(
        &["router", "status", "--interface", "lo0"],
        &mut out,
        &mut Refusing,
    );
    assert_eq!(code, 3);
    assert!(out.is_empty());
}

/// `ssh-relay` connects to its socket before it touches standard input or
/// output: a socket that is not there is the relay's failure.
#[test]
fn ssh_relay_without_its_socket_fails_before_relaying() {
    let mut harness = Harness::new(9);
    let socket = harness.home.path().join("relay-1-0.sock");
    let outcome = harness.run(&["ssh-relay", socket.to_str().unwrap()]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        "mooringctl: the node could not be reached or refused\n  caused by: relaying the connection to the node failed\n  caused by: No such file or directory (os error 2)\n"
    );
}

/// `router pin` refuses a pin file it cannot read, and reports a pin it
/// cannot write; neither is taken as no pin.
#[test]
fn a_pin_file_that_cannot_be_read_or_written_is_an_error() {
    let mut harness = Harness::new(9);
    harness.pin(PINNED);
    let pin = harness.support_dir().join(ROUTER_PIN_FILE);
    fs::write(&pin, b"{\"version\": 9}\n").unwrap();
    let outcome = harness.run(&["router", "pin", "--interface", "lo0", "--yes"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the router identity file failed\n"),
        "{}",
        outcome.stderr
    );
    assert_eq!(fs::read(&pin).unwrap(), b"{\"version\": 9}\n");

    let mut harness = Harness::new(9);
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    fs::set_permissions(&support, fs::Permissions::from_mode(0o500)).unwrap();
    let outcome = harness.run(&["router", "pin", "--interface", "lo0", "--yes"]);
    fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the router identity file failed\n"),
        "{}",
        outcome.stderr
    );
    assert!(!support.join(ROUTER_PIN_FILE).exists());
}

/// A keychain that refuses the password is the command's failure, naming
/// the status; nothing is stored.
#[test]
fn a_password_the_keychain_refuses_is_not_stored() {
    let mut harness = Harness::new(9);
    harness.stdin = Cursor::new(b"p@ss w&rd\n".to_vec());
    *harness.keychain.lock().unwrap() = Refusals {
        get: None,
        put: Some(-25_293),
    };
    let outcome = harness.run(&["router", "set-password", "--stdin"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the keychain failed\n  caused by: keychain put failed with OSStatus -25293\n"
    );
    assert!(harness.secrets.is_empty());
}
