// SPDX-License-Identifier: GPL-3.0-or-later

//! `router status` refuses before it touches the network when what it
//! reads first cannot be read (design §15.6, step 1): a pin file that is
//! not a pin, and a keychain that refuses the password. Neither is taken
//! as "not set up".

use std::fs;

use mooring_store::ROUTER_PIN_FILE;

use super::stub::Stub;
use super::support::{Harness, PINNED, Refusals};
use crate::error::EXIT_LOCAL;

#[test]
fn a_pin_file_that_is_not_a_pin_is_refused_before_any_request() {
    let stub = Stub::start(vec![]);
    let mut harness = Harness::configured(stub.port());
    fs::write(
        harness.support_dir().join(ROUTER_PIN_FILE),
        b"{\"version\": 9}\n",
    )
    .unwrap();
    let outcome = harness.run(&["router", "status", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the router identity file failed\n"),
        "{}",
        outcome.stderr
    );
    assert!(stub.finish().is_empty(), "the M7 was not asked");
}

#[test]
fn a_keychain_that_refuses_the_password_is_refused_before_any_request() {
    let stub = Stub::start(vec![]);
    let mut harness = Harness::new(stub.port());
    harness.pin(PINNED);
    *harness.keychain.lock().unwrap() = Refusals {
        get: Some(-25_293),
        put: None,
        delete: None,
    };
    let outcome = harness.run(&["router", "status", "--interface", "lo0"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: the keychain failed\n  caused by: keychain get failed with OSStatus -25293\n"
    );
    assert!(stub.finish().is_empty(), "the M7 was not asked");
}
