// SPDX-License-Identifier: GPL-3.0-or-later

//! `router set-password`: from stdin (one trailing newline removed) or
//! typed twice at the terminal; never echoed, never an argument.

use std::io::Cursor;

use mooring_model::secret::{SecretMaterial, SecretRef};
use mooring_store::SecretStore;

use super::support::{Harness, PASSWORD};

fn stored(harness: &Harness) -> Option<String> {
    match harness.secrets.get(&SecretRef::RouterAdmin) {
        Ok(SecretMaterial::RouterAdminPassword(password)) => Some(password.expose_str().to_owned()),
        Ok(other) => panic!("{other:?}"),
        Err(_) => None,
    }
}

fn from_stdin(input: &[u8]) -> (Harness, super::support::Outcome) {
    let mut harness = Harness::new(9);
    harness.stdin = Cursor::new(input.to_vec());
    let outcome = harness.run(&["router", "set-password", "--stdin"]);
    (harness, outcome)
}

#[test]
fn stdin_strips_exactly_one_newline() {
    for (input, expected) in [
        (format!("{PASSWORD}\n"), PASSWORD.to_owned()),
        (PASSWORD.to_owned(), PASSWORD.to_owned()),
        (format!("{}\n", "~".repeat(128)), "~".repeat(128)),
    ] {
        let (harness, outcome) = from_stdin(input.as_bytes());
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(
            outcome.stdout,
            "the M7 admin password is stored as router/admin\n"
        );
        assert_eq!(stored(&harness), Some(expected));
    }
    for input in [
        format!("{PASSWORD}\n\n"),
        format!("{PASSWORD}\r\n"),
        String::new(),
        "\n".to_owned(),
        "a".repeat(129),
        format!("{}\n", "a".repeat(129)),
        "a".repeat(131),
        "a".repeat(4096),
        "caf\u{e9}\n".to_owned(),
    ] {
        let (harness, outcome) = from_stdin(input.as_bytes());
        assert_eq!(outcome.code, 1, "{input:?}");
        assert_eq!(
            outcome.stderr,
            "mooringctl: the password is not 1 to 128 bytes of printable ASCII\n  caused by: invalid RouterAdminPassword secret material\n"
        );
        assert_eq!(outcome.stdout, "");
        assert_eq!(stored(&harness), None);
    }
    let (_, outcome) = from_stdin(&[0xff, b'\n']);
    assert_eq!(outcome.code, 1);
}

#[test]
fn tty_entries_must_match() {
    let mut harness = Harness::new(9);
    harness
        .console
        .passwords
        .extend([PASSWORD.as_bytes().to_vec(), b"something else".to_vec()]);
    let outcome = harness.run(&["router", "set-password"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.stderr, "mooringctl: the two passwords differ\n");
    assert_eq!(stored(&harness), None);
    harness
        .console
        .passwords
        .extend([PASSWORD.as_bytes().to_vec(), PASSWORD.as_bytes().to_vec()]);
    let outcome = harness.run(&["router", "set-password"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(stored(&harness), Some(PASSWORD.to_owned()));
    assert_eq!(
        harness.console.asked,
        [
            "M7 admin password: ",
            "Again: ",
            "M7 admin password: ",
            "Again: "
        ]
    );
    assert!(!outcome.stdout.contains(PASSWORD));
    // Without a terminal the password must come from stdin.
    let outcome = harness.run(&["router", "set-password"]);
    assert_eq!(outcome.code, 1);
    assert_eq!(
        outcome.stderr,
        "mooringctl: no terminal to ask for the password (use --stdin)\n"
    );
}
