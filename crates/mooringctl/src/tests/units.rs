// SPDX-License-Identifier: GPL-3.0-or-later

//! The small parts: the command line, the keychain's status mapping, the
//! cookie jar, exit codes, the support directory, the terminal's line
//! reading and yes/no answers, and the password on stdin.

use std::ffi::OsString;
use std::io::Cursor;
use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use mooring_daemon_core::router::RouterUnavailableReason;
use mooring_model::secret::{MAX_ROUTER_ADMIN_PASSWORD_BYTES, SecretMaterial, SecretRef};
use mooring_store::{SecretOp, SecretStoreError};

use crate::cli::Cli;
use crate::error::{CommandError, EXIT_LOCAL, EXIT_USAGE, LocalError, reason_exit_code};
use crate::keychain::{
    ERR_SEC_DUPLICATE_ITEM, ERR_SEC_ITEM_NOT_FOUND, LABEL, SERVICE, decode_item, status_error,
};
use crate::paths::support_dir;
use crate::prompt::{
    Answer, MAX_ANSWER_BYTES, MAX_STDIN_BYTES, answer_of, read_line, stdin_password,
};
use crate::router::cookies::{CookieJar, MAX_COOKIE_BYTES, MAX_COOKIES, parse_set_cookie};
use crate::router::error::{HttpFault, Missing, RouterError};

#[test]
fn the_cli_definition_is_valid() {
    Cli::command().debug_assert();
}

#[test]
fn set_password_has_no_argv_secret() {
    let command = Cli::command();
    let router = command.find_subcommand("router").unwrap();
    let set_password = router.find_subcommand("set-password").unwrap();
    let arguments: Vec<&str> = set_password
        .get_arguments()
        .map(|argument| argument.get_id().as_str())
        .filter(|id| *id != "help")
        .collect();
    assert_eq!(arguments, ["stdin"]);
    assert!(set_password.get_positionals().next().is_none());
    for args in [
        &["mooringctl", "router", "set-password", "--password", "x"][..],
        &["mooringctl", "router", "set-password", "x"],
        &["mooringctl", "router", "set-password", "--stdin=x"],
    ] {
        assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
    }
}

#[test]
fn usage_errors_are_claps_exit_code_2() {
    for args in [
        &["mooringctl", "router", "status"][..],
        &["mooringctl", "router", "status", "--interface", "EN9"],
        &["mooringctl", "router", "status", "--interface", "en09"],
        &["mooringctl", "router", "capture", "--interface", "en9"],
        &["mooringctl", "router", "probe"],
    ] {
        let error = Cli::try_parse_from(args).unwrap_err();
        assert_eq!(error.exit_code(), i32::from(EXIT_USAGE), "{args:?}");
    }
}

#[test]
fn exit_codes_follow_the_reasons() {
    for (reason, code) in [
        (RouterUnavailableReason::NotConfigured, 3),
        (RouterUnavailableReason::Unreachable, 4),
        (RouterUnavailableReason::AuthFailed, 5),
        (RouterUnavailableReason::IdentityMismatch, 6),
        (RouterUnavailableReason::Unsupported, 7),
        (RouterUnavailableReason::Malformed, 8),
    ] {
        assert_eq!(reason_exit_code(reason), code, "{reason:?}");
    }
    let not_configured = CommandError::Router(RouterError::NotConfigured {
        missing: Missing::Pin,
    });
    assert_eq!(not_configured.exit_code(), 3);
    assert_eq!(
        RouterError::http(HttpFault::TooLarge).reason(),
        RouterUnavailableReason::Malformed
    );
    assert_eq!(
        CommandError::Local(LocalError::Home).exit_code(),
        EXIT_LOCAL
    );
    assert_eq!(EXIT_LOCAL, 1);
}

#[test]
fn keychain_statuses_map_to_store_errors() {
    let reference = SecretRef::RouterAdmin;
    assert_eq!(ERR_SEC_ITEM_NOT_FOUND, -25_300);
    // A put that meets an existing item updates it (found by service and
    // account, whatever its label) on exactly this status.
    assert_eq!(ERR_SEC_DUPLICATE_ITEM, -25_299);
    for op in [SecretOp::Get, SecretOp::Delete] {
        assert_eq!(
            status_error(op, &reference, ERR_SEC_ITEM_NOT_FOUND),
            SecretStoreError::SecretMissing {
                secret_ref: SecretRef::RouterAdmin
            }
        );
    }
    for (op, status) in [
        (SecretOp::Put, ERR_SEC_ITEM_NOT_FOUND),
        (SecretOp::Get, -25_293),
        (SecretOp::Put, -25_299),
        (SecretOp::Delete, -128),
    ] {
        assert_eq!(
            status_error(op, &reference, status),
            SecretStoreError::Keychain { op, status }
        );
    }
    assert_eq!(SERVICE, "com.bill.mooring.dev");
    assert_eq!(LABEL, "Mooring (development)");
}

#[test]
fn invalid_items_are_item_invalid() {
    let reference = SecretRef::RouterAdmin;
    let invalid = SecretStoreError::ItemInvalid {
        secret_ref: SecretRef::RouterAdmin,
    };
    for bytes in [&b""[..], b"\xff\xfe", b"line\n", b"tab\there"] {
        assert_eq!(
            decode_item(&reference, bytes),
            Err(invalid.clone()),
            "{bytes:?}"
        );
    }
    match decode_item(&reference, b"p@ss w&rd=+%") {
        Ok(SecretMaterial::RouterAdminPassword(password)) => {
            assert_eq!(password.expose_str(), "p@ss w&rd=+%");
        }
        other => panic!("{other:?}"),
    }
    let error = decode_item(&reference, b"SECRET\n").unwrap_err();
    assert!(!error.to_string().contains("SECRET"));
    assert!(!format!("{error:?}").contains("SECRET"));
}

#[test]
fn cookies_parse_replace_and_bound() {
    let mut jar = CookieJar::default();
    for header in [
        &b"sid=one; Path=/; HttpOnly"[..],
        b" auth = \"two\" ;Secure",
        b"empty=",
        b"sid=three",
    ] {
        jar.store(parse_set_cookie(header).unwrap()).unwrap();
    }
    let mut header = String::new();
    jar.write_header_value(&mut header);
    assert_eq!(header, "sid=three; auth=\"two\"; empty=");
    assert_eq!(jar.names(), ["sid", "auth", "empty"]);
    assert_eq!(format!("{jar:?}"), "[\"sid\", \"auth\", \"empty\"]");
    for bad in [
        &b"novalue"[..],
        b"=value",
        b"bad name=v",
        b"n=a b",
        b"n=a,b",
        b"n=a\\b",
        b"n=\"a",
    ] {
        assert_eq!(
            parse_set_cookie(bad).map(|_| ()),
            Err(HttpFault::Cookie),
            "{bad:?}"
        );
    }
    let longest = format!("n={}", "v".repeat(MAX_COOKIE_BYTES - 1));
    assert!(parse_set_cookie(longest.as_bytes()).is_ok());
    let too_long = format!("n={}", "v".repeat(MAX_COOKIE_BYTES));
    assert_eq!(
        parse_set_cookie(too_long.as_bytes()).map(|_| ()),
        Err(HttpFault::Cookie)
    );
    let mut full = CookieJar::default();
    for index in 0..MAX_COOKIES {
        full.store(parse_set_cookie(format!("c{index}=v").as_bytes()).unwrap())
            .unwrap();
    }
    assert_eq!(
        full.store(parse_set_cookie(b"one=more").unwrap()),
        Err(HttpFault::TooManyCookies)
    );
    // Replacing one of the full jar's cookies is still allowed.
    full.store(parse_set_cookie(b"c0=new").unwrap()).unwrap();
    assert_eq!(MAX_COOKIES, 16);
}

#[test]
fn home_must_be_absolute() {
    for home in [None, Some(""), Some("relative"), Some("./home")] {
        assert!(matches!(
            support_dir(home.map(OsString::from)),
            Err(LocalError::Home)
        ));
    }
    assert_eq!(
        support_dir(Some(OsString::from("/Users/operator"))).unwrap(),
        PathBuf::from("/Users/operator/Library/Application Support/Mooring")
    );
}

#[test]
fn stdin_reading_is_bounded() {
    assert_eq!(MAX_STDIN_BYTES, 130);
    let mut exact = Cursor::new(format!("{}\r\n", "a".repeat(128)).into_bytes());
    assert!(matches!(
        stdin_password(&mut exact),
        Err(LocalError::Password(_))
    ));
    let mut ok = Cursor::new(b"pw\n".to_vec());
    assert_eq!(stdin_password(&mut ok).unwrap().expose_str(), "pw");
}

/// Reads every line `read_line` gives from `input` with `limit`, as text
/// (`None` for an overlong one), until the input is spent.
fn lines(input: &[u8], limit: usize) -> Vec<Option<String>> {
    let mut source = Cursor::new(input.to_vec());
    let mut read = Vec::new();
    while source.position() < input.len() as u64 {
        let line = read_line(&mut source, limit).unwrap();
        read.push(line.map(|line| String::from_utf8(line.to_vec()).unwrap()));
    }
    read
}

#[test]
fn terminal_lines_are_bounded() {
    let some = |text: &str| Some(text.to_owned());
    // Exactly the limit is a line; one byte more is refused, and the rest
    // of that line is consumed, so the next line starts clean.
    assert_eq!(
        lines(b"abcd\nabcde\nnext\n", 4),
        [some("abcd"), None, some("next")]
    );
    // The end of the input ends a line; an empty line is empty.
    assert_eq!(lines(b"\nabc", 4), [some(""), some("abc")]);
    assert_eq!(
        read_line(&mut Cursor::new(Vec::new()), 4)
            .unwrap()
            .as_deref(),
        Some(&Vec::new())
    );
    // A carriage return is kept: the password's own rule refuses it.
    assert_eq!(lines(b"ab\r\n", 4), [some("ab\r")]);
    // The password prompt's limit is the password's.
    let longest = "p".repeat(MAX_ROUTER_ADMIN_PASSWORD_BYTES);
    let typed = format!("{longest}\n{longest}q\n");
    assert_eq!(
        lines(typed.as_bytes(), MAX_ROUTER_ADMIN_PASSWORD_BYTES),
        [Some(longest), None]
    );
    assert_eq!(MAX_ANSWER_BYTES, 64);
}

#[test]
fn only_an_explicit_yes_confirms() {
    for yes in ["y", "Y", "yes", "YES", "Yes", " yes ", "\ty\r"] {
        assert_eq!(answer_of(Some(yes.as_bytes())), Answer::Yes, "{yes:?}");
    }
    for no in [
        "",
        " ",
        "n",
        "no",
        "yess",
        "ye",
        "y es",
        "yes please",
        "oui",
    ] {
        assert_eq!(answer_of(Some(no.as_bytes())), Answer::No, "{no:?}");
    }
    // An overlong answer is no answer.
    assert_eq!(answer_of(None), Answer::No);
}
