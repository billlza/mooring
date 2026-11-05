// SPDX-License-Identifier: GPL-3.0-or-later

//! `status` against a daemon that answers with something else than a
//! status, a control socket whose path cannot be used, and output that
//! cannot be written (design §15.1). The daemon's answers otherwise are
//! the daemon tests'.

use std::fs;

use mooring_daemon_core::control::{DaemonReply, MAX_REPLY_LINE_BYTES, encode_line};

use super::daemon::{available_line, fake_daemon, harness};
use super::support::Refusing;
use crate::daemon::RunPaths;
use crate::error::EXIT_LOCAL;

/// A daemon that answers `status` with a retry's answer is refused.
#[test]
fn a_reply_that_is_not_a_status_is_refused() {
    let mut harness = harness();
    let queued = encode_line(&DaemonReply::RetryQueued, MAX_REPLY_LINE_BYTES).unwrap();
    let daemon = fake_daemon(&harness, vec![queued]);
    let outcome = harness.run(&["status", "--json"]);
    daemon.result();
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        "mooringctl: the daemon answered with a reply to another request\n"
    );
}

/// A control socket whose path is longer than a socket's address holds,
/// or lies under a file, cannot be talked to: that is the error, naming
/// the path, not a daemon that is not running.
#[test]
fn a_control_socket_path_that_cannot_be_used_is_the_error() {
    let mut harness = super::support::Harness::new(9);
    harness.home = tempfile::Builder::new()
        .prefix(&"h".repeat(60))
        .tempdir()
        .unwrap();
    let socket = RunPaths::under(&harness.support_dir()).socket;
    let outcome = harness.run(&["status"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome.stderr.starts_with(&format!(
            "mooringctl: talking to the daemon on {} failed\n",
            socket.display()
        )),
        "{}",
        outcome.stderr
    );

    let mut harness = super::daemon::harness();
    let support = harness.support_dir();
    fs::create_dir_all(&support).unwrap();
    fs::write(RunPaths::under(&support).dir, b"").unwrap();
    let socket = RunPaths::under(&support).socket;
    let outcome = harness.run(&["status"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: talking to the daemon on {} failed\n  caused by: Not a directory (os error 20)\n",
            socket.display()
        )
    );
}

/// A status that cannot be written is the command's failure.
#[test]
fn a_status_that_cannot_be_written_is_the_error() {
    let mut harness = harness();
    let daemon = fake_daemon(&harness, vec![available_line(super::support::NOW)]);
    let mut err = Vec::new();
    let code = harness.run_to(&["status", "--json"], &mut Refusing, &mut err);
    daemon.result();
    assert_eq!(code, EXIT_LOCAL);
    assert_eq!(
        String::from_utf8(err).unwrap(),
        "mooringctl: writing the output failed\n  caused by: broken pipe\n"
    );
}
