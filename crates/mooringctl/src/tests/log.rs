// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's log: `~/Library/Logs/Mooring/daemon.log`, 0600 in a 0700
//! directory, appended to, rotated to `daemon.log.1` once full at the next
//! line's start (never splitting a line), with standard error pointed at
//! each new file; the stand-in redirect leaves this test's stderr alone. A
//! log that cannot be opened stops the daemon before anything else.

use std::cell::Cell;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mooring_macsys::MacsysError;

use super::support::Harness;
use crate::daemon::log::{DaemonLog, LOG_FILE, ROTATED_LOG_FILE, log_dir};
use crate::error::{EXIT_LOCAL, LocalError};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn the_log_lives_under_the_home_library() {
    assert_eq!(
        log_dir(Some("/Users/operator".into())).unwrap(),
        Path::new("/Users/operator/Library/Logs/Mooring")
    );
    assert!(matches!(log_dir(None), Err(LocalError::Home)));
    assert!(matches!(
        log_dir(Some("relative".into())),
        Err(LocalError::Home)
    ));
}

#[test]
fn the_log_is_private_appended_and_rotated_at_a_line_start() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("Library").join("Logs").join("Mooring");
    let redirects = Cell::new(0);
    let redirect = |_: std::os::fd::BorrowedFd<'_>| {
        redirects.set(redirects.get() + 1);
        Ok(())
    };
    {
        let mut log = DaemonLog::open(&dir, 20, &redirect).unwrap();
        assert_eq!(redirects.get(), 1, "stderr points at the log once open");
        writeln!(log, "first line here").unwrap();
    }
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join(LOG_FILE)), 0o600);
    // Reopened, it appends; a line written in parts is never split, even
    // past the limit.
    let mut log = DaemonLog::open(&dir, 20, &redirect).unwrap();
    write!(log, "second ").unwrap();
    write!(log, "line, longer than the limit").unwrap();
    writeln!(log).unwrap();
    assert_eq!(redirects.get(), 2);
    assert_eq!(
        fs::read_to_string(dir.join(LOG_FILE)).unwrap(),
        "first line here\nsecond line, longer than the limit\n"
    );
    assert!(!dir.join(ROTATED_LOG_FILE).exists());
    // Full: the next line starts a new file, and stderr follows it.
    writeln!(log, "third").unwrap();
    assert_eq!(redirects.get(), 3);
    assert_eq!(
        fs::read_to_string(dir.join(ROTATED_LOG_FILE)).unwrap(),
        "first line here\nsecond line, longer than the limit\n"
    );
    assert_eq!(fs::read_to_string(dir.join(LOG_FILE)).unwrap(), "third\n");
    assert_eq!(mode(&dir.join(LOG_FILE)), 0o600);
    // A second rotation replaces the first rotated file: two files at most.
    writeln!(log, "fourth, to fill it up").unwrap();
    writeln!(log, "fifth").unwrap();
    assert_eq!(redirects.get(), 4);
    assert_eq!(
        fs::read_to_string(dir.join(ROTATED_LOG_FILE)).unwrap(),
        "third\nfourth, to fill it up\n"
    );
    assert_eq!(fs::read_to_string(dir.join(LOG_FILE)).unwrap(), "fifth\n");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, [LOG_FILE, ROTATED_LOG_FILE]);
}

#[test]
fn a_redirect_that_fails_stops_the_open() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("logs");
    let refuse = |_: std::os::fd::BorrowedFd<'_>| {
        Err(MacsysError::Process {
            call: mooring_macsys::ProcessCall::Dup2,
            errno: 9,
        })
    };
    let error = DaemonLog::open(&dir, 20, &refuse).unwrap_err();
    assert!(matches!(error, LocalError::LogRedirect(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "cannot send the daemon's standard error to its log"
    );
}

/// A log directory that cannot be made, or a log file that cannot be
/// opened, stops the open, naming the path; nothing is redirected.
#[test]
fn a_log_that_cannot_be_opened_stops_the_open() {
    let home = tempfile::tempdir().unwrap();
    let redirects = Cell::new(0);
    let redirect = |_: std::os::fd::BorrowedFd<'_>| {
        redirects.set(redirects.get() + 1);
        Ok(())
    };
    // A file where a directory above the log's goes.
    fs::write(home.path().join("Library"), b"").unwrap();
    let dir = home.path().join("Library").join("Logs").join("Mooring");
    let error = DaemonLog::open(&dir, 20, &redirect).unwrap_err();
    assert!(
        matches!(&error, LocalError::LogDir { path, .. } if *path == dir),
        "{error:?}"
    );
    // A directory where the log file goes.
    let dir = home.path().join("logs");
    fs::create_dir_all(dir.join(LOG_FILE)).unwrap();
    let error = DaemonLog::open(&dir, 20, &redirect).unwrap_err();
    assert!(
        matches!(&error, LocalError::LogFile { path, .. } if *path == dir.join(LOG_FILE)),
        "{error:?}"
    );
    assert_eq!(redirects.get(), 0);
}

/// An empty write writes nothing and never rotates; the log's debug output
/// names its directory and its counts.
#[test]
fn an_empty_write_is_nothing_and_the_debug_output_names_the_log() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("logs");
    let redirect = |_: std::os::fd::BorrowedFd<'_>| Ok(());
    let mut log = DaemonLog::open(&dir, 0, &redirect).unwrap();
    assert_eq!(log.write(&[]).unwrap(), 0);
    assert!(!dir.join(ROTATED_LOG_FILE).exists());
    assert_eq!(
        format!("{log:?}"),
        format!("DaemonLog {{ dir: {dir:?}, written: 0, rotate_at: 0, .. }}")
    );
}

/// `mooringctl daemon` stops at once when its log cannot be opened: it
/// does not run without the file it reports to, and sets nothing else up.
#[test]
fn the_daemon_does_not_run_without_its_log() {
    let mut harness = Harness::new(9);
    fs::create_dir_all(harness.home.path().join("Library")).unwrap();
    fs::write(harness.home.path().join("Library").join("Logs"), b"").unwrap();
    let outcome = harness.run(&["daemon"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: cannot create the daemon's log directory "),
        "{}",
        outcome.stderr
    );
    assert_eq!(harness.redirected.get(), 0);
    assert!(!harness.support_dir().exists());
}
