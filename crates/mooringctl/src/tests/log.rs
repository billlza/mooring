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
use crate::daemon::log::{
    APPLY_LOG, DAEMON_LOG, LOG_FILE, LogFiles, ModeRestored, ROTATED_LOG_FILE, RotatingLog, log_dir,
};
use crate::error::{EXIT_LOCAL, LocalError};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Gives `path` exactly `mode`, whatever the umask.
fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// The log directory under a new home, made with `dir_mode`, holding the
/// log's file with one line at `file_mode` and its rotated file at
/// `rotated_mode`.
fn found(files: LogFiles, dir_mode: u32, file_mode: u32, rotated_mode: u32) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("Library").join("Logs").join("Mooring");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(files.name), "an earlier line\n").unwrap();
    fs::write(dir.join(files.rotated), "an older line\n").unwrap();
    set_mode(&dir.join(files.name), file_mode);
    set_mode(&dir.join(files.rotated), rotated_mode);
    set_mode(&dir, dir_mode);
    home
}

/// A log found with looser modes than the design's (0600 files in a 0700
/// directory), as launchd made `daemon.log` 0644 for the development
/// LaunchAgent of 2026-10-22, whose `StandardErrorPath` named it, is made
/// private again when it opens: the directory, the file written and the
/// rotated file, each set back and named in what the open restored. The
/// lines are kept, and the next is appended. A log already private is left
/// as it is, and nothing is restored. Both logs open alike.
#[test]
fn a_log_found_with_looser_modes_is_made_private_again() {
    for files in [DAEMON_LOG, APPLY_LOG] {
        let home = found(files, 0o755, 0o644, 0o640);
        let dir = home.path().join("Library").join("Logs").join("Mooring");
        let redirect = |_: std::os::fd::BorrowedFd<'_>| Ok(());
        let mut log = RotatingLog::open(&dir, files, 1024, &redirect).unwrap();
        assert_eq!(
            log.restored(),
            [
                ModeRestored {
                    name: "the log directory".to_owned(),
                    was: 0o755,
                    now: 0o700,
                },
                ModeRestored {
                    name: files.name.to_owned(),
                    was: 0o644,
                    now: 0o600,
                },
                ModeRestored {
                    name: files.rotated.to_owned(),
                    was: 0o640,
                    now: 0o600,
                },
            ],
            "{}",
            files.name
        );
        assert_eq!(
            log.restored()[1].line(),
            format!("{} had mode 0644; set to 0600", files.name)
        );
        writeln!(log, "the next line").unwrap();
        drop(log);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(files.name)), 0o600);
        assert_eq!(mode(&dir.join(files.rotated)), 0o600);
        assert_eq!(
            fs::read_to_string(dir.join(files.name)).unwrap(),
            "an earlier line\nthe next line\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join(files.rotated)).unwrap(),
            "an older line\n"
        );
        // Private now: opened again, nothing is restored.
        let log = RotatingLog::open(&dir, files, 1024, &redirect).unwrap();
        assert!(log.restored().is_empty(), "{:?}", log.restored());
    }
    // A mode stricter than the design's is set to it too, and a mode with
    // bits beyond the permissions is no exception. (A file its owner cannot
    // write is refused at the open, as it always was: the log cannot be
    // appended to.)
    let home = found(DAEMON_LOG, 0o700, 0o200, 0o4600);
    let dir = home.path().join("Library").join("Logs").join("Mooring");
    let redirect = |_: std::os::fd::BorrowedFd<'_>| Ok(());
    let log = RotatingLog::open(&dir, DAEMON_LOG, 1024, &redirect).unwrap();
    let restored: Vec<(String, u32)> = log
        .restored()
        .iter()
        .map(|mode| (mode.name.clone(), mode.was))
        .collect();
    assert_eq!(
        restored,
        [
            (LOG_FILE.to_owned(), 0o200),
            (ROTATED_LOG_FILE.to_owned(), 0o4600)
        ]
    );
    assert_eq!(mode(&dir.join(LOG_FILE)), 0o600);
    assert_eq!(mode(&dir.join(ROTATED_LOG_FILE)), 0o600);
}

/// No rotated file is no rotated file to restore, and a link where the
/// rotated file goes is left as it is: the log never writes through it,
/// and its mode is the link's target's.
#[test]
fn a_missing_or_linked_rotated_file_is_left_alone() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("logs");
    fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o700);
    let target = home.path().join("elsewhere");
    fs::write(&target, "not the log's\n").unwrap();
    set_mode(&target, 0o644);
    let redirect = |_: std::os::fd::BorrowedFd<'_>| Ok(());
    let log = RotatingLog::open(&dir, DAEMON_LOG, 1024, &redirect).unwrap();
    assert!(log.restored().is_empty());
    drop(log);
    std::os::unix::fs::symlink(&target, dir.join(ROTATED_LOG_FILE)).unwrap();
    let log = RotatingLog::open(&dir, DAEMON_LOG, 1024, &redirect).unwrap();
    assert!(log.restored().is_empty());
    assert_eq!(mode(&target), 0o644);
}

/// A link where the log directory goes is followed, as it always was, but
/// its target's mode is left as it is: it is not the log's own directory.
#[test]
fn a_linked_log_directory_keeps_its_targets_mode() {
    let home = tempfile::tempdir().unwrap();
    let target = home.path().join("shared");
    fs::create_dir_all(&target).unwrap();
    set_mode(&target, 0o755);
    let dir = home.path().join("logs");
    std::os::unix::fs::symlink(&target, &dir).unwrap();
    let redirect = |_: std::os::fd::BorrowedFd<'_>| Ok(());
    let log = RotatingLog::open(&dir, DAEMON_LOG, 1024, &redirect).unwrap();
    assert!(log.restored().is_empty(), "{:?}", log.restored());
    assert_eq!(mode(&target), 0o755);
    assert_eq!(mode(&target.join(LOG_FILE)), 0o600);
}

/// The daemon says in its log what the open restored, before anything
/// else: here its start then fails, as the support directory cannot be
/// made, and that is the next line.
#[test]
fn the_daemon_logs_the_modes_it_restored() {
    let mut harness = Harness::new(9);
    let dir = harness
        .home
        .path()
        .join("Library")
        .join("Logs")
        .join("Mooring");
    fs::create_dir_all(&dir).unwrap();
    set_mode(&dir, 0o700);
    fs::write(dir.join(LOG_FILE), "").unwrap();
    set_mode(&dir.join(LOG_FILE), 0o644);
    let support = harness.support_dir();
    fs::create_dir_all(support.parent().unwrap()).unwrap();
    fs::write(&support, b"").unwrap();
    let outcome = harness.run(&["daemon"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(mode(&dir.join(LOG_FILE)), 0o600);
    let log = fs::read_to_string(dir.join(LOG_FILE)).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(
        lines[0],
        "2026-10-13 19:20:00 UTC mooringctl daemon: daemon.log had mode 0644; set to 0600"
    );
    assert_eq!(lines.len(), 1, "{log}");
    assert!(
        outcome.stderr.starts_with("mooringctl: cannot create "),
        "{}",
        outcome.stderr
    );
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
        let mut log = RotatingLog::open(&dir, DAEMON_LOG, 20, &redirect).unwrap();
        assert_eq!(redirects.get(), 1, "stderr points at the log once open");
        writeln!(log, "first line here").unwrap();
    }
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join(LOG_FILE)), 0o600);
    // Reopened, it appends; a line written in parts is never split, even
    // past the limit.
    let mut log = RotatingLog::open(&dir, DAEMON_LOG, 20, &redirect).unwrap();
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
    let error = RotatingLog::open(&dir, DAEMON_LOG, 20, &refuse).unwrap_err();
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
    let error = RotatingLog::open(&dir, DAEMON_LOG, 20, &redirect).unwrap_err();
    assert!(
        matches!(&error, LocalError::LogDir { path, .. } if *path == dir),
        "{error:?}"
    );
    // A directory where the log file goes.
    let dir = home.path().join("logs");
    fs::create_dir_all(dir.join(LOG_FILE)).unwrap();
    let error = RotatingLog::open(&dir, DAEMON_LOG, 20, &redirect).unwrap_err();
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
    let mut log = RotatingLog::open(&dir, DAEMON_LOG, 0, &redirect).unwrap();
    assert_eq!(log.write(&[]).unwrap(), 0);
    assert!(!dir.join(ROTATED_LOG_FILE).exists());
    assert_eq!(
        format!("{log:?}"),
        format!(
            "RotatingLog {{ dir: {dir:?}, files: LogFiles {{ name: \"daemon.log\", rotated: \"daemon.log.1\" }}, written: 0, rotate_at: 0, .. }}"
        )
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
