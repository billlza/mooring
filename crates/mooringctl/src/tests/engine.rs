// SPDX-License-Identifier: GPL-3.0-or-later

//! An engine whose check does not finish in time, and one that does not
//! take its config (design §10.1): the first is killed and timed out, the
//! second stopped at once. Their check, start and stop otherwise are the
//! runtime tests'.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::runtime::engine::{Engine, EngineError, read_check_stderr};

/// An executable script at `dir/name`, run once (`warm`) so the system's
/// first scan of a new file is not part of what a test times.
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Command::new(&path).arg("warm").status().unwrap().success());
    path
}

/// A check still running at its limit is killed and is a time-out, not a
/// verdict on the config.
#[test]
fn a_check_that_does_not_finish_in_time_is_killed() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(&script(
        dir.path(),
        "slow",
        "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nexec /bin/sleep 30\n",
    ));
    let started = Instant::now();
    let checked = engine.check_within(b"{}", Duration::from_millis(200));
    assert!(
        matches!(checked, Err(EngineError::CheckTimeout)),
        "{checked:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// The budget includes delivering the configuration. A child that never
/// reads stdin must not block the daemon before its timeout even starts.
#[test]
fn a_check_that_never_reads_its_config_still_obeys_its_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(&script(
        dir.path(),
        "unreading-check",
        "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nexec /bin/sleep 2\n",
    ));
    let config = vec![b' '; 1024 * 1024];
    let started = Instant::now();
    let checked = engine.check_within(&config, Duration::from_millis(200));
    assert!(
        matches!(checked, Err(EngineError::CheckTimeout)),
        "{checked:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// An engine that exits without reading its config does not take it: the
/// start fails as such, and the engine is reaped. The config is larger
/// than a pipe holds, so writing it fails rather than waiting unread.
#[test]
fn an_engine_that_does_not_take_its_config_is_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(&script(dir.path(), "deaf", "#!/bin/sh\nexit 0\n"));
    let config = vec![b' '; 1024 * 1024];
    match engine.start(&config) {
        Err(EngineError::Config(source)) => {
            assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_start_that_never_reads_its_config_is_timed_out_and_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(&script(
        dir.path(),
        "unreading-start",
        "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\nexec /bin/sleep 2\n",
    ));
    let config = vec![b' '; 1024 * 1024];
    let started = Instant::now();
    match engine.start_within(&config, Duration::from_millis(200)) {
        Err(EngineError::Config(error)) => {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
        other => panic!("{other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// The diagnostic buffer is bounded, but the pipe is drained to EOF.
#[test]
fn check_stderr_is_drained_and_bounded() {
    let bytes = vec![b'x'; 20_000];
    let mut input = io::Cursor::new(&bytes);
    assert_eq!(read_check_stderr(&mut input).unwrap(), vec![b'x'; 4096]);
    assert_eq!(input.position(), bytes.len() as u64);
    assert!(read_check_stderr(&mut io::empty()).unwrap().is_empty());
}

#[test]
fn a_failed_stderr_read_is_not_successful_partial_output() {
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    let mut input = io::Cursor::new(b"partial diagnostic").chain(Failed);
    let error = read_check_stderr(&mut input).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}
