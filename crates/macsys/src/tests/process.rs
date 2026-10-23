// SPDX-License-Identifier: GPL-3.0-or-later

//! The boot time and the process calls, live: the boot lies between the
//! epoch and now, this test's own executable is its path, an engine
//! stand-in is ended with `SIGKILL`, a group is ended with its leader's
//! children, a process or group that is gone has no path and is no error
//! to end, and a process's stderr pointed at a file writes there (in a
//! child, so this test's own stderr is left alone).

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{MacsysError, MacsysErrorKind, ProcessCall};
use crate::process::{
    GroupKill, boot_time, kill_group, kill_process, process_path, redirect_stderr,
};

/// The environment variable that makes [`stderr_child`] redirect, naming
/// the file.
const REDIRECT_TO: &str = "MACSYS_TEST_REDIRECT_STDERR_TO";

#[test]
fn the_boot_time_lies_before_now() {
    let boot = boot_time().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // After 2020-01-01, and not in the future.
    assert!(boot > 1_577_836_800 && boot <= now, "{boot} {now}");
    assert_eq!(boot_time().unwrap(), boot);
}

#[test]
fn a_process_path_is_its_executable_and_a_gone_process_has_none() {
    let own = process_path(std::process::id()).unwrap().unwrap();
    assert_eq!(own, std::env::current_exe().unwrap());
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = child.id();
    assert_eq!(
        process_path(pid).unwrap().as_deref(),
        Some(std::path::Path::new("/bin/sleep"))
    );
    kill_process(pid).unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    // Reaped: no such process any more.
    assert_eq!(process_path(pid).unwrap(), None);
    kill_process(pid).unwrap();
}

/// A group's leader and the child it started both end, as an ssh session
/// and its dialler do; once the leader is reaped the group is exiting, then
/// gone, and neither is an error; a group that cannot exist is gone.
#[test]
fn a_group_ends_with_its_leaders_children() {
    let mut leader = Command::new("/bin/sh")
        .args(["-c", "/bin/sleep 30 & echo $!; wait"])
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(leader.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let sleeper: u32 = line.trim().parse().unwrap();
    // Alive, as the shell's fork or as /bin/sleep once it has exec'd.
    let alive = process_path(sleeper).unwrap().is_some();
    assert_eq!(kill_group(leader.id()).unwrap(), GroupKill::Killed);
    assert!(alive);
    assert_eq!(leader.wait().unwrap().signal(), Some(libc::SIGKILL));
    // The orphaned sleeper is launchd's to reap: it goes within moments.
    let until = Instant::now() + Duration::from_secs(5);
    while process_path(sleeper).unwrap().is_some() {
        assert!(
            Instant::now() < until,
            "the leader's child outlived its group"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let after = kill_group(leader.id()).unwrap();
    assert!(
        matches!(after, GroupKill::Exiting | GroupKill::Gone),
        "{after:?}"
    );
    // Above the kernel's highest process id, 99999: no such group.
    assert_eq!(kill_group(100_000).unwrap(), GroupKill::Gone);
}

#[test]
fn pids_outside_the_kernel_range_are_refused() {
    for pid in [0, u32::MAX] {
        let error = kill_process(pid).unwrap_err();
        assert_eq!(
            error,
            MacsysError::Process {
                call: ProcessCall::Kill,
                errno: libc::EINVAL
            }
        );
        assert_eq!(error.kind(), MacsysErrorKind::Process);
        assert_eq!(error.to_string(), "kill failed with errno 22");
    }
    // 0 is the caller's own group to `killpg`, and 1 is launchd's.
    for group in [0, 1, u32::MAX] {
        assert_eq!(
            kill_group(group).unwrap_err(),
            MacsysError::Process {
                call: ProcessCall::KillGroup,
                errno: libc::EINVAL
            }
        );
    }
    assert_eq!(
        process_path(u32::MAX).unwrap_err(),
        MacsysError::Process {
            call: ProcessCall::PidPath,
            errno: libc::EINVAL
        }
    );
    assert_eq!(
        MacsysError::BootTimeInvalid.kind(),
        MacsysErrorKind::BootTimeInvalid
    );
}

/// Run as a child by [`stderr_goes_to_the_file_after_a_redirect`]: points
/// its stderr at the file the environment names and writes two lines there,
/// one through `eprintln!` and one through a panic's message. Alone (no
/// such variable) it does nothing.
#[test]
fn stderr_child() {
    let Some(path) = std::env::var_os(REDIRECT_TO) else {
        return;
    };
    let file = File::create(path).unwrap();
    redirect_stderr(file.as_fd()).unwrap();
    drop(file);
    eprintln!("written after the redirect");
    std::io::stderr().flush().unwrap();
    panic!("a panic's message");
}

#[test]
fn stderr_goes_to_the_file_after_a_redirect() {
    let dir = std::env::temp_dir().join(format!("macsys-stderr-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("stderr.log");
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::process::stderr_child", "--nocapture"])
        .env(REDIRECT_TO, &path)
        .status()
        .unwrap();
    assert!(!status.success(), "the child's test panicked");
    let written = fs::read_to_string(&path).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert!(
        written.contains("written after the redirect\n"),
        "{written}"
    );
    assert!(written.contains("a panic's message"), "{written}");
}
