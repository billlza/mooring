// SPDX-License-Identifier: GPL-3.0-or-later

//! The boot time and the process calls, live: the boot lies between the
//! epoch and now, this test's own executable is its path, an engine
//! stand-in is ended with `SIGKILL`, a group is ended with its leader's
//! children, a group whose members have exited is exiting until they are
//! reaped, a process or group that cannot exist has no path and is no error
//! to end, and a process's stderr pointed at a file writes there, while
//! calls that need a descriptor past the open-files limit fail and say why
//! (both in a child, so this test's own stderr and limits are left alone).
//! Every process signalled is one these tests started and have not reaped.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::mem::{MaybeUninit, offset_of, size_of};
use std::os::fd::AsFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{assert_passed, run_child};
use crate::error::{MacsysError, MacsysErrorKind, ProcessCall};
use crate::limits::{open_files_limit, raise_open_files, set_limit};
use crate::process::{
    GroupKill, boot_seconds, boot_time, kill_group, kill_process, process_path, redirect_stderr,
};
use crate::terminal::controlling_terminal;

/// The environment variable that makes [`stderr_child`] redirect, naming
/// the file.
const REDIRECT_TO: &str = "MACSYS_TEST_REDIRECT_STDERR_TO";

/// The environment variable that makes [`past_the_limit_child`] run.
const PAST_THE_LIMIT: &str = "MACSYS_TEST_PAST_THE_LIMIT";

/// Above the kernel's highest process id, 99999: no process or group has
/// it, so ending it signals nothing.
const NO_SUCH_ID: u32 = 100_000;

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

/// A `kern.boottime` value of `seconds` and some microseconds, as the
/// kernel writes one.
fn timeval_bytes(seconds: libc::time_t) -> Vec<u8> {
    let mut value = vec![0_u8; size_of::<libc::timeval>()];
    let at = offset_of!(libc::timeval, tv_sec);
    value[at..at + size_of::<libc::time_t>()].copy_from_slice(&seconds.to_ne_bytes());
    let at = offset_of!(libc::timeval, tv_usec);
    value[at..at + size_of::<libc::suseconds_t>()]
        .copy_from_slice(&libc::suseconds_t::to_ne_bytes(999_999));
    value
}

/// The boot time is the whole seconds of one `timeval` at or after the
/// epoch; anything else the kernel might give is `BootTimeInvalid`, never
/// a time.
#[test]
fn a_boot_time_is_one_timeval_at_or_after_the_epoch() {
    assert_eq!(
        boot_seconds(&timeval_bytes(1_761_955_200)),
        Ok(1_761_955_200)
    );
    assert_eq!(boot_seconds(&timeval_bytes(0)), Ok(0));
    let whole = timeval_bytes(1_761_955_200);
    for (case, value) in [
        ("a short value", &whole[..whole.len() - 1]),
        ("a long value", &[whole.as_slice(), &[0]].concat()[..]),
        ("no value", &[][..]),
        ("before the epoch", &timeval_bytes(-1)[..]),
    ] {
        assert_eq!(
            boot_seconds(value),
            Err(MacsysError::BootTimeInvalid),
            "{case}"
        );
    }
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
    // A process that is gone is no error to end; the reaped id is not
    // signalled again, as another process may hold it by now.
    kill_process(NO_SUCH_ID).unwrap();
}

/// A group's leader and the child it started both end, as an ssh session
/// and its dialler do; a group that cannot exist is gone, which is no
/// error. The reaped leader's id is not signalled again, as another group
/// may hold it by now.
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
    assert_eq!(kill_group(NO_SUCH_ID).unwrap(), GroupKill::Gone);
}

/// A group whose one member has exited but is not yet reaped is still
/// there with no member left to signal: `Exiting`, as an ssh session's
/// group is while its processes end. The exit is awaited without reaping
/// (`WNOWAIT`), so until `wait` below the id stays this test's child's.
#[test]
fn a_group_of_an_unreaped_child_is_exiting() {
    let mut member = Command::new("/usr/bin/true")
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = member.id();
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: `info` is writable storage for one `siginfo_t`, which the
    // call fills; `pid` is this test's own child, which `WNOWAIT` leaves
    // unreaped, so no other process can hold the id meanwhile.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(waited, 0, "waitid failed: {}", io::Error::last_os_error());
    assert_eq!(kill_group(pid).unwrap(), GroupKill::Exiting);
    assert!(member.wait().unwrap().success());
}

/// Run as a child by [`calls_past_the_descriptor_limit_fail_and_say_why`]:
/// with its soft open-files limit at 2, descriptor 2 lies past the limit,
/// so `dup2` onto it fails with `EBADF`, and opening the terminal, which
/// needs a new descriptor, fails with `EMFILE`. The redirect is aimed at
/// standard output, so were it to succeed, what this test then writes would
/// still be seen. The limit is put back before anything is asserted, as
/// the profile written at exit needs descriptors of its own. Alone (no such
/// variable) it does nothing.
#[test]
fn past_the_limit_child() {
    if std::env::var_os(PAST_THE_LIMIT).is_none() {
        return;
    }
    let before = open_files_limit().unwrap();
    // Lowering the soft limit is always permitted; this process is a child
    // run for this test alone.
    set_limit(2, before.hard).unwrap();
    let redirected = redirect_stderr(io::stdout().as_fd());
    let terminal = controlling_terminal().map_err(|error| error.raw_os_error());
    let restored = raise_open_files(before.soft);
    assert_eq!(restored.unwrap(), before);
    assert_eq!(
        redirected,
        Err(MacsysError::Process {
            call: ProcessCall::Dup2,
            errno: libc::EBADF,
        })
    );
    assert!(matches!(terminal, Err(Some(libc::EMFILE))), "{terminal:?}");
}

/// Calls that need a descriptor past the open-files limit fail and say
/// why, never a loop or a silent success: a redirect of standard error is
/// an error naming `dup2` (the daemon does not start writing a log it never
/// opened), and a terminal that cannot be opened is that error, not "no
/// terminal".
#[test]
fn calls_past_the_descriptor_limit_fail_and_say_why() {
    let test = "tests::process::past_the_limit_child";
    assert_passed(test, &run_child(test, PAST_THE_LIMIT, "1"));
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
    io::stderr().flush().unwrap();
    panic!("a panic's message");
}

#[test]
fn stderr_goes_to_the_file_after_a_redirect() {
    let dir = std::env::temp_dir().join(format!("macsys-stderr-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("stderr.log");
    let output = run_child("tests::process::stderr_child", REDIRECT_TO, &path);
    assert!(!output.status.success(), "the child's test panicked");
    let written = fs::read_to_string(&path).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert!(
        written.contains("written after the redirect\n"),
        "{written}"
    );
    assert!(written.contains("a panic's message"), "{written}");
}
