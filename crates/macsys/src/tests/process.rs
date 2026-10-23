// SPDX-License-Identifier: GPL-3.0-or-later

//! The boot time and the process calls, live: the boot lies between the
//! epoch and now, this test's own executable is its path, an engine
//! stand-in is ended with `SIGKILL`, and a process that is gone has no
//! path and is no error to end.

use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{MacsysError, MacsysErrorKind, ProcessCall};
use crate::process::{boot_time, kill_process, process_path};

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
