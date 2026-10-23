// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's boot time and the daemon's engine processes (design §10.1):
//! when the kernel booted (`kern.boottime`), which tells the SIM meter a
//! reading of this boot from one of an earlier boot; and a process's
//! executable (`proc_pidpath`) and its end (`kill` with `SIGKILL`), with
//! which the daemon stops an engine an earlier daemon left, and only when
//! it is that engine.

use std::ffi::OsStr;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

use crate::error::{MacsysError, ProcessCall, last_errno};

/// When the kernel booted, in whole seconds since the epoch.
pub fn boot_time() -> Result<u64, MacsysError> {
    let mut name = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    let mut boot = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size: libc::size_t = size_of::<libc::timeval>();
    // SAFETY: `name` holds two integers and the length says so; `boot` is
    // a writable `timeval` of `size` bytes, which the kernel writes, storing
    // the count in `size`; no new value is set.
    let status = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            2,
            (&raw mut boot).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(MacsysError::Sysctl {
            errno: last_errno(),
        });
    }
    if size != size_of::<libc::timeval>() {
        return Err(MacsysError::BootTimeInvalid);
    }
    u64::try_from(boot.tv_sec).map_err(|_| MacsysError::BootTimeInvalid)
}

/// The executable of process `pid`, or `None` when there is no such
/// process.
pub fn process_path(pid: u32) -> Result<Option<PathBuf>, MacsysError> {
    let failed = |errno| MacsysError::Process {
        call: ProcessCall::PidPath,
        errno,
    };
    let pid = libc::pid_t::try_from(pid).map_err(|_| failed(libc::EINVAL))?;
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE.unsigned_abs() as usize];
    let room = u32::try_from(buffer.len()).map_err(|_| failed(libc::EINVAL))?;
    // SAFETY: `buffer` is `room` writable bytes; the call writes at most
    // that many and returns how many it wrote.
    let written = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), room) };
    if written <= 0 {
        let errno = last_errno();
        return if errno == libc::ESRCH {
            Ok(None)
        } else {
            Err(failed(errno))
        };
    }
    buffer.truncate(written.unsigned_abs() as usize);
    Ok(Some(PathBuf::from(OsStr::from_bytes(&buffer))))
}

/// Ends process `pid` with `SIGKILL`; a process that is gone already is
/// fine.
pub fn kill_process(pid: u32) -> Result<(), MacsysError> {
    let failed = |errno| MacsysError::Process {
        call: ProcessCall::Kill,
        errno,
    };
    let pid = libc::pid_t::try_from(pid)
        .ok()
        .filter(|&pid| pid > 0)
        .ok_or_else(|| failed(libc::EINVAL))?;
    // SAFETY: `kill` has no memory preconditions; `pid` names one process,
    // never a group (it is positive).
    let status = unsafe { libc::kill(pid, libc::SIGKILL) };
    if status == 0 {
        return Ok(());
    }
    match last_errno() {
        libc::ESRCH => Ok(()),
        errno => Err(failed(errno)),
    }
}
