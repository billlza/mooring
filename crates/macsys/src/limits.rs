// SPDX-License-Identifier: GPL-3.0-or-later

//! The process's open-files limit (`RLIMIT_NOFILE`), which a measurement
//! that holds thousands of connections open must raise first, and the
//! number of descriptors the kernel in fact lets the process hold, which
//! may be lower.

use crate::error::{MacsysError, RlimitCall, last_errno};

/// The open-files limit: the soft limit the process runs under, the hard
/// limit it may raise that to, and the descriptors it may in fact hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenFilesLimit {
    /// The soft limit.
    pub soft: u64,
    /// The hard limit.
    pub hard: u64,
    /// The descriptors the process may hold open (`getdtablesize`): the
    /// soft limit, or the kernel's per-process maximum
    /// (`kern.maxfilesperproc`) when that is lower. Measured on macOS 27.2
    /// on 2026-11-02: the kernel took a soft limit above that maximum
    /// without an error and enforced the maximum, so a process whose soft
    /// limit was 1048576 under a maximum of 122880 opened descriptors up to
    /// 122879, and the next `dup` failed with `EMFILE`.
    pub in_force: u64,
}

/// The process's open-files limit.
pub fn open_files_limit() -> Result<OpenFilesLimit, MacsysError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit` that outlives the call,
    // which only writes it.
    let status = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if status != 0 {
        return Err(MacsysError::Rlimit {
            call: RlimitCall::Get,
            errno: last_errno(),
        });
    }
    // SAFETY: `getdtablesize` has no preconditions and cannot fail.
    let table = unsafe { libc::getdtablesize() };
    Ok(OpenFilesLimit {
        soft: limit.rlim_cur,
        hard: limit.rlim_max,
        in_force: descriptors_in_force(table)?,
    })
}

/// The descriptors in force from the size `getdtablesize` gives:
/// `DescriptorTableSizeInvalid` below 0, as the kernel gives when
/// `kern.maxfilesperproc` is set below 0 *(read from xnu's source, not
/// measured: it takes the lower of the soft limit and that maximum,
/// compared as unsigned, and returns it as an `int`)*.
pub(crate) fn descriptors_in_force(size: libc::c_int) -> Result<u64, MacsysError> {
    u64::try_from(size).map_err(|_| MacsysError::DescriptorTableSizeInvalid { size })
}

/// Raises the soft open-files limit to `wanted`, or to the hard limit if
/// that is lower, and returns the limit afterwards; a soft limit already at
/// or above `wanted` is left as it is. Whether the process may then hold
/// `wanted` descriptors is [`OpenFilesLimit::in_force`]: macOS 27.2 takes a
/// soft limit above its per-process maximum without an error, and a kernel
/// that refuses one instead fails the raise with `Rlimit` (`EINVAL`).
pub fn raise_open_files(wanted: u64) -> Result<OpenFilesLimit, MacsysError> {
    let current = open_files_limit()?;
    if let Some(soft) = raised_soft(current.soft, current.hard, wanted) {
        set_limit(soft, current.hard)?;
    }
    open_files_limit()
}

/// The soft limit that raises `soft` towards `wanted`: `wanted`, or `hard`
/// if that is lower; `None` when the soft limit is there already, so a
/// raise never lowers it.
pub(crate) fn raised_soft(soft: u64, hard: u64, wanted: u64) -> Option<u64> {
    let raised = wanted.min(hard);
    (soft < raised).then_some(raised)
}

/// Sets the open-files limit to `soft` under `hard` (`setrlimit`).
pub(crate) fn set_limit(soft: u64, hard: u64) -> Result<(), MacsysError> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: `limit` is a valid `rlimit` that outlives the call, which
    // only reads it.
    let status = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    if status != 0 {
        return Err(MacsysError::Rlimit {
            call: RlimitCall::Set,
            errno: last_errno(),
        });
    }
    Ok(())
}
