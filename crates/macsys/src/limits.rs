// SPDX-License-Identifier: GPL-3.0-or-later

//! The process's open-files limit (`RLIMIT_NOFILE`), which a measurement
//! that holds thousands of connections open must raise first.

use crate::error::{MacsysError, RlimitCall, last_errno};

/// The open-files limit: the soft limit the process runs under, and the
/// hard limit it may raise that to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenFilesLimit {
    /// The soft limit.
    pub soft: u64,
    /// The hard limit.
    pub hard: u64,
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
    Ok(OpenFilesLimit {
        soft: limit.rlim_cur,
        hard: limit.rlim_max,
    })
}

/// Raises the soft open-files limit to `wanted`, or to the hard limit if
/// that is lower, and returns the limit in force afterwards. A soft limit
/// already at or above `wanted` is left as it is. The kernel may refuse a
/// value above its own per-process maximum (`kern.maxfilesperproc`), which
/// is `Rlimit` with `EINVAL`; the caller decides what a lower limit means.
pub fn raise_open_files(wanted: u64) -> Result<OpenFilesLimit, MacsysError> {
    let current = open_files_limit()?;
    if current.soft >= wanted {
        return Ok(current);
    }
    let raised = libc::rlimit {
        rlim_cur: wanted.min(current.hard),
        rlim_max: current.hard,
    };
    // SAFETY: `raised` is a valid `rlimit` that outlives the call, which
    // only reads it.
    let status = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) };
    if status != 0 {
        return Err(MacsysError::Rlimit {
            call: RlimitCall::Set,
            errno: last_errno(),
        });
    }
    open_files_limit()
}
