// SPDX-License-Identifier: GPL-3.0-or-later

//! The open-files limit, which bounds how many connections the
//! port-ceiling probe and its target can hold.

use crate::error::FieldkitError;

/// Raises the soft open-files limit to at least `want` if the hard limit
/// allows, and fails if the descriptors the process may then hold end below
/// `want`: with `OpenFilesLimit` when the soft limit is what stops it, and
/// with `OpenFilesKernelMaximum` when the kernel's per-process maximum
/// (`kern.maxfilesperproc`) is, which macOS enforces without refusing a
/// soft limit above it.
#[cfg(target_os = "macos")]
pub(crate) fn ensure_open_files(want: u64) -> Result<(), FieldkitError> {
    let limit = mooring_macsys::raise_open_files(want).map_err(|error| FieldkitError::Limit {
        reason: error.to_string(),
    })?;
    enough_open_files(limit.in_force, limit.soft, want)
}

/// Whether `in_force` descriptors cover `want`, under a soft limit of
/// `soft`: if not, `OpenFilesKernelMaximum` when the kernel's maximum holds
/// them below the soft limit, else `OpenFilesLimit`.
#[cfg(target_os = "macos")]
pub(crate) fn enough_open_files(in_force: u64, soft: u64, want: u64) -> Result<(), FieldkitError> {
    if in_force >= want {
        return Ok(());
    }
    Err(if in_force < soft {
        FieldkitError::OpenFilesKernelMaximum {
            maximum: in_force,
            want,
        }
    } else {
        FieldkitError::OpenFilesLimit {
            have: in_force,
            want,
        }
    })
}

/// Fails with `OpenFilesLimit` if the soft open-files limit is below
/// `want`; on Linux the operator raises it (`ulimit -n`) before starting.
#[cfg(target_os = "linux")]
pub(crate) fn ensure_open_files(want: u64) -> Result<(), FieldkitError> {
    let have = soft_limit()?;
    if have < want {
        return Err(FieldkitError::OpenFilesLimit { have, want });
    }
    Ok(())
}

/// The soft open-files limit, from `/proc/self/limits` ("unlimited" reads
/// as `u64::MAX`).
#[cfg(target_os = "linux")]
fn soft_limit() -> Result<u64, FieldkitError> {
    let limits =
        std::fs::read_to_string("/proc/self/limits").map_err(|error| FieldkitError::Limit {
            reason: format!("reading /proc/self/limits failed: {error}"),
        })?;
    let soft = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| FieldkitError::Limit {
            reason: "/proc/self/limits has no \"Max open files\" line".to_owned(),
        })?;
    if soft == "unlimited" {
        return Ok(u64::MAX);
    }
    soft.parse().map_err(|_| FieldkitError::Limit {
        reason: format!("/proc/self/limits gives the soft limit as {soft:?}"),
    })
}
