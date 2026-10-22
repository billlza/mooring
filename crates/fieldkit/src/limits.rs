// SPDX-License-Identifier: GPL-3.0-or-later

//! The open-files limit, which bounds how many connections the
//! port-ceiling probe and its target can hold.

use crate::error::FieldkitError;

/// Raises the soft open-files limit to at least `want` if the hard limit
/// allows, and fails with `OpenFilesLimit` if it ends below `want`.
#[cfg(target_os = "macos")]
pub(crate) fn ensure_open_files(want: u64) -> Result<(), FieldkitError> {
    let limit = mooring_macsys::raise_open_files(want).map_err(|error| FieldkitError::Limit {
        reason: error.to_string(),
    })?;
    if limit.soft < want {
        return Err(FieldkitError::OpenFilesLimit {
            have: limit.soft,
            want,
        });
    }
    Ok(())
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
