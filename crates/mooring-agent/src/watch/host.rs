// SPDX-License-Identifier: GPL-3.0-or-later

//! The host, read for `StatusV1::host` and the host conditions (design
//! §11.3 step 6, §14): the kernel's figures from `/proc`, the agent's
//! filesystem from `stat -f`, journald's persistent journal, the reboot and
//! upgrade marks, and chrony. Every figure is a count, a size or a time.

use std::fs;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use mooring_agent_proto::{
    AgentError, DISK_LOW_FREE_BYTES, DISK_LOW_FREE_PERCENT, HostHealth, IoOp, UnixTime, WatchError,
};

use super::status::HostReading;
use crate::host::{Node, Tool, run_ok};
use crate::paths::Paths;
use crate::store::{io_error, malformed};

/// Reads the host at `now`.
pub(crate) fn read(
    paths: &Paths,
    node: &dyn Node,
    now: UnixTime,
) -> Result<HostReading, AgentError> {
    let (disk_free_bytes, disk_total_bytes) = disk(paths, node)?;
    let reboot_required_since = modified(&paths.reboot_required())?;
    Ok(HostReading {
        at: now,
        health: HostHealth {
            uptime_secs: uptime(&read_text(&paths.proc("uptime"))?)?,
            load_milli: load_milli(&read_text(&paths.proc("loadavg"))?)?,
            mem_available_bytes: mem_available(&read_text(&paths.proc("meminfo"))?)?,
            disk_free_bytes,
            journal_bytes: tree_bytes(&paths.persistent_journal())?,
            reboot_required: reboot_required_since.is_some(),
            last_unattended_upgrade: modified(&paths.unattended_upgrades_log())?,
            ntp_synced: ntp_synced(node),
        },
        disk_total_bytes,
        reboot_required_since,
    })
}

/// The host conditions a reading shows: `DiskLow`, `ClockUnsynced` and
/// `RebootPending`.
pub(crate) fn conditions(reading: &HostReading) -> Vec<WatchError> {
    let free = reading.health.disk_free_bytes;
    let low_share = u128::from(free) * 100
        < u128::from(reading.disk_total_bytes) * u128::from(DISK_LOW_FREE_PERCENT);
    let mut conditions = Vec::new();
    if free < DISK_LOW_FREE_BYTES || low_share {
        conditions.push(WatchError::DiskLow { free });
    }
    if !reading.health.ntp_synced {
        conditions.push(WatchError::ClockUnsynced);
    }
    if let Some(since) = reading.reboot_required_since {
        conditions.push(WatchError::RebootPending { since });
    }
    conditions
}

fn read_text(path: &Path) -> Result<String, AgentError> {
    fs::read_to_string(path).map_err(|error| io_error(IoOp::ReadState, &error))
}

/// Whole seconds since boot, from `/proc/uptime`.
pub(crate) fn uptime(text: &str) -> Result<u64, AgentError> {
    text.split_whitespace()
        .next()
        .and_then(|seconds| seconds.split('.').next())
        .and_then(|whole| whole.parse().ok())
        .ok_or(malformed(IoOp::ReadState))
}

/// The one-minute load average in thousandths, from `/proc/loadavg`
/// (printed with two decimals), read without floating point.
pub(crate) fn load_milli(text: &str) -> Result<u32, AgentError> {
    let first = text
        .split_whitespace()
        .next()
        .ok_or(malformed(IoOp::ReadState))?;
    let (whole, fraction) = match first.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (first, "0"),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(whole) || !digits(fraction) || fraction.len() > 3 {
        return Err(malformed(IoOp::ReadState));
    }
    let whole: u32 = whole.parse().map_err(|_| malformed(IoOp::ReadState))?;
    let fraction: u32 = format!("{fraction:0<3}")
        .parse()
        .map_err(|_| malformed(IoOp::ReadState))?;
    whole
        .checked_mul(1000)
        .and_then(|milli| milli.checked_add(fraction))
        .ok_or(malformed(IoOp::ReadState))
}

/// `MemAvailable` in bytes, from `/proc/meminfo` (in kB).
pub(crate) fn mem_available(text: &str) -> Result<u64, AgentError> {
    text.lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|rest| rest.trim().strip_suffix(" kB"))
        .and_then(|kib| kib.trim().parse::<u64>().ok())
        .and_then(|kib| kib.checked_mul(1024))
        .ok_or(malformed(IoOp::ReadState))
}

/// The bytes available and the size of the filesystem holding
/// `/var/lib/mooring`: `stat -f` prints the available blocks, the
/// fundamental block size and the total blocks.
fn disk(paths: &Paths, node: &dyn Node) -> Result<(u64, u64), AgentError> {
    let path = paths.var_lib().display().to_string();
    let stdout = run_ok(node, Tool::Stat, &["-f", "-c", "%a %S %b", &path])?
        .map_err(|_| malformed(IoOp::ReadState))?;
    let text = std::str::from_utf8(&stdout).map_err(|_| malformed(IoOp::ReadState))?;
    let numbers: Vec<u64> = text
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| malformed(IoOp::ReadState))?;
    let [available, block, total] = numbers.as_slice() else {
        return Err(malformed(IoOp::ReadState));
    };
    let bytes = |blocks: u64| blocks.checked_mul(*block).ok_or(malformed(IoOp::ReadState));
    Ok((bytes(*available)?, bytes(*total)?))
}

/// The bytes the regular files under `root` occupy; a missing `root` (no
/// persistent journal) occupies none. Links are not followed.
fn tree_bytes(root: &Path) -> Result<u64, AgentError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(io_error(IoOp::ReadState, &error)),
    };
    let mut total = 0_u64;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(IoOp::ReadState, &error))?;
        let meta = fs::symlink_metadata(entry.path())
            .map_err(|error| io_error(IoOp::ReadState, &error))?;
        let bytes = if meta.is_dir() {
            tree_bytes(&entry.path())?
        } else if meta.is_file() {
            meta.len()
        } else {
            0
        };
        total = total.saturating_add(bytes);
    }
    Ok(total)
}

/// When `path` was last modified; `None` if it does not exist.
fn modified(path: &Path) -> Result<Option<UnixTime>, AgentError> {
    match fs::metadata(path) {
        Ok(meta) => {
            let modified = meta
                .modified()
                .map_err(|error| io_error(IoOp::ReadState, &error))?;
            let since = modified
                .duration_since(UNIX_EPOCH)
                .map_err(|_| malformed(IoOp::ReadState))?;
            Ok(Some(UnixTime::from_secs(since.as_secs())))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(IoOp::ReadState, &error)),
    }
}

/// Whether chrony reports the clock synchronised (`HostHealth::ntp_synced`):
/// its tracking report's leap status is one a synchronised clock has. A
/// chrony that cannot be asked, or does not answer, reports nothing, so the
/// clock is not reported synchronised.
fn ntp_synced(node: &dyn Node) -> bool {
    match run_ok(node, Tool::Chronyc, &["-n", "tracking"]) {
        Ok(Ok(stdout)) => synchronised(&String::from_utf8_lossy(&stdout)),
        Ok(Err(_)) | Err(_) => false,
    }
}

/// Whether a `chronyc tracking` report's leap status is `Normal`,
/// `Insert second` or `Delete second` (not `Not synchronised`).
pub(crate) fn synchronised(report: &str) -> bool {
    report
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "Leap status").then(|| value.trim().to_owned())
        })
        .is_some_and(|status| {
            matches!(
                status.as_str(),
                "Normal" | "Insert second" | "Delete second"
            )
        })
}
