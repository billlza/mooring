// SPDX-License-Identifier: GPL-3.0-or-later

//! Ops-only watch convergence after the frozen agent upgrade transaction.
//! The frozen transaction still proves control-plane rollback. This separate
//! operation reports failure unless the actual systemd process runs the
//! requested executable; it never changes a hold, halt or generation.

use std::fs::File;
use std::io::Read;
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use mooring_agent_proto::{
    AgentError, IoOp, Sha256Hex, SystemdOp, UnitName, WatchProcess, WatchRuntime,
};

use crate::blobs::digest_of;
use crate::hello::own_sha;
use crate::host::{Node, Tool, run_ok};
use crate::paths::Paths;
use crate::store::{io_error, malformed};

const WATCH: &str = "mooring-watch.service";

/// A bounded systemd query. A stopped service is explicitly no process.
fn main_pid(node: &dyn Node, deadline: Instant) -> Result<Option<NonZeroU32>, AgentError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(110),
        });
    }
    // GNU timeout accepts fractional seconds, but no `ms` suffix.
    let millis = left.as_millis().clamp(1, 5_000);
    let budget = format!("{}.{:03}s", millis / 1000, millis % 1000);
    let bytes = run_ok(
        node,
        Tool::Timeout,
        &[
            "--kill-after=1s",
            &budget,
            Tool::Systemctl.path(),
            "show",
            "--property=MainPID",
            "--value",
            WATCH,
        ],
    )?
    .map_err(|_| malformed(IoOp::ReadState))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| malformed(IoOp::ReadState))?;
    let digits = text.strip_suffix('\n').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed(IoOp::ReadState));
    }
    let pid = digits
        .parse::<u32>()
        .map_err(|_| malformed(IoOp::ReadState))?;
    Ok(NonZeroU32::new(pid))
}

/// Linux stat field 22, after the possibly parenthesized process name.
pub(crate) fn start_ticks(text: &str, pid: NonZeroU32) -> Result<u64, AgentError> {
    let (prefix, fields) = text
        .rsplit_once(") ")
        .ok_or_else(|| malformed(IoOp::ReadState))?;
    if !prefix.starts_with(&format!("{pid} (")) {
        return Err(malformed(IoOp::ReadState));
    }
    fields
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| malformed(IoOp::ReadState))
}

fn birth(paths: &Paths, pid: NonZeroU32) -> Result<u64, AgentError> {
    let file = File::open(paths.at(&format!("/proc/{pid}/stat")))
        .map_err(|e| io_error(IoOp::ReadState, &e))?;
    let mut text = String::new();
    file.take(16_385)
        .read_to_string(&mut text)
        .map_err(|e| io_error(IoOp::ReadState, &e))?;
    if text.len() > 16_384 {
        return Err(malformed(IoOp::ReadState));
    }
    start_ticks(&text, pid)
}

/// Samples the process, refusing a changing PID, start time or executable.
pub(crate) fn inspect(paths: &Paths, node: &dyn Node) -> Result<WatchRuntime, AgentError> {
    inspect_until(paths, node, Instant::now() + Duration::from_secs(10))
}

fn inspect_until(
    paths: &Paths,
    node: &dyn Node,
    deadline: Instant,
) -> Result<WatchRuntime, AgentError> {
    let agent_sha = own_sha(paths)?;
    let watch = match main_pid(node, deadline)? {
        None => None,
        Some(pid) => {
            let start_ticks = birth(paths, pid)?;
            let path = paths.at(&format!("/proc/{pid}/exe"));
            let executable = File::open(&path).map_err(|e| io_error(IoOp::ReadBlob, &e))?;
            let before = executable
                .metadata()
                .map_err(|e| io_error(IoOp::ReadBlob, &e))?;
            let executable_sha = digest_of(executable).map_err(|e| io_error(IoOp::ReadBlob, &e))?;
            if main_pid(node, deadline)? != Some(pid) || birth(paths, pid)? != start_ticks {
                return Err(malformed(IoOp::ReadState));
            }
            let after = File::open(path)
                .and_then(|file| file.metadata())
                .map_err(|e| io_error(IoOp::ReadBlob, &e))?;
            if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
                return Err(malformed(IoOp::ReadState));
            }
            Some(WatchProcess {
                pid,
                start_ticks,
                executable_sha,
            })
        }
    };
    Ok(WatchRuntime {
        at: node.now(),
        agent_sha,
        watch,
    })
}

/// Converges only the watch, after any pending transaction is confirmed.
/// `systemctl restart` is bounded to 15 s; verification retries for 10 s
/// only when the process is absent or /proc reports ENOENT while starting.
pub(crate) fn refresh(
    paths: &Paths,
    node: &dyn Node,
    expected: Sha256Hex,
) -> Result<WatchRuntime, AgentError> {
    let _lock = crate::txn::exclusive(paths)?;
    let actual = own_sha(paths)?;
    if actual != expected {
        return Err(AgentError::AgentShaMismatch { expected, actual });
    }
    let current = File::open(paths.agent_current()).map_err(|e| io_error(IoOp::ReadBlob, &e))?;
    let actual = digest_of(current).map_err(|e| io_error(IoOp::ReadBlob, &e))?;
    if actual != expected {
        return Err(AgentError::AgentShaMismatch { expected, actual });
    }
    let before = inspect(paths, node)?;
    if matches_expected(&before, expected) {
        return Ok(before);
    }
    run_ok(
        node,
        Tool::Timeout,
        &[
            "--kill-after=1s",
            "15s",
            Tool::Systemctl.path(),
            "restart",
            WATCH,
        ],
    )?
    .map_err(|_| AgentError::Systemd {
        unit: UnitName::watch(),
        op: SystemdOp::Restart,
    })?;
    let deadline = Instant::now() + Duration::from_secs(10);
    for attempt in 0..=10 {
        match inspect_until(paths, node, deadline) {
            Ok(runtime) if matches_expected(&runtime, expected) => return Ok(runtime),
            Ok(_) | Err(AgentError::Io { errno: Some(2), .. }) => {}
            Err(AgentError::Io {
                errno: Some(110), ..
            }) => break,
            Err(error) => return Err(error),
        }
        if attempt < 10 {
            node.sleep(Duration::from_secs(1));
        }
    }
    Err(AgentError::WatchNotUpdated { expected })
}

fn matches_expected(runtime: &WatchRuntime, expected: Sha256Hex) -> bool {
    runtime
        .watch
        .as_ref()
        .is_some_and(|watch| watch.executable_sha == expected)
}
