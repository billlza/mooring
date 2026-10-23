// SPDX-License-Identifier: GPL-3.0-or-later

//! Xray's counters through its API (design §11.5), read with the current
//! generation's own `xray api` from the rendered API listener: `statsquery`
//! with the pattern `user>>>` and no reset, and `statssys`.
//!
//! What the pinned source prints (Xray v26.9.30 `b26a91de`,
//! `main/commands/all/api` and `common/reflect/marshal.go`, read on
//! 2026-10-23): indented JSON from a reflection walker that leaves out
//! every zero or empty field, numbers as JSON numbers. `statsquery` prints
//! `{"stat":[{"name":…,"value":…}]}` in no particular order, a counter at
//! zero without its `"value"`, and `{}` when nothing matches; the pattern
//! is a substring. `statssys` prints the Go runtime's figures by their
//! field names; `Uptime` is whole seconds since the stats service started
//! with the process. A failure is a message on stderr and exit status 1.

use std::collections::BTreeMap;
use std::path::Path;

use mooring_agent_proto::{StatsEmail, Traffic};
use serde::Deserialize;

use crate::host::Node;
use crate::paths::Paths;
use crate::txn::stage::{XRAY, program};

/// The API listener the rendered configuration opens (design §8.2).
pub(crate) const XRAY_API_SERVER: &str = "--server=127.0.0.1:10085";

/// The counter names `statsquery` is asked for.
const USER_PATTERN: &str = "user>>>";

/// A query that failed or printed what the pinned source never prints:
/// `StatsQueryFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueryFailed;

/// `statssys`'s figures the watch uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SysStats {
    /// Seconds since the stats service started.
    pub(crate) uptime_secs: u64,
    /// The Go runtime's heap in use, in bytes (`Alloc`).
    pub(crate) alloc_bytes: u64,
}

/// Every accounting email's counters, those at zero included: a counter
/// exists once the email's first connection is dispatched.
pub(crate) fn query(
    paths: &Paths,
    node: &dyn Node,
) -> Result<BTreeMap<StatsEmail, Traffic>, QueryFailed> {
    let pattern = format!("-pattern={USER_PATTERN}");
    parse_query(&api(
        paths,
        node,
        &["api", "statsquery", XRAY_API_SERVER, &pattern],
    )?)
}

/// `statssys`.
pub(crate) fn sys(paths: &Paths, node: &dyn Node) -> Result<SysStats, QueryFailed> {
    parse_sys(&api(paths, node, &["api", "statssys", XRAY_API_SERVER])?)
}

fn api(paths: &Paths, node: &dyn Node, args: &[&str]) -> Result<Vec<u8>, QueryFailed> {
    let xray = program(&paths.current(), XRAY);
    match node.run_program(Path::new(&xray), args, &[]) {
        Ok(output) if output.success => Ok(output.stdout),
        Ok(_) | Err(_) => Err(QueryFailed),
    }
}

/// `statsquery`'s reply. A missing `stat` or `value` is how the source
/// prints an empty list and a zero.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryReply {
    #[serde(default)]
    stat: Vec<Stat>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stat {
    name: String,
    #[serde(default)]
    value: u64,
}

/// The counters from `statsquery`'s output: each name is
/// `user>>>EMAIL>>>traffic>>>uplink` or `…>>>downlink`, once, with an
/// email the renderer writes ([`StatsEmail`]), and every email has both.
pub(crate) fn parse_query(stdout: &[u8]) -> Result<BTreeMap<StatsEmail, Traffic>, QueryFailed> {
    let reply: QueryReply = serde_json::from_slice(stdout).map_err(|_| QueryFailed)?;
    let mut counters: BTreeMap<StatsEmail, (Option<u64>, Option<u64>)> = BTreeMap::new();
    for stat in reply.stat {
        let rest = stat.name.strip_prefix(USER_PATTERN).ok_or(QueryFailed)?;
        let (email, direction) = rest.split_once(">>>traffic>>>").ok_or(QueryFailed)?;
        let email: StatsEmail = email.parse().map_err(|_| QueryFailed)?;
        let (uplink, downlink) = counters.entry(email).or_default();
        let slot = match direction {
            "uplink" => uplink,
            "downlink" => downlink,
            _ => return Err(QueryFailed),
        };
        if slot.replace(stat.value).is_some() {
            return Err(QueryFailed);
        }
    }
    // The rendered policy counts both directions, and Xray registers an
    // email's two counters together, so one alone is not that policy.
    counters
        .into_iter()
        .map(|(email, counted)| match counted {
            (Some(uplink), Some(downlink)) => Ok((email, Traffic { uplink, downlink })),
            _ => Err(QueryFailed),
        })
        .collect()
}

/// The figures from `statssys`'s output: `Uptime` and `Alloc`, each absent
/// when zero; its other figures are not read.
pub(crate) fn parse_sys(stdout: &[u8]) -> Result<SysStats, QueryFailed> {
    let reply: serde_json::Value = serde_json::from_slice(stdout).map_err(|_| QueryFailed)?;
    let object = reply.as_object().ok_or(QueryFailed)?;
    let figure = |key: &str| match object.get(key) {
        None => Ok(0),
        Some(value) => value.as_u64().ok_or(QueryFailed),
    };
    Ok(SysStats {
        uptime_secs: figure("Uptime")?,
        alloc_bytes: figure("Alloc")?,
    })
}
