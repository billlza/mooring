// SPDX-License-Identifier: GPL-3.0-or-later

//! The hourly target check (design §11.3): `target-watch`, which
//! `mooring-target-check.service` and its timer run as a unit of their
//! own, because `xray tls ping` sets no time limit and a target that does
//! not answer must not hold up the watch's loop. It probes the configured
//! address, not the first of the set the name resolves to, through the
//! current generation's Xray and without the handshake sampler, and
//! records its verdict, which the watch reads at every tick through
//! [`degraded`].

use mooring_agent_proto::{
    AgentError, HttpProbe, HttpVersion, IoOp, UnixTime, WatchConfig, WatchTarget,
};
use serde::{Deserialize, Serialize};

use super::probes::{TlsPing, http_probe, resolve, tls_ping};
use crate::host::Node;
use crate::paths::Paths;
use crate::store::{read_json, write_json};
use crate::txn::stage::{self, XRAY};

/// The hourly check's latest result (`/var/lib/mooring/watch/target.json`),
/// with the target it checked: a result about another target than the
/// configured one says nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetReading {
    /// When it was checked.
    pub(crate) at: UnixTime,
    /// What was checked.
    pub(crate) target: WatchTarget,
    /// Whether the check failed (`TargetDegraded`).
    pub(crate) degraded: bool,
}

/// The reading's mode: the state group reads it.
const READING_MODE: u32 = 0o640;

/// `target-watch`, the hourly unit: checks the configured target with the
/// current generation's Xray and records the result. The target is
/// degraded when its name no longer resolves to the configured address,
/// when the TLS handshake with it does not complete, or when it does not
/// answer over HTTP/2.
pub(crate) fn watch(paths: &Paths, node: &dyn Node) -> Result<TargetReading, AgentError> {
    let config: WatchConfig =
        read_json(&paths.watch_config())?.ok_or(crate::store::malformed(IoOp::ReadState))?;
    let target = config.target;
    let xray = stage::program(&paths.current(), XRAY);
    let degraded = match resolve(node, &target.host) {
        Ok(resolved) if resolved.contains(&target.ipv4) => {
            let tls = tls_ping(node, &xray, &target.host, target.ipv4);
            let http = http_probe(node, &target.host, target.ipv4);
            !matches!(tls, Ok(TlsPing::Completed(_)))
                || !matches!(
                    http,
                    Ok(HttpProbe::Responded {
                        version: HttpVersion::Http2,
                        ..
                    })
                )
        }
        Ok(_) | Err(_) => true,
    };
    let reading = TargetReading {
        at: node.now(),
        target,
        degraded,
    };
    write_json(&paths.target_reading(), &reading, READING_MODE)?;
    Ok(reading)
}

/// Whether the latest hourly check found `target` degraded; no check of it
/// yet is no news.
pub(crate) fn degraded(paths: &Paths, target: &WatchTarget) -> Result<bool, AgentError> {
    Ok(read_json::<TargetReading>(&paths.target_reading())?
        .is_some_and(|reading| reading.target == *target && reading.degraded))
}
