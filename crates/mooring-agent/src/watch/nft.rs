// SPDX-License-Identifier: GPL-3.0-or-later

//! The watch's `nft` runner, through which gating lists the gate set and
//! changes its element, and the named counters (the flow cap's and the
//! probe flows'), read and parsed. A call that fails ends the watch
//! (`NftFailed`, design §11.3 step 3).

use mooring_agent_proto::{AgentError, IoOp, NFT_TABLE, NftCounter};

use super::Fatal;
use crate::host::{Node, Tool, run_ok};
use crate::store::malformed;

/// Runs `nft`; a failure ends the watch, described with nft's own message,
/// which names no secret.
pub(super) fn nft(node: &dyn Node, args: &[&str]) -> Result<Vec<u8>, Fatal> {
    match run_ok(node, Tool::Nft, args) {
        Ok(Ok(stdout)) => Ok(stdout),
        Ok(Err(stderr)) => Err(Fatal::Nft(format!(
            "nft {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&stderr).trim_end()
        ))),
        Err(error) => Err(Fatal::Nft(format!("nft {}: {error}", args.join(" ")))),
    }
}

/// A named counter's packets.
pub(super) fn counter(node: &dyn Node, counter: NftCounter) -> Result<u64, Fatal> {
    let stdout = nft(
        node,
        &["-j", "list", "counter", "inet", NFT_TABLE, counter.name()],
    )?;
    counter_packets(&stdout).map_err(|error| Fatal::Nft(error.to_string()))
}

/// The packets in `nft -j list counter`'s output for one named counter.
pub(crate) fn counter_packets(stdout: &[u8]) -> Result<u64, AgentError> {
    let listing: serde_json::Value =
        serde_json::from_slice(stdout).map_err(|_| malformed(IoOp::ReadState))?;
    let counters: Vec<u64> = listing["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("counter"))
        .filter_map(|counter| counter.get("packets").and_then(serde_json::Value::as_u64))
        .collect();
    match counters.as_slice() {
        [packets] => Ok(*packets),
        _ => Err(malformed(IoOp::ReadState)),
    }
}
