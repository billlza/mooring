// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac peer as WireGuard reports it, from `wg show wgexit dump`
//! (design §11.3): its latest handshake and what it has moved.

use mooring_agent_proto::{AgentError, IoOp, UnixTime, WG_INTERFACE};

use crate::host::{Node, Tool, run_ok};
use crate::store::malformed;

/// The Mac peer, the interface's only one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peer {
    /// Its latest handshake; `None` when none has completed.
    pub(crate) latest_handshake: Option<UnixTime>,
    /// Bytes received from it.
    pub(crate) rx_bytes: u64,
}

/// Reads the peer from `wg show wgexit dump`.
pub(crate) fn peer(node: &dyn Node) -> Result<Peer, AgentError> {
    let stdout = run_ok(node, Tool::Wg, &["show", WG_INTERFACE, "dump"])?
        .map_err(|_| malformed(IoOp::ReadState))?;
    parse_dump(&stdout)
}

/// The peer from a dump: a first line describing the interface (its private
/// key among it, skipped unread), then exactly one tab-separated peer line:
/// public key, preshared key, endpoint, allowed IPs, latest handshake (0 for
/// none), rx, tx and keepalive.
pub(crate) fn parse_dump(dump: &[u8]) -> Result<Peer, AgentError> {
    let text = std::str::from_utf8(dump).map_err(|_| malformed(IoOp::ReadState))?;
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let (Some(_interface), Some(peer), None) = (lines.next(), lines.next(), lines.next()) else {
        return Err(malformed(IoOp::ReadState));
    };
    let fields: Vec<&str> = peer.split('\t').collect();
    let [
        _key,
        _preshared,
        _endpoint,
        _allowed,
        handshake,
        rx,
        _tx,
        _keepalive,
    ] = fields.as_slice()
    else {
        return Err(malformed(IoOp::ReadState));
    };
    let number = |field: &str| field.parse::<u64>().map_err(|_| malformed(IoOp::ReadState));
    let handshake = number(handshake)?;
    Ok(Peer {
        latest_handshake: (handshake > 0).then(|| UnixTime::from_secs(handshake)),
        rx_bytes: number(rx)?,
    })
}
