// SPDX-License-Identifier: GPL-3.0-or-later

//! The gate's part of a tick (design §11.3): the Mac peer's rx observed;
//! then, under `gate.lock`, a viewer's stop recorded, a drain hold the Mac
//! has come back from cleared, and the gate set: open only for a live peer,
//! with a generation installed, no hold, no halt and no stop left
//! unrecorded. The gate set is re-read, with the flow-cap counter the
//! conditions report, when it is unknown, when [`GATE_SET_REREAD_SECS`]
//! have passed, or when the clock has stepped back.
//!
//! With a generation that carries the abuse guard (design §11.8), the gate
//! opens in the same nft transaction that sets the cut set to the cut
//! users' addresses, read from the abuse state under the same lock: a
//! ruleset load empties the cut set and closes the gate together, so the
//! gate is never open with a cut missing. At every re-read the cut set is
//! set again from the state, which undoes any change made to it by hand.

use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AgentError, GATE_SET_REREAD_SECS, GateState, HANDSHAKE_MAX_AGE_SECS, Halt, Holds,
    InstalledWatchConfig, MacDrainHold, NFT_GATE_SET, NFT_TABLE, NftCounter, OperatorHold,
    UnixTime, WG_INTERFACE,
};

use super::nft::{counter, nft};
use super::{Fatal, Watch};
use crate::abuse::state::AbuseState;
use crate::abuse::{as_args, cut_addresses, open_words, served_sources, sync_words};
use crate::gate::{self, StopRequest};
use crate::host::Node;
use crate::paths::Paths;
use crate::store::{Lock, errno, read_json};
use crate::wg::Peer;

/// The Mac peer's rx as the watch last read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Rx {
    bytes: u64,
    /// When it last grew; `None` until it has grown since the watch
    /// started (or since the counter restarted).
    grew_at: Option<UnixTime>,
}

/// What the gate's part of a tick found and did.
#[derive(Debug, Clone, Copy)]
pub(super) struct GateTick {
    pub(super) holds: Holds,
    pub(super) halted: Option<Halt>,
    /// The gate as it was before the tick set it.
    pub(super) before: GateState,
    pub(super) gate: GateState,
    /// The error number of a hold write that failed.
    pub(super) failed: Option<Option<i32>>,
}

impl Watch {
    /// The gate's part of a tick, under `gate.lock`: a viewer's stop is
    /// recorded first, then a drain hold the Mac has come back from is
    /// cleared, and the gate is set. A stop whose hold cannot be written
    /// keeps the gate closed until a later tick records it.
    pub(super) fn gate_tick(
        &mut self,
        paths: &Paths,
        node: &dyn Node,
        now: UnixTime,
        config: Option<&InstalledWatchConfig>,
        peer: Option<&Result<Peer, AgentError>>,
    ) -> Result<GateTick, Fatal> {
        let _lock = Lock::exclusive(&paths.gate_lock())?;
        let mut holds = gate::holds(paths)?;
        let halted = gate::halted(paths)?;
        let mut failed = None;
        let mut stop_unrecorded = false;
        if let Some(request) = read_json::<StopRequest>(&paths.stop_request())? {
            // A request whose hold an earlier tick recorded, but could not
            // remove, is not recorded again.
            let carried_out = holds.operator.is_some_and(|hold| hold.at >= request.at);
            let recorded = if carried_out {
                Ok(())
            } else {
                let recorded = Holds {
                    operator: Some(OperatorHold {
                        at: now.max(request.at),
                    }),
                    ..holds
                };
                gate::write_holds(paths, &recorded).map(|()| holds = recorded)
            };
            match recorded.and_then(|()| crate::store::remove(&paths.stop_request())) {
                Ok(()) => {}
                Err(error) => {
                    stop_unrecorded = holds.operator.is_none_or(|hold| hold.at < request.at);
                    failed = Some(errno(&error));
                }
            }
        }
        if let Some(drain) = holds.mac_drain
            && self.drain_cleared(drain, peer)
        {
            let cleared = Holds {
                mac_drain: None,
                ..holds
            };
            match gate::write_holds(paths, &cleared) {
                Ok(()) => holds = cleared,
                Err(error) => failed = Some(errno(&error)),
            }
        }
        let Some(config) = config else {
            // No generation: no ruleset of Mooring's, nothing can exit.
            return Ok(GateTick {
                holds,
                halted,
                before: GateState::Closed,
                gate: GateState::Closed,
                failed,
            });
        };
        let live = peer.is_some_and(|peer| {
            peer.as_ref()
                .is_ok_and(|peer| self.peer_live(now, peer, config))
        });
        let wanted = if live && !stop_unrecorded && holds.is_empty() && halted.is_none() {
            GateState::Open
        } else {
            GateState::Closed
        };
        let cut = match config.abuse_guard() {
            Some(_) => Some(cut_addresses(
                AbuseState::read(paths)?.cuts(),
                &served_sources(config),
            )),
            None => None,
        };
        let before = self.set_gate(node, now, wanted, cut.as_deref())?;
        Ok(GateTick {
            holds,
            halted,
            before,
            gate: wanted,
            failed,
        })
    }

    pub(super) fn observe_rx(&mut self, now: UnixTime, bytes: u64) {
        self.rx = Some(match self.rx {
            Some(previous) if bytes > previous.bytes => Rx {
                bytes,
                grew_at: Some(now),
            },
            Some(previous) if bytes == previous.bytes => previous,
            // The first reading, or a counter that restarted with the
            // interface: growth is counted from here.
            Some(_) | None => Rx {
                bytes,
                grew_at: None,
            },
        });
    }

    /// Whether the peer lets the gate open: a handshake at most
    /// [`HANDSHAKE_MAX_AGE_SECS`] old and rx grown within
    /// [`InstalledWatchConfig::rx_growth_window_secs`].
    fn peer_live(&self, now: UnixTime, peer: &Peer, config: &InstalledWatchConfig) -> bool {
        let fresh = peer
            .latest_handshake
            .and_then(|handshake| now.secs_since(handshake))
            .is_some_and(|age| age <= HANDSHAKE_MAX_AGE_SECS);
        let growing = self
            .rx
            .and_then(|rx| rx.grew_at)
            .and_then(|grew| now.secs_since(grew))
            .is_some_and(|age| age <= config.rx_growth_window_secs());
        fresh && growing
    }

    /// Whether the drain hold has cleared: the handshake differs from the
    /// one at the drain and rx has grown since the watch first saw the
    /// hold.
    fn drain_cleared(
        &mut self,
        drain: MacDrainHold,
        peer: Option<&Result<Peer, AgentError>>,
    ) -> bool {
        let Some(Ok(peer)) = peer else {
            return false;
        };
        match self.drain {
            Some((watched, base)) if watched == drain => {
                peer.latest_handshake != drain.handshake_at_drain && peer.rx_bytes > base
            }
            _ => {
                self.drain = Some((drain, peer.rx_bytes));
                false
            }
        }
    }

    /// Sets the gate to `wanted`, re-reading the set (and the flow-cap
    /// counter) when it is unknown or [`GATE_SET_REREAD_SECS`] have passed;
    /// returns the gate as it was before. With the abuse guard, `cut` is
    /// what the cut set must hold: the gate opens in the transaction that
    /// sets it, and every re-read sets it again.
    fn set_gate(
        &mut self,
        node: &dyn Node,
        now: UnixTime,
        wanted: GateState,
        cut: Option<&[Ipv4Addr]>,
    ) -> Result<GateState, Fatal> {
        let due = self.set_read_at.is_none_or(|read| {
            now.secs_since(read)
                .is_none_or(|age| age >= GATE_SET_REREAD_SECS)
        });
        let known = match self.gate {
            Some(known) if !due => known,
            _ => {
                let set = nft(
                    node,
                    &["-j", "list", "set", "inet", NFT_TABLE, NFT_GATE_SET],
                )?;
                let read = gate::parse_set(&set).map_err(|error| Fatal::Nft(error.to_string()))?;
                self.flow_cap = counter(node, NftCounter::FlowCap)?;
                self.set_read_at = Some(now);
                read
            }
        };
        match (known != wanted, wanted, cut) {
            // Only the watch removes the element, which opens the gate
            // (design §11.3), and with the guard it sets the cut set in the
            // same transaction.
            (true, GateState::Open, Some(cut)) => {
                nft(node, &as_args(&open_words(cut)))?;
            }
            (true, _, _) => {
                let element = format!("{{ \"{WG_INTERFACE}\" }}");
                // Adding the element closes the gate.
                let verb = match wanted {
                    GateState::Open => "delete",
                    GateState::Closed => "add",
                };
                nft(
                    node,
                    &[verb, "element", "inet", NFT_TABLE, NFT_GATE_SET, &element],
                )?;
                if let (true, Some(cut)) = (due, cut) {
                    nft(node, &as_args(&sync_words(cut)))?;
                }
            }
            (false, _, Some(cut)) if due => {
                nft(node, &as_args(&sync_words(cut)))?;
            }
            (false, _, _) => {}
        }
        self.gate = Some(wanted);
        Ok(known)
    }
}
