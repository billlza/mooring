// SPDX-License-Identifier: GPL-3.0-or-later

//! The conditions a tick raises (design §11.3), at most one of each kind:
//! from the peer, the target check, accounting, the flow cap, a failed
//! write, the Mac's silence and the host's figures.

use mooring_agent_proto::{
    AgentError, Holds, Inbound, InboundSet, IoOp, MAC_SILENT_SECS, UnixTime, WatchConditions,
    WatchError, WatchErrorKind,
};

use super::reading::Reading;
use super::{Watch, host};
use crate::store::malformed;
use crate::wg::Peer;

/// What a tick knows of the installed generation.
#[derive(Debug, Clone, Copy)]
pub(super) struct Installed {
    /// The hourly target check's latest result about the configured target
    /// was a failure (design §11.3).
    pub(super) target_degraded: bool,
}

impl Watch {
    /// The conditions of a tick, at most one of each kind; `installed` is
    /// `None` before the first `Apply`.
    pub(super) fn conditions(
        &self,
        now: UnixTime,
        installed: Option<Installed>,
        peer: Option<&Result<Peer, AgentError>>,
        holds: &Holds,
        failed: Option<Option<i32>>,
        reading: &Reading,
    ) -> Result<WatchConditions, AgentError> {
        let mut conditions = Vec::new();
        if let Some(Err(_)) = peer {
            conditions.push(WatchError::WgReadFailed);
        }
        if installed.is_some_and(|installed| installed.target_degraded) {
            conditions.push(WatchError::TargetDegraded);
        }
        let installed = installed.is_some();
        if installed && reading.accounting.query_failed {
            conditions.push(WatchError::StatsQueryFailed);
        }
        if installed && reading.accounting.canary_missing {
            // The evidence, a probe flow, does not say which inbound it
            // came through (design §11.5).
            let inbounds = Inbound::ALL
                .iter()
                .fold(InboundSet::of(Inbound::ALL[0]), |set, inbound| {
                    set.with(*inbound)
                });
            conditions.push(WatchError::AccountingCanaryMissing { inbounds });
        }
        if installed && self.flow_cap > 0 {
            conditions.push(WatchError::ExitFlowCapHit {
                count: self.flow_cap,
            });
        }
        if let Some(errno) = failed {
            conditions.push(WatchError::StateWrite { errno });
        }
        if let Some(silent) = self.mac_silent(now, peer, holds) {
            conditions.push(silent);
        }
        conditions.extend(host::conditions(&reading.host));
        WatchConditions::new(conditions).map_err(|_| malformed(IoOp::WriteState))
    }

    /// `MacSilent` with a generation installed and no operator hold, once
    /// the handshake is older than [`MAC_SILENT_SECS`] or none has
    /// completed. While WireGuard cannot be read the handshake is unknown,
    /// so the condition stays as it was.
    fn mac_silent(
        &self,
        now: UnixTime,
        peer: Option<&Result<Peer, AgentError>>,
        holds: &Holds,
    ) -> Option<WatchError> {
        match peer {
            None => None,
            Some(Err(_)) => self
                .view
                .as_ref()
                .and_then(|view| {
                    view.observed
                        .conditions
                        .get(WatchErrorKind::MacSilent)
                        .copied()
                })
                .filter(|_| holds.operator.is_none()),
            Some(Ok(peer)) => {
                let silent = peer.latest_handshake.is_none_or(|handshake| {
                    now.secs_since(handshake)
                        .is_some_and(|age| age > MAC_SILENT_SECS)
                });
                (silent && holds.operator.is_none()).then_some(WatchError::MacSilent {
                    since: peer.latest_handshake,
                })
            }
        }
    }
}
