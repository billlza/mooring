// SPDX-License-Identifier: GPL-3.0-or-later

//! `watch`, the `mooring-watch` unit (design §11.3), the only process that
//! opens the gate. Every [`WATCH_TICK_SECS`] it reads the Mac peer, carries
//! out a viewer's stop, clears a drain hold the Mac has come back from,
//! opens or closes the gate, takes a reading every [`HOST_READING_SECS`]
//! (the host, the engine units, the uplink's transfer, and accounting,
//! design §11.5), evaluates its conditions, journals what changed since the
//! journal last recorded, and writes its view.
//!
//! What ends it: an `nft` failure (`NftFailed`, design §11.3 step 3), and
//! any reading it needs but cannot take (the installed generation, its
//! `watch.json` and record, the holds, the halt marker, the host's
//! figures, the engine units, the uplink's counters). Its unit restarts it
//! without limit, and `ExecStopPost` closes the gate meanwhile.
//! A WireGuard reading that fails closes the gate (`WgReadFailed`); Xray's
//! API failing is `StatsQueryFailed`. The hourly target check's result
//! that cannot be read is `TargetReadFailed`, read again at the next tick:
//! it says nothing of the watch's own work (2026-11-03; it used to end the
//! watch, which then failed at every restart, the gate closed, until the
//! check next wrote its result). A state write, journal append or usage
//! file that fails is reported (`StateWrite`) and retried at the next
//! tick or reading; until the journal records them, changes stay in the
//! view's difference from what it last recorded, so each is journaled at
//! least once (twice when an append fails after its lines reached the file).

mod conditions;
pub(crate) mod engines;
mod gating;
pub(crate) mod host;
pub(crate) mod journaling;
pub(crate) mod nft;
mod reading;
pub(crate) mod status;
pub(crate) mod transfer;

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use mooring_agent_proto::{
    ACCOUNTING_INTERVAL_SECS, AgentError, GateState, Generation, IoOp, MacDrainHold, TxnState,
    UnixTime, WATCH_TICK_SECS, WatchConditions, WatchConfig, WatchError, WatchErrorKind,
};

use crate::gate;
use crate::host::Node;
use crate::journal::Journal;
use crate::paths::Paths;
use crate::store::{errno, malformed, read_json};
use crate::wg;
use conditions::Installed;
use gating::Rx;
use journaling::changes;
use status::{EngineRestarts, Observed, WatchStatus};

/// Seconds between readings: the accounting interval (design §11.3 step
/// 4), at which the host is read too.
pub(crate) const HOST_READING_SECS: u64 = ACCOUNTING_INTERVAL_SECS;

/// What ends the watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fatal {
    /// `nft` failed, as described.
    Nft(String),
    /// A reading the watch needs failed.
    Reading(AgentError),
}

impl From<AgentError> for Fatal {
    fn from(error: AgentError) -> Self {
        Self::Reading(error)
    }
}

/// The watch between ticks.
#[derive(Debug)]
pub(crate) struct Watch {
    /// The view of the latest tick, or the one found at start.
    view: Option<WatchStatus>,
    /// The journal, opened at the first append and again after a failed
    /// one.
    journal: Option<Journal>,
    /// The gate as last read or set; `None` until read.
    gate: Option<GateState>,
    /// When the gate set and the flow-cap counter were last read.
    set_read_at: Option<UnixTime>,
    /// The flow-cap counter at that reading.
    flow_cap: u64,
    rx: Option<Rx>,
    /// The drain hold being watched, and the rx when it was first seen.
    drain: Option<(MacDrainHold, u64)>,
    /// The error number of a state write that failed in the latest tick.
    write_failed: Option<Option<i32>>,
}

/// Runs the watch until something ends it.
pub(crate) fn run(paths: &Paths, node: &dyn Node, stderr: &mut dyn Write) -> ExitCode {
    let mut watch = match Watch::start(paths) {
        Ok(watch) => watch,
        Err(error) => return crate::fail(stderr, &format!("the watch cannot start: {error}")),
    };
    loop {
        match watch.tick(paths, node) {
            Ok(()) => node.sleep(Duration::from_secs(WATCH_TICK_SECS)),
            Err(Fatal::Nft(error)) => {
                if let Err(recording) = watch.record_nft_failure(paths, node) {
                    crate::fail(stderr, &format!("recording NftFailed failed: {recording}"));
                }
                return crate::fail(stderr, &format!("nft failed: {error}"));
            }
            Err(Fatal::Reading(error)) => {
                return crate::fail(
                    stderr,
                    &format!("a reading the watch needs failed: {error}"),
                );
            }
        }
    }
}

impl Watch {
    /// The watch as it starts, from its latest view.
    pub(crate) fn start(paths: &Paths) -> Result<Self, AgentError> {
        Ok(Self {
            view: status::read(paths)?,
            journal: None,
            gate: None,
            set_read_at: None,
            flow_cap: 0,
            rx: None,
            drain: None,
            write_failed: None,
        })
    }

    /// One tick.
    pub(crate) fn tick(&mut self, paths: &Paths, node: &dyn Node) -> Result<(), Fatal> {
        let now = node.now();
        let boot_id = boot_id(paths)?;
        let generation = gate::current_generation(paths)?;
        let config = if generation == Generation::ZERO {
            None
        } else {
            Some(
                read_json::<WatchConfig>(&paths.watch_config())?
                    .ok_or(malformed(IoOp::ReadState))?,
            )
        };
        let peer = config.as_ref().map(|_| wg::peer(node));
        if let Some(Ok(peer)) = &peer {
            self.observe_rx(now, peer.rx_bytes);
        }
        let gated = self.gate_tick(paths, node, now, config.as_ref(), peer.as_ref())?;
        let reading = self.reading(paths, node, now, &boot_id, config.as_ref())?;
        let failed = gated
            .failed
            .or(reading.accounting.failed.map(|failure| failure.errno))
            .or(self.write_failed.take());
        let previous_committed = self.view.as_ref().and_then(|view| view.observed.committed);
        let committed = if generation != Generation::ZERO
            && crate::txn::record::record(paths, generation)?.state == TxnState::Committed
            && previous_committed.is_none_or(|previous| previous < generation)
        {
            Some(generation)
        } else {
            previous_committed
        };
        let installed = config.as_ref().map(|config| Installed {
            target: crate::target::hourly::verdict(paths, &config.target),
        });
        let conditions = self.conditions(
            now,
            installed,
            peer.as_ref(),
            &gated.holds,
            failed,
            &reading,
        )?;
        let observed = Observed {
            boot_id,
            generation,
            gate: gated.gate,
            holds: gated.holds,
            halted: gated.halted,
            committed,
            restarts: EngineRestarts::of(&reading.engines),
            conditions,
        };
        let journaled = match &self.view {
            Some(view) => view.journaled.clone(),
            // The first tick ever: what it finds is the baseline, so only
            // its conditions and what it does to the gate are news.
            None => Observed {
                gate: gated.before,
                conditions: WatchConditions::default(),
                ..observed.clone()
            },
        };
        let events = changes(&journaled, &observed);
        let journaled = match self.append(paths, now, &events) {
            Ok(()) => observed.clone(),
            Err(error) => {
                self.write_failed = Some(errno(&error));
                journaled
            }
        };
        let view = WatchStatus {
            at: now,
            observed,
            latest_handshake: match &peer {
                Some(Ok(peer)) => peer.latest_handshake,
                None | Some(Err(_)) => None,
            },
            host: reading.host,
            engines: reading.engines,
            transfer: reading.transfer,
            accounting: reading.accounting,
            journaled,
        };
        if let Err(error) = status::write(paths, &view) {
            self.write_failed = Some(errno(&error));
        }
        self.view = Some(view);
        Ok(())
    }

    /// Records `NftFailed` before the watch exits: in its view, and in the
    /// journal if it is not recorded already.
    fn record_nft_failure(&mut self, paths: &Paths, node: &dyn Node) -> Result<(), AgentError> {
        let Some(mut view) = self.view.clone() else {
            return Ok(());
        };
        let now = node.now();
        let mut conditions: Vec<WatchError> = view
            .observed
            .conditions
            .iter()
            .copied()
            .filter(|condition| condition.kind() != WatchErrorKind::NftFailed)
            .collect();
        conditions.push(WatchError::NftFailed);
        view.observed.conditions =
            WatchConditions::new(conditions).map_err(|_| malformed(IoOp::WriteState))?;
        view.at = now;
        let events = changes(&view.journaled, &view.observed);
        let appended = self.append(paths, now, &events);
        if appended.is_ok() {
            view.journaled = view.observed.clone();
        }
        let written = status::write(paths, &view);
        self.view = Some(view);
        appended.and(written)
    }
}

/// The kernel's boot id.
fn boot_id(paths: &Paths) -> Result<String, AgentError> {
    let text = std::fs::read_to_string(paths.proc_sys("kernel/random/boot_id"))
        .map_err(|error| crate::store::io_error(IoOp::ReadState, &error))?;
    let id = text.trim();
    if id.is_empty() {
        Err(malformed(IoOp::ReadState))
    } else {
        Ok(id.to_owned())
    }
}
