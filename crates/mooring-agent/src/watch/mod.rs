// SPDX-License-Identifier: GPL-3.0-or-later

//! `watch`, the `mooring-watch` unit (design §11.3), the only process that
//! opens the gate. Every [`WATCH_TICK_SECS`] it reads the Mac peer, carries
//! out a viewer's stop, clears a drain hold the Mac has come back from,
//! opens or closes the gate, reads the host every [`HOST_READING_SECS`],
//! evaluates its conditions, journals what changed since the journal last
//! recorded, and writes its view.
//!
//! What ends it: an `nft` failure (`NftFailed`, design §11.3 step 3), and
//! any reading it needs but cannot take (the installed generation, its
//! `watch.json`, its record, the holds, the halt marker, the host's
//! figures). Its unit restarts it without limit, and `ExecStopPost` closes
//! the gate meanwhile. A WireGuard reading that fails closes the gate
//! (`WgReadFailed`). A state write or journal append that fails is reported
//! (`StateWrite`) and retried at the next tick; until the journal records
//! them, changes stay in the view's difference from what it last recorded.

pub(crate) mod host;
pub(crate) mod status;

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use mooring_agent_proto::{
    AgentError, AgentEventKind, GATE_SET_REREAD_SECS, GateReason, GateState, Generation,
    HANDSHAKE_MAX_AGE_SECS, Halt, Holds, IoOp, MAC_SILENT_SECS, MacDrainHold, NFT_GATE_SET,
    NFT_TABLE, NftCounter, OperatorHold, TxnState, UnixTime, WATCH_TICK_SECS, WG_INTERFACE,
    WatchConditions, WatchConfig, WatchError, WatchErrorKind,
};

use crate::gate::{self, StopRequest};
use crate::host::{Node, Tool, run_ok};
use crate::journal::Journal;
use crate::paths::Paths;
use crate::store::{Lock, malformed, read_json};
use crate::wg::{self, Peer};
use status::{HostReading, Observed, WatchStatus};

/// Seconds between host readings.
pub(crate) const HOST_READING_SECS: u64 = 60;

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

/// The Mac peer's rx as the watch last read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rx {
    bytes: u64,
    /// When it last grew; `None` until it has grown since the watch
    /// started (or since the counter restarted).
    grew_at: Option<UnixTime>,
}

/// What the gate's part of a tick found and did.
#[derive(Debug, Clone, Copy)]
struct GateTick {
    holds: Holds,
    halted: Option<Halt>,
    /// The gate as it was before the tick set it.
    before: GateState,
    gate: GateState,
    /// The error number of a hold write that failed.
    failed: Option<Option<i32>>,
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
        let failed = gated.failed.or(self.write_failed.take());
        let host = self.host_reading(paths, node, now)?;
        let previous_committed = self.view.as_ref().and_then(|view| view.observed.committed);
        let committed = if generation != Generation::ZERO
            && crate::txn::record::record(paths, generation)?.state == TxnState::Committed
            && previous_committed.is_none_or(|previous| previous < generation)
        {
            Some(generation)
        } else {
            previous_committed
        };
        let conditions = self.conditions(
            now,
            config.is_some(),
            peer.as_ref(),
            &gated.holds,
            failed,
            &host,
        )?;
        let observed = Observed {
            boot_id,
            generation,
            gate: gated.gate,
            holds: gated.holds,
            halted: gated.halted,
            committed,
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
            host,
            journaled,
        };
        if let Err(error) = status::write(paths, &view) {
            self.write_failed = Some(errno(&error));
        }
        self.view = Some(view);
        Ok(())
    }

    /// The gate's part of a tick, under `gate.lock`: a viewer's stop is
    /// recorded first, then a drain hold the Mac has come back from is
    /// cleared, and the gate is set. A stop whose hold cannot be written
    /// keeps the gate closed until a later tick records it.
    fn gate_tick(
        &mut self,
        paths: &Paths,
        node: &dyn Node,
        now: UnixTime,
        config: Option<&WatchConfig>,
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
        let before = self.set_gate(node, now, wanted)?;
        Ok(GateTick {
            holds,
            halted,
            before,
            gate: wanted,
            failed,
        })
    }

    /// The conditions of a tick, at most one of each kind.
    fn conditions(
        &self,
        now: UnixTime,
        installed: bool,
        peer: Option<&Result<Peer, AgentError>>,
        holds: &Holds,
        failed: Option<Option<i32>>,
        host: &HostReading,
    ) -> Result<WatchConditions, AgentError> {
        let mut conditions = Vec::new();
        if let Some(Err(_)) = peer {
            conditions.push(WatchError::WgReadFailed);
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
        conditions.extend(host::conditions(host));
        WatchConditions::new(conditions).map_err(|_| malformed(IoOp::WriteState))
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

    fn append(
        &mut self,
        paths: &Paths,
        now: UnixTime,
        events: &[AgentEventKind],
    ) -> Result<(), AgentError> {
        if events.is_empty() {
            return Ok(());
        }
        let journal = match &mut self.journal {
            Some(journal) => journal,
            None => self.journal.insert(Journal::open(paths)?),
        };
        let appended = journal.append(now, events);
        if appended.is_err() {
            // Reopened at the next append, which cuts off anything torn.
            self.journal = None;
        }
        appended
    }

    fn observe_rx(&mut self, now: UnixTime, bytes: u64) {
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
    /// [`WatchConfig::rx_growth_window_secs`].
    fn peer_live(&self, now: UnixTime, peer: &Peer, config: &WatchConfig) -> bool {
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
    /// returns the gate as it was before.
    fn set_gate(
        &mut self,
        node: &dyn Node,
        now: UnixTime,
        wanted: GateState,
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
                let counter = nft(
                    node,
                    &[
                        "-j",
                        "list",
                        "counter",
                        "inet",
                        NFT_TABLE,
                        NftCounter::FlowCap.name(),
                    ],
                )?;
                self.flow_cap =
                    flow_cap(&counter).map_err(|error| Fatal::Nft(error.to_string()))?;
                self.set_read_at = Some(now);
                read
            }
        };
        if known != wanted {
            let element = format!("{{ \"{WG_INTERFACE}\" }}");
            // Only the watch removes the element, which opens the gate
            // (design §11.3); adding it closes the gate.
            let verb = match wanted {
                GateState::Open => "delete",
                GateState::Closed => "add",
            };
            nft(
                node,
                &[verb, "element", "inet", NFT_TABLE, NFT_GATE_SET, &element],
            )?;
        }
        self.gate = Some(wanted);
        Ok(known)
    }

    /// The host, read anew every [`HOST_READING_SECS`] (and at the first
    /// tick, or after the clock stepped back).
    fn host_reading(
        &self,
        paths: &Paths,
        node: &dyn Node,
        now: UnixTime,
    ) -> Result<HostReading, Fatal> {
        match &self.view {
            Some(view)
                if now
                    .secs_since(view.host.at)
                    .is_some_and(|age| age < HOST_READING_SECS) =>
            {
                Ok(view.host)
            }
            _ => Ok(host::read(paths, node, now)?),
        }
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

/// What changed from `before` to `after`, as journal events, causes before
/// effects: a boot; a halt; holds recorded; a commit; a resume; holds
/// cleared; conditions raised, then cleared; the gate.
pub(crate) fn changes(before: &Observed, after: &Observed) -> Vec<AgentEventKind> {
    let mut events = Vec::new();
    if before.boot_id != after.boot_id {
        events.push(AgentEventKind::HostBooted);
    }
    if let Some(halt) = after.halted
        && before.halted != after.halted
    {
        events.push(AgentEventKind::Halted {
            reason: halt.reason,
        });
    }
    let holds = hold_changes(&before.holds, &after.holds);
    for change in &holds {
        if change.recorded() {
            events.push(AgentEventKind::HoldRecorded { hold: change.hold });
        }
    }
    if let Some(generation) = after.committed
        && before.committed != after.committed
    {
        events.push(AgentEventKind::Committed { generation });
    }
    if before.halted.is_some() && after.halted.is_none() {
        events.push(AgentEventKind::Resumed {
            generation: after.generation,
        });
    }
    for change in &holds {
        if change.cleared() {
            events.push(AgentEventKind::HoldCleared { hold: change.hold });
        }
    }
    for condition in after.conditions.iter() {
        if before.conditions.get(condition.kind()).is_none() {
            events.push(AgentEventKind::ConditionRaised {
                condition: *condition,
            });
        }
    }
    for condition in before.conditions.iter() {
        if after.conditions.get(condition.kind()).is_none() {
            events.push(AgentEventKind::ConditionCleared {
                condition: condition.kind(),
            });
        }
    }
    match (before.gate, after.gate) {
        (GateState::Closed, GateState::Open) => events.push(AgentEventKind::GateOpened),
        (GateState::Open, GateState::Closed) => events.push(AgentEventKind::GateClosed),
        (GateState::Open, GateState::Open) | (GateState::Closed, GateState::Closed) => {}
    }
    events
}

/// How one kind of hold differs between two observations.
#[derive(Debug, Clone, Copy)]
struct HoldChange {
    hold: GateReason,
    was: bool,
    is: bool,
    changed: bool,
}

impl HoldChange {
    /// Recorded: present now, and absent or different before (a hold
    /// recorded again, as by a second `GateSet`, is a new recording).
    const fn recorded(self) -> bool {
        self.is && self.changed
    }

    /// Cleared: present before, absent now.
    const fn cleared(self) -> bool {
        self.was && !self.is
    }
}

fn hold_changes(before: &Holds, after: &Holds) -> [HoldChange; 3] {
    [
        HoldChange {
            hold: GateReason::MacDrain,
            was: before.mac_drain.is_some(),
            is: after.mac_drain.is_some(),
            changed: before.mac_drain != after.mac_drain,
        },
        HoldChange {
            hold: GateReason::EgressViolation,
            was: before.egress_violation.is_some(),
            is: after.egress_violation.is_some(),
            changed: before.egress_violation != after.egress_violation,
        },
        HoldChange {
            hold: GateReason::Operator,
            was: before.operator.is_some(),
            is: after.operator.is_some(),
            changed: before.operator != after.operator,
        },
    ]
}

/// Runs `nft`; a failure ends the watch, described with nft's own message,
/// which names no secret.
fn nft(node: &dyn Node, args: &[&str]) -> Result<Vec<u8>, Fatal> {
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

/// The packets the flow cap has rejected, from `nft -j list counter`'s
/// output for its named counter.
fn flow_cap(stdout: &[u8]) -> Result<u64, AgentError> {
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

/// The error number a failed write reports in `StateWrite`.
const fn errno(error: &AgentError) -> Option<i32> {
    match error {
        AgentError::Io { errno, .. } => *errno,
        _ => None,
    }
}
