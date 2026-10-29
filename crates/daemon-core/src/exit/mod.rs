// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit's state machine (design §10.1, §10.2): from what the daemon
//! observes at each tick, it decides whether `mooring-exit` runs, probes
//! the carrier address, latches violations and says what the nodes must be
//! told. Every effect goes through [`ExitPorts`], which `mooringctl`
//! implements over the engine, the sockets, the latch file and the
//! operations key's sessions, and the tests over a script.
//!
//! # Preflight
//!
//! The engine runs only while every check passes, in this order; the first
//! that fails stops it and is the exit's [`DownReason`]:
//!
//! 1. the operator enabled the exit (`exit enable`), else `Disabled`;
//! 2. the SIM plan is recorded (`SimPlanUnrecorded`) and the cycle's bytes
//!    are below the hard stop (`SimCapReached`, until the cycle resets);
//! 3. the egress (and a separate uplink) resolve;
//! 4. no foreign network is attached (P0-2): CFM's TUN and the operator's
//!    declared own networks are allowed and reported, not foreign
//!    ([`crate::network`]);
//! 5. the carrier check is recorded (`CarrierCheckUnrecorded`);
//! 6. no violation is latched;
//! 7. a node has confirmed a configuration (`NoAppliedNode`);
//! 8. the latest direct probe succeeded and its address passed
//!    [`direct_verdict`]; a violation is latched at once. While the engine
//!    runs, one failed round is tolerated and a second stops it
//!    (`DirectProbeFailed`); before it starts, one failed round does;
//! 9. the config renders (`SecretsUnavailable`, `NoAppliedNode`).
//!
//! # Supervision
//!
//! The engine restarts only when the rendered config's digest changes. A
//! config check that fails, a spawn that fails, or an engine that exits
//! within [`START_GRACE`] keeps it stopped (`EngineConfigRejected`,
//! `EngineSpawnFailed`, `EngineStartFailed`) until the digest changes or
//! the operator retries. An engine that exits after that is started again
//! after 1, 2, 4 … [`MAX_BACKOFF`] seconds; the [`CRASH_LIMIT`]th exit
//! within [`CRASH_WINDOW`] is `EngineCrashLoop`, held the same way.
//!
//! # Violations
//!
//! A violation stops the engine first (local, no network), then persists
//! the latch, then asks every node with a site to close its gate
//! (`GateSet{Closed, EgressViolation}`), or to halt (`Shutdown`) for the
//! node whose address the egress showed. Calls that fail are tried again
//! every [`NODE_CALL_RETRY`]; a node that refuses one is not asked again.
//! The latch clears only on a retry, another `config_generation`, or
//! another egress identity; the nodes are then asked to clear their holds
//! (`ClearHold{EgressViolation}`) once a fresh direct probe has passed.
//!
//! # In-chain probes
//!
//! While the engine runs, `mooring-probe` runs beside it ([`in_chain`]):
//! [`IN_CHAIN_FIRST`] after the engine starts, and then every
//! `in_chain_every` (300 s), each applied node is probed through each
//! protocol, bracketed by direct probes. A violation is latched as above; a
//! probe that fails, or a carrier address that will not hold still,
//! degrades the exit, naming the node and protocol; a round that verifies
//! makes it `Serving`. `mooring-probe` failing only degrades: it never takes
//! the exit down.
//!
//! # Sleep
//!
//! When macOS is about to sleep (design §10.3), [`ExitMachine::sleep`]
//! stops `mooring-exit` first, which needs no network, then asks every node
//! with a site to close its gate and hold it for the Mac's drain
//! (`GateSet{Closed, MacDrain}`) while its budget lasts, and the exit is
//! `Paused`: no tick starts the engine again, so no handshake can complete
//! between the drain and the sleep, until [`ExitMachine::wake`]. The next
//! tick after that runs the preflight with a fresh direct probe.

mod in_chain;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use mooring_model::collections::NonEmpty;
use mooring_model::date::CalendarDate;
use mooring_model::exit::EgressCheck;
use mooring_model::iface::{BsdName, ResolvedInterface, ResolvedInterfaces};
use mooring_model::node::NodeAddress;
use mooring_model::verdict::{LatchRecord, Violation, direct_verdict};
use mooring_model::{Deployment, NodeId, Sha256Digest, UnixTime};

use crate::alert::MacEngine;
use crate::network::{AllowedNetwork, ForeignNetworkFinding};
use crate::status::{
    CarrierCheck, DegradedReason, DownReason, DrainOutcome, EgressFacts, EngineExit, EngineProcess,
    ExitSection, ExitState, Latch, LinkState, MacEngines, OwnNetworkInput, PowerSource,
    PowerStatus, ProbeStage, ProcessEnd, ProtocolVerdicts,
};

pub use in_chain::{IN_CHAIN_FIRST, InChainProbe, InChainTarget, RenderedProber};

/// An engine that exits within this long of its start failed to start.
pub const START_GRACE: Duration = Duration::from_secs(10);

/// The window in which [`CRASH_LIMIT`] exits make a crash loop.
pub const CRASH_WINDOW: Duration = Duration::from_secs(600);

/// The exits within [`CRASH_WINDOW`] that make a crash loop.
pub const CRASH_LIMIT: usize = 5;

/// The longest wait before an engine that crashed is started again.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// How long a node call that could not be delivered waits before the next
/// attempt.
pub const NODE_CALL_RETRY: Duration = Duration::from_secs(60);

/// Failed direct-probe rounds a running engine survives; the next one
/// stops it.
pub const FAILED_ROUNDS_TOLERATED: u32 = 1;

/// Why the egress or the separate uplink did not resolve (design §10.1
/// step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressFault {
    /// No interface matches the egress selector.
    Absent,
    /// Several interfaces match it.
    Ambiguous {
        /// How many.
        matches: u32,
    },
    /// The interface the selector names has no IPv4 address.
    NoIpv4 {
        /// The interface.
        interface: BsdName,
    },
    /// Its IPv4 address is outside the selector's subnet.
    SubnetMismatch,
    /// The separate uplink is absent.
    UplinkAbsent,
    /// The separate uplink is the egress.
    UplinkEqualsEgress,
}

impl EgressFault {
    fn reason(&self) -> DownReason {
        match self {
            Self::Absent => DownReason::EgressInterfaceAbsent,
            Self::Ambiguous { matches } => DownReason::EgressAmbiguous { matches: *matches },
            Self::NoIpv4 { interface } => DownReason::EgressNoIpv4 {
                interface: interface.clone(),
            },
            Self::SubnetMismatch => DownReason::EgressSubnetMismatch,
            Self::UplinkAbsent => DownReason::UplinkAbsent,
            Self::UplinkEqualsEgress => DownReason::UplinkEqualsEgress,
        }
    }
}

/// The fault as the daemon's log names it, when a poll of the M7 or of a
/// node could not be made for it.
impl fmt::Display for EgressFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("no interface matches the egress selector"),
            Self::Ambiguous { matches } => {
                write!(f, "{matches} interfaces match the egress selector")
            }
            Self::NoIpv4 { interface } => write!(
                f,
                "{}, which the egress selector names, has no IPv4 address",
                interface.as_str()
            ),
            Self::SubnetMismatch => {
                f.write_str("the egress's IPv4 address is outside the selector's subnet")
            }
            Self::UplinkAbsent => f.write_str("the separate uplink is absent"),
            Self::UplinkEqualsEgress => f.write_str("the separate uplink is the egress"),
        }
    }
}

/// The resolved interfaces and the egress link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    /// The interfaces, resolved against the deployment's exit site.
    pub interfaces: ResolvedInterfaces,
    /// The egress link.
    pub link: LinkState,
}

/// The cycle's SIM bytes, as the meter counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimUse {
    /// The cycle's first day.
    pub cycle_start: CalendarDate,
    /// Its bytes in both directions.
    pub bytes: u64,
}

/// What the daemon observed for one tick.
#[derive(Debug, Clone)]
pub struct TickInputs<'a> {
    /// The Mac's clock.
    pub now: UnixTime,
    /// A monotonic clock, for the machine's timers.
    pub mono: Duration,
    /// The deployment, as `state.json` holds it now.
    pub deployment: &'a Deployment,
    /// Whether the operator enabled the exit.
    pub exit_enabled: bool,
    /// The interfaces, or why they did not resolve.
    pub egress: Result<Egress, EgressFault>,
    /// What the network check found foreign.
    pub foreign: BTreeSet<ForeignNetworkFinding>,
    /// What the network check allowed (CFM's TUN, the operator's own
    /// networks), reported in the section.
    pub allowed: BTreeSet<AllowedNetwork>,
    /// The inputs of the own-network match that could not be read this
    /// tick; each degrades a running exit (`OwnNetworksUnreadable`).
    pub own_networks_unreadable: BTreeSet<OwnNetworkInput>,
    /// The cycle's SIM bytes.
    pub sim: SimUse,
    /// The Mac's power.
    pub power: PowerStatus,
    /// Whether the power helper runs; without it the exit is degraded
    /// (`PowerHelperExited`).
    pub power_helper_running: bool,
    /// Whether the operator asked to retry (`exit retry`).
    pub retry: bool,
    /// What the node polls found wrong (`WatchStale`), which degrades a
    /// serving exit.
    pub nodes_degraded: Vec<DegradedReason>,
}

/// A rendered engine config and its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered<C> {
    /// The config.
    pub config: C,
    /// Its digest; the engine restarts only when it changes.
    pub digest: Sha256Digest,
}

/// Why no config rendered, when that is the exit's state rather than a
/// fault of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderOutcome {
    /// The Keychain refused to give the secrets without interaction.
    SecretsUnavailable,
    /// No node has confirmed a configuration.
    NoAppliedNode,
}

/// How an engine check or start failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartFault {
    /// The binary could not be started.
    Spawn,
    /// The engine refused its config.
    Rejected,
    /// The check did not finish in time.
    CheckTimedOut,
}

/// How a node call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallFault {
    /// The node could not be reached or did not answer; the call is tried
    /// again.
    Unreachable,
    /// The node's agent refused the call; it is not tried again.
    Refused,
}

/// What a node is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCall {
    /// Close the gate and hold it closed for the latched violation
    /// (`GateSet{Closed, EgressViolation}`).
    CloseGate(LatchRecord),
    /// Halt: the egress showed this node's address (`Shutdown`).
    Shutdown(LatchRecord),
    /// Clear the violation's hold (`ClearHold{EgressViolation}`).
    ClearHold,
    /// Close the gate and hold it closed for the Mac's sleep
    /// (`GateSet{Closed, MacDrain}`), `within` what is left of the drain's
    /// budget, past which the call is abandoned: sent by
    /// [`ExitMachine::sleep`] only, never queued. The node clears it itself
    /// once a handshake completes after it and its receive count grows.
    Drain {
        /// The budget left when the call is made.
        within: Duration,
    },
}

/// The daemon's effects, as the machine uses them.
pub trait ExitPorts {
    /// A rendered `mooring-exit` config.
    type Config;
    /// A rendered `mooring-probe` config.
    type ProberConfig;
    /// A fault of the daemon itself, which ends it.
    type Error;

    /// Renders the exit's config for `interfaces`.
    fn render(
        &mut self,
        deployment: &Deployment,
        interfaces: &ResolvedInterfaces,
    ) -> Result<Result<Rendered<Self::Config>, RenderOutcome>, Self::Error>;

    /// Checks `config` with the engine (`check -c stdin`).
    fn check(&mut self, config: &Self::Config) -> Result<Result<(), StartFault>, Self::Error>;

    /// Starts the engine with `config` (`run -c stdin`): its process id.
    fn start(&mut self, config: &Self::Config) -> Result<Result<u32, StartFault>, Self::Error>;

    /// The running engine's end, once it has ended.
    fn exited(&mut self) -> Result<Option<ProcessEnd>, Self::Error>;

    /// Stops the running engine: its end.
    fn stop(&mut self) -> Result<ProcessEnd, Self::Error>;

    /// The address `reflector` saw, through `via`.
    fn probe(
        &mut self,
        via: &ResolvedInterface,
        reflector: SocketAddrV4,
    ) -> Result<Ipv4Addr, ProbeStage>;

    /// Persists the latch, or its absence.
    fn persist_latch(&mut self, latch: Option<&LatchRecord>) -> Result<(), Self::Error>;

    /// Sends `call` to `node`.
    fn call(&mut self, node: &NodeId, call: &NodeCall) -> Result<(), CallFault>;

    /// Renders `mooring-probe`'s config for `interfaces`.
    fn render_prober(
        &mut self,
        deployment: &Deployment,
        interfaces: &ResolvedInterfaces,
    ) -> Result<Result<RenderedProber<Self::ProberConfig>, RenderOutcome>, Self::Error>;

    /// Checks and starts `mooring-probe` with `config`: its process id.
    fn start_prober(
        &mut self,
        config: &Self::ProberConfig,
    ) -> Result<Result<u32, StartFault>, Self::Error>;

    /// The running prober's end, once it has ended.
    fn prober_exited(&mut self) -> Result<Option<ProcessEnd>, Self::Error>;

    /// Stops the running prober: its end.
    fn stop_prober(&mut self) -> Result<ProcessEnd, Self::Error>;

    /// The address the reflector saw through the probe inbound on the
    /// loopback `port`, and how long that took.
    fn probe_in_chain(&mut self, port: u16) -> Result<InChainProbe, ProbeStage>;
}

/// The engine as the machine knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Engine {
    Stopped,
    Running {
        digest: Sha256Digest,
        started: Duration,
        pid: u32,
    },
    /// It crashed and starts again at `until`.
    Backoff {
        until: Duration,
    },
}

/// A failure that keeps the engine stopped until the config changes or the
/// operator retries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Blocked {
    reason: DownReason,
    digest: Sha256Digest,
}

/// The latest direct-probe round.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Round {
    Passed,
    Failed { node: NodeId, stage: ProbeStage },
}

/// A node call not yet delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    call: NodeCall,
    next_try: Duration,
}

/// The exit's state machine; see the module documentation.
#[derive(Debug, Clone)]
pub struct ExitMachine {
    state: ExitState,
    since: UnixTime,
    latch: Option<LatchRecord>,
    engine: Engine,
    started_once: bool,
    restarts: u32,
    last_exit: Option<EngineExit>,
    crashes: VecDeque<Duration>,
    backoff_step: u32,
    blocked: Option<Blocked>,
    probed_at: Option<Duration>,
    round: Option<Round>,
    failed_rounds: u32,
    carrier_check: Option<CarrierCheck>,
    clear_holds: bool,
    /// Whether the latest tick reached the direct probes.
    probing: bool,
    /// Whether a latch read at start still has to be sent to the nodes.
    resend: bool,
    pending: BTreeMap<NodeId, Pending>,
    /// `mooring-probe` and the in-chain probes.
    in_chain: in_chain::InChain,
    /// Between a sleep's drain and the wake: the engine stays stopped.
    paused: bool,
}

impl ExitMachine {
    /// The machine as the daemon starts at `now`: no engine of its own runs
    /// (the daemon stopped any it left), and `latch` is what
    /// `run/latch.json` holds. A latch is sent to the nodes again at the
    /// first tick, since the daemon that latched it may have ended before
    /// it told them; closing a gate twice changes nothing.
    #[must_use]
    pub fn new(now: UnixTime, latch: Option<LatchRecord>) -> Self {
        let latch_present = latch.is_some();
        Self {
            state: ExitState::Preflight,
            since: now,
            latch,
            engine: Engine::Stopped,
            started_once: false,
            restarts: 0,
            last_exit: None,
            crashes: VecDeque::new(),
            backoff_step: 0,
            blocked: None,
            probed_at: None,
            round: None,
            failed_rounds: 0,
            carrier_check: None,
            clear_holds: false,
            probing: false,
            resend: latch_present,
            pending: BTreeMap::new(),
            in_chain: in_chain::InChain::default(),
            paused: false,
        }
    }

    /// The latched violation, if any.
    #[must_use]
    pub const fn latch(&self) -> Option<&LatchRecord> {
        self.latch.as_ref()
    }

    /// How long until the next direct-probe round is due at `mono`, while
    /// the latest tick reached the probes (`None`: it stopped before them,
    /// so none is pending): zero when one is due now. The daemon starts
    /// slow work of its own (a router poll) only when enough is left, so
    /// the probes keep their cadence.
    #[must_use]
    pub fn next_probe_in(&self, mono: Duration, deployment: &Deployment) -> Option<Duration> {
        if !self.probing {
            return None;
        }
        let every = Duration::from_secs(u64::from(deployment.exit().probe.direct_every.seconds()));
        Some(self.probed_at.map_or(Duration::ZERO, |at| {
            every.saturating_sub(mono.saturating_sub(at))
        }))
    }

    /// The latest in-chain probe of each node, through each protocol.
    #[must_use]
    pub fn verdicts(&self) -> BTreeMap<NodeId, ProtocolVerdicts> {
        self.in_chain.verdicts()
    }

    /// The node calls not yet delivered, by node.
    #[must_use]
    pub fn pending_calls(&self) -> BTreeMap<&NodeId, &NodeCall> {
        self.pending
            .iter()
            .map(|(node, pending)| (node, &pending.call))
            .collect()
    }

    /// The sleep drain (design §10.3), when macOS is about to sleep at
    /// `now`: stops `mooring-exit` and `mooring-probe` first, so the exit is
    /// `Paused` from here until [`Self::wake`], then asks every node of
    /// `deployment` with a site, in id order, to close its gate for the
    /// drain, each within what `budget_left` says is left of the budget
    /// (`None` once it has run out). `Completed` when every node closed it
    /// within the budget, `TimedOut` when the budget ran out first, and
    /// otherwise `Failed`, when a node could not be reached or refused: the
    /// daemon lets the sleep proceed in every case, and a node that was not
    /// told notices the Mac's silence itself.
    pub fn sleep<P: ExitPorts>(
        &mut self,
        now: UnixTime,
        deployment: &Deployment,
        ports: &mut P,
        budget_left: &mut dyn FnMut() -> Option<Duration>,
    ) -> Result<DrainOutcome, P::Error> {
        self.paused = true;
        self.stop_engine(now, ports)?;
        self.in_chain.stop_prober(now, ports)?;
        self.set_state(ExitState::Paused, now);
        let mut outcome = DrainOutcome::Completed;
        for node in deployment.nodes().values() {
            if node.lifecycle.site().is_none() {
                continue;
            }
            let Some(within) = budget_left() else {
                return Ok(DrainOutcome::TimedOut);
            };
            if ports.call(&node.id, &NodeCall::Drain { within }).is_err() {
                outcome = DrainOutcome::Failed;
            }
        }
        if budget_left().is_none() {
            return Ok(DrainOutcome::TimedOut);
        }
        Ok(outcome)
    }

    /// The Mac woke (design §10.3): the next tick re-resolves the
    /// interfaces and runs the preflight with a fresh direct probe, and
    /// starts the engine if it passes.
    pub fn wake(&mut self) {
        self.paused = false;
        self.probed_at = None;
        self.round = None;
    }

    /// Whether the exit is paused for a sleep.
    #[must_use]
    pub const fn paused(&self) -> bool {
        self.paused
    }

    /// One tick: observes, decides, acts through `ports`, and returns the
    /// exit's section of the status.
    pub fn tick<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        ports: &mut P,
    ) -> Result<ExitSection, P::Error> {
        self.prune_crashes(inputs.mono);
        self.probing = false;
        if self.paused {
            self.stop_engine(inputs.now, ports)?;
            self.in_chain.stop_prober(inputs.now, ports)?;
            self.set_state(ExitState::Paused, inputs.now);
            return Ok(self.section(inputs));
        }
        self.reap(inputs, ports)?;
        self.clear_stale_latch(inputs, ports)?;
        if std::mem::take(&mut self.resend)
            && let Some(latch) = self.latch.clone()
        {
            self.tell_nodes(&latch, inputs);
        }
        if inputs.retry {
            self.retry(ports)?;
        }
        let state = if inputs.exit_enabled {
            match self.preflight(inputs, ports)? {
                Ok(interfaces) => self.supervise(inputs, &interfaces, ports)?,
                Err(reason) => down(reason),
            }
        } else {
            ExitState::Disabled
        };
        if matches!(state, ExitState::Down { .. } | ExitState::Disabled) {
            self.stop_engine(inputs.now, ports)?;
        }
        if !matches!(self.engine, Engine::Running { .. }) {
            self.in_chain.stop_prober(inputs.now, ports)?;
        }
        self.set_state(state, inputs.now);
        self.deliver(inputs, ports);
        Ok(self.section(inputs))
    }

    /// Notes an engine that ended on its own: a start failure within the
    /// grace, a crash after it.
    fn reap<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        ports: &mut P,
    ) -> Result<(), P::Error> {
        let Engine::Running {
            digest, started, ..
        } = self.engine
        else {
            return Ok(());
        };
        let Some(end) = ports.exited()? else {
            return Ok(());
        };
        self.last_exit = Some(EngineExit {
            at: inputs.now,
            end,
        });
        self.engine = Engine::Stopped;
        if inputs.mono.saturating_sub(started) < START_GRACE {
            self.block(
                DownReason::EngineStartFailed {
                    engine: MacEngine::Exit,
                },
                digest,
            );
            return Ok(());
        }
        self.crashes.push_back(inputs.mono);
        self.prune_crashes(inputs.mono);
        if self.crashes.len() >= CRASH_LIMIT {
            self.block(
                DownReason::EngineCrashLoop {
                    engine: MacEngine::Exit,
                },
                digest,
            );
        } else {
            let wait = Duration::from_secs(1_u64 << self.backoff_step.min(6)).min(MAX_BACKOFF);
            self.backoff_step = self.backoff_step.saturating_add(1);
            self.engine = Engine::Backoff {
                until: inputs.mono + wait,
            };
        }
        Ok(())
    }

    fn prune_crashes(&mut self, mono: Duration) {
        while self
            .crashes
            .front()
            .is_some_and(|&crash| mono.saturating_sub(crash) >= CRASH_WINDOW)
        {
            self.crashes.pop_front();
        }
        if self.crashes.is_empty() {
            self.backoff_step = 0;
        }
    }

    fn block(&mut self, reason: DownReason, digest: Sha256Digest) {
        self.blocked = Some(Blocked { reason, digest });
    }

    /// Clears a latch whose generation or egress identity is no longer the
    /// current one.
    fn clear_stale_latch<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        ports: &mut P,
    ) -> Result<(), P::Error> {
        let Some(latch) = &self.latch else {
            return Ok(());
        };
        let other_generation = latch.config_generation != inputs.deployment.config_generation();
        let other_egress = inputs
            .egress
            .as_ref()
            .is_ok_and(|egress| egress.interfaces.egress().identity() != latch.egress);
        if other_generation || other_egress {
            self.clear_latch(ports)?;
        }
        Ok(())
    }

    fn clear_latch<P: ExitPorts>(&mut self, ports: &mut P) -> Result<(), P::Error> {
        ports.persist_latch(None)?;
        self.latch = None;
        self.clear_holds = true;
        // A gate not yet closed need not be; a halt stands until the
        // operator resumes the node.
        self.pending
            .retain(|_, pending| !matches!(pending.call, NodeCall::CloseGate(_)));
        self.probed_at = None;
        Ok(())
    }

    /// `exit retry`: clears the latch and every hold on the engine, and
    /// asks the nodes to clear theirs once a fresh preflight has passed.
    fn retry<P: ExitPorts>(&mut self, ports: &mut P) -> Result<(), P::Error> {
        if self.latch.is_some() {
            self.clear_latch(ports)?;
        }
        self.clear_holds = true;
        self.blocked = None;
        self.crashes.clear();
        self.backoff_step = 0;
        if matches!(self.engine, Engine::Backoff { .. }) {
            self.engine = Engine::Stopped;
        }
        self.probed_at = None;
        Ok(())
    }

    /// The preflight checks; see the module documentation.
    fn preflight<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        ports: &mut P,
    ) -> Result<Result<ResolvedInterfaces, DownReason>, P::Error> {
        let deployment = inputs.deployment;
        let sim = &deployment.exit().sim;
        if sim.plan().is_none() {
            return Ok(Err(DownReason::SimPlanUnrecorded));
        }
        if sim
            .stop()
            .hard_stop_bytes()
            .is_some_and(|stop| inputs.sim.bytes >= stop)
        {
            return Ok(Err(DownReason::SimCapReached {
                cycle_start: inputs.sim.cycle_start,
            }));
        }
        let egress = match &inputs.egress {
            Ok(egress) => egress,
            Err(fault) => return Ok(Err(fault.reason())),
        };
        if let Ok(findings) = NonEmpty::try_from(inputs.foreign.iter().cloned().collect::<Vec<_>>())
        {
            return Ok(Err(DownReason::ForeignNetworkAttached { findings }));
        }
        let Some(check) = &deployment.exit().egress_check else {
            return Ok(Err(DownReason::CarrierCheckUnrecorded));
        };
        if let Some(latch) = &self.latch {
            return Ok(Err(DownReason::Violation(latch.violation.clone())));
        }
        if !deployment
            .nodes()
            .values()
            .any(|node| node.lifecycle.applied().is_some())
        {
            return Ok(Err(DownReason::NoAppliedNode));
        }
        let running = matches!(self.engine, Engine::Running { .. });
        self.probing = true;
        let due = self.probed_at.is_none_or(|at| {
            inputs.mono.saturating_sub(at)
                >= Duration::from_secs(u64::from(deployment.exit().probe.direct_every.seconds()))
        });
        if due && let Some(violation) = self.probe_round(inputs, egress, check, ports) {
            self.violate(violation.clone(), inputs, egress, ports)?;
            return Ok(Err(DownReason::Violation(violation)));
        }
        match &self.round {
            Some(Round::Failed { node, stage })
                if !running || self.failed_rounds > FAILED_ROUNDS_TOLERATED =>
            {
                Ok(Err(DownReason::DirectProbeFailed {
                    node: node.clone(),
                    stage: *stage,
                }))
            }
            _ => Ok(Ok(egress.interfaces.clone())),
        }
    }

    /// One direct-probe round: the first node whose reflector answers
    /// gives the carrier address, which is checked; a violation is
    /// returned.
    fn probe_round<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        egress: &Egress,
        check: &EgressCheck,
        ports: &mut P,
    ) -> Option<Violation> {
        self.probed_at = Some(inputs.mono);
        let deployment = inputs.deployment;
        let mut failure = None;
        let mut observed = None;
        for node in deployment.nodes().values() {
            let Some(site) = node.lifecycle.site() else {
                continue;
            };
            let NodeAddress::Public(address) = site.address;
            let reflector = SocketAddrV4::new(address.get(), node.ports.reflector().get());
            match ports.probe(egress.interfaces.egress(), reflector) {
                Ok(ip) => {
                    observed = Some(ip);
                    break;
                }
                Err(stage) => failure = Some((node.id.clone(), stage)),
            }
        }
        let Some(ip) = observed else {
            self.failed_rounds = self.failed_rounds.saturating_add(1);
            self.round = failure.map(|(node, stage)| Round::Failed { node, stage });
            return None;
        };
        self.failed_rounds = 0;
        self.round = Some(Round::Passed);
        self.carrier_check = Some(CarrierCheck {
            egress_ip: ip,
            in_carrier_prefixes: check.in_carrier(ip),
            pairing: check.pairing,
            checked_at: inputs.now,
        });
        if let Err(violation) = direct_verdict(ip, &deployment.node_addresses(), check) {
            return Some(violation);
        }
        if self.clear_holds {
            self.clear_holds = false;
            for node in deployment.nodes().values() {
                // A halt not yet delivered stands: only the operator
                // resumes a node.
                let halting = self
                    .pending
                    .get(&node.id)
                    .is_some_and(|pending| matches!(pending.call, NodeCall::Shutdown(_)));
                if node.lifecycle.site().is_some() && !halting {
                    self.pending.insert(
                        node.id.clone(),
                        Pending {
                            call: NodeCall::ClearHold,
                            next_try: inputs.mono,
                        },
                    );
                }
            }
        }
        None
    }

    /// Latches `violation`: the engine stops first, then the latch is
    /// persisted, then every node with a site is told.
    fn violate<P: ExitPorts>(
        &mut self,
        violation: Violation,
        inputs: &TickInputs<'_>,
        egress: &Egress,
        ports: &mut P,
    ) -> Result<(), P::Error> {
        self.stop_engine(inputs.now, ports)?;
        let latch = LatchRecord {
            violation,
            at: inputs.now,
            config_generation: inputs.deployment.config_generation(),
            egress: egress.interfaces.egress().identity(),
        };
        ports.persist_latch(Some(&latch))?;
        self.clear_holds = false;
        self.tell_nodes(&latch, inputs);
        self.latch = Some(latch);
        Ok(())
    }

    /// Queues the calls `latch` makes: every node with a site closes its
    /// gate, and the node whose address the egress showed halts.
    fn tell_nodes(&mut self, latch: &LatchRecord, inputs: &TickInputs<'_>) {
        for node in inputs.deployment.nodes().values() {
            if node.lifecycle.site().is_none() {
                continue;
            }
            let call = if latch.violation.shutdown_node() == Some(&node.id) {
                NodeCall::Shutdown(latch.clone())
            } else {
                NodeCall::CloseGate(latch.clone())
            };
            self.pending.insert(
                node.id.clone(),
                Pending {
                    call,
                    next_try: inputs.mono,
                },
            );
        }
    }

    /// Runs the engine on the rendered config; returns the exit's state.
    fn supervise<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        interfaces: &ResolvedInterfaces,
        ports: &mut P,
    ) -> Result<ExitState, P::Error> {
        let rendered = match ports.render(inputs.deployment, interfaces)? {
            Ok(rendered) => rendered,
            Err(RenderOutcome::SecretsUnavailable) => {
                return Ok(down(DownReason::SecretsUnavailable));
            }
            Err(RenderOutcome::NoAppliedNode) => return Ok(down(DownReason::NoAppliedNode)),
        };
        if let Some(blocked) = &self.blocked {
            if blocked.digest == rendered.digest {
                return Ok(down(blocked.reason.clone()));
            }
            // An input changed: the engine may try again.
            self.blocked = None;
            self.crashes.clear();
            self.backoff_step = 0;
        }
        match self.engine {
            Engine::Running { digest, .. } if digest == rendered.digest => {}
            Engine::Running { .. } => {
                self.stop_engine(inputs.now, ports)?;
                if let Some(state) = self.start(inputs, &rendered, ports)? {
                    return Ok(state);
                }
            }
            Engine::Backoff { until } if inputs.mono < until => return Ok(ExitState::Starting),
            Engine::Backoff { .. } | Engine::Stopped => {
                if let Some(state) = self.start(inputs, &rendered, ports)? {
                    return Ok(state);
                }
            }
        }
        let Engine::Running { started, .. } = self.engine else {
            return Ok(ExitState::Starting);
        };
        let round_due = self.in_chain.due(inputs, started);
        self.in_chain
            .supervise_prober(inputs, interfaces, round_due, ports)?;
        if round_due {
            let egress = match &inputs.egress {
                Ok(egress) => egress,
                // The preflight resolved it this tick.
                Err(fault) => return Ok(down(fault.reason())),
            };
            let Some(check) = inputs.deployment.exit().egress_check.as_ref() else {
                return Ok(down(DownReason::CarrierCheckUnrecorded));
            };
            if let Some(violation) = self.in_chain_round(inputs, egress, check, ports) {
                self.violate(violation.clone(), inputs, egress, ports)?;
                return Ok(down(DownReason::Violation(violation)));
            }
        }
        Ok(self.running_state(inputs))
    }

    /// Checks and starts the engine; the exit's state if that failed.
    fn start<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        rendered: &Rendered<P::Config>,
        ports: &mut P,
    ) -> Result<Option<ExitState>, P::Error> {
        let outcome = match ports.check(&rendered.config)? {
            Ok(()) => ports.start(&rendered.config)?,
            Err(fault) => Err(fault),
        };
        match outcome {
            Ok(pid) => {
                if self.started_once {
                    self.restarts = self.restarts.saturating_add(1);
                }
                self.started_once = true;
                self.engine = Engine::Running {
                    digest: rendered.digest,
                    started: inputs.mono,
                    pid,
                };
                Ok(None)
            }
            Err(fault) => {
                let engine = MacEngine::Exit;
                let reason = match fault {
                    StartFault::Spawn => DownReason::EngineSpawnFailed { engine },
                    StartFault::Rejected => DownReason::EngineConfigRejected { engine },
                    StartFault::CheckTimedOut => DownReason::EngineStartFailed { engine },
                };
                self.engine = Engine::Stopped;
                self.block(reason.clone(), rendered.digest);
                Ok(Some(down(reason)))
            }
        }
    }

    /// The state of a running engine: starting within the grace; degraded
    /// for what the Mac knows to be wrong (the power, a node's watch, an
    /// in-chain probe of this engine that failed); serving through the
    /// address an in-chain probe of this engine verified; verifying until
    /// one has.
    fn running_state(&self, inputs: &TickInputs<'_>) -> ExitState {
        let Engine::Running { started, .. } = self.engine else {
            return ExitState::Starting;
        };
        if inputs.mono.saturating_sub(started) < START_GRACE {
            return ExitState::Starting;
        }
        let mut reasons = Vec::new();
        if inputs.power.source == PowerSource::Battery {
            reasons.push(DegradedReason::OnBattery);
        }
        if !inputs.power_helper_running {
            reasons.push(DegradedReason::PowerHelperExited);
        }
        reasons.extend(
            inputs
                .own_networks_unreadable
                .iter()
                .map(|&input| DegradedReason::OwnNetworksUnreadable { input }),
        );
        reasons.extend(inputs.nodes_degraded.iter().cloned());
        reasons.extend(self.in_chain.failures_since(started));
        match NonEmpty::try_from(reasons) {
            Ok(reasons) => ExitState::Degraded { reasons },
            Err(_) => match self.in_chain.verified_since(started) {
                Some((ip, verified_at)) => ExitState::Serving { ip, verified_at },
                None => ExitState::Verifying,
            },
        }
    }

    fn stop_engine<P: ExitPorts>(&mut self, now: UnixTime, ports: &mut P) -> Result<(), P::Error> {
        match self.engine {
            Engine::Running { .. } => {
                let end = ports.stop()?;
                self.last_exit = Some(EngineExit { at: now, end });
                self.engine = Engine::Stopped;
            }
            Engine::Backoff { .. } => self.engine = Engine::Stopped,
            Engine::Stopped => {}
        }
        Ok(())
    }

    fn set_state(&mut self, state: ExitState, now: UnixTime) {
        if state != self.state {
            self.state = state;
            self.since = now;
        }
    }

    /// Sends the node calls that are due; a refused one is dropped, an
    /// undelivered one waits [`NODE_CALL_RETRY`].
    fn deliver<P: ExitPorts>(&mut self, inputs: &TickInputs<'_>, ports: &mut P) {
        let due: Vec<NodeId> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.next_try <= inputs.mono)
            .map(|(node, _)| node.clone())
            .collect();
        for node in due {
            let Some(pending) = self.pending.get_mut(&node) else {
                continue;
            };
            match ports.call(&node, &pending.call) {
                Ok(()) | Err(CallFault::Refused) => {
                    self.pending.remove(&node);
                }
                Err(CallFault::Unreachable) => pending.next_try = inputs.mono + NODE_CALL_RETRY,
            }
        }
    }

    fn section(&self, inputs: &TickInputs<'_>) -> ExitSection {
        let pid = match self.engine {
            Engine::Running { pid, .. } => Some(pid),
            Engine::Stopped | Engine::Backoff { .. } => None,
        };
        ExitSection {
            state: self.state.clone(),
            since: self.since,
            latches: self
                .latch
                .iter()
                .map(|latch| Latch {
                    violation: latch.violation.clone(),
                    at: latch.at,
                })
                .collect(),
            egress: inputs.egress.as_ref().ok().map(|egress| {
                let interface = egress.interfaces.egress();
                EgressFacts {
                    interface: interface.bsd_name.clone(),
                    lladdr: interface.lladdr,
                    ipv4: interface.ipv4,
                    link: egress.link,
                }
            }),
            carrier_check: self.carrier_check,
            engines: MacEngines {
                exit: EngineProcess {
                    pid,
                    restarts: self.restarts,
                    last_exit: self.last_exit,
                },
                probe: self.in_chain.process(),
            },
            power: inputs.power,
            foreign_networks: inputs.foreign.clone(),
            allowed_networks: inputs.allowed.clone(),
        }
    }
}

const fn down(reason: DownReason) -> ExitState {
    ExitState::Down { reason }
}
