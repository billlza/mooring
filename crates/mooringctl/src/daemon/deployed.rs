// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon with a deployment (design §10.1): every [`TICK`] it reads
//! the state, resolves the exit's interfaces, checks for foreign networks,
//! reads the SIM meter and ticks the exit machine; it polls the M7 every
//! [`POLL_INTERVAL`] and each node's agent every [`NODE_POLL_EVERY`]
//! (`Status`, design §10.5) in the slot after a direct-probe round, so
//! neither delays a probe; and it publishes the deployment's status when
//! the exit's state changes and at least every [`PUBLISH_EVERY`]. The SIM
//! meter reads the egress counters on a thread of its own.
//!
//! The daemon keeps std threads, as the router console did (design §10.1,
//! revision 9): this loop, the meter's thread, and the control socket's
//! acceptor and connections.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mooring_agent_proto::{LineRequest, ReadError, Response, WATCH_STALE_SECS};
use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::exit::{ExitMachine, SimUse, TickInputs};
use mooring_daemon_core::meter::{MAX_SIM_METER_BYTES, SimMeter, accuracy};
use mooring_daemon_core::period::BillingCycle;
use mooring_daemon_core::router::{RouterReading, RouterUnavailableReason};
use mooring_daemon_core::snapshot::{NodePoll, SimTotals, StatusInputs, assemble};
use mooring_daemon_core::status::{
    AgentUnreachable, DegradedReason, ExitState, NodeAgentState, PowerSource, PowerStatus,
};
use mooring_model::iface::BsdName;
use mooring_model::time::UnixTime;
use mooring_model::{Deployment, NodeId};
use mooring_store::{Store, read_latch, read_sim_meter};

use super::{
    Control, LoopState, POLL_INTERVAL, RunPaths, Waited, chain, poll_router, publish,
    router_after_poll, say, wait_for_next_poll,
};
use crate::app::Env;
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::node::session::ops_session;
use crate::runtime::meter::{METER_TICK, MeterThread, PERSIST_EVERY, Watched};
use crate::runtime::network::foreign;
use crate::runtime::ports::{
    DaemonPorts, ENGINE_PID_FILE, EXIT_ENGINE, PROBE_ENGINE, PROBER_PID_FILE, stop_stale_engine,
};
use crate::runtime::resolve::exit_interfaces;

/// The loop's tick (design §10.1).
pub(crate) const TICK: Duration = Duration::from_secs(2);

/// The longest the console goes without a new status.
pub(crate) const PUBLISH_EVERY: Duration = Duration::from_secs(10);

/// How often the power source is read.
pub(crate) const POWER_EVERY: Duration = Duration::from_secs(60);

/// How often each node's agent is polled (design §10.5).
pub(crate) const NODE_POLL_EVERY: Duration = Duration::from_secs(600);

/// A router poll starts only with at least this long left before the next
/// direct-probe round: each of its requests takes at most 15 s, and the
/// first that fails ends it.
pub(crate) const ROUTER_SLOT: Duration = Duration::from_secs(20);

/// The engine directory, in the support directory: the hosted build's
/// `out/` (or at least its `darwin-arm64/`), whose engine is checked
/// against its pin at every start.
pub(crate) const ENGINES_DIRECTORY: &str = "engines";

/// Why the loop stopped without a failure of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// The control socket's acceptor ended.
    AcceptorEnded,
}

/// The exit's side of the daemon, between ticks.
pub(crate) struct Deployed<'e, 'a> {
    env: &'e Env<'a>,
    support_dir: PathBuf,
    store: Store,
    machine: ExitMachine,
    ports: DaemonPorts<'e, 'a>,
    meter: MeterThread,
    begun: Instant,
    router: RouterReading,
    router_failure: Option<String>,
    router_polled: Option<Instant>,
    power: PowerSource,
    power_read: Instant,
    power_failure: Option<String>,
    published: Option<(Instant, ExitState)>,
    snapshot_failure: Option<String>,
    meter_failure: Option<String>,
    nodes_polled: Option<Instant>,
    polls: BTreeMap<NodeId, NodePoll>,
    unreachable: BTreeMap<NodeId, NodeAgentState>,
}

impl std::fmt::Debug for Deployed<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deployed")
            .field("support_dir", &self.support_dir)
            .field("machine", &self.machine)
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

impl<'e, 'a> Deployed<'e, 'a> {
    /// Prepares the exit: stops an engine an earlier daemon left, reads the
    /// latch and the SIM meter (a corrupt one of either stops the daemon:
    /// neither is read as none), starts the meter's thread and reads the
    /// power source; then it polls the M7 once, so every status it
    /// publishes has a panel. `router` is the panel the router console last
    /// showed, if it ran.
    pub(crate) fn open(
        env: &'e Env<'a>,
        support_dir: &Path,
        log: &mut dyn Write,
        router: Option<RouterReading>,
    ) -> Result<Self, CommandError> {
        let now = (env.clock)()?;
        let run_dir = RunPaths::under(support_dir).dir;
        let engines = support_dir.join(ENGINES_DIRECTORY);
        for (pid_file, engine) in [
            (ENGINE_PID_FILE, EXIT_ENGINE),
            (PROBER_PID_FILE, PROBE_ENGINE),
        ] {
            if let Some(pid) = stop_stale_engine(&run_dir, pid_file, &engines.join(engine))? {
                say(
                    log,
                    now,
                    &format!("stopped the engine an earlier daemon left (pid {pid})"),
                )?;
            }
        }
        let latch = read_latch(&run_dir).map_err(|error| LocalError::Latch(Box::new(error)))?;
        if let Some(latch) = &latch {
            say(
                log,
                now,
                &format!("a violation is latched: {:?}", latch.violation),
            )?;
        }
        let meter = match read_sim_meter(support_dir, MAX_SIM_METER_BYTES + 1)
            .map_err(|error| LocalError::MeterFile(Box::new(error)))?
        {
            Some(bytes) => {
                SimMeter::decode(&bytes).map_err(|error| LocalError::Meter(Box::new(error)))?
            }
            None => SimMeter::new(),
        };
        let meter = MeterThread::start(
            support_dir.to_path_buf(),
            meter,
            (env.meter_reader)(),
            METER_TICK,
            PERSIST_EVERY,
        )?;
        let power = (env.power)()?;
        let store = Store::new(support_dir);
        let state = store
            .load()
            .map_err(|error| LocalError::StateRead(Box::new(error)))?;
        let egress = exit_interfaces(env.router.link, state.deployment.exit())?;
        let mut router_failure = None;
        let router = poll_m7(
            env,
            support_dir,
            log,
            router.as_ref(),
            &mut router_failure,
            egress
                .as_ref()
                .ok()
                .map(|egress| &egress.interfaces.egress().bsd_name),
        )?;
        Ok(Self {
            env,
            support_dir: support_dir.to_path_buf(),
            store,
            machine: ExitMachine::new(now, latch),
            ports: DaemonPorts::new(env, run_dir, engines),
            meter,
            begun: Instant::now(),
            router,
            router_failure,
            router_polled: Some(Instant::now()),
            power,
            power_read: Instant::now(),
            power_failure: None,
            published: None,
            snapshot_failure: None,
            meter_failure: None,
            nodes_polled: None,
            polls: BTreeMap::new(),
            unreachable: BTreeMap::new(),
        })
    }

    /// One tick; `retry` when the operator asked for one since the last.
    pub(crate) fn tick(
        &mut self,
        control: &Control,
        log: &mut dyn Write,
        retry: bool,
    ) -> Result<ExitState, CommandError> {
        let env = self.env;
        let state = self
            .store
            .load()
            .map_err(|error| LocalError::StateRead(Box::new(error)))?;
        let deployment = &state.deployment;
        let now = (env.clock)()?;
        let egress = exit_interfaces(env.router.link, deployment.exit())?;
        let egress_name = egress
            .as_ref()
            .ok()
            .map(|egress| egress.interfaces.egress().bsd_name.clone());
        self.meter
            .watch(egress.as_ref().ok().map(|egress| Watched {
                index: egress.interfaces.egress().index,
                lladdr: egress.interfaces.egress().lladdr,
            }))?;
        // The check runs while the egress resolves: without it the exit is
        // down already, for that.
        let foreign = match &egress_name {
            Some(name) => foreign(
                &env.router.link.interfaces().map_err(LocalError::Kernel)?,
                name,
            )?,
            None => BTreeSet::new(),
        };
        self.read_power(log, now)?;
        let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), now)
            .map_err(LocalError::Cycle)?;
        let counted = self.meter.meter()?;
        let bytes = counted.cycle_bytes(cycle);
        self.ports.set_egress(egress_name.clone());
        let previous = self.published.as_ref().map(|(_, state)| state.clone());
        let section = self.machine.tick(
            &TickInputs {
                now,
                mono: self.begun.elapsed(),
                deployment,
                exit_enabled: state.runtime.exit_enabled,
                egress,
                foreign,
                sim: SimUse {
                    cycle_start: cycle.start(),
                    bytes: bytes.total(),
                },
                power: PowerStatus {
                    source: self.power,
                    assertions_held: false,
                    last_sleep: None,
                    last_wake: None,
                    last_drain: None,
                },
                retry,
                nodes_degraded: stale_watches(&self.polls),
            },
            &mut self.ports,
        )?;
        for note in self.ports.take_notes() {
            say(log, now, &note)?;
        }
        if previous.as_ref() != Some(&section.state) {
            say(log, now, &format!("exit: {:?}", section.state))?;
        }
        let due = self
            .router_polled
            .is_none_or(|at| at.elapsed() >= POLL_INTERVAL);
        let slot = self
            .machine
            .next_probe_in(self.begun.elapsed(), deployment)
            .is_none_or(|left| left >= ROUTER_SLOT);
        if due && slot {
            self.poll_router(log, egress_name.as_ref())?;
        }
        let nodes_due = self
            .nodes_polled
            .is_none_or(|at| at.elapsed() >= NODE_POLL_EVERY);
        if nodes_due && slot {
            self.poll_nodes(log, deployment, egress_name.as_ref())?;
        }
        self.note_meter(log, now)?;
        let state_changed = previous.as_ref() != Some(&section.state);
        let stale = self
            .published
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= PUBLISH_EVERY);
        if state_changed || stale {
            let router = self.router.clone();
            let exit_state = section.state.clone();
            let status = assemble(StatusInputs {
                deployment,
                at: now,
                exit: section,
                sim: SimTotals {
                    rx_bytes: bytes.rx,
                    tx_bytes: bytes.tx,
                    daily: &counted
                        .daily(cycle, now)
                        .map_err(|error| LocalError::Meter(Box::new(error)))?,
                    accuracy: accuracy(bytes, &router),
                },
                router,
                capacity: None,
                ledgers: &[],
                through: now,
                polls: &self.polls,
                unreachable: &self.unreachable,
                verdicts: &self.machine.verdicts(),
                pending_apply: &BTreeMap::new(),
                alerts: Vec::new(),
            })
            .map_err(|error| LocalError::Snapshot(Box::new(error)))?;
            publish(
                &control.hub,
                &self.support_dir,
                log,
                &mut self.snapshot_failure,
                &ConsoleStatus::Deployed(Box::new(status)),
                now,
            )?;
            self.published = Some((Instant::now(), exit_state.clone()));
            return Ok(exit_state);
        }
        Ok(section.state)
    }

    /// Polls the M7 through the egress; without one it cannot be reached,
    /// which the panel says rather than show an old reading.
    fn poll_router(
        &mut self,
        log: &mut dyn Write,
        egress: Option<&BsdName>,
    ) -> Result<(), CommandError> {
        self.router_polled = Some(Instant::now());
        self.router = poll_m7(
            self.env,
            &self.support_dir,
            log,
            Some(&self.router),
            &mut self.router_failure,
            egress,
        )?;
        Ok(())
    }

    /// Polls every node with a site for its `Status` through the egress.
    /// A node that answers is reported; one that does not is unreachable
    /// since its first failed poll in a row, which is logged once.
    fn poll_nodes(
        &mut self,
        log: &mut dyn Write,
        deployment: &Deployment,
        egress: Option<&BsdName>,
    ) -> Result<(), CommandError> {
        self.nodes_polled = Some(Instant::now());
        let sited: Vec<_> = deployment
            .nodes()
            .values()
            .filter(|node| node.lifecycle.site().is_some())
            .collect();
        self.polls
            .retain(|id, _| sited.iter().any(|node| node.id == *id));
        self.unreachable
            .retain(|id, _| sited.iter().any(|node| node.id == *id));
        for node in sited {
            let now = (self.env.clock)()?;
            let outcome = match egress {
                Some(egress) => ops_session(self.env, node, egress)
                    .and_then(|mut session| Ok(session.request(&LineRequest::Status)?)),
                None => Err(LocalError::NodeUnreachableWithoutEgress.into()),
            };
            match outcome {
                Ok(Response::Status(status)) => {
                    if self.unreachable.remove(&node.id).is_some() {
                        say(log, now, &format!("{}: polled again", node.id))?;
                    }
                    self.polls.insert(
                        node.id.clone(),
                        NodePoll {
                            polled_at: now,
                            status: *status,
                        },
                    );
                }
                outcome => {
                    let (cause, text) = match &outcome {
                        Ok(response) => (
                            AgentUnreachable::ProtocolMismatch,
                            format!("the agent answered Status with {:?}", response.kind()),
                        ),
                        Err(error) => (unreachable_cause(error), chain(error)),
                    };
                    self.polls.remove(&node.id);
                    let since = match self.unreachable.get(&node.id) {
                        Some(NodeAgentState::Unreachable { since, .. }) => *since,
                        _ => {
                            say(log, now, &format!("{}: poll failed: {text}", node.id))?;
                            now
                        }
                    };
                    self.unreachable.insert(
                        node.id.clone(),
                        NodeAgentState::Unreachable { since, cause },
                    );
                }
            }
        }
        Ok(())
    }

    /// Reads the power source every [`POWER_EVERY`]; a failed read is
    /// logged once while it lasts and keeps the source last read.
    fn read_power(&mut self, log: &mut dyn Write, now: UnixTime) -> Result<(), CommandError> {
        if self.power_read.elapsed() < POWER_EVERY {
            return Ok(());
        }
        self.power_read = Instant::now();
        match (self.env.power)() {
            Ok(source) => {
                self.power = source;
                if self.power_failure.take().is_some() {
                    say(log, now, "the power source is read again")?;
                }
            }
            Err(error) => {
                let text = chain(&error);
                if self.power_failure.as_deref() != Some(text.as_str()) {
                    say(log, now, &format!("the power source was not read: {text}"))?;
                    self.power_failure = Some(text);
                }
            }
        }
        Ok(())
    }

    /// Logs a failing meter write once while it lasts, and its recovery.
    fn note_meter(&mut self, log: &mut dyn Write, now: UnixTime) -> Result<(), CommandError> {
        match self.meter.write_failure()? {
            Some(text) => {
                if self.meter_failure.as_deref() != Some(text.as_str()) {
                    say(log, now, &format!("the SIM meter was not written: {text}"))?;
                    self.meter_failure = Some(text);
                }
            }
            None => {
                if self.meter_failure.take().is_some() {
                    say(log, now, "the SIM meter is written again")?;
                }
            }
        }
        Ok(())
    }
}

/// The nodes whose watch had not written its status for longer than
/// [`WATCH_STALE_SECS`] when they answered (design §10.2, `WatchStale`),
/// by the node's own clock.
pub(crate) fn stale_watches(polls: &BTreeMap<NodeId, NodePoll>) -> Vec<DegradedReason> {
    polls
        .iter()
        .filter(|(_, poll)| {
            poll.status
                .now
                .secs_since(poll.status.watch_at)
                .is_none_or(|age| age > WATCH_STALE_SECS)
        })
        .map(|(node, _)| DegradedReason::WatchStale { node: node.clone() })
        .collect()
}

/// Why a node could not be polled, as the status names it. ssh's own
/// failures (connection, login, host key) are one `Transport` until the
/// runner tells them apart.
pub(crate) fn unreachable_cause(error: &CommandError) -> AgentUnreachable {
    match error {
        CommandError::Local(LocalError::Node(node)) => match node {
            NodeError::Spawn(_) => AgentUnreachable::Spawn,
            NodeError::Reply(ReadError::TooLarge { .. }) => AgentUnreachable::ResponseTooLarge,
            NodeError::Reply(_) => AgentUnreachable::Decode,
            NodeError::Encode(_) | NodeError::Agent(_) | NodeError::Unexpected { .. } => {
                AgentUnreachable::ProtocolMismatch
            }
            NodeError::Pipe
            | NodeError::Read(_)
            | NodeError::Ssh { .. }
            | NodeError::Connect(_)
            | NodeError::Relay(_) => AgentUnreachable::Transport,
        },
        CommandError::Local(_) | CommandError::Router(_) => AgentUnreachable::Transport,
    }
}

/// One poll of the M7 through `egress`, after `previous`; without an
/// egress the M7 cannot be reached, which the panel says rather than show
/// an older reading.
fn poll_m7(
    env: &Env<'_>,
    support_dir: &Path,
    log: &mut dyn Write,
    previous: Option<&RouterReading>,
    failure: &mut Option<String>,
    egress: Option<&BsdName>,
) -> Result<RouterReading, CommandError> {
    let polled_at = (env.clock)()?;
    match egress {
        Some(egress) => {
            let outcome = poll_router(env, support_dir, Some(egress));
            let now = (env.clock)()?;
            router_after_poll(log, previous, failure, polled_at, &outcome, now)
        }
        None => Ok(RouterReading::after_poll(
            previous,
            polled_at,
            Err(RouterUnavailableReason::Unreachable),
        )),
    }
}

/// Serves the exit until the acceptor ends or the daemon fails. `state` is
/// the router console's, so the panel carries on.
pub(crate) fn serve(
    env: &mut Env<'_>,
    log: &mut dyn Write,
    support_dir: &Path,
    control: &Control,
    acceptor_ended: &mpsc::Receiver<()>,
    retries: &mpsc::Receiver<()>,
    state: LoopState,
) -> Result<Stopped, CommandError> {
    let env: &Env<'_> = env;
    let mut deployed = Deployed::open(env, support_dir, log, state.previous)?;
    control.deployed.store(true, Ordering::SeqCst);
    say(log, (env.clock)()?, "serving the exit")?;
    loop {
        let next = Instant::now() + TICK;
        let retry = retries.try_iter().count() > 0;
        deployed.tick(control, log, retry)?;
        if wait_for_next_poll(next, acceptor_ended) == Waited::AcceptorEnded {
            return Ok(Stopped::AcceptorEnded);
        }
    }
}
