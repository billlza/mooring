// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon with a deployment (design §10.1): every [`TICK`] it reads
//! the state, resolves the exit's interfaces, checks for foreign networks,
//! reads the SIM meter and ticks the exit machine; it polls the M7 every
//! [`POLL_INTERVAL`] and each node's agent every [`NODE_POLL_EVERY`]
//! (`Status`, design §10.5) in the slot after a direct-probe round, so
//! neither delays a probe; and it publishes the deployment's status when
//! the exit's state changes and at least every [`PUBLISH_EVERY`]. The SIM
//! meter reads the egress counters on a thread of its own, and the power
//! helper's events arrive on one (design §10.3, [`crate::runtime::power`]):
//! the power source, the assertions it holds while the exit is enabled on
//! mains, and the Mac's sleeps, each drained before the daemon lets it
//! proceed, and wakes.
//!
//! The daemon keeps std threads, as the router console did (design §10.1,
//! revision 9): this loop, the meter's thread, and the control socket's
//! acceptor and connections.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

use mooring_agent_proto::{LineRequest, ReadError, Response, WATCH_STALE_SECS};
use mooring_daemon_core::console::ConsoleStatus;
use mooring_daemon_core::exit::{EgressFault, ExitMachine, SimUse, TickInputs};
use mooring_daemon_core::meter::{MAX_SIM_METER_BYTES, SimMeter, accuracy};
use mooring_daemon_core::period::BillingCycle;
use mooring_daemon_core::power::{HelperCommand, HelperEvent};
use mooring_daemon_core::router::RouterReading;
use mooring_daemon_core::snapshot::{NodePoll, SimTotals, StatusInputs, assemble};
use mooring_daemon_core::status::{
    AgentUnreachable, DegradedReason, DrainRecord, ExitState, NodeAgentState, PowerSource,
    PowerStatus,
};
use mooring_model::iface::BsdName;
use mooring_model::time::UnixTime;
use mooring_model::{Deployment, NodeId};
use mooring_store::{Store, read_latch, read_sim_meter};

use super::{
    Control, LoopState, POLL_INTERVAL, RunPaths, Waited, chain, poll_router_on, publish,
    router_after_poll, say, wait_for_next_poll,
};
use crate::app::Env;
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::node::session::ops_session;
use crate::router::error::{RouterError, UnreachableCause};
use crate::runtime::meter::{METER_TICK, MeterThread, PERSIST_EVERY, Watched};
use crate::runtime::network::foreign;
use crate::runtime::ports::{
    DaemonPorts, ENGINE_PID_FILE, EXIT_ENGINE, PROBE_ENGINE, PROBER_PID_FILE, stop_stale_engine,
};
use crate::runtime::power::{PowerLink, PowerMessage};
use crate::runtime::resolve::exit_interfaces;

/// The loop's tick (design §10.1).
pub(crate) const TICK: Duration = Duration::from_secs(2);

/// The longest the console goes without a new status.
pub(crate) const PUBLISH_EVERY: Duration = Duration::from_secs(10);

/// How long the daemon waits for the power helper's first report of the
/// power source after starting it.
pub(crate) const HELPER_FIRST_REPORT: Duration = Duration::from_secs(5);

/// How long after the power helper ended the daemon starts it again, as
/// launchd throttles the daemon itself.
pub(crate) const HELPER_RESTART_EVERY: Duration = Duration::from_secs(60);

/// The sleep drain's budget (design §10.3): past it the daemon lets the
/// sleep proceed (`TimedOut`); a node it did not tell notices the Mac's
/// silence itself.
pub(crate) const DRAIN_BUDGET: Duration = Duration::from_secs(4);

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
    /// The power helper while it runs.
    helper: Option<PowerLink>,
    /// When the power helper ended, for its restart.
    helper_lost: Option<Instant>,
    power: PowerSource,
    assertions_held: bool,
    /// The hold the helper was last told to keep.
    held_sent: Option<bool>,
    last_sleep: Option<UnixTime>,
    last_wake: Option<UnixTime>,
    last_drain: Option<DrainRecord>,
    /// A drained sleep to let proceed once its status is published.
    allow_sleep: Option<u64>,
    published: Option<(Instant, ExitState)>,
    /// The power status last published: a change publishes at once.
    published_power: Option<PowerStatus>,
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
    /// neither is read as none), starts the meter's thread and the power
    /// helper and waits for its report of the power source (one that does
    /// not start or report within [`HELPER_FIRST_REPORT`] stops the daemon:
    /// the bundle that carries the daemon carries the helper); then it
    /// polls the M7 once, so every status it publishes has a panel.
    /// `router` is the panel the router console last showed, if it ran.
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
        let helper = (env.power_helper)()?;
        let power = first_power_source(&helper, HELPER_FIRST_REPORT)?;
        say(log, now, &format!("power helper started: {power:?}"))?;
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
            helper: Some(helper),
            helper_lost: None,
            power,
            assertions_held: false,
            held_sent: None,
            last_sleep: None,
            last_wake: None,
            last_drain: None,
            allow_sleep: None,
            published: None,
            published_power: None,
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
        // The polls' interface, or the fault a poll then fails with.
        let egress_name = egress
            .as_ref()
            .map(|egress| egress.interfaces.egress().bsd_name.clone())
            .map_err(EgressFault::clone);
        self.meter
            .watch(egress.as_ref().ok().map(|egress| Watched {
                index: egress.interfaces.egress().index,
                lladdr: egress.interfaces.egress().lladdr,
            }))?;
        // The check runs while the egress resolves: without it the exit is
        // down already, for that.
        let foreign = match &egress_name {
            Ok(name) => foreign(
                &env.router.link.interfaces().map_err(LocalError::Kernel)?,
                name,
            )?,
            Err(_) => BTreeSet::new(),
        };
        let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), now)
            .map_err(LocalError::Cycle)?;
        let counted = self.meter.meter()?;
        let bytes = counted.cycle_bytes(cycle);
        self.ports.set_egress(egress_name.as_ref().ok().cloned());
        self.service_helper(log, now, deployment)?;
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
                    assertions_held: self.assertions_held,
                    last_sleep: self.last_sleep,
                    last_wake: self.last_wake,
                    last_drain: self.last_drain,
                },
                power_helper_running: self.helper.is_some(),
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
        let state_changed = previous.as_ref() != Some(&section.state)
            || self.published_power != Some(section.power);
        let stale = self
            .published
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= PUBLISH_EVERY);
        if state_changed || stale {
            let router = self.router.clone();
            let exit_state = section.state.clone();
            let section_power = section.power;
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
            self.published_power = Some(section_power);
            self.tell_helper(log, now, state.runtime.exit_enabled)?;
            return Ok(exit_state);
        }
        self.tell_helper(log, now, state.runtime.exit_enabled)?;
        Ok(section.state)
    }

    /// Takes the power helper's events: the source, the assertions it
    /// holds, a sleep, which is drained at once, and a wake. When the
    /// helper has ended it is started again [`HELPER_RESTART_EVERY`] later.
    fn service_helper(
        &mut self,
        log: &mut dyn Write,
        now: UnixTime,
        deployment: &Deployment,
    ) -> Result<(), CommandError> {
        if self.helper.is_none() {
            if self
                .helper_lost
                .is_some_and(|at| at.elapsed() >= HELPER_RESTART_EVERY)
            {
                self.restart_helper(log, now)?;
            }
            return Ok(());
        }
        while let Some(helper) = &self.helper {
            let message = match helper.messages.try_recv() {
                Ok(message) => message,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    PowerMessage::Ended("the power helper's reader stopped".to_owned())
                }
            };
            match message {
                PowerMessage::Event(HelperEvent::PowerSource(source)) => {
                    if source != self.power {
                        say(log, now, &format!("power: {source:?}"))?;
                    }
                    self.power = source;
                }
                PowerMessage::Event(HelperEvent::Assertions { held }) => {
                    self.assertions_held = held;
                }
                PowerMessage::Event(HelperEvent::WillSleep { id }) => {
                    self.drain_for_sleep(log, now, deployment, id)?;
                }
                PowerMessage::Event(HelperEvent::DidWake) => {
                    self.last_wake = Some(now);
                    self.machine.wake();
                    say(log, now, "the Mac woke")?;
                }
                PowerMessage::Ended(text) => self.lose_helper(log, now, &text)?,
            }
        }
        Ok(())
    }

    /// The sleep drain (design §10.3): the machine stops the engine and
    /// tells the nodes within [`DRAIN_BUDGET`], each call bounded by what is
    /// left of it; the sleep is let proceed at the end of this tick, once
    /// the paused status is published.
    fn drain_for_sleep(
        &mut self,
        log: &mut dyn Write,
        now: UnixTime,
        deployment: &Deployment,
        id: u64,
    ) -> Result<(), CommandError> {
        let started = Instant::now();
        let deadline = started + DRAIN_BUDGET;
        let outcome = self
            .machine
            .sleep(now, deployment, &mut self.ports, &mut || {
                budget_left(deadline, Instant::now())
            })?;
        for note in self.ports.take_notes() {
            say(log, now, &note)?;
        }
        say(
            log,
            now,
            &format!(
                "the Mac will sleep: drain {outcome:?} in {:?}",
                started.elapsed()
            ),
        )?;
        self.last_sleep = Some(now);
        self.last_drain = Some(DrainRecord { at: now, outcome });
        self.allow_sleep = Some(id);
        Ok(())
    }

    /// Tells the helper the hold the exit wants, enabled on mains, when it
    /// changed, and lets a drained sleep proceed. A helper that cannot be
    /// written to is lost.
    fn tell_helper(
        &mut self,
        log: &mut dyn Write,
        now: UnixTime,
        exit_enabled: bool,
    ) -> Result<(), CommandError> {
        let Some(helper) = &mut self.helper else {
            return Ok(());
        };
        let wanted = exit_enabled && self.power == PowerSource::Ac;
        let mut sent = Ok(());
        if self.held_sent != Some(wanted) {
            sent = helper.send(&HelperCommand::Hold(wanted));
            if sent.is_ok() {
                self.held_sent = Some(wanted);
            }
        }
        if sent.is_ok()
            && let Some(id) = self.allow_sleep.take()
        {
            sent = helper.send(&HelperCommand::AllowSleep { id });
        }
        if let Err(error) = sent {
            self.lose_helper(log, now, &chain(&error))?;
        }
        Ok(())
    }

    /// The helper ended: the exit is degraded until it runs again, nothing
    /// holds the Mac awake, and a sleep it was holding has proceeded (or the
    /// helper died with it), so the exit is woken.
    fn lose_helper(
        &mut self,
        log: &mut dyn Write,
        now: UnixTime,
        why: &str,
    ) -> Result<(), CommandError> {
        let end = self
            .helper
            .take()
            .map_or_else(|| "not running".to_owned(), PowerLink::close);
        say(log, now, &format!("the power helper ended: {why} ({end})"))?;
        self.helper_lost = Some(Instant::now());
        self.assertions_held = false;
        self.held_sent = None;
        self.allow_sleep = None;
        if self.machine.paused() {
            self.machine.wake();
        }
        Ok(())
    }

    /// Starts the helper again; one that does not start is tried again
    /// [`HELPER_RESTART_EVERY`] later.
    fn restart_helper(&mut self, log: &mut dyn Write, now: UnixTime) -> Result<(), CommandError> {
        match (self.env.power_helper)() {
            Ok(helper) => {
                self.helper = Some(helper);
                self.helper_lost = None;
                say(log, now, "the power helper started again")?;
            }
            Err(error) => {
                self.helper_lost = Some(Instant::now());
                say(
                    log,
                    now,
                    &format!("the power helper could not be started: {}", chain(&error)),
                )?;
            }
        }
        Ok(())
    }

    /// Polls the M7 through the egress ([`poll_m7`]).
    fn poll_router(
        &mut self,
        log: &mut dyn Write,
        egress: Result<&BsdName, &EgressFault>,
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
        egress: Result<&BsdName, &EgressFault>,
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
                Ok(egress) => ops_session(self.env, node, egress, None)
                    .and_then(|mut session| Ok(session.request(&LineRequest::Status)?)),
                Err(fault) => Err(LocalError::NodeUnreachableWithoutEgress {
                    fault: fault.clone(),
                }
                .into()),
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

/// What is left at `now` of a budget that ends at `deadline`; none once
/// it has passed.
pub(crate) fn budget_left(deadline: Instant, now: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|left| !left.is_zero())
}

/// The power helper's first report, within `wait`, which is the power
/// source: the helper reports it before it listens for anything else. A
/// helper that ends, stays silent or reports anything else first stops the
/// daemon.
pub(crate) fn first_power_source(
    helper: &PowerLink,
    wait: Duration,
) -> Result<PowerSource, LocalError> {
    match helper.messages.recv_timeout(wait) {
        Ok(PowerMessage::Event(HelperEvent::PowerSource(source))) => Ok(source),
        Ok(PowerMessage::Event(event)) => Err(LocalError::PowerHelperFirstReport(event)),
        Ok(PowerMessage::Ended(text)) => Err(LocalError::PowerHelperEnded(text)),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(LocalError::PowerHelperSilent { waited: wait }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(LocalError::PowerHelperEnded(
            "the power helper's reader stopped".to_owned(),
        )),
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
            NodeError::PastDeadline => AgentUnreachable::Timeout,
            NodeError::Pipe
            | NodeError::Read(_)
            | NodeError::Ssh { .. }
            | NodeError::Connect(_)
            | NodeError::Relay(_)
            | NodeError::End(_) => AgentUnreachable::Transport,
        },
        CommandError::Local(_) | CommandError::Router(_) => AgentUnreachable::Transport,
    }
}

/// One poll of the M7 through `egress`, after `previous`. Without an
/// egress the M7 cannot be reached: that is the poll's failure, so the
/// panel says so rather than show an older reading, and the log names the
/// fault when the outcome changes, as for any other failure.
pub(crate) fn poll_m7(
    env: &Env<'_>,
    support_dir: &Path,
    log: &mut dyn Write,
    previous: Option<&RouterReading>,
    failure: &mut Option<String>,
    egress: Result<&BsdName, &EgressFault>,
) -> Result<RouterReading, CommandError> {
    let polled_at = (env.clock)()?;
    let outcome = match egress {
        Ok(egress) => poll_router_on(env, support_dir, egress),
        Err(fault) => Err(CommandError::Router(RouterError::unreachable(
            UnreachableCause::ExitInterfacesUnresolved {
                fault: fault.clone(),
            },
        ))),
    };
    let now = (env.clock)()?;
    router_after_poll(log, previous, failure, polled_at, &outcome, now)
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
