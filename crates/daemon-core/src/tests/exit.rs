// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit's state machine (design §10.1, §10.2, §16 L1) against scripted
//! ports: the preflight order, starting and verifying, restarts only on a
//! new digest, violations (engine first, then the latch, then every node),
//! node calls retried or dropped, a retry and the holds it clears, a latch
//! that outlives the daemon, the carrier address changing between probes,
//! failed rounds, start failures, crash back-off and crash loops.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use mooring_fixtures::Fixture;
use mooring_model::collections::NonEmpty;
use mooring_model::counters::ConfigGeneration;
use mooring_model::iface::{BsdName, MacAddr, ResolvedInterface, ResolvedInterfaces};
use mooring_model::node::NodeLifecycle;
use mooring_model::sim::SimPolicy;
use mooring_model::verdict::{LatchRecord, Violation, ViolationKind};
use mooring_model::{Deployment, NodeId, Sha256Digest, UnixTime};
use proptest::prelude::*;

use crate::alert::MacEngine;
use crate::exit::{
    CRASH_LIMIT, CallFault, Egress, EgressFault, ExitMachine, ExitPorts, FAILED_ROUNDS_TOLERATED,
    IN_CHAIN_FIRST, InChainProbe, InChainTarget, NODE_CALL_RETRY, NodeCall, RenderOutcome,
    Rendered, RenderedProber, START_GRACE, SimUse, StartFault, TickInputs,
};
use crate::network::ForeignNetworkFinding;
use crate::status::{
    DegradedReason, DownReason, DrainOutcome, ExitSection, ExitState, LinkState, PowerSource,
    PowerStatus, ProbeStage, ProcessEnd,
};

/// Inside the fixtures' carrier prefix, 31.120.0.0/14.
const CARRIER: Ipv4Addr = Ipv4Addr::new(31, 120, 5, 6);
const OTHER_CARRIER: Ipv4Addr = Ipv4Addr::new(31, 121, 9, 9);
const OUTSIDE: Ipv4Addr = Ipv4Addr::new(82, 10, 20, 30);
/// The fixtures' lon1 address.
const LON1: Ipv4Addr = Ipv4Addr::new(45, 67, 89, 10);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Probe(Ipv4Addr),
    InChain(u16),
    Check(&'static str),
    Start(&'static str),
    Stop,
    Persist(Option<ViolationKind>),
    Call(&'static str, Call),
}

/// A node call by kind, for comparing event logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    CloseGate,
    Shutdown,
    ClearHold,
    Drain(Duration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fault;

#[derive(Debug)]
struct Fake {
    answers: VecDeque<Result<Ipv4Addr, ProbeStage>>,
    answer: Result<Ipv4Addr, ProbeStage>,
    render: Result<Rendered<&'static str>, RenderOutcome>,
    check: Result<(), StartFault>,
    start: Result<(), StartFault>,
    next_pid: u32,
    running: Option<u32>,
    ends: Option<ProcessEnd>,
    calls: BTreeMap<&'static str, VecDeque<Result<(), CallFault>>>,
    latch: Option<LatchRecord>,
    fail_persist: bool,
    log: Vec<Event>,
    /// The prober: its rendered config (no probes unless a test gives
    /// some), its start, and what it did, kept apart from `log`.
    prober: Result<RenderedProber<&'static str>, RenderOutcome>,
    prober_start: Result<(), StartFault>,
    prober_running: Option<u32>,
    prober_ends: Option<ProcessEnd>,
    prober_log: Vec<&'static str>,
    chain: VecDeque<Result<InChainProbe, ProbeStage>>,
    chain_answer: Result<InChainProbe, ProbeStage>,
}

fn config(name: &'static str) -> Rendered<&'static str> {
    Rendered {
        config: name,
        digest: Sha256Digest::of(name.as_bytes()),
    }
}

impl Fake {
    fn new() -> Self {
        Self {
            answers: VecDeque::new(),
            answer: Ok(CARRIER),
            render: Ok(config("one")),
            check: Ok(()),
            start: Ok(()),
            next_pid: 100,
            running: None,
            ends: None,
            calls: BTreeMap::new(),
            latch: None,
            fail_persist: false,
            log: Vec::new(),
            prober: Ok(RenderedProber {
                config: "probe-one",
                digest: Sha256Digest::of(b"probe-one"),
                targets: Vec::new(),
            }),
            prober_start: Ok(()),
            prober_running: None,
            prober_ends: None,
            prober_log: Vec::new(),
            chain: VecDeque::new(),
            chain_answer: Ok(chained(CARRIER)),
        }
    }

    fn take_log(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.log)
    }
}

fn call_name(node: &NodeId) -> &'static str {
    match node.as_str() {
        "lon1" => "lon1",
        "ams1" => "ams1",
        other => panic!("unexpected node {other}"),
    }
}

/// An in-chain answer of `ip`, taking 120 ms.
fn chained(ip: Ipv4Addr) -> InChainProbe {
    InChainProbe {
        ip,
        latency: Duration::from_millis(120),
    }
}

impl ExitPorts for Fake {
    type Config = &'static str;
    type ProberConfig = &'static str;
    type Error = Fault;

    fn render(
        &mut self,
        _deployment: &Deployment,
        _interfaces: &ResolvedInterfaces,
    ) -> Result<Result<Rendered<&'static str>, RenderOutcome>, Fault> {
        Ok(self.render.clone())
    }

    fn check(&mut self, config: &&'static str) -> Result<Result<(), StartFault>, Fault> {
        self.log.push(Event::Check(config));
        Ok(self.check)
    }

    fn start(&mut self, config: &&'static str) -> Result<Result<u32, StartFault>, Fault> {
        self.log.push(Event::Start(config));
        assert!(self.running.is_none(), "started over a running engine");
        Ok(self.start.map(|()| {
            let pid = self.next_pid;
            self.next_pid += 1;
            self.running = Some(pid);
            pid
        }))
    }

    fn exited(&mut self) -> Result<Option<ProcessEnd>, Fault> {
        assert!(
            self.running.is_some(),
            "asked about an engine that is not running"
        );
        Ok(self.ends.take().inspect(|_| self.running = None))
    }

    fn stop(&mut self) -> Result<ProcessEnd, Fault> {
        self.log.push(Event::Stop);
        assert!(self.running.take().is_some(), "stopped no engine");
        Ok(ProcessEnd::Signalled { signal: 9 })
    }

    fn probe(
        &mut self,
        via: &ResolvedInterface,
        reflector: SocketAddrV4,
    ) -> Result<Ipv4Addr, ProbeStage> {
        assert!(via.bsd_name.as_str().starts_with("en"));
        assert_eq!(reflector.port(), 27900);
        self.log.push(Event::Probe(*reflector.ip()));
        self.answers.pop_front().unwrap_or(self.answer)
    }

    fn persist_latch(&mut self, latch: Option<&LatchRecord>) -> Result<(), Fault> {
        if self.fail_persist {
            return Err(Fault);
        }
        self.log
            .push(Event::Persist(latch.map(|latch| latch.violation.kind())));
        self.latch = latch.cloned();
        Ok(())
    }

    fn render_prober(
        &mut self,
        _deployment: &Deployment,
        _interfaces: &ResolvedInterfaces,
    ) -> Result<Result<RenderedProber<&'static str>, RenderOutcome>, Fault> {
        Ok(self.prober.clone())
    }

    fn start_prober(&mut self, config: &&'static str) -> Result<Result<u32, StartFault>, Fault> {
        self.prober_log.push(config);
        assert!(
            self.prober_running.is_none(),
            "started over a running prober"
        );
        Ok(self.prober_start.map(|()| {
            self.prober_running = Some(900);
            900
        }))
    }

    fn prober_exited(&mut self) -> Result<Option<ProcessEnd>, Fault> {
        assert!(self.prober_running.is_some());
        Ok(self
            .prober_ends
            .take()
            .inspect(|_| self.prober_running = None))
    }

    fn stop_prober(&mut self) -> Result<ProcessEnd, Fault> {
        self.prober_log.push("stop");
        assert!(self.prober_running.take().is_some(), "stopped no prober");
        Ok(ProcessEnd::Signalled { signal: 9 })
    }

    fn probe_in_chain(&mut self, port: u16) -> Result<InChainProbe, ProbeStage> {
        self.log.push(Event::InChain(port));
        self.chain.pop_front().unwrap_or(self.chain_answer)
    }

    fn call(&mut self, node: &NodeId, call: &NodeCall) -> Result<(), CallFault> {
        let name = call_name(node);
        let kind = match call {
            NodeCall::CloseGate(_) => Call::CloseGate,
            NodeCall::Shutdown(_) => Call::Shutdown,
            NodeCall::ClearHold => Call::ClearHold,
            NodeCall::Drain { within } => Call::Drain(*within),
        };
        self.log.push(Event::Call(name, kind));
        self.calls
            .get_mut(name)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(()))
    }
}

/// The daemon's view at one tick.
struct World {
    fixture: Fixture,
    deployment: Deployment,
    now: u64,
    mono: u64,
    enabled: bool,
    egress: Result<Egress, EgressFault>,
    foreign: BTreeSet<ForeignNetworkFinding>,
    sim_bytes: u64,
    power: PowerStatus,
    power_helper_running: bool,
    nodes_degraded: Vec<DegradedReason>,
}

impl World {
    fn new() -> Self {
        let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
        let deployment = fixture.deployment.clone();
        let egress = Ok(Egress {
            interfaces: fixture.interfaces.clone(),
            link: LinkState {
                up: true,
                speed_mbps: Some(1000),
            },
        });
        Self {
            fixture,
            deployment,
            now: mooring_fixtures::FIXTURE_NOW.as_secs(),
            mono: 1_000,
            enabled: true,
            egress,
            foreign: BTreeSet::new(),
            sim_bytes: 0,
            power_helper_running: true,
            nodes_degraded: Vec::new(),
            power: PowerStatus {
                source: PowerSource::Ac,
                assertions_held: false,
                last_sleep: None,
                last_wake: None,
                last_drain: None,
            },
        }
    }

    fn inputs(&self, retry: bool) -> TickInputs<'_> {
        TickInputs {
            now: UnixTime::from_secs(self.now),
            mono: Duration::from_secs(self.mono),
            deployment: &self.deployment,
            exit_enabled: self.enabled,
            egress: self.egress.clone(),
            foreign: self.foreign.clone(),
            sim: SimUse {
                cycle_start: mooring_model::CalendarDate::parse("2026-10-01").unwrap(),
                bytes: self.sim_bytes,
            },
            power: self.power,
            power_helper_running: self.power_helper_running,
            retry,
            nodes_degraded: self.nodes_degraded.clone(),
        }
    }

    fn tick(&self, machine: &mut ExitMachine, fake: &mut Fake) -> ExitSection {
        machine.tick(&self.inputs(false), fake).unwrap()
    }

    fn retry(&self, machine: &mut ExitMachine, fake: &mut Fake) -> ExitSection {
        machine.tick(&self.inputs(true), fake).unwrap()
    }

    fn advance(&mut self, secs: u64) {
        self.now += secs;
        self.mono += secs;
    }

    fn machine(&self) -> ExitMachine {
        ExitMachine::new(UnixTime::from_secs(self.now), None)
    }

    /// The deployment with `edit` applied to its parts.
    fn edit(&mut self, edit: impl FnOnce(&mut mooring_model::DeploymentParts)) {
        let mut parts = self.deployment.clone().into_parts();
        edit(&mut parts);
        self.deployment = Deployment::try_from(parts).unwrap();
    }

    /// A running, verifying exit, its log cleared.
    fn serving(&mut self) -> (ExitMachine, Fake) {
        let mut machine = self.machine();
        let mut fake = Fake::new();
        self.tick(&mut machine, &mut fake);
        self.advance(START_GRACE.as_secs());
        assert_eq!(
            self.tick(&mut machine, &mut fake).state,
            ExitState::Verifying
        );
        fake.take_log();
        (machine, fake)
    }
}

fn down(reason: DownReason) -> ExitState {
    ExitState::Down { reason }
}

#[test]
fn a_good_probe_starts_the_engine_which_verifies_after_the_grace() {
    let mut world = World::new();
    let mut machine = world.machine();
    let mut fake = Fake::new();
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.state, ExitState::Starting);
    assert_eq!(section.since, UnixTime::from_secs(world.now));
    // The first node whose reflector answers is enough.
    assert_eq!(
        fake.take_log(),
        [
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12)),
            Event::Check("one"),
            Event::Start("one")
        ]
    );
    assert_eq!(section.engines.exit.pid, Some(100));
    assert_eq!(section.engines.exit.restarts, 0);
    let check = section.carrier_check.unwrap();
    assert_eq!(
        (check.egress_ip, check.in_carrier_prefixes, check.checked_at),
        (CARRIER, true, UnixTime::from_secs(world.now))
    );
    let egress = section.egress.unwrap();
    assert_eq!(
        (egress.interface.as_str(), egress.ipv4),
        ("en8", Ipv4Addr::new(192, 168, 1, 20))
    );
    world.advance(START_GRACE.as_secs() - 1);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Starting
    );
    world.advance(1);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.state, ExitState::Verifying);
    assert_eq!(section.since, UnixTime::from_secs(world.now));
    // No probe until 30 s after the first, and no restart.
    assert_eq!(fake.take_log(), []);
    // The state's start stays while the state does.
    let verified_at = section.since;
    world.advance(10);
    assert_eq!(world.tick(&mut machine, &mut fake).since, verified_at);
    // The next round is due 30 s after the first.
    let mono = |world: &World| Duration::from_secs(world.mono);
    assert_eq!(
        machine.next_probe_in(mono(&world), &world.deployment),
        Some(Duration::from_secs(10))
    );
    world.advance(10);
    assert_eq!(
        machine.next_probe_in(mono(&world), &world.deployment),
        Some(Duration::ZERO)
    );
    world.tick(&mut machine, &mut fake);
    assert_eq!(
        fake.take_log(),
        [Event::Probe(Ipv4Addr::new(46, 78, 90, 12))]
    );
    // Before any tick, and after one that stopped before the probes, no
    // probe is pending.
    assert_eq!(
        world
            .machine()
            .next_probe_in(mono(&world), &world.deployment),
        None
    );
    world.enabled = false;
    world.tick(&mut machine, &mut fake);
    assert_eq!(machine.next_probe_in(mono(&world), &world.deployment), None);
}

#[test]
fn the_engine_restarts_only_when_the_digest_changes() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    for _ in 0..20 {
        world.advance(30);
        world.tick(&mut machine, &mut fake);
    }
    assert!(
        fake.take_log()
            .iter()
            .all(|event| matches!(event, Event::Probe(_)))
    );
    fake.render = Ok(config("two"));
    world.advance(2);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(
        fake.take_log(),
        [Event::Stop, Event::Check("two"), Event::Start("two")]
    );
    assert_eq!(section.state, ExitState::Starting);
    assert_eq!(section.engines.exit.pid, Some(101));
    assert_eq!(section.engines.exit.restarts, 1);
    assert_eq!(
        section.engines.exit.last_exit.map(|exit| exit.end),
        Some(ProcessEnd::Signalled { signal: 9 })
    );
}

/// A change to the world before a tick.
type Setup = Box<dyn Fn(&mut World)>;

#[test]
fn preflight_checks_apply_in_order_and_stop_the_engine() {
    let cases: Vec<(&str, Setup, DownReason)> = vec![
        (
            "plan",
            Box::new(|world: &mut World| {
                let mut policy = serde_json::to_value(&world.deployment.exit().sim).unwrap();
                policy["plan"] = serde_json::Value::Null;
                let policy: SimPolicy = serde_json::from_value(policy).unwrap();
                world.edit(|parts| parts.exit.sim = policy);
                // Everything after it fails too.
                world.egress = Err(EgressFault::Absent);
            }),
            DownReason::SimPlanUnrecorded,
        ),
        (
            "cap",
            Box::new(|world: &mut World| {
                world.sim_bytes = mooring_fixtures::FIXTURE_SIM_HARD_STOP_BYTES;
                world.egress = Err(EgressFault::Absent);
            }),
            DownReason::SimCapReached {
                cycle_start: mooring_model::CalendarDate::parse("2026-10-01").unwrap(),
            },
        ),
        (
            "egress",
            Box::new(|world: &mut World| {
                world.egress = Err(EgressFault::Ambiguous { matches: 2 });
                world.foreign = BTreeSet::from([ForeignNetworkFinding::RoutableIpv4 {
                    interface: BsdName::parse("en0").unwrap(),
                }]);
            }),
            DownReason::EgressAmbiguous { matches: 2 },
        ),
        (
            "foreign",
            Box::new(|world: &mut World| {
                world.foreign = BTreeSet::from([ForeignNetworkFinding::RoutableIpv4 {
                    interface: BsdName::parse("en0").unwrap(),
                }]);
                world.edit(|parts| parts.exit.egress_check = None);
            }),
            DownReason::ForeignNetworkAttached {
                findings: NonEmpty::new(ForeignNetworkFinding::RoutableIpv4 {
                    interface: BsdName::parse("en0").unwrap(),
                }),
            },
        ),
        (
            "carrier",
            Box::new(|world: &mut World| world.edit(|parts| parts.exit.egress_check = None)),
            DownReason::CarrierCheckUnrecorded,
        ),
        (
            "applied",
            Box::new(|world: &mut World| {
                world.edit(|parts| {
                    for node in &mut parts.nodes {
                        if let NodeLifecycle::Applied { site, .. } = &node.lifecycle {
                            node.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
                        }
                    }
                });
            }),
            DownReason::NoAppliedNode,
        ),
    ];
    for (name, setup, reason) in cases {
        let mut world = World::new();
        let (mut machine, mut fake) = world.serving();
        setup(&mut world);
        world.advance(2);
        let section = world.tick(&mut machine, &mut fake);
        assert_eq!(section.state, down(reason), "{name}");
        // No probe ran: the check before it failed.
        assert_eq!(fake.take_log(), [Event::Stop], "{name}");
        assert_eq!(section.engines.exit.pid, None, "{name}");
    }
}

#[test]
fn every_egress_fault_is_its_down_reason() {
    for (fault, reason) in [
        (EgressFault::Absent, DownReason::EgressInterfaceAbsent),
        (
            EgressFault::Ambiguous { matches: 3 },
            DownReason::EgressAmbiguous { matches: 3 },
        ),
        (
            EgressFault::NoIpv4 {
                interface: BsdName::parse("en8").unwrap(),
            },
            DownReason::EgressNoIpv4 {
                interface: BsdName::parse("en8").unwrap(),
            },
        ),
        (
            EgressFault::SubnetMismatch,
            DownReason::EgressSubnetMismatch,
        ),
        (EgressFault::UplinkAbsent, DownReason::UplinkAbsent),
        (
            EgressFault::UplinkEqualsEgress,
            DownReason::UplinkEqualsEgress,
        ),
    ] {
        let mut world = World::new();
        world.egress = Err(fault);
        let section = world.tick(&mut world.machine(), &mut Fake::new());
        assert_eq!(section.state, down(reason));
        assert_eq!(section.egress, None);
    }
}

#[test]
fn a_disabled_exit_runs_nothing_and_disabling_stops_the_engine() {
    let mut world = World::new();
    world.enabled = false;
    let mut machine = world.machine();
    let mut fake = Fake::new();
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Disabled
    );
    assert_eq!(fake.take_log(), []);
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    world.enabled = false;
    world.advance(2);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Disabled
    );
    assert_eq!(fake.take_log(), [Event::Stop]);
}

#[test]
fn an_address_outside_the_prefixes_stops_latches_then_closes_every_gate() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Ok(OUTSIDE);
    world.advance(30);
    let section = world.tick(&mut machine, &mut fake);
    let violation = Violation::OutsideCarrierPrefixes { ip: OUTSIDE };
    assert_eq!(
        section.state,
        down(DownReason::Violation(violation.clone()))
    );
    // The engine first, then the latch, then the nodes in id order.
    assert_eq!(
        fake.take_log(),
        [
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12)),
            Event::Stop,
            Event::Persist(Some(ViolationKind::OutsideCarrierPrefixes)),
            Event::Call("ams1", Call::CloseGate),
            Event::Call("lon1", Call::CloseGate),
        ]
    );
    let latch = fake.latch.clone().unwrap();
    assert_eq!(latch.violation, violation);
    assert_eq!(latch.at, UnixTime::from_secs(world.now));
    assert_eq!(
        latch.config_generation,
        world.deployment.config_generation()
    );
    assert_eq!(latch.egress, world.fixture.interfaces.egress().identity());
    assert_eq!(section.latches.len(), 1);
    assert!(!section.carrier_check.unwrap().in_carrier_prefixes);
    // It stays down, probes nothing, and never starts by itself.
    fake.answer = Ok(CARRIER);
    for _ in 0..10 {
        world.advance(30);
        assert_eq!(
            world.tick(&mut machine, &mut fake).state,
            down(DownReason::Violation(violation.clone()))
        );
    }
    assert_eq!(fake.take_log(), []);
}

#[test]
fn the_egress_showing_a_node_address_halts_that_node() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Ok(LON1);
    world.advance(30);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(
        section.state,
        down(DownReason::Violation(Violation::EgressIsNodeAddress {
            node: NodeId::parse("lon1").unwrap(),
            ip: LON1,
        }))
    );
    assert_eq!(
        fake.take_log()[3..],
        [
            Event::Call("ams1", Call::CloseGate),
            Event::Call("lon1", Call::Shutdown),
        ]
    );
}

#[test]
fn undelivered_calls_are_retried_and_refused_ones_dropped() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.calls.insert(
        "ams1",
        VecDeque::from([Err(CallFault::Unreachable), Err(CallFault::Unreachable)]),
    );
    fake.calls
        .insert("lon1", VecDeque::from([Err(CallFault::Refused)]));
    fake.answer = Ok(OUTSIDE);
    world.advance(30);
    world.tick(&mut machine, &mut fake);
    fake.take_log();
    let pending: Vec<&str> = machine
        .pending_calls()
        .keys()
        .map(|node| node.as_str())
        .collect();
    assert_eq!(pending, ["ams1"]);
    world.advance(NODE_CALL_RETRY.as_secs() - 1);
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.take_log(), []);
    world.advance(1);
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.take_log(), [Event::Call("ams1", Call::CloseGate)]);
    world.advance(NODE_CALL_RETRY.as_secs());
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.take_log(), [Event::Call("ams1", Call::CloseGate)]);
    assert!(machine.pending_calls().is_empty());
}

#[test]
fn a_retry_clears_the_latch_then_the_holds_after_a_fresh_probe() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Ok(OUTSIDE);
    world.advance(30);
    world.tick(&mut machine, &mut fake);
    fake.take_log();
    // Still outside: the retry clears the latch, and the fresh probe
    // latches again; no hold is cleared.
    world.advance(5);
    let section = world.retry(&mut machine, &mut fake);
    assert!(matches!(
        section.state,
        ExitState::Down {
            reason: DownReason::Violation(_)
        }
    ));
    assert_eq!(
        fake.take_log(),
        [
            Event::Persist(None),
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12)),
            Event::Persist(Some(ViolationKind::OutsideCarrierPrefixes)),
            Event::Call("ams1", Call::CloseGate),
            Event::Call("lon1", Call::CloseGate),
        ]
    );
    // Back on the carrier: the holds clear, then the engine starts.
    fake.answer = Ok(CARRIER);
    world.advance(5);
    let section = world.retry(&mut machine, &mut fake);
    assert_eq!(section.state, ExitState::Starting);
    assert_eq!(section.latches, []);
    assert_eq!(fake.latch, None);
    assert_eq!(
        fake.take_log(),
        [
            Event::Persist(None),
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12)),
            Event::Check("one"),
            Event::Start("one"),
            Event::Call("ams1", Call::ClearHold),
            Event::Call("lon1", Call::ClearHold),
        ]
    );
}

#[test]
fn a_retry_without_a_latch_still_clears_the_holds() {
    // The nodes may hold a violation the Mac no longer has a latch for
    // (its file was removed by hand): a retry clears their holds too.
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    world.advance(2);
    assert_eq!(
        world.retry(&mut machine, &mut fake).state,
        ExitState::Verifying
    );
    assert_eq!(
        fake.take_log(),
        [
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12)),
            Event::Call("ams1", Call::ClearHold),
            Event::Call("lon1", Call::ClearHold),
        ]
    );
}

#[test]
fn a_retry_drops_an_undelivered_gate_call_but_keeps_a_halt() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.calls
        .insert("ams1", VecDeque::from([Err(CallFault::Unreachable)]));
    fake.calls
        .insert("lon1", VecDeque::from([Err(CallFault::Unreachable)]));
    fake.answer = Ok(LON1);
    world.advance(30);
    world.tick(&mut machine, &mut fake);
    fake.take_log();
    // The address is the carrier's again; the operator retries.
    fake.answer = Ok(CARRIER);
    world.advance(5);
    world.retry(&mut machine, &mut fake);
    let pending: Vec<(&str, bool)> = machine
        .pending_calls()
        .iter()
        .map(|(node, call)| (node.as_str(), matches!(call, NodeCall::Shutdown(_))))
        .collect();
    // ams1's undelivered gate call is replaced by its hold being cleared;
    // lon1's halt stands, until the operator resumes the node.
    assert_eq!(pending, [("lon1", true)]);
    assert!(
        fake.take_log()
            .contains(&Event::Call("ams1", Call::ClearHold))
    );
}

#[test]
fn a_latch_cleared_by_a_new_generation_is_followed_by_a_fresh_probe() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Ok(OUTSIDE);
    world.advance(30);
    world.tick(&mut machine, &mut fake);
    fake.take_log();
    fake.answer = Ok(CARRIER);
    world.advance(2);
    world.edit(|parts| parts.config_generation = ConfigGeneration::new(2).unwrap());
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Starting
    );
    assert_eq!(
        fake.take_log()[..2],
        [
            Event::Persist(None),
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12))
        ]
    );
}

#[test]
fn a_latch_outlives_the_daemon_and_is_sent_to_the_nodes_again() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Ok(OUTSIDE);
    world.advance(30);
    world.tick(&mut machine, &mut fake);
    let latch = fake.latch.clone().unwrap();
    // A new daemon reads the file.
    world.advance(60);
    let mut restarted = ExitMachine::new(UnixTime::from_secs(world.now), Some(latch.clone()));
    let mut fake = Fake::new();
    fake.answer = Ok(CARRIER);
    let section = world.tick(&mut restarted, &mut fake);
    assert_eq!(
        section.state,
        down(DownReason::Violation(latch.violation.clone()))
    );
    assert_eq!(section.latches[0].at, latch.at);
    assert_eq!(
        fake.take_log(),
        [
            Event::Call("ams1", Call::CloseGate),
            Event::Call("lon1", Call::CloseGate),
        ]
    );
    world.advance(30);
    world.tick(&mut restarted, &mut fake);
    assert_eq!(fake.take_log(), []);
    assert_eq!(restarted.latch(), Some(&latch));
}

#[test]
fn a_new_generation_or_egress_identity_clears_the_latch() {
    let latched = |world: &World| LatchRecord {
        violation: Violation::OutsideCarrierPrefixes { ip: OUTSIDE },
        at: UnixTime::from_secs(world.now - 100),
        config_generation: world.deployment.config_generation(),
        egress: world.fixture.interfaces.egress().identity(),
    };
    // Another generation.
    let mut world = World::new();
    let latch = latched(&world);
    world.edit(|parts| parts.config_generation = ConfigGeneration::new(2).unwrap());
    let mut machine = ExitMachine::new(UnixTime::from_secs(world.now), Some(latch.clone()));
    let mut fake = Fake::new();
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.state, ExitState::Starting);
    assert_eq!(
        fake.take_log(),
        [
            Event::Persist(None),
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12)),
            Event::Check("one"),
            Event::Start("one"),
            Event::Call("ams1", Call::ClearHold),
            Event::Call("lon1", Call::ClearHold),
        ]
    );
    // Another egress interface.
    let mut world = World::new();
    let latch = latched(&world);
    let site = world.deployment.exit().clone();
    world.egress = Ok(Egress {
        interfaces: site
            .resolve(
                ResolvedInterface {
                    bsd_name: BsdName::parse("en9").unwrap(),
                    index: mooring_model::iface::InterfaceIndex::new(22).unwrap(),
                    lladdr: MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
                    ipv4: Ipv4Addr::new(192, 168, 1, 21),
                },
                mooring_model::iface::ResolvedUplink::SameAsExit,
            )
            .unwrap(),
        link: LinkState {
            up: true,
            speed_mbps: None,
        },
    });
    let mut machine = ExitMachine::new(UnixTime::from_secs(world.now), Some(latch.clone()));
    let mut fake = Fake::new();
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Starting
    );
    assert_eq!(fake.latch, None);
    // The same generation and egress keep it.
    let mut world = World::new();
    let latch = latched(&world);
    let mut machine = ExitMachine::new(UnixTime::from_secs(world.now), Some(latch.clone()));
    world.advance(1);
    assert_eq!(
        world.tick(&mut machine, &mut Fake::new()).state,
        down(DownReason::Violation(latch.violation))
    );
}

#[test]
fn a_carrier_address_that_changes_within_the_prefixes_is_no_violation() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Ok(OTHER_CARRIER);
    world.advance(30);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.state, ExitState::Verifying);
    assert_eq!(section.carrier_check.unwrap().egress_ip, OTHER_CARRIER);
    assert_eq!(
        fake.take_log(),
        [Event::Probe(Ipv4Addr::new(46, 78, 90, 12))]
    );
}

#[test]
fn failed_rounds_stop_a_running_engine_only_past_the_tolerance() {
    // Before the engine starts, one failed round keeps it stopped; every
    // node is tried and the last failure is named.
    let mut world = World::new();
    let mut machine = world.machine();
    let mut fake = Fake::new();
    fake.answers = VecDeque::from([Err(ProbeStage::Connect), Err(ProbeStage::Read)]);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(
        section.state,
        down(DownReason::DirectProbeFailed {
            node: NodeId::parse("lon1").unwrap(),
            stage: ProbeStage::Read,
        })
    );
    assert_eq!(
        fake.take_log(),
        [
            Event::Probe(Ipv4Addr::new(46, 78, 90, 12)),
            Event::Probe(LON1)
        ]
    );
    // It stays down without probing until the next round is due.
    world.advance(2);
    assert!(matches!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Down { .. }
    ));
    assert_eq!(fake.take_log(), []);
    world.advance(28);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Starting
    );
    // A running engine survives the tolerated rounds.
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Err(ProbeStage::Connect);
    for _ in 0..FAILED_ROUNDS_TOLERATED {
        world.advance(30);
        assert_eq!(
            world.tick(&mut machine, &mut fake).state,
            ExitState::Verifying
        );
    }
    world.advance(30);
    let section = world.tick(&mut machine, &mut fake);
    assert!(matches!(
        section.state,
        ExitState::Down {
            reason: DownReason::DirectProbeFailed { .. }
        }
    ));
    assert_eq!(section.engines.exit.pid, None);
    // A good round brings it back.
    fake.answer = Ok(CARRIER);
    world.advance(30);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Starting
    );
}

#[test]
fn an_exit_within_the_grace_holds_the_engine_until_the_config_changes() {
    let mut world = World::new();
    let mut machine = world.machine();
    let mut fake = Fake::new();
    world.tick(&mut machine, &mut fake);
    fake.ends = Some(ProcessEnd::Exited { code: 1 });
    world.advance(START_GRACE.as_secs() - 1);
    let failed = down(DownReason::EngineStartFailed {
        engine: MacEngine::Exit,
    });
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.state, failed);
    assert_eq!(
        section.engines.exit.last_exit.map(|exit| exit.end),
        Some(ProcessEnd::Exited { code: 1 })
    );
    fake.take_log();
    for _ in 0..5 {
        world.advance(30);
        assert_eq!(world.tick(&mut machine, &mut fake).state, failed);
    }
    assert!(
        fake.take_log()
            .iter()
            .all(|event| matches!(event, Event::Probe(_)))
    );
    // A new config tries again.
    fake.render = Ok(config("two"));
    world.advance(2);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Starting
    );
    assert_eq!(fake.take_log(), [Event::Check("two"), Event::Start("two")]);
    // So does a retry, with the same config.
    fake.ends = Some(ProcessEnd::Signalled { signal: 6 });
    world.advance(1);
    assert_eq!(world.tick(&mut machine, &mut fake).state, failed);
    world.advance(1);
    assert_eq!(
        world.retry(&mut machine, &mut fake).state,
        ExitState::Starting
    );
}

#[test]
fn an_exit_at_the_end_of_the_grace_is_a_crash() {
    let mut world = World::new();
    let mut machine = world.machine();
    let mut fake = Fake::new();
    world.tick(&mut machine, &mut fake);
    fake.ends = Some(ProcessEnd::Exited { code: 1 });
    world.advance(START_GRACE.as_secs());
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.state, ExitState::Starting);
    world.advance(1);
    assert!(
        world
            .tick(&mut machine, &mut fake)
            .engines
            .exit
            .pid
            .is_some()
    );
}

#[test]
fn a_rejected_config_a_failed_spawn_or_a_slow_check_holds_the_engine() {
    for (fault, reason, started) in [
        (
            StartFault::Rejected,
            DownReason::EngineConfigRejected {
                engine: MacEngine::Exit,
            },
            false,
        ),
        (
            StartFault::CheckTimedOut,
            DownReason::EngineStartFailed {
                engine: MacEngine::Exit,
            },
            false,
        ),
        (
            StartFault::Spawn,
            DownReason::EngineSpawnFailed {
                engine: MacEngine::Exit,
            },
            true,
        ),
    ] {
        let mut world = World::new();
        let mut machine = world.machine();
        let mut fake = Fake::new();
        if started {
            fake.start = Err(fault);
        } else {
            fake.check = Err(fault);
        }
        assert_eq!(
            world.tick(&mut machine, &mut fake).state,
            down(reason.clone())
        );
        world.advance(30);
        assert_eq!(
            world.tick(&mut machine, &mut fake).state,
            down(reason.clone())
        );
        let starts = fake
            .take_log()
            .iter()
            .filter(|event| matches!(event, Event::Check(_)))
            .count();
        assert_eq!(starts, 1, "{reason:?}");
    }
}

#[test]
fn crashes_back_off_and_the_fifth_in_ten_minutes_is_a_crash_loop() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    let mut waits = Vec::new();
    for crash in 1..=CRASH_LIMIT {
        fake.ends = Some(ProcessEnd::Signalled { signal: 11 });
        world.advance(2);
        let section = world.tick(&mut machine, &mut fake);
        if crash == CRASH_LIMIT {
            assert_eq!(
                section.state,
                down(DownReason::EngineCrashLoop {
                    engine: MacEngine::Exit
                })
            );
            break;
        }
        assert_eq!(section.state, ExitState::Starting, "crash {crash}");
        assert_eq!(section.engines.exit.pid, None);
        // Count the seconds until it starts again.
        let mut waited = 0;
        loop {
            world.advance(1);
            waited += 1;
            if world
                .tick(&mut machine, &mut fake)
                .engines
                .exit
                .pid
                .is_some()
            {
                break;
            }
        }
        waits.push(waited);
        // Healthy again before the next crash.
        world.advance(START_GRACE.as_secs());
        world.tick(&mut machine, &mut fake);
    }
    assert_eq!(waits, [1, 2, 4, 8]);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.engines.exit.restarts, 4);
}

#[test]
fn render_outcomes_are_down_reasons() {
    for (outcome, reason) in [
        (
            RenderOutcome::SecretsUnavailable,
            DownReason::SecretsUnavailable,
        ),
        (RenderOutcome::NoAppliedNode, DownReason::NoAppliedNode),
    ] {
        let mut world = World::new();
        let (mut machine, mut fake) = world.serving();
        fake.render = Err(outcome);
        world.advance(2);
        assert_eq!(world.tick(&mut machine, &mut fake).state, down(reason));
        assert_eq!(fake.take_log(), [Event::Stop]);
    }
}

#[test]
fn on_battery_a_running_exit_is_degraded() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    world.power.source = PowerSource::Battery;
    world.advance(2);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(
        section.state,
        ExitState::Degraded {
            reasons: NonEmpty::new(DegradedReason::OnBattery)
        }
    );
    assert_eq!(section.power.source, PowerSource::Battery);
}

/// Without the power helper a running exit is degraded: nothing keeps the
/// Mac awake and no sleep is drained.
#[test]
fn without_the_power_helper_a_running_exit_is_degraded() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    world.power_helper_running = false;
    world.advance(2);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Degraded {
            reasons: NonEmpty::new(DegradedReason::PowerHelperExited)
        }
    );
    world.power_helper_running = true;
    world.advance(2);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Verifying
    );
}

/// A sleep stops the engine first, then asks every node with a site to
/// close its gate for the drain, and the exit stays paused, the engine
/// stopped, until the wake; the tick after the wake probes afresh and
/// starts the engine again.
#[test]
fn a_sleep_stops_the_engine_drains_the_nodes_and_pauses_until_the_wake() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    let deployment = world.deployment.clone();
    let mut left = [3_000, 2_500, 2_000].map(Duration::from_millis).into_iter();
    let mut budget = || left.next();
    let outcome = machine
        .sleep(
            UnixTime::from_secs(world.now),
            &deployment,
            &mut fake,
            &mut budget,
        )
        .unwrap();
    assert_eq!(outcome, DrainOutcome::Completed);
    assert!(machine.paused());
    let log = fake.take_log();
    assert_eq!(log.first(), Some(&Event::Stop), "{log:?}");
    let drained: Vec<&Event> = log
        .iter()
        .filter(|event| matches!(event, Event::Call(_, Call::Drain(_))))
        .collect();
    // Each call is bounded by what was left of the budget when it was made.
    assert_eq!(
        drained,
        [
            &Event::Call("ams1", Call::Drain(Duration::from_millis(3_000))),
            &Event::Call("lon1", Call::Drain(Duration::from_millis(2_500)))
        ]
    );
    // Paused: ticks keep the engine stopped and probe nothing.
    for _ in 0..3 {
        world.advance(30);
        let section = world.tick(&mut machine, &mut fake);
        assert_eq!(section.state, ExitState::Paused);
        assert_eq!(section.engines.exit.pid, None);
    }
    assert_eq!(fake.take_log(), []);
    // Woken: the next tick probes at once and starts the engine.
    machine.wake();
    assert!(!machine.paused());
    world.advance(2);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.state, ExitState::Starting);
    let log = fake.take_log();
    assert!(
        matches!(log.first(), Some(Event::Probe(_))),
        "a fresh direct probe first: {log:?}"
    );
    assert!(log.contains(&Event::Start("one")), "{log:?}");
}

/// The drain's budget is checked before each node and after the last: a
/// budget that runs out stops the calls (`TimedOut`), and one that runs out
/// during the last call times the drain out too; a node that cannot be
/// reached is `Failed`, the other nodes still asked.
#[test]
fn a_drain_past_its_budget_times_out_and_an_unreached_node_fails_it() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    let deployment = world.deployment.clone();
    let mut left = [Some(Duration::from_millis(1_500)), None].into_iter();
    let mut budget = || left.next().flatten();
    let outcome = machine
        .sleep(
            UnixTime::from_secs(world.now),
            &deployment,
            &mut fake,
            &mut budget,
        )
        .unwrap();
    assert_eq!(outcome, DrainOutcome::TimedOut);
    let drained: Vec<Event> = fake
        .take_log()
        .into_iter()
        .filter(|event| matches!(event, Event::Call(_, Call::Drain(_))))
        .collect();
    assert_eq!(
        drained,
        [Event::Call(
            "ams1",
            Call::Drain(Duration::from_millis(1_500))
        )]
    );
    // Both nodes asked, and the budget gone by the end: timed out.
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    let mut left = [
        Some(Duration::from_secs(2)),
        Some(Duration::from_secs(1)),
        None,
    ]
    .into_iter();
    let mut budget = || left.next().flatten();
    let outcome = machine
        .sleep(
            UnixTime::from_secs(world.now),
            &deployment,
            &mut fake,
            &mut budget,
        )
        .unwrap();
    assert_eq!(outcome, DrainOutcome::TimedOut);
    assert!(
        fake.take_log()
            .contains(&Event::Call("lon1", Call::Drain(Duration::from_secs(1))))
    );

    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.calls
        .insert("ams1", VecDeque::from([Err(CallFault::Unreachable)]));
    let mut budget = || Some(Duration::from_secs(4));
    let outcome = machine
        .sleep(
            UnixTime::from_secs(world.now),
            &deployment,
            &mut fake,
            &mut budget,
        )
        .unwrap();
    assert_eq!(outcome, DrainOutcome::Failed);
    assert!(
        fake.take_log()
            .contains(&Event::Call("lon1", Call::Drain(Duration::from_secs(4))))
    );
    // A sleep with no engine running drains all the same.
    let mut world = World::new();
    world.enabled = false;
    let mut machine = world.machine();
    let mut fake = Fake::new();
    world.tick(&mut machine, &mut fake);
    fake.take_log();
    let outcome = machine
        .sleep(
            UnixTime::from_secs(world.now),
            &deployment,
            &mut fake,
            &mut budget,
        )
        .unwrap();
    assert_eq!(outcome, DrainOutcome::Completed);
    let log = fake.take_log();
    assert!(!log.contains(&Event::Stop), "{log:?}");
    assert_eq!(log.len(), 2, "{log:?}");
}

#[test]
fn a_latch_that_cannot_be_persisted_ends_the_tick_with_the_engine_stopped() {
    let mut world = World::new();
    let (mut machine, mut fake) = world.serving();
    fake.answer = Ok(OUTSIDE);
    fake.fail_persist = true;
    world.advance(30);
    assert_eq!(machine.tick(&world.inputs(false), &mut fake), Err(Fault));
    assert_eq!(fake.running, None);
    assert_eq!(
        fake.take_log(),
        [Event::Probe(Ipv4Addr::new(46, 78, 90, 12)), Event::Stop]
    );
}

/// One probe answer in the property below.
#[derive(Debug, Clone, Copy)]
enum Answer {
    Carrier,
    Outside,
    Node,
    Fails,
}

proptest! {
    /// Whatever the carrier address does from one round to the next, the
    /// engine never runs after a round that saw a violation, and the first
    /// violation is the one latched until a retry.
    #[test]
    fn the_engine_never_runs_after_a_violation(
        answers in prop::collection::vec(
            prop_oneof![
                4 => Just(Answer::Carrier),
                1 => Just(Answer::Outside),
                1 => Just(Answer::Node),
                1 => Just(Answer::Fails),
            ],
            1..30,
        ),
    ) {
        let mut world = World::new();
        let mut machine = world.machine();
        let mut fake = Fake::new();
        let mut first = None;
        for answer in answers {
            fake.answers = VecDeque::from(match answer {
                Answer::Carrier => vec![Ok(CARRIER)],
                Answer::Outside => vec![Ok(OUTSIDE)],
                Answer::Node => vec![Ok(LON1)],
                Answer::Fails => vec![Err(ProbeStage::Connect), Err(ProbeStage::Connect)],
            });
            world.advance(30);
            let section = world.tick(&mut machine, &mut fake);
            if first.is_none() && matches!(answer, Answer::Outside | Answer::Node) {
                first = Some(answer);
            }
            if let Some(first) = first {
                prop_assert_eq!(section.engines.exit.pid, None);
                prop_assert_eq!(fake.running, None);
                let kind = fake.latch.as_ref().map(|latch| latch.violation.kind());
                let expected = match first {
                    Answer::Outside => ViolationKind::OutsideCarrierPrefixes,
                    _ => ViolationKind::EgressIsNodeAddress,
                };
                prop_assert_eq!(kind, Some(expected));
            }
        }
    }
}

// --- In-chain probes ------------------------------------------------------

const AMS1: Ipv4Addr = Ipv4Addr::new(46, 78, 90, 12);

/// A prober serving ams1 through REALITY and lon1 through Hysteria2.
fn two_probes(fake: &mut Fake) {
    fake.prober = Ok(RenderedProber {
        config: "probe-one",
        digest: Sha256Digest::of(b"probe-one"),
        targets: vec![
            InChainTarget {
                node: NodeId::parse("ams1").unwrap(),
                protocol: mooring_model::exit::ProbeProtocol::Reality,
                port: 47101,
                reflector: SocketAddrV4::new(AMS1, 27900),
            },
            InChainTarget {
                node: NodeId::parse("lon1").unwrap(),
                protocol: mooring_model::exit::ProbeProtocol::Hy2,
                port: 47104,
                reflector: SocketAddrV4::new(LON1, 27900),
            },
        ],
    });
}

/// A started engine with two probes, its log cleared, just before its
/// first round.
fn before_the_round() -> (World, ExitMachine, Fake) {
    let world = World::new();
    let mut machine = world.machine();
    let mut fake = Fake::new();
    two_probes(&mut fake);
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.prober_log, ["probe-one"]);
    fake.take_log();
    (world, machine, fake)
}

#[test]
fn a_round_brackets_each_probe_and_a_verified_round_serves() {
    let (mut world, mut machine, mut fake) = before_the_round();
    world.advance(IN_CHAIN_FIRST.as_secs() - 1);
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.take_log(), [], "no round before its time");
    world.advance(1);
    let section = world.tick(&mut machine, &mut fake);
    // Each probe between two direct probes to its node's reflector.
    assert_eq!(
        fake.take_log(),
        [
            Event::Probe(AMS1),
            Event::InChain(47101),
            Event::Probe(AMS1),
            Event::Probe(LON1),
            Event::InChain(47104),
            Event::Probe(LON1),
        ]
    );
    assert_eq!(
        section.state,
        ExitState::Serving {
            ip: CARRIER,
            verified_at: UnixTime::from_secs(world.now)
        }
    );
    assert_eq!(section.engines.probe.pid, Some(900));
    let verdicts = machine.verdicts();
    let reality = verdicts[&NodeId::parse("ams1").unwrap()].reality.unwrap();
    assert_eq!(reality.outcome, crate::status::InChainOutcome::Verified);
    assert_eq!(reality.latency_ms, Some(120));
    assert_eq!(reality.at, UnixTime::from_secs(world.now));
    assert!(verdicts[&NodeId::parse("ams1").unwrap()].hy2.is_none());
    assert!(verdicts[&NodeId::parse("lon1").unwrap()].hy2.is_some());
    // The next round waits its interval (300 s); the direct probes go on.
    world.advance(299);
    world.tick(&mut machine, &mut fake);
    assert!(!fake.take_log().contains(&Event::InChain(47101)));
    world.advance(1);
    world.tick(&mut machine, &mut fake);
    assert!(fake.take_log().contains(&Event::InChain(47101)));
}

#[test]
fn an_unsteady_bracket_runs_again_once_and_then_degrades() {
    let (mut world, mut machine, mut fake) = before_the_round();
    let a = Ipv4Addr::new(31, 120, 0, 1);
    let b = Ipv4Addr::new(31, 120, 0, 2);
    let c = Ipv4Addr::new(31, 120, 0, 3);
    // ams1: d1 = a, x = c, d2 = b, twice; lon1: steady.
    fake.answers = VecDeque::from([Ok(a), Ok(b), Ok(a), Ok(b), Ok(CARRIER), Ok(CARRIER)]);
    fake.chain = VecDeque::from([Ok(chained(c)), Ok(chained(c)), Ok(chained(CARRIER))]);
    world.advance(IN_CHAIN_FIRST.as_secs());
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(
        fake.take_log()
            .iter()
            .filter(|event| **event == Event::InChain(47101))
            .count(),
        2
    );
    assert_eq!(
        section.state,
        ExitState::Degraded {
            reasons: NonEmpty::new(DegradedReason::NodeProbeFailed {
                node: NodeId::parse("ams1").unwrap(),
                protocol: mooring_model::exit::ProbeProtocol::Reality,
                stage: ProbeStage::CarrierAddressUnstable,
            })
        }
    );
    // The engine keeps running.
    assert!(section.engines.exit.pid.is_some());
}

#[test]
fn an_in_chain_address_away_from_a_steady_carrier_is_a_mismatch() {
    let (mut world, mut machine, mut fake) = before_the_round();
    let elsewhere = Ipv4Addr::new(31, 121, 7, 7);
    fake.chain = VecDeque::from([Ok(chained(elsewhere))]);
    world.advance(IN_CHAIN_FIRST.as_secs());
    let section = world.tick(&mut machine, &mut fake);
    let violation = Violation::EgressMismatch {
        d1: CARRIER,
        d2: CARRIER,
        observed: elsewhere,
    };
    assert_eq!(
        section.state,
        down(DownReason::Violation(violation.clone()))
    );
    assert_eq!(fake.latch.as_ref().unwrap().violation, violation);
    // The round stops at the violation; the engine and the prober stop.
    let log = fake.take_log();
    assert!(!log.contains(&Event::InChain(47104)));
    assert!(log.contains(&Event::Stop));
    assert_eq!(fake.prober_running, None);
    assert_eq!(fake.prober_log.last(), Some(&"stop"));
    assert_eq!(
        machine.verdicts()[&NodeId::parse("ams1").unwrap()]
            .reality
            .unwrap()
            .outcome,
        crate::status::InChainOutcome::Violation {
            kind: ViolationKind::EgressMismatch
        }
    );
}

#[test]
fn an_in_chain_address_outside_the_prefixes_or_a_node_s_is_latched() {
    for (seen, kind) in [
        (OUTSIDE, ViolationKind::OutsideCarrierPrefixes),
        (LON1, ViolationKind::EgressIsNodeAddress),
    ] {
        let (mut world, mut machine, mut fake) = before_the_round();
        fake.chain = VecDeque::from([Ok(chained(seen))]);
        world.advance(IN_CHAIN_FIRST.as_secs());
        let section = world.tick(&mut machine, &mut fake);
        assert!(matches!(section.state, ExitState::Down { .. }), "{kind:?}");
        assert_eq!(fake.latch.as_ref().unwrap().violation.kind(), kind);
    }
    // A bracketing direct probe outside the prefixes is a violation too.
    let (mut world, mut machine, mut fake) = before_the_round();
    fake.answers = VecDeque::from([Ok(OUTSIDE)]);
    world.advance(IN_CHAIN_FIRST.as_secs());
    world.tick(&mut machine, &mut fake);
    assert_eq!(
        fake.latch.as_ref().unwrap().violation.kind(),
        ViolationKind::OutsideCarrierPrefixes
    );
    assert_eq!(fake.take_log()[..2], [Event::Probe(AMS1), Event::Stop]);
}

#[test]
fn a_failed_probe_degrades_naming_its_node_and_protocol() {
    let (mut world, mut machine, mut fake) = before_the_round();
    fake.chain = VecDeque::from([Ok(chained(CARRIER)), Err(ProbeStage::Read)]);
    world.advance(IN_CHAIN_FIRST.as_secs());
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(
        section.state,
        ExitState::Degraded {
            reasons: NonEmpty::new(DegradedReason::NodeProbeFailed {
                node: NodeId::parse("lon1").unwrap(),
                protocol: mooring_model::exit::ProbeProtocol::Hy2,
                stage: ProbeStage::Read,
            })
        }
    );
    // A bracketing direct probe that fails fails the probe the same way.
    let (mut world, mut machine, mut fake) = before_the_round();
    fake.answers = VecDeque::from([Err(ProbeStage::Connect)]);
    world.advance(IN_CHAIN_FIRST.as_secs());
    let section = world.tick(&mut machine, &mut fake);
    assert!(matches!(section.state, ExitState::Degraded { .. }));
    assert_eq!(
        fake.take_log()[..2],
        [Event::Probe(AMS1), Event::Probe(LON1)]
    );
}

#[test]
fn a_prober_that_cannot_start_degrades_every_probe_and_never_downs() {
    let mut world = World::new();
    let mut machine = world.machine();
    let mut fake = Fake::new();
    two_probes(&mut fake);
    fake.prober_start = Err(StartFault::Rejected);
    world.tick(&mut machine, &mut fake);
    world.advance(IN_CHAIN_FIRST.as_secs());
    let section = world.tick(&mut machine, &mut fake);
    let ExitState::Degraded { reasons } = &section.state else {
        panic!("{:?}", section.state);
    };
    assert_eq!(usize::from(reasons.len()), 4, "both nodes, both protocols");
    assert!(reasons.iter().all(|reason| matches!(
        reason,
        DegradedReason::NodeProbeFailed {
            stage: ProbeStage::ProberUnavailable,
            ..
        }
    )));
    assert!(section.engines.exit.pid.is_some());
    assert_eq!(section.engines.probe.pid, None);
    // It is tried again at the next round, not every tick.
    let starts = fake.prober_log.len();
    world.advance(2);
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.prober_log.len(), starts);
    fake.prober_start = Ok(());
    world.advance(300);
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.prober_running, Some(900));
}

#[test]
fn the_prober_restarts_with_its_config_and_stops_with_the_engine() {
    let (mut world, mut machine, mut fake) = before_the_round();
    fake.prober = Ok(RenderedProber {
        config: "probe-two",
        digest: Sha256Digest::of(b"probe-two"),
        targets: Vec::new(),
    });
    world.advance(2);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(fake.prober_log, ["probe-one", "stop", "probe-two"]);
    assert_eq!(section.engines.probe.restarts, 1);
    // An exit of its own is seen, and it starts again at the next round.
    fake.prober_ends = Some(ProcessEnd::Exited { code: 1 });
    world.advance(2);
    let section = world.tick(&mut machine, &mut fake);
    assert_eq!(section.engines.probe.pid, None);
    assert_eq!(
        section.engines.probe.last_exit.map(|exit| exit.end),
        Some(ProcessEnd::Exited { code: 1 })
    );
    world.advance(IN_CHAIN_FIRST.as_secs());
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.prober_running, Some(900));
    world.enabled = false;
    world.advance(2);
    world.tick(&mut machine, &mut fake);
    assert_eq!(fake.prober_running, None);
    assert_eq!(fake.prober_log.last(), Some(&"stop"));
}

#[test]
fn a_node_s_stale_watch_degrades_a_serving_exit() {
    let (mut world, mut machine, mut fake) = before_the_round();
    world.advance(IN_CHAIN_FIRST.as_secs());
    assert!(matches!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Serving { .. }
    ));
    world.nodes_degraded = vec![DegradedReason::WatchStale {
        node: NodeId::parse("lon1").unwrap(),
    }];
    world.advance(2);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Degraded {
            reasons: NonEmpty::new(DegradedReason::WatchStale {
                node: NodeId::parse("lon1").unwrap()
            })
        }
    );
    // A new engine forgets the old engine's verdicts until its own round.
    world.nodes_degraded.clear();
    fake.render = Ok(config("two"));
    world.advance(2);
    world.tick(&mut machine, &mut fake);
    world.advance(START_GRACE.as_secs() - 1);
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Starting
    );
    world.advance(1);
    assert!(matches!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Serving { .. }
    ));
}

/// The verdicts of an engine count only while it runs: a new engine whose
/// round does not reach a probe that failed, or verifies nothing, is not
/// judged by the old one's.
#[test]
fn a_new_engine_is_not_judged_by_the_old_engine_s_verdicts() {
    // An old failure through lon1 is forgotten when the new prober serves
    // ams1 alone.
    let (mut world, mut machine, mut fake) = before_the_round();
    fake.chain = VecDeque::from([Ok(chained(CARRIER)), Err(ProbeStage::Read)]);
    world.advance(IN_CHAIN_FIRST.as_secs());
    assert!(matches!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Degraded { .. }
    ));
    fake.render = Ok(config("two"));
    if let Ok(prober) = &mut fake.prober {
        prober.targets.truncate(1);
        prober.digest = Sha256Digest::of(b"probe-two");
    }
    world.advance(2);
    world.tick(&mut machine, &mut fake);
    world.advance(IN_CHAIN_FIRST.as_secs());
    assert!(matches!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Serving { .. }
    ));
    // An old verification is forgotten when the new prober serves nothing.
    fake.render = Ok(config("three"));
    if let Ok(prober) = &mut fake.prober {
        prober.targets.clear();
        prober.digest = Sha256Digest::of(b"probe-three");
    }
    world.advance(2);
    world.tick(&mut machine, &mut fake);
    world.advance(IN_CHAIN_FIRST.as_secs());
    assert_eq!(
        world.tick(&mut machine, &mut fake).state,
        ExitState::Verifying
    );
}
