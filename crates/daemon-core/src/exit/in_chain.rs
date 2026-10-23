// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooring-probe` and the in-chain probes (design §10.2, "Running
//! checks"): for each applied node and protocol, a connection to the probe
//! inbound on loopback travels the whole chain (the probe identity's
//! exported outbound, the node, `wgexit`, `mooring-exit` and the egress) to
//! the node's reflector, which answers with the address it saw. Direct
//! probes taken immediately before and after bracket it, and the model's
//! [`in_chain_verdict`] judges the three: a violation is latched, an
//! inconclusive bracket is run again once, and one inconclusive again is
//! `CarrierAddressUnstable`. Every direct probe of the bracket is judged
//! too, as every direct probe is.
//!
//! The prober runs while the engine does and restarts only when its config
//! changes; one that cannot start is tried again at the next round, and
//! until it runs every probe of a round fails as `ProberUnavailable`. It
//! never takes the exit down.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use mooring_model::NodeAddress;
use mooring_model::exit::{EgressCheck, ProbeProtocol};
use mooring_model::iface::ResolvedInterfaces;
use mooring_model::verdict::{
    Bracket, BracketAttempt, InChainInputs, Verdict, Violation, direct_verdict, in_chain_verdict,
};
use mooring_model::{NodeId, Sha256Digest, UnixTime};

use super::{Egress, ExitMachine, ExitPorts, TickInputs};
use crate::status::{
    CarrierCheck, DegradedReason, EngineExit, EngineProcess, InChainOutcome, InChainResult,
    ProbeStage, ProtocolVerdicts,
};

/// How long after the engine starts the first round runs.
pub const IN_CHAIN_FIRST: Duration = Duration::from_secs(10);

/// One in-chain probe: a node, a protocol, the loopback port of its probe
/// inbound, and the node's reflector, which the bracketing direct probes
/// ask too.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InChainTarget {
    /// The node.
    pub node: NodeId,
    /// The protocol.
    pub protocol: ProbeProtocol,
    /// The probe inbound's port on 127.0.0.1.
    pub port: u16,
    /// The node's reflector.
    pub reflector: SocketAddrV4,
}

/// A rendered `mooring-probe` config, its digest and its probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedProber<C> {
    /// The config.
    pub config: C,
    /// Its digest; the prober restarts only when it changes.
    pub digest: Sha256Digest,
    /// Every probe it serves.
    pub targets: Vec<InChainTarget>,
}

/// What an in-chain probe read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InChainProbe {
    /// The address the reflector saw.
    pub ip: Ipv4Addr,
    /// How long the probe took.
    pub latency: Duration,
}

/// The prober as the machine knows it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum Prober {
    #[default]
    Stopped,
    Running {
        digest: Sha256Digest,
        pid: u32,
    },
    /// It could not be rendered or started; it is tried again at the next
    /// round, or when its config changes.
    Unavailable {
        digest: Option<Sha256Digest>,
    },
}

/// How one probe ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Verified { ip: Ipv4Addr, latency: Duration },
    Violation(Violation),
    Failed(ProbeStage),
}

/// One probe of a round: its node and protocol, and the inbound port and
/// reflector it goes through while the prober runs.
struct Planned {
    node: NodeId,
    protocol: ProbeProtocol,
    through: Option<(u16, SocketAddrV4)>,
}

/// One probe's latest result, with when it ran on the machine's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Recorded {
    result: InChainResult,
    mono: Duration,
}

/// The prober and the latest results.
#[derive(Debug, Clone, Default)]
pub(super) struct InChain {
    prober: Prober,
    started_once: bool,
    restarts: u32,
    last_exit: Option<EngineExit>,
    targets: Vec<InChainTarget>,
    round_at: Option<Duration>,
    results: BTreeMap<(NodeId, ProbeProtocol), Recorded>,
    verified: Option<(Ipv4Addr, UnixTime, Duration)>,
}

impl InChain {
    /// The latest result of each node and protocol.
    pub(super) fn verdicts(&self) -> BTreeMap<NodeId, ProtocolVerdicts> {
        let mut verdicts: BTreeMap<NodeId, ProtocolVerdicts> = BTreeMap::new();
        for ((node, protocol), recorded) in &self.results {
            let entry = verdicts.entry(node.clone()).or_insert(ProtocolVerdicts {
                reality: None,
                hy2: None,
            });
            match protocol {
                ProbeProtocol::Reality => entry.reality = Some(recorded.result),
                ProbeProtocol::Hy2 => entry.hy2 = Some(recorded.result),
            }
        }
        verdicts
    }

    /// The prober's process.
    pub(super) const fn process(&self) -> EngineProcess {
        EngineProcess {
            pid: match self.prober {
                Prober::Running { pid, .. } => Some(pid),
                Prober::Stopped | Prober::Unavailable { .. } => None,
            },
            restarts: self.restarts,
            last_exit: self.last_exit,
        }
    }

    /// The probes of the engine started at `started` that failed.
    pub(super) fn failures_since(&self, started: Duration) -> Vec<DegradedReason> {
        self.results
            .iter()
            .filter(|(_, recorded)| recorded.mono >= started)
            .filter_map(
                |((node, protocol), recorded)| match recorded.result.outcome {
                    InChainOutcome::Failed { stage } => Some(DegradedReason::NodeProbeFailed {
                        node: node.clone(),
                        protocol: *protocol,
                        stage,
                    }),
                    InChainOutcome::Verified | InChainOutcome::Violation { .. } => None,
                },
            )
            .collect()
    }

    /// The latest address a probe of the engine started at `started`
    /// verified, and when.
    pub(super) fn verified_since(&self, started: Duration) -> Option<(Ipv4Addr, UnixTime)> {
        self.verified
            .filter(|(_, _, mono)| *mono >= started)
            .map(|(ip, at, _)| (ip, at))
    }

    /// Whether a round is due for the engine started at `started`.
    pub(super) fn due(&self, inputs: &TickInputs<'_>, started: Duration) -> bool {
        let every = Duration::from_secs(u64::from(
            inputs.deployment.exit().probe.in_chain_every.seconds(),
        ));
        inputs.mono.saturating_sub(started) >= IN_CHAIN_FIRST
            && self
                .round_at
                .is_none_or(|at| at < started || inputs.mono.saturating_sub(at) >= every)
    }

    /// Keeps the prober running on the current config: it restarts when the
    /// config changes, and one that could not start is tried again when
    /// `retry` (a round is due) or its config changes.
    pub(super) fn supervise_prober<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        interfaces: &ResolvedInterfaces,
        retry: bool,
        ports: &mut P,
    ) -> Result<(), P::Error> {
        if matches!(self.prober, Prober::Running { .. })
            && let Some(end) = ports.prober_exited()?
        {
            self.last_exit = Some(EngineExit {
                at: inputs.now,
                end,
            });
            self.prober = Prober::Unavailable { digest: None };
        }
        let rendered = match ports.render_prober(inputs.deployment, interfaces)? {
            Ok(rendered) => rendered,
            Err(_) => {
                self.stop_prober(inputs.now, ports)?;
                self.prober = Prober::Unavailable { digest: None };
                self.targets.clear();
                return Ok(());
            }
        };
        self.targets = rendered.targets.clone();
        let start = match &self.prober {
            Prober::Running { digest, .. } => *digest != rendered.digest,
            Prober::Unavailable {
                digest: Some(digest),
            } => *digest != rendered.digest || retry,
            Prober::Unavailable { digest: None } => retry || !self.started_once,
            Prober::Stopped => true,
        };
        if !start {
            return Ok(());
        }
        self.stop_prober(inputs.now, ports)?;
        match ports.start_prober(&rendered.config)? {
            Ok(pid) => {
                if self.started_once {
                    self.restarts = self.restarts.saturating_add(1);
                }
                self.started_once = true;
                self.prober = Prober::Running {
                    digest: rendered.digest,
                    pid,
                };
            }
            Err(_) => {
                self.prober = Prober::Unavailable {
                    digest: Some(rendered.digest),
                };
            }
        }
        Ok(())
    }

    /// Stops a running prober.
    pub(super) fn stop_prober<P: ExitPorts>(
        &mut self,
        now: UnixTime,
        ports: &mut P,
    ) -> Result<(), P::Error> {
        if matches!(self.prober, Prober::Running { .. }) {
            let end = ports.stop_prober()?;
            self.last_exit = Some(EngineExit { at: now, end });
        }
        self.prober = Prober::Stopped;
        Ok(())
    }

    fn record(
        &mut self,
        inputs: &TickInputs<'_>,
        node: &NodeId,
        protocol: ProbeProtocol,
        outcome: &Outcome,
    ) {
        let (outcome, latency_ms) = match outcome {
            Outcome::Verified { ip, latency } => {
                self.verified = Some((*ip, inputs.now, inputs.mono));
                (
                    InChainOutcome::Verified,
                    Some(u32::try_from(latency.as_millis()).unwrap_or(u32::MAX)),
                )
            }
            Outcome::Violation(violation) => (
                InChainOutcome::Violation {
                    kind: violation.kind(),
                },
                None,
            ),
            Outcome::Failed(stage) => (InChainOutcome::Failed { stage: *stage }, None),
        };
        self.results.insert(
            (node.clone(), protocol),
            Recorded {
                result: InChainResult {
                    at: inputs.now,
                    outcome,
                    latency_ms,
                },
                mono: inputs.mono,
            },
        );
    }
}

impl ExitMachine {
    /// One round: every probe in order, each recorded; the first violation
    /// ends the round and is returned.
    pub(super) fn in_chain_round<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        egress: &Egress,
        check: &EgressCheck,
        ports: &mut P,
    ) -> Option<Violation> {
        self.in_chain.round_at = Some(inputs.mono);
        let deployment = inputs.deployment;
        let running = matches!(self.in_chain.prober, Prober::Running { .. });
        // Without a prober every applied node's probes fail as
        // `ProberUnavailable`; with one, its own probes run.
        let planned: Vec<Planned> = if running {
            self.in_chain
                .targets
                .iter()
                .map(|target| Planned {
                    node: target.node.clone(),
                    protocol: target.protocol,
                    through: Some((target.port, target.reflector)),
                })
                .collect()
        } else {
            deployment
                .nodes()
                .values()
                .filter(|node| node.lifecycle.applied().is_some())
                .flat_map(|node| {
                    ProbeProtocol::ALL.into_iter().map(|protocol| Planned {
                        node: node.id.clone(),
                        protocol,
                        through: None,
                    })
                })
                .collect()
        };
        for probe in planned {
            let outcome = match probe.through {
                Some((port, reflector)) => {
                    self.probe_through_chain(inputs, egress, check, reflector, port, ports)
                }
                None => Outcome::Failed(ProbeStage::ProberUnavailable),
            };
            self.in_chain
                .record(inputs, &probe.node, probe.protocol, &outcome);
            if let Outcome::Violation(violation) = outcome {
                return Some(violation);
            }
        }
        None
    }

    /// One probe through the chain, bracketed by direct probes to the same
    /// reflector, run again once when the bracket is inconclusive.
    fn probe_through_chain<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        egress: &Egress,
        check: &EgressCheck,
        reflector: SocketAddrV4,
        port: u16,
        ports: &mut P,
    ) -> Outcome {
        let addresses = inputs.deployment.node_addresses();
        let uplink = match egress
            .interfaces
            .uplink_address(|uplink| ports.probe(uplink, reflector))
        {
            Ok(uplink) => uplink,
            Err(stage) => return Outcome::Failed(stage),
        };
        for attempt in [BracketAttempt::First, BracketAttempt::Rerun] {
            let d1 = match self.bracket_probe(inputs, egress, check, &addresses, reflector, ports) {
                Ok(ip) => ip,
                Err(outcome) => return outcome,
            };
            let probe = match ports.probe_in_chain(port) {
                Ok(probe) => probe,
                Err(stage) => return Outcome::Failed(stage),
            };
            let d2 = match self.bracket_probe(inputs, egress, check, &addresses, reflector, ports) {
                Ok(ip) => ip,
                Err(outcome) => return outcome,
            };
            match in_chain_verdict(&InChainInputs {
                observed: probe.ip,
                bracket: Bracket { d1, d2 },
                nodes: &addresses,
                egress_check: check,
                uplink,
                attempt,
            }) {
                Verdict::Verified { ip } => {
                    return Outcome::Verified {
                        ip,
                        latency: probe.latency,
                    };
                }
                Verdict::Violation(violation) => return Outcome::Violation(violation),
                Verdict::RerunBracket => {}
                Verdict::CarrierAddressUnstable { .. } => {
                    return Outcome::Failed(ProbeStage::CarrierAddressUnstable);
                }
            }
        }
        // The re-run never asks for another.
        Outcome::Failed(ProbeStage::CarrierAddressUnstable)
    }

    /// A direct probe of a bracket: it updates the carrier check and is
    /// judged as every direct probe is.
    fn bracket_probe<P: ExitPorts>(
        &mut self,
        inputs: &TickInputs<'_>,
        egress: &Egress,
        check: &EgressCheck,
        addresses: &BTreeMap<NodeId, NodeAddress>,
        reflector: SocketAddrV4,
        ports: &mut P,
    ) -> Result<Ipv4Addr, Outcome> {
        let ip = ports
            .probe(egress.interfaces.egress(), reflector)
            .map_err(Outcome::Failed)?;
        self.carrier_check = Some(CarrierCheck {
            egress_ip: ip,
            in_carrier_prefixes: check.in_carrier(ip),
            pairing: check.pairing,
            checked_at: inputs.now,
        });
        direct_verdict(ip, addresses, check).map_err(Outcome::Violation)?;
        Ok(ip)
    }
}
