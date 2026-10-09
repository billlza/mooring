// SPDX-License-Identifier: GPL-3.0-or-later

//! [`MacStatusV1`]: one line of `mooringctl status --follow --json`, and
//! the snapshot in `status.json` (design §15, console spec B.1 and B.2).
//! The name avoids a clash with the agent's `StatusV1` (critique A-14).
//!
//! Mooring.app decodes it through a Codable mirror tested against the
//! fixtures in `contract/status-fixtures/`, which the tests here generate
//! from the fixture deployments and pin byte for byte.
//!
//! # What it carries
//!
//! The exit's state and its evidence, the SIM meter and forecast, the
//! router, the uplink's capacity, one row per user and per node, and the
//! open alerts. It stays on the Mac: users appear by opaque id and public
//! alias only (labels stay in `state.json`, and the app joins them from
//! the CLI's user list), and it never carries a destination, a user's
//! address, a cell id, an IMEI, an ICCID, a phone number or an SMS text,
//! because none of its types has a field for one. The only addresses in it
//! are the Mac's own: the egress interface, the carrier address the carrier
//! check observed, and the evidence of a latched violation. What leaves the
//! Mac is derived from it by an allowlist of its own: the remote viewer's
//! report ([`crate::report`], decision F5) and the push notices
//! ([`crate::notify`], decision F6).

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AppliedGeneration, EngineHealth, GateState, Halt, Holds, HostHealth, StatusV1, UplinkTransfer,
    WatchConditions,
};
use mooring_model::collections::{NonEmpty, NonEmptySet};
use mooring_model::exit::ProbeProtocol;
use mooring_model::iface::{BsdName, MacAddr};
use mooring_model::node::{LifecycleStage, NodeRole};
use mooring_model::sim::SimThresholds;
use mooring_model::user::UserStatus;
use mooring_model::verdict::{Violation, ViolationKind};
use mooring_model::{
    CalendarDate, ConfigGeneration, NodeId, Pairing, PublicAlias, UnixTime, UserId,
};
use serde::{Deserialize, Serialize};

use crate::alert::{AlertCondition, DegradedReasonKind, MacEngine, OpenAlert};
use crate::capacity::CapacityStatus;
use crate::error::{ForecastErrorKind, StatusError, UsageErrorKind};
use crate::forecast::SimForecast;
use crate::network::ForeignNetworkFinding;
use crate::period::{BillingCycle, UsagePeriods};
use crate::policy::{ExpiryState, QuotaState};
use crate::router::RouterReading;
use crate::usage::{UsageAccuracy, UserActivity, UserUsage};
use crate::wire::mac_time;

/// The version [`MacStatusV1`] documents carry.
pub const MAC_STATUS_VERSION: u32 = 1;

/// Where a probe failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStage {
    /// The TCP connect failed.
    Connect,
    /// Reading the reflector's line failed or timed out.
    Read,
    /// The line was not an IPv4 address.
    Parse,
    /// `mooring-probe` is not running.
    ProberUnavailable,
    /// The bracketing direct probes disagreed twice (design §10.2 step 4).
    CarrierAddressUnstable,
}

/// Why the exit is degraded: it serves, with a problem.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DegradedReason {
    /// A node's probe failed; the exit keeps serving its other nodes.
    NodeProbeFailed {
        /// The node.
        node: NodeId,
        /// The protocol probed.
        protocol: ProbeProtocol,
        /// Where it failed.
        stage: ProbeStage,
    },
    /// A node may be blocked in China (design §10.2).
    ReachabilitySuspect {
        /// The node.
        node: NodeId,
    },
    /// A node's watch status is older than
    /// [`mooring_agent_proto::WATCH_STALE_SECS`] (30 s).
    WatchStale {
        /// The node.
        node: NodeId,
    },
    /// The Mac runs on battery and may sleep.
    OnBattery,
    /// The power helper exited.
    PowerHelperExited,
}

impl DegradedReason {
    /// The reason's kind, which alerts carry.
    #[must_use]
    pub const fn kind(&self) -> DegradedReasonKind {
        match self {
            Self::NodeProbeFailed { .. } => DegradedReasonKind::NodeProbeFailed,
            Self::ReachabilitySuspect { .. } => DegradedReasonKind::ReachabilitySuspect,
            Self::WatchStale { .. } => DegradedReasonKind::WatchStale,
            Self::OnBattery => DegradedReasonKind::OnBattery,
            Self::PowerHelperExited => DegradedReasonKind::PowerHelperExited,
        }
    }

    const fn node(&self) -> Option<&NodeId> {
        match self {
            Self::NodeProbeFailed { node, .. }
            | Self::ReachabilitySuspect { node }
            | Self::WatchStale { node } => Some(node),
            Self::OnBattery | Self::PowerHelperExited => None,
        }
    }
}

/// Why the exit is down: its engine is stopped (design §14, "daemon").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DownReason {
    /// No interface matches the egress selector.
    EgressInterfaceAbsent,
    /// Several interfaces match the egress selector.
    EgressAmbiguous {
        /// How many.
        matches: u32,
    },
    /// The egress has no IPv4 address.
    EgressNoIpv4 {
        /// The egress.
        interface: BsdName,
    },
    /// The egress's IPv4 address is outside the selector's subnet.
    EgressSubnetMismatch,
    /// The separate uplink is absent.
    UplinkAbsent,
    /// The separate uplink is the egress.
    UplinkEqualsEgress,
    /// No direct probe succeeded at preflight.
    DirectProbeFailed {
        /// The last node tried.
        node: NodeId,
        /// Where it failed.
        stage: ProbeStage,
    },
    /// The Keychain could not be read (`errSecInteractionNotAllowed`).
    SecretsUnavailable,
    /// The agent on a node is not enabled.
    AgentNotEnabled {
        /// The node.
        node: NodeId,
    },
    /// An engine could not be spawned.
    EngineSpawnFailed {
        /// Which engine.
        engine: MacEngine,
    },
    /// An engine rejected its configuration.
    EngineConfigRejected {
        /// Which engine.
        engine: MacEngine,
    },
    /// An engine exited within 10 s of starting.
    EngineStartFailed {
        /// Which engine.
        engine: MacEngine,
    },
    /// An engine crashed five times within 10 minutes.
    EngineCrashLoop {
        /// Which engine.
        engine: MacEngine,
    },
    /// A violation is latched; it carries its evidence.
    Violation(Violation),
    /// The SIM hard stop was reached; the exit stays down until the cycle
    /// resets.
    SimCapReached {
        /// The cycle's first day.
        cycle_start: CalendarDate,
    },
    /// The Mac is attached to a network other than the M7's (P0-2).
    ForeignNetworkAttached {
        /// What was found.
        findings: NonEmpty<ForeignNetworkFinding>,
    },
}

impl DownReason {
    /// The node the reason names, if any.
    const fn node(&self) -> Option<&NodeId> {
        match self {
            Self::DirectProbeFailed { node, .. } | Self::AgentNotEnabled { node } => Some(node),
            Self::Violation(violation) => violation.shutdown_node(),
            Self::EgressInterfaceAbsent
            | Self::EgressAmbiguous { .. }
            | Self::EgressNoIpv4 { .. }
            | Self::EgressSubnetMismatch
            | Self::UplinkAbsent
            | Self::UplinkEqualsEgress
            | Self::SecretsUnavailable
            | Self::EngineSpawnFailed { .. }
            | Self::EngineConfigRejected { .. }
            | Self::EngineStartFailed { .. }
            | Self::EngineCrashLoop { .. }
            | Self::SimCapReached { .. }
            | Self::ForeignNetworkAttached { .. } => None,
        }
    }
}

/// The exit's state (design §10.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExitState {
    /// The operator disabled the exit.
    Disabled,
    /// Preflight is running.
    Preflight,
    /// The engine is starting.
    Starting,
    /// The engine runs and the first verdicts are pending.
    Verifying,
    /// Serving through a verified carrier address.
    Serving {
        /// The verified egress address.
        ip: Ipv4Addr,
        /// When it was verified.
        verified_at: UnixTime,
    },
    /// Serving, with problems.
    Degraded {
        /// The problems.
        reasons: NonEmpty<DegradedReason>,
    },
    /// Not serving.
    Down {
        /// Why.
        reason: DownReason,
    },
    /// The Mac is asleep; the exit drained before it slept.
    Paused,
}

impl ExitState {
    /// The `ExitDegraded` condition a degraded exit raises: the kinds of
    /// its reasons, so the alert and the state cannot disagree. `None`
    /// unless the exit is degraded.
    #[must_use]
    pub fn degraded_alert(&self) -> Option<AlertCondition> {
        let Self::Degraded { reasons } = self else {
            return None;
        };
        let mut kinds = NonEmptySet::new(reasons.first().kind());
        for reason in reasons {
            kinds.insert(reason.kind());
        }
        Some(AlertCondition::ExitDegraded { reasons: kinds })
    }
}

/// A latched violation (`run/latch.json`, design §10.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Latch {
    /// The violation with its evidence.
    pub violation: Violation,
    /// When it was latched.
    pub at: UnixTime,
}

/// The egress link's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkState {
    /// Whether the link is up.
    pub up: bool,
    /// The negotiated speed in Mbit/s, when the driver reports one.
    #[serde(deserialize_with = "Option::deserialize")]
    pub speed_mbps: Option<u32>,
}

/// The resolved egress interface (design §10.1 step 2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressFacts {
    /// The interface.
    pub interface: BsdName,
    /// Its link-layer address.
    pub lladdr: MacAddr,
    /// Its IPv4 address on the M7's network.
    pub ipv4: Ipv4Addr,
    /// The link.
    pub link: LinkState,
}

/// The latest direct probe's carrier check (design §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierCheck {
    /// The carrier address the reflector saw.
    pub egress_ip: Ipv4Addr,
    /// Whether it lies in the recorded carrier prefixes.
    pub in_carrier_prefixes: bool,
    /// The pairing mode the verdicts use.
    pub pairing: Pairing,
    /// When it was checked.
    pub checked_at: UnixTime,
}

/// How a process last ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ProcessEnd {
    /// It exited with a code.
    Exited {
        /// The code.
        code: i32,
    },
    /// A signal ended it.
    Signalled {
        /// The signal number.
        signal: i32,
    },
}

/// An engine's last end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineExit {
    /// When.
    pub at: UnixTime,
    /// How.
    pub end: ProcessEnd,
}

/// One supervised engine on the Mac (design §15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineProcess {
    /// Its process id while it runs.
    #[serde(deserialize_with = "Option::deserialize")]
    pub pid: Option<u32>,
    /// Restarts since the daemon started.
    pub restarts: u32,
    /// Its last end, if it has ended.
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_exit: Option<EngineExit>,
}

/// Both engines on the Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacEngines {
    /// `mooring-exit`.
    pub exit: EngineProcess,
    /// `mooring-probe`.
    pub probe: EngineProcess,
}

/// Where the Mac's power comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerSource {
    /// Mains.
    Ac,
    /// The battery.
    Battery,
}

/// How a sleep drain ended (design §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainOutcome {
    /// Every node acknowledged within the budget.
    Completed,
    /// The 4 s budget ran out (`DrainTimedOut`).
    TimedOut,
    /// A node could not be reached (`DrainFailed`).
    Failed,
}

/// The last sleep drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainRecord {
    /// When it ran.
    pub at: UnixTime,
    /// How it ended.
    pub outcome: DrainOutcome,
}

/// The Mac's power (design §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerStatus {
    /// The source.
    pub source: PowerSource,
    /// Whether the power helper holds its assertions.
    pub assertions_held: bool,
    /// The last sleep.
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_sleep: Option<UnixTime>,
    /// The last wake.
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_wake: Option<UnixTime>,
    /// The last drain.
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_drain: Option<DrainRecord>,
}

/// The exit Mac.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitSection {
    /// The state.
    pub state: ExitState,
    /// Since when.
    pub since: UnixTime,
    /// The latched violations.
    pub latches: Vec<Latch>,
    /// The resolved egress; `None` while it does not resolve.
    #[serde(deserialize_with = "Option::deserialize")]
    pub egress: Option<EgressFacts>,
    /// The latest carrier check; `None` before the first direct probe.
    #[serde(deserialize_with = "Option::deserialize")]
    pub carrier_check: Option<CarrierCheck>,
    /// The engines.
    pub engines: MacEngines,
    /// The power.
    pub power: PowerStatus,
    /// Networks the Mac must not be attached to.
    pub foreign_networks: BTreeSet<ForeignNetworkFinding>,
}

impl ExitSection {
    /// The `ExitViolation` condition the latched violations raise: the
    /// kinds of every latch, so the alert and the latches cannot disagree.
    /// `None` while nothing is latched.
    #[must_use]
    pub fn violation_alert(&self) -> Option<AlertCondition> {
        let mut latches = self.latches.iter();
        let mut kinds = NonEmptySet::new(latches.next()?.violation.kind());
        for latch in latches {
            kinds.insert(latch.violation.kind());
        }
        Some(AlertCondition::ExitViolation { violations: kinds })
    }
}

/// Whether the SIM meter counts every byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterAccuracy {
    /// The egress counters see all of the SIM's traffic.
    Exact,
    /// Some traffic may bypass them (the M7's Wi-Fi or offload is on, or a
    /// counter reset was detected): the figures are a lower bound.
    LowerBound,
}

/// The forecast, or why there is none.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ForecastView {
    /// The forecast.
    Projected(SimForecast),
    /// No forecast could be made.
    Unavailable {
        /// Why.
        reason: ForecastErrorKind,
    },
}

/// The SIM meter (design §10.1 step 5, console spec B.2.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimMeterStatus {
    /// The billing cycle.
    pub cycle: BillingCycle,
    /// Bytes received this cycle.
    pub rx_bytes: u64,
    /// Bytes sent this cycle.
    pub tx_bytes: u64,
    /// Whether the figures are exact.
    pub accuracy: MeterAccuracy,
    /// The thresholds, with the stop policy and the plan's line; decoding
    /// checks them as the model's `SimPolicy` does.
    pub thresholds: SimThresholds,
    /// The forecast.
    pub forecast: ForecastView,
}

/// The users' usage figures, or why there are none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum UsageView {
    /// Every user row carries usage over these periods.
    Report {
        /// The periods.
        periods: UsagePeriods,
    },
    /// No user row carries usage.
    Unavailable {
        /// Why.
        reason: UsageErrorKind,
    },
}

/// One user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserRow {
    /// The public alias, if one was issued.
    #[serde(deserialize_with = "Option::deserialize")]
    pub alias: Option<PublicAlias>,
    /// The lifecycle state.
    pub status: UserStatus,
    /// The nodes holding the user's credentials.
    pub nodes: BTreeSet<NodeId>,
    /// Recent activity.
    pub activity: UserActivity,
    /// Usage, when the status's usage view is a report.
    #[serde(deserialize_with = "Option::deserialize")]
    pub usage: Option<UserUsage>,
    /// The quota.
    pub quota: QuotaState,
    /// The expiry.
    pub expiry: ExpiryState,
    /// What limits the row's accuracy.
    pub accuracy: UsageAccuracy,
}

/// How an in-chain probe ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InChainOutcome {
    /// The egress was verified.
    Verified,
    /// A violation (the exit's latches carry the evidence).
    Violation {
        /// Its kind.
        kind: ViolationKind,
    },
    /// The probe failed.
    Failed {
        /// Where.
        stage: ProbeStage,
    },
}

/// The latest in-chain probe through one protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InChainResult {
    /// When it ran.
    pub at: UnixTime,
    /// How it ended.
    pub outcome: InChainOutcome,
    /// The round trip in milliseconds, when it completed.
    #[serde(deserialize_with = "Option::deserialize")]
    pub latency_ms: Option<u32>,
}

/// The latest in-chain probes of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVerdicts {
    /// Through REALITY.
    #[serde(deserialize_with = "Option::deserialize")]
    pub reality: Option<InChainResult>,
    /// Through Hysteria2.
    #[serde(deserialize_with = "Option::deserialize")]
    pub hy2: Option<InChainResult>,
}

/// Why a node's agent could not be polled (design §14, "ssh").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentUnreachable {
    /// `ssh` could not be started.
    Spawn,
    /// The host key did not match its pin (a security alert).
    HostKeyMismatch,
    /// The node refused the key.
    AuthFailed,
    /// The connection failed.
    Transport,
    /// No answer in time.
    Timeout,
    /// The agent speaks another protocol version.
    ProtocolMismatch,
    /// The answer could not be decoded.
    Decode,
    /// The answer exceeded 1 MiB.
    ResponseTooLarge,
    /// The node's forced command is not active.
    ForcedCommandNotActive,
}

/// A node's latest `StatusV1`, without its per-user activity (which the
/// user rows carry). Its ages use the node's clock only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReport {
    /// When the Mac received it.
    pub polled_at: UnixTime,
    /// The node's clock when it answered.
    pub agent_now: UnixTime,
    /// Seconds since the watch's latest tick; `None` if the node's clock
    /// stepped back.
    #[serde(deserialize_with = "Option::deserialize")]
    pub watch_age_secs: Option<u64>,
    /// The gate.
    pub gate: GateState,
    /// The holds.
    pub holds: Holds,
    /// The halt marker.
    #[serde(deserialize_with = "Option::deserialize")]
    pub halted: Option<Halt>,
    /// Seconds since the Mac's latest WireGuard handshake; `None` when none
    /// has completed (or the clock stepped back).
    #[serde(deserialize_with = "Option::deserialize")]
    pub handshake_age_secs: Option<u64>,
    /// The last committed generation.
    #[serde(deserialize_with = "Option::deserialize")]
    pub applied: Option<AppliedGeneration>,
    /// The watch's conditions.
    pub conditions: WatchConditions,
    /// The latest accounting poll.
    #[serde(deserialize_with = "Option::deserialize")]
    pub accounting_at: Option<UnixTime>,
    /// The engines.
    pub engines: EngineHealth,
    /// The host.
    pub host: HostHealth,
    /// The uplink's transfer this month.
    pub transfer: UplinkTransfer,
}

impl NodeReport {
    /// The report of `status`, received at `polled_at`.
    #[must_use]
    pub fn of(polled_at: UnixTime, status: &StatusV1) -> Self {
        Self {
            polled_at,
            agent_now: mac_time(status.now),
            watch_age_secs: status.watch_age_secs(),
            gate: status.gate,
            holds: status.holds,
            halted: status.halted,
            handshake_age_secs: status
                .latest_handshake
                .and_then(|handshake| status.now.secs_since(handshake)),
            applied: status.applied,
            conditions: status.conditions.clone(),
            accounting_at: status.accounting_at.map(mac_time),
            engines: status.engines,
            host: status.host,
            transfer: status.transfer,
        }
    }
}

/// A node's agent as the Mac last saw it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeAgentState {
    /// Not polled since the daemon started.
    NotPolled,
    /// The latest poll's report.
    Reported(Box<NodeReport>),
    /// Polls have failed since `since`.
    Unreachable {
        /// The first failed poll of the current run.
        since: UnixTime,
        /// The latest failure.
        cause: AgentUnreachable,
    },
}

/// One node (console spec B.2.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRow {
    /// The node's role.
    pub role: NodeRole,
    /// Its lifecycle stage.
    pub stage: LifecycleStage,
    /// The deployment's current configuration generation.
    pub current_generation: ConfigGeneration,
    /// Since when the node has been behind the current generation; `None`
    /// when it is not.
    #[serde(deserialize_with = "Option::deserialize")]
    pub pending_apply_since: Option<UnixTime>,
    /// The latest in-chain probes.
    pub verdicts: ProtocolVerdicts,
    /// The agent.
    pub agent: NodeAgentState,
}

/// Every part of a [`MacStatusV1`], unchecked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MacStatusParts {
    /// When the daemon produced the status.
    pub at: UnixTime,
    /// The exit Mac.
    pub exit: ExitSection,
    /// The SIM meter.
    pub sim: SimMeterStatus,
    /// The router.
    pub router: RouterReading,
    /// The latest capacity view; `None` before the first sample.
    pub capacity: Option<CapacityStatus>,
    /// Whether the user rows carry usage.
    pub usage: UsageView,
    /// One row per user, by opaque id.
    pub users: BTreeMap<UserId, UserRow>,
    /// One row per node, retired ones included.
    pub nodes: BTreeMap<NodeId, NodeRow>,
    /// The open alerts, in key order.
    pub alerts: Vec<OpenAlert>,
}

/// One status line. Built only from [`MacStatusParts`] (also when
/// decoded), which must be consistent:
///
/// - every node a user row, an alert, the exit state or a latch names has a
///   node row (`UnknownNode`);
/// - every user row carries usage exactly when the usage view is a report
///   (`UsageMismatch`);
/// - the open alerts are in strictly increasing key order, so no alert is
///   listed twice (`AlertsNotOrdered`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "MacStatusRepr", into = "MacStatusRepr")]
pub struct MacStatusV1(MacStatusParts);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacStatusRepr {
    version: u32,
    at: UnixTime,
    exit: ExitSection,
    sim: SimMeterStatus,
    router: RouterReading,
    #[serde(deserialize_with = "Option::deserialize")]
    capacity: Option<CapacityStatus>,
    usage: UsageView,
    users: BTreeMap<UserId, UserRow>,
    nodes: BTreeMap<NodeId, NodeRow>,
    alerts: Vec<OpenAlert>,
}

impl MacStatusV1 {
    /// Checks `parts` (see the type's invariant).
    pub fn new(parts: MacStatusParts) -> Result<Self, StatusError> {
        for node in referenced_nodes(&parts) {
            if !parts.nodes.contains_key(node) {
                return Err(StatusError::UnknownNode { node: node.clone() });
            }
        }
        let with_usage = matches!(parts.usage, UsageView::Report { .. });
        for (user, row) in &parts.users {
            if row.usage.is_some() != with_usage {
                return Err(StatusError::UsageMismatch { user: user.clone() });
            }
        }
        for pair in parts.alerts.windows(2) {
            if let [earlier, later] = pair
                && earlier.key() >= later.key()
            {
                return Err(StatusError::AlertsNotOrdered { key: later.key() });
            }
        }
        Ok(Self(parts))
    }

    /// The checked parts.
    #[must_use]
    pub const fn parts(&self) -> &MacStatusParts {
        &self.0
    }

    /// The parts, to change and check again.
    #[must_use]
    pub fn into_parts(self) -> MacStatusParts {
        self.0
    }
}

impl TryFrom<MacStatusRepr> for MacStatusV1 {
    type Error = StatusError;

    fn try_from(repr: MacStatusRepr) -> Result<Self, Self::Error> {
        if repr.version != MAC_STATUS_VERSION {
            return Err(StatusError::UnsupportedVersion {
                found: repr.version,
            });
        }
        Self::new(MacStatusParts {
            at: repr.at,
            exit: repr.exit,
            sim: repr.sim,
            router: repr.router,
            capacity: repr.capacity,
            usage: repr.usage,
            users: repr.users,
            nodes: repr.nodes,
            alerts: repr.alerts,
        })
    }
}

impl From<MacStatusV1> for MacStatusRepr {
    fn from(status: MacStatusV1) -> Self {
        let parts = status.0;
        Self {
            version: MAC_STATUS_VERSION,
            at: parts.at,
            exit: parts.exit,
            sim: parts.sim,
            router: parts.router,
            capacity: parts.capacity,
            usage: parts.usage,
            users: parts.users,
            nodes: parts.nodes,
            alerts: parts.alerts,
        }
    }
}

/// Every node the parts name outside the node rows.
fn referenced_nodes(parts: &MacStatusParts) -> Vec<&NodeId> {
    let mut nodes: Vec<&NodeId> = Vec::new();
    for row in parts.users.values() {
        nodes.extend(&row.nodes);
        nodes.extend(row.activity.by_node.keys());
        if let Some(usage) = &row.usage {
            nodes.extend(usage.cycle_by_node().keys());
            if let Some(shares) = usage.cycle_shares() {
                nodes.extend(shares.by_node().keys());
            }
        }
    }
    nodes.extend(
        parts
            .alerts
            .iter()
            .filter_map(|alert| alert.condition.node()),
    );
    match &parts.exit.state {
        ExitState::Degraded { reasons } => {
            nodes.extend(reasons.iter().filter_map(DegradedReason::node))
        }
        ExitState::Down { reason } => nodes.extend(reason.node()),
        ExitState::Disabled
        | ExitState::Preflight
        | ExitState::Starting
        | ExitState::Verifying
        | ExitState::Serving { .. }
        | ExitState::Paused => {}
    }
    for latch in &parts.exit.latches {
        nodes.extend(latch.violation.shutdown_node());
    }
    nodes
}
