// SPDX-License-Identifier: GPL-3.0-or-later

//! Alerts (console spec B.4, corrected by critique C-12, D-3 and D-4): a
//! typed set of conditions and a pure state machine that turns the set
//! active at each observation into notices.
//!
//! # Rules
//!
//! - A notice is sent only on a transition, and conditions are
//!   deduplicated by [`AlertKey`] (kind and subject): while an alert is
//!   open, a changed payload (a new count, say) does not notify again; the
//!   next reminder or the resolution carries the latest payload.
//! - A key is as fine as the facts that can hold at once: whatever can be
//!   true of several things at the same time is either in the subject (an
//!   engine's crash loop is about that engine) or gathered into one
//!   condition's set (the latched violations, the degraded reasons, the
//!   inbounds whose canary is missing). So the conditions active at one
//!   observation never share a key, and an observation is never refused
//!   for holding two true facts.
//! - A condition is raised once it has stayed active for its hold
//!   ([`AlertConditionKind::hold_secs`]): at once for a critical one except
//!   [`AlertCondition::NodeUnreachable`], 15 minutes for a warning by
//!   default, longer for a few kinds the spec names. One that clears
//!   earlier is never sent. A condition that carries its source's start
//!   (`since`: a pending reboot, a pending apply, an operator hold, an
//!   unreachable node) is held from that start, not from the machine's
//!   first observation.
//! - A critical alert is reminded every [`AlertTiming::reminder_secs`] (6
//!   hours) while it stays active.
//! - A raised alert that clears is resolved with a notice.
//! - The projected crossing of a SIM threshold is raised at most once per
//!   billing cycle.
//!
//! # What an alert may carry
//!
//! Notices leave the Mac (through the push channel of decision F6, rendered
//! by [`crate::notify`]), so a condition carries only Level-0
//! aggregates: kinds, counts, byte totals, dates, and node ids. It has no
//! field that can hold a user id, a public alias, a label, an IP address, a
//! cell id or any text, so none can reach a notice (critique C-12). The
//! machine knows nothing of channels.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;

use mooring_agent_proto::InboundSet;
use mooring_model::verdict::ViolationKind;
use mooring_model::{CalendarDate, NodeId, NonEmptySet, UnixTime, kinds};
use serde::{Deserialize, Serialize};

use crate::error::AlertError;
use crate::forecast::SimThreshold;

/// How urgent an alert is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Raised at once and reminded while active.
    Critical,
    /// Raised after a hold; not reminded.
    Warning,
}

/// An engine on the Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacEngine {
    /// `mooring-exit`.
    Exit,
    /// `mooring-probe`.
    Probe,
}

impl fmt::Display for MacEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Exit => "mooring-exit",
            Self::Probe => "mooring-probe",
        })
    }
}

/// An engine on a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeEngine {
    /// `mooring-xray`.
    Xray,
    /// `mooring-hy2`.
    Hy2,
}

impl fmt::Display for NodeEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Xray => "mooring-xray",
            Self::Hy2 => "mooring-hy2",
        })
    }
}

/// Where a crash-looping engine runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EngineHost {
    /// On the exit Mac.
    Mac {
        /// Which engine.
        engine: MacEngine,
    },
    /// On a node.
    Node {
        /// The node.
        node: NodeId,
        /// Which engine.
        engine: NodeEngine,
    },
}

kinds! {
    /// Why the exit is degraded, without details (design §14, "daemon").
    #[derive(Serialize, Deserialize)]
    pub enum DegradedReasonKind {
        /// An in-chain or direct probe of a node failed.
        NodeProbeFailed,
        /// A node may be blocked in China.
        ReachabilitySuspect,
        /// A node's watch status is stale.
        WatchStale,
        /// The Mac runs on battery.
        OnBattery,
        /// The power helper exited.
        PowerHelperExited,
        /// The own-network declarations or the routers they match could
        /// not be read, so no declared network matches.
        OwnNetworksUnreadable,
    }
}

/// The M7's thermal step at which it shuts parts down: level 2 (5G stops,
/// LTE on one band) or level 3 (the device shuts down), as the M7 manual
/// describes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalThermalLevel {
    /// Level 2.
    Level2,
    /// Level 3.
    Level3,
}

/// A condition that can raise an alert. Every payload is a Level-0
/// aggregate (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AlertCondition {
    // Critical.
    /// Exit violations are latched; the engine is stopped.
    ExitViolation {
        /// The kinds of every latched violation (several can be latched at
        /// once, two of a kind on two nodes among them); their evidence
        /// (addresses) stays on the Mac.
        violations: NonEmptySet<ViolationKind>,
    },
    /// The SIM hard stop was reached; the exit is stopped until the cycle
    /// resets.
    SimCapReached {
        /// The billing cycle's first day.
        cycle_start: CalendarDate,
    },
    /// The M7 routes the WAN over Wi-Fi or Ethernet offload, so traffic
    /// may leave elsewhere than the carrier; raised before the carrier
    /// check fails.
    RouterOffloadActive,
    /// The M7's Wi-Fi radio is on, so the SIM meter is no longer exact.
    RouterWifiRadioOn,
    /// The M7 reached a thermal step that cuts service.
    RouterOverheating {
        /// The step.
        level: CriticalThermalLevel,
    },
    /// The M7 rebooted or shut down.
    RouterRestarted,
    /// A node is halted.
    NodeHalted {
        /// The node.
        node: NodeId,
    },
    /// A node's rollback failed.
    RollbackFailed {
        /// The node.
        node: NodeId,
    },
    /// Closing a node's gate failed.
    GateCloseFailed {
        /// The node.
        node: NodeId,
    },
    /// An engine is crash-looping; each engine is its own alert.
    EngineCrashLoop {
        /// Which engine, and where.
        host: EngineHost,
    },
    /// A node's SSH host key did not match its pin (a security alert).
    HostKeyMismatch {
        /// The node.
        node: NodeId,
    },
    /// A node reports that the Mac has been silent (agent `MacSilent`).
    MacSilent {
        /// The node.
        node: NodeId,
    },
    /// A node's agent has not answered the Mac's polls (transport failure
    /// or timeout) since `since`: the node may be down. Critical, but held
    /// for [`NODE_UNREACHABLE_HOLD_SECS`] from `since`, so one lost poll
    /// over the lossy uplink is not reported.
    NodeUnreachable {
        /// The node.
        node: NodeId,
        /// The first failed poll of the current run of failures
        /// (`NodeAgentState::Unreachable::since`).
        since: UnixTime,
    },
    /// A node's disk is nearly full (agent `DiskLow`).
    NodeDiskLow {
        /// The node.
        node: NodeId,
        /// The bytes free.
        free_bytes: u64,
    },
    // Warnings.
    /// The SIM warning threshold was passed.
    SimWarn {
        /// The billing cycle's first day.
        cycle_start: CalendarDate,
    },
    /// The forecast projects a threshold to be crossed before the cycle
    /// ends; raised at most once per cycle.
    SimForecastCrossing {
        /// The billing cycle's first day.
        cycle_start: CalendarDate,
        /// The first threshold projected to be crossed.
        threshold: SimThreshold,
        /// The day it is projected to be crossed.
        on: CalendarDate,
    },
    /// The exit is degraded.
    ExitDegraded {
        /// Why, without details: the kinds of every degraded reason.
        reasons: NonEmptySet<DegradedReasonKind>,
    },
    /// An interface other than the egress joined a network
    /// (`ForeignNetworkAttached`).
    ForeignNetworkAttached {
        /// How many findings.
        findings: u64,
    },
    /// A node may be blocked in China.
    ReachabilitySuspect {
        /// The node.
        node: NodeId,
    },
    /// A node's REALITY target is degraded.
    TargetDegraded {
        /// The node.
        node: NodeId,
    },
    /// The M7 has no service.
    RouterNoService,
    /// The M7 fell back to LTE.
    RouterOnLte,
    /// The M7 is at thermal level 1 (fewer bands, lower speed).
    RouterThermalStepDown,
    /// The M7's RSRP stays low.
    RouterWeakSignal {
        /// The latest LTE RSRP in tenths of a dBm.
        rsrp_dbm_x10: i16,
    },
    /// The M7's firmware version changed: re-run the M7 settings checklist.
    RouterFirmwareChanged,
    /// The M7 holds unread SMS; only the count is ever read.
    RouterUnreadSms {
        /// How many.
        count: u64,
    },
    /// The M7's own counter and the SIM meter disagree.
    RouterCounterMismatch {
        /// The difference over the day, in tenths of a percent.
        permille: u32,
    },
    /// Users at or above their quota's warning share.
    UsersNearQuota {
        /// How many.
        count: u64,
    },
    /// Users at or above their quota.
    UsersOverQuota {
        /// How many.
        count: u64,
    },
    /// Users suspended.
    UsersSuspended {
        /// How many.
        count: u64,
    },
    /// Users whose access expires within three days.
    UsersExpiringSoon {
        /// How many.
        count: u64,
    },
    /// Users whose access has expired.
    UsersExpired {
        /// How many.
        count: u64,
    },
    /// The uplink is saturated.
    CapacitySaturated,
    /// A node's exit flow cap is rejecting flows.
    ExitFlowCapHit {
        /// The node.
        node: NodeId,
        /// The flows rejected so far.
        count: u64,
    },
    /// A node's clock is not synchronised.
    NodeClockUnsynced {
        /// The node.
        node: NodeId,
    },
    /// A node has been waiting for a reboot.
    NodeRebootPending {
        /// The node.
        node: NodeId,
        /// When the reboot became required (agent `RebootPending{since}`).
        since: UnixTime,
    },
    /// A node has not applied the current configuration.
    PendingApply {
        /// The node.
        node: NodeId,
        /// Since when the node has been behind (`NodeRow::pending_apply_since`).
        since: UnixTime,
    },
    /// An operator hold has been set on a node (it also suppresses
    /// `MacSilent`, critique D-4).
    OperatorHoldLong {
        /// The node.
        node: NodeId,
        /// When the agent recorded the hold (`OperatorHold::at`).
        since: UnixTime,
    },
    /// A node is not counting the probe's traffic (critique C-11).
    AccountingCanaryMissing {
        /// The node.
        node: NodeId,
        /// Every inbound whose canary is missing, as the agent's
        /// `AccountingCanaryMissing{inbounds}` reports them.
        inbounds: InboundSet,
    },
}

kinds! {
    /// The kind of an [`AlertCondition`], without its payload. Serialised
    /// as its name.
    #[derive(Serialize, Deserialize)]
    pub enum AlertConditionKind {
        /// See [`AlertCondition::ExitViolation`].
        ExitViolation,
        /// See [`AlertCondition::SimCapReached`].
        SimCapReached,
        /// See [`AlertCondition::RouterOffloadActive`].
        RouterOffloadActive,
        /// See [`AlertCondition::RouterWifiRadioOn`].
        RouterWifiRadioOn,
        /// See [`AlertCondition::RouterOverheating`].
        RouterOverheating,
        /// See [`AlertCondition::RouterRestarted`].
        RouterRestarted,
        /// See [`AlertCondition::NodeHalted`].
        NodeHalted,
        /// See [`AlertCondition::RollbackFailed`].
        RollbackFailed,
        /// See [`AlertCondition::GateCloseFailed`].
        GateCloseFailed,
        /// See [`AlertCondition::EngineCrashLoop`].
        EngineCrashLoop,
        /// See [`AlertCondition::HostKeyMismatch`].
        HostKeyMismatch,
        /// See [`AlertCondition::MacSilent`].
        MacSilent,
        /// See [`AlertCondition::NodeUnreachable`].
        NodeUnreachable,
        /// See [`AlertCondition::NodeDiskLow`].
        NodeDiskLow,
        /// See [`AlertCondition::SimWarn`].
        SimWarn,
        /// See [`AlertCondition::SimForecastCrossing`].
        SimForecastCrossing,
        /// See [`AlertCondition::ExitDegraded`].
        ExitDegraded,
        /// See [`AlertCondition::ForeignNetworkAttached`].
        ForeignNetworkAttached,
        /// See [`AlertCondition::ReachabilitySuspect`].
        ReachabilitySuspect,
        /// See [`AlertCondition::TargetDegraded`].
        TargetDegraded,
        /// See [`AlertCondition::RouterNoService`].
        RouterNoService,
        /// See [`AlertCondition::RouterOnLte`].
        RouterOnLte,
        /// See [`AlertCondition::RouterThermalStepDown`].
        RouterThermalStepDown,
        /// See [`AlertCondition::RouterWeakSignal`].
        RouterWeakSignal,
        /// See [`AlertCondition::RouterFirmwareChanged`].
        RouterFirmwareChanged,
        /// See [`AlertCondition::RouterUnreadSms`].
        RouterUnreadSms,
        /// See [`AlertCondition::RouterCounterMismatch`].
        RouterCounterMismatch,
        /// See [`AlertCondition::UsersNearQuota`].
        UsersNearQuota,
        /// See [`AlertCondition::UsersOverQuota`].
        UsersOverQuota,
        /// See [`AlertCondition::UsersSuspended`].
        UsersSuspended,
        /// See [`AlertCondition::UsersExpiringSoon`].
        UsersExpiringSoon,
        /// See [`AlertCondition::UsersExpired`].
        UsersExpired,
        /// See [`AlertCondition::CapacitySaturated`].
        CapacitySaturated,
        /// See [`AlertCondition::ExitFlowCapHit`].
        ExitFlowCapHit,
        /// See [`AlertCondition::NodeClockUnsynced`].
        NodeClockUnsynced,
        /// See [`AlertCondition::NodeRebootPending`].
        NodeRebootPending,
        /// See [`AlertCondition::PendingApply`].
        PendingApply,
        /// See [`AlertCondition::OperatorHoldLong`].
        OperatorHoldLong,
        /// See [`AlertCondition::AccountingCanaryMissing`].
        AccountingCanaryMissing,
    }
}

/// Seconds in an hour.
const HOUR_SECS: u64 = 3600;

/// How long, in seconds, a node must have failed every poll before
/// [`AlertCondition::NodeUnreachable`] is raised: one status-poll interval
/// (design §10.5), so the next scheduled poll has failed too. Inference,
/// calibrated in M8.
pub const NODE_UNREACHABLE_HOLD_SECS: u64 = 10 * 60;

impl AlertConditionKind {
    /// How urgent alerts of this kind are (console spec B.4).
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::ExitViolation
            | Self::SimCapReached
            | Self::RouterOffloadActive
            | Self::RouterWifiRadioOn
            | Self::RouterOverheating
            | Self::RouterRestarted
            | Self::NodeHalted
            | Self::RollbackFailed
            | Self::GateCloseFailed
            | Self::EngineCrashLoop
            | Self::HostKeyMismatch
            | Self::MacSilent
            | Self::NodeUnreachable
            | Self::NodeDiskLow
            | Self::AccountingCanaryMissing => Severity::Critical,
            Self::SimWarn
            | Self::SimForecastCrossing
            | Self::ExitDegraded
            | Self::ForeignNetworkAttached
            | Self::ReachabilitySuspect
            | Self::TargetDegraded
            | Self::RouterNoService
            | Self::RouterOnLte
            | Self::RouterThermalStepDown
            | Self::RouterWeakSignal
            | Self::RouterFirmwareChanged
            | Self::RouterUnreadSms
            | Self::RouterCounterMismatch
            | Self::UsersNearQuota
            | Self::UsersOverQuota
            | Self::UsersSuspended
            | Self::UsersExpiringSoon
            | Self::UsersExpired
            | Self::CapacitySaturated
            | Self::ExitFlowCapHit
            | Self::NodeClockUnsynced
            | Self::NodeRebootPending
            | Self::PendingApply
            | Self::OperatorHoldLong => Severity::Warning,
        }
    }

    /// How long, in seconds, a condition of this kind must stay active
    /// before it is raised: zero for critical kinds but a node that does
    /// not answer ([`NODE_UNREACHABLE_HOLD_SECS`]); for warnings the spec's
    /// longer holds (30 minutes on LTE, at thermal level 1 or saturated; 24
    /// hours for a pending reboot and an operator hold; 48 hours for a
    /// pending apply), and otherwise `timing`'s warning debounce. The
    /// values are the console spec's and are inference.
    #[must_use]
    pub const fn hold_secs(self, timing: &AlertTiming) -> u64 {
        match self.severity() {
            Severity::Critical => match self {
                Self::NodeUnreachable => NODE_UNREACHABLE_HOLD_SECS,
                _ => 0,
            },
            Severity::Warning => match self {
                Self::RouterOnLte | Self::RouterThermalStepDown | Self::CapacitySaturated => {
                    HOUR_SECS / 2
                }
                Self::NodeRebootPending | Self::OperatorHoldLong => 24 * HOUR_SECS,
                Self::PendingApply => 48 * HOUR_SECS,
                _ => timing.warning_debounce_secs,
            },
        }
    }

    /// Whether an alert of this kind is raised at most once per subject,
    /// even if it clears and returns: the forecast crossing, once per
    /// cycle.
    #[must_use]
    pub const fn once_per_subject(self) -> bool {
        matches!(self, Self::SimForecastCrossing)
    }
}

/// What an alert is about. Together with the kind it is the alert's
/// identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AlertSubject {
    /// The exit as a whole.
    Exit,
    /// One engine, on the Mac or a node.
    Engine {
        /// The engine and where it runs.
        host: EngineHost,
    },
    /// One SIM billing cycle.
    SimCycle {
        /// The cycle's first day.
        start: CalendarDate,
    },
    /// The M7.
    Router,
    /// The uplink's capacity.
    Capacity,
    /// The users, in aggregate.
    Users,
    /// A node.
    Node {
        /// The node.
        node: NodeId,
    },
}

/// An alert's identity: conditions with the same key are the same alert.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertKey {
    /// The kind.
    pub kind: AlertConditionKind,
    /// The subject.
    pub subject: AlertSubject,
}

impl fmt::Display for AlertKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.subject {
            AlertSubject::Exit => write!(f, "{} on the exit", self.kind),
            AlertSubject::Engine {
                host: EngineHost::Mac { engine },
            } => write!(f, "{} of {engine} on the Mac", self.kind),
            AlertSubject::Engine {
                host: EngineHost::Node { node, engine },
            } => write!(f, "{} of {engine} on {node}", self.kind),
            AlertSubject::SimCycle { start } => {
                write!(f, "{} in the cycle from {start}", self.kind)
            }
            AlertSubject::Router => write!(f, "{} on the router", self.kind),
            AlertSubject::Capacity => write!(f, "{} on the uplink", self.kind),
            AlertSubject::Users => write!(f, "{} among users", self.kind),
            AlertSubject::Node { node } => write!(f, "{} on {node}", self.kind),
        }
    }
}

impl AlertCondition {
    /// The condition's kind.
    #[must_use]
    pub const fn kind(&self) -> AlertConditionKind {
        match self {
            Self::ExitViolation { .. } => AlertConditionKind::ExitViolation,
            Self::SimCapReached { .. } => AlertConditionKind::SimCapReached,
            Self::RouterOffloadActive => AlertConditionKind::RouterOffloadActive,
            Self::RouterWifiRadioOn => AlertConditionKind::RouterWifiRadioOn,
            Self::RouterOverheating { .. } => AlertConditionKind::RouterOverheating,
            Self::RouterRestarted => AlertConditionKind::RouterRestarted,
            Self::NodeHalted { .. } => AlertConditionKind::NodeHalted,
            Self::RollbackFailed { .. } => AlertConditionKind::RollbackFailed,
            Self::GateCloseFailed { .. } => AlertConditionKind::GateCloseFailed,
            Self::EngineCrashLoop { .. } => AlertConditionKind::EngineCrashLoop,
            Self::HostKeyMismatch { .. } => AlertConditionKind::HostKeyMismatch,
            Self::MacSilent { .. } => AlertConditionKind::MacSilent,
            Self::NodeUnreachable { .. } => AlertConditionKind::NodeUnreachable,
            Self::NodeDiskLow { .. } => AlertConditionKind::NodeDiskLow,
            Self::SimWarn { .. } => AlertConditionKind::SimWarn,
            Self::SimForecastCrossing { .. } => AlertConditionKind::SimForecastCrossing,
            Self::ExitDegraded { .. } => AlertConditionKind::ExitDegraded,
            Self::ForeignNetworkAttached { .. } => AlertConditionKind::ForeignNetworkAttached,
            Self::ReachabilitySuspect { .. } => AlertConditionKind::ReachabilitySuspect,
            Self::TargetDegraded { .. } => AlertConditionKind::TargetDegraded,
            Self::RouterNoService => AlertConditionKind::RouterNoService,
            Self::RouterOnLte => AlertConditionKind::RouterOnLte,
            Self::RouterThermalStepDown => AlertConditionKind::RouterThermalStepDown,
            Self::RouterWeakSignal { .. } => AlertConditionKind::RouterWeakSignal,
            Self::RouterFirmwareChanged => AlertConditionKind::RouterFirmwareChanged,
            Self::RouterUnreadSms { .. } => AlertConditionKind::RouterUnreadSms,
            Self::RouterCounterMismatch { .. } => AlertConditionKind::RouterCounterMismatch,
            Self::UsersNearQuota { .. } => AlertConditionKind::UsersNearQuota,
            Self::UsersOverQuota { .. } => AlertConditionKind::UsersOverQuota,
            Self::UsersSuspended { .. } => AlertConditionKind::UsersSuspended,
            Self::UsersExpiringSoon { .. } => AlertConditionKind::UsersExpiringSoon,
            Self::UsersExpired { .. } => AlertConditionKind::UsersExpired,
            Self::CapacitySaturated => AlertConditionKind::CapacitySaturated,
            Self::ExitFlowCapHit { .. } => AlertConditionKind::ExitFlowCapHit,
            Self::NodeClockUnsynced { .. } => AlertConditionKind::NodeClockUnsynced,
            Self::NodeRebootPending { .. } => AlertConditionKind::NodeRebootPending,
            Self::PendingApply { .. } => AlertConditionKind::PendingApply,
            Self::OperatorHoldLong { .. } => AlertConditionKind::OperatorHoldLong,
            Self::AccountingCanaryMissing { .. } => AlertConditionKind::AccountingCanaryMissing,
        }
    }

    /// The node the condition is about, if it is about one.
    #[must_use]
    pub const fn node(&self) -> Option<&NodeId> {
        match self {
            Self::EngineCrashLoop {
                host: EngineHost::Node { node, .. },
            }
            | Self::NodeHalted { node }
            | Self::RollbackFailed { node }
            | Self::GateCloseFailed { node }
            | Self::HostKeyMismatch { node }
            | Self::MacSilent { node }
            | Self::NodeUnreachable { node, .. }
            | Self::NodeDiskLow { node, .. }
            | Self::ReachabilitySuspect { node }
            | Self::TargetDegraded { node }
            | Self::ExitFlowCapHit { node, .. }
            | Self::NodeClockUnsynced { node }
            | Self::NodeRebootPending { node, .. }
            | Self::PendingApply { node, .. }
            | Self::OperatorHoldLong { node, .. }
            | Self::AccountingCanaryMissing { node, .. } => Some(node),
            Self::ExitViolation { .. }
            | Self::SimCapReached { .. }
            | Self::RouterOffloadActive
            | Self::RouterWifiRadioOn
            | Self::RouterOverheating { .. }
            | Self::RouterRestarted
            | Self::EngineCrashLoop {
                host: EngineHost::Mac { .. },
            }
            | Self::SimWarn { .. }
            | Self::SimForecastCrossing { .. }
            | Self::ExitDegraded { .. }
            | Self::ForeignNetworkAttached { .. }
            | Self::RouterNoService
            | Self::RouterOnLte
            | Self::RouterThermalStepDown
            | Self::RouterWeakSignal { .. }
            | Self::RouterFirmwareChanged
            | Self::RouterUnreadSms { .. }
            | Self::RouterCounterMismatch { .. }
            | Self::UsersNearQuota { .. }
            | Self::UsersOverQuota { .. }
            | Self::UsersSuspended { .. }
            | Self::UsersExpiringSoon { .. }
            | Self::UsersExpired { .. }
            | Self::CapacitySaturated => None,
        }
    }

    /// When the condition's source says it started, for the kinds that
    /// carry it; the machine holds such a condition from that start.
    #[must_use]
    pub const fn source_since(&self) -> Option<UnixTime> {
        match self {
            Self::NodeUnreachable { since, .. }
            | Self::NodeRebootPending { since, .. }
            | Self::PendingApply { since, .. }
            | Self::OperatorHoldLong { since, .. } => Some(*since),
            _ => None,
        }
    }

    /// What the condition is about.
    #[must_use]
    pub fn subject(&self) -> AlertSubject {
        match self {
            Self::ExitViolation { .. }
            | Self::ExitDegraded { .. }
            | Self::ForeignNetworkAttached { .. } => AlertSubject::Exit,
            Self::EngineCrashLoop { host } => AlertSubject::Engine { host: host.clone() },
            Self::SimCapReached { cycle_start }
            | Self::SimWarn { cycle_start }
            | Self::SimForecastCrossing { cycle_start, .. } => AlertSubject::SimCycle {
                start: *cycle_start,
            },
            Self::RouterOffloadActive
            | Self::RouterWifiRadioOn
            | Self::RouterOverheating { .. }
            | Self::RouterRestarted
            | Self::RouterNoService
            | Self::RouterOnLte
            | Self::RouterThermalStepDown
            | Self::RouterWeakSignal { .. }
            | Self::RouterFirmwareChanged
            | Self::RouterUnreadSms { .. }
            | Self::RouterCounterMismatch { .. } => AlertSubject::Router,
            Self::CapacitySaturated => AlertSubject::Capacity,
            Self::UsersNearQuota { .. }
            | Self::UsersOverQuota { .. }
            | Self::UsersSuspended { .. }
            | Self::UsersExpiringSoon { .. }
            | Self::UsersExpired { .. } => AlertSubject::Users,
            Self::NodeHalted { node }
            | Self::RollbackFailed { node }
            | Self::GateCloseFailed { node }
            | Self::HostKeyMismatch { node }
            | Self::MacSilent { node }
            | Self::NodeUnreachable { node, .. }
            | Self::NodeDiskLow { node, .. }
            | Self::ReachabilitySuspect { node }
            | Self::TargetDegraded { node }
            | Self::ExitFlowCapHit { node, .. }
            | Self::NodeClockUnsynced { node }
            | Self::NodeRebootPending { node, .. }
            | Self::PendingApply { node, .. }
            | Self::OperatorHoldLong { node, .. }
            | Self::AccountingCanaryMissing { node, .. } => {
                AlertSubject::Node { node: node.clone() }
            }
        }
    }

    /// The alert's identity.
    #[must_use]
    pub fn key(&self) -> AlertKey {
        AlertKey {
            kind: self.kind(),
            subject: self.subject(),
        }
    }

    /// How urgent the alert is.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.kind().severity()
    }
}

/// The machine's intervals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertTiming {
    /// How long a warning must stay active before it is raised, unless its
    /// kind sets a longer hold.
    pub warning_debounce_secs: u64,
    /// How often an active critical alert is reminded.
    pub reminder_secs: NonZeroU64,
}

impl AlertTiming {
    /// 15 minutes and 6 hours (console spec B.4).
    pub const DEFAULT: Self = Self {
        warning_debounce_secs: 15 * 60,
        reminder_secs: match NonZeroU64::new(6 * HOUR_SECS) {
            Some(secs) => secs,
            None => panic!("six hours is not zero"),
        },
    };
}

/// What a notice reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeEvent {
    /// The alert opened.
    Raised,
    /// The critical alert is still active.
    Reminder,
    /// The alert cleared.
    Resolved,
}

/// One notice for the channels to deliver.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertNotice {
    /// The observation that produced it.
    pub at: UnixTime,
    /// What it reports.
    pub event: NoticeEvent,
    /// The alert's severity.
    pub severity: Severity,
    /// The condition's latest payload.
    pub condition: AlertCondition,
    /// Since when the condition has been continuously active.
    pub active_since: UnixTime,
}

/// An open (raised and not yet resolved) alert.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenAlert {
    /// The alert's severity.
    pub severity: Severity,
    /// The condition's latest payload.
    pub condition: AlertCondition,
    /// Since when the condition has been continuously active.
    pub active_since: UnixTime,
    /// When it was raised.
    pub raised_at: UnixTime,
}

impl OpenAlert {
    /// The alert's identity.
    #[must_use]
    pub fn key(&self) -> AlertKey {
        self.condition.key()
    }
}

/// One tracked condition.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    condition: AlertCondition,
    active_since: UnixTime,
    /// `Some` once raised: when it was raised, and when it last notified.
    raised: Option<(UnixTime, UnixTime)>,
}

/// The alert state machine. It holds no clock: each [`AlertMachine::step`]
/// is told the time and the conditions active at it.
///
/// Its state lives in memory. A daemon that restarts starts a new machine,
/// so active critical conditions are raised again once their hold is met,
/// and conditions that carry their source's start (`since`) keep their
/// hold measured from it, so a restart does not delay them. Other warnings
/// wait their hold again from the first observation after the restart;
/// only those (15 or 30 minutes) can be delayed by restarts, and nothing
/// is suppressed outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertMachine {
    timing: AlertTiming,
    last_step: Option<UnixTime>,
    tracked: BTreeMap<AlertKey, Tracked>,
    /// Keys of once-per-subject kinds already raised. Only the subjects of
    /// the latest billing cycle seen are kept.
    raised_once: BTreeSet<AlertKey>,
}

impl AlertMachine {
    /// A machine with nothing active.
    #[must_use]
    pub const fn new(timing: AlertTiming) -> Self {
        Self {
            timing,
            last_step: None,
            tracked: BTreeMap::new(),
            raised_once: BTreeSet::new(),
        }
    }

    /// Observes the conditions active at `now` and returns the notices due,
    /// in key order: resolutions of raised alerts no longer active, then
    /// raises and reminders.
    ///
    /// `now` must not be earlier than the previous observation
    /// (`ClockWentBackwards`), and no two conditions may share a key
    /// (`DuplicateCondition`); a refused observation changes nothing.
    pub fn step(
        &mut self,
        now: UnixTime,
        active: Vec<AlertCondition>,
    ) -> Result<Vec<AlertNotice>, AlertError> {
        if let Some(previous) = self.last_step
            && now < previous
        {
            return Err(AlertError::ClockWentBackwards { previous, now });
        }
        let mut current: BTreeMap<AlertKey, AlertCondition> = BTreeMap::new();
        for condition in active {
            let key = condition.key();
            if current.contains_key(&key) {
                return Err(AlertError::DuplicateCondition { key });
            }
            current.insert(key, condition);
        }
        self.last_step = Some(now);
        let mut notices = Vec::new();
        let cleared: Vec<AlertKey> = self
            .tracked
            .keys()
            .filter(|key| !current.contains_key(*key))
            .cloned()
            .collect();
        for key in cleared {
            if let Some(tracked) = self.tracked.remove(&key)
                && tracked.raised.is_some()
            {
                notices.push(AlertNotice {
                    at: now,
                    event: NoticeEvent::Resolved,
                    severity: tracked.condition.severity(),
                    condition: tracked.condition,
                    active_since: tracked.active_since,
                });
            }
        }
        for (key, condition) in current {
            let hold = key.kind.hold_secs(&self.timing);
            let reminder = self.timing.reminder_secs.get();
            let once = key.kind.once_per_subject();
            let tracked = self.tracked.entry(key.clone()).or_insert(Tracked {
                condition: condition.clone(),
                active_since: now,
                raised: None,
            });
            if let Some(since) = condition.source_since() {
                tracked.active_since = since;
            }
            tracked.condition = condition;
            // A source's start may lie ahead of the Mac's clock (a node's
            // clock); it then counts as just started.
            let active_for = now.as_secs().saturating_sub(tracked.active_since.as_secs());
            let event = match tracked.raised {
                None if active_for >= hold => {
                    if once && self.raised_once.contains(&key) {
                        None
                    } else {
                        tracked.raised = Some((now, now));
                        Some(NoticeEvent::Raised)
                    }
                }
                Some((raised_at, last_notice))
                    if key.kind.severity() == Severity::Critical
                        && now.as_secs() - last_notice.as_secs() >= reminder =>
                {
                    tracked.raised = Some((raised_at, now));
                    Some(NoticeEvent::Reminder)
                }
                _ => None,
            };
            if let Some(event) = event {
                notices.push(AlertNotice {
                    at: now,
                    event,
                    severity: key.kind.severity(),
                    condition: tracked.condition.clone(),
                    active_since: tracked.active_since,
                });
            }
            if once && event == Some(NoticeEvent::Raised) {
                self.remember_once(key);
            }
        }
        Ok(notices)
    }

    /// Records a once-per-subject raise, keeping only the latest cycle's.
    fn remember_once(&mut self, key: AlertKey) {
        if let AlertSubject::SimCycle { start } = key.subject {
            self.raised_once.retain(|kept| match kept.subject {
                AlertSubject::SimCycle { start: kept_start } => kept_start >= start,
                _ => true,
            });
        }
        self.raised_once.insert(key);
    }

    /// The open alerts, in key order.
    #[must_use]
    pub fn open(&self) -> Vec<OpenAlert> {
        self.tracked
            .values()
            .filter_map(|tracked| {
                tracked.raised.map(|(raised_at, _)| OpenAlert {
                    severity: tracked.condition.severity(),
                    condition: tracked.condition.clone(),
                    active_since: tracked.active_since,
                    raised_at,
                })
            })
            .collect()
    }
}
