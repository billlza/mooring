// SPDX-License-Identifier: GPL-3.0-or-later

//! `contract/status-fixtures/variants.json`: one value of every variant of
//! every enum a `MacStatusV1` carries, the model's and agent-proto's
//! included. The scenario fixtures reach only the states their scenarios
//! are in, so this document gives Mooring.app's Codable mirror a fixture
//! for every variant, and pins each variant's encoding byte for byte: a
//! renamed variant fails here.
//!
//! [`variants`] builds it. Each list is checked to hold every variant once,
//! in declaration order, by an exhaustive `match` (or the kind's `ALL`),
//! so a new variant cannot be left out. To change it, change the builder,
//! write [`encode`]'s output over the file, and review the diff.
//!
//! The same module checks that every JSON object of every status fixture,
//! and of this document, refuses an unknown key, as `deny_unknown_fields`
//! promises.

use std::net::Ipv4Addr;

use mooring_agent_proto::{EngineRun, GateState, Inbound, ShutdownReason, WatchError};
use mooring_model::collections::NonEmpty;
use mooring_model::exit::ProbeProtocol;
use mooring_model::iface::BsdName;
use mooring_model::node::{LifecycleStage, NodeRole};
use mooring_model::sim::{PlanLineKind, StopPolicy};
use mooring_model::user::{SuspendReason, UserStatus};
use mooring_model::verdict::{Violation, ViolationKind};
use mooring_model::{CalendarDate, Pairing, UnixTime};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::alerts::every_condition;
use super::router;
use super::support::{at, date, deployment, node, status};
use crate::alert::{
    AlertCondition, AlertConditionKind, CriticalThermalLevel, DegradedReasonKind, EngineHost,
    MacEngine, NodeEngine, Severity,
};
use crate::capacity::{Saturation, UplinkUse};
use crate::error::{ForecastErrorKind, UsageErrorKind};
use crate::forecast::{Crossing, DailySimBytes, SimForecast, SimThreshold};
use crate::network::{ForeignNetworkFinding, IpFamily};
use crate::period::UsagePeriods;
use crate::policy::{ExpiryState, QuotaState};
use crate::router::{
    Band, BandNumber, BatteryState, ChargeSource, DataService, LteBandwidth, NetworkService,
    PowerState, RadioState, RouterReading, RouterUnavailableReason, ThermalState, WifiApStatus,
};
use crate::status::{
    AgentUnreachable, DegradedReason, DownReason, DrainOutcome, ExitState, ForecastView,
    InChainOutcome, MacStatusV1, MeterAccuracy, NodeAgentState, NodeReport, PowerSource,
    ProbeStage, ProcessEnd, UsageView,
};
use crate::usage::ActiveNow;

const FIXTURE: &[u8] = include_bytes!("../../../../contract/status-fixtures/variants.json");

/// Every enum a status carries, one list per enum.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Variants {
    exit_state: Vec<ExitState>,
    degraded_reason: Vec<DegradedReason>,
    down_reason: Vec<DownReason>,
    probe_stage: Vec<ProbeStage>,
    process_end: Vec<ProcessEnd>,
    power_source: Vec<PowerSource>,
    drain_outcome: Vec<DrainOutcome>,
    meter_accuracy: Vec<MeterAccuracy>,
    forecast_view: Vec<ForecastView>,
    usage_view: Vec<UsageView>,
    in_chain_outcome: Vec<InChainOutcome>,
    agent_unreachable: Vec<AgentUnreachable>,
    node_agent_state: Vec<NodeAgentState>,
    alert_condition: Vec<AlertCondition>,
    severity: Vec<Severity>,
    mac_engine: Vec<MacEngine>,
    node_engine: Vec<NodeEngine>,
    engine_host: Vec<EngineHost>,
    degraded_reason_kind: Vec<DegradedReasonKind>,
    critical_thermal_level: Vec<CriticalThermalLevel>,
    sim_threshold: Vec<SimThreshold>,
    crossing: Vec<Crossing>,
    uplink_use: Vec<UplinkUse>,
    saturation: Vec<Saturation>,
    foreign_network_finding: Vec<ForeignNetworkFinding>,
    ip_family: Vec<IpFamily>,
    quota_state: Vec<QuotaState>,
    expiry_state: Vec<ExpiryState>,
    network_service: Vec<NetworkService>,
    data_service: Vec<DataService>,
    radio_state: Vec<RadioState>,
    thermal_state: Vec<ThermalState>,
    power_state: Vec<PowerState>,
    battery_state: Vec<BatteryState>,
    charge_source: Vec<ChargeSource>,
    wifi_ap_status: Vec<WifiApStatus>,
    lte_bandwidth: Vec<LteBandwidth>,
    router_unavailable_reason: Vec<RouterUnavailableReason>,
    router_reading: Vec<RouterReading>,
    band: Vec<Band>,
    active_now: Vec<ActiveNow>,
    forecast_error_kind: Vec<ForecastErrorKind>,
    usage_error_kind: Vec<UsageErrorKind>,
    user_status: Vec<UserStatus>,
    suspend_reason: Vec<SuspendReason>,
    lifecycle_stage: Vec<LifecycleStage>,
    node_role: Vec<NodeRole>,
    pairing: Vec<Pairing>,
    probe_protocol: Vec<ProbeProtocol>,
    violation: Vec<Violation>,
    violation_kind: Vec<ViolationKind>,
    stop_policy: Vec<StopPolicy>,
    plan_line_kind: Vec<PlanLineKind>,
    gate_state: Vec<GateState>,
    shutdown_reason: Vec<ShutdownReason>,
    watch_error: Vec<WatchError>,
    engine_run: Vec<EngineRun>,
    inbound: Vec<Inbound>,
}

fn t(secs: u64) -> UnixTime {
    UnixTime::from_secs(1_791_417_600 + secs)
}

fn interface(name: &str) -> BsdName {
    BsdName::parse(name).unwrap()
}

/// One of each finding, on an interface other than the egress.
fn findings() -> Vec<ForeignNetworkFinding> {
    vec![
        ForeignNetworkFinding::RoutableIpv4 {
            interface: interface("en0"),
        },
        ForeignNetworkFinding::GlobalIpv6 {
            interface: interface("en0"),
        },
        ForeignNetworkFinding::DefaultRoute {
            interface: interface("en0"),
            family: IpFamily::V6,
        },
        ForeignNetworkFinding::PersonalHotspot {
            interface: interface("en5"),
        },
    ]
}

/// One of each violation, with documentation addresses.
fn violations() -> Vec<Violation> {
    vec![
        Violation::EgressIsNodeAddress {
            node: node("lon1"),
            ip: Ipv4Addr::new(203, 0, 113, 10),
        },
        Violation::OutsideCarrierPrefixes {
            ip: Ipv4Addr::new(198, 51, 100, 7),
        },
        Violation::EgressEqualsUplink {
            ip: Ipv4Addr::new(198, 51, 100, 8),
        },
        Violation::EgressMismatch {
            d1: Ipv4Addr::new(192, 0, 2, 1),
            d2: Ipv4Addr::new(192, 0, 2, 1),
            observed: Ipv4Addr::new(192, 0, 2, 9),
        },
    ]
}

fn degraded_reasons() -> Vec<DegradedReason> {
    vec![
        DegradedReason::NodeProbeFailed {
            node: node("lon1"),
            protocol: ProbeProtocol::Hy2,
            stage: ProbeStage::Read,
        },
        DegradedReason::ReachabilitySuspect { node: node("lon1") },
        DegradedReason::WatchStale { node: node("ams1") },
        DegradedReason::OnBattery,
        DegradedReason::PowerHelperExited,
    ]
}

fn cycle_start() -> CalendarDate {
    date("2026-10-01")
}

/// The variants document.
fn variants() -> Variants {
    let deployment = deployment();
    let sim = &deployment.exit().sim;
    let as_of = at("2026-10-04", 0);
    let forecast = SimForecast::project(
        sim,
        as_of,
        &(1..=3)
            .map(|day| DailySimBytes {
                date: date(&format!("2026-10-0{day}")),
                bytes: 20_000_000_000,
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let now = at("2026-10-08", 36_000);
    let report = NodeReport::of(
        UnixTime::from_secs(now.as_secs() + 1),
        &status(
            now,
            Some(UnixTime::from_secs(now.as_secs() - 30)),
            Vec::new(),
        ),
    );
    let mut down_reasons = vec![
        DownReason::EgressInterfaceAbsent,
        DownReason::EgressAmbiguous { matches: 2 },
        DownReason::EgressNoIpv4 {
            interface: interface("en8"),
        },
        DownReason::EgressSubnetMismatch,
        DownReason::UplinkAbsent,
        DownReason::UplinkEqualsEgress,
        DownReason::DirectProbeFailed {
            node: node("lon1"),
            stage: ProbeStage::Connect,
        },
        DownReason::SecretsUnavailable,
        DownReason::AgentNotEnabled { node: node("ams1") },
        DownReason::EngineSpawnFailed {
            engine: MacEngine::Exit,
        },
        DownReason::EngineConfigRejected {
            engine: MacEngine::Probe,
        },
        DownReason::EngineStartFailed {
            engine: MacEngine::Exit,
        },
        DownReason::EngineCrashLoop {
            engine: MacEngine::Probe,
        },
    ];
    down_reasons.push(DownReason::Violation(violations().remove(3)));
    down_reasons.push(DownReason::SimCapReached {
        cycle_start: cycle_start(),
    });
    let mut all_findings = findings();
    let first = all_findings.remove(0);
    down_reasons.push(DownReason::ForeignNetworkAttached {
        findings: NonEmpty::from_parts(first, all_findings),
    });
    let mut reasons = degraded_reasons();
    let first_reason = reasons.remove(0);
    Variants {
        exit_state: vec![
            ExitState::Disabled,
            ExitState::Preflight,
            ExitState::Starting,
            ExitState::Verifying,
            ExitState::Serving {
                ip: Ipv4Addr::new(198, 51, 100, 17),
                verified_at: t(60),
            },
            ExitState::Degraded {
                reasons: NonEmpty::from_parts(first_reason, reasons),
            },
            ExitState::Down {
                reason: DownReason::SecretsUnavailable,
            },
            ExitState::Paused,
        ],
        degraded_reason: degraded_reasons(),
        down_reason: down_reasons,
        probe_stage: vec![
            ProbeStage::Connect,
            ProbeStage::Read,
            ProbeStage::Parse,
            ProbeStage::ProberUnavailable,
            ProbeStage::CarrierAddressUnstable,
        ],
        process_end: vec![
            ProcessEnd::Exited { code: 1 },
            ProcessEnd::Signalled { signal: 9 },
        ],
        power_source: vec![PowerSource::Ac, PowerSource::Battery],
        drain_outcome: vec![
            DrainOutcome::Completed,
            DrainOutcome::TimedOut,
            DrainOutcome::Failed,
        ],
        meter_accuracy: vec![MeterAccuracy::Exact, MeterAccuracy::LowerBound],
        forecast_view: vec![
            ForecastView::Projected(forecast),
            ForecastView::Unavailable {
                reason: ForecastErrorKind::MissingDay,
            },
        ],
        usage_view: vec![
            UsageView::Report {
                periods: UsagePeriods::ending(sim.bill_day(), now).unwrap(),
            },
            UsageView::Unavailable {
                reason: UsageErrorKind::MissingLedger,
            },
        ],
        in_chain_outcome: vec![
            InChainOutcome::Verified,
            InChainOutcome::Violation {
                kind: ViolationKind::EgressMismatch,
            },
            InChainOutcome::Failed {
                stage: ProbeStage::Parse,
            },
        ],
        agent_unreachable: vec![
            AgentUnreachable::Spawn,
            AgentUnreachable::HostKeyMismatch,
            AgentUnreachable::AuthFailed,
            AgentUnreachable::Transport,
            AgentUnreachable::Timeout,
            AgentUnreachable::ProtocolMismatch,
            AgentUnreachable::Decode,
            AgentUnreachable::ResponseTooLarge,
            AgentUnreachable::ForcedCommandNotActive,
        ],
        node_agent_state: vec![
            NodeAgentState::NotPolled,
            NodeAgentState::Reported(Box::new(report)),
            NodeAgentState::Unreachable {
                since: t(0),
                cause: AgentUnreachable::Transport,
            },
        ],
        alert_condition: every_condition()
            .into_iter()
            .map(|(_, condition, _)| condition)
            .collect(),
        severity: vec![Severity::Critical, Severity::Warning],
        mac_engine: vec![MacEngine::Exit, MacEngine::Probe],
        node_engine: vec![NodeEngine::Xray, NodeEngine::Hy2],
        engine_host: vec![
            EngineHost::Mac {
                engine: MacEngine::Exit,
            },
            EngineHost::Node {
                node: node("lon1"),
                engine: NodeEngine::Hy2,
            },
        ],
        degraded_reason_kind: DegradedReasonKind::ALL.to_vec(),
        critical_thermal_level: vec![CriticalThermalLevel::Level2, CriticalThermalLevel::Level3],
        sim_threshold: vec![
            SimThreshold::Warn,
            SimThreshold::HardStop,
            SimThreshold::FairUse,
            SimThreshold::Allowance,
        ],
        crossing: vec![
            Crossing::Reached {
                on: date("2026-10-03"),
            },
            Crossing::Projected {
                on: date("2026-10-25"),
            },
            Crossing::NotThisCycle,
        ],
        uplink_use: vec![
            UplinkUse::NoBaseline,
            UplinkUse::Measured {
                permille: 870,
                baseline_p50_bps: 16_000_000,
            },
        ],
        saturation: vec![
            Saturation::NoEvidence,
            Saturation::Clear,
            Saturation::Building { since: t(120) },
            Saturation::Saturated { since: t(0) },
        ],
        foreign_network_finding: findings(),
        ip_family: vec![IpFamily::V4, IpFamily::V6],
        quota_state: vec![
            QuotaState::NoQuota,
            QuotaState::Within {
                used_bytes: 1,
                quota_bytes: 10,
            },
            QuotaState::Warn {
                used_bytes: 8,
                quota_bytes: 10,
            },
            QuotaState::Over {
                used_bytes: 10,
                quota_bytes: 10,
            },
            QuotaState::UsageUnavailable { quota_bytes: 10 },
        ],
        expiry_state: vec![
            ExpiryState::NoExpiry,
            ExpiryState::Expires {
                at: t(86_400),
                days_left: 1,
            },
            ExpiryState::Expired { at: t(0) },
        ],
        network_service: NetworkService::ALL.to_vec(),
        data_service: DataService::ALL.to_vec(),
        radio_state: vec![RadioState::NoService, router::status().into_parts().radio],
        thermal_state: ThermalState::ALL.to_vec(),
        power_state: PowerState::ALL.to_vec(),
        battery_state: BatteryState::ALL.to_vec(),
        charge_source: ChargeSource::ALL.to_vec(),
        wifi_ap_status: WifiApStatus::ALL.to_vec(),
        lte_bandwidth: LteBandwidth::ALL.to_vec(),
        router_unavailable_reason: vec![
            RouterUnavailableReason::NotConfigured,
            RouterUnavailableReason::Unreachable,
            RouterUnavailableReason::AuthFailed,
            RouterUnavailableReason::IdentityMismatch,
            RouterUnavailableReason::Unsupported,
            RouterUnavailableReason::Malformed,
        ],
        router_reading: vec![
            router::reading(),
            RouterReading::Unavailable {
                reason: RouterUnavailableReason::IdentityMismatch,
                last_polled_at: None,
            },
        ],
        band: vec![
            Band::Lte(BandNumber::new(3).unwrap()),
            Band::Nr(BandNumber::new(78).unwrap()),
        ],
        active_now: vec![ActiveNow::Active, ActiveNow::Idle, ActiveNow::Unknown],
        forecast_error_kind: ForecastErrorKind::ALL.to_vec(),
        usage_error_kind: UsageErrorKind::ALL.to_vec(),
        user_status: vec![
            UserStatus::Active,
            UserStatus::Suspended {
                reason: SuspendReason::AbuseReview,
                since: t(0),
            },
            UserStatus::RevokePending,
            UserStatus::Revoked,
        ],
        suspend_reason: vec![
            SuspendReason::Operator,
            SuspendReason::QuotaExceeded {
                cycle_start: cycle_start(),
            },
            SuspendReason::Expired,
            SuspendReason::AbuseReview,
        ],
        lifecycle_stage: LifecycleStage::ALL.to_vec(),
        node_role: vec![NodeRole::Primary, NodeRole::Standby],
        pairing: vec![Pairing::Paired, Pairing::Unpaired],
        probe_protocol: vec![ProbeProtocol::Reality, ProbeProtocol::Hy2],
        violation: violations(),
        violation_kind: ViolationKind::ALL.to_vec(),
        stop_policy: vec![
            StopPolicy::HardStop {
                bytes: 560_000_000_000,
            },
            StopPolicy::AcceptDeprioritisation,
        ],
        plan_line_kind: vec![PlanLineKind::FairUse, PlanLineKind::Allowance],
        gate_state: vec![GateState::Open, GateState::Closed],
        shutdown_reason: ShutdownReason::ALL.to_vec(),
        watch_error: watch_errors(),
        engine_run: vec![
            EngineRun::Inactive,
            EngineRun::Active {
                uptime_secs: 3_600,
                go_heap_bytes: Some(37_748_736),
            },
        ],
        inbound: Inbound::ALL.to_vec(),
    }
}

/// One watch condition of every kind.
fn watch_errors() -> Vec<WatchError> {
    use mooring_agent_proto::{InboundSet, UnixTime as WireTime};
    vec![
        WatchError::WgReadFailed,
        WatchError::NftFailed,
        WatchError::StatsQueryFailed,
        WatchError::TargetDegraded,
        WatchError::ExitFlowCapHit { count: 14 },
        WatchError::StateWrite { errno: Some(28) },
        WatchError::MacSilent {
            since: Some(WireTime::from_secs(1_791_416_400)),
        },
        WatchError::DiskLow { free: 950_000_000 },
        WatchError::ClockUnsynced,
        WatchError::RebootPending {
            since: WireTime::from_secs(1_791_331_200),
        },
        WatchError::AccountingCanaryMissing {
            inbounds: InboundSet::of(Inbound::Reality).with(Inbound::Hy2),
        },
    ]
}

/// The fixture file's content: the pretty-printed document and a newline.
fn encode(variants: &Variants) -> String {
    let mut text = serde_json::to_string_pretty(variants).unwrap();
    text.push('\n');
    text
}

/// Asserts `values` hold exactly one value of each of `count` variants, in
/// declaration order, as `index` numbers them.
fn every_variant<T>(name: &str, values: &[T], index: impl Fn(&T) -> usize, count: usize) {
    assert_eq!(
        values.iter().map(index).collect::<Vec<_>>(),
        (0..count).collect::<Vec<_>>(),
        "{name} must list every variant once, in order"
    );
}

/// Asserts a field-less kind's list is its `ALL`.
fn every_kind<T: PartialEq + std::fmt::Debug>(name: &str, values: &[T], all: &[T]) {
    assert_eq!(values, all, "{name} must list every kind once, in order");
}

#[test]
fn the_variants_fixture_is_what_its_builder_generates() {
    let variants = variants();
    assert!(
        encode(&variants).as_bytes() == FIXTURE,
        "contract/status-fixtures/variants.json is not what `variants` generates"
    );
    let decoded: Variants = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(decoded, variants);
    assert!(encode(&decoded).as_bytes() == FIXTURE);
}

/// Every list holds every variant: the matches below are exhaustive, so a
/// new variant stops this from compiling until it is listed.
#[test]
fn the_variants_fixture_lists_every_variant() {
    let v = variants();
    every_variant(
        "exit_state",
        &v.exit_state,
        |value| match value {
            ExitState::Disabled => 0,
            ExitState::Preflight => 1,
            ExitState::Starting => 2,
            ExitState::Verifying => 3,
            ExitState::Serving { .. } => 4,
            ExitState::Degraded { .. } => 5,
            ExitState::Down { .. } => 6,
            ExitState::Paused => 7,
        },
        8,
    );
    every_variant(
        "degraded_reason",
        &v.degraded_reason,
        |value| match value {
            DegradedReason::NodeProbeFailed { .. } => 0,
            DegradedReason::ReachabilitySuspect { .. } => 1,
            DegradedReason::WatchStale { .. } => 2,
            DegradedReason::OnBattery => 3,
            DegradedReason::PowerHelperExited => 4,
        },
        5,
    );
    every_variant(
        "down_reason",
        &v.down_reason,
        |value| match value {
            DownReason::EgressInterfaceAbsent => 0,
            DownReason::EgressAmbiguous { .. } => 1,
            DownReason::EgressNoIpv4 { .. } => 2,
            DownReason::EgressSubnetMismatch => 3,
            DownReason::UplinkAbsent => 4,
            DownReason::UplinkEqualsEgress => 5,
            DownReason::DirectProbeFailed { .. } => 6,
            DownReason::SecretsUnavailable => 7,
            DownReason::AgentNotEnabled { .. } => 8,
            DownReason::EngineSpawnFailed { .. } => 9,
            DownReason::EngineConfigRejected { .. } => 10,
            DownReason::EngineStartFailed { .. } => 11,
            DownReason::EngineCrashLoop { .. } => 12,
            DownReason::Violation(_) => 13,
            DownReason::SimCapReached { .. } => 14,
            DownReason::ForeignNetworkAttached { .. } => 15,
        },
        16,
    );
    every_variant(
        "probe_stage",
        &v.probe_stage,
        |value| match value {
            ProbeStage::Connect => 0,
            ProbeStage::Read => 1,
            ProbeStage::Parse => 2,
            ProbeStage::ProberUnavailable => 3,
            ProbeStage::CarrierAddressUnstable => 4,
        },
        5,
    );
    every_variant(
        "process_end",
        &v.process_end,
        |value| match value {
            ProcessEnd::Exited { .. } => 0,
            ProcessEnd::Signalled { .. } => 1,
        },
        2,
    );
    every_variant(
        "power_source",
        &v.power_source,
        |value| match value {
            PowerSource::Ac => 0,
            PowerSource::Battery => 1,
        },
        2,
    );
    every_variant(
        "drain_outcome",
        &v.drain_outcome,
        |value| match value {
            DrainOutcome::Completed => 0,
            DrainOutcome::TimedOut => 1,
            DrainOutcome::Failed => 2,
        },
        3,
    );
    every_variant(
        "meter_accuracy",
        &v.meter_accuracy,
        |value| match value {
            MeterAccuracy::Exact => 0,
            MeterAccuracy::LowerBound => 1,
        },
        2,
    );
    every_variant(
        "forecast_view",
        &v.forecast_view,
        |value| match value {
            ForecastView::Projected(_) => 0,
            ForecastView::Unavailable { .. } => 1,
        },
        2,
    );
    every_variant(
        "usage_view",
        &v.usage_view,
        |value| match value {
            UsageView::Report { .. } => 0,
            UsageView::Unavailable { .. } => 1,
        },
        2,
    );
    every_variant(
        "in_chain_outcome",
        &v.in_chain_outcome,
        |value| match value {
            InChainOutcome::Verified => 0,
            InChainOutcome::Violation { .. } => 1,
            InChainOutcome::Failed { .. } => 2,
        },
        3,
    );
    every_variant(
        "agent_unreachable",
        &v.agent_unreachable,
        |value| match value {
            AgentUnreachable::Spawn => 0,
            AgentUnreachable::HostKeyMismatch => 1,
            AgentUnreachable::AuthFailed => 2,
            AgentUnreachable::Transport => 3,
            AgentUnreachable::Timeout => 4,
            AgentUnreachable::ProtocolMismatch => 5,
            AgentUnreachable::Decode => 6,
            AgentUnreachable::ResponseTooLarge => 7,
            AgentUnreachable::ForcedCommandNotActive => 8,
        },
        9,
    );
    every_variant(
        "node_agent_state",
        &v.node_agent_state,
        |value| match value {
            NodeAgentState::NotPolled => 0,
            NodeAgentState::Reported(_) => 1,
            NodeAgentState::Unreachable { .. } => 2,
        },
        3,
    );
    every_kind(
        "alert_condition",
        &v.alert_condition
            .iter()
            .map(AlertCondition::kind)
            .collect::<Vec<_>>(),
        AlertConditionKind::ALL,
    );
    every_variant(
        "severity",
        &v.severity,
        |value| match value {
            Severity::Critical => 0,
            Severity::Warning => 1,
        },
        2,
    );
    every_variant(
        "mac_engine",
        &v.mac_engine,
        |value| match value {
            MacEngine::Exit => 0,
            MacEngine::Probe => 1,
        },
        2,
    );
    every_variant(
        "node_engine",
        &v.node_engine,
        |value| match value {
            NodeEngine::Xray => 0,
            NodeEngine::Hy2 => 1,
        },
        2,
    );
    every_variant(
        "engine_host",
        &v.engine_host,
        |value| match value {
            EngineHost::Mac { .. } => 0,
            EngineHost::Node { .. } => 1,
        },
        2,
    );
    every_kind(
        "degraded_reason_kind",
        &v.degraded_reason_kind,
        DegradedReasonKind::ALL,
    );
    every_variant(
        "critical_thermal_level",
        &v.critical_thermal_level,
        |value| match value {
            CriticalThermalLevel::Level2 => 0,
            CriticalThermalLevel::Level3 => 1,
        },
        2,
    );
    every_variant(
        "sim_threshold",
        &v.sim_threshold,
        |value| match value {
            SimThreshold::Warn => 0,
            SimThreshold::HardStop => 1,
            SimThreshold::FairUse => 2,
            SimThreshold::Allowance => 3,
        },
        4,
    );
    every_variant(
        "crossing",
        &v.crossing,
        |value| match value {
            Crossing::Reached { .. } => 0,
            Crossing::Projected { .. } => 1,
            Crossing::NotThisCycle => 2,
        },
        3,
    );
    every_variant(
        "uplink_use",
        &v.uplink_use,
        |value| match value {
            UplinkUse::NoBaseline => 0,
            UplinkUse::Measured { .. } => 1,
        },
        2,
    );
    every_variant(
        "saturation",
        &v.saturation,
        |value| match value {
            Saturation::NoEvidence => 0,
            Saturation::Clear => 1,
            Saturation::Building { .. } => 2,
            Saturation::Saturated { .. } => 3,
        },
        4,
    );
    every_variant(
        "foreign_network_finding",
        &v.foreign_network_finding,
        |value| match value {
            ForeignNetworkFinding::RoutableIpv4 { .. } => 0,
            ForeignNetworkFinding::GlobalIpv6 { .. } => 1,
            ForeignNetworkFinding::DefaultRoute { .. } => 2,
            ForeignNetworkFinding::PersonalHotspot { .. } => 3,
        },
        4,
    );
    every_variant(
        "ip_family",
        &v.ip_family,
        |value| match value {
            IpFamily::V4 => 0,
            IpFamily::V6 => 1,
        },
        2,
    );
    every_variant(
        "quota_state",
        &v.quota_state,
        |value| match value {
            QuotaState::NoQuota => 0,
            QuotaState::Within { .. } => 1,
            QuotaState::Warn { .. } => 2,
            QuotaState::Over { .. } => 3,
            QuotaState::UsageUnavailable { .. } => 4,
        },
        5,
    );
    every_variant(
        "expiry_state",
        &v.expiry_state,
        |value| match value {
            ExpiryState::NoExpiry => 0,
            ExpiryState::Expires { .. } => 1,
            ExpiryState::Expired { .. } => 2,
        },
        3,
    );
    every_variant(
        "network_service",
        &v.network_service,
        |value| match value {
            NetworkService::Nr5g => 0,
        },
        1,
    );
    every_variant(
        "data_service",
        &v.data_service,
        |value| match value {
            DataService::NrSub6 => 0,
        },
        1,
    );
    every_variant(
        "radio_state",
        &v.radio_state,
        |value| match value {
            RadioState::NoService => 0,
            RadioState::Attached(_) => 1,
        },
        2,
    );
    every_variant(
        "thermal_state",
        &v.thermal_state,
        |value| match value {
            ThermalState::Normal => 0,
        },
        1,
    );
    every_variant(
        "power_state",
        &v.power_state,
        |value| match value {
            PowerState::Online => 0,
        },
        1,
    );
    every_variant(
        "battery_state",
        &v.battery_state,
        |value| match value {
            BatteryState::Normal => 0,
        },
        1,
    );
    every_variant(
        "charge_source",
        &v.charge_source,
        |value| match value {
            ChargeSource::QuickCharge => 0,
        },
        1,
    );
    every_variant(
        "wifi_ap_status",
        &v.wifi_ap_status,
        |value| match value {
            WifiApStatus::Off => 0,
        },
        1,
    );
    every_variant(
        "lte_bandwidth",
        &v.lte_bandwidth,
        |value| match value {
            LteBandwidth::Mhz3 => 0,
            LteBandwidth::Mhz5 => 1,
            LteBandwidth::Mhz10 => 2,
            LteBandwidth::Mhz15 => 3,
            LteBandwidth::Mhz20 => 4,
        },
        5,
    );
    every_variant(
        "router_unavailable_reason",
        &v.router_unavailable_reason,
        |value| match value {
            RouterUnavailableReason::NotConfigured => 0,
            RouterUnavailableReason::Unreachable => 1,
            RouterUnavailableReason::AuthFailed => 2,
            RouterUnavailableReason::IdentityMismatch => 3,
            RouterUnavailableReason::Unsupported => 4,
            RouterUnavailableReason::Malformed => 5,
        },
        6,
    );
    every_variant(
        "router_reading",
        &v.router_reading,
        |value| match value {
            RouterReading::Available { .. } => 0,
            RouterReading::Unavailable { .. } => 1,
        },
        2,
    );
    every_variant(
        "band",
        &v.band,
        |value| match value {
            Band::Lte(_) => 0,
            Band::Nr(_) => 1,
        },
        2,
    );
    every_variant(
        "active_now",
        &v.active_now,
        |value| match value {
            ActiveNow::Active => 0,
            ActiveNow::Idle => 1,
            ActiveNow::Unknown => 2,
        },
        3,
    );
    every_kind(
        "forecast_error_kind",
        &v.forecast_error_kind,
        ForecastErrorKind::ALL,
    );
    every_kind("usage_error_kind", &v.usage_error_kind, UsageErrorKind::ALL);
    every_variant(
        "user_status",
        &v.user_status,
        |value| match value {
            UserStatus::Active => 0,
            UserStatus::Suspended { .. } => 1,
            UserStatus::RevokePending => 2,
            UserStatus::Revoked => 3,
        },
        4,
    );
    every_variant(
        "suspend_reason",
        &v.suspend_reason,
        |value| match value {
            SuspendReason::Operator => 0,
            SuspendReason::QuotaExceeded { .. } => 1,
            SuspendReason::Expired => 2,
            SuspendReason::AbuseReview => 3,
        },
        4,
    );
    every_kind("lifecycle_stage", &v.lifecycle_stage, LifecycleStage::ALL);
    every_variant(
        "node_role",
        &v.node_role,
        |value| match value {
            NodeRole::Primary => 0,
            NodeRole::Standby => 1,
        },
        2,
    );
    every_variant(
        "pairing",
        &v.pairing,
        |value| match value {
            Pairing::Paired => 0,
            Pairing::Unpaired => 1,
        },
        2,
    );
    every_variant(
        "probe_protocol",
        &v.probe_protocol,
        |value| match value {
            ProbeProtocol::Reality => 0,
            ProbeProtocol::Hy2 => 1,
        },
        2,
    );
    every_kind(
        "violation",
        &v.violation.iter().map(Violation::kind).collect::<Vec<_>>(),
        ViolationKind::ALL,
    );
    every_kind("violation_kind", &v.violation_kind, ViolationKind::ALL);
    every_variant(
        "stop_policy",
        &v.stop_policy,
        |value| match value {
            StopPolicy::HardStop { .. } => 0,
            StopPolicy::AcceptDeprioritisation => 1,
        },
        2,
    );
    every_variant(
        "plan_line_kind",
        &v.plan_line_kind,
        |value| match value {
            PlanLineKind::FairUse => 0,
            PlanLineKind::Allowance => 1,
        },
        2,
    );
    every_kind("gate_state", &v.gate_state, GateState::ALL);
    every_kind("shutdown_reason", &v.shutdown_reason, ShutdownReason::ALL);
    every_kind(
        "watch_error",
        &v.watch_error
            .iter()
            .map(WatchError::kind)
            .collect::<Vec<_>>(),
        mooring_agent_proto::WatchErrorKind::ALL,
    );
    every_variant(
        "engine_run",
        &v.engine_run,
        |value| match value {
            EngineRun::Inactive => 0,
            EngineRun::Active { .. } => 1,
        },
        2,
    );
    every_kind("inbound", &v.inbound, Inbound::ALL);
}

/// Every object of every status fixture, and of the variants document,
/// refuses an unknown key: each type keeps `deny_unknown_fields` (or
/// checks itself), so a field the app does not know is never dropped.
#[test]
fn every_object_of_every_status_document_denies_unknown_keys() {
    let mut counts = Vec::new();
    for bytes in [
        include_bytes!("../../../../contract/status-fixtures/serving.json").as_slice(),
        include_bytes!("../../../../contract/status-fixtures/degraded.json"),
        include_bytes!("../../../../contract/status-fixtures/down.json"),
    ] {
        counts.push(each_object_denies_unknown_keys::<MacStatusV1>(bytes));
    }
    counts.push(each_object_denies_unknown_keys::<Variants>(FIXTURE));
    // Each document is many objects deep; a count this low would mean the
    // walk stopped at the top.
    assert!(counts.iter().all(|&count| count > 50), "{counts:?}");
}

/// Decodes `bytes` as `T`, then adds an unknown key to each of its JSON
/// objects in turn and requires the decode to fail. Returns the number of
/// objects tried.
fn each_object_denies_unknown_keys<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> usize {
    let json: Value = serde_json::from_slice(bytes).unwrap();
    assert!(serde_json::from_value::<T>(json.clone()).is_ok());
    let mut pointers = Vec::new();
    object_pointers(&json, String::new(), &mut pointers);
    for pointer in &pointers {
        let mut mutated = json.clone();
        mutated
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("zz_unknown".into(), Value::Bool(true));
        assert!(
            serde_json::from_value::<T>(mutated).is_err(),
            "accepted an unknown key at {pointer:?}"
        );
    }
    pointers.len()
}

/// The JSON pointer of every object in `value`.
fn object_pointers(value: &Value, pointer: String, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            out.push(pointer.clone());
            for (key, child) in map {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                object_pointers(child, format!("{pointer}/{escaped}"), out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                object_pointers(child, format!("{pointer}/{index}"), out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
