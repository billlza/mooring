// SPDX-License-Identifier: GPL-3.0-or-later

//! The status scenarios behind `contract/status-fixtures/`: each is built
//! from a fixture deployment by running the core's own logic (usage
//! aggregation, activity, the SIM forecast, the capacity monitor, quota and
//! expiry evaluation, the alert machine and the foreign-network check) on
//! inputs shaped like the daemon's, so the fixtures are what the daemon
//! would emit rather than hand-written JSON.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::num::NonZeroU64;

use mooring_agent_proto::{
    EgressViolationHold, GateState, Generation, Holds, Inbound, Resolution, StatusV1, WatchError,
};
use mooring_daemon_core::alert::{AlertCondition, AlertMachine, AlertTiming, OpenAlert};
use mooring_daemon_core::capacity::{
    CapacityMonitor, CapacitySample, CapacityStatus, CapacityThresholds, RttSample,
};
use mooring_daemon_core::forecast::{Crossing, DailySimBytes, SimForecast, SimThreshold};
use mooring_daemon_core::network::{
    Exemptions, InterfaceObservation, IpFamily, NetworkSnapshot, foreign_networks,
};
use mooring_daemon_core::policy::{
    ExpiryState, QuotaState, automatic_quota, effective_quota, evaluate, user_alerts,
};
use mooring_daemon_core::router::{
    Band, BandNumber, Battery, BatteryPercent, BatteryState, CarrierName, Celsius, ChargeSource,
    DataService, FirmwareVersion, LteBandwidth, LteCarrier, LteCarriers, LteSignal, Mcc, Mnc,
    NetworkService, NrSignal, Plmn, PowerState, Radio, RadioState, RouterPower, RouterReading,
    RouterSettings, RouterStatus, RouterStatusParts, RouterUnavailableReason, RouterWifi, Rsrp,
    Rsrq, Rssi, Sinr, ThermalState, WebAppVersion, WifiApStatus, WwanCounters,
};
use mooring_daemon_core::status::{
    AgentUnreachable, CarrierCheck, DegradedReason, DownReason, EgressFacts, EngineExit,
    EngineProcess, ExitSection, ExitState, ForecastView, InChainOutcome, InChainResult, Latch,
    LinkState, MacEngines, MeterAccuracy, NodeAgentState, NodeReport, NodeRow, PowerSource,
    PowerStatus, ProbeStage, ProcessEnd, ProtocolVerdicts, SimMeterStatus, UsageView, UserRow,
};
use mooring_daemon_core::usage::{
    LedgerEnd, LedgerStart, LifetimeBase, NodeLedger, UsageAccuracy, activity, aggregate,
};
use mooring_daemon_core::{BillingCycle, MacStatusParts, MacStatusV1};
use mooring_fixtures::Fixture;
use mooring_model::exit::ProbeProtocol;
use mooring_model::ids::LocalLabel;
use mooring_model::iface::{BsdName, MacAddr};
use mooring_model::node::NodeLifecycle;
use mooring_model::user::{QuotaAction, SuspendReason, UserPolicy, UserQuota, WarnPercent};
use mooring_model::verdict::Violation;
use mooring_model::{
    Deployment, NodeId, Pairing, PublicAlias, Sha256Digest, UnixTime, UplinkBaseline, UserId,
};

use crate::support::{
    GB, GRAMMAR_SHAPED_LABEL, HOUR, MINUTE, NodeStatus, applied, at, before, daily, date, email,
    node, polled, probe, series, wire,
};

/// A scenario's name (its fixture file's stem) and its status.
pub(crate) fn all() -> Vec<(&'static str, MacStatusV1)> {
    vec![
        ("serving", serving()),
        ("degraded", degraded()),
        ("down", down()),
    ]
}

/// Everything a scenario varies; [`assemble`] runs the core's logic on it.
struct Inputs {
    deployment: Deployment,
    at: UnixTime,
    exit: ExitSection,
    sim_daily: Vec<DailySimBytes>,
    sim_accuracy: MeterAccuracy,
    router: RouterReading,
    capacity: Option<CapacityStatus>,
    ledgers: Vec<NodeLedger>,
    through: UnixTime,
    statuses: BTreeMap<NodeId, StatusV1>,
    unreachable: BTreeMap<NodeId, NodeAgentState>,
    verdicts: BTreeMap<NodeId, ProtocolVerdicts>,
    pending_apply: BTreeMap<NodeId, UnixTime>,
    alerts: Vec<OpenAlert>,
}

fn assemble(inputs: Inputs) -> MacStatusV1 {
    let deployment = &inputs.deployment;
    let sim = &deployment.exit().sim;
    let users = deployment.users();
    let used: u64 = inputs.sim_daily.iter().map(|day| day.bytes).sum();
    let forecast = match SimForecast::project(sim, inputs.at, &inputs.sim_daily) {
        Ok(forecast) => ForecastView::Projected(forecast),
        Err(error) => ForecastView::Unavailable {
            reason: error.kind(),
        },
    };
    let report = aggregate(deployment, &inputs.ledgers, inputs.through);
    let activity = activity(users, &inputs.statuses, inputs.at).unwrap();
    let usage = match &report {
        Ok(report) => UsageView::Report {
            periods: report.periods,
        },
        Err(error) => UsageView::Unavailable {
            reason: error.kind(),
        },
    };
    let automatic = automatic_quota(deployment, inputs.at).unwrap();
    let rows = users
        .iter()
        .map(|(id, user)| {
            let usage = report.as_ref().ok().map(|report| report.users[id].clone());
            let quota = effective_quota(user, automatic);
            let quota = match &usage {
                Some(usage) => QuotaState::of(quota, usage.cycle_served_bytes()),
                None => QuotaState::without_usage(quota),
            };
            (
                id.clone(),
                UserRow {
                    alias: user.alias.clone(),
                    status: user.status,
                    nodes: user.per_node.keys().cloned().collect(),
                    activity: activity[id].clone(),
                    usage,
                    quota,
                    expiry: ExpiryState::of(&user.policy, inputs.at),
                    accuracy: UsageAccuracy::of(user),
                },
            )
        })
        .collect();
    let nodes = deployment
        .nodes()
        .iter()
        .map(|(id, node)| {
            let agent = match inputs.statuses.get(id) {
                Some(status) => NodeAgentState::Reported(Box::new(NodeReport::of(
                    UnixTime::from_secs(status.now.as_secs() + 1),
                    status,
                ))),
                None => inputs
                    .unreachable
                    .get(id)
                    .cloned()
                    .unwrap_or(NodeAgentState::NotPolled),
            };
            (
                id.clone(),
                NodeRow {
                    role: node.role,
                    stage: node.lifecycle.stage(),
                    current_generation: deployment.config_generation(),
                    pending_apply_since: inputs.pending_apply.get(id).copied(),
                    verdicts: inputs
                        .verdicts
                        .get(id)
                        .copied()
                        .unwrap_or(ProtocolVerdicts {
                            reality: None,
                            hy2: None,
                        }),
                    agent,
                },
            )
        })
        .collect();
    MacStatusV1::new(MacStatusParts {
        at: inputs.at,
        exit: inputs.exit,
        sim: SimMeterStatus {
            cycle: BillingCycle::of_instant(sim.bill_day(), inputs.at).unwrap(),
            // The SIM is near-symmetric: what users download arrives and
            // leaves again through the tunnel.
            rx_bytes: used - used * 47 / 100,
            tx_bytes: used * 47 / 100,
            accuracy: inputs.sim_accuracy,
            thresholds: sim.thresholds(),
            forecast,
        },
        router: inputs.router,
        capacity: inputs.capacity,
        usage,
        users: rows,
        nodes,
        alerts: inputs.alerts,
    })
    .unwrap()
}

fn egress() -> EgressFacts {
    EgressFacts {
        interface: BsdName::parse("en8").unwrap(),
        lladdr: MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
        ipv4: Ipv4Addr::new(192, 168, 1, 20),
        link: LinkState {
            up: true,
            speed_mbps: Some(2500),
        },
    }
}

/// The exit Mac as designed, which the foreign-network check passes.
fn clean_network() -> BTreeSet<mooring_daemon_core::ForeignNetworkFinding> {
    let name = |text| BsdName::parse(text).unwrap();
    let snapshot = NetworkSnapshot {
        interfaces: BTreeMap::from([
            (
                name("lo0"),
                InterfaceObservation {
                    ipv4: BTreeSet::from([Ipv4Addr::LOCALHOST]),
                    ..InterfaceObservation::default()
                },
            ),
            (
                name("en8"),
                InterfaceObservation {
                    ipv4: BTreeSet::from([Ipv4Addr::new(192, 168, 1, 20)]),
                    ..InterfaceObservation::default()
                },
            ),
            (name("en0"), InterfaceObservation::default()),
        ]),
        default_routes: BTreeSet::from([(IpFamily::V4, name("en8"))]),
    };
    foreign_networks(
        &snapshot,
        &Exemptions {
            egress: name("en8"),
            tunnels: BTreeSet::new(),
        },
    )
}

fn engine(pid: Option<u32>, restarts: u32, last_exit: Option<EngineExit>) -> EngineProcess {
    EngineProcess {
        pid,
        restarts,
        last_exit,
    }
}

fn verified(when: UnixTime, latency_ms: u32) -> Option<InChainResult> {
    Some(InChainResult {
        at: when,
        outcome: InChainOutcome::Verified,
        latency_ms: Some(latency_ms),
    })
}

fn baseline() -> UplinkBaseline {
    UplinkBaseline::new(5_200_000, 16_100_000, at("2026-09-24", 18 * HOUR)).unwrap()
}

/// Feeds the monitor one sample a minute over `minutes`, ending at `end`.
fn capacity(
    end: UnixTime,
    minutes: u64,
    tx_bps: u64,
    rx_bps: u64,
    rtt: RttSample,
) -> CapacityStatus {
    let mut monitor = CapacityMonitor::new(CapacityThresholds::DEFAULT, Some(baseline()));
    let mut latest = None;
    for minute in (0..=minutes).rev() {
        let sample = CapacitySample {
            at: before(end, minute * MINUTE),
            tx_bps,
            rx_bps,
            rtt: Some(rtt),
        };
        latest = Some(monitor.observe(sample).unwrap());
    }
    latest.unwrap()
}

/// The M7's reading in a scenario: the M2a firmware and settings (Wi-Fi,
/// offload, UPnP, Analytics and Insight off), on the battery the operator
/// keeps installed, with the web app version `web_app` and the SMARTY SIM.
/// With that SIM the M7 reported no service provider name and no web app
/// version (2026-10-16): the degraded scenario carries both as `None`, the
/// serving one M2a's version. The SIM is on MCC 234 MNC 20, as the
/// operator reported, with a network name not yet recorded *(inference:
/// `SMARTY`)*.
fn router(
    polled_at: UnixTime,
    web_app: Option<&str>,
    radio: RadioState,
    temperature: i16,
    charge: u8,
) -> RouterReading {
    let status = RouterStatus::new(RouterStatusParts {
        firmware: FirmwareVersion::parse("NTGX75_10.04.43.01").unwrap(),
        web_app: web_app.map(|version| WebAppVersion::parse(version).unwrap()),
        uptime_secs: 523_014,
        temperature_c: Celsius::new(temperature).unwrap(),
        thermal: ThermalState::Normal,
        power: RouterPower {
            state: PowerState::Online,
            battery: Battery {
                charge: BatteryPercent::new(charge).unwrap(),
                state: BatteryState::Normal,
                charging: false,
                source: ChargeSource::QuickCharge,
                temperature_c: Celsius::new(33).unwrap(),
            },
        },
        sim_spn: None,
        radio,
        counters: WwanCounters {
            rx_bytes: 81_000_000_000,
            tx_bytes: 16_412_311_040,
        },
        wifi: RouterWifi {
            enabled: false,
            main: WifiApStatus::Off,
            guest: WifiApStatus::Off,
            aux: WifiApStatus::Off,
            clients: 0,
        },
        settings: RouterSettings {
            wifi_offload: false,
            ethernet_offload: false,
            upnp: false,
            analytics: false,
            insight_active: false,
        },
        unread_sms: 0,
    })
    .unwrap();
    RouterReading::Available {
        polled_at,
        status: Box::new(status),
    }
}

/// Attached on LTE band `band` (the M7's one carrier, of `dl_bandwidth`),
/// with the LTE readings given in tenths and no NR reading, as the M7
/// reported in M2a while claiming a 5G data service. The service types the
/// M7 reported with the SMARTY SIM (`LteService`, and `4G` or `4GPLUS`,
/// 2026-10-16) are not yet values the status holds, so the scenarios keep
/// M2a's.
fn attached(band: u16, dl_bandwidth: LteBandwidth, lte: [Option<i16>; 4]) -> RadioState {
    let number = BandNumber::new(band).unwrap();
    RadioState::Attached(Radio {
        network_service: NetworkService::Nr5g,
        data_service: DataService::NrSub6,
        band: Band::Lte(number),
        lte_carriers: Some(
            LteCarriers::new(
                LteCarrier {
                    band: number,
                    dl_bandwidth,
                },
                Vec::new(),
            )
            .unwrap(),
        ),
        ca_secondary_count: 0,
        lte: LteSignal {
            rsrp: lte[0].map(|tenths| Rsrp::from_tenths(tenths).unwrap()),
            rsrq: lte[1].map(|tenths| Rsrq::from_tenths(tenths).unwrap()),
            sinr: lte[2].map(|tenths| Sinr::from_tenths(tenths).unwrap()),
            rssi: lte[3].map(|tenths| Rssi::from_tenths(tenths).unwrap()),
        },
        nr: NrSignal {
            rsrp: None,
            rsrq: None,
            sinr: None,
        },
        network: CarrierName::parse("SMARTY").unwrap(),
        plmn: Plmn {
            mcc: Mcc::parse("234").unwrap(),
            mnc: Mnc::parse("20").unwrap(),
        },
        session_secs: 522_950,
    })
}

fn ledger(
    node_id: &str,
    base: Vec<(mooring_agent_proto::StatsEmail, u64, u64)>,
    days: &[(UnixTime, mooring_agent_proto::StatsEmail, u64, u64)],
    hours: &[(UnixTime, mooring_agent_proto::StatsEmail, u64, u64)],
    covered_to: UnixTime,
) -> NodeLedger {
    NodeLedger::new(
        node(node_id),
        LedgerStart::Continued(LifetimeBase {
            as_of: at("2026-09-01", 0),
            totals: base
                .into_iter()
                .map(|(email, uplink, downlink)| {
                    (email, mooring_agent_proto::Traffic { uplink, downlink })
                })
                .collect(),
        }),
        vec![
            series(
                at("2026-09-01", 0),
                at("2026-10-06", 0),
                Resolution::Day,
                days,
            ),
            series(at("2026-10-06", 0), covered_to, Resolution::Hour, hours),
        ],
        LedgerEnd::Open,
    )
    .unwrap()
}

fn fixture_users(fixture: &Fixture) -> Vec<UserId> {
    fixture.deployment.users().keys().cloned().collect()
}

/// Two nodes and three users on an ordinary morning: serving, nothing open.
fn serving() -> MacStatusV1 {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let ids = fixture_users(&fixture);
    let (u1, u2, u3) = (&ids[0], &ids[1], &ids[2]);
    let now = at("2026-10-08", 10 * HOUR + 30);
    let through = at("2026-10-08", 10 * HOUR);
    let (lon1, ams1) = (node("lon1"), node("ams1"));
    let lon1_status = NodeStatus {
        now: before(now, 95),
        applied: applied(&fixture.deployment.nodes()[&lon1]),
        last_active: vec![
            (email(u1, Inbound::Reality), polled(before(now, 95), 0)),
            (email(u1, Inbound::Hy2), polled(before(now, 95), 47)),
            (email(u2, Inbound::Reality), polled(before(now, 95), 1_240)),
            (email(u3, Inbound::Hy2), polled(before(now, 95), 0)),
            (probe(Inbound::Reality), polled(before(now, 95), 3)),
            (probe(Inbound::Hy2), polled(before(now, 95), 3)),
        ],
        conditions: Vec::new(),
        gate: GateState::Open,
        holds: Holds::NONE,
        reboot_required: false,
        handshake_age_secs: 19,
    }
    .build();
    let ams1_status = NodeStatus {
        now: before(now, 92),
        applied: applied(&fixture.deployment.nodes()[&ams1]),
        last_active: vec![
            (
                email(u2, Inbound::Hy2),
                at("2026-09-20", 12 * HOUR + 7 * MINUTE),
            ),
            (probe(Inbound::Reality), polled(before(now, 92), 3)),
            (probe(Inbound::Hy2), polled(before(now, 92), 3)),
        ],
        conditions: Vec::new(),
        gate: GateState::Open,
        holds: Holds::NONE,
        reboot_required: false,
        handshake_age_secs: 19,
    }
    .build();
    let ledgers = vec![
        ledger(
            "lon1",
            vec![
                (email(u1, Inbound::Reality), 2_310_455_808, 41_206_177_792),
                (email(u1, Inbound::Hy2), 310_378_496, 5_212_811_264),
                (email(u2, Inbound::Reality), 901_775_360, 12_431_683_584),
                (probe(Inbound::Reality), 40_108_032, 41_009_152),
            ],
            &[
                (
                    at("2026-09-03", 0),
                    email(u1, Inbound::Reality),
                    96_468_992,
                    1_874_853_888,
                ),
                (
                    at("2026-09-15", 0),
                    email(u2, Inbound::Hy2),
                    23_068_672,
                    402_653_184,
                ),
                (
                    at("2026-10-02", 0),
                    email(u1, Inbound::Reality),
                    131_072_000,
                    2_684_354_560,
                ),
                (
                    at("2026-10-02", 0),
                    email(u2, Inbound::Reality),
                    41_943_040,
                    768_606_208,
                ),
                (
                    at("2026-10-02", 0),
                    probe(Inbound::Reality),
                    1_310_720,
                    1_376_256,
                ),
                (
                    at("2026-10-04", 0),
                    email(u3, Inbound::Hy2),
                    62_914_560,
                    1_258_291_200,
                ),
            ],
            &[
                (
                    at("2026-10-07", 13 * HOUR),
                    email(u1, Inbound::Reality),
                    18_874_368,
                    402_653_184,
                ),
                (
                    at("2026-10-07", 13 * HOUR),
                    email(u1, Inbound::Hy2),
                    2_097_152,
                    31_457_280,
                ),
                (
                    at("2026-10-07", 14 * HOUR),
                    email(u2, Inbound::Reality),
                    9_437_184,
                    167_772_160,
                ),
                (
                    at("2026-10-08", 8 * HOUR),
                    email(u1, Inbound::Reality),
                    12_582_912,
                    268_435_456,
                ),
                (
                    at("2026-10-08", 9 * HOUR),
                    email(u1, Inbound::Reality),
                    7_340_032,
                    146_800_640,
                ),
                (
                    at("2026-10-08", 9 * HOUR),
                    email(u3, Inbound::Hy2),
                    3_145_728,
                    52_428_800,
                ),
                (
                    at("2026-10-08", 9 * HOUR),
                    probe(Inbound::Reality),
                    65_536,
                    69_632,
                ),
            ],
            through,
        ),
        ledger(
            "ams1",
            Vec::new(),
            &[(
                at("2026-09-20", 0),
                email(u2, Inbound::Hy2),
                5_242_880,
                94_371_840,
            )],
            &[(
                at("2026-10-08", 9 * HOUR),
                probe(Inbound::Hy2),
                65_536,
                69_632,
            )],
            through,
        ),
    ];
    let exit = ExitSection {
        state: ExitState::Serving {
            ip: Ipv4Addr::new(31, 120, 4, 17),
            verified_at: before(now, 212),
        },
        since: at("2026-10-08", 6 * HOUR + 12 * MINUTE),
        latches: Vec::new(),
        egress: Some(egress()),
        carrier_check: Some(CarrierCheck {
            egress_ip: Ipv4Addr::new(31, 120, 4, 17),
            in_carrier_prefixes: true,
            pairing: Pairing::Paired,
            checked_at: before(now, 14),
        }),
        engines: MacEngines {
            exit: engine(Some(4123), 0, None),
            probe: engine(
                Some(4127),
                1,
                Some(EngineExit {
                    at: at("2026-10-08", 6 * HOUR + 11 * MINUTE),
                    end: ProcessEnd::Exited { code: 1 },
                }),
            ),
        },
        power: PowerStatus {
            source: PowerSource::Ac,
            assertions_held: true,
            last_sleep: Some(at("2026-10-08", HOUR + 3 * MINUTE)),
            last_wake: Some(at("2026-10-08", 6 * HOUR + 11 * MINUTE)),
            last_drain: Some(mooring_daemon_core::status::DrainRecord {
                at: at("2026-10-08", HOUR + 3 * MINUTE),
                outcome: mooring_daemon_core::status::DrainOutcome::Completed,
            }),
        },
        foreign_networks: clean_network(),
    };
    assemble(Inputs {
        exit,
        sim_daily: daily(
            "2026-10-01",
            &[
                1_932_735_283,
                3_543_348_019,
                1_181_116_006,
                3_006_477_107,
                1_288_490_188,
                1_073_741_824,
                1_610_612_736,
                933_232_640,
            ],
        ),
        sim_accuracy: MeterAccuracy::Exact,
        router: router(
            before(now, 44),
            Some("M7_GENERIC_v07.01.81.00"),
            attached(
                3,
                LteBandwidth::Mhz20,
                [Some(-990), Some(-110), Some(120), Some(-700)],
            ),
            41,
            100,
        ),
        capacity: Some(capacity(
            before(now, 20),
            5,
            3_211_264,
            9_633_792,
            RttSample {
                loaded_ms: 61,
                idle_p10_ms: 48,
            },
        )),
        ledgers,
        through,
        statuses: BTreeMap::from([(lon1.clone(), lon1_status), (ams1.clone(), ams1_status)]),
        unreachable: BTreeMap::new(),
        verdicts: BTreeMap::from([
            (
                lon1,
                ProtocolVerdicts {
                    reality: verified(before(now, 212), 186),
                    hy2: verified(before(now, 210), 142),
                },
            ),
            (
                ams1,
                ProtocolVerdicts {
                    reality: verified(before(now, 208), 205),
                    hy2: verified(before(now, 206), 171),
                },
            ),
        ]),
        pending_apply: BTreeMap::new(),
        alerts: Vec::new(),
        deployment: fixture.deployment,
        at: now,
    })
}

fn quota(gb: u64, warn: u8, action: QuotaAction) -> UserQuota {
    UserQuota {
        cycle_served_bytes: NonZeroU64::new(gb * GB).unwrap(),
        warn_percent: WarnPercent::new(warn).unwrap(),
        action,
    }
}

/// Twenty users on a busy China evening with the Mac on battery: degraded,
/// one node unreachable, the uplink saturated, the SIM forecast to pass its
/// warning tomorrow, and warnings open.
///
/// The deployment runs without a cap on active users (the 20-user
/// fixture's `CapacityPolicy::UNLIMITED`), so 18 users are active: the
/// scenario exercises the app at the scale the model allows, beyond the
/// pilot's cap of 5 (decision F3), which the operator may raise. With 18
/// users on 300 GB the SIM runs short within the cycle, which is what the
/// forecast alert says.
fn degraded() -> MacStatusV1 {
    let fixture = mooring_fixtures::two_nodes_twenty_users().unwrap();
    let now = at("2026-10-08", 13 * HOUR + 30);
    let through = at("2026-10-08", 12 * HOUR);
    let (lon1, ams1) = (node("lon1"), node("ams1"));
    let mut parts = fixture.deployment.clone().into_parts();
    for (index, user) in parts.users.iter_mut().enumerate() {
        if index == 0 {
            // A label shaped like a report user id and a node name, so the
            // label scans could fail if a label ever reached the status.
            user.label = LocalLabel::parse(GRAMMAR_SHAPED_LABEL).unwrap();
        }
        if index < 6 {
            let bits = (0x5f1e_0000 + 7919 * index as u64).to_be_bytes();
            user.alias = Some(PublicAlias::from_random_bytes([
                bits[3], bits[4], bits[5], bits[6], bits[7],
            ]));
        }
        match index {
            1 => user.policy.quota = Some(quota(40, 80, QuotaAction::Suspend)),
            2 => user.policy.quota = Some(quota(30, 80, QuotaAction::Warn)),
            3 => {
                user.policy.quota = Some(quota(20, 80, QuotaAction::Suspend));
                user.suspend(
                    SuspendReason::QuotaExceeded {
                        cycle_start: date("2026-10-01"),
                    },
                    at("2026-10-06", 19 * HOUR + 15 * MINUTE),
                )
                .unwrap();
            }
            4 => user.policy.expires_at = Some(at("2026-10-10", 12 * HOUR)),
            5 => user
                .suspend(SuspendReason::Operator, at("2026-10-02", 9 * HOUR))
                .unwrap(),
            _ => {}
        }
    }
    // Suspending users changed the configuration: lon1 has applied the new
    // generation, and ams1 has not.
    parts.config_generation = parts.config_generation.next().unwrap();
    for entry in &mut parts.nodes {
        if entry.id == lon1
            && let NodeLifecycle::Applied { applied, .. } = &mut entry.lifecycle
        {
            applied.config_generation = parts.config_generation;
            applied.digest = Sha256Digest::of(b"lon1 bundle at generation 2");
        }
    }
    let deployment = Deployment::try_from(parts).unwrap();
    let ids: Vec<UserId> = deployment.users().keys().cloned().collect();
    let mut hours = Vec::new();
    // Every active user is busy in the China evening (12:00-14:00 UTC).
    for (index, id) in ids.iter().enumerate() {
        if index == 3 || index == 5 {
            continue;
        }
        let weight = (index as u64 % 4) + 1;
        hours.push((
            at("2026-10-08", 11 * HOUR),
            email(id, Inbound::Reality),
            9_437_184 * weight,
            188_743_680 * weight,
        ));
        if index % 3 == 0 {
            hours.push((
                at("2026-10-08", 11 * HOUR),
                email(id, Inbound::Hy2),
                4_194_304 * weight,
                83_886_080 * weight,
            ));
        }
    }
    let mut days = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        let weight = (index as u64 % 5) + 1;
        days.push((
            at("2026-10-03", 0),
            email(id, Inbound::Reality),
            10_485_760 * weight,
            209_715_200 * weight,
        ));
    }
    // Users 2 and 3 have used most of their quotas this cycle, and user 4
    // passed theirs before being suspended.
    days.push((
        at("2026-10-05", 0),
        email(&ids[3], Inbound::Reality),
        838_860_800,
        20_132_659_200,
    ));
    days.push((
        at("2026-10-04", 0),
        email(&ids[1], Inbound::Reality),
        1_610_612_736,
        31_138_512_896,
    ));
    days.push((
        at("2026-10-04", 0),
        email(&ids[2], Inbound::Hy2),
        1_288_490_188,
        30_064_771_072,
    ));
    let ledgers = vec![
        ledger(
            "lon1",
            Vec::new(),
            &days,
            &hours,
            at("2026-10-08", 13 * HOUR),
        ),
        ledger("ams1", Vec::new(), &[], &[], through),
    ];
    let lon1_status = NodeStatus {
        now: before(now, 61),
        applied: applied(&deployment.nodes()[&lon1]),
        last_active: ids
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 3 && *index != 5)
            .map(|(index, id)| {
                (
                    email(id, Inbound::Reality),
                    polled(before(now, 61), index as u64 % 3),
                )
            })
            .collect(),
        conditions: vec![
            WatchError::ExitFlowCapHit { count: 14 },
            WatchError::RebootPending {
                since: wire(at("2026-10-07", 20 * HOUR + 4 * MINUTE)),
            },
        ],
        gate: GateState::Open,
        holds: Holds::NONE,
        reboot_required: true,
        handshake_age_secs: 7,
    }
    .build();
    let exit = ExitSection {
        state: ExitState::Degraded {
            reasons: mooring_model::collections::NonEmpty::from_parts(
                DegradedReason::NodeProbeFailed {
                    node: ams1.clone(),
                    protocol: ProbeProtocol::Hy2,
                    stage: ProbeStage::Connect,
                },
                vec![
                    DegradedReason::WatchStale { node: ams1.clone() },
                    DegradedReason::OnBattery,
                ],
            ),
        },
        since: before(now, 26 * MINUTE),
        latches: Vec::new(),
        egress: Some(egress()),
        carrier_check: Some(CarrierCheck {
            egress_ip: Ipv4Addr::new(31, 121, 18, 203),
            in_carrier_prefixes: true,
            pairing: Pairing::Paired,
            checked_at: before(now, 9),
        }),
        engines: MacEngines {
            exit: engine(Some(5310), 0, None),
            probe: engine(Some(5318), 0, None),
        },
        power: PowerStatus {
            source: PowerSource::Battery,
            assertions_held: false,
            last_sleep: None,
            last_wake: Some(at("2026-10-07", 22 * HOUR + 40 * MINUTE)),
            last_drain: None,
        },
        foreign_networks: clean_network(),
    };
    // The policy actions the next apply window would take, and the alerts.
    let report = aggregate(&deployment, &ledgers, through).unwrap();
    let actions = evaluate(&deployment, &report.cycle_usage(), now).unwrap();
    let sim_daily = daily(
        "2026-10-01",
        &[
            26_521_830_195,
            28_776_544_256,
            32_319_628_902,
            29_957_646_336,
            30_494_620_877,
            28_132_366_336,
            31_138_512_896,
            16_750_372_454,
        ],
    );
    // The forecast projects the warning for tomorrow and the hard stop
    // three days later; the forecast alert names the first of them.
    let forecast = SimForecast::project(&deployment.exit().sim, now, &sim_daily).unwrap();
    let first = forecast.crossings[0];
    let Crossing::Projected { on } = first.crossing else {
        panic!("the degraded scenario's warning is projected, not reached");
    };
    assert_eq!(
        (first.threshold, on),
        (SimThreshold::Warn, date("2026-10-09"))
    );
    // The alerts as the machine saw them develop: the users' alerts, the
    // SIM forecast, the LTE fallback, the weak signal and the flow cap from
    // two hours ago, saturation from 40 minutes ago, and ams1's silence and
    // the degraded exit from 26.
    let mut early = user_alerts(deployment.users(), &actions);
    early.extend([
        AlertCondition::SimForecastCrossing {
            cycle_start: forecast.cycle.start(),
            threshold: first.threshold,
            on,
        },
        // The scenario's alerts are its inputs, not derived from its
        // reading, which still claims the 5G data service as M2a's did.
        AlertCondition::RouterOnLte,
        AlertCondition::RouterWeakSignal {
            rsrp_dbm_x10: -1125,
        },
        AlertCondition::ExitFlowCapHit {
            node: lon1.clone(),
            count: 14,
        },
    ]);
    let mut saturated = early.clone();
    saturated.push(AlertCondition::CapacitySaturated);
    let mut all = saturated.clone();
    all.push(AlertCondition::NodeUnreachable {
        node: ams1.clone(),
        since: before(now, 26 * MINUTE),
    });
    // The degraded exit's alert names exactly the kinds of its reasons.
    all.extend(exit.state.degraded_alert());
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    for (step, active) in [
        (before(now, 2 * HOUR), &early),
        (before(now, 40 * MINUTE), &saturated),
        (before(now, 26 * MINUTE), &all),
        (now, &all),
    ] {
        machine.step(step, active.clone()).unwrap();
    }
    assemble(Inputs {
        exit,
        sim_daily,
        sim_accuracy: MeterAccuracy::Exact,
        router: router(
            before(now, 51),
            None,
            attached(
                20,
                LteBandwidth::Mhz10,
                [Some(-1125), Some(-145), Some(-15), Some(-810)],
            ),
            47,
            64,
        ),
        capacity: Some(capacity(
            before(now, 12),
            50,
            14_680_064,
            15_728_640,
            RttSample {
                loaded_ms: 410,
                idle_p10_ms: 48,
            },
        )),
        ledgers,
        through,
        statuses: BTreeMap::from([(lon1.clone(), lon1_status)]),
        unreachable: BTreeMap::from([(
            ams1.clone(),
            NodeAgentState::Unreachable {
                since: before(now, 26 * MINUTE),
                cause: AgentUnreachable::Timeout,
            },
        )]),
        verdicts: BTreeMap::from([
            (
                lon1,
                ProtocolVerdicts {
                    reality: verified(before(now, 140), 391),
                    hy2: verified(before(now, 138), 344),
                },
            ),
            (
                ams1.clone(),
                ProtocolVerdicts {
                    reality: verified(before(now, 31 * MINUTE), 402),
                    hy2: Some(InChainResult {
                        at: before(now, 135),
                        outcome: InChainOutcome::Failed {
                            stage: ProbeStage::Connect,
                        },
                        latency_ms: None,
                    }),
                },
            ),
        ]),
        pending_apply: BTreeMap::from([(ams1, at("2026-10-08", 9 * HOUR + 5 * MINUTE))]),
        alerts: machine.open(),
        deployment,
        at: now,
    })
}

/// One node and one user, minutes after a paired-mode egress mismatch:
/// down and latched, the router unreachable, and the meter missing a day.
fn down() -> MacStatusV1 {
    let fixture = mooring_fixtures::one_node_one_user().unwrap();
    let now = at("2026-10-08", 16 * HOUR + 45 * MINUTE);
    let latched_at = before(now, 5 * MINUTE);
    let lon1 = node("lon1");
    let mut parts = fixture.deployment.clone().into_parts();
    parts.users[0].policy = UserPolicy {
        expires_at: None,
        quota: Some(quota(50, 80, QuotaAction::Suspend)),
    };
    let deployment = Deployment::try_from(parts).unwrap();
    let id = deployment.users().keys().next().unwrap().clone();
    let violation = Violation::EgressMismatch {
        d1: Ipv4Addr::new(31, 120, 4, 17),
        d2: Ipv4Addr::new(31, 120, 4, 17),
        observed: Ipv4Addr::new(81, 2, 69, 142),
    };
    let lon1_status = NodeStatus {
        now: before(now, 70),
        applied: applied(&deployment.nodes()[&lon1]),
        last_active: vec![(email(&id, Inbound::Reality), before(latched_at, 31))],
        conditions: Vec::new(),
        gate: GateState::Closed,
        holds: Holds {
            mac_drain: None,
            egress_violation: Some(EgressViolationHold {
                at: wire(latched_at),
                generation: Generation::new(1),
            }),
            operator: None,
        },
        reboot_required: false,
        handshake_age_secs: 331,
    }
    .build();
    let exit = ExitSection {
        state: ExitState::Down {
            reason: DownReason::Violation(violation.clone()),
        },
        since: latched_at,
        latches: vec![Latch {
            violation,
            at: latched_at,
        }],
        egress: Some(egress()),
        carrier_check: Some(CarrierCheck {
            egress_ip: Ipv4Addr::new(31, 120, 4, 17),
            in_carrier_prefixes: true,
            pairing: Pairing::Paired,
            checked_at: before(now, 21),
        }),
        engines: MacEngines {
            exit: engine(
                None,
                0,
                Some(EngineExit {
                    at: latched_at,
                    end: ProcessEnd::Signalled { signal: 15 },
                }),
            ),
            probe: engine(Some(6011), 0, None),
        },
        power: PowerStatus {
            source: PowerSource::Ac,
            assertions_held: true,
            last_sleep: None,
            last_wake: None,
            last_drain: None,
        },
        foreign_networks: clean_network(),
    };
    // The latch's alert names exactly the latched violations' kinds.
    let mut machine = AlertMachine::new(AlertTiming::DEFAULT);
    machine
        .step(latched_at, exit.violation_alert().into_iter().collect())
        .unwrap();
    // The meter has no bin for 5 October (the daemon was not running).
    let mut sim_daily = daily(
        "2026-10-01",
        &[
            3_221_225_472,
            2_684_354_560,
            3_489_660_928,
            0,
            2_952_790_016,
            3_758_096_384,
            3_355_443_200,
            2_013_265_920,
        ],
    );
    sim_daily.remove(4);
    assemble(Inputs {
        exit,
        sim_daily,
        sim_accuracy: MeterAccuracy::LowerBound,
        router: RouterReading::Unavailable {
            reason: RouterUnavailableReason::Unreachable,
            last_polled_at: Some(before(now, 6 * MINUTE)),
        },
        capacity: None,
        // The usage store has not pulled since noon.
        ledgers: vec![ledger(
            "lon1",
            Vec::new(),
            &[(
                at("2026-10-02", 0),
                email(&id, Inbound::Reality),
                734_003_200,
                14_680_064_000,
            )],
            &[],
            at("2026-10-08", 12 * HOUR),
        )],
        through: at("2026-10-08", 16 * HOUR),
        statuses: BTreeMap::from([(lon1.clone(), lon1_status)]),
        unreachable: BTreeMap::new(),
        verdicts: BTreeMap::from([(
            lon1,
            ProtocolVerdicts {
                reality: Some(InChainResult {
                    at: latched_at,
                    outcome: InChainOutcome::Violation {
                        kind: mooring_model::verdict::ViolationKind::EgressMismatch,
                    },
                    latency_ms: Some(188),
                }),
                hy2: verified(before(now, 9 * MINUTE), 151),
            },
        )]),
        pending_apply: BTreeMap::new(),
        alerts: machine.open(),
        deployment,
        at: now,
    })
}
