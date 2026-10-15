// SPDX-License-Identifier: GPL-3.0-or-later

//! One sample value of every request, response and error variant. The
//! matches are exhaustive, so adding a variant fails to compile here until
//! it has a sample, which every test that iterates `ALL` then covers.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use mooring_agent_proto::{
    AcceptLocal, AgentError, AgentErrorKind, AgentEvent, AgentEventKind, AppliedGeneration,
    ApplyStep, Arch, BlobLen, BundleFiles, BundleHeader, ClearableHold, EgressViolationHold,
    EngineHealth, EngineRun, EngineSet, EngineState, EngineUser, EventSeq, EventsV1, ExitPhase,
    GateReason, GateState, Generation, Halt, HealthCheck, HelloInfo, Holds, HostFact, HostFacts,
    HostHealth, HostProfileVersion, HttpProbe, HttpStatus, HttpVersion, IfName, Inbound,
    InboundSet, IoOp, KernelIdent, KernelRelease, LineRequest, MacAlertKind, MacDrainHold,
    MacReportParts, MacReportV1, NodeName, OperatorHold, PROTOCOL, PortRange, ReportAccuracy,
    ReportAlert, ReportBand, ReportBandNumber, ReportCapacity, ReportDataService, ReportExit,
    ReportForecast, ReportLteSignal, ReportNrSignal, ReportPlanLine, ReportRadio,
    ReportRadioSystem, ReportRouter, ReportSaturation, ReportSeverity, ReportSim, ReportUsage,
    ReportUser, ReportUserId, ReportUserStatus, Request, RequestKind, Resolution, Response,
    ResponseKind, Role, RollbackCause, SeriesRange, SeriesSpan, Sha256Hex, ShutdownReason,
    SshEd25519Key, SshdDirective, StatusV1, StderrTail, StoredMacReport, SystemdOp, TargetFacts,
    TargetHost, TargetTool, TlsGroup, TlsProbe, TlsSession, TlsVersion, Traffic, TxnStage,
    TxnState, UnitName, UnixTime, UplinkTransfer, UsageBin, UsageMonth, UsageSeriesV1, UsageV1,
    VIEWER_STOP_WAIT_SECS, ValidationTool, WatchConditions, WatchConfig, WatchError,
    WatchErrorKind, WatchTarget,
};

pub(crate) fn digest(byte: u8) -> Sha256Hex {
    Sha256Hex::from_bytes([byte; 32])
}

pub(crate) fn ops_key() -> SshEd25519Key {
    SshEd25519Key::new(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH",
    )
    .unwrap()
}

pub(crate) fn tail(text: &str) -> StderrTail {
    let tail = StderrTail::scrubbed(text.as_bytes(), &[]);
    assert_eq!(tail.as_str(), text, "fixture tails need no escaping");
    tail
}

pub(crate) fn host_facts() -> HostFacts {
    HostFacts {
        uplink: IfName::new("eth0").unwrap(),
        vps4: Ipv4Addr::new(203, 0, 113, 10),
        arch: Arch::Amd64,
        ip_local_port_range: PortRange::new(32768, 60999).unwrap(),
        debian_major: 13,
        kernel: KernelRelease::new("6.12.48+deb13-amd64").unwrap(),
        congestion_control: KernelIdent::new("bbr").unwrap(),
        qdisc: KernelIdent::new("fq").unwrap(),
    }
}

pub(crate) fn bundle_header() -> BundleHeader {
    BundleHeader {
        config_generation: Generation::new(7),
        digest: digest(0xd1),
        host_facts: host_facts(),
        host_profile_version: HostProfileVersion::new(1),
        files: BundleFiles::from_fn(|file| digest(0x10 + file as u8)),
        engines: EngineSet {
            xray: digest(0x21),
            hy2: digest(0x22),
            geoip: digest(0x23),
            geosite: digest(0x24),
        },
    }
}

pub(crate) fn holds() -> Holds {
    Holds {
        mac_drain: Some(MacDrainHold {
            handshake_at_drain: Some(UnixTime::from_secs(1_790_000_000)),
        }),
        egress_violation: None,
        operator: Some(OperatorHold {
            at: UnixTime::from_secs(1_790_000_100),
        }),
    }
}

pub(crate) fn hello_info() -> HelloInfo {
    HelloInfo {
        protocol: PROTOCOL,
        agent_sha: digest(0xa9),
        host_profile_version: HostProfileVersion::new(1),
        host: host_facts(),
        wgexit_accept_local: AcceptLocal::Enabled,
        sshd_mismatches: BTreeSet::from([SshdDirective::MaxAuthTries]),
        halted: None,
        holds: holds(),
        client_ip: Ipv4Addr::new(198, 51, 100, 20),
    }
}

pub(crate) fn status() -> StatusV1 {
    StatusV1 {
        now: UnixTime::from_secs(1_790_000_200),
        watch_at: UnixTime::from_secs(1_790_000_197),
        gate: GateState::Closed,
        holds: Holds {
            egress_violation: Some(EgressViolationHold {
                at: UnixTime::from_secs(1_790_000_150),
                generation: Generation::new(7),
            }),
            ..Holds::NONE
        },
        halted: Some(Halt {
            at: UnixTime::from_secs(1_790_000_160),
            reason: ShutdownReason::EgressIsNodeAddress,
        }),
        latest_handshake: Some(UnixTime::from_secs(1_790_000_190)),
        applied: Some(AppliedGeneration {
            generation: Generation::new(7),
            digest: digest(0xd1),
        }),
        conditions: WatchConditions::new([
            WatchError::TargetDegraded,
            WatchError::ExitFlowCapHit { count: 12 },
            WatchError::MacSilent { since: None },
            WatchError::AccountingCanaryMissing {
                inbounds: InboundSet::of(Inbound::Reality).with(Inbound::Hy2),
            },
        ])
        .unwrap(),
        accounting_at: Some(UnixTime::from_secs(1_790_000_160)),
        last_active: BTreeMap::from([
            (
                "u01@reality".parse().unwrap(),
                UnixTime::from_secs(1_790_000_160),
            ),
            (
                "probe@hy2".parse().unwrap(),
                UnixTime::from_secs(1_790_000_100),
            ),
        ]),
        engines: engine_health(),
        host: host_health(),
        transfer: uplink_transfer(),
    }
}

/// Xray active with its Go heap, Hysteria2 stopped after two restarts.
pub(crate) fn engine_health() -> EngineHealth {
    EngineHealth {
        xray: EngineState {
            restarts: 0,
            run: EngineRun::Active {
                uptime_secs: 86_400,
                go_heap_bytes: Some(21_000_000),
            },
        },
        hy2: EngineState {
            restarts: 2,
            run: EngineRun::Inactive,
        },
    }
}

pub(crate) fn host_health() -> HostHealth {
    HostHealth {
        uptime_secs: 90_000,
        load_milli: 120,
        mem_available_bytes: 600_000_000,
        disk_free_bytes: 18_000_000_000,
        journal_bytes: 150_000_000,
        reboot_required: true,
        last_unattended_upgrade: Some(UnixTime::from_secs(1_789_950_000)),
        ntp_synced: true,
    }
}

pub(crate) fn uplink_transfer() -> UplinkTransfer {
    UplinkTransfer {
        month: UsageMonth::new(2026, 10).unwrap(),
        counted_from: UnixTime::from_secs(1_790_000_000),
        rx_bytes: 40_000_000_000,
        tx_bytes: 41_000_000_000,
        counter_resets: 1,
    }
}

/// Two five-minute bins of a one-hour range.
pub(crate) fn series_range() -> SeriesRange {
    SeriesRange::new(
        UnixTime::from_secs(1_791_417_600),
        UnixTime::from_secs(1_791_421_200),
        Resolution::FiveMin,
    )
    .unwrap()
}

pub(crate) fn usage_series() -> UsageSeriesV1 {
    let bin = |start: u64, entries: &[(&str, u64, u64)]| {
        UsageBin::new(
            UnixTime::from_secs(start),
            entries
                .iter()
                .map(|(email, uplink, downlink)| {
                    (
                        email.parse().unwrap(),
                        Traffic {
                            uplink: *uplink,
                            downlink: *downlink,
                        },
                    )
                })
                .collect(),
        )
        .unwrap()
    };
    UsageSeriesV1::new(
        series_range(),
        vec![
            bin(
                1_791_417_600,
                &[("probe@reality", 900, 1200), ("u01@hy2", 0, 5)],
            ),
            bin(1_791_418_800, &[("u01@reality", 70_000, 3_100_000)]),
        ],
    )
    .unwrap()
}

/// One event of every kind, numbered from 40.
pub(crate) fn events() -> EventsV1 {
    let kinds = [
        AgentEventKind::ConditionRaised {
            condition: WatchError::DiskLow { free: 900_000_000 },
        },
        AgentEventKind::ConditionCleared {
            condition: WatchErrorKind::DiskLow,
        },
        AgentEventKind::GateOpened,
        AgentEventKind::GateClosed,
        AgentEventKind::HoldRecorded {
            hold: GateReason::Operator,
        },
        AgentEventKind::HoldCleared {
            hold: GateReason::MacDrain,
        },
        AgentEventKind::Halted {
            reason: ShutdownReason::Operator,
        },
        AgentEventKind::Resumed {
            generation: Generation::new(7),
        },
        AgentEventKind::Committed {
            generation: Generation::new(8),
        },
        AgentEventKind::EngineRestarted {
            engine: EngineUser::Hy2,
        },
        AgentEventKind::HostBooted,
    ];
    let events = (40..)
        .zip(kinds)
        .map(|(seq, kind)| AgentEvent {
            seq: EventSeq::new(seq),
            at: UnixTime::from_secs(1_790_000_000 + seq),
            kind,
        })
        .collect();
    EventsV1::new(events, EventSeq::new(60)).unwrap()
}

/// The fixture condition of `kind`.
pub(crate) fn watch_error(kind: WatchErrorKind) -> WatchError {
    match kind {
        WatchErrorKind::WgReadFailed => WatchError::WgReadFailed,
        WatchErrorKind::NftFailed => WatchError::NftFailed,
        WatchErrorKind::StatsQueryFailed => WatchError::StatsQueryFailed,
        WatchErrorKind::TargetDegraded => WatchError::TargetDegraded,
        WatchErrorKind::ExitFlowCapHit => WatchError::ExitFlowCapHit { count: 1 },
        WatchErrorKind::StateWrite => WatchError::StateWrite { errno: None },
        WatchErrorKind::MacSilent => WatchError::MacSilent {
            since: Some(UnixTime::from_secs(1_790_000_000)),
        },
        WatchErrorKind::DiskLow => WatchError::DiskLow { free: 900_000_000 },
        WatchErrorKind::ClockUnsynced => WatchError::ClockUnsynced,
        WatchErrorKind::RebootPending => WatchError::RebootPending {
            since: UnixTime::from_secs(1_789_900_000),
        },
        WatchErrorKind::AccountingCanaryMissing => WatchError::AccountingCanaryMissing {
            inbounds: InboundSet::of(Inbound::Reality),
        },
    }
}

/// A report id.
pub(crate) fn report_user(text: &str) -> ReportUserId {
    ReportUserId::new(text).unwrap()
}

/// A node name.
pub(crate) fn node_name(text: &str) -> NodeName {
    NodeName::new(text).unwrap()
}

/// The parts of a degraded exit's report: an attached radio, a building
/// saturation run, usage for an active and a suspended user, and two
/// alerts, one about a node.
pub(crate) fn mac_report_parts() -> MacReportParts {
    let time = UnixTime::from_secs;
    MacReportParts {
        at: time(1_790_000_200),
        exit: ReportExit {
            phase: ExitPhase::Degraded,
            since: time(1_790_000_000),
        },
        sim: ReportSim {
            cycle_starts_at: time(1_789_603_200),
            cycle_ends_at: time(1_792_195_200),
            rx_bytes: 40_000_000_000,
            tx_bytes: 2_500_000_000,
            accuracy: ReportAccuracy::LowerBound,
            warn_bytes: 240_000_000_000,
            hard_stop_bytes: Some(300_000_000_000),
            line: Some(ReportPlanLine::FairUse {
                bytes: 644_245_094_400,
            }),
            forecast: Some(ReportForecast {
                daily_average_bytes: 9_000_000_000,
                projected_bytes: 279_000_000_000,
            }),
        },
        router: ReportRouter::Available {
            polled_at: time(1_790_000_190),
            radio: ReportRadio::Attached {
                service: ReportDataService::NrSub6,
                band: ReportBand {
                    system: ReportRadioSystem::Nr,
                    number: ReportBandNumber::new(78).unwrap(),
                },
                lte: ReportLteSignal {
                    rsrp_tenths: Some(-1005),
                    rsrq_tenths: Some(-110),
                    sinr_tenths: None,
                    rssi_tenths: Some(-650),
                },
                nr: ReportNrSignal {
                    rsrp_tenths: Some(-950),
                    rsrq_tenths: None,
                    sinr_tenths: Some(85),
                },
            },
            temperature_c: 47,
        },
        capacity: Some(ReportCapacity {
            at: time(1_790_000_180),
            tx_bps: 12_000_000,
            rx_bps: 48_000_000,
            saturation: ReportSaturation::Building {
                since: time(1_790_000_100),
            },
        }),
        usage: ReportUsage::Available {
            through: time(1_790_000_160),
        },
        users: BTreeMap::from([
            (
                report_user("fxuseraaab"),
                ReportUser {
                    status: ReportUserStatus::Active,
                    cycle: Some(Traffic {
                        uplink: 300_000_000,
                        downlink: 9_000_000_000,
                    }),
                    last_seen: Some(time(1_790_000_160)),
                },
            ),
            (
                report_user("fxuseraaac"),
                ReportUser {
                    status: ReportUserStatus::Suspended,
                    cycle: Some(Traffic::default()),
                    last_seen: None,
                },
            ),
        ]),
        alerts: vec![
            ReportAlert {
                kind: MacAlertKind::ExitDegraded,
                severity: ReportSeverity::Warning,
                node: None,
                active_since: time(1_790_000_000),
            },
            ReportAlert {
                kind: MacAlertKind::NodeDiskLow,
                severity: ReportSeverity::Critical,
                node: Some(node_name("lon1")),
                active_since: time(1_790_000_050),
            },
        ],
    }
}

pub(crate) fn mac_report() -> MacReportV1 {
    MacReportV1::new(mac_report_parts()).unwrap()
}

pub(crate) fn stored_mac_report() -> StoredMacReport {
    StoredMacReport {
        received_at: UnixTime::from_secs(1_790_000_205),
        report: mac_report(),
    }
}

pub(crate) fn usage() -> UsageV1 {
    UsageV1 {
        month: UsageMonth::new(2026, 10).unwrap(),
        updated_at: UnixTime::from_secs(1_790_000_000),
        traffic: BTreeMap::from([
            (
                "u01@reality".parse().unwrap(),
                Traffic {
                    uplink: 10,
                    downlink: 2000,
                },
            ),
            (
                "probe@hy2".parse().unwrap(),
                Traffic {
                    uplink: 5,
                    downlink: 7,
                },
            ),
        ]),
    }
}

pub(crate) fn target_facts() -> TargetFacts {
    TargetFacts {
        host: TargetHost::new("www.example.com").unwrap(),
        resolved: BTreeSet::from([Ipv4Addr::new(198, 51, 100, 7)]),
        tls: TlsProbe::Completed(TlsSession {
            version: TlsVersion::Tls13,
            group: Some(TlsGroup::X25519_MLKEM768),
            chain_bytes: 4100,
            chain_certs: 2,
            leaf_names: vec![
                "www.example.com".parse().unwrap(),
                "*.example.com".parse().unwrap(),
            ],
            handshake_p95_micros: 1800,
            first_flight_bytes: 5200,
        }),
        http: HttpProbe::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
            redirect: None,
        },
    }
}

pub(crate) fn watch_config() -> WatchConfig {
    WatchConfig {
        keepalive_secs: NonZeroU16::new(10).unwrap(),
        target: WatchTarget {
            host: TargetHost::new("www.example.com").unwrap(),
            ipv4: Ipv4Addr::new(198, 51, 100, 7),
        },
    }
}

/// The fixture request of `kind`.
pub(crate) fn request(kind: RequestKind) -> Request {
    match kind {
        RequestKind::PutBlob => Request::PutBlob {
            sha256: digest(3),
            len: BlobLen::new(5).unwrap(),
        },
        line => Request::Line(line_request(line)),
    }
}

/// The fixture line request of `kind`; `PutBlob` has none.
pub(crate) fn line_request(kind: RequestKind) -> LineRequest {
    match kind {
        RequestKind::PutBlob => panic!("PutBlob is not a line request"),
        RequestKind::Hello => LineRequest::Hello,
        RequestKind::HaveBlobs => LineRequest::HaveBlobs {
            blobs: BTreeSet::from([digest(1), digest(2)]),
        },
        RequestKind::ActivateAgent => LineRequest::ActivateAgent { sha: digest(4) },
        RequestKind::Confirm => LineRequest::Confirm {
            generation: Generation::new(7),
        },
        RequestKind::Bootstrap => LineRequest::Bootstrap {
            expected_agent_sha: digest(4),
            ops_pubkey: ops_key(),
        },
        RequestKind::RevokeBootstrap => LineRequest::RevokeBootstrap,
        RequestKind::Apply => LineRequest::Apply(Box::new(bundle_header())),
        RequestKind::TxnStatus => LineRequest::TxnStatus {
            generation: Generation::new(7),
        },
        RequestKind::Rollback => LineRequest::Rollback,
        RequestKind::Status => LineRequest::Status,
        RequestKind::Usage => LineRequest::Usage {
            month: UsageMonth::new(2026, 10).unwrap(),
        },
        RequestKind::UsageSeries => LineRequest::UsageSeries(series_range()),
        RequestKind::Events => LineRequest::Events {
            since: EventSeq::new(40),
        },
        RequestKind::TargetCheck => LineRequest::TargetCheck {
            host: TargetHost::new("www.example.com").unwrap(),
        },
        RequestKind::GateSet => LineRequest::GateSet {
            reason: GateReason::MacDrain,
        },
        RequestKind::ClearHold => LineRequest::ClearHold {
            hold: ClearableHold::EgressViolation,
        },
        RequestKind::Shutdown => LineRequest::Shutdown {
            reason: ShutdownReason::Operator,
        },
        RequestKind::Resume => LineRequest::Resume {
            config_generation: Generation::new(7),
        },
        RequestKind::PutMacReport => LineRequest::PutMacReport(Box::new(mac_report())),
        RequestKind::MacReport => LineRequest::MacReport,
    }
}

pub(crate) fn response(kind: ResponseKind) -> Response {
    match kind {
        ResponseKind::Hello => Response::Hello(Box::new(hello_info())),
        ResponseKind::Blobs => Response::Blobs {
            present: BTreeSet::from([digest(1)]),
        },
        ResponseKind::BlobStored => Response::BlobStored { sha256: digest(3) },
        ResponseKind::AwaitingConfirm => Response::AwaitingConfirm {
            generation: Generation::new(7),
        },
        ResponseKind::Confirmed => Response::Confirmed {
            generation: Generation::new(7),
        },
        ResponseKind::BootstrapDone => Response::BootstrapDone {
            host_pubkey: ops_key(),
        },
        ResponseKind::BootstrapRevoked => Response::BootstrapRevoked,
        ResponseKind::TxnLaunched => Response::TxnLaunched {
            generation: Generation::new(8),
        },
        ResponseKind::Unchanged => Response::Unchanged {
            generation: Generation::new(7),
        },
        ResponseKind::TxnStatus => Response::TxnStatus {
            generation: Generation::new(8),
            state: TxnState::Failed {
                error: agent_error(AgentErrorKind::RolledBack),
            },
        },
        ResponseKind::Reverted => Response::Reverted {
            generation: Generation::new(8),
        },
        ResponseKind::Status => Response::Status(Box::new(status())),
        ResponseKind::Usage => Response::Usage(Box::new(usage())),
        ResponseKind::UsageSeries => Response::UsageSeries(Box::new(usage_series())),
        ResponseKind::Events => Response::Events(Box::new(events())),
        ResponseKind::TargetFacts => Response::TargetFacts(Box::new(target_facts())),
        ResponseKind::GateClosed => Response::GateClosed { holds: holds() },
        ResponseKind::HoldCleared => Response::HoldCleared { holds: Holds::NONE },
        ResponseKind::Halted => Response::Halted(Halt {
            at: UnixTime::from_secs(1_790_000_160),
            reason: ShutdownReason::Retire,
        }),
        ResponseKind::Resumed => Response::Resumed {
            generation: Generation::new(7),
        },
        ResponseKind::MacReportStored => Response::MacReportStored {
            at: UnixTime::from_secs(1_790_000_200),
        },
        ResponseKind::MacReport => Response::MacReport(Box::new(stored_mac_report())),
    }
}

pub(crate) fn txn_states() -> Vec<TxnState> {
    vec![
        TxnState::Running {
            stage: TxnStage::Validate,
        },
        TxnState::AwaitingConfirm,
        TxnState::Committed,
        TxnState::Reverted,
        TxnState::Failed {
            error: agent_error(AgentErrorKind::RevertedUnconfirmed),
        },
    ]
}

pub(crate) fn agent_error(kind: AgentErrorKind) -> AgentError {
    match kind {
        AgentErrorKind::BlobHash => AgentError::BlobHash {
            expected: digest(3),
            actual: digest(9),
        },
        AgentErrorKind::BlobMissing => AgentError::BlobMissing { sha256: digest(3) },
        AgentErrorKind::BlobTruncated => AgentError::BlobTruncated {
            expected: 5,
            received: 2,
        },
        AgentErrorKind::TrailingInput => AgentError::TrailingInput,
        AgentErrorKind::StageValidation => AgentError::StageValidation {
            tool: ValidationTool::Xray,
            stderr_tail: tail("invalid \"privateKey\": <redacted>"),
        },
        AgentErrorKind::Apt => AgentError::Apt {
            stderr_tail: tail("E: Unable to locate package"),
        },
        AgentErrorKind::Systemd => AgentError::Systemd {
            unit: UnitName::new("mooring-xray.service").unwrap(),
            op: SystemdOp::Restart,
        },
        AgentErrorKind::HealthGate => AgentError::HealthGate {
            failed: HealthCheck::Listeners,
        },
        AgentErrorKind::RolledBack => AgentError::RolledBack {
            generation: Generation::new(8),
            cause: RollbackCause::HealthGate {
                failed: HealthCheck::Listeners,
            },
        },
        AgentErrorKind::RollbackFailed => AgentError::RollbackFailed {
            generation: Generation::new(8),
            cause: RollbackCause::Apply {
                step: ApplyStep::Nftables,
                stderr_tail: tail("Error: syntax error"),
            },
        },
        AgentErrorKind::RevertedUnconfirmed => AgentError::RevertedUnconfirmed {
            generation: Generation::new(8),
        },
        AgentErrorKind::AgentSelfTestFailed => AgentError::AgentSelfTestFailed {
            stderr_tail: tail("self-test: bad profile"),
        },
        AgentErrorKind::AgentShaMismatch => AgentError::AgentShaMismatch {
            expected: digest(4),
            actual: digest(5),
        },
        AgentErrorKind::Busy => AgentError::Busy {
            generation: Generation::new(8),
        },
        AgentErrorKind::GenerationNotNewer => AgentError::GenerationNotNewer {
            current: Generation::new(8),
        },
        AgentErrorKind::GenerationMismatch => AgentError::GenerationMismatch {
            current: Generation::new(8),
        },
        AgentErrorKind::NotAwaitingConfirm => AgentError::NotAwaitingConfirm,
        AgentErrorKind::UnknownTransaction => AgentError::UnknownTransaction {
            generation: Generation::new(9),
        },
        AgentErrorKind::NodeHalted => AgentError::NodeHalted,
        AgentErrorKind::NotHalted => AgentError::NotHalted,
        AgentErrorKind::HostFactsChanged => AgentError::HostFactsChanged {
            field: HostFact::Uplink,
        },
        AgentErrorKind::HostFactUnavailable => AgentError::HostFactUnavailable {
            field: HostFact::Vps4,
        },
        AgentErrorKind::PortPlanConflict => AgentError::PortPlanConflict {
            recorded: PortRange::new(32768, 60999).unwrap(),
            live: PortRange::new(1024, 65535).unwrap(),
        },
        AgentErrorKind::TargetFactsUnavailable => AgentError::TargetFactsUnavailable {
            tool: TargetTool::Curl,
            stderr_tail: tail("curl: (6) Could not resolve host"),
        },
        AgentErrorKind::NoUsageRecorded => AgentError::NoUsageRecorded {
            month: UsageMonth::new(2026, 9).unwrap(),
        },
        AgentErrorKind::SeriesTooLarge => AgentError::SeriesTooLarge { fitting_bins: 30 },
        AgentErrorKind::SeriesNotRecorded => AgentError::SeriesNotRecorded {
            recorded: Some(
                SeriesSpan::new(
                    UnixTime::from_secs(1_791_331_200),
                    UnixTime::from_secs(1_791_420_000),
                    Resolution::FiveMin,
                )
                .unwrap(),
            ),
        },
        AgentErrorKind::MacReportMissing => AgentError::MacReportMissing,
        AgentErrorKind::GateCloseFailed => AgentError::GateCloseFailed {
            stderr_tail: tail("Error: No such file or directory"),
        },
        AgentErrorKind::Io => AgentError::Io {
            op: IoOp::WriteBlob,
            errno: Some(28),
        },
        AgentErrorKind::RoleNotPermitted => AgentError::RoleNotPermitted {
            role: Role::Bootstrap,
            request: RequestKind::Apply,
        },
        AgentErrorKind::GateStopUnconfirmed => AgentError::GateStopUnconfirmed {
            waited_secs: VIEWER_STOP_WAIT_SECS,
        },
        AgentErrorKind::GateReasonNotPermitted => AgentError::GateReasonNotPermitted {
            role: Role::Viewer,
            reason: GateReason::MacDrain,
        },
        AgentErrorKind::UnknownRequest => AgentError::UnknownRequest,
        AgentErrorKind::RequestTooLarge => AgentError::RequestTooLarge,
    }
}
