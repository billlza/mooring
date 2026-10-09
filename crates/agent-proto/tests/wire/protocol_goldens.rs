// SPDX-License-Identifier: GPL-3.0-or-later

//! Byte-exact goldens of the protocol-1 frames outside the frozen core that
//! the console reads: `Status` with its health fields, `UsageSeries` and
//! `Events` (design §11.1, console spec B.7), and the Mac report's
//! `PutMacReport` and `MacReport` (design §15.9). They are not frozen: a
//! later protocol may change them, and the golden then shows the change.
//! Every new condition and every event kind appears in one of them; the two
//! reports between them hold both radio shapes, two saturation shapes, both
//! usage shapes, a plan without a line and one with an allowance (the
//! property tests in `report` cover every shape).
//!
//! As in `frozen_core`, the values are spelled out here rather than taken
//! from shared fixtures, so editing a fixture cannot move a golden.

use std::collections::BTreeMap;

use mooring_agent_proto::{
    AgentEvent, AgentEventKind, AppliedGeneration, EngineHealth, EngineRun, EngineState,
    EngineUser, EventSeq, EventsV1, ExitPhase, GateReason, GateState, Generation, Holds,
    HostHealth, Inbound, InboundSet, LineRequest, MacAlertKind, MacReportParts, MacReportV1,
    NodeName, ReportAccuracy, ReportAlert, ReportBand, ReportBandNumber, ReportCapacity,
    ReportExit, ReportForecast, ReportPlanLine, ReportRadio, ReportRadioAccess, ReportRadioSystem,
    ReportRouter, ReportSaturation, ReportSeverity, ReportSim, ReportUsage, ReportUser,
    ReportUserId, ReportUserStatus, RequestKind, Resolution, Response, SeriesRange, ShutdownReason,
    StatsEmail, StatusV1, StoredMacReport, Traffic, UnixTime, UplinkTransfer, UsageBin, UsageMonth,
    UsageSeriesV1, WatchConditions, WatchError, WatchErrorKind,
};

use crate::golden::{
    Frame, Golden, golden_line, golden_name, golden_settings, reply_frame, request_frame,
};

const DESCRIPTION: &str = "SPDX-License-Identifier: GPL-3.0-or-later. Protocol 1 (design 11.1), not frozen: a change here changes protocol 1. The frame is this line plus one newline.";

fn time(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

fn email(text: &str) -> StatsEmail {
    text.parse().unwrap()
}

fn status_request() -> Vec<u8> {
    request_frame(&LineRequest::Status)
}

fn status_response() -> Vec<u8> {
    let status = StatusV1 {
        now: time(1_791_417_900),
        watch_at: time(1_791_417_897),
        gate: GateState::Open,
        holds: Holds::NONE,
        halted: None,
        latest_handshake: Some(time(1_791_417_890)),
        applied: Some(AppliedGeneration {
            generation: Generation::new(13),
            digest: "8e2d6a4c0b1f3e5d7c9a8b6f4e2d0c1b3a5f7e9d8c6b4a2f0e1d3c5b7a9f8e6d"
                .parse()
                .unwrap(),
        }),
        conditions: WatchConditions::new([
            WatchError::ExitFlowCapHit { count: 3 },
            WatchError::RebootPending {
                since: time(1_791_380_000),
            },
        ])
        .unwrap(),
        accounting_at: Some(time(1_791_417_880)),
        last_active: BTreeMap::from([
            (email("fxuseraaab@hy2"), time(1_791_417_760)),
            (email("fxuseraaab@reality"), time(1_791_417_880)),
            (email("probe@hy2"), time(1_791_417_700)),
            (email("probe@reality"), time(1_791_417_700)),
        ]),
        engines: EngineHealth {
            xray: EngineState {
                restarts: 1,
                run: EngineRun::Active {
                    uptime_secs: 52_000,
                    go_heap_bytes: Some(18_350_080),
                },
            },
            hy2: EngineState {
                restarts: 0,
                run: EngineRun::Active {
                    uptime_secs: 52_001,
                    go_heap_bytes: None,
                },
            },
        },
        host: HostHealth {
            uptime_secs: 52_100,
            load_milli: 80,
            mem_available_bytes: 612_000_000,
            disk_free_bytes: 17_800_000_000,
            journal_bytes: 96_000_000,
            reboot_required: true,
            last_unattended_upgrade: Some(time(1_791_380_000)),
            ntp_synced: true,
        },
        transfer: UplinkTransfer {
            month: UsageMonth::new(2026, 10).unwrap(),
            counted_from: time(1_790_812_860),
            rx_bytes: 61_000_000_000,
            tx_bytes: 63_500_000_000,
            counter_resets: 7,
        },
    };
    reply_frame(&Ok(Response::Status(Box::new(status))))
}

fn series_range() -> SeriesRange {
    SeriesRange::new(
        time(1_791_417_600),
        time(1_791_418_800),
        Resolution::FiveMin,
    )
    .unwrap()
}

fn usage_series_request() -> Vec<u8> {
    request_frame(&LineRequest::UsageSeries(series_range()))
}

fn usage_series_response() -> Vec<u8> {
    let traffic = |uplink, downlink| Traffic { uplink, downlink };
    let series = UsageSeriesV1::new(
        series_range(),
        vec![
            UsageBin::new(
                time(1_791_417_600),
                BTreeMap::from([
                    (email("fxuseraaab@reality"), traffic(48_211, 2_901_334)),
                    (email("probe@hy2"), traffic(612, 389)),
                    (email("probe@reality"), traffic(1_480, 5_120)),
                ]),
            )
            .unwrap(),
            UsageBin::new(
                time(1_791_418_200),
                BTreeMap::from([(email("fxuseraaab@hy2"), traffic(0, 77_312))]),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    reply_frame(&Ok(Response::UsageSeries(Box::new(series))))
}

fn events_request() -> Vec<u8> {
    request_frame(&LineRequest::Events {
        since: EventSeq::new(40),
    })
}

fn events_response() -> Vec<u8> {
    let kinds = [
        AgentEventKind::ConditionRaised {
            condition: WatchError::MacSilent {
                since: Some(time(1_791_416_400)),
            },
        },
        AgentEventKind::GateClosed,
        AgentEventKind::ConditionRaised {
            condition: WatchError::MacSilent { since: None },
        },
        AgentEventKind::ConditionRaised {
            condition: WatchError::DiskLow { free: 950_000_000 },
        },
        AgentEventKind::ConditionRaised {
            condition: WatchError::ClockUnsynced,
        },
        AgentEventKind::ConditionRaised {
            condition: WatchError::AccountingCanaryMissing {
                inbounds: InboundSet::of(Inbound::Reality).with(Inbound::Hy2),
            },
        },
        AgentEventKind::ConditionCleared {
            condition: WatchErrorKind::MacSilent,
        },
        AgentEventKind::GateOpened,
        AgentEventKind::HoldRecorded {
            hold: GateReason::Operator,
        },
        AgentEventKind::HoldCleared {
            hold: GateReason::Operator,
        },
        AgentEventKind::Halted {
            reason: ShutdownReason::Operator,
        },
        AgentEventKind::Resumed {
            generation: Generation::new(12),
        },
        AgentEventKind::Committed {
            generation: Generation::new(13),
        },
        AgentEventKind::EngineRestarted {
            engine: EngineUser::Xray,
        },
        AgentEventKind::HostBooted,
    ];
    let events = (40..)
        .zip(kinds)
        .map(|(seq, kind)| AgentEvent {
            seq: EventSeq::new(seq),
            at: time(1_791_416_400 + 60 * seq),
            kind,
        })
        .collect();
    let page = EventsV1::new(events, EventSeq::new(55)).unwrap();
    reply_frame(&Ok(Response::Events(Box::new(page))))
}

fn report_user(text: &str) -> ReportUserId {
    ReportUserId::new(text).unwrap()
}

fn node(text: &str) -> Option<NodeName> {
    Some(NodeName::new(text).unwrap())
}

/// A serving exit on the decided line: a hard stop and no plan line, the
/// radio attached on NR band 78, a saturated uplink, usage for an active,
/// a suspended and a revoking user, and two alerts.
fn put_mac_report_request() -> Vec<u8> {
    let report = MacReportV1::new(MacReportParts {
        at: time(1_791_417_900),
        exit: ReportExit {
            phase: ExitPhase::Serving,
            since: time(1_791_380_000),
        },
        sim: ReportSim {
            cycle_starts_at: time(1_791_331_200),
            cycle_ends_at: time(1_793_923_200),
            rx_bytes: 118_204_331_520,
            tx_bytes: 9_871_203_840,
            accuracy: ReportAccuracy::Exact,
            warn_bytes: 240_000_000_000,
            hard_stop_bytes: Some(300_000_000_000),
            line: None,
            forecast: Some(ReportForecast {
                daily_average_bytes: 8_005_000_000,
                projected_bytes: 248_155_000_000,
            }),
        },
        router: ReportRouter::Available {
            polled_at: time(1_791_417_890),
            radio: ReportRadio::Attached {
                access: ReportRadioAccess::NrNsa,
                band: ReportBand {
                    system: ReportRadioSystem::Nr,
                    number: ReportBandNumber::new(78).unwrap(),
                },
                rsrp_tenths: Some(-982),
                rsrq_tenths: Some(-105),
                sinr_tenths: Some(143),
                rssi_tenths: None,
            },
            temperature_c: 46,
        },
        capacity: Some(ReportCapacity {
            at: time(1_791_417_880),
            tx_bps: 18_400_000,
            rx_bps: 61_000_000,
            saturation: ReportSaturation::Saturated {
                since: time(1_791_415_000),
            },
        }),
        usage: ReportUsage::Available {
            through: time(1_791_417_840),
        },
        users: BTreeMap::from([
            (
                report_user("fxuseraaab"),
                ReportUser {
                    status: ReportUserStatus::Active,
                    cycle: Some(Traffic {
                        uplink: 2_310_000_000,
                        downlink: 41_870_000_000,
                    }),
                    last_seen: Some(time(1_791_417_840)),
                },
            ),
            (
                report_user("fxuseraaac"),
                ReportUser {
                    status: ReportUserStatus::Suspended,
                    cycle: Some(Traffic {
                        uplink: 0,
                        downlink: 0,
                    }),
                    last_seen: None,
                },
            ),
            (
                report_user("fxuseraaad"),
                ReportUser {
                    status: ReportUserStatus::RevokePending,
                    cycle: Some(Traffic {
                        uplink: 1_200,
                        downlink: 77_312,
                    }),
                    last_seen: Some(time(1_791_331_260)),
                },
            ),
        ]),
        alerts: vec![
            ReportAlert {
                kind: MacAlertKind::CapacitySaturated,
                severity: ReportSeverity::Warning,
                node: None,
                active_since: time(1_791_415_000),
            },
            ReportAlert {
                kind: MacAlertKind::NodeRebootPending,
                severity: ReportSeverity::Warning,
                node: node("lon1"),
                active_since: time(1_791_380_000),
            },
        ],
    })
    .unwrap();
    request_frame(&LineRequest::PutMacReport(Box::new(report)))
}

fn put_mac_report_response() -> Vec<u8> {
    reply_frame(&Ok(Response::MacReportStored {
        at: time(1_791_417_900),
    }))
}

fn mac_report_request() -> Vec<u8> {
    request_frame(&LineRequest::MacReport)
}

/// A down exit on a capped plan whose radio has no service: the meter a
/// lower bound with no forecast, a clear uplink, no usage view, and a
/// critical alert about a node.
fn mac_report_response() -> Vec<u8> {
    let report = MacReportV1::new(MacReportParts {
        at: time(1_791_418_200),
        exit: ReportExit {
            phase: ExitPhase::Down,
            since: time(1_791_418_000),
        },
        sim: ReportSim {
            cycle_starts_at: time(1_791_331_200),
            cycle_ends_at: time(1_793_923_200),
            rx_bytes: 52_000_000_000,
            tx_bytes: 4_000_000_000,
            accuracy: ReportAccuracy::LowerBound,
            warn_bytes: 80_000_000_000,
            hard_stop_bytes: Some(95_000_000_000),
            line: Some(ReportPlanLine::Allowance {
                bytes: 107_374_182_400,
            }),
            forecast: None,
        },
        router: ReportRouter::Available {
            polled_at: time(1_791_418_190),
            radio: ReportRadio::NoService,
            temperature_c: 38,
        },
        capacity: Some(ReportCapacity {
            at: time(1_791_418_180),
            tx_bps: 0,
            rx_bps: 0,
            saturation: ReportSaturation::Clear,
        }),
        usage: ReportUsage::Unavailable,
        users: BTreeMap::from([(
            report_user("fxuseraaab"),
            ReportUser {
                status: ReportUserStatus::Active,
                cycle: None,
                last_seen: Some(time(1_791_417_840)),
            },
        )]),
        alerts: vec![ReportAlert {
            kind: MacAlertKind::NodeHalted,
            severity: ReportSeverity::Critical,
            node: node("ams1"),
            active_since: time(1_791_418_000),
        }],
    })
    .unwrap();
    let stored = StoredMacReport {
        received_at: time(1_791_418_203),
        report,
    };
    reply_frame(&Ok(Response::MacReport(Box::new(stored))))
}

/// Every protocol-1 golden outside the frozen core.
pub(crate) const GOLDENS: [Golden; 10] = [
    (RequestKind::Status, Frame::Request, status_request),
    (RequestKind::Status, Frame::Response, status_response),
    (
        RequestKind::UsageSeries,
        Frame::Request,
        usage_series_request,
    ),
    (
        RequestKind::UsageSeries,
        Frame::Response,
        usage_series_response,
    ),
    (RequestKind::Events, Frame::Request, events_request),
    (RequestKind::Events, Frame::Response, events_response),
    (
        RequestKind::PutMacReport,
        Frame::Request,
        put_mac_report_request,
    ),
    (
        RequestKind::PutMacReport,
        Frame::Response,
        put_mac_report_response,
    ),
    (RequestKind::MacReport, Frame::Request, mac_report_request),
    (RequestKind::MacReport, Frame::Response, mac_report_response),
];

#[test]
fn protocol_frames_match_their_goldens() {
    for (kind, frame, build) in GOLDENS {
        let name = golden_name(kind, frame);
        let built = build();
        let line = golden_line(&name, &built);
        golden_settings(DESCRIPTION).bind(|| insta::assert_snapshot!(name, line));
    }
}
