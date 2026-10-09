// SPDX-License-Identifier: GPL-3.0-or-later

//! The size bounds of the frames that grow with the data: the largest
//! `UsageSeriesV1` and `EventsV1` the types can hold fit one reply frame
//! (`MAX_RESPONSE_LINE_BYTES`), the largest `MacReportV1` fits both the
//! `PutMacReport` request and the `MacReport` reply, and one entry, event,
//! user or alert more is refused by the type itself. Also the request-side
//! range rule, on construction and on receipt.

use std::collections::BTreeSet;
use std::io::Cursor;

use mooring_agent_proto::{
    AgentEvent, AgentEventKind, EngineUser, EventSeq, EventsV1, ExitPhase, GateReason, Generation,
    Inbound, InboundSet, LineRequest, MAX_EVENTS, MAX_MAC_REPORT_BYTES, MAX_REPORT_ALERTS,
    MAX_REPORT_USERS, MAX_REQUEST_LINE_BYTES, MAX_RESPONSE_LINE_BYTES, MAX_SERIES_ENTRIES,
    MAX_USAGE_SERIES_REPLY_BYTES, MacAlertKind, MacReportParts, MacReportRule, MacReportV1,
    NodeName, Reply, ReportAccuracy, ReportAlert, ReportBand, ReportBandNumber, ReportCapacity,
    ReportExit, ReportForecast, ReportPlanLine, ReportRadio, ReportRadioAccess, ReportRadioSystem,
    ReportRouter, ReportSaturation, ReportSeverity, ReportSim, ReportUsage, ReportUser,
    ReportUserId, ReportUserStatus, Request, Resolution, Response, SeriesRange, ShutdownReason,
    StatsEmail, StoredMacReport, Traffic, UnixTime, UsageBin, UsageSeriesV1, ValueError,
    WatchError, WatchErrorKind, read_reply, read_request, write_reply, write_request,
};
use proptest::prelude::*;
use proptest::sample::select;
use serde::Serialize;

/// The `index`th longest accounting email: a 32-character principal on the
/// longer inbound name, with both counters at their maximum.
fn longest_entry(index: usize) -> (StatsEmail, Traffic) {
    let email = format!("{index:0>32}@{}", Inbound::Reality.as_str());
    (
        email.parse().unwrap(),
        Traffic {
            uplink: u64::MAX,
            downlink: u64::MAX,
        },
    )
}

/// The latest range of `resolution`'s most bins, so every number has 20
/// digits, holding `entries` of the longest entries spread over all bins.
fn largest_series(resolution: Resolution, entries: usize) -> Result<UsageSeriesV1, ValueError> {
    let width = resolution.bin_secs();
    let bins = resolution.max_bins();
    let end = u64::MAX / width;
    let from = (end - bins) * width;
    let range = SeriesRange::new(
        UnixTime::from_secs(from),
        UnixTime::from_secs(end * width),
        resolution,
    )
    .unwrap();
    let bins = usize::try_from(bins).unwrap();
    let (base, extra) = (entries / bins, entries % bins);
    let series = (0..bins)
        .map(|index| (index, base + usize::from(index < extra)))
        .filter(|(_, count)| *count > 0)
        .map(|(index, count)| {
            let start = from + u64::try_from(index).unwrap() * width;
            UsageBin::new(
                UnixTime::from_secs(start),
                (0..count).map(longest_entry).collect(),
            )
            .unwrap()
        })
        .collect();
    UsageSeriesV1::new(range, series)
}

fn reply_line(reply: &Reply) -> Vec<u8> {
    let mut frame = Vec::new();
    write_reply(&mut frame, reply).unwrap();
    assert_eq!(
        read_reply(&mut Cursor::new(frame.as_slice())).unwrap(),
        *reply
    );
    assert_eq!(frame.pop(), Some(b'\n'));
    frame
}

/// At every resolution the largest series fits the computed bound, which
/// fits the frame; the bound is exact for the widest resolution but for
/// the separators it counts after every bin and entry and the longer
/// resolution name it assumes.
#[test]
fn the_largest_usage_series_reply_fits_one_frame() {
    const _: () = assert!(MAX_USAGE_SERIES_REPLY_BYTES <= MAX_RESPONSE_LINE_BYTES);
    for resolution in Resolution::ALL {
        let series = largest_series(*resolution, MAX_SERIES_ENTRIES).unwrap();
        let bins = series.bins().len();
        assert_eq!(u64::try_from(bins).unwrap(), resolution.max_bins());
        let line = reply_line(&Ok(Response::UsageSeries(Box::new(series)))).len();
        assert!(
            line <= MAX_USAGE_SERIES_REPLY_BYTES,
            "{resolution:?}: {line} bytes"
        );
        if *resolution == Resolution::Hour {
            let names = "FiveMin".len() - "Hour".len();
            assert_eq!(MAX_USAGE_SERIES_REPLY_BYTES - line, 1 + bins + names);
        }
    }
}

#[test]
fn one_entry_more_than_a_reply_carries_is_refused() {
    for resolution in Resolution::ALL {
        assert_eq!(
            largest_series(*resolution, MAX_SERIES_ENTRIES + 1).map(|_| ()),
            Err(ValueError::UsageSeries),
            "{resolution:?}"
        );
    }
}

/// Each event kind with the longest data it can carry.
fn longest_kinds() -> Vec<AgentEventKind> {
    let at = UnixTime::from_secs(u64::MAX);
    let mut kinds: Vec<AgentEventKind> = Vec::new();
    for kind in WatchErrorKind::ALL {
        let condition = match kind {
            WatchErrorKind::WgReadFailed => WatchError::WgReadFailed,
            WatchErrorKind::NftFailed => WatchError::NftFailed,
            WatchErrorKind::StatsQueryFailed => WatchError::StatsQueryFailed,
            WatchErrorKind::TargetDegraded => WatchError::TargetDegraded,
            WatchErrorKind::ExitFlowCapHit => WatchError::ExitFlowCapHit { count: u64::MAX },
            WatchErrorKind::StateWrite => WatchError::StateWrite {
                errno: Some(i32::MIN),
            },
            WatchErrorKind::MacSilent => WatchError::MacSilent { since: Some(at) },
            WatchErrorKind::DiskLow => WatchError::DiskLow { free: u64::MAX },
            WatchErrorKind::ClockUnsynced => WatchError::ClockUnsynced,
            WatchErrorKind::RebootPending => WatchError::RebootPending { since: at },
            WatchErrorKind::AccountingCanaryMissing => WatchError::AccountingCanaryMissing {
                inbounds: InboundSet::of(Inbound::Reality).with(Inbound::Hy2),
            },
        };
        kinds.push(AgentEventKind::ConditionRaised { condition });
        kinds.push(AgentEventKind::ConditionCleared { condition: *kind });
    }
    for hold in GateReason::ALL {
        kinds.push(AgentEventKind::HoldRecorded { hold: *hold });
        kinds.push(AgentEventKind::HoldCleared { hold: *hold });
    }
    kinds.extend(
        ShutdownReason::ALL
            .iter()
            .map(|reason| AgentEventKind::Halted { reason: *reason }),
    );
    kinds.extend(
        EngineUser::ALL
            .iter()
            .map(|engine| AgentEventKind::EngineRestarted { engine: *engine }),
    );
    let generation = Generation::new(u64::MAX);
    kinds.extend([
        AgentEventKind::GateOpened,
        AgentEventKind::GateClosed,
        AgentEventKind::Resumed { generation },
        AgentEventKind::Committed { generation },
        AgentEventKind::HostBooted,
    ]);
    kinds
}

/// The variant's name; the match is exhaustive, so a new event kind fails
/// to compile here until `longest_kinds` is told about it.
fn variant(kind: &AgentEventKind) -> &'static str {
    match kind {
        AgentEventKind::ConditionRaised { .. } => "ConditionRaised",
        AgentEventKind::ConditionCleared { .. } => "ConditionCleared",
        AgentEventKind::GateOpened => "GateOpened",
        AgentEventKind::GateClosed => "GateClosed",
        AgentEventKind::HoldRecorded { .. } => "HoldRecorded",
        AgentEventKind::HoldCleared { .. } => "HoldCleared",
        AgentEventKind::Halted { .. } => "Halted",
        AgentEventKind::Resumed { .. } => "Resumed",
        AgentEventKind::Committed { .. } => "Committed",
        AgentEventKind::EngineRestarted { .. } => "EngineRestarted",
        AgentEventKind::HostBooted => "HostBooted",
    }
}

/// `MAX_EVENTS` events of the longest kind, numbered just below the
/// largest number, fit one reply frame; one more is refused by the type.
#[test]
fn the_largest_events_reply_fits_one_frame() {
    let kinds = longest_kinds();
    let covered: BTreeSet<&str> = kinds.iter().map(variant).collect();
    assert_eq!(covered.len(), 11, "every event kind has a longest sample");
    let event = |seq: u64, kind: AgentEventKind| AgentEvent {
        seq: EventSeq::new(seq),
        at: UnixTime::from_secs(u64::MAX),
        kind,
    };
    let longest = kinds
        .into_iter()
        .max_by_key(|kind| serde_json::to_vec(&event(u64::MAX, *kind)).unwrap().len())
        .unwrap();
    let first = u64::MAX - 1 - u64::try_from(MAX_EVENTS).unwrap();
    let mut events: Vec<AgentEvent> = (first..)
        .take(MAX_EVENTS)
        .map(|seq| event(seq, longest))
        .collect();
    let end = EventSeq::new(u64::MAX);
    let page = EventsV1::new(events.clone(), end).unwrap();
    let line = reply_line(&Ok(Response::Events(Box::new(page)))).len();
    assert!(line <= MAX_RESPONSE_LINE_BYTES, "{line} bytes");
    events.push(event(first + u64::try_from(MAX_EVENTS).unwrap(), longest));
    assert_eq!(EventsV1::new(events, end), Err(ValueError::Events));
}

/// The candidate whose encoding is longest.
fn longest<T: Serialize>(candidates: Vec<T>) -> T {
    candidates
        .into_iter()
        .max_by_key(|candidate| serde_json::to_vec(candidate).unwrap().len())
        .unwrap()
}

/// Every option of a value: absent, or `value`.
fn options<T: Clone>(value: T) -> [Option<T>; 2] {
    [None, Some(value)]
}

/// The `index`th report user id.
fn report_user_id(index: usize) -> ReportUserId {
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let text: String = (0..10)
        .map(|digit| char::from(alphabet[(index >> (5 * digit)) % 32]))
        .collect();
    ReportUserId::new(text).unwrap()
}

/// The longest report: every field in its longest shape with every number
/// at its longest (the fields' encodings add up, so the longest of each
/// makes the longest report), `users` users and `alerts` alerts, each the
/// longest possible.
fn largest_report(users: usize, alerts: usize) -> MacReportParts {
    let max = UnixTime::from_secs(u64::MAX);
    let big = u64::MAX;
    let signal = i16::MIN;
    let sims = ReportAccuracy::ALL.iter().flat_map(|accuracy| {
        options(big).into_iter().flat_map(move |hard_stop_bytes| {
            [
                None,
                Some(ReportPlanLine::FairUse { bytes: big }),
                Some(ReportPlanLine::Allowance { bytes: big }),
            ]
            .into_iter()
            .flat_map(move |line| {
                options(ReportForecast {
                    daily_average_bytes: big,
                    projected_bytes: big,
                })
                .into_iter()
                .map(move |forecast| ReportSim {
                    cycle_starts_at: max,
                    cycle_ends_at: max,
                    rx_bytes: big,
                    tx_bytes: big,
                    accuracy: *accuracy,
                    warn_bytes: big,
                    hard_stop_bytes,
                    line,
                    forecast,
                })
            })
        })
    });
    let mut radios = vec![ReportRadio::NoService];
    for access in ReportRadioAccess::ALL {
        for system in ReportRadioSystem::ALL {
            for signals in 0..16_u8 {
                let reading = |bit: u8| (signals & (1 << bit) != 0).then_some(signal);
                radios.push(ReportRadio::Attached {
                    access: *access,
                    band: ReportBand {
                        system: *system,
                        number: ReportBandNumber::new(ReportBandNumber::MAX).unwrap(),
                    },
                    rsrp_tenths: reading(0),
                    rsrq_tenths: reading(1),
                    sinr_tenths: reading(2),
                    rssi_tenths: reading(3),
                });
            }
        }
    }
    let mut routers: Vec<ReportRouter> = options(max)
        .into_iter()
        .map(|last_polled_at| ReportRouter::Unavailable { last_polled_at })
        .collect();
    routers.extend(radios.into_iter().map(|radio| ReportRouter::Available {
        polled_at: max,
        radio,
        temperature_c: signal,
    }));
    let capacities = [
        ReportSaturation::NoEvidence,
        ReportSaturation::Clear,
        ReportSaturation::Building { since: max },
        ReportSaturation::Saturated { since: max },
    ]
    .map(|saturation| {
        Some(ReportCapacity {
            at: max,
            tx_bps: big,
            rx_bps: big,
            saturation,
        })
    });
    let status = longest(ReportUserStatus::ALL.to_vec());
    let node = NodeName::new(format!("a{}", "9".repeat(11))).unwrap();
    let alert = ReportAlert {
        kind: longest(MacAlertKind::ALL.to_vec()),
        severity: longest(ReportSeverity::ALL.to_vec()),
        node: Some(node),
        active_since: max,
    };
    // Usage that is available puts a cycle in every user, so it is the
    // longer choice for the report as a whole.
    let usage = longest(vec![
        ReportUsage::Unavailable,
        ReportUsage::Available { through: max },
    ]);
    MacReportParts {
        at: max,
        exit: ReportExit {
            phase: longest(ExitPhase::ALL.to_vec()),
            since: max,
        },
        sim: longest(sims.collect()),
        router: longest(routers),
        capacity: longest([vec![None], capacities.to_vec()].concat()),
        usage,
        users: (0..users)
            .map(|index| {
                let user = ReportUser {
                    status,
                    cycle: Some(Traffic {
                        uplink: big,
                        downlink: big,
                    }),
                    last_seen: Some(max),
                };
                (report_user_id(index), user)
            })
            .collect(),
        alerts: vec![alert; alerts],
    }
}

/// The largest report fits its computed bound, which is exact but for the
/// commas after the last user and the last alert; the `PutMacReport`
/// request and the `MacReport` reply carrying it fit their frames; one
/// user or alert more is refused by the type.
#[test]
fn the_largest_mac_report_fits_both_frames() {
    let parts = largest_report(MAX_REPORT_USERS, MAX_REPORT_ALERTS);
    assert!(matches!(parts.usage, ReportUsage::Available { .. }));
    let report = MacReportV1::new(parts.clone()).unwrap();
    let encoded = serde_json::to_vec(&report).unwrap().len();
    assert_eq!(MAX_MAC_REPORT_BYTES - encoded, 2);

    let request = LineRequest::PutMacReport(Box::new(report.clone()));
    let mut frame = Vec::new();
    write_request(&mut frame, &request).unwrap();
    assert!(
        frame.len() <= MAX_REQUEST_LINE_BYTES + 1,
        "{} bytes",
        frame.len()
    );
    assert_eq!(
        read_request(&mut Cursor::new(frame.as_slice())).unwrap(),
        Request::Line(request)
    );
    let stored = StoredMacReport {
        received_at: UnixTime::from_secs(u64::MAX),
        report,
    };
    let line = reply_line(&Ok(Response::MacReport(Box::new(stored)))).len();
    assert!(line <= MAX_RESPONSE_LINE_BYTES, "{line} bytes");

    let refused = |rule| Err(ValueError::MacReport { rule });
    assert_eq!(
        MacReportV1::new(largest_report(MAX_REPORT_USERS + 1, MAX_REPORT_ALERTS)).map(drop),
        refused(MacReportRule::TooManyUsers)
    );
    assert_eq!(
        MacReportV1::new(largest_report(MAX_REPORT_USERS, MAX_REPORT_ALERTS + 1)).map(drop),
        refused(MacReportRule::TooManyAlerts)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A range is accepted, by its constructor and in a received request,
    /// exactly when it is whole bins (both ends on a boundary, `from`
    /// before `to`) and at most `max_bins` of them.
    #[test]
    fn ranges_are_whole_bins_within_the_bound(
        resolution in select(Resolution::ALL),
        first in 0..1_000_000_u64,
        bins in 0..200_u64,
        from_offset in 0..3_u64,
        to_offset in 0..3_u64,
    ) {
        let width = resolution.bin_secs();
        let from = first * width + from_offset;
        let to = (first + bins) * width + to_offset;
        let expected = if from_offset != 0 || to_offset != 0 || bins == 0 {
            Err(ValueError::SeriesSpan)
        } else if bins > resolution.max_bins() {
            Err(ValueError::RangeTooLarge { resolution, bins })
        } else {
            Ok(())
        };
        let built = SeriesRange::new(UnixTime::from_secs(from), UnixTime::from_secs(to), resolution);
        prop_assert_eq!(built.clone().map(|_| ()), expected.clone());
        let line = format!(
            "{{\"UsageSeries\":{{\"from\":{from},\"to\":{to},\"resolution\":\"{resolution:?}\"}}}}\n"
        );
        let received = read_request(&mut Cursor::new(line.as_bytes()));
        prop_assert_eq!(received.is_ok(), expected.is_ok());
        if let (Ok(Request::Line(request)), Ok(range)) = (received, built) {
            prop_assert_eq!(request, LineRequest::UsageSeries(range));
        }
    }
}
