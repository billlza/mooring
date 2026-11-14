// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history's tables (design §15.6 rule 13): the headers, a row
//! of each kind of sample and of each kind of event byte for byte, the
//! names against the JSON document's, the bound on a time, and that a
//! table loses nothing of what it is made from.

use std::fmt;

use mooring_model::{CalendarDate, ModelError, UnixTime};
use proptest::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::radio_history::any_sample;
use crate::radio_history::{
    RadioEvent, RadioEventKind, RadioPoll, RadioReading, RadioSample, SampledAttachment,
    SampledRadio, events,
};
use crate::radio_table::{EVENTS_HEADER, SAMPLES_HEADER, events_table, samples_table};
use crate::router::{
    Band, BandNumber, Celsius, DataService, LteSignal, Mcc, Mnc, NetworkService, NrSignal, Plmn,
    RouterUnavailableReason, Rsrp, Rsrq, Rssi, Sinr, ThermalState,
};

/// 2026-10-13 19:20:00 UTC, the M2a poll.
const POLLED: u64 = 1_791_919_200;

/// The last second of the year 9999.
const LAST_SECOND: u64 = 253_402_300_799;

/// The samples table's columns, written out.
const SAMPLE_COLUMNS: [&str; 21] = [
    "at_unix",
    "at_utc",
    "outcome",
    "failure",
    "uptime_secs",
    "temperature_c",
    "thermal",
    "service",
    "network_service",
    "data_service",
    "band",
    "ca_secondary_count",
    "lte_rsrp_dbm",
    "lte_rsrq_db",
    "lte_sinr_db",
    "lte_rssi_dbm",
    "nr_rsrp_dbm",
    "nr_rsrq_db",
    "nr_sinr_db",
    "plmn",
    "session_secs",
];

/// The events table's columns, written out.
const EVENT_COLUMNS: [&str; 6] = ["at_unix", "at_utc", "event", "reason", "from", "to"];

/// Every reason a poll fails for, written out; the match keeps the list
/// whole when a reason is added.
const REASONS: [RouterUnavailableReason; 7] = [
    RouterUnavailableReason::NotConfigured,
    RouterUnavailableReason::Unreachable,
    RouterUnavailableReason::AuthFailed,
    RouterUnavailableReason::IdentityMismatch,
    RouterUnavailableReason::Unsupported,
    RouterUnavailableReason::Malformed,
    RouterUnavailableReason::LocalFailure,
];

const fn listed(reason: RouterUnavailableReason) -> usize {
    match reason {
        RouterUnavailableReason::NotConfigured => 0,
        RouterUnavailableReason::Unreachable => 1,
        RouterUnavailableReason::AuthFailed => 2,
        RouterUnavailableReason::IdentityMismatch => 3,
        RouterUnavailableReason::Unsupported => 4,
        RouterUnavailableReason::Malformed => 5,
        RouterUnavailableReason::LocalFailure => 6,
    }
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

fn tenths<T: TryFrom<i16>>(value: i16) -> Option<T>
where
    T::Error: fmt::Debug,
{
    Some(T::try_from(value).unwrap())
}

fn plmn(mnc: &str) -> Plmn {
    Plmn {
        mcc: Mcc::parse("234").unwrap(),
        mnc: Mnc::parse(mnc).unwrap(),
    }
}

/// An attachment with every reading reported, each with its own value.
fn full() -> SampledAttachment {
    SampledAttachment {
        network_service: NetworkService::Nr5g,
        data_service: DataService::NrSub6,
        band: Band::Nr(BandNumber::new(78).unwrap()),
        ca_secondary_count: 2,
        lte: LteSignal {
            rsrp: tenths(-1_045),
            rsrq: tenths(-170),
            sinr: tenths(-5),
            rssi: tenths(-720),
        },
        nr: NrSignal {
            rsrp: tenths(-905),
            rsrq: tenths(-105),
            sinr: tenths(155),
        },
        plmn: plmn("30"),
        session_secs: 359_217,
    }
}

fn read(secs: u64, radio: SampledRadio) -> RadioSample {
    RadioSample {
        at: at(secs),
        poll: RadioPoll::Read(RadioReading {
            uptime_secs: 359_272,
            temperature_c: Celsius::new(35).unwrap(),
            thermal: ThermalState::Normal,
            radio,
        }),
    }
}

fn failed(secs: u64, reason: RouterUnavailableReason) -> RadioSample {
    RadioSample {
        at: at(secs),
        poll: RadioPoll::Failed { reason },
    }
}

/// The one row of the table of `sample`, without its newline.
fn row(sample: RadioSample) -> String {
    let table = samples_table(&[sample]).unwrap();
    let rest = table
        .strip_prefix(SAMPLES_HEADER)
        .and_then(|rest| rest.strip_prefix('\n'))
        .unwrap();
    rest.strip_suffix('\n').unwrap().to_owned()
}

/// The one row of the table of the event `kind` at the M2a poll.
fn event_row(kind: RadioEventKind) -> String {
    let table = events_table(&[RadioEvent {
        at: at(POLLED),
        kind,
    }])
    .unwrap();
    let rest = table
        .strip_prefix(EVENTS_HEADER)
        .and_then(|rest| rest.strip_prefix('\n'))
        .unwrap();
    rest.strip_suffix('\n').unwrap().to_owned()
}

/// The name the JSON document gives `value`: the string itself, or the
/// one key of a variant that holds fields.
fn json_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value).unwrap() {
        Value::String(name) => name,
        Value::Object(object) => {
            assert_eq!(object.len(), 1);
            object.keys().next().unwrap().clone()
        }
        other => panic!("{other} is no name"),
    }
}

// --- The headers ------------------------------------------------------------

#[test]
fn the_headers_name_the_columns_in_order() {
    assert_eq!(SAMPLES_HEADER, SAMPLE_COLUMNS.join(","));
    assert_eq!(EVENTS_HEADER, EVENT_COLUMNS.join(","));
    // No samples and no events: the header alone, with its newline.
    assert_eq!(samples_table(&[]).unwrap(), format!("{SAMPLES_HEADER}\n"));
    assert_eq!(events_table(&[]).unwrap(), format!("{EVENTS_HEADER}\n"));
}

// --- Sample rows ------------------------------------------------------------

#[test]
fn an_attached_read_fills_every_column() {
    assert_eq!(
        row(read(POLLED, SampledRadio::Attached(full()))),
        "1791919200,2026-10-13T19:20:00Z,read,,359272,35,normal,attached,nr5g,nr_sub6,n78,2,\
         -104.5,-17.0,-0.5,-72.0,-90.5,-10.5,15.5,234-30,359217"
    );
}

#[test]
fn a_reading_the_m7_did_not_report_is_an_empty_cell() {
    let radio = SampledAttachment {
        network_service: NetworkService::Lte,
        data_service: DataService::LtePlus,
        band: Band::Lte(BandNumber::new(3).unwrap()),
        ca_secondary_count: 0,
        lte: LteSignal {
            rsrp: tenths(-1_040),
            rsrq: None,
            sinr: tenths(0),
            rssi: None,
        },
        nr: NrSignal {
            rsrp: None,
            rsrq: None,
            sinr: None,
        },
        plmn: plmn("20"),
        session_secs: 0,
    };
    assert_eq!(
        row(read(POLLED, SampledRadio::Attached(radio))),
        "1791919200,2026-10-13T19:20:00Z,read,,359272,35,normal,attached,lte,lte_plus,B3,0,\
         -104.0,,0.0,,,,,234-20,0"
    );
}

#[test]
fn a_read_without_service_leaves_the_attachments_cells_empty() {
    assert_eq!(
        row(read(POLLED + 120, SampledRadio::NoService)),
        "1791919320,2026-10-13T19:22:00Z,read,,359272,35,normal,no_service,,,,,,,,,,,,,"
    );
}

#[test]
fn a_failed_poll_holds_its_time_and_its_reason() {
    assert_eq!(
        row(failed(POLLED + 60, RouterUnavailableReason::Unreachable)),
        "1791919260,2026-10-13T19:21:00Z,failed,unreachable,,,,,,,,,,,,,,,,,"
    );
    let names = [
        "not_configured",
        "unreachable",
        "auth_failed",
        "identity_mismatch",
        "unsupported",
        "malformed",
        "local_failure",
    ];
    for (index, reason) in REASONS.into_iter().enumerate() {
        assert_eq!(listed(reason), index);
        let row = row(failed(POLLED, reason));
        let cells: Vec<&str> = row.split(',').collect();
        assert_eq!(cells[3], names[index]);
        assert_eq!(cells[3], json_name(&reason));
        assert!(cells[4..].iter().all(|cell| cell.is_empty()), "{row}");
    }
}

/// A reading keeps its one decimal whatever its value: a whole number has
/// `.0`, and one between -1 and 0 keeps its sign.
#[test]
fn a_reading_has_one_decimal() {
    let lte_sinr = |sinr: i16| {
        let radio = SampledAttachment {
            lte: LteSignal {
                rsrp: None,
                rsrq: None,
                sinr: tenths(sinr),
                rssi: None,
            },
            ..full()
        };
        let row = row(read(POLLED, SampledRadio::Attached(radio)));
        row.split(',').nth(14).unwrap().to_owned()
    };
    for (sinr, cell) in [
        (-230, "-23.0"),
        (-15, "-1.5"),
        (-10, "-1.0"),
        (-9, "-0.9"),
        (-1, "-0.1"),
        (0, "0.0"),
        (1, "0.1"),
        (9, "0.9"),
        (10, "1.0"),
        (155, "15.5"),
        (400, "40.0"),
    ] {
        assert_eq!(lte_sinr(sinr), cell, "{sinr}");
    }
    // The bounds of the widest range, RSRP's and RSSI's.
    let radio = SampledAttachment {
        lte: LteSignal {
            rsrp: tenths(Rsrp::MIN_TENTHS),
            rsrq: tenths(Rsrq::MAX_TENTHS),
            sinr: tenths(Sinr::MIN_TENTHS),
            rssi: tenths(Rssi::MAX_TENTHS),
        },
        ..full()
    };
    let row = row(read(POLLED, SampledRadio::Attached(radio)));
    let cells: Vec<&str> = row.split(',').collect();
    assert_eq!(cells[12..16], ["-156.0", "20.0", "-23.0", "0.0"]);
}

/// The names are the JSON document's, for every value of each vocabulary.
#[test]
fn the_names_are_the_json_documents() {
    let cell = |radio: SampledAttachment, column: usize| {
        let row = row(read(POLLED, SampledRadio::Attached(radio)));
        row.split(',').nth(column).unwrap().to_owned()
    };
    for &service in NetworkService::ALL {
        let radio = SampledAttachment {
            network_service: service,
            ..full()
        };
        assert_eq!(cell(radio, 8), json_name(&service));
    }
    for &service in DataService::ALL {
        let radio = SampledAttachment {
            data_service: service,
            ..full()
        };
        assert_eq!(cell(radio, 9), json_name(&service));
    }
    for &thermal in ThermalState::ALL {
        let sample = RadioSample {
            at: at(POLLED),
            poll: RadioPoll::Read(RadioReading {
                uptime_secs: 1,
                temperature_c: Celsius::new(-40).unwrap(),
                thermal,
                radio: SampledRadio::NoService,
            }),
        };
        let row = row(sample);
        let cells: Vec<&str> = row.split(',').collect();
        assert_eq!(cells[6], json_name(&thermal));
        // The coldest temperature the status accepts keeps its sign.
        assert_eq!(cells[5], "-40");
    }
    assert_eq!(
        json_name(&SampledRadio::NoService),
        row(read(POLLED, SampledRadio::NoService))
            .split(',')
            .nth(7)
            .unwrap()
    );
    assert_eq!(json_name(&SampledRadio::Attached(full())), "attached");
    assert_eq!(
        json_name(&read(POLLED, SampledRadio::NoService).poll),
        "read"
    );
    assert_eq!(
        json_name(&failed(POLLED, RouterUnavailableReason::Malformed).poll),
        "failed"
    );
}

/// A band is spelled as the M7 and the document spell it, an NR band
/// apart from an LTE band of the same number.
#[test]
fn a_band_keeps_its_technology() {
    let band_cell = |band: Band| {
        let radio = SampledAttachment { band, ..full() };
        let row = row(read(POLLED, SampledRadio::Attached(radio)));
        row.split(',').nth(10).unwrap().to_owned()
    };
    let number = BandNumber::new(3).unwrap();
    assert_eq!(band_cell(Band::Lte(number)), "B3");
    assert_eq!(band_cell(Band::Nr(number)), "n3");
    assert_eq!(band_cell(Band::Lte(BandNumber::new(999).unwrap())), "B999");
}

// --- Times ------------------------------------------------------------------

#[test]
fn a_time_is_the_macs_in_seconds_and_in_utc() {
    for (secs, stamp) in [
        (0, "0,1970-01-01T00:00:00Z"),
        (59, "59,1970-01-01T00:00:59Z"),
        (3_599, "3599,1970-01-01T00:59:59Z"),
        (86_399, "86399,1970-01-01T23:59:59Z"),
        (86_400, "86400,1970-01-02T00:00:00Z"),
        (1_791_936_001, "1791936001,2026-10-14T00:00:01Z"),
        (LAST_SECOND, "253402300799,9999-12-31T23:59:59Z"),
    ] {
        let row = row(failed(secs, RouterUnavailableReason::Unreachable));
        assert!(row.starts_with(&format!("{stamp},failed,")), "{row}");
        let event = events_table(&[RadioEvent {
            at: at(secs),
            kind: RadioEventKind::PollRecovered,
        }])
        .unwrap();
        assert_eq!(
            event,
            format!("{EVENTS_HEADER}\n{stamp},poll_recovered,,,\n")
        );
    }
}

/// A time past the year 9999 has no UTC date the table can write: the
/// whole table is refused, and nothing of it is returned.
#[test]
fn a_time_past_the_year_9999_is_refused() {
    let good = failed(POLLED, RouterUnavailableReason::Unreachable);
    let late = failed(LAST_SECOND + 1, RouterUnavailableReason::Unreachable);
    assert_eq!(samples_table(&[good, late]), Err(ModelError::InvalidDate));
    assert_eq!(
        samples_table(&[failed(u64::MAX, RouterUnavailableReason::Unreachable)]),
        Err(ModelError::InvalidDate)
    );
    let event = |secs| RadioEvent {
        at: at(secs),
        kind: RadioEventKind::PollRecovered,
    };
    assert_eq!(
        events_table(&[event(POLLED), event(LAST_SECOND + 1)]),
        Err(ModelError::InvalidDate)
    );
}

// --- Event rows -------------------------------------------------------------

#[test]
fn an_event_holds_its_name_and_what_changed() {
    let stamp = "1791919200,2026-10-13T19:20:00Z";
    let lte = Band::Lte(BandNumber::new(3).unwrap());
    let nr = Band::Nr(BandNumber::new(78).unwrap());
    let rows = [
        (
            RadioEventKind::PollFailed {
                reason: RouterUnavailableReason::AuthFailed,
            },
            "poll_failed,auth_failed,,",
        ),
        (RadioEventKind::PollRecovered, "poll_recovered,,,"),
        (RadioEventKind::RouterRebooted, "router_rebooted,,,"),
        (RadioEventKind::ServiceLost, "service_lost,,,"),
        (RadioEventKind::ServiceRegained, "service_regained,,,"),
        (
            RadioEventKind::NetworkServiceChanged {
                from: NetworkService::Nr5g,
                to: NetworkService::Lte,
            },
            "network_service_changed,,nr5g,lte",
        ),
        (
            RadioEventKind::DataServiceChanged {
                from: DataService::NrSub6,
                to: DataService::LtePlus,
            },
            "data_service_changed,,nr_sub6,lte_plus",
        ),
        (
            RadioEventKind::BandChanged { from: nr, to: lte },
            "band_changed,,n78,B3",
        ),
        (
            RadioEventKind::PlmnChanged {
                from: plmn("30"),
                to: plmn("20"),
            },
            "plmn_changed,,234-30,234-20",
        ),
        (RadioEventKind::SessionRestarted, "session_restarted,,,"),
    ];
    for (kind, rest) in rows {
        let row = event_row(kind);
        assert_eq!(row, format!("{stamp},{rest}"));
        // The name is the JSON document's.
        assert_eq!(row.split(',').nth(2).unwrap(), json_name(&kind));
    }
    // Every reason a failed poll's event can name.
    for reason in REASONS {
        let row = event_row(RadioEventKind::PollFailed { reason });
        assert_eq!(row.split(',').nth(3).unwrap(), json_name(&reason));
    }
    // The other direction of a change is not the same row.
    assert_eq!(
        event_row(RadioEventKind::BandChanged { from: lte, to: nr }),
        format!("{stamp},band_changed,,B3,n78")
    );
    assert_eq!(
        event_row(RadioEventKind::NetworkServiceChanged {
            from: NetworkService::Lte,
            to: NetworkService::Nr5g,
        }),
        format!("{stamp},network_service_changed,,lte,nr5g")
    );
    assert_eq!(
        event_row(RadioEventKind::DataServiceChanged {
            from: DataService::Lte,
            to: DataService::NrSub6,
        }),
        format!("{stamp},data_service_changed,,lte,nr_sub6")
    );
    assert_eq!(
        event_row(RadioEventKind::PlmnChanged {
            from: plmn("20"),
            to: plmn("30"),
        }),
        format!("{stamp},plmn_changed,,234-20,234-30")
    );
}

// --- Reading a table back ---------------------------------------------------

fn named<T: DeserializeOwned>(cell: &str) -> T {
    serde_json::from_value(Value::String(cell.to_owned())).unwrap()
}

/// A reading's cell, back in tenths.
fn reading<T: TryFrom<i16>>(cell: &str) -> Option<T>
where
    T::Error: fmt::Debug,
{
    if cell.is_empty() {
        return None;
    }
    let (whole, tenth) = cell.split_once('.').unwrap();
    assert_eq!(tenth.len(), 1, "{cell}");
    let magnitude: i16 =
        whole.trim_start_matches('-').parse::<i16>().unwrap() * 10 + tenth.parse::<i16>().unwrap();
    let value = if whole.starts_with('-') {
        -magnitude
    } else {
        magnitude
    };
    Some(T::try_from(value).unwrap())
}

fn codes(cell: &str) -> Plmn {
    let (mcc, mnc) = cell.split_once('-').unwrap();
    Plmn {
        mcc: Mcc::parse(mcc).unwrap(),
        mnc: Mnc::parse(mnc).unwrap(),
    }
}

/// The time of a row: its seconds, which its UTC stamp must name too.
fn time(cells: &[&str]) -> UnixTime {
    let secs: u64 = cells[0].parse().unwrap();
    let (date, of_day) = cells[1].split_once('T').unwrap();
    let of_day = of_day.strip_suffix('Z').unwrap();
    let parts: Vec<u64> = of_day
        .split(':')
        .map(|part| {
            assert_eq!(part.len(), 2, "{of_day}");
            part.parse().unwrap()
        })
        .collect();
    assert_eq!(parts.len(), 3);
    assert!(parts[0] < 24 && parts[1] < 60 && parts[2] < 60);
    let start = CalendarDate::parse(date).unwrap().utc_start().as_secs();
    assert_eq!(start + parts[0] * 3_600 + parts[1] * 60 + parts[2], secs);
    at(secs)
}

/// The sample a row was made from, read back independently of the code
/// that wrote it; panics on a row no sample gives.
fn sample_of(row: &str) -> RadioSample {
    let cells: Vec<&str> = row.split(',').collect();
    assert_eq!(cells.len(), SAMPLE_COLUMNS.len(), "{row}");
    let empty = |cells: &[&str]| cells.iter().all(|cell| cell.is_empty());
    let poll = match cells[2] {
        "failed" => {
            assert!(empty(&cells[4..]), "{row}");
            RadioPoll::Failed {
                reason: named(cells[3]),
            }
        }
        "read" => {
            assert_eq!(cells[3], "", "{row}");
            let radio = match cells[7] {
                "no_service" => {
                    assert!(empty(&cells[8..]), "{row}");
                    SampledRadio::NoService
                }
                "attached" => SampledRadio::Attached(SampledAttachment {
                    network_service: named(cells[8]),
                    data_service: named(cells[9]),
                    band: Band::parse(cells[10]).unwrap(),
                    ca_secondary_count: cells[11].parse().unwrap(),
                    lte: LteSignal {
                        rsrp: reading(cells[12]),
                        rsrq: reading(cells[13]),
                        sinr: reading(cells[14]),
                        rssi: reading(cells[15]),
                    },
                    nr: NrSignal {
                        rsrp: reading(cells[16]),
                        rsrq: reading(cells[17]),
                        sinr: reading(cells[18]),
                    },
                    plmn: codes(cells[19]),
                    session_secs: cells[20].parse().unwrap(),
                }),
                other => panic!("service {other:?} in {row}"),
            };
            RadioPoll::Read(RadioReading {
                uptime_secs: cells[4].parse().unwrap(),
                temperature_c: Celsius::new(cells[5].parse().unwrap()).unwrap(),
                thermal: named(cells[6]),
                radio,
            })
        }
        other => panic!("outcome {other:?} in {row}"),
    };
    RadioSample {
        at: time(&cells),
        poll,
    }
}

/// The event a row was made from, read back independently.
fn event_of(row: &str) -> RadioEvent {
    let cells: Vec<&str> = row.split(',').collect();
    assert_eq!(cells.len(), EVENT_COLUMNS.len(), "{row}");
    let (reason, from, to) = (cells[3], cells[4], cells[5]);
    let plain = |kind| {
        assert!(
            reason.is_empty() && from.is_empty() && to.is_empty(),
            "{row}"
        );
        kind
    };
    let kind = match cells[2] {
        "poll_failed" => {
            assert!(from.is_empty() && to.is_empty(), "{row}");
            RadioEventKind::PollFailed {
                reason: named(reason),
            }
        }
        "poll_recovered" => plain(RadioEventKind::PollRecovered),
        "router_rebooted" => plain(RadioEventKind::RouterRebooted),
        "service_lost" => plain(RadioEventKind::ServiceLost),
        "service_regained" => plain(RadioEventKind::ServiceRegained),
        "session_restarted" => plain(RadioEventKind::SessionRestarted),
        changed => {
            assert!(reason.is_empty(), "{row}");
            match changed {
                "network_service_changed" => RadioEventKind::NetworkServiceChanged {
                    from: named(from),
                    to: named(to),
                },
                "data_service_changed" => RadioEventKind::DataServiceChanged {
                    from: named(from),
                    to: named(to),
                },
                "band_changed" => RadioEventKind::BandChanged {
                    from: Band::parse(from).unwrap(),
                    to: Band::parse(to).unwrap(),
                },
                "plmn_changed" => RadioEventKind::PlmnChanged {
                    from: codes(from),
                    to: codes(to),
                },
                other => panic!("event {other:?} in {row}"),
            }
        }
    };
    RadioEvent {
        at: time(&cells),
        kind,
    }
}

/// The rows of `table` after `header`, each without its newline; the
/// table must end with one.
fn rows<'a>(table: &'a str, header: &str) -> Vec<&'a str> {
    let body = table.strip_suffix('\n').unwrap();
    let mut lines = body.split('\n');
    assert_eq!(lines.next(), Some(header));
    lines.collect()
}

/// Every cell is made of letters, digits and `_ . : -`, so no cell can
/// hold the comma that ends it, a quote or a line's end.
fn cell_text(cell: &str) -> bool {
    cell.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

proptest! {
    #[test]
    fn a_samples_table_reads_back_as_its_samples(samples in proptest::collection::vec(any_sample(), 0..40)) {
        let table = samples_table(&samples).unwrap();
        let rows = rows(&table, SAMPLES_HEADER);
        prop_assert_eq!(rows.len(), samples.len());
        for (row, sample) in rows.iter().zip(&samples) {
            prop_assert_eq!(row.matches(',').count(), SAMPLE_COLUMNS.len() - 1);
            prop_assert!(row.split(',').all(cell_text), "{}", row);
            prop_assert_eq!(&sample_of(row), sample);
        }
    }

    #[test]
    fn an_events_table_reads_back_as_its_events(samples in proptest::collection::vec(any_sample(), 0..40)) {
        let found = events(&samples);
        let table = events_table(&found).unwrap();
        let rows = rows(&table, EVENTS_HEADER);
        prop_assert_eq!(rows.len(), found.len());
        for (row, event) in rows.iter().zip(&found) {
            prop_assert_eq!(row.matches(',').count(), EVENT_COLUMNS.len() - 1);
            prop_assert!(row.split(',').all(cell_text), "{}", row);
            prop_assert_eq!(&event_of(row), event);
        }
    }
}
