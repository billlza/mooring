// SPDX-License-Identifier: GPL-3.0-or-later

//! The radio history (design §15.6 rule 11): the sample a poll leaves, its
//! line, the faults a line can have, the events and hourly statistics the
//! samples give, the `router history --json` document, and the error kinds.

use std::fmt;

use mooring_model::{CalendarDate, UnixTime};
use proptest::prelude::*;
use serde_json::Value;

use super::router::status;
use crate::error::{RadioHistoryError, RadioHistoryErrorKind};
use crate::radio_history::{
    HourBin, MAX_RADIO_LINE_BYTES, RADIO_HISTORY_VERSION, RADIO_SAMPLE_VERSION, RadioEvent,
    RadioEventKind, RadioHistory, RadioPoll, RadioReading, RadioSample, SampledAttachment,
    SampledRadio, Stats, decode_line, encode_line, events, hourly,
};
use crate::router::{
    Band, BandNumber, CarrierName, Celsius, DataService, FirmwareVersion, LteSignal, Mcc, Mnc,
    NetworkService, NrSignal, Plmn, RadioState, RouterStatus, RouterUnavailableReason, Rsrp, Rsrq,
    Rssi, Sinr, ThermalState, WebAppVersion,
};

/// 2026-10-13 19:20:00 UTC, the M2a poll.
const POLLED: u64 = 1_791_919_200;

/// The M2a status's sample line, byte for byte.
const READ_LINE: &str = concat!(
    r#"{"version":1,"at":1791919200,"poll":{"read":{"uptime_secs":359272,"temperature_c":35,"thermal":"normal","#,
    r#""radio":{"attached":{"network_service":"nr5g","data_service":"nr_sub6","band":"B3","ca_secondary_count":0,"#,
    r#""lte":{"rsrp":-1040,"rsrq":-170,"sinr":0,"rssi":-720},"nr":{"rsrp":null,"rsrq":null,"sinr":null},"#,
    r#""plmn":{"mcc":"234","mnc":"30"},"session_secs":359217}}}}}"#,
    "\n"
);

/// A failed poll's line.
const FAILED_LINE: &str =
    "{\"version\":1,\"at\":1791919260,\"poll\":{\"failed\":{\"reason\":\"unreachable\"}}}\n";

/// A poll that read no service.
const NO_SERVICE_LINE: &str = concat!(
    r#"{"version":1,"at":1791919320,"poll":{"read":{"uptime_secs":359392,"temperature_c":35,"thermal":"normal","#,
    r#""radio":"no_service"}}}"#,
    "\n"
);

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

fn date(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

fn band(number: u16) -> Band {
    Band::Lte(BandNumber::new(number).unwrap())
}

fn plmn(mnc: &str) -> Plmn {
    Plmn {
        mcc: Mcc::parse("234").unwrap(),
        mnc: Mnc::parse(mnc).unwrap(),
    }
}

/// What an attached sample varies in these tests.
#[derive(Debug, Clone, Copy)]
struct Attached {
    service: NetworkService,
    data: DataService,
    band: u16,
    mnc: &'static str,
    uptime: u64,
    session: u64,
    rsrp: Option<i16>,
    sinr: Option<i16>,
}

impl Default for Attached {
    fn default() -> Self {
        Self {
            service: NetworkService::Lte,
            data: DataService::LtePlus,
            band: 3,
            mnc: "30",
            uptime: 10_000,
            session: 9_000,
            rsrp: Some(-1_000),
            sinr: Some(20),
        }
    }
}

fn reading(uptime: u64, radio: SampledRadio) -> RadioReading {
    RadioReading {
        uptime_secs: uptime,
        temperature_c: Celsius::new(35).unwrap(),
        thermal: ThermalState::Normal,
        radio,
    }
}

fn attached(secs: u64, attached: Attached) -> RadioSample {
    RadioSample {
        at: at(secs),
        poll: RadioPoll::Read(reading(
            attached.uptime,
            SampledRadio::Attached(SampledAttachment {
                network_service: attached.service,
                data_service: attached.data,
                band: band(attached.band),
                ca_secondary_count: 0,
                lte: LteSignal {
                    rsrp: attached
                        .rsrp
                        .map(|tenths| Rsrp::from_tenths(tenths).unwrap()),
                    rsrq: Some(Rsrq::from_tenths(-120).unwrap()),
                    sinr: attached
                        .sinr
                        .map(|tenths| Sinr::from_tenths(tenths).unwrap()),
                    rssi: Some(Rssi::from_tenths(-690).unwrap()),
                },
                nr: NrSignal {
                    rsrp: None,
                    rsrq: None,
                    sinr: None,
                },
                plmn: plmn(attached.mnc),
                session_secs: attached.session,
            }),
        )),
    }
}

fn no_service(secs: u64, uptime: u64) -> RadioSample {
    RadioSample {
        at: at(secs),
        poll: RadioPoll::Read(reading(uptime, SampledRadio::NoService)),
    }
}

fn failed(secs: u64, reason: RouterUnavailableReason) -> RadioSample {
    RadioSample {
        at: at(secs),
        poll: RadioPoll::Failed { reason },
    }
}

fn kinds(samples: &[RadioSample]) -> Vec<(u64, RadioEventKind)> {
    events(samples)
        .into_iter()
        .map(|event| (event.at.as_secs(), event.kind))
        .collect()
}

fn text(line: &[u8]) -> String {
    String::from_utf8(line.to_vec()).unwrap()
}

// --- The sample -----------------------------------------------------------

/// The sample keeps the readings, the service and band, the PLMN, the
/// session and uptime, the temperature and thermal state; the network's
/// name, the carrier list, the counters, power, Wi-Fi, settings and SMS
/// count never reach it, and a failed poll is recorded with its reason.
#[test]
fn the_sample_keeps_the_radio_and_drops_the_rest_of_the_status() {
    let sample = RadioSample::of(at(POLLED), Ok(&status()));
    assert_eq!(
        sample,
        RadioSample {
            at: at(POLLED),
            poll: RadioPoll::Read(RadioReading {
                uptime_secs: 359_272,
                temperature_c: Celsius::new(35).unwrap(),
                thermal: ThermalState::Normal,
                radio: SampledRadio::Attached(SampledAttachment {
                    network_service: NetworkService::Nr5g,
                    data_service: DataService::NrSub6,
                    band: band(3),
                    ca_secondary_count: 0,
                    lte: LteSignal {
                        rsrp: Some(Rsrp::from_tenths(-1040).unwrap()),
                        rsrq: Some(Rsrq::from_tenths(-170).unwrap()),
                        sinr: Some(Sinr::from_tenths(0).unwrap()),
                        rssi: Some(Rssi::from_tenths(-720).unwrap()),
                    },
                    nr: NrSignal {
                        rsrp: None,
                        rsrq: None,
                        sinr: None,
                    },
                    plmn: plmn("30"),
                    session_secs: 359_217,
                }),
            }),
        }
    );
    let line = text(&encode_line(&sample).unwrap());
    for dropped in [
        "CMLink",
        "\"network\"",
        "lte_carriers",
        "dl_bandwidth",
        "firmware",
        "web_app",
        "sim_spn",
        "counters",
        "rx_bytes",
        "power",
        "battery",
        "wifi",
        "settings",
        "unread_sms",
    ] {
        assert!(!line.contains(dropped), "{dropped} in {line}");
    }
    let mut parts = status().into_parts();
    parts.radio = RadioState::NoService;
    let sample = RadioSample::of(at(POLLED), Ok(&RouterStatus::new(parts).unwrap()));
    assert!(matches!(
        sample.poll,
        RadioPoll::Read(RadioReading {
            radio: SampledRadio::NoService,
            uptime_secs: 359_272,
            ..
        })
    ));
    assert_eq!(
        RadioSample::of(at(POLLED), Err(RouterUnavailableReason::AuthFailed)),
        failed(POLLED, RouterUnavailableReason::AuthFailed)
    );
}

/// Canaries in every text the status carries (the network's and the SIM's
/// names, the firmware and web app versions) reach neither the sample's
/// line nor its `Debug`.
#[test]
fn no_text_of_the_status_reaches_a_sample() {
    let mut parts = status().into_parts();
    parts.firmware = FirmwareVersion::parse("canary-fw-1").unwrap();
    parts.web_app = Some(WebAppVersion::parse("canary-web-2").unwrap());
    parts.sim_spn = Some(CarrierName::parse("canary-sim-3").unwrap());
    if let RadioState::Attached(radio) = &mut parts.radio {
        radio.network = CarrierName::parse("canary-net-4").unwrap();
    }
    let sample = RadioSample::of(at(POLLED), Ok(&RouterStatus::new(parts).unwrap()));
    let line = text(&encode_line(&sample).unwrap());
    let debug = format!("{sample:?}");
    for canary in [
        "canary-fw-1",
        "canary-web-2",
        "canary-sim-3",
        "canary-net-4",
    ] {
        assert!(!line.contains(canary), "{canary} in the line");
        assert!(!debug.contains(canary), "{canary} in Debug");
    }
}

// --- The line -------------------------------------------------------------

/// A sample's line is one compact JSON document, its version first, ended
/// by a newline; every sample shape has a fixed encoding, and decoding its
/// line gives the sample back.
#[test]
fn the_three_sample_shapes_have_fixed_lines() {
    assert_eq!(RADIO_SAMPLE_VERSION, 1);
    assert_eq!(MAX_RADIO_LINE_BYTES, 1024);
    let read = RadioSample::of(at(POLLED), Ok(&status()));
    let unreachable = failed(POLLED + 60, RouterUnavailableReason::Unreachable);
    let none = no_service(POLLED + 120, 359_392);
    for (sample, expected) in [
        (read, READ_LINE),
        (unreachable, FAILED_LINE),
        (none, NO_SERVICE_LINE),
    ] {
        let line = encode_line(&sample).unwrap();
        assert_eq!(text(&line), expected);
        assert!(line.len() <= MAX_RADIO_LINE_BYTES);
        assert_eq!(line.iter().filter(|&&byte| byte == b'\n').count(), 1);
        assert_eq!(decode_line(&line).unwrap(), sample);
    }
}

/// Each fault of a line is typed, and no fault carries a byte of the line.
#[test]
fn each_line_fault_is_typed_and_carries_no_bytes() {
    let body = READ_LINE.strip_suffix('\n').unwrap();
    let padded = |total: usize| {
        let mut line = body.to_owned();
        line.push_str(&" ".repeat(total - body.len() - 1));
        line.push('\n');
        line
    };
    assert_eq!(
        decode_line(padded(MAX_RADIO_LINE_BYTES + 1).as_bytes()),
        Err(RadioHistoryError::LineTooLong {
            bytes: MAX_RADIO_LINE_BYTES + 1
        })
    );
    assert!(decode_line(padded(MAX_RADIO_LINE_BYTES).as_bytes()).is_ok());
    for undecodable in [
        "not json\n",
        "\n",
        "",
        // The newline is part of the line: without it the line is not whole.
        body,
        &READ_LINE.replace("\"rsrp\":-1040", "\"rsrp\":-1570"),
        &READ_LINE.replace("\"band\":\"B3\"", "\"band\":\"B0\""),
        &READ_LINE.replace("\"session_secs\":359217", "\"session_secs\":-1"),
        &READ_LINE.replace(",\"rssi\":-720", ""),
        &READ_LINE.replace("\"thermal\":\"normal\",", ""),
        &READ_LINE.replace(
            "\"ca_secondary_count\"",
            "\"cell_id\":\"0x1a2b\",\"ca_secondary_count\"",
        ),
        &READ_LINE.replace(
            "\"at\":1791919200",
            "\"at\":1791919200,\"imei\":\"356938035643809\"",
        ),
        &FAILED_LINE.replace("\"unreachable\"", "\"cell_id\""),
        &READ_LINE.replace("\"version\":1", "\"version\":\"1\""),
        &READ_LINE.replace("\"version\":1,", ""),
    ] {
        assert_eq!(
            decode_line(undecodable.as_bytes()),
            Err(RadioHistoryError::Undecodable),
            "{undecodable}"
        );
    }
    // Another version is refused as such, whatever keys it adds or lacks.
    for (newer, version) in [
        (READ_LINE.replace("\"version\":1", "\"version\":2"), 2),
        ("{\"version\":2,\"future_key\":true}\n".to_owned(), 2),
        ("{\"version\":0}\n".to_owned(), 0),
    ] {
        assert_eq!(
            decode_line(newer.as_bytes()),
            Err(RadioHistoryError::UnsupportedVersion { version }),
            "{newer}"
        );
    }
    // A line of canaries leaves no trace in the error's text.
    let error = decode_line(b"{\"version\":1,\"canary-line-9\":true}\n").unwrap_err();
    assert!(!format!("{error} {error:?}").contains("canary"));
}

// --- Events ---------------------------------------------------------------

#[test]
fn equal_adjacent_samples_give_no_event() {
    let same = attached(100, Attached::default());
    assert_eq!(events(&[same, same, same]), []);
    assert_eq!(events(&[same]), []);
    assert_eq!(events(&[]), []);
    assert_eq!(
        events(&[
            failed(100, RouterUnavailableReason::Unreachable),
            failed(160, RouterUnavailableReason::Unreachable),
        ]),
        []
    );
    assert_eq!(events(&[no_service(100, 50), no_service(160, 110)]), []);
}

/// A failed poll is an event at the poll that failed, once while its
/// reason lasts, again when the reason changes; the first read after it is
/// the recovery. The first sample of a history is never an event.
#[test]
fn a_failed_poll_and_its_recovery_are_events() {
    let first = attached(100, Attached::default());
    let samples = [
        first,
        failed(160, RouterUnavailableReason::Unreachable),
        failed(220, RouterUnavailableReason::Unreachable),
        failed(280, RouterUnavailableReason::AuthFailed),
        attached(340, Attached::default()),
    ];
    assert_eq!(
        kinds(&samples),
        [
            (
                160,
                RadioEventKind::PollFailed {
                    reason: RouterUnavailableReason::Unreachable
                }
            ),
            (
                280,
                RadioEventKind::PollFailed {
                    reason: RouterUnavailableReason::AuthFailed
                }
            ),
            (340, RadioEventKind::PollRecovered),
        ]
    );
    assert_eq!(
        kinds(&[
            failed(100, RouterUnavailableReason::Unreachable),
            attached(160, Attached::default())
        ]),
        [(160, RadioEventKind::PollRecovered)]
    );
}

/// A change of the network service, the data service, the band or the PLMN
/// is an event at the sample that shows it, with the values before and
/// after; several at one sample come in a fixed order.
#[test]
fn radio_changes_are_events_in_a_fixed_order() {
    let before = Attached {
        service: NetworkService::Nr5g,
        data: DataService::NrSub6,
        ..Attached::default()
    };
    let samples = [
        attached(100, before),
        attached(160, Attached::default()),
        attached(220, Attached::default()),
        attached(
            280,
            Attached {
                band: 20,
                mnc: "20",
                ..Attached::default()
            },
        ),
    ];
    assert_eq!(
        kinds(&samples),
        [
            (
                160,
                RadioEventKind::NetworkServiceChanged {
                    from: NetworkService::Nr5g,
                    to: NetworkService::Lte,
                }
            ),
            (
                160,
                RadioEventKind::DataServiceChanged {
                    from: DataService::NrSub6,
                    to: DataService::LtePlus,
                }
            ),
            (
                280,
                RadioEventKind::BandChanged {
                    from: band(3),
                    to: band(20),
                }
            ),
            (
                280,
                RadioEventKind::PlmnChanged {
                    from: plmn("30"),
                    to: plmn("20"),
                }
            ),
        ]
    );
    // The NR band is a band too.
    let nr = RadioSample {
        at: at(340),
        poll: match attached(340, Attached::default()).poll {
            RadioPoll::Read(mut reading) => {
                if let SampledRadio::Attached(radio) = &mut reading.radio {
                    radio.band = Band::Nr(BandNumber::new(78).unwrap());
                }
                RadioPoll::Read(reading)
            }
            RadioPoll::Failed { .. } => unreachable!(),
        },
    };
    assert_eq!(
        kinds(&[attached(280, Attached::default()), nr]),
        [(
            340,
            RadioEventKind::BandChanged {
                from: band(3),
                to: Band::Nr(BandNumber::new(78).unwrap()),
            }
        )]
    );
}

/// No service between two attached samples is a loss and a regain; the
/// regain is compared with the no-service sample, so a band or PLMN that
/// differs across the gap is no event.
#[test]
fn no_service_between_attached_samples_is_a_loss_and_a_regain() {
    let samples = [
        attached(100, Attached::default()),
        no_service(160, 10_060),
        no_service(220, 10_120),
        attached(
            280,
            Attached {
                band: 20,
                mnc: "20",
                uptime: 10_180,
                session: 30,
                ..Attached::default()
            },
        ),
    ];
    assert_eq!(
        kinds(&samples),
        [
            (160, RadioEventKind::ServiceLost),
            (280, RadioEventKind::ServiceRegained),
        ]
    );
    assert_eq!(
        kinds(&[no_service(100, 50), attached(160, Attached::default())]),
        [(160, RadioEventKind::ServiceRegained)]
    );
}

/// A session that is shorter than at the last read restarted; an uptime
/// that is shorter is a reboot, which says enough: the session restarted
/// with it and is not reported again. Both compare with the last *read*
/// sample, across failed polls, which is where a reboot hides.
#[test]
fn a_shorter_session_or_uptime_is_a_restart_or_a_reboot() {
    let samples = [
        attached(
            100,
            Attached {
                uptime: 10_000,
                session: 9_000,
                ..Attached::default()
            },
        ),
        attached(
            160,
            Attached {
                uptime: 10_060,
                session: 20,
                ..Attached::default()
            },
        ),
        failed(220, RouterUnavailableReason::Unreachable),
        failed(280, RouterUnavailableReason::Unreachable),
        attached(
            340,
            Attached {
                uptime: 40,
                session: 10,
                ..Attached::default()
            },
        ),
        attached(
            400,
            Attached {
                uptime: 100,
                session: 70,
                ..Attached::default()
            },
        ),
    ];
    assert_eq!(
        kinds(&samples),
        [
            (160, RadioEventKind::SessionRestarted),
            (
                220,
                RadioEventKind::PollFailed {
                    reason: RouterUnavailableReason::Unreachable
                }
            ),
            (340, RadioEventKind::PollRecovered),
            (340, RadioEventKind::RouterRebooted),
        ]
    );
    // A band that changed behind the failed polls is seen on recovery too,
    // in the order: recovery, reboot, then the radio's changes.
    let behind = [
        attached(100, Attached::default()),
        failed(160, RouterUnavailableReason::Unreachable),
        attached(
            220,
            Attached {
                band: 20,
                uptime: 5,
                session: 5,
                ..Attached::default()
            },
        ),
    ];
    assert_eq!(
        kinds(&behind),
        [
            (
                160,
                RadioEventKind::PollFailed {
                    reason: RouterUnavailableReason::Unreachable
                }
            ),
            (220, RadioEventKind::PollRecovered),
            (220, RadioEventKind::RouterRebooted),
            (
                220,
                RadioEventKind::BandChanged {
                    from: band(3),
                    to: band(20),
                }
            ),
        ]
    );
}

/// Events follow the samples' order (the poll order), not their times: a
/// clock that stepped back does not reorder them.
#[test]
fn events_follow_the_sample_order_when_the_clock_stepped_back() {
    let samples = [
        attached(
            1_000,
            Attached {
                service: NetworkService::Nr5g,
                ..Attached::default()
            },
        ),
        attached(500, Attached::default()),
    ];
    assert_eq!(
        kinds(&samples),
        [(
            500,
            RadioEventKind::NetworkServiceChanged {
                from: NetworkService::Nr5g,
                to: NetworkService::Lte,
            }
        )]
    );
}

// --- Hourly statistics ----------------------------------------------------

const HOUR: u64 = 3_600;
/// 2026-10-13 19:00:00 UTC.
const NINETEEN: u64 = POLLED - 20 * 60;

fn with_readings(secs: u64, rsrp: Option<i16>, sinr: Option<i16>) -> RadioSample {
    attached(
        secs,
        Attached {
            rsrp,
            sinr,
            ..Attached::default()
        },
    )
}

/// A bin holds the minimum, the lower median and the maximum of the readings
/// present; a reading not reported is skipped, never read as zero; a count
/// of polls and of reads; and the services seen.
#[test]
fn hourly_bins_hold_min_median_max_over_the_readings_present() {
    let samples = [
        with_readings(NINETEEN, Some(-1040), Some(0)),
        with_readings(NINETEEN + 20 * 60, None, Some(50)),
        with_readings(NINETEEN + 40 * 60, Some(-900), None),
        with_readings(NINETEEN + HOUR - 1, Some(-1000), Some(20)),
    ];
    let stats = |min: i16, median: i16, max: i16| Stats {
        min: Rsrp::from_tenths(min).unwrap(),
        median: Rsrp::from_tenths(median).unwrap(),
        max: Rsrp::from_tenths(max).unwrap(),
    };
    let bins = hourly(&samples);
    assert_eq!(
        bins,
        [HourBin {
            start: at(NINETEEN),
            polls: 4,
            read: 4,
            no_service: 0,
            services: vec![NetworkService::Lte],
            lte_rsrp: Some(stats(-1040, -1000, -900)),
            lte_sinr: Some(Stats {
                min: Sinr::from_tenths(0).unwrap(),
                median: Sinr::from_tenths(20).unwrap(),
                max: Sinr::from_tenths(50).unwrap(),
            }),
            nr_rsrp: None,
            nr_sinr: None,
        }]
    );
    // An even count takes the lower middle value, an observed reading.
    let mut even = samples.to_vec();
    even.push(with_readings(NINETEEN + 50 * 60, Some(-950), None));
    assert_eq!(hourly(&even)[0].lte_rsrp, Some(stats(-1040, -1000, -900)));
    assert_eq!(hourly(&even)[0].polls, 5);
    // A single reading is its own minimum, median and maximum.
    assert_eq!(
        hourly(&samples[..1])[0].lte_rsrp,
        Some(stats(-1040, -1040, -1040))
    );
}

/// Failed polls and no-service reads count in their hour and give no
/// reading; the services seen are listed once each, in the vocabulary's
/// order.
#[test]
fn failed_polls_and_no_service_count_without_readings() {
    let samples = [
        with_readings(NINETEEN, Some(-1040), Some(0)),
        failed(NINETEEN + 60, RouterUnavailableReason::Unreachable),
        no_service(NINETEEN + 120, 10_120),
        attached(
            NINETEEN + 180,
            Attached {
                service: NetworkService::Nr5g,
                rsrp: Some(-800),
                sinr: Some(100),
                ..Attached::default()
            },
        ),
        attached(NINETEEN + 240, Attached::default()),
    ];
    let bin = &hourly(&samples)[0];
    assert_eq!((bin.polls, bin.read, bin.no_service), (5, 4, 1));
    assert_eq!(bin.services, [NetworkService::Nr5g, NetworkService::Lte]);
    assert_eq!(bin.lte_rsrp.unwrap().max, Rsrp::from_tenths(-800).unwrap());
    assert_eq!(bin.lte_sinr.unwrap().min, Sinr::from_tenths(0).unwrap());
    let only_failures = hourly(&[
        failed(NINETEEN, RouterUnavailableReason::Unreachable),
        no_service(NINETEEN + 60, 60),
    ]);
    assert_eq!(
        only_failures,
        [HourBin {
            start: at(NINETEEN),
            polls: 2,
            read: 1,
            no_service: 1,
            services: Vec::new(),
            lte_rsrp: None,
            lte_sinr: None,
            nr_rsrp: None,
            nr_sinr: None,
        }]
    );
}

/// Bins start on the hour, hold only the hours with a sample, and come in
/// time order whatever the samples' order; the same hour of two days is
/// two bins.
#[test]
fn empty_hours_are_omitted_and_bins_are_hour_aligned() {
    let ten = NINETEEN - 9 * HOUR;
    let samples = [
        with_readings(ten + 30 * 60, Some(-1000), None),
        with_readings(ten + 2 * HOUR + 15 * 60, Some(-1000), None),
        with_readings(ten + 2 * HOUR + 45 * 60, Some(-1000), None),
        with_readings(ten + HOUR - 1, Some(-1000), None),
        with_readings(ten + HOUR, Some(-1000), None),
        with_readings(ten + 24 * HOUR + 10, Some(-1000), None),
    ];
    let starts: Vec<(u64, usize)> = hourly(&samples)
        .iter()
        .map(|bin| (bin.start.as_secs(), bin.polls))
        .collect();
    assert_eq!(
        starts,
        [
            (ten, 2),
            (ten + HOUR, 1),
            (ten + 2 * HOUR, 2),
            (ten + 24 * HOUR, 1)
        ]
    );
    let mut shuffled = samples.to_vec();
    shuffled.reverse();
    assert_eq!(hourly(&shuffled), hourly(&samples));
    assert_eq!(hourly(&[]), []);
}

/// The NR readings have their own statistics, present only when an NR
/// reading was reported.
#[test]
fn nr_readings_have_their_own_statistics() {
    let mut sample = attached(NINETEEN, Attached::default());
    if let RadioPoll::Read(RadioReading {
        radio: SampledRadio::Attached(radio),
        ..
    }) = &mut sample.poll
    {
        radio.nr = NrSignal {
            rsrp: Some(Rsrp::from_tenths(-850).unwrap()),
            rsrq: Some(Rsrq::from_tenths(-100).unwrap()),
            sinr: None,
        };
    }
    let bin = &hourly(&[sample])[0];
    assert_eq!(
        bin.nr_rsrp,
        Some(Stats {
            min: Rsrp::from_tenths(-850).unwrap(),
            median: Rsrp::from_tenths(-850).unwrap(),
            max: Rsrp::from_tenths(-850).unwrap(),
        })
    );
    assert_eq!(bin.nr_sinr, None);
}

// --- The document ---------------------------------------------------------

fn history() -> RadioHistory {
    RadioHistory::new(
        date("2026-10-12"),
        date("2026-10-13"),
        vec![
            attached(
                POLLED,
                Attached {
                    service: NetworkService::Nr5g,
                    data: DataService::NrSub6,
                    ..Attached::default()
                },
            ),
            failed(POLLED + 60, RouterUnavailableReason::Unreachable),
            attached(POLLED + 120, Attached::default()),
        ],
        vec![date("2026-10-13")],
    )
}

/// The document carries its version, the days asked for, the samples in
/// their order, the events they show and the incomplete days; it has a
/// fixed encoding and reads back equal.
#[test]
fn the_document_has_a_fixed_encoding_and_carries_the_events_of_its_samples() {
    assert_eq!(RADIO_HISTORY_VERSION, 1);
    let history = history();
    assert_eq!(history.since(), date("2026-10-12"));
    assert_eq!(history.until(), date("2026-10-13"));
    assert_eq!(history.samples().len(), 3);
    assert_eq!(history.incomplete_days(), [date("2026-10-13")]);
    assert_eq!(
        history.events(),
        [
            RadioEvent {
                at: at(POLLED + 60),
                kind: RadioEventKind::PollFailed {
                    reason: RouterUnavailableReason::Unreachable,
                },
            },
            RadioEvent {
                at: at(POLLED + 120),
                kind: RadioEventKind::PollRecovered,
            },
            RadioEvent {
                at: at(POLLED + 120),
                kind: RadioEventKind::NetworkServiceChanged {
                    from: NetworkService::Nr5g,
                    to: NetworkService::Lte,
                },
            },
            RadioEvent {
                at: at(POLLED + 120),
                kind: RadioEventKind::DataServiceChanged {
                    from: DataService::NrSub6,
                    to: DataService::LtePlus,
                },
            },
        ]
    );
    let json = serde_json::to_string(&history).unwrap();
    assert!(json.starts_with(
        r#"{"version":1,"since":"2026-10-12","until":"2026-10-13","samples":[{"at":1791919200,"poll":{"read":{"#
    ));
    assert!(json.contains(
        r#"],"events":[{"at":1791919260,"kind":{"poll_failed":{"reason":"unreachable"}}},{"at":1791919320,"kind":"poll_recovered"},{"at":1791919320,"kind":{"network_service_changed":{"from":"nr5g","to":"lte"}}},{"at":1791919320,"kind":{"data_service_changed":{"from":"nr_sub6","to":"lte_plus"}}}],"incomplete_days":["2026-10-13"]}"#
    ), "{json}");
    assert!(!json.contains('\n'));
    assert_eq!(
        serde_json::from_str::<RadioHistory>(&json).unwrap(),
        history
    );
    // The samples carry no version of their own: the document's is the one.
    assert_eq!(json.matches("\"version\"").count(), 1);
}

/// A document of another version, with an unknown key, without a key, or
/// whose events do not follow from its samples is refused.
#[test]
fn a_document_is_version_1_with_every_key_and_its_own_events() {
    let json: Value = serde_json::to_value(history()).unwrap();
    let refused = |document: Value| serde_json::from_value::<RadioHistory>(document).unwrap_err();
    let mut later = json.clone();
    later["version"] = Value::from(2);
    let error = refused(later);
    let expected = RadioHistoryError::UnsupportedDocumentVersion { found: 2 };
    assert!(error.to_string().contains(&expected.to_string()), "{error}");
    assert_eq!(
        expected.kind(),
        RadioHistoryErrorKind::UnsupportedDocumentVersion
    );
    let mut forged = json.clone();
    forged["events"] = Value::Array(Vec::new());
    let error = refused(forged);
    assert!(
        error
            .to_string()
            .contains(&RadioHistoryError::EventsMismatch.to_string()),
        "{error}"
    );
    for key in [
        "version",
        "since",
        "until",
        "samples",
        "events",
        "incomplete_days",
    ] {
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove(key);
        refused(missing);
    }
    let with_extra = |edit: &dyn Fn(&mut Value)| {
        let mut document = json.clone();
        edit(&mut document);
        assert!(serde_json::from_value::<RadioHistory>(document).is_err());
    };
    let insert = |object: &mut Value, key: &str| {
        object
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), Value::from("x"));
    };
    with_extra(&|document| insert(document, "cell_id"));
    with_extra(&|document| insert(&mut document["samples"][0], "cell_id"));
    with_extra(&|document| insert(&mut document["samples"][0]["poll"]["read"], "imei"));
    with_extra(&|document| insert(&mut document["events"][0], "note"));
}

// --- Error kinds ----------------------------------------------------------

/// No error of the history can own a byte of a line: the type is `Copy`.
const _: () = {
    const fn copy<T: Copy>() {}
    copy::<RadioHistoryError>();
};

#[test]
fn every_radio_history_error_kind_is_named_once() {
    let errors = [
        (
            RadioHistoryErrorKind::LineTooLong,
            RadioHistoryError::LineTooLong { bytes: 1025 },
        ),
        (
            RadioHistoryErrorKind::Undecodable,
            RadioHistoryError::Undecodable,
        ),
        (
            RadioHistoryErrorKind::UnsupportedVersion,
            RadioHistoryError::UnsupportedVersion { version: 2 },
        ),
        (
            RadioHistoryErrorKind::UnsupportedDocumentVersion,
            RadioHistoryError::UnsupportedDocumentVersion { found: 2 },
        ),
        (
            RadioHistoryErrorKind::EventsMismatch,
            RadioHistoryError::EventsMismatch,
        ),
        (
            RadioHistoryErrorKind::Unencodable,
            RadioHistoryError::Unencodable,
        ),
    ];
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        RadioHistoryErrorKind::ALL
    );
    for (kind, error) in errors {
        assert_eq!(error.kind(), kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        RadioHistoryError::LineTooLong { bytes: 1025 }.to_string(),
        "a radio history line of 1025 bytes is longer than 1024"
    );
    assert_eq!(
        RadioHistoryError::UnsupportedVersion { version: 2 }.to_string(),
        "a radio history line names sample version 2; this build reads version 1"
    );
}

// --- Properties -----------------------------------------------------------

fn any_reason() -> impl Strategy<Value = RouterUnavailableReason> {
    prop_oneof![
        Just(RouterUnavailableReason::NotConfigured),
        Just(RouterUnavailableReason::Unreachable),
        Just(RouterUnavailableReason::AuthFailed),
        Just(RouterUnavailableReason::IdentityMismatch),
        Just(RouterUnavailableReason::Unsupported),
        Just(RouterUnavailableReason::Malformed),
        Just(RouterUnavailableReason::LocalFailure),
    ]
}

fn any_tenths<T: TryFrom<i16> + fmt::Debug>(
    min: i16,
    max: i16,
) -> impl Strategy<Value = Option<T>> {
    proptest::option::of((min..=max).prop_map(|tenths| match T::try_from(tenths) {
        Ok(value) => value,
        Err(_) => unreachable!("within the range"),
    }))
}

fn any_attached() -> impl Strategy<Value = SampledAttachment> {
    (
        proptest::sample::select(NetworkService::ALL),
        proptest::sample::select(DataService::ALL),
        (1_u16..=999, any::<bool>()),
        0_u8..=6,
        (
            any_tenths::<Rsrp>(Rsrp::MIN_TENTHS, Rsrp::MAX_TENTHS),
            any_tenths::<Rsrq>(Rsrq::MIN_TENTHS, Rsrq::MAX_TENTHS),
            any_tenths::<Sinr>(Sinr::MIN_TENTHS, Sinr::MAX_TENTHS),
            any_tenths::<Rssi>(Rssi::MIN_TENTHS, Rssi::MAX_TENTHS),
        ),
        (
            any_tenths::<Rsrp>(Rsrp::MIN_TENTHS, Rsrp::MAX_TENTHS),
            any_tenths::<Rsrq>(Rsrq::MIN_TENTHS, Rsrq::MAX_TENTHS),
            any_tenths::<Sinr>(Sinr::MIN_TENTHS, Sinr::MAX_TENTHS),
        ),
        proptest::sample::select(&["30", "20", "10", "999"][..]),
        any::<u64>(),
    )
        .prop_map(
            |(
                service,
                data,
                (number, nr),
                count,
                (rsrp, rsrq, sinr, rssi),
                (nrsrp, nrsrq, nsinr),
                mnc,
                session,
            )| {
                let number = BandNumber::new(number).unwrap();
                SampledAttachment {
                    network_service: service,
                    data_service: data,
                    band: if nr {
                        Band::Nr(number)
                    } else {
                        Band::Lte(number)
                    },
                    ca_secondary_count: count,
                    lte: LteSignal {
                        rsrp,
                        rsrq,
                        sinr,
                        rssi,
                    },
                    nr: NrSignal {
                        rsrp: nrsrp,
                        rsrq: nrsrq,
                        sinr: nsinr,
                    },
                    plmn: plmn(mnc),
                    session_secs: session,
                }
            },
        )
}

fn any_sample() -> impl Strategy<Value = RadioSample> {
    let read = (
        any::<u64>(),
        -40_i16..=125,
        prop_oneof![
            Just(SampledRadio::NoService),
            any_attached().prop_map(SampledRadio::Attached)
        ],
    )
        .prop_map(|(uptime, celsius, radio)| {
            RadioPoll::Read(RadioReading {
                uptime_secs: uptime,
                temperature_c: Celsius::new(celsius).unwrap(),
                thermal: ThermalState::Normal,
                radio,
            })
        });
    let failed = any_reason().prop_map(|reason| RadioPoll::Failed { reason });
    (0_u64..=4_102_444_800, prop_oneof![read, failed])
        .prop_map(|(secs, poll)| RadioSample { at: at(secs), poll })
}

/// The changes between a sample and the ones before it, counted by the
/// rule the events follow, written out independently.
fn expected_events(samples: &[RadioSample]) -> usize {
    let mut count = 0;
    let mut previous: Option<&RadioSample> = None;
    let mut last_read: Option<&RadioReading> = None;
    for sample in samples {
        match (&sample.poll, previous.map(|sample| &sample.poll)) {
            (_, None) => {}
            (RadioPoll::Failed { reason }, Some(RadioPoll::Failed { reason: before })) => {
                count += usize::from(reason != before);
            }
            (RadioPoll::Failed { .. }, Some(RadioPoll::Read(_))) => count += 1,
            (RadioPoll::Read(_), Some(RadioPoll::Failed { .. })) => count += 1,
            (RadioPoll::Read(_), Some(RadioPoll::Read(_))) => {}
        }
        if let RadioPoll::Read(reading) = &sample.poll {
            if let Some(before) = last_read {
                let rebooted = reading.uptime_secs < before.uptime_secs;
                count += usize::from(rebooted);
                match (&before.radio, &reading.radio) {
                    (SampledRadio::NoService, SampledRadio::NoService) => {}
                    (SampledRadio::Attached(_), SampledRadio::NoService)
                    | (SampledRadio::NoService, SampledRadio::Attached(_)) => count += 1,
                    (SampledRadio::Attached(a), SampledRadio::Attached(b)) => {
                        count += usize::from(a.network_service != b.network_service)
                            + usize::from(a.data_service != b.data_service)
                            + usize::from(a.band != b.band)
                            + usize::from(a.plmn != b.plmn)
                            + usize::from(b.session_secs < a.session_secs && !rebooted);
                    }
                }
            }
            last_read = Some(reading);
        }
        previous = Some(sample);
    }
    count
}

proptest! {
    #[test]
    fn any_sample_round_trips_through_its_line_within_the_bound(sample in any_sample()) {
        let line = encode_line(&sample).unwrap();
        prop_assert!(line.len() <= MAX_RADIO_LINE_BYTES);
        prop_assert_eq!(line.iter().filter(|&&byte| byte == b'\n').count(), 1);
        prop_assert_eq!(line.last(), Some(&b'\n'));
        prop_assert_eq!(decode_line(&line).unwrap(), sample);
    }

    #[test]
    fn events_count_the_changes_in_sample_order(samples in proptest::collection::vec(any_sample(), 0..40)) {
        let found = events(&samples);
        prop_assert_eq!(found.len(), expected_events(&samples));
        let mut index = 0;
        for event in &found {
            while samples[index].at != event.at {
                index += 1;
            }
        }
        let history = RadioHistory::new(date("2026-10-12"), date("2026-10-13"), samples, Vec::new());
        let json = serde_json::to_string(&history).unwrap();
        prop_assert_eq!(serde_json::from_str::<RadioHistory>(&json).unwrap(), history);
    }

    #[test]
    fn hourly_bins_partition_the_samples(samples in proptest::collection::vec(any_sample(), 0..40)) {
        let bins = hourly(&samples);
        let polls: usize = bins.iter().map(|bin| bin.polls).sum();
        prop_assert_eq!(polls, samples.len());
        for pair in bins.windows(2) {
            prop_assert!(pair[0].start < pair[1].start);
        }
        for bin in &bins {
            prop_assert_eq!(bin.start.as_secs() % HOUR, 0);
            prop_assert!(bin.polls > 0);
            prop_assert!(bin.read <= bin.polls);
            prop_assert!(bin.no_service <= bin.read);
            let in_bin: Vec<&RadioSample> = samples
                .iter()
                .filter(|sample| sample.at.as_secs() / HOUR * HOUR == bin.start.as_secs())
                .collect();
            prop_assert_eq!(in_bin.len(), bin.polls);
            let rsrps: Vec<Rsrp> = in_bin
                .iter()
                .filter_map(|sample| match &sample.poll {
                    RadioPoll::Read(RadioReading { radio: SampledRadio::Attached(radio), .. }) => radio.lte.rsrp,
                    _ => None,
                })
                .collect();
            match bin.lte_rsrp {
                None => prop_assert!(rsrps.is_empty()),
                Some(stats) => {
                    prop_assert!(stats.min <= stats.median && stats.median <= stats.max);
                    prop_assert_eq!(Some(stats.min), rsrps.iter().copied().min());
                    prop_assert_eq!(Some(stats.max), rsrps.iter().copied().max());
                    prop_assert!(rsrps.contains(&stats.median));
                }
            }
        }
        let mut reversed = samples.clone();
        reversed.reverse();
        prop_assert_eq!(hourly(&reversed), bins);
    }
}
