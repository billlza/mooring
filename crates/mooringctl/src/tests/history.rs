// SPDX-License-Identifier: GPL-3.0-or-later

//! `router history` (design §15.6 rule 11): the day files the daemon
//! recorded, read through the store and printed as the document the app
//! reads or as a summary; the range's rules; what a corrupt line does; and
//! that the command never writes.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use clap::Parser;
use mooring_daemon_core::radio_history::{
    RadioHistory, RadioPoll, RadioReading, RadioSample, SampledAttachment, SampledRadio,
    encode_line,
};
use mooring_daemon_core::router::{
    Band, BandNumber, Celsius, DataService, LteSignal, Mcc, Mnc, NetworkService, NrSignal, Plmn,
    RouterUnavailableReason, Rsrp, Rsrq, Rssi, Sinr, ThermalState,
};
use mooring_model::{CalendarDate, UnixTime};
use mooring_store::{RADIO_DIRECTORY, append_radio_line, radio_day_path};

use super::support::{Harness, NOW};
use crate::cli::Cli;
use crate::error::{EXIT_LOCAL, EXIT_USAGE};

/// 2026-10-13 00:00:00 UTC.
const MIDNIGHT: u64 = NOW - 19 * 3600 - 20 * 60;

fn day(text: &str) -> CalendarDate {
    CalendarDate::parse(text).unwrap()
}

fn plmn(mnc: &str) -> Plmn {
    Plmn {
        mcc: Mcc::parse("234").unwrap(),
        mnc: Mnc::parse(mnc).unwrap(),
    }
}

/// An attached read at `secs` after midnight.
#[allow(clippy::too_many_arguments)]
fn attached(
    secs: u64,
    service: NetworkService,
    data: DataService,
    band: u16,
    mnc: &str,
    uptime: u64,
    session: u64,
    rsrp: i16,
    sinr: i16,
) -> RadioSample {
    RadioSample {
        at: UnixTime::from_secs(MIDNIGHT + secs),
        poll: RadioPoll::Read(RadioReading {
            uptime_secs: uptime,
            temperature_c: Celsius::new(35).unwrap(),
            thermal: ThermalState::Normal,
            radio: SampledRadio::Attached(SampledAttachment {
                network_service: service,
                data_service: data,
                band: Band::Lte(BandNumber::new(band).unwrap()),
                ca_secondary_count: 0,
                lte: LteSignal {
                    rsrp: Some(Rsrp::from_tenths(rsrp).unwrap()),
                    rsrq: Some(Rsrq::from_tenths(-120).unwrap()),
                    sinr: Some(Sinr::from_tenths(sinr).unwrap()),
                    rssi: Some(Rssi::from_tenths(-690).unwrap()),
                },
                nr: NrSignal {
                    rsrp: None,
                    rsrq: None,
                    sinr: None,
                },
                plmn: plmn(mnc),
                session_secs: session,
            }),
        }),
    }
}

fn no_service(secs: u64, uptime: u64) -> RadioSample {
    RadioSample {
        at: UnixTime::from_secs(MIDNIGHT + secs),
        poll: RadioPoll::Read(RadioReading {
            uptime_secs: uptime,
            temperature_c: Celsius::new(35).unwrap(),
            thermal: ThermalState::Normal,
            radio: SampledRadio::NoService,
        }),
    }
}

fn failed(secs: u64, reason: RouterUnavailableReason) -> RadioSample {
    RadioSample {
        at: UnixTime::from_secs(MIDNIGHT + secs),
        poll: RadioPoll::Failed { reason },
    }
}

/// The samples of 2026-10-13 the tests plant: every event kind shows once.
fn today() -> Vec<RadioSample> {
    vec![
        attached(
            19 * 3600,
            NetworkService::Nr5g,
            DataService::NrSub6,
            3,
            "30",
            10_000,
            9_000,
            -1040,
            0,
        ),
        failed(19 * 3600 + 60, RouterUnavailableReason::Unreachable),
        attached(
            19 * 3600 + 120,
            NetworkService::Lte,
            DataService::LtePlus,
            3,
            "30",
            10_120,
            9_120,
            -1000,
            20,
        ),
        attached(
            19 * 3600 + 180,
            NetworkService::Lte,
            DataService::LtePlus,
            20,
            "20",
            10_180,
            30,
            -900,
            55,
        ),
        no_service(20 * 3600, 40),
    ]
}

/// Plants `samples` as the day's file, with a torn fragment after them
/// when asked. (The support directory is the daemon's to create; here the
/// test does.)
fn plant(support: &Path, date: CalendarDate, samples: &[RadioSample], torn: bool) {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(support)
        .unwrap();
    for sample in samples {
        append_radio_line(support, date, &encode_line(sample).unwrap()).unwrap();
    }
    if torn {
        let path = radio_day_path(support, date);
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(b"{\"version\":1,\"at\":17");
        fs::write(&path, bytes).unwrap();
    }
}

fn history_dir(harness: &Harness) -> std::path::PathBuf {
    harness.support_dir().join(RADIO_DIRECTORY)
}

/// The document of the default range (yesterday and today, UTC), on one
/// line, exactly as `daemon-core` builds it from the files' samples, with
/// the torn day listed.
#[test]
fn history_json_is_the_document_on_one_line() {
    let mut harness = Harness::new(0);
    let yesterday = [failed(0, RouterUnavailableReason::NotConfigured)];
    plant(&harness.support_dir(), day("2026-10-12"), &yesterday, false);
    plant(&harness.support_dir(), day("2026-10-13"), &today(), true);
    let outcome = harness.run(&["router", "history", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let mut samples = yesterday.to_vec();
    samples.extend(today());
    let expected = RadioHistory::new(
        day("2026-10-12"),
        day("2026-10-13"),
        samples,
        vec![day("2026-10-13")],
    );
    assert_eq!(
        outcome.stdout,
        format!("{}\n", serde_json::to_string(&expected).unwrap())
    );
    assert_eq!(outcome.stdout.matches('\n').count(), 1);
    assert_eq!(
        serde_json::from_str::<RadioHistory>(outcome.stdout.trim_end()).unwrap(),
        expected
    );
    // Today's nine events, and the recovery from yesterday's failed poll.
    assert_eq!(expected.events().len(), 10);
}

/// Without dates the range is yesterday and today; `--since` alone runs to
/// today, `--until` alone from the day before it; days without a file are
/// empty, never an error, and nothing is created for them.
#[test]
fn the_range_defaults_to_yesterday_and_today_and_absent_days_are_empty() {
    let mut harness = Harness::new(0);
    let empty = |since: &str, until: &str| {
        format!(
            "{{\"version\":1,\"since\":\"{since}\",\"until\":\"{until}\",\"samples\":[],\"events\":[],\"incomplete_days\":[]}}\n"
        )
    };
    for (args, since, until) in [
        (vec![], "2026-10-12", "2026-10-13"),
        (
            vec!["--since", "2026-10-01", "--until", "2026-10-05"],
            "2026-10-01",
            "2026-10-05",
        ),
        (vec!["--since", "2026-10-10"], "2026-10-10", "2026-10-13"),
        (vec!["--until", "2026-10-10"], "2026-10-09", "2026-10-10"),
        (
            vec!["--since", "2026-10-13", "--until", "2026-10-13"],
            "2026-10-13",
            "2026-10-13",
        ),
    ] {
        let mut full = vec!["router", "history", "--json"];
        full.extend(args.iter().copied());
        let outcome = harness.run(&full);
        assert_eq!(outcome.code, 0, "{args:?}: {}", outcome.stderr);
        assert_eq!(outcome.stdout, empty(since, until), "{args:?}");
    }
    assert!(!history_dir(&harness).exists());
    let outcome = harness.run(&["router", "history"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "radio history 2026-10-12 to 2026-10-13 UTC: 0 polls, 0 read\n\
         2026-10-12: no samples\n\
         2026-10-13: no samples\n\
         events: none\n"
    );
}

/// A range that runs backwards, or over more days than the daemon keeps,
/// is refused as a local error before any file is read; a date that is not
/// a date is clap's usage error.
#[test]
fn a_range_that_is_inverted_or_too_long_is_refused() {
    let mut harness = Harness::new(0);
    let outcome = harness.run(&[
        "router",
        "history",
        "--since",
        "2026-10-14",
        "--until",
        "2026-10-13",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        "mooringctl: --since 2026-10-14 is after --until 2026-10-13\n"
    );
    let outcome = harness.run(&[
        "router",
        "history",
        "--since",
        "2026-07-14",
        "--until",
        "2026-10-13",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        "mooringctl: the range covers 92 days; at most 90 can be read at once (narrow it with --since and --until)\n"
    );
    let outcome = harness.run(&[
        "router",
        "history",
        "--json",
        "--since",
        "2026-07-16",
        "--until",
        "2026-10-13",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .starts_with("{\"version\":1,\"since\":\"2026-07-16\"")
    );
    let outcome = harness.run(&["router", "history", "--since", "2026-10-14"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: --since 2026-10-14 is after --until 2026-10-13\n"
    );
    let error = Cli::try_parse_from(["mooringctl", "router", "history", "--since", "2026-13-01"])
        .unwrap_err();
    assert_eq!(error.exit_code(), i32::from(EXIT_USAGE));
}

/// A line the decoder refuses is a typed error naming the file and the
/// line, never its bytes; nothing is printed, with or without `--json`.
#[test]
fn a_corrupt_line_is_a_typed_error_naming_file_and_line() {
    let mut harness = Harness::new(0);
    let support = harness.support_dir();
    plant(&support, day("2026-10-13"), &today()[..2], false);
    let path = radio_day_path(&support, day("2026-10-13"));
    let good = fs::read(&path).unwrap();
    let mut corrupt = good.clone();
    corrupt.extend_from_slice(b"not json canary-line\n");
    corrupt.extend_from_slice(&encode_line(&today()[2]).unwrap());
    fs::write(&path, &corrupt).unwrap();
    for args in [&["router", "history"][..], &["router", "history", "--json"]] {
        let outcome = harness.run(args);
        assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
        assert_eq!(outcome.stdout, "", "{args:?}");
        assert_eq!(
            outcome.stderr,
            format!(
                "mooringctl: radio history file {} cannot be read at line 3\n  caused by: a radio history line is not a radio sample\n",
                path.display()
            ),
            "{args:?}"
        );
        assert!(!outcome.stderr.contains("canary"));
    }
    let mut newer = good;
    newer.extend_from_slice(
        &String::from_utf8(encode_line(&today()[2]).unwrap())
            .unwrap()
            .replacen("\"version\":1", "\"version\":2", 1)
            .into_bytes(),
    );
    fs::write(&path, &newer).unwrap();
    let outcome = harness.run(&["router", "history", "--json"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: radio history file {} cannot be read at line 3\n  caused by: a radio history line names sample version 2; this build reads version 1\n",
            path.display()
        )
    );
    // The file was left as it was.
    assert_eq!(fs::read(&path).unwrap(), newer);
}

/// The human summary: a header per day with its counts and the torn note,
/// the events with the M7's own spellings, and the hourly table.
#[test]
fn the_human_summary_of_two_days() {
    let mut harness = Harness::new(0);
    plant(&harness.support_dir(), day("2026-10-13"), &today(), true);
    let before = fs::read(radio_day_path(&harness.support_dir(), day("2026-10-13"))).unwrap();
    let outcome = harness.run(&["router", "history"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        "radio history 2026-10-12 to 2026-10-13 UTC: 5 polls, 4 read\n\
         2026-10-12: no samples\n\
         2026-10-13: 5 polls, 4 read; the last line is incomplete (the daemon may be writing it, or stopped while writing it)\n\
         events:\n\
         \x20 2026-10-13 19:01:00 UTC  poll failed: the M7 is unreachable\n\
         \x20 2026-10-13 19:02:00 UTC  poll recovered\n\
         \x20 2026-10-13 19:02:00 UTC  network service Nr5gService -> LteService\n\
         \x20 2026-10-13 19:02:00 UTC  data service 5GSUB6 -> 4GPLUS\n\
         \x20 2026-10-13 19:03:00 UTC  band B3 -> B20\n\
         \x20 2026-10-13 19:03:00 UTC  network 234-30 -> 234-20\n\
         \x20 2026-10-13 19:03:00 UTC  data session restarted (shorter than at the last read)\n\
         \x20 2026-10-13 20:00:00 UTC  the M7 rebooted (uptime shorter than at the last read)\n\
         \x20 2026-10-13 20:00:00 UTC  no service\n\
         by hour (polls/read; LTE RSRP and SINR, NR RSRP and SINR as min/median/max; service types seen):\n\
         \x20 2026-10-13 19:00  4/3  LTE RSRP -104/-100/-90 dBm, SINR 0/2/5.5 dB; NR RSRP not reported, SINR not reported; Nr5gService, LteService\n\
         \x20 2026-10-13 20:00  1/1  LTE RSRP not reported, SINR not reported; NR RSRP not reported, SINR not reported; no service\n"
    );
    // Reading never writes: the torn tail is still there.
    assert_eq!(
        fs::read(radio_day_path(&harness.support_dir(), day("2026-10-13"))).unwrap(),
        before
    );
}
