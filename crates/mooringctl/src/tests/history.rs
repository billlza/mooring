// SPDX-License-Identifier: GPL-3.0-or-later

//! `router history` (design §15.6 rules 11 and 13): the day files the
//! daemon recorded, read through the store and printed as the document the
//! app reads, as a table of the samples or of their events, or as a
//! summary; the range's rules; what a corrupt line does; and that the
//! command never writes.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::Path;

use clap::Parser;
use mooring_daemon_core::radio_history::{
    RadioHistory, RadioPoll, RadioReading, RadioSample, SampledAttachment, SampledRadio,
    encode_line,
};
use mooring_daemon_core::radio_table::{
    EVENTS_HEADER, SAMPLES_HEADER, events_table, samples_table,
};
use mooring_daemon_core::router::{
    Band, BandNumber, Celsius, DataService, LteSignal, Mcc, Mnc, NetworkService, NrSignal, Plmn,
    RouterUnavailableReason, Rsrp, Rsrq, Rssi, Sinr, ThermalState,
};
use mooring_model::{CalendarDate, UnixTime};
use mooring_store::{RADIO_DIRECTORY, append_radio_line, radio_day_path};

use super::support::{Harness, NOW};
use crate::cli::{Cli, HistoryTableArg};
use crate::error::{EXIT_LOCAL, EXIT_USAGE};
use crate::router::history::Form;

/// The command in each of its forms: the summary, the document and the
/// two tables.
const FORMS: [&[&str]; 4] = [
    &["router", "history"],
    &["router", "history", "--json"],
    &["router", "history", "--csv", "samples"],
    &["router", "history", "--csv", "events"],
];

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
/// line, never its bytes; nothing is printed, in any form.
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
    for args in FORMS {
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

/// A day file that is not a regular file is a local failure naming it,
/// never an empty day: a link to nothing, and a socket, which until
/// 2026-11-03 was the open's own failure rather than this refusal. Nothing
/// is printed, and the file is left as it is.
#[test]
fn a_day_file_that_is_not_a_regular_file_is_a_local_failure() {
    let mut harness = Harness::new(0);
    let support = harness.support_dir();
    plant(&support, day("2026-10-12"), &today()[..1], false);
    let path = radio_day_path(&support, day("2026-10-13"));
    symlink(support.join("moved.jsonl"), &path).unwrap();
    let refused = |harness: &mut Harness| {
        for args in FORMS {
            let outcome = harness.run(args);
            assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
            assert_eq!(outcome.stdout, "", "{args:?}");
            assert_eq!(
                outcome.stderr,
                format!(
                    "mooringctl: the radio history's files failed\n  caused by: {} is not a regular file\n",
                    path.display()
                ),
                "{args:?}"
            );
        }
    };
    refused(&mut harness);
    fs::remove_file(&path).unwrap();
    // Bound under a short name in the home (a socket's path is short),
    // then moved into place.
    let bound = harness.home.path().join("s");
    drop(UnixListener::bind(&bound).unwrap());
    fs::rename(&bound, &path).unwrap();
    refused(&mut harness);
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
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

/// Service lost and regained within an hour shows both events, and the
/// hour counts its reads without service; an hour whose polls all failed
/// has no reads.
#[test]
fn the_summary_counts_reads_without_service_and_hours_without_reads() {
    let mut harness = Harness::new(0);
    let lte = |secs, uptime| {
        attached(
            secs,
            NetworkService::Lte,
            DataService::LtePlus,
            3,
            "30",
            uptime,
            uptime - 100,
            -1000,
            20,
        )
    };
    let samples = [
        lte(18 * 3600, 5_000),
        no_service(18 * 3600 + 60, 5_060),
        lte(18 * 3600 + 120, 5_120),
        failed(19 * 3600, RouterUnavailableReason::Unreachable),
    ];
    plant(&harness.support_dir(), day("2026-10-13"), &samples, false);
    let outcome = harness.run(&["router", "history", "--since", "2026-10-13"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    for said in [
        "  2026-10-13 18:01:00 UTC  no service\n",
        "  2026-10-13 18:02:00 UTC  service regained\n",
        "; LteService (1 without service)\n",
        "  2026-10-13 19:00  1/0  ",
        "; no reads\n",
    ] {
        assert!(outcome.stdout.contains(said), "{said}: {}", outcome.stdout);
    }
}

/// A radio directory that cannot be read is the error, never no history.
#[test]
fn a_radio_directory_that_cannot_be_read_is_the_error() {
    let mut harness = Harness::new(0);
    fs::create_dir_all(harness.support_dir()).unwrap();
    fs::write(history_dir(&harness), b"").unwrap();
    let outcome = harness.run(&["router", "history"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert!(
        outcome
            .stderr
            .starts_with("mooringctl: the radio history's files failed\n"),
        "{}",
        outcome.stderr
    );
}

// --- The tables (design §15.6 rule 13) --------------------------------------

/// `--csv samples` prints one row per whole line of the range's files, in
/// their order, and `--csv events` one row per change they show: the
/// tables `daemon-core` makes, byte for byte. The torn last line is no
/// row, and reading never writes.
#[test]
fn history_csv_prints_the_samples_and_their_events_as_tables() {
    let mut harness = Harness::new(0);
    let yesterday = [failed(0, RouterUnavailableReason::NotConfigured)];
    plant(&harness.support_dir(), day("2026-10-12"), &yesterday, false);
    plant(&harness.support_dir(), day("2026-10-13"), &today(), true);
    let path = radio_day_path(&harness.support_dir(), day("2026-10-13"));
    let before = fs::read(&path).unwrap();
    let mut samples = yesterday.to_vec();
    samples.extend(today());
    let expected = RadioHistory::new(
        day("2026-10-12"),
        day("2026-10-13"),
        samples,
        vec![day("2026-10-13")],
    );

    let outcome = harness.run(&["router", "history", "--csv", "samples"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        "at_unix,at_utc,outcome,failure,uptime_secs,temperature_c,thermal,service,network_service,data_service,band,ca_secondary_count,lte_rsrp_dbm,lte_rsrq_db,lte_sinr_db,lte_rssi_dbm,nr_rsrp_dbm,nr_rsrq_db,nr_sinr_db,plmn,session_secs\n\
         1791849600,2026-10-13T00:00:00Z,failed,not_configured,,,,,,,,,,,,,,,,,\n\
         1791918000,2026-10-13T19:00:00Z,read,,10000,35,normal,attached,nr5g,nr_sub6,B3,0,-104.0,-12.0,0.0,-69.0,,,,234-30,9000\n\
         1791918060,2026-10-13T19:01:00Z,failed,unreachable,,,,,,,,,,,,,,,,,\n\
         1791918120,2026-10-13T19:02:00Z,read,,10120,35,normal,attached,lte,lte_plus,B3,0,-100.0,-12.0,2.0,-69.0,,,,234-30,9120\n\
         1791918180,2026-10-13T19:03:00Z,read,,10180,35,normal,attached,lte,lte_plus,B20,0,-90.0,-12.0,5.5,-69.0,,,,234-20,30\n\
         1791921600,2026-10-13T20:00:00Z,read,,40,35,normal,no_service,,,,,,,,,,,,,\n"
    );
    assert_eq!(outcome.stdout, samples_table(expected.samples()).unwrap());

    let outcome = harness.run(&["router", "history", "--csv", "events"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        "at_unix,at_utc,event,reason,from,to\n\
         1791918000,2026-10-13T19:00:00Z,poll_recovered,,,\n\
         1791918060,2026-10-13T19:01:00Z,poll_failed,unreachable,,\n\
         1791918120,2026-10-13T19:02:00Z,poll_recovered,,,\n\
         1791918120,2026-10-13T19:02:00Z,network_service_changed,,nr5g,lte\n\
         1791918120,2026-10-13T19:02:00Z,data_service_changed,,nr_sub6,lte_plus\n\
         1791918180,2026-10-13T19:03:00Z,band_changed,,B3,B20\n\
         1791918180,2026-10-13T19:03:00Z,plmn_changed,,234-30,234-20\n\
         1791918180,2026-10-13T19:03:00Z,session_restarted,,,\n\
         1791921600,2026-10-13T20:00:00Z,router_rebooted,,,\n\
         1791921600,2026-10-13T20:00:00Z,service_lost,,,\n"
    );
    assert_eq!(outcome.stdout, events_table(expected.events()).unwrap());

    // Reading never writes: the torn tail is still there.
    assert_eq!(fs::read(&path).unwrap(), before);
}

/// The range is the same in every form: one day's rows alone, and for
/// days without a file the header alone, with nothing created.
#[test]
fn a_table_covers_the_range_asked_for_and_is_its_header_without_samples() {
    let mut harness = Harness::new(0);
    for (table, header) in [("samples", SAMPLES_HEADER), ("events", EVENTS_HEADER)] {
        let outcome = harness.run(&["router", "history", "--csv", table]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stderr, "");
        assert_eq!(outcome.stdout, format!("{header}\n"));
    }
    assert!(!history_dir(&harness).exists());

    let yesterday = [failed(0, RouterUnavailableReason::NotConfigured)];
    plant(&harness.support_dir(), day("2026-10-12"), &yesterday, false);
    plant(&harness.support_dir(), day("2026-10-13"), &today(), false);
    let one_day = ["--since", "2026-10-13", "--until", "2026-10-13"];
    let mut args = vec!["router", "history", "--csv", "samples"];
    args.extend(one_day);
    let outcome = harness.run(&args);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout, samples_table(&today()).unwrap());
    assert_eq!(outcome.stdout.lines().count(), 6);
    // Without yesterday's failed poll before it, today's first read is no
    // recovery: nine events, not ten.
    let mut args = vec!["router", "history", "--csv", "events"];
    args.extend(one_day);
    let outcome = harness.run(&args);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stdout.lines().count(), 10);
    assert!(
        outcome
            .stdout
            .starts_with("at_unix,at_utc,event,reason,from,to\n1791918060,2026-10-13T19:01:00Z,poll_failed,unreachable,,\n"),
        "{}",
        outcome.stdout
    );

    // The range's rules hold for a table as for the other forms.
    let outcome = harness.run(&[
        "router",
        "history",
        "--csv",
        "samples",
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
}

/// `--csv` names its table, takes no other word, and does not go with
/// `--json`: each is clap's usage error.
#[test]
fn the_table_is_named_and_excludes_the_document() {
    for args in [
        &["mooringctl", "router", "history", "--csv"][..],
        &["mooringctl", "router", "history", "--csv", "hourly"],
        &["mooringctl", "router", "history", "--csv", "Samples"],
        &[
            "mooringctl",
            "router",
            "history",
            "--csv",
            "samples",
            "--json",
        ],
        &[
            "mooringctl",
            "router",
            "history",
            "--json",
            "--csv",
            "events",
        ],
    ] {
        let error = Cli::try_parse_from(args).unwrap_err();
        assert_eq!(error.exit_code(), i32::from(EXIT_USAGE), "{args:?}");
    }
    Cli::try_parse_from(["mooringctl", "router", "history", "--csv", "samples"]).unwrap();
    Cli::try_parse_from(["mooringctl", "router", "history", "--csv", "events"]).unwrap();

    assert_eq!(Form::of(false, None), Form::Summary);
    assert_eq!(Form::of(true, None), Form::Json);
    for table in [HistoryTableArg::Samples, HistoryTableArg::Events] {
        assert_eq!(Form::of(false, Some(table)), Form::Table(table));
        // The command line never gives both; a table would win.
        assert_eq!(Form::of(true, Some(table)), Form::Table(table));
    }
}

/// A sample dated past the year 9999 has no UTC date a table can write:
/// the command fails as the Mac's clock outside its range, and prints no
/// part of a table.
#[test]
fn a_sample_past_the_year_9999_is_no_row() {
    let mut harness = Harness::new(0);
    let late = RadioSample {
        at: UnixTime::from_secs(253_402_300_800),
        poll: RadioPoll::Failed {
            reason: RouterUnavailableReason::Unreachable,
        },
    };
    let samples = [today()[0], late, today()[2]];
    plant(&harness.support_dir(), day("2026-10-13"), &samples, false);
    for table in ["samples", "events"] {
        let outcome = harness.run(&["router", "history", "--csv", table]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{table}");
        assert_eq!(outcome.stdout, "", "{table}");
        assert_eq!(
            outcome.stderr, "mooringctl: the Mac's clock is outside 1970 to 9999\n",
            "{table}"
        );
    }
}
