// SPDX-License-Identifier: GPL-3.0-or-later

//! `contract/history-fixtures/`: the `RadioHistory` document Mooring.app
//! decodes from `mooringctl router history --json`, generated here and
//! pinned byte for byte like the status fixtures. Its nine samples show
//! every kind of event once, so the Codable mirror has a fixture for each.
//!
//! To change it, change the builder, write [`encode`]'s output over the
//! file, and review the diff.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use mooring_daemon_core::radio_history::{
    RadioEventKind, RadioHistory, RadioPoll, RadioReading, RadioSample, SampledAttachment,
    SampledRadio,
};
use mooring_daemon_core::router::{
    Band, BandNumber, Celsius, DataService, LteSignal, Mcc, Mnc, NetworkService, NrSignal, Plmn,
    RouterUnavailableReason, Rsrp, Rsrq, Rssi, Sinr, ThermalState,
};
use serde_json::Value;

use crate::support::{at, date};

const FIXTURE: &[u8] = include_bytes!("../../../../contract/history-fixtures/radio.json");

/// A fixture file's content: the pretty-printed document and a newline.
fn encode(history: &RadioHistory) -> String {
    let mut text = serde_json::to_string_pretty(history).unwrap();
    text.push('\n');
    text
}

fn plmn(mnc: &str) -> Plmn {
    Plmn {
        mcc: Mcc::parse("234").unwrap(),
        mnc: Mnc::parse(mnc).unwrap(),
    }
}

/// A read, attached sample at `secs` into 2026-10-13.
#[allow(clippy::too_many_arguments)]
fn attached(
    secs: u64,
    service: NetworkService,
    data: DataService,
    band: Band,
    mnc: &str,
    uptime: u64,
    session: u64,
    lte: LteSignal,
    nr: NrSignal,
) -> RadioSample {
    RadioSample {
        at: at("2026-10-13", secs),
        poll: RadioPoll::Read(RadioReading {
            uptime_secs: uptime,
            temperature_c: Celsius::new(44).unwrap(),
            thermal: ThermalState::Normal,
            radio: SampledRadio::Attached(SampledAttachment {
                network_service: service,
                data_service: data,
                band,
                ca_secondary_count: 0,
                lte,
                nr,
                plmn: plmn(mnc),
                session_secs: session,
            }),
        }),
    }
}

/// The SMARTY SIM's LTE readings (2026-10-16).
fn smarty_lte() -> LteSignal {
    LteSignal {
        rsrp: Some(Rsrp::from_tenths(-1_000).unwrap()),
        rsrq: Some(Rsrq::from_tenths(-120).unwrap()),
        sinr: Some(Sinr::from_tenths(20).unwrap()),
        rssi: Some(Rssi::from_tenths(-690).unwrap()),
    }
}

fn no_nr() -> NrSignal {
    NrSignal {
        rsrp: None,
        rsrq: None,
        sinr: None,
    }
}

/// The document: yesterday and today, with today's nine samples showing
/// every kind of event once, in the order the kinds are declared in, and
/// today's file torn.
pub(crate) fn history() -> RadioHistory {
    let hour = 19 * 3_600;
    let minute = |n: u64| hour + n * 60;
    let b3 = Band::Lte(BandNumber::new(3).unwrap());
    let samples = vec![
        // On NR with an NR reading, the LTE band 3 primary carrier as in
        // the M2a capture.
        attached(
            minute(0),
            NetworkService::Nr5g,
            DataService::NrSub6,
            b3,
            "30",
            523_014,
            86_400,
            smarty_lte(),
            NrSignal {
                rsrp: Some(Rsrp::from_tenths(-905).unwrap()),
                rsrq: Some(Rsrq::from_tenths(-105).unwrap()),
                sinr: Some(Sinr::from_tenths(155).unwrap()),
            },
        ),
        // The M7 did not answer.
        RadioSample {
            at: at("2026-10-13", minute(1)),
            poll: RadioPoll::Failed {
                reason: RouterUnavailableReason::Unreachable,
            },
        },
        // Back, fallen to LTE on band 3: recovery, service and data service.
        attached(
            minute(2),
            NetworkService::Lte,
            DataService::LtePlus,
            b3,
            "30",
            523_134,
            86_520,
            smarty_lte(),
            no_nr(),
        ),
        // Band 20.
        attached(
            minute(3),
            NetworkService::Lte,
            DataService::LtePlus,
            Band::Lte(BandNumber::new(20).unwrap()),
            "30",
            523_194,
            86_580,
            smarty_lte(),
            no_nr(),
        ),
        // No service.
        RadioSample {
            at: at("2026-10-13", minute(4)),
            poll: RadioPoll::Read(RadioReading {
                uptime_secs: 523_254,
                temperature_c: Celsius::new(44).unwrap(),
                thermal: ThermalState::Normal,
                radio: SampledRadio::NoService,
            }),
        },
        // Service regained, with a new session.
        attached(
            minute(5),
            NetworkService::Lte,
            DataService::LtePlus,
            Band::Lte(BandNumber::new(20).unwrap()),
            "30",
            523_314,
            30,
            smarty_lte(),
            no_nr(),
        ),
        // The session restarted.
        attached(
            minute(6),
            NetworkService::Lte,
            DataService::LtePlus,
            Band::Lte(BandNumber::new(20).unwrap()),
            "30",
            523_374,
            20,
            smarty_lte(),
            no_nr(),
        ),
        // Another network.
        attached(
            minute(7),
            NetworkService::Lte,
            DataService::LtePlus,
            Band::Lte(BandNumber::new(20).unwrap()),
            "20",
            523_434,
            80,
            smarty_lte(),
            no_nr(),
        ),
        // The M7 rebooted.
        attached(
            minute(8),
            NetworkService::Lte,
            DataService::LtePlus,
            Band::Lte(BandNumber::new(20).unwrap()),
            "20",
            40,
            20,
            smarty_lte(),
            no_nr(),
        ),
    ];
    RadioHistory::new(
        date("2026-10-12"),
        date("2026-10-13"),
        samples,
        vec![date("2026-10-13")],
    )
}

#[test]
fn the_fixture_is_what_its_builder_generates() {
    let generated = encode(&history());
    assert!(
        generated.as_bytes() == FIXTURE,
        "contract/history-fixtures/radio.json is not what its builder generates:\n{generated}"
    );
}

#[test]
fn the_fixture_round_trips_byte_for_byte() {
    let history: RadioHistory = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(encode(&history).as_bytes(), FIXTURE);
    // The CLI prints the same document as one compact line.
    let line = serde_json::to_string(&history).unwrap();
    assert!(!line.contains('\n'));
    assert_eq!(
        serde_json::from_str::<RadioHistory>(&line).unwrap(),
        history
    );
    assert_eq!(history.since(), date("2026-10-12"));
    assert_eq!(history.incomplete_days(), [date("2026-10-13")]);
}

/// The samples show every kind of event exactly once, in declaration
/// order: the mirror has a fixture for each, and a kind added here cannot
/// be left out (the match is exhaustive).
#[test]
fn the_fixture_holds_every_event_kind_once() {
    let history = history();
    let order: Vec<usize> = history
        .events()
        .iter()
        .map(|event| match event.kind {
            RadioEventKind::PollFailed { .. } => 0,
            RadioEventKind::PollRecovered => 1,
            RadioEventKind::RouterRebooted => 2,
            RadioEventKind::ServiceLost => 3,
            RadioEventKind::ServiceRegained => 4,
            RadioEventKind::NetworkServiceChanged { .. } => 5,
            RadioEventKind::DataServiceChanged { .. } => 6,
            RadioEventKind::BandChanged { .. } => 7,
            RadioEventKind::PlmnChanged { .. } => 8,
            RadioEventKind::SessionRestarted => 9,
        })
        .collect();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    for kind in &order {
        assert!(
            seen.insert(*kind),
            "kind {kind} shows twice: {:?}",
            history.events()
        );
    }
    assert_eq!(seen.len(), 10, "{:?}", history.events());
    // Every object of the document refuses an unknown key.
    let json: Value = serde_json::from_slice(FIXTURE).unwrap();
    for path in object_paths(&json, Vec::new()) {
        let mut edited = json.clone();
        let mut target = &mut edited;
        for step in &path {
            target = match step {
                Step::Key(key) => &mut target[key.as_str()],
                Step::Index(index) => &mut target[*index],
            };
        }
        target
            .as_object_mut()
            .unwrap()
            .insert("zz_unknown".to_owned(), Value::Bool(true));
        assert!(
            serde_json::from_value::<RadioHistory>(edited).is_err(),
            "an unknown key at {path:?} was accepted"
        );
    }
}

#[derive(Debug, Clone)]
enum Step {
    Key(String),
    Index(usize),
}

/// The path of every object in `value`.
fn object_paths(value: &Value, path: Vec<Step>) -> Vec<Vec<Step>> {
    match value {
        Value::Object(object) => {
            let mut paths = vec![path.clone()];
            for (key, inner) in object {
                let mut next = path.clone();
                next.push(Step::Key(key.clone()));
                paths.extend(object_paths(inner, next));
            }
            paths
        }
        Value::Array(array) => array
            .iter()
            .enumerate()
            .flat_map(|(index, inner)| {
                let mut next = path.clone();
                next.push(Step::Index(index));
                object_paths(inner, next)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The directory holds exactly the fixture and its licence sidecar.
#[test]
fn the_fixture_directory_holds_exactly_the_fixture() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contract/history-fixtures");
    let found: BTreeSet<String> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let expected: BTreeSet<String> = ["radio.json", "radio.json.license"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(found, expected);
    assert_eq!(
        fs::read_to_string(directory.join("radio.json.license")).unwrap(),
        "SPDX-License-Identifier: GPL-3.0-or-later\n"
    );
}
