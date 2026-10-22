// SPDX-License-Identifier: GPL-3.0-or-later

//! `contract/console-fixtures/`: the `ConsoleStatus` documents Mooring.app
//! decodes from `mooringctl status --json`, generated here and pinned byte
//! for byte like the status fixtures. Before a deployment exists the
//! document carries the router alone; once it exists, the deployment's
//! `MacStatusV1`.
//!
//! To change one, change its builder, write [`encode`]'s output over the
//! file, and review the diff.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use mooring_daemon_core::control::{DaemonReply, MAX_REPLY_LINE_BYTES, decode_reply, encode_line};
use mooring_daemon_core::router::{
    Band, BandNumber, DataService, LteBandwidth, LteCarrier, LteCarriers, LteSignal,
    NetworkService, NrSignal, Plmn, Radio, RadioState, RouterReading, RouterUnavailableReason,
    Rsrp, Rsrq, Rssi, Sinr,
};
use mooring_daemon_core::router::{CarrierName, Mcc, Mnc};
use mooring_daemon_core::{
    ConsoleError, ConsoleErrorKind, ConsoleStatus, UNDEPLOYED_STATUS_VERSION, UndeployedStatus,
};
use mooring_model::UnixTime;
use serde_json::Value;

use crate::scenarios;
use crate::support::at;

const FIXTURES: &[(&str, &[u8])] = &[
    (
        "no-deployment",
        include_bytes!("../../../../contract/console-fixtures/no-deployment.json"),
    ),
    (
        "no-deployment-router-unavailable",
        include_bytes!(
            "../../../../contract/console-fixtures/no-deployment-router-unavailable.json"
        ),
    ),
    (
        "deployed",
        include_bytes!("../../../../contract/console-fixtures/deployed.json"),
    ),
];

/// When the undeployed documents were produced.
fn produced() -> UnixTime {
    at("2026-10-22", 3 * 3600 + 30 * 60)
}

/// Attached as the M7 reported with the SMARTY SIM (2026-10-16): an LTE
/// network service, the `4GPLUS` data service, band 3 at 20 MHz as the
/// primary with one unassigned slot after it, LTE readings and none for NR.
fn smarty_radio() -> RadioState {
    let b3 = BandNumber::new(3).unwrap();
    RadioState::Attached(Radio {
        network_service: NetworkService::Lte,
        data_service: DataService::LtePlus,
        band: Band::Lte(b3),
        lte_carriers: Some(
            LteCarriers::new(
                LteCarrier {
                    band: b3,
                    dl_bandwidth: LteBandwidth::Mhz20,
                },
                Vec::new(),
                1,
            )
            .unwrap(),
        ),
        ca_secondary_count: 0,
        lte: LteSignal {
            rsrp: Some(Rsrp::from_tenths(-1_000).unwrap()),
            rsrq: Some(Rsrq::from_tenths(-120).unwrap()),
            sinr: Some(Sinr::from_tenths(20).unwrap()),
            rssi: Some(Rssi::from_tenths(-690).unwrap()),
        },
        nr: NrSignal {
            rsrp: None,
            rsrq: None,
            sinr: None,
        },
        network: CarrierName::parse("3 UK").unwrap(),
        plmn: Plmn {
            mcc: Mcc::parse("234").unwrap(),
            mnc: Mnc::parse("20").unwrap(),
        },
        session_secs: 86_400,
    })
}

/// Every console fixture, in file order.
fn all() -> Vec<(&'static str, ConsoleStatus)> {
    let polled_at = UnixTime::from_secs(produced().as_secs() - 20);
    let available = scenarios::router(polled_at, None, smarty_radio(), 44, 100);
    let unavailable = RouterReading::Unavailable {
        reason: RouterUnavailableReason::LocalFailure,
        last_polled_at: Some(UnixTime::from_secs(produced().as_secs() - 60)),
    };
    vec![
        (
            "no-deployment",
            ConsoleStatus::NoDeployment(UndeployedStatus::new(produced(), available)),
        ),
        (
            "no-deployment-router-unavailable",
            ConsoleStatus::NoDeployment(UndeployedStatus::new(produced(), unavailable)),
        ),
        (
            "deployed",
            ConsoleStatus::Deployed(Box::new(scenarios::serving())),
        ),
    ]
}

/// A fixture file's content: the pretty-printed document and a newline.
fn encode(status: &ConsoleStatus) -> String {
    let mut text = serde_json::to_string_pretty(status).unwrap();
    text.push('\n');
    text
}

#[test]
fn the_console_fixtures_are_what_their_builders_generate() {
    let built = all();
    assert_eq!(
        built.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        FIXTURES.iter().map(|(name, _)| *name).collect::<Vec<_>>()
    );
    for ((name, status), (_, bytes)) in built.iter().zip(FIXTURES) {
        assert!(
            encode(status).as_bytes() == *bytes,
            "contract/console-fixtures/{name}.json is not what its builder generates"
        );
    }
}

/// Each fixture decodes and re-encodes to exactly its bytes, and travels
/// as one compact line of the status stream too.
#[test]
fn every_console_fixture_round_trips_byte_for_byte() {
    for (name, bytes) in FIXTURES {
        let status: ConsoleStatus = serde_json::from_slice(bytes)
            .unwrap_or_else(|error| panic!("{name}.json does not decode: {error}"));
        assert!(
            encode(&status).as_bytes() == *bytes,
            "{name}.json does not re-encode to itself"
        );
        let line = serde_json::to_string(&status).unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(
            serde_json::from_str::<ConsoleStatus>(&line).unwrap(),
            status
        );
    }
}

/// The directory holds exactly these fixtures and their licence sidecars.
#[test]
fn the_console_fixture_directory_holds_exactly_the_fixtures() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contract/console-fixtures");
    let found: BTreeSet<String> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let expected: BTreeSet<String> = FIXTURES
        .iter()
        .flat_map(|(name, _)| [format!("{name}.json"), format!("{name}.json.license")])
        .collect();
    assert_eq!(found, expected);
    for (name, _) in FIXTURES {
        let sidecar = fs::read_to_string(directory.join(format!("{name}.json.license"))).unwrap();
        assert_eq!(sidecar, "SPDX-License-Identifier: GPL-3.0-or-later\n");
    }
}

/// The undeployed document names its version, which must be 1, and refuses
/// to drop a key: the router panel and the time are required.
#[test]
fn an_undeployed_document_is_version_1_with_every_key() {
    let json: Value = serde_json::from_slice(FIXTURES[0].1).unwrap();
    assert_eq!(
        json["no_deployment"]["version"],
        Value::from(UNDEPLOYED_STATUS_VERSION)
    );
    assert_eq!(UNDEPLOYED_STATUS_VERSION, 1);
    let mut later = json.clone();
    later["no_deployment"]["version"] = Value::from(2);
    let error = serde_json::from_value::<ConsoleStatus>(later).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&ConsoleError::UnsupportedVersion { found: 2 }.to_string()),
        "{error}"
    );
    assert_eq!(
        ConsoleError::UnsupportedVersion { found: 2 }.kind(),
        ConsoleErrorKind::UnsupportedVersion
    );
    for key in ["version", "at", "router"] {
        let mut missing = json.clone();
        missing["no_deployment"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(
            serde_json::from_value::<ConsoleStatus>(missing).is_err(),
            "{key}"
        );
    }
    // A document is exactly one of the two.
    let mut both = json.as_object().unwrap().clone();
    both.insert(
        "deployed".into(),
        serde_json::from_slice::<Value>(FIXTURES[2].1).unwrap()["deployed"].clone(),
    );
    assert!(serde_json::from_value::<ConsoleStatus>(Value::Object(both)).is_err());
}

/// The router panel and the production time read the same from both
/// documents.
#[test]
fn both_documents_give_the_router_and_the_time() {
    for (name, status) in all() {
        match &status {
            ConsoleStatus::NoDeployment(undeployed) => {
                assert_eq!(status.router(), undeployed.router(), "{name}");
                assert_eq!(status.at(), produced(), "{name}");
            }
            ConsoleStatus::Deployed(deployed) => {
                assert_eq!(status.router(), &deployed.parts().router, "{name}");
                assert_eq!(status.at(), deployed.parts().at, "{name}");
            }
        }
    }
}

/// The largest fixture status, the degraded scenario's 20-user deployment,
/// fits a reply line with room to spare, and survives the line codec.
#[test]
fn a_reply_line_holds_the_largest_fixture_status() {
    for (name, status) in scenarios::all() {
        let reply = DaemonReply::Status(ConsoleStatus::Deployed(Box::new(status)));
        let line = encode_line(&reply, MAX_REPLY_LINE_BYTES).unwrap();
        assert!(
            line.len() < MAX_REPLY_LINE_BYTES / 8,
            "{name}: {}",
            line.len()
        );
        assert_eq!(decode_reply(&line).unwrap(), reply, "{name}");
    }
}
