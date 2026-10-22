// SPDX-License-Identifier: GPL-3.0-or-later

//! The parsers: the fixture's reading, sentinels and units, required and
//! typed leaves, closed vocabularies, the session gate, the carrier list's
//! form, canonical counters, and the error kinds.

use proptest::prelude::*;
use serde_json::{Value, json};

use super::{FIXTURE, edited, element_of, field, fixture, pointer, spliced, with, without};
use crate::error::{CarrierFaultKind, FieldFaultKind, RouterParseError, RouterParseErrorKind};
use crate::router::netgear::{
    ADMIN_ROLE, LeafSet, NOT_REPORTED, NetgearLeaf, Segment, parse_netgear_model_json,
    parse_netgear_session,
};
use crate::router::{
    BandNumber, DataService, LteBandwidth, LteCarrier, LteCarriers, NetworkService, RadioState,
    RouterStatus, RouterUnavailableReason,
};
use crate::tests::router;

fn parse(body: &[u8]) -> Result<RouterStatus, RouterParseError> {
    parse_netgear_model_json(body)
}

fn carriers_fault(fault: CarrierFaultKind) -> RouterParseError {
    RouterParseError::Carriers { fault }
}

/// The status leaves, those the status parse reads.
fn status_leaves() -> impl Iterator<Item = NetgearLeaf> {
    NetgearLeaf::ALL
        .iter()
        .copied()
        .filter(|leaf| LeafSet::Status.contains(*leaf))
}

/// The fixture reads as the M2a reading, field by field.
#[test]
fn the_fixture_parses_to_the_m2a_reading() {
    let status = parse(FIXTURE).unwrap();
    assert_eq!(status, router::status());
    let parts = status.parts();
    assert_eq!(
        (parts.counters.rx_bytes, parts.counters.tx_bytes),
        (591_655_199, 188_784_597)
    );
    let RadioState::Attached(radio) = &parts.radio else {
        panic!("the M2a reading is attached");
    };
    assert_eq!(radio.lte.rsrp.map(|value| value.tenths()), Some(-1040));
    assert_eq!(radio.lte.rssi.map(|value| value.tenths()), Some(-720));
    assert_eq!(radio.band.to_string(), "B3");
    assert_eq!(radio.plmn.mnc.to_string(), "30");
}

/// The fixture's session is an administrator's with no cool-off, and its
/// token (a placeholder in the fixture) is read exactly and never shown.
#[test]
fn the_fixture_session_is_an_admin_session_with_a_token() {
    let session = parse_netgear_session(FIXTURE).unwrap();
    assert!(session.is_admin());
    assert_eq!(session.cooloff(), 0);
    assert_eq!(session.token().expose_str(), "REDACTED");
    let token = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P";
    let session =
        parse_netgear_session(&with(&pointer(NetgearLeaf::SessionToken, 0), json!(token))).unwrap();
    assert_eq!(session.token().expose_str(), token);
    assert!(!format!("{session:?}").contains(token));
    for role in ["admin", "ADMIN", "Admin ", "Guest", ""] {
        let session = parse_netgear_session(&with(
            &pointer(NetgearLeaf::SessionUserRole, 0),
            json!(role),
        ))
        .unwrap();
        assert!(!session.is_admin(), "{role:?}");
    }
    let cooling = parse_netgear_session(&with(
        &pointer(NetgearLeaf::SessionPasswordCooloff, 0),
        json!(30),
    ))
    .unwrap();
    assert_eq!(cooling.cooloff(), 30);
    for bad in [json!(-1), json!(4_294_967_296_u64)] {
        assert_eq!(
            parse_netgear_session(&with(&pointer(NetgearLeaf::SessionPasswordCooloff, 0), bad))
                .map(|_| ()),
            Err(field(
                NetgearLeaf::SessionPasswordCooloff,
                None,
                FieldFaultKind::OutOfRange
            ))
        );
    }
}

const READINGS: [NetgearLeaf; 7] = [
    NetgearLeaf::SignalRsrp,
    NetgearLeaf::SignalRsrq,
    NetgearLeaf::SignalSinr,
    NetgearLeaf::SignalRssi,
    NetgearLeaf::SignalNrRsrp,
    NetgearLeaf::SignalNrRsrq,
    NetgearLeaf::SignalNrSinr,
];

/// The readings in the order of [`READINGS`], in tenths.
fn readings(status: &RouterStatus) -> [Option<i16>; 7] {
    let RadioState::Attached(radio) = &status.parts().radio else {
        panic!("the reading is attached");
    };
    [
        radio.lte.rsrp.map(|value| value.tenths()),
        radio.lte.rsrq.map(|value| value.tenths()),
        radio.lte.sinr.map(|value| value.tenths()),
        radio.lte.rssi.map(|value| value.tenths()),
        radio.nr.rsrp.map(|value| value.tenths()),
        radio.nr.rsrq.map(|value| value.tenths()),
        radio.nr.sinr.map(|value| value.tenths()),
    ]
}

/// `-32768` is "not reported" for every reading, LTE and NR alike, and
/// only that value is.
#[test]
fn the_not_reported_sentinel_is_none_for_every_reading() {
    assert_eq!(NOT_REPORTED, -32_768);
    let fixture_readings = readings(&parse(FIXTURE).unwrap());
    assert_eq!(
        fixture_readings,
        [
            Some(-1040),
            Some(-170),
            Some(0),
            Some(-720),
            None,
            None,
            None
        ]
    );
    for (index, leaf) in READINGS.iter().enumerate() {
        let status = parse(&with(&pointer(*leaf, 0), json!(-32_768))).unwrap();
        let mut expected = fixture_readings;
        expected[index] = None;
        assert_eq!(readings(&status), expected, "{leaf}");
    }
    let all = edited(|value| {
        for leaf in READINGS {
            *value.pointer_mut(&pointer(leaf, 0)).unwrap() = json!(-32_768);
        }
    });
    assert_eq!(readings(&parse(&all).unwrap()), [None; 7]);
}

/// The fixture's reading as JSON, with `absent` set to `null`.
fn reading_without(absent: &[&str]) -> Value {
    let mut reading = serde_json::to_value(router::status()).unwrap();
    for field in absent {
        assert!(reading.get(*field).is_some_and(Value::is_string), "{field}");
        reading[*field] = Value::Null;
    }
    reading
}

/// The status of `body`, as JSON.
fn parsed(body: &[u8]) -> Result<Value, RouterParseError> {
    parse(body).map(|status| serde_json::to_value(status).unwrap())
}

/// The SMARTY SIM's SPN is the empty string (2026-10-16): the status holds
/// no SIM name (`null`), not an empty one, and reads everything else as
/// before.
#[test]
fn an_empty_spn_is_no_sim_name() {
    let body = with(&pointer(NetgearLeaf::SimSpn, 0), json!(""));
    assert_eq!(parsed(&body), Ok(reading_without(&["sim_spn"])));
}

/// With the SMARTY SIM the M7 also reported its web app's version as the
/// empty string (2026-10-16): the status holds no version (`null`), and
/// reads everything else as before, the SPN's absence too.
#[test]
fn an_empty_web_app_version_is_no_version() {
    let web_app = pointer(NetgearLeaf::GeneralWebAppVersion, 0);
    let body = with(&web_app, json!(""));
    assert_eq!(parsed(&body), Ok(reading_without(&["web_app"])));
    let both = edited(|value| {
        *value.pointer_mut(&web_app).unwrap() = json!("");
        *value.pointer_mut(&pointer(NetgearLeaf::SimSpn, 0)).unwrap() = json!("");
    });
    assert_eq!(parsed(&both), Ok(reading_without(&["web_app", "sim_spn"])));
}

/// The M7 reports whole dB and dBm; the status keeps tenths. A value
/// outside the reading's range, or outside what tenths can hold, is
/// `OutOfRange`, never wrapped or saturated.
#[test]
fn whole_units_become_tenths_and_overflow_is_out_of_range() {
    let rsrp = NetgearLeaf::SignalRsrp;
    let at = pointer(rsrp, 0);
    for (whole, tenths) in [(-104, -1040), (-156, -1560), (-31, -310)] {
        let status = parse(&with(&at, json!(whole))).unwrap();
        assert_eq!(readings(&status)[0], Some(tenths), "{whole}");
    }
    let out_of_range = Err(field(rsrp, None, FieldFaultKind::OutOfRange));
    for whole in [
        json!(-157),
        json!(-30),
        json!(-32_767),
        json!(32_767),
        json!(65_432),
        json!(-65_640),
        json!(i64::MIN),
        json!(u64::MAX),
    ] {
        assert_eq!(
            parse(&with(&at, whole.clone())).map(|_| ()),
            out_of_range,
            "{whole}"
        );
    }
    // The NR readings take the same path.
    assert_eq!(
        parse(&with(&pointer(NetgearLeaf::SignalNrSinr, 0), json!(41))).map(|_| ()),
        Err(field(
            NetgearLeaf::SignalNrSinr,
            None,
            FieldFaultKind::OutOfRange
        ))
    );
    let status = parse(&with(&pointer(NetgearLeaf::SignalNrSinr, 0), json!(-23))).unwrap();
    assert_eq!(readings(&status)[6], Some(-230));
}

/// Every leaf the status parse reads is required: without it the parse
/// fails naming it (in its carrier, for a carrier's leaf), and the carrier
/// list itself is required.
#[test]
fn every_status_leaf_is_required() {
    for leaf in status_leaves() {
        let element = element_of(leaf);
        assert_eq!(
            parse(&without(&pointer(leaf, 0))).map(|_| ()),
            Err(field(leaf, element, FieldFaultKind::Missing)),
            "{leaf}"
        );
    }
    assert_eq!(
        parse(&without("/wwan/lteBandInfo")).map(|_| ()),
        Err(carriers_fault(CarrierFaultKind::Absent))
    );
    // A parent that is not an object leaves its leaves missing.
    assert_eq!(
        parse(&with("/sms", json!("x"))).map(|_| ()),
        Err(field(NetgearLeaf::SmsUnread, None, FieldFaultKind::Missing))
    );
    assert_eq!(
        parse(&with("/wwan/signalStrength", json!([1]))).map(|_| ()),
        Err(field(
            NetgearLeaf::SignalRsrp,
            None,
            FieldFaultKind::Missing
        ))
    );
}

/// A value of another JSON type than the leaf's shape, for every leaf the
/// status parse reads: `WrongType` naming it.
#[test]
fn every_status_leaf_refuses_the_wrong_type() {
    use crate::router::netgear::LeafShape;
    for leaf in status_leaves() {
        let wrong: &[Value] = match leaf.shape() {
            LeafShape::Bool => &[json!(0), json!(1), json!("true")],
            LeafShape::Int => &[json!("1"), json!(true), json!(1.0)],
            LeafShape::Text { .. }
            | LeafShape::Line { .. }
            | LeafShape::Digits { .. }
            | LeafShape::Secret { .. }
            | LeafShape::OrEmpty(LeafShape::Text { .. } | LeafShape::Line { .. }) => {
                &[json!(1), json!(false), Value::Null]
            }
            LeafShape::OrEmpty(other) => panic!("{leaf}: empty or {other:?}"),
        };
        for value in wrong {
            assert_eq!(
                parse(&with(&pointer(leaf, 0), value.clone())).map(|_| ()),
                Err(field(leaf, element_of(leaf), FieldFaultKind::WrongType)),
                "{leaf} {value}"
            );
        }
    }
}

/// An allowlisted key given twice is refused, whichever value comes last;
/// a repeated key outside the allowlist is skipped like any other.
#[test]
fn a_repeated_allowlisted_key_is_refused() {
    use NetgearLeaf as L;
    for (from, to, leaf, element) in [
        (
            "\"unreadMsgs\":0,",
            "\"unreadMsgs\":0,\"unreadMsgs\":0,",
            L::SmsUnread,
            None,
        ),
        (
            "\"unreadMsgs\":0,",
            "\"unreadMsgs\":5,\"unreadMsgs\":0,",
            L::SmsUnread,
            None,
        ),
        (
            "\"band\":3,",
            "\"band\":3,\"band\":3,",
            L::LteCarrierBand,
            Some(0),
        ),
    ] {
        let body = spliced(from, to);
        let duplicate = Err(field(leaf, element, FieldFaultKind::Duplicate));
        assert_eq!(parse(&body).map(|_| ()), duplicate, "{to}");
        assert_eq!(
            crate::router::netgear::redact_netgear_model_json(&body).map(|_| ()),
            duplicate,
            "{to}"
        );
    }
    // A second `signalStrength` object repeats its leaves.
    let body = spliced("\"laa\":{", "\"signalStrength\":{\"rsrp\":-90},\"laa\":{");
    assert_eq!(
        parse(&body).map(|_| ()),
        Err(field(L::SignalRsrp, None, FieldFaultKind::Duplicate))
    );
    let body = spliced("\"msgCount\":0,", "\"msgCount\":0,\"msgCount\":7,");
    assert_eq!(parse(&body), Ok(router::status()));
}

/// The service types the M7 reported with the SMARTY SIM (2026-10-16 and
/// 17) are read as such: `LteService` with `4G`, and with `4GPLUS`.
#[test]
fn the_smarty_service_types_are_read() {
    use NetgearLeaf as L;
    for (network, data, network_service, data_service) in [
        ("LteService", "4G", NetworkService::Lte, DataService::Lte),
        (
            "LteService",
            "4GPLUS",
            NetworkService::Lte,
            DataService::LtePlus,
        ),
        (
            "Nr5gService",
            "5GSUB6",
            NetworkService::Nr5g,
            DataService::NrSub6,
        ),
    ] {
        let body = edited(|value| {
            *value
                .pointer_mut(&pointer(L::WwanNetworkService, 0))
                .unwrap() = json!(network);
            *value.pointer_mut(&pointer(L::WwanDataService, 0)).unwrap() = json!(data);
        });
        let status = parse(&body).unwrap();
        let RadioState::Attached(radio) = &status.parts().radio else {
            panic!("the reading is attached");
        };
        assert_eq!(radio.network_service, network_service, "{network}");
        assert_eq!(radio.data_service, data_service, "{data}");
        assert_eq!(network_service.wire(), network);
        assert_eq!(data_service.wire(), data);
    }
}

/// The power states and charge sources the M7 has reported are read as
/// such: `Online` with `QuickCharge` (M2a), and, while the M7 ran on its
/// battery (2026-10-22), `Online` and then `Standby`, each with `None`.
#[test]
fn the_power_values_seen_are_read() {
    use NetgearLeaf as L;
    for (state, source) in [
        ("Online", "QuickCharge"),
        ("Online", "None"),
        ("Standby", "None"),
    ] {
        let body = edited(|value| {
            *value.pointer_mut(&pointer(L::PowerState, 0)).unwrap() = json!(state);
            *value
                .pointer_mut(&pointer(L::BatteryChargeSource, 0))
                .unwrap() = json!(source);
        });
        let status = parse(&body).unwrap();
        let power = &status.parts().power;
        assert_eq!(power.state.wire(), state, "{state}");
        assert_eq!(power.battery.source.wire(), source, "{source}");
    }
}

/// Every device enumeration accepts exactly the values the M2a capture
/// showed; any other spelling, in another case too, is `UnknownValue`
/// naming the path, never the value.
#[test]
fn unknown_enum_values_name_the_path_not_the_value() {
    use NetgearLeaf as L;
    let cases: [(NetgearLeaf, &str, &[&str]); 11] = [
        (L::WifiStatus, "Off", &["On", "off", "OFF"]),
        (L::WifiGuestStatus, "Off", &["On"]),
        (L::WifiAuxStatus, "Off", &["On"]),
        (
            L::WwanDataService,
            "5GSUB6",
            &["LTE", "5gsub6", "5GMMW", "4g", "4G+", "4GPlus"],
        ),
        (
            L::WwanConnection,
            "Connected",
            &["Disconnected", "connected"],
        ),
        (
            L::WwanNetworkService,
            "Nr5gService",
            &["lteservice", "LTEService", "nr5gservice", "UmtsService"],
        ),
        (
            L::BatteryChargeSource,
            "QuickCharge",
            &["Standard", "quickcharge", "none", "NONE"],
        ),
        (
            L::PowerState,
            "Online",
            &["Sleep", "online", "standby", "STANDBY"],
        ),
        (L::WwanThermalState, "Normal", &["Hot", "normal"]),
        (
            L::CurrentBand,
            "LTE B3",
            &["NR5G n78", "lte B3", "LTE B03", "LTE B", "LTE B3a", "B3"],
        ),
        (
            L::LteCarrierBandwidth,
            "20MHz",
            &["25MHz", "20mhz", "1.4MHz"],
        ),
    ];
    for (leaf, observed, unobserved) in cases {
        let at = pointer(leaf, 0);
        assert_eq!(fixture().pointer(&at), Some(&json!(observed)), "{leaf}");
        for value in unobserved {
            let error = parse(&with(&at, json!(value))).unwrap_err();
            assert_eq!(
                error,
                field(leaf, element_of(leaf), FieldFaultKind::UnknownValue),
                "{leaf} {value}"
            );
            let text = error.to_string();
            let path = if element_of(leaf).is_some() {
                "wwan.lteBandInfo[0].dlBandwidth".to_owned()
            } else {
                leaf.to_string()
            };
            assert!(text.contains(&path), "{text}");
            assert!(!text.contains(value), "{text}");
            assert!(!format!("{error:?}").contains(value));
        }
    }
    assert_eq!(
        parse(&with(&pointer(L::BatteryState, 0), json!("Charging"))).map(|_| ()),
        Err(field(L::BatteryState, None, FieldFaultKind::UnknownValue))
    );
    // Band 0 is out of range, not unknown; four digits or more exceed the
    // leaf's digit run, so they are not even text of its form.
    let band = |text: &str| parse(&with(&pointer(L::CurrentBand, 0), json!(text))).map(|_| ());
    assert_eq!(
        band("LTE B0"),
        Err(field(L::CurrentBand, None, FieldFaultKind::OutOfRange))
    );
    for text in ["LTE B1000", "LTE B99999"] {
        assert_eq!(
            band(text),
            Err(field(L::CurrentBand, None, FieldFaultKind::InvalidText)),
            "{text}"
        );
    }
    assert_eq!(band("LTE B999"), Ok(()));
}

/// Only an administrator's session is parsed as a status: the role must be
/// exactly `Admin`.
#[test]
fn only_admin_sessions_parse() {
    assert_eq!(ADMIN_ROLE, "Admin");
    for role in [
        "",
        "Guest",
        "admin",
        "ADMIN",
        "Admin ",
        " Admin",
        "Administrator",
    ] {
        assert_eq!(
            parse(&with(
                &pointer(NetgearLeaf::SessionUserRole, 0),
                json!(role)
            )),
            Err(RouterParseError::NotAdmin),
            "{role:?}"
        );
    }
}

/// Another model, or another API version, is unsupported; the session
/// parse checks the model too.
#[test]
fn another_model_or_api_is_unsupported() {
    let model = with(&pointer(NetgearLeaf::GeneralModel, 0), json!("MR6400"));
    let unsupported_model = RouterParseError::Unsupported {
        leaf: NetgearLeaf::GeneralModel,
    };
    assert_eq!(parse(&model), Err(unsupported_model));
    assert_eq!(
        parse_netgear_session(&model).map(|_| ()),
        Err(unsupported_model)
    );
    for api in ["3.0", "2.1", "2", "2.0 "] {
        assert_eq!(
            parse(&with(
                &pointer(NetgearLeaf::GeneralApiVersion, 0),
                json!(api)
            )),
            Err(RouterParseError::Unsupported {
                leaf: NetgearLeaf::GeneralApiVersion
            }),
            "{api:?}"
        );
    }
    assert_eq!(
        unsupported_model.to_string(),
        "the router is not an MR7450 speaking API 2.0 (general.model)"
    );
}

/// The checks run in a fixed order: the role, the model, the API, then the
/// fields; so an anonymous answer, which lacks every status leaf, is
/// `NotAdmin`, and an answer from another device is unsupported before any
/// field is missing.
#[test]
fn the_checks_run_in_order() {
    let anonymous = json!({
        "session": {
            "userRole": "",
            "lang": "en",
            "passwordCooloff": 0,
            "secToken": "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P",
            "supportedLangList": [{"id": "en", "isCurrent": true, "label": "English"}],
            "end": ""
        },
        "general": {"model": "MR7450", "productSKU": "x", "InstallID": "x", "end": ""}
    });
    let body = serde_json::to_vec(&anonymous).unwrap();
    assert_eq!(parse(&body), Err(RouterParseError::NotAdmin));
    let session = parse_netgear_session(&body).unwrap();
    assert!(!session.is_admin());
    assert_eq!(session.cooloff(), 0);
    let mut admin = anonymous.clone();
    admin["session"]["userRole"] = json!("Admin");
    let body = serde_json::to_vec(&admin).unwrap();
    assert_eq!(
        parse(&body),
        Err(field(
            NetgearLeaf::GeneralApiVersion,
            None,
            FieldFaultKind::Missing
        ))
    );
    admin["general"]["apiVersion"] = json!("2.0");
    let body = serde_json::to_vec(&admin).unwrap();
    assert_eq!(
        parse(&body),
        Err(field(
            NetgearLeaf::GeneralFirmware,
            None,
            FieldFaultKind::Missing
        ))
    );
    admin["general"]["model"] = json!("MR6400");
    let body = serde_json::to_vec(&admin).unwrap();
    assert_eq!(
        parse(&body),
        Err(RouterParseError::Unsupported {
            leaf: NetgearLeaf::GeneralModel
        })
    );
    // Within the fields, the first in table order wins.
    let both = edited(|value| {
        *value.pointer_mut("/sms/unreadMsgs").unwrap() = json!(-1);
        *value.pointer_mut("/general/devTemperature").unwrap() = json!(200);
    });
    assert_eq!(
        parse(&both).map(|_| ()),
        Err(field(
            NetgearLeaf::GeneralTemperature,
            None,
            FieldFaultKind::OutOfRange
        ))
    );
}

fn pcc() -> Value {
    json!({"isPcc": true, "sccId": 0, "band": 3, "dlBandwidth": "20MHz", "phyCid": "REDACTED"})
}

fn scc(band: u16) -> Value {
    json!({"isPcc": false, "sccId": 1, "band": band, "dlBandwidth": "10MHz"})
}

fn with_carriers(list: Value) -> Result<RouterStatus, RouterParseError> {
    parse(&with("/wwan/lteBandInfo", list))
}

fn lte_carriers(status: &RouterStatus) -> Option<LteCarriers> {
    let RadioState::Attached(radio) = &status.parts().radio else {
        panic!("the reading is attached");
    };
    radio.lte_carriers.clone()
}

/// The carrier list is entries then exactly one empty object as a
/// terminator, the primary first: `[{}]` is no carrier, and every other
/// arrangement is refused with its fault.
#[test]
fn lte_carriers_follow_the_terminator_convention() {
    let carrier = |band, dl_bandwidth| LteCarrier {
        band: BandNumber::new(band).unwrap(),
        dl_bandwidth,
    };
    let primary = carrier(3, LteBandwidth::Mhz20);
    assert_eq!(lte_carriers(&with_carriers(json!([{}])).unwrap()), None);
    assert_eq!(
        lte_carriers(&with_carriers(json!([pcc(), {}])).unwrap()),
        Some(LteCarriers::new(primary, Vec::new(), 0).unwrap())
    );
    assert_eq!(
        lte_carriers(&with_carriers(json!([pcc(), scc(20), {}])).unwrap()),
        Some(LteCarriers::new(primary, vec![carrier(20, LteBandwidth::Mhz10)], 0).unwrap())
    );
    let six: Vec<Value> = std::iter::once(pcc())
        .chain((1..=6).map(scc))
        .chain(std::iter::once(json!({})))
        .collect();
    assert_eq!(
        lte_carriers(&with_carriers(Value::Array(six)).unwrap())
            .unwrap()
            .secondary()
            .len(),
        6
    );
    let many = |entries: usize| -> Value {
        Value::Array(
            std::iter::once(pcc())
                .chain((1..entries).map(|band| scc(u16::try_from(band).unwrap())))
                .chain(std::iter::once(json!({})))
                .collect(),
        )
    };
    for (list, fault) in [
        (json!([pcc()]), CarrierFaultKind::MissingTerminator),
        (json!([]), CarrierFaultKind::MissingTerminator),
        (json!([pcc(), scc(20)]), CarrierFaultKind::MissingTerminator),
        (
            json!([{}, pcc(), {}]),
            CarrierFaultKind::MisplacedTerminator,
        ),
        (
            json!([pcc(), {}, {}]),
            CarrierFaultKind::MisplacedTerminator,
        ),
        (json!([{}, {}]), CarrierFaultKind::MisplacedTerminator),
        (
            json!([scc(20), pcc(), {}]),
            CarrierFaultKind::PrimaryNotFirst,
        ),
        (json!([scc(20), {}]), CarrierFaultKind::PrimaryNotFirst),
        (json!([pcc(), pcc(), {}]), CarrierFaultKind::SecondPrimary),
        (
            json!([pcc(), scc(20), pcc(), {}]),
            CarrierFaultKind::SecondPrimary,
        ),
        (many(8), CarrierFaultKind::TooManySecondaries),
        (many(15), CarrierFaultKind::TooManySecondaries),
        (many(16), CarrierFaultKind::TooLong),
        (json!({}), CarrierFaultKind::NotAnArray),
        (json!("[{}]"), CarrierFaultKind::NotAnArray),
        (Value::Null, CarrierFaultKind::NotAnArray),
        (json!([pcc(), 1, {}]), CarrierFaultKind::ElementNotAnObject),
        (json!([pcc(), [], {}]), CarrierFaultKind::ElementNotAnObject),
    ] {
        assert_eq!(
            with_carriers(list.clone()).map(|_| ()),
            Err(carriers_fault(fault)),
            "{list}"
        );
    }
    assert_eq!(usize::from(crate::router::netgear::MAX_ARRAY_ELEMENTS), 16);
    let twice = spliced("\"laa\":{", "\"lteBandInfo\":[{}],\"laa\":{");
    assert_eq!(
        parse(&twice).map(|_| ()),
        Err(carriers_fault(CarrierFaultKind::Duplicate))
    );
    assert_eq!(
        carriers_fault(CarrierFaultKind::MissingTerminator).to_string(),
        "router field wwan.lteBandInfo: no terminating empty object"
    );
}

/// The entry the M7 listed after the primary in 2 of 77 captures with the
/// SMARTY SIM (2026-10-16 and 17), each with `wwan.ca.SCCcount` 0, in
/// that capture's shape (the redactor's placeholders included).
fn unassigned() -> Value {
    json!({
        "band": 0, "channel": "REDACTED", "dlBandwidth": "Unknown", "isPcc": false,
        "phyCid": "REDACTED", "sccId": 0, "sccState": 0, "sccUlBandwidth": "REDACTED",
        "sccUlCaEnabled": "REDACTED", "sccUlChannel": 0
    })
}

/// Band 0 with the bandwidth `Unknown` after the primary is an unassigned
/// slot: counted, never listed as a carrier. Either alone is still refused
/// with the fault a carrier's leaf has, the primary is never one, and the
/// slots count toward the bound on secondary entries.
#[test]
fn an_unassigned_slot_is_counted_not_listed() {
    use NetgearLeaf as L;
    let carrier = |band, dl_bandwidth| LteCarrier {
        band: BandNumber::new(band).unwrap(),
        dl_bandwidth,
    };
    let primary = carrier(3, LteBandwidth::Mhz20);
    let b20 = carrier(20, LteBandwidth::Mhz10);
    for (list, secondary, slots) in [
        (json!([pcc(), unassigned(), {}]), vec![], 1),
        (json!([pcc(), scc(20), unassigned(), {}]), vec![b20], 1),
        (json!([pcc(), unassigned(), scc(20), {}]), vec![b20], 1),
        (json!([pcc(), unassigned(), unassigned(), {}]), vec![], 2),
    ] {
        assert_eq!(
            lte_carriers(&with_carriers(list.clone()).unwrap()),
            Some(LteCarriers::new(primary, secondary, slots).unwrap()),
            "{list}"
        );
    }
    let six_slots: Vec<Value> = std::iter::once(pcc())
        .chain(std::iter::repeat_with(unassigned).take(6))
        .chain(std::iter::once(json!({})))
        .collect();
    assert_eq!(
        lte_carriers(&with_carriers(Value::Array(six_slots)).unwrap())
            .unwrap()
            .unassigned_slots(),
        6
    );
    let seven_slots: Vec<Value> = std::iter::once(pcc())
        .chain(std::iter::repeat_with(unassigned).take(7))
        .chain(std::iter::once(json!({})))
        .collect();
    assert_eq!(
        with_carriers(Value::Array(seven_slots)).map(|_| ()),
        Err(carriers_fault(CarrierFaultKind::TooManySecondaries))
    );
    let mut band_alone = unassigned();
    band_alone["dlBandwidth"] = json!("10MHz");
    assert_eq!(
        with_carriers(json!([pcc(), band_alone, {}])).map(|_| ()),
        Err(field(
            L::LteCarrierBand,
            Some(1),
            FieldFaultKind::OutOfRange
        ))
    );
    let mut bandwidth_alone = unassigned();
    bandwidth_alone["band"] = json!(20);
    assert_eq!(
        with_carriers(json!([pcc(), bandwidth_alone, {}])).map(|_| ()),
        Err(field(
            L::LteCarrierBandwidth,
            Some(1),
            FieldFaultKind::UnknownValue
        ))
    );
    // Not the primary: first and not primary, or first and claiming to be.
    assert_eq!(
        with_carriers(json!([unassigned(), {}])).map(|_| ()),
        Err(carriers_fault(CarrierFaultKind::PrimaryNotFirst))
    );
    let mut claimed = unassigned();
    claimed["isPcc"] = json!(true);
    assert_eq!(
        with_carriers(json!([claimed, {}])).map(|_| ()),
        Err(field(
            L::LteCarrierBand,
            Some(0),
            FieldFaultKind::OutOfRange
        ))
    );
    // A second primary is refused before its band is read.
    let mut second = unassigned();
    second["isPcc"] = json!(true);
    assert_eq!(
        with_carriers(json!([pcc(), second, {}])).map(|_| ()),
        Err(carriers_fault(CarrierFaultKind::SecondPrimary))
    );
}

/// A fault in a carrier's leaf names the carrier by its index.
#[test]
fn carrier_field_errors_carry_the_element_index() {
    use NetgearLeaf as L;
    let mut bad_band = scc(20);
    bad_band["band"] = json!(0);
    let error = with_carriers(json!([pcc(), bad_band, {}])).unwrap_err();
    assert_eq!(
        error,
        field(L::LteCarrierBand, Some(1), FieldFaultKind::OutOfRange)
    );
    assert_eq!(
        error.to_string(),
        "router field wwan.lteBandInfo[1].band: out of range"
    );
    let mut no_bandwidth = scc(20);
    no_bandwidth.as_object_mut().unwrap().remove("dlBandwidth");
    assert_eq!(
        with_carriers(json!([pcc(), scc(1), no_bandwidth, {}])).map(|_| ()),
        Err(field(
            L::LteCarrierBandwidth,
            Some(2),
            FieldFaultKind::Missing
        ))
    );
    let mut no_primary_flag = pcc();
    no_primary_flag.as_object_mut().unwrap().remove("isPcc");
    assert_eq!(
        with_carriers(json!([no_primary_flag, {}])).map(|_| ()),
        Err(field(
            L::LteCarrierPrimary,
            Some(0),
            FieldFaultKind::Missing
        ))
    );
    let mut text_band = scc(20);
    text_band["band"] = json!("20");
    assert_eq!(
        with_carriers(json!([pcc(), text_band, {}])).map(|_| ()),
        Err(field(L::LteCarrierBand, Some(1), FieldFaultKind::WrongType))
    );
    assert_eq!(
        with_carriers(json!([pcc(), scc(1000), {}])).map(|_| ()),
        Err(field(
            L::LteCarrierBand,
            Some(1),
            FieldFaultKind::OutOfRange
        ))
    );
}

/// The WWAN counters are decimal strings in canonical form within a
/// `u64`.
#[test]
fn decimal_counters_are_canonical() {
    let leaf = NetgearLeaf::WwanRxBytes;
    let at = pointer(leaf, 0);
    let rx =
        |text: &str| parse(&with(&at, json!(text))).map(|status| status.parts().counters.rx_bytes);
    assert_eq!(rx("0"), Ok(0));
    assert_eq!(rx("591655199"), Ok(591_655_199));
    assert_eq!(rx("18446744073709551615"), Ok(u64::MAX));
    for (text, fault) in [
        ("007", FieldFaultKind::NotCanonical),
        ("00", FieldFaultKind::NotCanonical),
        ("-1", FieldFaultKind::InvalidText),
        ("+1", FieldFaultKind::InvalidText),
        ("1e3", FieldFaultKind::InvalidText),
        ("1 ", FieldFaultKind::InvalidText),
        ("", FieldFaultKind::InvalidText),
        ("123456789012345678901", FieldFaultKind::InvalidText),
        ("18446744073709551616", FieldFaultKind::OutOfRange),
        ("99999999999999999999", FieldFaultKind::OutOfRange),
    ] {
        assert_eq!(rx(text), Err(field(leaf, None, fault)), "{text:?}");
    }
    assert_eq!(
        parse(&with(&at, json!(591_655_199))).map(|_| ()),
        Err(field(leaf, None, FieldFaultKind::WrongType))
    );
    let tx = NetgearLeaf::WwanTxBytes;
    assert_eq!(
        parse(&with(&pointer(tx, 0), json!("01"))).map(|_| ()),
        Err(field(tx, None, FieldFaultKind::NotCanonical))
    );
}

/// An identifier written into any allowlisted text leaf is refused by the
/// parser, and the redactor withholds it (a placeholder, the leaf named): no allowlisted text leaf
/// can carry an IMEI, ICCID, IMSI or phone number, whatever the firmware
/// puts there.
#[test]
fn identifier_shaped_values_fit_no_allowlisted_text() {
    use crate::router::netgear::{LeafShape, redact_netgear_model_json};
    let identifiers = [
        "356938035643809",
        "8944110068256270054",
        "234301234567890",
        "+447700900123",
        "07700900123",
    ];
    let mut exercised = 0;
    for leaf in NetgearLeaf::ALL.iter().copied() {
        let (line, digits) = match leaf.shape() {
            // An empty-or leaf judges every identifier by its inner shape.
            LeafShape::Text { .. } | LeafShape::OrEmpty(LeafShape::Text { .. }) => (false, false),
            LeafShape::Line { .. } | LeafShape::OrEmpty(LeafShape::Line { .. }) => (true, false),
            LeafShape::Digits { .. } => (false, true),
            LeafShape::Bool | LeafShape::Int | LeafShape::Secret { .. } => continue,
            LeafShape::OrEmpty(other) => panic!("{leaf}: empty or {other:?}"),
        };
        exercised += 1;
        for identifier in identifiers {
            let text = if line {
                format!("{identifier}\n")
            } else {
                identifier.to_owned()
            };
            let body = with(&pointer(leaf, 0), json!(text));
            let redacted = redact_netgear_model_json(&body).unwrap();
            let withheld = || {
                let captured = String::from_utf8(redacted.as_bytes().to_vec()).unwrap();
                assert!(
                    !captured.contains(identifier.trim_start_matches('+')),
                    "{leaf} {identifier}"
                );
                redacted.withheld().to_vec()
            };
            if digits {
                // The counters are digits by nature; the MCC and MNC are
                // three digits at most.
                if matches!(leaf, NetgearLeaf::PlmnMcc | NetgearLeaf::PlmnMnc) {
                    assert_eq!(
                        withheld(),
                        [field(leaf, None, FieldFaultKind::InvalidText)],
                        "{leaf} {identifier}"
                    );
                }
            } else {
                assert_eq!(
                    withheld(),
                    [field(leaf, element_of(leaf), FieldFaultKind::InvalidText)],
                    "{leaf} {identifier}"
                );
                if LeafSet::Status.contains(leaf) {
                    assert!(parse(&body).is_err(), "{leaf} {identifier}");
                }
            }
        }
    }
    // Every text, line and digit leaf, the SPN and the web app version among
    // them.
    assert_eq!(exercised, 23);
}

/// A data session longer than the uptime is refused (a session cannot
/// outlast the boot); one as long is accepted.
#[test]
fn a_session_longer_than_uptime_is_refused() {
    let session = pointer(NetgearLeaf::WwanSessionDuration, 0);
    assert_eq!(
        parse(&with(&session, json!(359_273))),
        Err(RouterParseError::SessionExceedsUptime)
    );
    assert!(parse(&with(&session, json!(359_272))).is_ok());
    assert_eq!(
        RouterParseError::SessionExceedsUptime.to_string(),
        "the router reports a data session longer than its uptime"
    );
}

/// Every JSON pointer of a scalar or empty container of `value`, with the
/// allowlist path it would match (array indices as `[]`).
fn leaves(value: &Value, pointer: String, path: Vec<String>, out: &mut Vec<(String, Vec<String>)>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                let mut path = path.clone();
                path.push(key.clone());
                leaves(child, format!("{pointer}/{key}"), path, out);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (index, child) in items.iter().enumerate() {
                let mut path = path.clone();
                path.push("[]".to_owned());
                leaves(child, format!("{pointer}/{index}"), path, out);
            }
        }
        _ => out.push((pointer, path)),
    }
}

/// Whether `path` is an allowlisted leaf's path or leads to one (the
/// carrier list's terminator, an empty object, is on the carriers' path).
fn on_an_allowlisted_path(path: &[String]) -> bool {
    NetgearLeaf::ALL.iter().any(|leaf| {
        let segments = leaf.segments();
        segments.len() >= path.len()
            && segments
                .iter()
                .zip(path)
                .all(|(segment, part)| match segment {
                    Segment::Key(key) => key == part,
                    Segment::Each => part == "[]",
                })
    })
}

/// The fixture's leaves (scalars and empty containers) off the allowlisted
/// paths.
pub(super) fn outside_pointers() -> Vec<String> {
    let mut found = Vec::new();
    leaves(&fixture(), String::new(), Vec::new(), &mut found);
    let outside: Vec<String> = found
        .into_iter()
        .filter(|(_, path)| !on_an_allowlisted_path(path))
        .map(|(pointer, _)| pointer)
        .collect();
    assert!(outside.len() > 500, "{}", outside.len());
    outside
}

fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("finite", |value| value.is_finite())
            .prop_map(Value::from),
        ".{0,24}".prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[a-z]{1,8}", inner, 0..4)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    /// Whatever a leaf outside the allowlist holds, the status is the
    /// same: the parser never reads it.
    #[test]
    fn the_status_does_not_depend_on_any_outside_leaf(
        index in any::<prop::sample::Index>(),
        replacement in any_json(),
    ) {
        let pointers = outside_pointers();
        let at = &pointers[index.index(pointers.len())];
        prop_assert_eq!(parse(&with(at, replacement)), Ok(router::status()));
    }
}

/// An error's unavailable reason: a session that is not an
/// administrator's is a failed login, another device is unsupported, every
/// other fault is a malformed answer.
#[test]
fn parse_errors_map_to_unavailable_reasons() {
    for (error, reason) in every_error() {
        let expected = match error.kind() {
            RouterParseErrorKind::NotAdmin => RouterUnavailableReason::AuthFailed,
            RouterParseErrorKind::Unsupported => RouterUnavailableReason::Unsupported,
            RouterParseErrorKind::Syntax
            | RouterParseErrorKind::Truncated
            | RouterParseErrorKind::NotAnObject
            | RouterParseErrorKind::KeyRefused
            | RouterParseErrorKind::Field
            | RouterParseErrorKind::Carriers
            | RouterParseErrorKind::SessionExceedsUptime => RouterUnavailableReason::Malformed,
        };
        assert_eq!(error.reason(), expected, "{error:?}");
        assert_eq!(reason, expected, "{error:?}");
    }
}

/// One error of every kind, each produced by a real input, with the
/// reason it maps to.
fn every_error() -> Vec<(RouterParseError, RouterUnavailableReason)> {
    use crate::router::netgear::redact_netgear_model_json;
    use RouterUnavailableReason as R;
    vec![
        (parse(b"{,}").unwrap_err(), R::Malformed),
        (parse(b"{\"a\":").unwrap_err(), R::Malformed),
        (parse(b"[]").unwrap_err(), R::Malformed),
        (
            redact_netgear_model_json(b"{\"aa:bb:cc:dd:ee:ff\":1}").unwrap_err(),
            R::Malformed,
        ),
        (
            parse(&without("/sms/unreadMsgs")).unwrap_err(),
            R::Malformed,
        ),
        (with_carriers(json!([])).unwrap_err(), R::Malformed),
        (
            parse(&with(
                &pointer(NetgearLeaf::SessionUserRole, 0),
                json!("Guest"),
            ))
            .unwrap_err(),
            R::AuthFailed,
        ),
        (
            parse(&with(
                &pointer(NetgearLeaf::GeneralModel, 0),
                json!("MR6400"),
            ))
            .unwrap_err(),
            R::Unsupported,
        ),
        (
            parse(&with(
                &pointer(NetgearLeaf::WwanSessionDuration, 0),
                json!(400_000),
            ))
            .unwrap_err(),
            R::Malformed,
        ),
    ]
}

#[test]
fn every_router_parse_error_kind_is_named_once() {
    let errors = every_error();
    let kinds: Vec<RouterParseErrorKind> = errors.iter().map(|(error, _)| error.kind()).collect();
    assert_eq!(
        kinds,
        [
            RouterParseErrorKind::Syntax,
            RouterParseErrorKind::Truncated,
            RouterParseErrorKind::NotAnObject,
            RouterParseErrorKind::KeyRefused,
            RouterParseErrorKind::Field,
            RouterParseErrorKind::Carriers,
            RouterParseErrorKind::NotAdmin,
            RouterParseErrorKind::Unsupported,
            RouterParseErrorKind::SessionExceedsUptime,
        ]
    );
    assert_eq!(kinds, RouterParseErrorKind::ALL);
    for (error, _) in &errors {
        assert!(!error.to_string().is_empty());
    }
}

/// Every field fault is produced by a real input.
#[test]
fn every_field_fault_kind_is_produced() {
    use NetgearLeaf as L;
    let produced = [
        (
            FieldFaultKind::Missing,
            parse(&without("/sms/unreadMsgs")).unwrap_err(),
        ),
        (
            FieldFaultKind::WrongType,
            parse(&with(&pointer(L::SmsUnread, 0), json!("0"))).unwrap_err(),
        ),
        (
            FieldFaultKind::Duplicate,
            parse(&spliced(
                "\"unreadMsgs\":0,",
                "\"unreadMsgs\":0,\"unreadMsgs\":0,",
            ))
            .unwrap_err(),
        ),
        (
            FieldFaultKind::OutOfRange,
            parse(&with(&pointer(L::SmsUnread, 0), json!(-1))).unwrap_err(),
        ),
        (
            FieldFaultKind::UnknownValue,
            parse(&with(&pointer(L::WifiStatus, 0), json!("On"))).unwrap_err(),
        ),
        (
            FieldFaultKind::InvalidText,
            parse(&with(&pointer(L::SimSpn, 0), json!("CM123"))).unwrap_err(),
        ),
        (
            FieldFaultKind::NotCanonical,
            parse(&with(&pointer(L::WwanRxBytes, 0), json!("01"))).unwrap_err(),
        ),
    ];
    let kinds: Vec<FieldFaultKind> = produced.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, FieldFaultKind::ALL);
    for (kind, error) in produced {
        let RouterParseError::Field { fault, .. } = error else {
            panic!("{kind} produced {error:?}");
        };
        assert_eq!(fault, kind);
        assert!(!kind.describe().is_empty());
    }
}

/// Every carrier fault is produced by a real input.
#[test]
fn every_carrier_fault_kind_is_produced() {
    let produced = [
        (
            CarrierFaultKind::Absent,
            parse(&without("/wwan/lteBandInfo")).unwrap_err(),
        ),
        (
            CarrierFaultKind::NotAnArray,
            with_carriers(json!({})).unwrap_err(),
        ),
        (
            CarrierFaultKind::Duplicate,
            parse(&spliced("\"laa\":{", "\"lteBandInfo\":[{}],\"laa\":{")).unwrap_err(),
        ),
        (
            CarrierFaultKind::TooLong,
            with_carriers(Value::Array(vec![json!({}); 17])).unwrap_err(),
        ),
        (
            CarrierFaultKind::ElementNotAnObject,
            with_carriers(json!([1])).unwrap_err(),
        ),
        (
            CarrierFaultKind::MissingTerminator,
            with_carriers(json!([pcc()])).unwrap_err(),
        ),
        (
            CarrierFaultKind::MisplacedTerminator,
            with_carriers(json!([{}, pcc(), {}])).unwrap_err(),
        ),
        (
            CarrierFaultKind::PrimaryNotFirst,
            with_carriers(json!([scc(20), {}])).unwrap_err(),
        ),
        (
            CarrierFaultKind::SecondPrimary,
            with_carriers(json!([pcc(), pcc(), {}])).unwrap_err(),
        ),
        (
            CarrierFaultKind::TooManySecondaries,
            with_carriers(Value::Array(
                std::iter::once(pcc())
                    .chain((1..=7).map(scc))
                    .chain(std::iter::once(json!({})))
                    .collect(),
            ))
            .unwrap_err(),
        ),
    ];
    let kinds: Vec<CarrierFaultKind> = produced.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, CarrierFaultKind::ALL);
    for (kind, error) in produced {
        assert_eq!(error, carriers_fault(kind));
        assert!(!kind.describe().is_empty());
    }
}
