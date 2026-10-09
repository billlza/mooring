// SPDX-License-Identifier: GPL-3.0-or-later

//! The router's value types: plausible bounds, printable texts, and an
//! encoding that refuses any field it does not name.

use mooring_model::UnixTime;

use crate::error::{RouterValueError, RouterValueErrorKind};
use crate::router::{
    Band, BandNumber, BatteryPercent, CarrierName, Celsius, FirmwareVersion, RadioAccess,
    RadioState, RouterPower, RouterReading, RouterStatus, RouterTextField, RouterUnavailableReason,
    Rsrp, Rsrq, Rssi, Signal, SignalMetric, Sinr,
};

macro_rules! bounds {
    ($name:ident, $metric:ident) => {{
        assert_eq!(
            $name::from_tenths($name::MIN_TENTHS).unwrap().tenths(),
            $name::MIN_TENTHS
        );
        assert_eq!(
            $name::from_tenths($name::MAX_TENTHS).unwrap().tenths(),
            $name::MAX_TENTHS
        );
        for outside in [
            $name::MIN_TENTHS - 1,
            $name::MAX_TENTHS + 1,
            i16::MIN,
            i16::MAX,
        ] {
            assert_eq!(
                $name::from_tenths(outside),
                Err(RouterValueError::SignalOutOfRange {
                    metric: SignalMetric::$metric,
                    tenths: outside
                })
            );
            assert!(serde_json::from_str::<$name>(&outside.to_string()).is_err());
        }
        let inside = $name::from_tenths($name::MAX_TENTHS - 5).unwrap();
        let json = serde_json::to_string(&inside).unwrap();
        assert_eq!(json, ($name::MAX_TENTHS - 5).to_string());
        assert_eq!(serde_json::from_str::<$name>(&json).unwrap(), inside);
    }};
}

#[test]
fn signal_readings_stay_within_the_3gpp_reporting_ranges() {
    bounds!(Rsrp, Rsrp);
    bounds!(Rsrq, Rsrq);
    bounds!(Sinr, Sinr);
    bounds!(Rssi, Rssi);
    assert_eq!((Rsrp::MIN_TENTHS, Rsrp::MAX_TENTHS), (-1560, -310));
    assert_eq!((Rsrq::MIN_TENTHS, Rsrq::MAX_TENTHS), (-430, 200));
    assert_eq!((Sinr::MIN_TENTHS, Sinr::MAX_TENTHS), (-230, 400));
    assert_eq!((Rssi::MIN_TENTHS, Rssi::MAX_TENTHS), (-1500, 0));
    for metric in [
        SignalMetric::Rsrp,
        SignalMetric::Rsrq,
        SignalMetric::Sinr,
        SignalMetric::Rssi,
    ] {
        assert!(!metric.to_string().is_empty());
    }
}

#[test]
fn temperature_and_charge_are_bounded() {
    assert_eq!(Celsius::new(-40).unwrap().get(), -40);
    assert_eq!(Celsius::new(125).unwrap().get(), 125);
    assert_eq!(
        Celsius::new(-41),
        Err(RouterValueError::TemperatureOutOfRange { celsius: -41 })
    );
    assert_eq!(
        Celsius::new(126),
        Err(RouterValueError::TemperatureOutOfRange { celsius: 126 })
    );
    assert!(serde_json::from_str::<Celsius>("200").is_err());
    assert_eq!(BatteryPercent::new(0).unwrap().get(), 0);
    assert_eq!(BatteryPercent::new(100).unwrap().get(), 100);
    assert_eq!(
        BatteryPercent::new(101),
        Err(RouterValueError::BatteryPercentOutOfRange { percent: 101 })
    );
    assert!(serde_json::from_str::<BatteryPercent>("101").is_err());
    assert_eq!(
        serde_json::to_string(&Celsius::new(41).unwrap()).unwrap(),
        "41"
    );
}

#[test]
fn router_texts_are_short_printable_ascii_and_never_echoed() {
    assert_eq!(CarrierName::parse("EE").unwrap().as_str(), "EE");
    assert_eq!(CarrierName::parse("O2-UK").unwrap().as_str(), "O2-UK");
    assert_eq!(
        FirmwareVersion::parse("NTG9X75C_10.05.07.00")
            .unwrap()
            .as_str(),
        "NTG9X75C_10.05.07.00"
    );
    assert_eq!(CarrierName::MAX_BYTES, 32);
    assert_eq!(FirmwareVersion::MAX_BYTES, 64);
    assert!(CarrierName::parse(&"E".repeat(32)).is_ok());
    assert!(FirmwareVersion::parse(&"1.".repeat(32)).is_ok());
    let secretish = "SMS: meet at 9";
    for bad in ["", " EE", "EE ", "E\nE", "É", "\u{0}", &"E".repeat(33)] {
        assert_eq!(
            CarrierName::parse(bad),
            Err(RouterValueError::InvalidText {
                field: RouterTextField::Carrier
            })
        );
    }
    let error = CarrierName::parse(&format!("{secretish}{}", "x".repeat(20))).unwrap_err();
    assert_eq!(
        error,
        RouterValueError::InvalidText {
            field: RouterTextField::Carrier
        }
    );
    assert!(!format!("{error} {error:?}").contains("meet"));
    assert_eq!(
        FirmwareVersion::parse(&"1.".repeat(33)),
        Err(RouterValueError::InvalidText {
            field: RouterTextField::Firmware
        })
    );
    assert!(serde_json::from_str::<CarrierName>("\"\"").is_err());
    for field in [
        RouterTextField::Band,
        RouterTextField::Carrier,
        RouterTextField::Firmware,
    ] {
        assert!(!field.to_string().is_empty());
    }
}

/// A band is `B<n>` (LTE) or `n<n>` (NR) with a band number of 1..=999
/// and no leading zero, so it can hold nothing but a band.
#[test]
fn a_band_is_a_typed_band_number() {
    let number = |number| BandNumber::new(number).unwrap();
    for (text, band) in [
        ("B3", Band::Lte(number(3))),
        ("B20", Band::Lte(number(20))),
        ("n78", Band::Nr(number(78))),
        ("n258", Band::Nr(number(258))),
        ("B999", Band::Lte(number(999))),
    ] {
        assert_eq!(Band::parse(text), Ok(band), "{text}");
        assert_eq!(band.to_string(), text);
        assert_eq!(serde_json::to_string(&band).unwrap(), format!("\"{text}\""));
        assert_eq!(
            serde_json::from_str::<Band>(&format!("\"{text}\"")).unwrap(),
            band
        );
    }
    for bad in [
        "", "B", "n", "B0", "B03", "B1000", "b3", "N78", "LTE B3", "B3 ", "B-3", "B3a", "n78+B3",
    ] {
        assert_eq!(
            Band::parse(bad),
            Err(RouterValueError::InvalidText {
                field: RouterTextField::Band
            }),
            "{bad}"
        );
    }
    assert!(serde_json::from_str::<Band>("\"B0\"").is_err());
    for bad in [0, 1000, u16::MAX] {
        assert_eq!(
            BandNumber::new(bad),
            Err(RouterValueError::InvalidText {
                field: RouterTextField::Band
            })
        );
    }
    assert_eq!(number(999).get(), BandNumber::MAX);
}

/// The free-text fields cannot carry a subscriber, device or cell
/// identifier even if a parser mapped the wrong field into one: IMEI-,
/// IMSI-, ICCID- and phone-number-shaped values are refused by every text
/// field and by the band (critique C-7, design §15.5).
#[test]
fn identifier_shaped_values_fit_no_router_field() {
    let identifiers = [
        "356938035643809",      // IMEI, 15 digits
        "234301234567890",      // IMSI, 15 digits
        "8944110068256270054",  // ICCID, 19 digits
        "89441100682562700543", // ICCID, 20 digits
        "+447700900123",        // MSISDN, international
        "07700900123",          // MSISDN, national
        "IMEI 356938035643809",
        "fw-20230815-1234567",
        "cell 26843545",
    ];
    for text in identifiers {
        assert!(Band::parse(text).is_err(), "band {text}");
        assert!(CarrierName::parse(text).is_err(), "carrier {text}");
        assert!(FirmwareVersion::parse(text).is_err(), "firmware {text}");
    }
    // The limits: a carrier name holds at most two digits in a row, a
    // firmware version at most six (a date stamp such as 230815).
    assert!(CarrierName::parse("Mobile 42").is_ok());
    assert!(CarrierName::parse("Mobile 423").is_err());
    assert!(FirmwareVersion::parse("M7_230815_1.2").is_ok());
    assert!(FirmwareVersion::parse("M7_2308150_1.2").is_err());
}

pub(crate) fn status() -> RouterStatus {
    RouterStatus {
        polled_at: UnixTime::from_secs(1_791_453_600),
        radio: RadioState::Attached {
            access: RadioAccess::NrNsa,
            band: Band::parse("n78").unwrap(),
            // The exit line's carrier, as the scenarios spell it; what the
            // M7 displays for a SMARTY SIM is unknown until the M2a capture.
            carrier: CarrierName::parse("SMARTY").unwrap(),
            signal: Signal {
                rsrp: Some(Rsrp::from_tenths(-985).unwrap()),
                rsrq: Some(Rsrq::from_tenths(-105).unwrap()),
                sinr: Some(Sinr::from_tenths(124).unwrap()),
                rssi: None,
            },
        },
        temperature_c: Celsius::new(41).unwrap(),
        power: RouterPower::Plugged,
        data_counter_bytes: 212_000_000_000,
        connected_clients: 1,
        unread_sms: 0,
        firmware: FirmwareVersion::parse("NTG9X75C_10.05.07.00").unwrap(),
        uptime_secs: 523_000,
    }
}

/// The router status has a fixed encoding and refuses any field it does
/// not name, so a parser cannot smuggle a cell id or an IMEI through it.
#[test]
fn the_router_status_refuses_fields_it_does_not_name() {
    let reading = RouterReading::Available(status());
    let json = serde_json::to_string(&reading).unwrap();
    assert_eq!(
        json,
        r#"{"available":{"polled_at":1791453600,"radio":{"attached":{"access":"nr_nsa","band":"n78","carrier":"SMARTY","signal":{"rsrp":-985,"rsrq":-105,"sinr":124,"rssi":null}}},"temperature_c":41,"power":"plugged","data_counter_bytes":212000000000,"connected_clients":1,"unread_sms":0,"firmware":"NTG9X75C_10.05.07.00","uptime_secs":523000}}"#
    );
    assert_eq!(
        serde_json::from_str::<RouterReading>(&json).unwrap(),
        reading
    );
    for (extra, key) in [
        (r#","cell_id":"0x1a2b""#, "cell_id"),
        (r#","imei":"356938035643809""#, "imei"),
        (r#","sms":[{"text":"x"}]"#, "sms"),
    ] {
        let smuggled = json.replacen(r#","uptime_secs""#, &format!(r#"{extra},"uptime_secs""#), 1);
        assert!(smuggled.contains(key));
        assert!(
            serde_json::from_str::<RouterReading>(&smuggled).is_err(),
            "{key}"
        );
    }
    // A missing reading is an error, not "no reading".
    let missing = json.replace(r#","rssi":null"#, "");
    assert!(serde_json::from_str::<RouterReading>(&missing).is_err());
    let battery = RouterPower::Battery {
        percent: BatteryPercent::new(64).unwrap(),
        charging: true,
    };
    assert_eq!(
        serde_json::to_string(&battery).unwrap(),
        r#"{"battery":{"percent":64,"charging":true}}"#
    );
    let unavailable = RouterReading::Unavailable {
        reason: RouterUnavailableReason::NotConfigured,
        last_polled_at: None,
    };
    assert_eq!(
        serde_json::to_string(&unavailable).unwrap(),
        r#"{"unavailable":{"reason":"not_configured","last_polled_at":null}}"#
    );
    assert!(
        serde_json::from_str::<RouterReading>(r#"{"unavailable":{"reason":"not_configured"}}"#)
            .is_err()
    );
    assert_eq!(
        serde_json::to_string(&RadioState::NoService).unwrap(),
        "\"no_service\""
    );
}

#[test]
fn every_router_value_error_kind_is_named_once() {
    let errors = [
        (
            RouterValueErrorKind::SignalOutOfRange,
            RouterValueError::SignalOutOfRange {
                metric: SignalMetric::Rsrp,
                tenths: 0,
            },
        ),
        (
            RouterValueErrorKind::TemperatureOutOfRange,
            RouterValueError::TemperatureOutOfRange { celsius: 200 },
        ),
        (
            RouterValueErrorKind::BatteryPercentOutOfRange,
            RouterValueError::BatteryPercentOutOfRange { percent: 101 },
        ),
        (
            RouterValueErrorKind::InvalidText,
            RouterValueError::InvalidText {
                field: RouterTextField::Firmware,
            },
        ),
    ];
    for (kind, error) in &errors {
        assert_eq!(error.kind(), *kind);
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(
        errors.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
        RouterValueErrorKind::ALL
    );
}
