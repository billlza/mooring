// SPDX-License-Identifier: GPL-3.0-or-later

//! The router's value types: plausible bounds, printable texts, closed
//! device vocabularies, and an encoding that refuses any field it does not
//! name.

use mooring_model::UnixTime;

use crate::error::{RouterValueError, RouterValueErrorKind};
use crate::router::{
    Band, BandNumber, Battery, BatteryPercent, BatteryState, CarrierName, Celsius, ChargeSource,
    DataService, FirmwareVersion, LteBandwidth, LteCarrier, LteCarriers, LteSignal, Mcc, Mnc,
    NetworkService, NrSignal, Plmn, PowerState, Radio, RadioState, RouterPower, RouterReading,
    RouterSettings, RouterStatus, RouterStatusParts, RouterTextField, RouterUnavailableReason,
    RouterWifi, Rsrp, Rsrq, Rssi, SignalMetric, Sinr, ThermalState, WebAppVersion, WifiApStatus,
    WwanCounters,
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
        FirmwareVersion::parse("NTGX75_10.04.43.01")
            .unwrap()
            .as_str(),
        "NTGX75_10.04.43.01"
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
        RouterTextField::WebApp,
        RouterTextField::Mcc,
        RouterTextField::Mnc,
    ] {
        assert!(!field.to_string().is_empty());
    }
}

/// The web app version has the firmware version's limits; an MCC is
/// exactly three digits and an MNC two or three, its length kept (`30`
/// and `030` are different networks' codes), both on the wire as strings.
#[test]
fn new_text_types_are_bounded() {
    assert_eq!(
        WebAppVersion::parse("M7_GENERIC_v07.01.81.00")
            .unwrap()
            .as_str(),
        "M7_GENERIC_v07.01.81.00"
    );
    assert_eq!(
        (WebAppVersion::MAX_BYTES, WebAppVersion::MAX_DIGIT_RUN),
        (64, 6)
    );
    for bad in [
        "",
        "M7_GENERIC_v07.01.81.00\n",
        "M7_2308150",
        &"v".repeat(65),
    ] {
        assert_eq!(
            WebAppVersion::parse(bad),
            Err(RouterValueError::InvalidText {
                field: RouterTextField::WebApp
            }),
            "{bad:?}"
        );
    }
    let mcc = Mcc::parse("234").unwrap();
    assert_eq!(
        (mcc.to_string(), mcc.digits()),
        ("234".to_owned(), &b"234"[..])
    );
    assert_eq!(serde_json::to_string(&mcc).unwrap(), "\"234\"");
    assert_eq!(serde_json::from_str::<Mcc>("\"234\"").unwrap(), mcc);
    for bad in ["", "23", "2345", "23a", " 234", "-23", "２３４"] {
        assert_eq!(
            Mcc::parse(bad),
            Err(RouterValueError::InvalidText {
                field: RouterTextField::Mcc
            }),
            "{bad:?}"
        );
    }
    assert!(serde_json::from_str::<Mcc>("234").is_err());
    let two = Mnc::parse("30").unwrap();
    let three = Mnc::parse("030").unwrap();
    assert_ne!(two, three);
    assert_eq!(
        (two.to_string(), three.to_string()),
        ("30".to_owned(), "030".to_owned())
    );
    assert_eq!(serde_json::to_string(&three).unwrap(), "\"030\"");
    assert_eq!(serde_json::from_str::<Mnc>("\"030\"").unwrap(), three);
    for bad in ["", "3", "0300", "3O", "+30"] {
        assert_eq!(
            Mnc::parse(bad),
            Err(RouterValueError::InvalidText {
                field: RouterTextField::Mnc
            }),
            "{bad:?}"
        );
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
        assert!(serde_json::from_str::<BandNumber>(&bad.to_string()).is_err());
    }
    assert_eq!(number(999).get(), BandNumber::MAX);
    assert_eq!(serde_json::to_string(&number(3)).unwrap(), "3");
    assert_eq!(serde_json::from_str::<BandNumber>("3").unwrap(), number(3));
}

/// The free-text fields cannot carry a subscriber, device or cell
/// identifier even if a parser mapped the wrong field into one: IMEI-,
/// IMSI-, ICCID- and phone-number-shaped values are refused by every text
/// field, the band and the network codes (critique C-7, design §15.5).
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
        assert!(WebAppVersion::parse(text).is_err(), "web app {text}");
        assert!(Mcc::parse(text).is_err(), "MCC {text}");
        assert!(Mnc::parse(text).is_err(), "MNC {text}");
    }
    // The limits: a carrier name holds at most two digits in a row, a
    // firmware version at most six (a date stamp such as 230815).
    assert!(CarrierName::parse("Mobile 42").is_ok());
    assert!(CarrierName::parse("Mobile 423").is_err());
    assert!(FirmwareVersion::parse("M7_230815_1.2").is_ok());
    assert!(FirmwareVersion::parse("M7_2308150_1.2").is_err());
}

/// Every device vocabulary holds exactly the values the M2a capture
/// showed, spelled as the M7 spells them, looked up exactly.
#[test]
fn device_vocabularies_hold_the_observed_values_only() {
    fn check<T: Copy + PartialEq + std::fmt::Debug + serde::Serialize>(
        all: &[T],
        wire: fn(T) -> &'static str,
        from_wire: fn(&str) -> Option<T>,
        expected: &[(&str, &str)],
    ) {
        let found: Vec<(&str, String)> = all
            .iter()
            .map(|value| (wire(*value), serde_json::to_string(value).unwrap()))
            .collect();
        let expected: Vec<(&str, String)> = expected
            .iter()
            .map(|(device, json)| (*device, format!("\"{json}\"")))
            .collect();
        assert_eq!(found, expected);
        for value in all {
            assert_eq!(from_wire(wire(*value)), Some(*value));
            assert_eq!(from_wire(&wire(*value).to_lowercase()), None);
            assert_eq!(from_wire(&format!("{} ", wire(*value))), None);
        }
        assert_eq!(from_wire(""), None);
    }
    check(
        NetworkService::ALL,
        NetworkService::wire,
        NetworkService::from_wire,
        &[("Nr5gService", "nr5g"), ("LteService", "lte")],
    );
    check(
        DataService::ALL,
        DataService::wire,
        DataService::from_wire,
        &[("5GSUB6", "nr_sub6"), ("4G", "lte"), ("4GPLUS", "lte_plus")],
    );
    check(
        ThermalState::ALL,
        ThermalState::wire,
        ThermalState::from_wire,
        &[("Normal", "normal")],
    );
    check(
        PowerState::ALL,
        PowerState::wire,
        PowerState::from_wire,
        &[("Online", "online"), ("Standby", "standby")],
    );
    check(
        BatteryState::ALL,
        BatteryState::wire,
        BatteryState::from_wire,
        &[("Normal", "normal")],
    );
    check(
        ChargeSource::ALL,
        ChargeSource::wire,
        ChargeSource::from_wire,
        &[("QuickCharge", "quick_charge"), ("None", "no_source")],
    );
    check(
        WifiApStatus::ALL,
        WifiApStatus::wire,
        WifiApStatus::from_wire,
        &[("Off", "off")],
    );
    check(
        LteBandwidth::ALL,
        LteBandwidth::wire,
        LteBandwidth::from_wire,
        &[
            ("3MHz", "mhz3"),
            ("5MHz", "mhz5"),
            ("10MHz", "mhz10"),
            ("15MHz", "mhz15"),
            ("20MHz", "mhz20"),
        ],
    );
    for unobserved in ["1.4MHz", "25MHz", "20 MHz", "20mhz"] {
        assert_eq!(LteBandwidth::from_wire(unobserved), None, "{unobserved}");
    }
}

fn carrier(band: u16, dl_bandwidth: LteBandwidth) -> LteCarrier {
    LteCarrier {
        band: BandNumber::new(band).unwrap(),
        dl_bandwidth,
    }
}

/// A carrier list is a primary and at most six secondaries, by type and on
/// decode.
#[test]
fn lte_carriers_are_bounded_and_primary_first_by_type() {
    let primary = carrier(3, LteBandwidth::Mhz20);
    let secondary = |count| vec![carrier(20, LteBandwidth::Mhz10); count];
    assert_eq!(LteCarriers::MAX_SECONDARY, 6);
    let six = LteCarriers::new(primary, secondary(6), 0).unwrap();
    assert_eq!(six.primary(), primary);
    assert_eq!(six.secondary(), secondary(6).as_slice());
    assert_eq!(
        LteCarriers::new(primary, secondary(7), 0),
        Err(RouterValueError::TooManySecondaryCarriers { count: 7 })
    );
    // Unassigned slots count toward the bound.
    let five_and_one = LteCarriers::new(primary, secondary(5), 1).unwrap();
    assert_eq!(five_and_one.secondary().len(), 5);
    assert_eq!(five_and_one.unassigned_slots(), 1);
    assert_eq!(
        LteCarriers::new(primary, secondary(6), 1),
        Err(RouterValueError::TooManySecondaryCarriers { count: 7 })
    );
    assert_eq!(
        LteCarriers::new(primary, Vec::new(), 7),
        Err(RouterValueError::TooManySecondaryCarriers { count: 7 })
    );
    let json = serde_json::to_string(&six).unwrap();
    assert!(json.starts_with(r#"{"primary":{"band":3,"dl_bandwidth":"mhz20"},"secondary":["#));
    assert_eq!(serde_json::from_str::<LteCarriers>(&json).unwrap(), six);
    let seven = json.replacen(
        r#""secondary":["#,
        r#""secondary":[{"band":20,"dl_bandwidth":"mhz10"},"#,
        1,
    );
    assert!(serde_json::from_str::<LteCarriers>(&seven).is_err());
    let none = LteCarriers::new(primary, Vec::new(), 0).unwrap();
    assert_eq!(
        serde_json::to_string(&none).unwrap(),
        r#"{"primary":{"band":3,"dl_bandwidth":"mhz20"},"secondary":[],"unassigned_slots":0}"#
    );
    let slot = LteCarriers::new(primary, Vec::new(), 1).unwrap();
    let slot_json = serde_json::to_string(&slot).unwrap();
    assert_eq!(
        slot_json,
        r#"{"primary":{"band":3,"dl_bandwidth":"mhz20"},"secondary":[],"unassigned_slots":1}"#
    );
    assert_eq!(
        serde_json::from_str::<LteCarriers>(&slot_json).unwrap(),
        slot
    );
    // The count is required, and bounded on decode too.
    assert!(
        serde_json::from_str::<LteCarriers>(
            r#"{"primary":{"band":3,"dl_bandwidth":"mhz20"},"secondary":[]}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<LteCarriers>(
            r#"{"primary":{"band":3,"dl_bandwidth":"mhz20"},"secondary":[],"unassigned_slots":7}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<LteCarriers>(r#"{"primary":{"band":3,"dl_bandwidth":"mhz20"}}"#)
            .is_err()
    );
}

/// The M2a reading of 2026-10-13, as `parse_netgear_model_json` reads it
/// from `contract/router-fixtures/`: values real, the SIM a CMLink
/// practice SIM on EE.
pub(crate) fn status() -> RouterStatus {
    RouterStatus::new(RouterStatusParts {
        firmware: FirmwareVersion::parse("NTGX75_10.04.43.01").unwrap(),
        web_app: Some(WebAppVersion::parse("M7_GENERIC_v07.01.81.00").unwrap()),
        uptime_secs: 359_272,
        temperature_c: Celsius::new(35).unwrap(),
        thermal: ThermalState::Normal,
        power: RouterPower {
            state: PowerState::Online,
            battery: Battery {
                charge: BatteryPercent::new(100).unwrap(),
                state: BatteryState::Normal,
                charging: false,
                source: ChargeSource::QuickCharge,
                temperature_c: Celsius::new(32).unwrap(),
            },
        },
        sim_spn: Some(CarrierName::parse("CMLink").unwrap()),
        radio: RadioState::Attached(Radio {
            network_service: NetworkService::Nr5g,
            data_service: DataService::NrSub6,
            band: Band::Lte(BandNumber::new(3).unwrap()),
            lte_carriers: Some(
                LteCarriers::new(carrier(3, LteBandwidth::Mhz20), Vec::new(), 0).unwrap(),
            ),
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
            network: CarrierName::parse("CMLink").unwrap(),
            plmn: Plmn {
                mcc: Mcc::parse("234").unwrap(),
                mnc: Mnc::parse("30").unwrap(),
            },
            session_secs: 359_217,
        }),
        counters: WwanCounters {
            rx_bytes: 591_655_199,
            tx_bytes: 188_784_597,
        },
        wifi: RouterWifi {
            enabled: false,
            main: WifiApStatus::Off,
            guest: WifiApStatus::Off,
            aux: WifiApStatus::Off,
            clients: 0,
        },
        settings: RouterSettings {
            wifi_offload: false,
            ethernet_offload: false,
            upnp: false,
            analytics: false,
            insight_active: false,
        },
        unread_sms: 0,
    })
    .unwrap()
}

/// The M2a reading as the Mac polled it.
/// Each setting the exit needs off gives its advisory, in their order;
/// Analytics gives none.
#[test]
fn the_settings_the_exit_needs_off_give_advisories() {
    use crate::router::RouterAdvisory as A;
    assert_eq!(status().advisories(), []);
    let with = |change: &dyn Fn(&mut RouterStatusParts)| {
        let mut parts = status().into_parts();
        change(&mut parts);
        RouterStatus::new(parts).unwrap().advisories()
    };
    assert_eq!(with(&|p| p.wifi.enabled = true), [A::WifiRadioOn]);
    assert_eq!(
        with(&|p| p.settings.wifi_offload = true),
        [A::WifiOffloadOn]
    );
    assert_eq!(
        with(&|p| p.settings.ethernet_offload = true),
        [A::EthernetOffloadOn]
    );
    assert_eq!(with(&|p| p.settings.upnp = true), [A::UpnpOn]);
    assert_eq!(
        with(&|p| p.settings.insight_active = true),
        [A::InsightActive]
    );
    assert_eq!(with(&|p| p.settings.analytics = true), []);
    assert_eq!(
        with(&|p| {
            p.settings.insight_active = true;
            p.settings.upnp = true;
            p.settings.ethernet_offload = true;
            p.settings.wifi_offload = true;
            p.wifi.enabled = true;
            p.settings.analytics = true;
        }),
        [
            A::WifiRadioOn,
            A::WifiOffloadOn,
            A::EthernetOffloadOn,
            A::UpnpOn,
            A::InsightActive
        ]
    );
}

pub(crate) fn reading() -> RouterReading {
    RouterReading::Available {
        polled_at: UnixTime::from_secs(1_791_919_200),
        status: Box::new(status()),
    }
}

/// The encoding of [`reading`], byte for byte.
const READING_JSON: &str = concat!(
    r#"{"available":{"polled_at":1791919200,"status":{"#,
    r#""firmware":"NTGX75_10.04.43.01","web_app":"M7_GENERIC_v07.01.81.00","#,
    r#""uptime_secs":359272,"temperature_c":35,"thermal":"normal","#,
    r#""power":{"state":"online","battery":{"charge":100,"state":"normal","charging":false,"source":"quick_charge","temperature_c":32}},"#,
    r#""sim_spn":"CMLink","#,
    r#""radio":{"attached":{"network_service":"nr5g","data_service":"nr_sub6","band":"B3","#,
    r#""lte_carriers":{"primary":{"band":3,"dl_bandwidth":"mhz20"},"secondary":[],"unassigned_slots":0},"ca_secondary_count":0,"#,
    r#""lte":{"rsrp":-1040,"rsrq":-170,"sinr":0,"rssi":-720},"nr":{"rsrp":null,"rsrq":null,"sinr":null},"#,
    r#""network":"CMLink","plmn":{"mcc":"234","mnc":"30"},"session_secs":359217}},"#,
    r#""counters":{"rx_bytes":591655199,"tx_bytes":188784597},"#,
    r#""wifi":{"enabled":false,"main":"off","guest":"off","aux":"off","clients":0},"#,
    r#""settings":{"wifi_offload":false,"ethernet_offload":false,"upnp":false,"analytics":false,"insight_active":false},"#,
    r#""unread_sms":0}}}"#
);

/// The router reading has a fixed encoding and refuses any field it does
/// not name, so a parser cannot smuggle a cell id or an IMEI through it; a
/// reading the M7 did not report is spelled `null`, never left out.
#[test]
fn the_router_reading_has_a_fixed_encoding() {
    let reading = reading();
    let json = serde_json::to_string(&reading).unwrap();
    assert_eq!(json, READING_JSON);
    assert_eq!(
        serde_json::from_str::<RouterReading>(&json).unwrap(),
        reading
    );
    for (extra, key) in [
        (r#","cell_id":"0x1a2b""#, "cell_id"),
        (r#","imei":"356938035643809""#, "imei"),
        (r#","sms":[{"text":"x"}]"#, "sms"),
    ] {
        let smuggled = json.replacen(r#","unread_sms""#, &format!(r#"{extra},"unread_sms""#), 1);
        assert!(smuggled.contains(key));
        assert!(
            serde_json::from_str::<RouterReading>(&smuggled).is_err(),
            "{key}"
        );
    }
    // A reading not reported is `null`, and a missing one is an error.
    for missing in [
        r#","sinr":null}"#,
        r#","rssi":-720"#,
        r#""lte_carriers":{"primary":{"band":3,"dl_bandwidth":"mhz20"},"secondary":[],"unassigned_slots":0},"#,
        r#","unassigned_slots":0}"#,
    ] {
        assert!(json.contains(missing), "{missing}");
        let without = json.replacen(missing, if missing.ends_with('}') { "}" } else { "" }, 1);
        assert!(
            serde_json::from_str::<RouterReading>(&without).is_err(),
            "{missing}"
        );
    }
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

/// A SIM name or web app version the M7 did not report (the empty string
/// on the device, 2026-10-16) is `null` on the wire: decoded and encoded
/// as such, never an empty string, and never left out.
#[test]
fn an_unreported_sim_name_or_web_app_version_is_null() {
    let decoded = |json: &str| {
        serde_json::from_str::<RouterReading>(json)
            .map(|reading| serde_json::to_string(&reading).unwrap())
            .map_err(|error| error.to_string())
    };
    for (present, absent) in [
        (r#""sim_spn":"CMLink","#, r#""sim_spn":null,"#),
        (
            r#""web_app":"M7_GENERIC_v07.01.81.00","#,
            r#""web_app":null,"#,
        ),
    ] {
        assert!(READING_JSON.contains(present), "{present}");
        let null = READING_JSON.replacen(present, absent, 1);
        assert_eq!(decoded(&null), Ok(null.clone()), "{absent}");
        let (key, _) = present.split_once(':').unwrap();
        for refused in [format!("{key}:\"\","), String::new()] {
            let json = READING_JSON.replacen(present, &refused, 1);
            assert!(decoded(&json).is_err(), "{json}");
        }
    }
}

/// A data session cannot outlast the boot it runs in: the status refuses a
/// session longer than the uptime, built or decoded; equal is accepted.
#[test]
fn a_session_longer_than_the_uptime_is_refused_by_the_status() {
    let with_session = |secs| {
        let mut parts = status().into_parts();
        let RadioState::Attached(radio) = &mut parts.radio else {
            panic!("the M2a reading is attached");
        };
        radio.session_secs = secs;
        parts
    };
    assert!(RouterStatus::new(with_session(359_272)).is_ok());
    assert_eq!(
        RouterStatus::new(with_session(359_273)),
        Err(RouterValueError::SessionExceedsUptime)
    );
    let json = READING_JSON.replace(r#""session_secs":359217"#, r#""session_secs":359273"#);
    assert!(serde_json::from_str::<RouterReading>(&json).is_err());
    let mut parts = status().into_parts();
    parts.radio = RadioState::NoService;
    parts.uptime_secs = 0;
    assert_eq!(
        RouterStatus::new(parts.clone()).unwrap().into_parts(),
        parts
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
        (
            RouterValueErrorKind::TooManySecondaryCarriers,
            LteCarriers::new(
                carrier(3, LteBandwidth::Mhz20),
                vec![carrier(1, LteBandwidth::Mhz5); 7],
                0,
            )
            .unwrap_err(),
        ),
        (
            RouterValueErrorKind::SessionExceedsUptime,
            RouterValueError::SessionExceedsUptime,
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

/// A poll's outcome becomes the panel: a status read is shown with its
/// poll's time; a failed poll shows why, with the last successful poll
/// carried over, and never an earlier status as if it were current.
#[test]
fn a_poll_outcome_becomes_the_panel() {
    let first = UnixTime::from_secs(1_000);
    let second = UnixTime::from_secs(1_060);
    let third = UnixTime::from_secs(1_120);
    let read = RouterReading::after_poll(None, first, Ok(status()));
    assert_eq!(
        read,
        RouterReading::Available {
            polled_at: first,
            status: Box::new(status()),
        }
    );
    assert_eq!(read.last_successful_poll(), Some(first));
    let failed = RouterReading::after_poll(
        Some(&read),
        second,
        Err(RouterUnavailableReason::Unreachable),
    );
    assert_eq!(
        failed,
        RouterReading::Unavailable {
            reason: RouterUnavailableReason::Unreachable,
            last_polled_at: Some(first),
        }
    );
    // A second failure keeps the same last success and takes its own reason.
    let again = RouterReading::after_poll(
        Some(&failed),
        third,
        Err(RouterUnavailableReason::LocalFailure),
    );
    assert_eq!(
        again,
        RouterReading::Unavailable {
            reason: RouterUnavailableReason::LocalFailure,
            last_polled_at: Some(first),
        }
    );
    assert_eq!(again.last_successful_poll(), Some(first));
    // Before any success there is none to carry.
    let never = RouterReading::after_poll(None, first, Err(RouterUnavailableReason::AuthFailed));
    assert_eq!(never.last_successful_poll(), None);
    let still_never = RouterReading::after_poll(
        Some(&never),
        second,
        Err(RouterUnavailableReason::AuthFailed),
    );
    assert_eq!(still_never.last_successful_poll(), None);
    // A success after failures is current again.
    let recovered = RouterReading::after_poll(Some(&again), third, Ok(status()));
    assert_eq!(recovered.last_successful_poll(), Some(third));
    assert!(matches!(recovered, RouterReading::Available { .. }));
}
