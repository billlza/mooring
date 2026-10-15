// SPDX-License-Identifier: GPL-3.0-or-later

//! The M7's status as the console shows it (console spec B.2.7, corrected
//! by critique C-7 and C-8), shaped by what the MR7450 reported in the M2a
//! capture of 2026-10-13, and the allowlist parser and redactor of its
//! `model.json` ([`netgear`]).
//!
//! [`RouterStatus`] is an allowlist by construction: it has no field for
//! the cell id, IMEI, ICCID, IMSI, phone number, SMS text or sender, WWAN
//! address, connected clients' addresses or names, Wi-Fi keys, GPS, or the
//! admin password, so a parser built on it can only drop them. Nor can a
//! field it does have hold one by mistake (a parser reading the wrong
//! leaf): numbers are typed and bounded, the device's enumerations are
//! closed sets of the values the M7 was seen to report, and the free-text
//! fields refuse a run of digits long enough to be an identifier
//! ([`CarrierName::MAX_DIGIT_RUN`], [`FirmwareVersion::MAX_DIGIT_RUN`],
//! [`WebAppVersion::MAX_DIGIT_RUN`]).
//!
//! The M7 is not interpreted beyond what it reports: it names its network
//! and data services itself (`Nr5gService`, `5GSUB6`), its LTE and NR
//! readings are kept apart, and a reading it reports as `-32768` is `None`
//! (not reported). The M2a capture shows why: the M7 claimed `5GSUB6` while
//! every NR reading was `-32768` and its only carrier was LTE band 3, so an
//! access type such as "5G NSA" would have been a guess.
//!
//! No M7 timestamp is kept: its clock read 2016 in the M2a capture.

pub mod netgear;

use std::fmt;

use mooring_model::UnixTime;
use serde::{Deserialize, Serialize};

use crate::error::RouterValueError;

/// A signal reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalMetric {
    /// Reference signal received power.
    Rsrp,
    /// Reference signal received quality.
    Rsrq,
    /// Signal to interference plus noise ratio.
    Sinr,
    /// Received signal strength indicator.
    Rssi,
}

impl fmt::Display for SignalMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rsrp => "RSRP",
            Self::Rsrq => "RSRQ",
            Self::Sinr => "SINR",
            Self::Rssi => "RSSI",
        })
    }
}

macro_rules! signal {
    (
        $(#[$meta:meta])*
        $name:ident, $metric:ident, $min:literal, $max:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "i16", into = "i16")]
        pub struct $name(i16);

        impl $name {
            /// The lowest plausible value, in tenths.
            pub const MIN_TENTHS: i16 = $min;
            /// The highest plausible value, in tenths.
            pub const MAX_TENTHS: i16 = $max;

            /// Accepts a value in tenths within the plausible range
            /// (`SignalOutOfRange` otherwise).
            pub const fn from_tenths(tenths: i16) -> Result<Self, RouterValueError> {
                if tenths >= Self::MIN_TENTHS && tenths <= Self::MAX_TENTHS {
                    Ok(Self(tenths))
                } else {
                    Err(RouterValueError::SignalOutOfRange {
                        metric: SignalMetric::$metric,
                        tenths,
                    })
                }
            }

            /// The value in tenths.
            #[must_use]
            pub const fn tenths(self) -> i16 {
                self.0
            }
        }

        impl TryFrom<i16> for $name {
            type Error = RouterValueError;

            fn try_from(tenths: i16) -> Result<Self, Self::Error> {
                Self::from_tenths(tenths)
            }
        }

        impl From<$name> for i16 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

signal!(
    /// RSRP in tenths of a dBm, within -156..=-31 dBm: the NR SS-RSRP
    /// reporting range of 3GPP TS 38.133 (which contains LTE's -140..=-44).
    Rsrp,
    Rsrp,
    -1560,
    -310
);
signal!(
    /// RSRQ in tenths of a dB, within -43..=20 dB: the NR SS-RSRQ reporting
    /// range of 3GPP TS 38.133 (which contains LTE's -19.5..=-3, and its
    /// extended -34..=2.5).
    Rsrq,
    Rsrq,
    -430,
    200
);
signal!(
    /// SINR in tenths of a dB, within -23..=40 dB: the NR SS-SINR reporting
    /// range of 3GPP TS 38.133. LTE SINR has no standard report mapping;
    /// the M7's LTE SINR of 0 dB in the M2a capture fits.
    Sinr,
    Sinr,
    -230,
    400
);
signal!(
    /// RSSI in tenths of a dBm, within -150..=0 dBm (inference: a plausible
    /// bound, since 3GPP defines no RSSI report mapping for a UE).
    Rssi,
    Rssi,
    -1500,
    0
);

/// A temperature in whole °C, within -40..=125 (inference: the usual
/// rating of electronic temperature sensors): the M7's and its battery's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "i16", into = "i16")]
pub struct Celsius(i16);

impl Celsius {
    /// Accepts -40..=125 (`TemperatureOutOfRange` otherwise).
    pub const fn new(celsius: i16) -> Result<Self, RouterValueError> {
        if celsius >= -40 && celsius <= 125 {
            Ok(Self(celsius))
        } else {
            Err(RouterValueError::TemperatureOutOfRange { celsius })
        }
    }

    /// The temperature.
    #[must_use]
    pub const fn get(self) -> i16 {
        self.0
    }
}

impl TryFrom<i16> for Celsius {
    type Error = RouterValueError;

    fn try_from(celsius: i16) -> Result<Self, Self::Error> {
        Self::new(celsius)
    }
}

impl From<Celsius> for i16 {
    fn from(value: Celsius) -> Self {
        value.0
    }
}

/// A battery charge, 0..=100%.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct BatteryPercent(u8);

impl BatteryPercent {
    /// Accepts 0..=100 (`BatteryPercentOutOfRange` otherwise).
    pub const fn new(percent: u8) -> Result<Self, RouterValueError> {
        if percent <= 100 {
            Ok(Self(percent))
        } else {
            Err(RouterValueError::BatteryPercentOutOfRange { percent })
        }
    }

    /// The charge.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for BatteryPercent {
    type Error = RouterValueError;

    fn try_from(percent: u8) -> Result<Self, Self::Error> {
        Self::new(percent)
    }
}

impl From<BatteryPercent> for u8 {
    fn from(value: BatteryPercent) -> Self {
        value.0
    }
}

/// Which router text a value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterTextField {
    /// The band, for example `B3` or `n78` ([`Band`]).
    Band,
    /// A carrier's display name, for example `CMLink` (the SIM's SPN or
    /// the network's display name).
    Carrier,
    /// The firmware version.
    Firmware,
    /// The web application's version.
    WebApp,
    /// The mobile country code.
    Mcc,
    /// The mobile network code.
    Mnc,
}

impl fmt::Display for RouterTextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Band => "band",
            Self::Carrier => "carrier",
            Self::Firmware => "firmware",
            Self::WebApp => "web app",
            Self::Mcc => "MCC",
            Self::Mnc => "MNC",
        })
    }
}

macro_rules! router_text {
    (
        $(#[$meta:meta])*
        $name:ident, $field:ident, $max:literal, $digits:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The longest text accepted, in bytes.
            pub const MAX_BYTES: usize = $max;

            /// The longest run of consecutive digits accepted.
            pub const MAX_DIGIT_RUN: usize = $digits;

            /// Accepts 1 to `MAX_BYTES` bytes of printable ASCII (a space
            /// only between other characters) with no run of more than
            /// `MAX_DIGIT_RUN` digits; `InvalidText` otherwise, without
            /// echoing the text.
            pub fn parse(text: &str) -> Result<Self, RouterValueError> {
                if printable(text, Self::MAX_BYTES) && digit_runs_within(text, Self::MAX_DIGIT_RUN) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(RouterValueError::InvalidText {
                        field: RouterTextField::$field,
                    })
                }
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = RouterValueError;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

/// Whether `text` is 1 to `max` bytes of printable ASCII with no leading or
/// trailing space.
fn printable(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        && !text.starts_with(' ')
        && !text.ends_with(' ')
}

/// Whether no run of consecutive ASCII digits in `text` is longer than
/// `max`.
pub(crate) fn digit_runs_within(text: &str, max: usize) -> bool {
    text.split(|c: char| !c.is_ascii_digit())
        .all(|run| run.len() <= max)
}

router_text!(
    /// A carrier's display name (the M2a SIM reported `CMLink` both as its
    /// SPN and as the network's display name), at most 32 bytes and at most
    /// two digits in a row (`O2` and `3` fit). It names the network, not the
    /// subscriber: no phone number, IMSI or ICCID fits.
    CarrierName,
    Carrier,
    32,
    2
);
router_text!(
    /// The M7's firmware version (`NTGX75_10.04.43.01` in M2a), at most 64
    /// bytes and at most six digits in a row (a `YYMMDD` date stamp fits; an
    /// IMEI, IMSI, ICCID, phone number or most cell ids, seven digits or
    /// more, do not). A change raises `RouterFirmwareChanged`.
    FirmwareVersion,
    Firmware,
    64,
    6
);
router_text!(
    /// The M7's web application version (`M7_GENERIC_v07.01.81.00` in M2a;
    /// the device appends a newline, which the parser removes), with the
    /// firmware version's limits.
    WebAppVersion,
    WebApp,
    64,
    6
);

macro_rules! digit_code {
    (
        $(#[$meta:meta])*
        $name:ident, $field:ident, $min:literal, $max:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name {
            digits: [u8; $max],
            len: u8,
        }

        impl $name {
            /// Accepts the digits (`InvalidText` otherwise, without echoing
            /// the text). Their number is kept: `30` and `030` differ.
            pub fn parse(text: &str) -> Result<Self, RouterValueError> {
                let refused = RouterValueError::InvalidText {
                    field: RouterTextField::$field,
                };
                let bytes = text.as_bytes();
                if !($min..=$max).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_digit) {
                    return Err(refused);
                }
                let mut digits = [0; $max];
                let mut len = 0_u8;
                for (slot, digit) in digits.iter_mut().zip(bytes) {
                    *slot = *digit;
                    len += 1;
                }
                Ok(Self { digits, len })
            }

            /// The digits, in order.
            #[must_use]
            pub fn digits(&self) -> &[u8] {
                &self.digits[..usize::from(self.len)]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for digit in self.digits() {
                    write!(f, "{}", char::from(*digit))?;
                }
                Ok(())
            }
        }

        impl TryFrom<String> for $name {
            type Error = RouterValueError;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::parse(&text)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.to_string()
            }
        }
    };
}

digit_code!(
    /// A mobile country code: exactly three ASCII digits (`234` for the
    /// United Kingdom).
    Mcc,
    Mcc,
    3,
    3
);
digit_code!(
    /// A mobile network code: two or three ASCII digits (`30` for EE).
    Mnc,
    Mnc,
    2,
    3
);

/// The network the M7 is registered on: its mobile country and network
/// codes. A PLMN names a network, not a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plmn {
    /// The mobile country code.
    pub mcc: Mcc,
    /// The mobile network code.
    pub mnc: Mnc,
}

/// A band number, 1..=999: 3GPP numbers both LTE and NR bands within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct BandNumber(u16);

impl BandNumber {
    /// The highest band number accepted.
    pub const MAX: u16 = 999;

    /// Accepts 1..=999 (`InvalidText{field: Band}` otherwise).
    pub const fn new(number: u16) -> Result<Self, RouterValueError> {
        if number >= 1 && number <= Self::MAX {
            Ok(Self(number))
        } else {
            Err(RouterValueError::InvalidText {
                field: RouterTextField::Band,
            })
        }
    }

    /// The number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for BandNumber {
    type Error = RouterValueError;

    fn try_from(number: u16) -> Result<Self, Self::Error> {
        Self::new(number)
    }
}

impl From<BandNumber> for u16 {
    fn from(number: BandNumber) -> Self {
        number.0
    }
}

/// The radio band in use: an LTE band (`B3`) or an NR band (`n78`). On the
/// wire it is that text, without leading zeros; anything else is refused
/// (`InvalidText{field: Band}`, without echoing the text). The MR7450
/// reports it as `LTE B3` (M2a); its spelling of an NR band is not yet
/// observed, so the parser reads only LTE bands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Band {
    /// An E-UTRA (LTE) band, `B<n>`.
    Lte(BandNumber),
    /// An NR (5G) band, `n<n>`.
    Nr(BandNumber),
}

impl Band {
    /// Parses `B<n>` or `n<n>`, `n` a [`BandNumber`] without a leading
    /// zero.
    pub fn parse(text: &str) -> Result<Self, RouterValueError> {
        let refused = RouterValueError::InvalidText {
            field: RouterTextField::Band,
        };
        let (make, digits): (fn(BandNumber) -> Self, &str) =
            if let Some(rest) = text.strip_prefix('B') {
                (Self::Lte, rest)
            } else if let Some(rest) = text.strip_prefix('n') {
                (Self::Nr, rest)
            } else {
                return Err(refused);
            };
        let canonical = (1..=3).contains(&digits.len())
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && !digits.starts_with('0');
        if !canonical {
            return Err(refused);
        }
        let number = digits.parse::<u16>().map_err(|_| refused)?;
        Ok(make(BandNumber::new(number)?))
    }
}

impl fmt::Display for Band {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lte(number) => write!(f, "B{}", number.get()),
            Self::Nr(number) => write!(f, "n{}", number.get()),
        }
    }
}

impl TryFrom<String> for Band {
    type Error = RouterValueError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<Band> for String {
    fn from(band: Band) -> Self {
        band.to_string()
    }
}

/// One of the M7's own enumerations, holding exactly the values the M2a
/// capture of 2026-10-13 showed, except [`LteBandwidth`], whose set is
/// inferred: an enum, its `ALL`, its device spelling (`wire`) and the
/// exact lookup of a device string (`from_wire`). A device string without
/// a variant is an unknown value the parser refuses (design §15.6 rule 2):
/// there is no fallback variant.
macro_rules! device_vocabulary {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident = $wire:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The value as the M7 spells it.
            #[must_use]
            pub const fn wire(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire ),+
                }
            }

            /// The value the M7 spells `text`, matched exactly; `None` for a
            /// spelling not yet observed.
            #[must_use]
            pub fn from_wire(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.wire() == text)
            }
        }
    };
}

device_vocabulary! {
    /// The network service type (`wwan.currentNWserviceType`).
    pub enum NetworkService {
        /// `Nr5gService` (M2a).
        Nr5g = "Nr5gService",
    }
}

device_vocabulary! {
    /// The packet-switched (data) service type
    /// (`wwan.currentPSserviceType`).
    pub enum DataService {
        /// `5GSUB6`: the M7 reports a 5G sub-6 GHz data service (M2a, with
        /// no NR reading reported and an LTE primary carrier).
        NrSub6 = "5GSUB6",
    }
}

device_vocabulary! {
    /// The modem's thermal state (`wwan.thermalState`).
    pub enum ThermalState {
        /// `Normal` (M2a).
        Normal = "Normal",
    }
}

device_vocabulary! {
    /// The M7's power management state (`power.PMState`).
    pub enum PowerState {
        /// `Online` (M2a).
        Online = "Online",
    }
}

device_vocabulary! {
    /// The battery's state (`power.batteryState`).
    pub enum BatteryState {
        /// `Normal` (M2a).
        Normal = "Normal",
    }
}

device_vocabulary! {
    /// What charges the battery (`power.battChargeSource`).
    pub enum ChargeSource {
        /// `QuickCharge` (M2a).
        QuickCharge = "QuickCharge",
    }
}

device_vocabulary! {
    /// A Wi-Fi access point's status (`wifi.status`, `wifi.guest.status`,
    /// `wifi.aux.status`).
    pub enum WifiApStatus {
        /// `Off` (M2a).
        Off = "Off",
    }
}

device_vocabulary! {
    /// An LTE carrier's downlink bandwidth (`wwan.lteBandInfo[].dlBandwidth`,
    /// spelled `20MHz` in M2a). The one vocabulary not limited to what M2a
    /// observed: the set is 3GPP's E-UTRA channel bandwidths spelled like
    /// `20MHz`, except 1.4 MHz, whose spelling cannot be inferred
    /// *(inference: only `20MHz` was seen; design §15.6 rule 2, M2.md)*.
    /// Another spelling is still refused, so the inference can make a
    /// carrier unreadable but never misread.
    pub enum LteBandwidth {
        /// 3 MHz.
        Mhz3 = "3MHz",
        /// 5 MHz.
        Mhz5 = "5MHz",
        /// 10 MHz.
        Mhz10 = "10MHz",
        /// 15 MHz.
        Mhz15 = "15MHz",
        /// 20 MHz (M2a).
        Mhz20 = "20MHz",
    }
}

/// One LTE carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LteCarrier {
    /// The band number.
    pub band: BandNumber,
    /// The downlink bandwidth.
    pub dl_bandwidth: LteBandwidth,
}

/// The LTE carriers: the primary first, then at most
/// [`LteCarriers::MAX_SECONDARY`] secondary carriers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "LteCarriersRepr", into = "LteCarriersRepr")]
pub struct LteCarriers {
    primary: LteCarrier,
    secondary: Vec<LteCarrier>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LteCarriersRepr {
    primary: LteCarrier,
    secondary: Vec<LteCarrier>,
}

impl LteCarriers {
    /// The most secondary carriers accepted: a plausibility bound
    /// (inference; the M2a capture showed none), above what LTE modems of
    /// the M7's class aggregate, that refuses a runaway list.
    pub const MAX_SECONDARY: usize = 6;

    /// Accepts a primary and at most [`Self::MAX_SECONDARY`] secondary
    /// carriers; that bound is its only rule (`TooManySecondaryCarriers`).
    pub fn new(primary: LteCarrier, secondary: Vec<LteCarrier>) -> Result<Self, RouterValueError> {
        if secondary.len() > Self::MAX_SECONDARY {
            return Err(RouterValueError::TooManySecondaryCarriers {
                count: secondary.len(),
            });
        }
        Ok(Self { primary, secondary })
    }

    /// The primary carrier.
    #[must_use]
    pub const fn primary(&self) -> LteCarrier {
        self.primary
    }

    /// The secondary carriers, in the M7's order.
    #[must_use]
    pub fn secondary(&self) -> &[LteCarrier] {
        &self.secondary
    }
}

impl TryFrom<LteCarriersRepr> for LteCarriers {
    type Error = RouterValueError;

    fn try_from(repr: LteCarriersRepr) -> Result<Self, Self::Error> {
        Self::new(repr.primary, repr.secondary)
    }
}

impl From<LteCarriers> for LteCarriersRepr {
    fn from(carriers: LteCarriers) -> Self {
        Self {
            primary: carriers.primary,
            secondary: carriers.secondary,
        }
    }
}

/// The LTE readings (`wwan.signalStrength.{rsrp,rsrq,sinr,rssi}`); a
/// reading the M7 reports as not available is `None`. They are read as
/// LTE because the M2a capture's RSRP equals its LTE receive level and its
/// only carrier was LTE (inference: on NR standalone they may hold NR
/// values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LteSignal {
    /// RSRP.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rsrp: Option<Rsrp>,
    /// RSRQ.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rsrq: Option<Rsrq>,
    /// SINR.
    #[serde(deserialize_with = "Option::deserialize")]
    pub sinr: Option<Sinr>,
    /// RSSI.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rssi: Option<Rssi>,
}

/// The NR readings (`wwan.signalStrength.nr5g{Rsrp,Rsrq,Sinr}`); a reading
/// the M7 reports as not available is `None` (all three in M2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NrSignal {
    /// SS-RSRP.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rsrp: Option<Rsrp>,
    /// SS-RSRQ.
    #[serde(deserialize_with = "Option::deserialize")]
    pub rsrq: Option<Rsrq>,
    /// SS-SINR.
    #[serde(deserialize_with = "Option::deserialize")]
    pub sinr: Option<Sinr>,
}

/// The M7's data attachment, as it reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Radio {
    /// The network service type.
    pub network_service: NetworkService,
    /// The data service type.
    pub data_service: DataService,
    /// The band in use (`wwanadv.curBand`).
    pub band: Band,
    /// The LTE carriers; `None` when the M7 lists none.
    #[serde(deserialize_with = "Option::deserialize")]
    pub lte_carriers: Option<LteCarriers>,
    /// How many secondary carriers the M7 counts (`wwan.ca.SCCcount`).
    pub ca_secondary_count: u8,
    /// The LTE readings.
    pub lte: LteSignal,
    /// The NR readings.
    pub nr: NrSignal,
    /// The network's display name.
    pub network: CarrierName,
    /// The network's codes.
    pub plmn: Plmn,
    /// Seconds the data session has lasted.
    pub session_secs: u64,
}

/// The M7's attachment to the mobile network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RadioState {
    /// Not attached: no service. The parser cannot produce it until the M7's
    /// no-service report is captured (M2.md, "Still to capture").
    NoService,
    /// Attached (`wwan.connection` is `Connected`).
    Attached(Radio),
}

/// The M7's battery (kept installed by the operator's choice, M2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Battery {
    /// The charge.
    pub charge: BatteryPercent,
    /// The battery's state.
    pub state: BatteryState,
    /// Whether it is charging.
    pub charging: bool,
    /// What charges it.
    pub source: ChargeSource,
    /// The battery's temperature.
    pub temperature_c: Celsius,
}

/// How the M7 is powered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterPower {
    /// The power management state.
    pub state: PowerState,
    /// The battery. How the M7 reports no battery is not yet observed:
    /// removing it (Plugged-In mode, design §2) needs a capture of that
    /// state and a change of this type (an absent battery) first, or every
    /// status reads as malformed (M2.md, "Still to capture").
    pub battery: Battery,
}

/// The WWAN counters (`wwan.dataTransferredRx`, `wwan.dataTransferredTx`),
/// which the M7 reports as decimal strings; bytes (inference), over a scope
/// (session, lifetime or since a reset) not yet verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WwanCounters {
    /// Received.
    pub rx_bytes: u64,
    /// Sent.
    pub tx_bytes: u64,
}

/// The M7's Wi-Fi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterWifi {
    /// Whether the Wi-Fi radio is on (`wifi.enabled`); off is expected.
    pub enabled: bool,
    /// The main access point's status.
    pub main: WifiApStatus,
    /// The guest access point's status (its `enabled` stays true while it
    /// is off, so it is not read).
    pub guest: WifiApStatus,
    /// The auxiliary access point's status.
    pub aux: WifiApStatus,
    /// How many Wi-Fi clients are connected; none is expected.
    pub clients: u16,
}

/// The M7 settings the exit depends on staying off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterSettings {
    /// Wi-Fi offload (`wifi.offload.enabled`).
    pub wifi_offload: bool,
    /// Ethernet offload (`ethernet.offload.enabled`).
    pub ethernet_offload: bool,
    /// UPnP (`router.UPNPenabled`).
    pub upnp: bool,
    /// NETGEAR Analytics (`ra.enabled`).
    pub analytics: bool,
    /// Whether NETGEAR Insight, a cloud control path, is active
    /// (`insight.active`).
    pub insight_active: bool,
}

/// Every part of a [`RouterStatus`], unchecked. This is also its wire
/// shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterStatusParts {
    /// The firmware version.
    pub firmware: FirmwareVersion,
    /// The web application's version.
    pub web_app: WebAppVersion,
    /// Seconds since the M7 booted; a decrease shows a reboot.
    pub uptime_secs: u64,
    /// The device temperature.
    pub temperature_c: Celsius,
    /// The modem's thermal state.
    pub thermal: ThermalState,
    /// The power.
    pub power: RouterPower,
    /// The SIM's service provider name.
    pub sim_spn: CarrierName,
    /// The radio.
    pub radio: RadioState,
    /// The WWAN counters.
    pub counters: WwanCounters,
    /// The Wi-Fi.
    pub wifi: RouterWifi,
    /// The settings.
    pub settings: RouterSettings,
    /// How many SMS are unread. Only the count is kept: the texts and their
    /// senders are never read (the operator reads SMS in the M7's own web
    /// interface).
    pub unread_sms: u32,
}

/// What the M7 reported at one poll; only these fields are ever kept.
/// Built only from [`RouterStatusParts`] (also when decoded) whose data
/// session, if attached, is no longer than the uptime.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RouterStatusParts", into = "RouterStatusParts")]
pub struct RouterStatus(RouterStatusParts);

impl RouterStatus {
    /// Checks `parts`: an attached radio's session is no longer than the
    /// uptime, its only rule (`SessionExceedsUptime`).
    pub fn new(parts: RouterStatusParts) -> Result<Self, RouterValueError> {
        if let RadioState::Attached(radio) = &parts.radio
            && radio.session_secs > parts.uptime_secs
        {
            return Err(RouterValueError::SessionExceedsUptime);
        }
        Ok(Self(parts))
    }

    /// The checked parts.
    #[must_use]
    pub const fn parts(&self) -> &RouterStatusParts {
        &self.0
    }

    /// The parts, to change and check again.
    #[must_use]
    pub fn into_parts(self) -> RouterStatusParts {
        self.0
    }
}

impl TryFrom<RouterStatusParts> for RouterStatus {
    type Error = RouterValueError;

    fn try_from(parts: RouterStatusParts) -> Result<Self, Self::Error> {
        Self::new(parts)
    }
}

impl From<RouterStatus> for RouterStatusParts {
    fn from(status: RouterStatus) -> Self {
        status.0
    }
}

/// Why no router status is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterUnavailableReason {
    /// No router adapter is configured: the M7's identity or admin
    /// password is not recorded yet.
    NotConfigured,
    /// The M7 did not answer.
    Unreachable,
    /// The M7 refused the login.
    AuthFailed,
    /// The device answering at the M7's address is not the recorded M7
    /// (its link-layer address differs; critique C-8), so no login was
    /// sent.
    IdentityMismatch,
    /// The device has no supported status interface.
    Unsupported,
    /// The device's answer could not be read as a status.
    Malformed,
}

/// The router panel: a status, or why there is none. Never a default.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RouterReading {
    /// The latest status.
    Available {
        /// When the Mac polled it (the Mac's clock; the M7's is not
        /// trusted).
        polled_at: UnixTime,
        /// What the M7 reported (boxed: a status is far larger than the
        /// other variant).
        status: Box<RouterStatus>,
    },
    /// No status.
    Unavailable {
        /// Why.
        reason: RouterUnavailableReason,
        /// The last successful poll, if any.
        #[serde(deserialize_with = "Option::deserialize")]
        last_polled_at: Option<UnixTime>,
    },
}
