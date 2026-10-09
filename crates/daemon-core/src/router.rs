// SPDX-License-Identifier: GPL-3.0-or-later

//! The M7's status as the console shows it (console spec B.2.7, corrected
//! by critique C-7 and C-8).
//!
//! The MR7450's JSON interface is unverified: the field paths in the spec
//! come from reverse-engineered clients of other NETGEAR hotspots, and the
//! M2a capture decides whether the interface exists at all. This module
//! therefore holds only the typed result such an adapter would produce, and
//! [`RouterReading::Unavailable`] for every case where it cannot. The
//! parser and the HTTP client come with the capture (work package WP8).
//!
//! [`RouterStatus`] is an allowlist by construction: it has no field for
//! the cell id, IMEI, ICCID, IMSI, phone number, SMS text or sender, WWAN
//! address history, connected clients' addresses or names, Wi-Fi keys,
//! GPS, or the admin password, so a parser built on it can only drop them.
//! Nor can a field it does have hold one by mistake (a parser reading the
//! wrong leaf): the band is a typed band number, and the free-text fields
//! refuse a run of digits long enough to be an identifier
//! ([`CarrierName::MAX_DIGIT_RUN`], [`FirmwareVersion::MAX_DIGIT_RUN`]).

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
    /// whether the M7's values fit is checked against the M2a capture.
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

/// The M7's temperature in whole °C, within -40..=125 (inference: the
/// usual rating of electronic temperature sensors).
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
    /// The carrier's display name, for example `SMARTY`.
    Carrier,
    /// The firmware version.
    Firmware,
}

impl fmt::Display for RouterTextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Band => "band",
            Self::Carrier => "carrier",
            Self::Firmware => "firmware",
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
fn digit_runs_within(text: &str, max: usize) -> bool {
    text.split(|c: char| !c.is_ascii_digit())
        .all(|run| run.len() <= max)
}

router_text!(
    /// The carrier's display name (`SMARTY`), at most 32 bytes and at most two
    /// digits in a row (`O2` and `3` fit). It names the network, not the
    /// subscriber: no phone number, IMSI or ICCID fits.
    CarrierName,
    Carrier,
    32,
    2
);
router_text!(
    /// The M7's firmware version, at most 64 bytes and at most six digits
    /// in a row (a `YYMMDD` date stamp fits; an IMEI, IMSI, ICCID, phone
    /// number or most cell ids, seven digits or more, do not). Whether the
    /// MR7450's versions fit this is checked against the M2a capture
    /// (inference). A change raises `RouterFirmwareChanged`.
    FirmwareVersion,
    Firmware,
    64,
    6
);

/// A band number, 1..=999: 3GPP numbers both LTE and NR bands within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// The radio band in use: an LTE band (`B3`) or an NR band (`n78`). On the
/// wire it is that text, without leading zeros; anything else is refused
/// (`InvalidText{field: Band}`, without echoing the text).
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

/// The radio access technology in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadioAccess {
    /// 4G LTE.
    Lte,
    /// 5G non-standalone (NR with an LTE anchor).
    NrNsa,
    /// 5G standalone.
    NrSa,
}

/// The signal readings; a reading the M7 does not report for the current
/// access is `None` (an NSA attachment may report no NR SINR, say).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
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

/// The M7's attachment to the mobile network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RadioState {
    /// Not attached: no service.
    NoService,
    /// Attached.
    Attached {
        /// The access technology.
        access: RadioAccess,
        /// The band.
        band: Band,
        /// The carrier's display name.
        carrier: CarrierName,
        /// The signal.
        signal: Signal,
    },
}

/// How the M7 is powered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RouterPower {
    /// Plugged-In mode: mains power, no battery.
    Plugged,
    /// On its battery.
    Battery {
        /// The charge.
        percent: BatteryPercent,
        /// Whether it is charging.
        charging: bool,
    },
}

/// What the M7 reported at one poll; only these fields are ever kept.
/// The offload and Wi-Fi radio states join them once the M2a capture has
/// found where the MR7450 reports them (console spec B.2.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterStatus {
    /// When the Mac polled it.
    pub polled_at: UnixTime,
    /// The radio.
    pub radio: RadioState,
    /// The device temperature.
    pub temperature_c: Celsius,
    /// The power source.
    pub power: RouterPower,
    /// The M7's own data counter, in bytes, for reconciliation with the SIM
    /// meter.
    pub data_counter_bytes: u64,
    /// How many clients are connected; exactly one (the Mac) is expected.
    pub connected_clients: u16,
    /// How many SMS are unread. Only the count is kept: the texts and their
    /// senders are never read into this type (the operator reads SMS in
    /// the M7's own web interface).
    pub unread_sms: u32,
    /// The firmware version.
    pub firmware: FirmwareVersion,
    /// Seconds since the M7 booted; a decrease shows a reboot.
    pub uptime_secs: u64,
}

/// Why no router status is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterUnavailableReason {
    /// No router adapter is configured: the M7's interface is not yet
    /// verified (the M2a capture), or the operator has not set it up.
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
    Available(RouterStatus),
    /// No status.
    Unavailable {
        /// Why.
        reason: RouterUnavailableReason,
        /// The last successful poll, if any.
        #[serde(deserialize_with = "Option::deserialize")]
        last_polled_at: Option<UnixTime>,
    },
}
