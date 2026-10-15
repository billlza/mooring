// SPDX-License-Identifier: GPL-3.0-or-later

//! The allowlist: one table, one row per leaf of `model.json` that Mooring
//! reads (its path, its shape, and which parse reads it), generated into
//! [`NetgearLeaf`]. The walker reads only these leaves, the parsers read
//! only through them, and the redactor keeps exactly the ones that are not
//! secret, so the three cannot drift apart. `docs/measurements/M2.md`
//! lists the same table; a test keeps the two equal.

use std::fmt;

/// One segment of a leaf's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// An object key.
    Key(&'static str),
    /// Every element of the carrier list (`wwan.lteBandInfo`), the one
    /// array whose elements are read.
    Each,
}

/// What a leaf's JSON value must be. The walker checks it before a value
/// is stored or written; ranges, vocabularies, sentinels and rules between
/// fields are the parser's, so the redactor can still capture an unknown
/// value of a known shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafShape {
    /// `true` or `false`.
    Bool,
    /// A JSON integer.
    Int,
    /// A string of `min..=max` bytes of printable ASCII (`0x20..=0x7E`)
    /// with no run of more than `digit_run` digits.
    Text {
        /// The fewest bytes.
        min: usize,
        /// The most bytes.
        max: usize,
        /// The longest run of digits.
        digit_run: usize,
    },
    /// A [`LeafShape::Text`] of `1..=max` bytes followed by exactly one
    /// line feed (the web application's version).
    Line {
        /// The most bytes before the line feed.
        max: usize,
        /// The longest run of digits.
        digit_run: usize,
    },
    /// A string of `min..=max` ASCII digits and nothing else.
    Digits {
        /// The fewest digits.
        min: usize,
        /// The most digits.
        max: usize,
    },
    /// A secret string of `1..=max` bytes of printable ASCII: read only by
    /// the session parser and never kept by the redactor.
    Secret {
        /// The most bytes.
        max: usize,
    },
}

/// Which parse reads a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafUse {
    /// Only the session parse (the anonymous answer's login fields).
    Session,
    /// Only the status parse.
    Status,
    /// Both.
    Both,
}

/// A set of leaves one walk extracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeafSet {
    /// The session parse's leaves.
    Session,
    /// The status parse's leaves: never the session token.
    Status,
    /// The redactor's: every leaf that is not secret.
    Kept,
}

impl LeafSet {
    /// Whether the set holds `leaf`.
    pub(crate) const fn contains(self, leaf: NetgearLeaf) -> bool {
        match self {
            Self::Session => matches!(leaf.used_by(), LeafUse::Session | LeafUse::Both),
            Self::Status => matches!(leaf.used_by(), LeafUse::Status | LeafUse::Both),
            Self::Kept => !leaf.is_secret(),
        }
    }
}

macro_rules! segment {
    ([]) => {
        Segment::Each
    };
    ($key:literal) => {
        Segment::Key($key)
    };
}

macro_rules! netgear_leaves {
    (
        $(
            $(#[$doc:meta])*
            $variant:ident = [ $($segment:tt),+ ] => $shape:expr, $usage:ident;
        )+
    ) => {
        /// A leaf of the MR7450's `model.json` that Mooring reads: the
        /// allowlist (design §15.6 rule 1). Its `Display` is the leaf's
        /// dotted path, `[]` standing for every element of the carrier
        /// list.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum NetgearLeaf {
            $( $(#[$doc])* $variant ),+
        }

        impl NetgearLeaf {
            /// Every leaf, in table order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The leaf's path.
            #[must_use]
            pub const fn segments(self) -> &'static [Segment] {
                match self {
                    $( Self::$variant => &[ $( segment!($segment) ),+ ] ),+
                }
            }

            /// The leaf's shape.
            pub(crate) const fn shape(self) -> LeafShape {
                use LeafShape::{Bool, Digits, Int, Line, Secret, Text};
                match self {
                    $( Self::$variant => $shape ),+
                }
            }

            /// Which parse reads the leaf.
            pub(crate) const fn used_by(self) -> LeafUse {
                match self {
                    $( Self::$variant => LeafUse::$usage ),+
                }
            }
        }
    };
}

netgear_leaves! {
    /// `session.userRole`: `Admin` after a login (M2a); anything else is
    /// not an administrator.
    SessionUserRole = ["session", "userRole"] => Text { min: 0, max: 32, digit_run: 2 }, Both;
    /// `session.passwordCooloff`: non-zero while the M7 refuses password
    /// attempts (inference); no password is sent then.
    SessionPasswordCooloff = ["session", "passwordCooloff"] => Int, Session;
    /// `session.secToken`: the login form's `token`. Secret: read only by
    /// the session parser, never kept by the redactor.
    SessionToken = ["session", "secToken"] => Secret { max: 128 }, Session;
    /// `general.model`: `MR7450`.
    GeneralModel = ["general", "model"] => Text { min: 1, max: 32, digit_run: 4 }, Both;
    /// `general.apiVersion`: `2.0`.
    GeneralApiVersion = ["general", "apiVersion"] => Text { min: 1, max: 16, digit_run: 3 }, Status;
    /// `general.FWversion`: the firmware version.
    GeneralFirmware = ["general", "FWversion"] => Text { min: 1, max: 64, digit_run: 6 }, Status;
    /// `general.webAppVersion`: the web application's version, ending in a
    /// line feed.
    GeneralWebAppVersion = ["general", "webAppVersion"] => Line { max: 64, digit_run: 6 }, Status;
    /// `general.devTemperature`: the device temperature, °C.
    GeneralTemperature = ["general", "devTemperature"] => Int, Status;
    /// `general.upTime`: seconds since boot.
    GeneralUptime = ["general", "upTime"] => Int, Status;
    /// `power.PMState`: the power management state.
    PowerState = ["power", "PMState"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `power.battChargeLevel`: the battery charge, %.
    BatteryCharge = ["power", "battChargeLevel"] => Int, Status;
    /// `power.batteryState`: the battery's state.
    BatteryState = ["power", "batteryState"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `power.charging`: whether the battery is charging.
    BatteryCharging = ["power", "charging"] => Bool, Status;
    /// `power.battChargeSource`: what charges the battery.
    BatteryChargeSource = ["power", "battChargeSource"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `power.batteryTemperature`: the battery's temperature, °C.
    BatteryTemperature = ["power", "batteryTemperature"] => Int, Status;
    /// `sim.SPN`: the SIM's service provider name.
    SimSpn = ["sim", "SPN"] => Text { min: 1, max: 32, digit_run: 2 }, Status;
    /// `wwan.connection`: the data session's state.
    WwanConnection = ["wwan", "connection"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `wwan.currentNWserviceType`: the network service type.
    WwanNetworkService = ["wwan", "currentNWserviceType"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `wwan.currentPSserviceType`: the data service type.
    WwanDataService = ["wwan", "currentPSserviceType"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `wwan.registerNetworkDisplay`: the network's display name.
    WwanNetworkName = ["wwan", "registerNetworkDisplay"] => Text { min: 1, max: 32, digit_run: 2 }, Status;
    /// `wwan.sessDuration`: seconds the data session has lasted.
    WwanSessionDuration = ["wwan", "sessDuration"] => Int, Status;
    /// `wwan.dataTransferredRx`: the receive counter, a decimal string.
    WwanRxBytes = ["wwan", "dataTransferredRx"] => Digits { min: 1, max: 20 }, Status;
    /// `wwan.dataTransferredTx`: the transmit counter, a decimal string.
    WwanTxBytes = ["wwan", "dataTransferredTx"] => Digits { min: 1, max: 20 }, Status;
    /// `wwan.thermalState`: the modem's thermal state.
    WwanThermalState = ["wwan", "thermalState"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `wwan.ca.SCCcount`: how many secondary carriers are aggregated.
    WwanSecondaryCount = ["wwan", "ca", "SCCcount"] => Int, Status;
    /// `wwan.lteBandInfo[].isPcc`: whether a carrier is the primary.
    LteCarrierPrimary = ["wwan", "lteBandInfo", [], "isPcc"] => Bool, Status;
    /// `wwan.lteBandInfo[].band`: a carrier's band number.
    LteCarrierBand = ["wwan", "lteBandInfo", [], "band"] => Int, Status;
    /// `wwan.lteBandInfo[].dlBandwidth`: a carrier's downlink bandwidth.
    LteCarrierBandwidth = ["wwan", "lteBandInfo", [], "dlBandwidth"] => Text { min: 1, max: 8, digit_run: 2 }, Status;
    /// `wwan.signalStrength.rsrp`: the LTE RSRP, dBm.
    SignalRsrp = ["wwan", "signalStrength", "rsrp"] => Int, Status;
    /// `wwan.signalStrength.rsrq`: the LTE RSRQ, dB.
    SignalRsrq = ["wwan", "signalStrength", "rsrq"] => Int, Status;
    /// `wwan.signalStrength.sinr`: the LTE SINR, dB.
    SignalSinr = ["wwan", "signalStrength", "sinr"] => Int, Status;
    /// `wwan.signalStrength.rssi`: the LTE RSSI, dBm.
    SignalRssi = ["wwan", "signalStrength", "rssi"] => Int, Status;
    /// `wwan.signalStrength.nr5gRsrp`: the NR RSRP, dBm.
    SignalNrRsrp = ["wwan", "signalStrength", "nr5gRsrp"] => Int, Status;
    /// `wwan.signalStrength.nr5gRsrq`: the NR RSRQ, dB.
    SignalNrRsrq = ["wwan", "signalStrength", "nr5gRsrq"] => Int, Status;
    /// `wwan.signalStrength.nr5gSinr`: the NR SINR, dB.
    SignalNrSinr = ["wwan", "signalStrength", "nr5gSinr"] => Int, Status;
    /// `wwanadv.MCC`: the network's mobile country code.
    PlmnMcc = ["wwanadv", "MCC"] => Digits { min: 3, max: 3 }, Status;
    /// `wwanadv.MNC`: the network's mobile network code.
    PlmnMnc = ["wwanadv", "MNC"] => Digits { min: 2, max: 3 }, Status;
    /// `wwanadv.curBand`: the band in use, `LTE B<n>`.
    CurrentBand = ["wwanadv", "curBand"] => Text { min: 1, max: 16, digit_run: 3 }, Status;
    /// `wifi.enabled`: whether the Wi-Fi radio is on.
    WifiEnabled = ["wifi", "enabled"] => Bool, Status;
    /// `wifi.status`: the main access point's status.
    WifiStatus = ["wifi", "status"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `wifi.guest.status`: the guest access point's status.
    WifiGuestStatus = ["wifi", "guest", "status"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `wifi.aux.status`: the auxiliary access point's status.
    WifiAuxStatus = ["wifi", "aux", "status"] => Text { min: 1, max: 32, digit_run: 3 }, Status;
    /// `wifi.clientCount`: how many Wi-Fi clients are connected.
    WifiClientCount = ["wifi", "clientCount"] => Int, Status;
    /// `wifi.offload.enabled`: Wi-Fi offload.
    WifiOffloadEnabled = ["wifi", "offload", "enabled"] => Bool, Status;
    /// `ethernet.offload.enabled`: Ethernet offload.
    EthernetOffloadEnabled = ["ethernet", "offload", "enabled"] => Bool, Status;
    /// `router.UPNPenabled`: UPnP.
    UpnpEnabled = ["router", "UPNPenabled"] => Bool, Status;
    /// `ra.enabled`: NETGEAR Analytics.
    AnalyticsEnabled = ["ra", "enabled"] => Bool, Status;
    /// `insight.active`: whether NETGEAR Insight is active.
    InsightActive = ["insight", "active"] => Bool, Status;
    /// `sms.unreadMsgs`: how many SMS are unread.
    SmsUnread = ["sms", "unreadMsgs"] => Int, Status;
}

impl NetgearLeaf {
    /// Whether the leaf is a secret (the session token).
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(self.shape(), LeafShape::Secret { .. })
    }
}

impl fmt::Display for NetgearLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_path(self.segments(), None, f)
    }
}

/// A leaf's path with the carrier list's element index, if any: `[1]` for
/// an element, `[]` for every element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeafPath {
    /// The leaf.
    pub(crate) leaf: NetgearLeaf,
    /// The element of the carrier list.
    pub(crate) element: Option<u16>,
}

impl fmt::Display for LeafPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_path(self.leaf.segments(), self.element, f)
    }
}

/// The carrier list's own path (`wwan.lteBandInfo`): a carrier leaf's
/// path up to its element segment.
pub(crate) const fn carrier_list_path() -> CarrierListPath {
    CarrierListPath
}

/// Displays [`carrier_list_path`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct CarrierListPath;

impl fmt::Display for CarrierListPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let segments = NetgearLeaf::LteCarrierPrimary.segments();
        let list = segments
            .iter()
            .position(|segment| *segment == Segment::Each)
            .map_or(segments, |each| &segments[..each]);
        write_path(list, None, f)
    }
}

fn write_path(
    segments: &[Segment],
    element: Option<u16>,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    for (index, segment) in segments.iter().enumerate() {
        match segment {
            Segment::Key(key) => {
                if index > 0 {
                    f.write_str(".")?;
                }
                f.write_str(key)?;
            }
            Segment::Each => match element {
                Some(element) => write!(f, "[{element}]")?,
                None => f.write_str("[]")?,
            },
        }
    }
    Ok(())
}

/// Whether two keys are the same text (a `const` string comparison).
const fn same_key(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if a[index] != b[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether the table is a tree the walker can follow without ambiguity:
/// every path starts and ends with a key and has no two element segments
/// in a row; no path equals or extends another; where two paths part, both
/// continue with a key (so a key never names both an object and the
/// iterated array); and every element segment belongs to one array.
/// Checked at compile time below.
const fn table_is_a_tree() -> bool {
    let all = NetgearLeaf::ALL;
    let mut array: Option<&[Segment]> = None;
    let mut i = 0;
    while i < all.len() {
        let path = all[i].segments();
        if path.is_empty()
            || matches!(path[0], Segment::Each)
            || matches!(path[path.len() - 1], Segment::Each)
        {
            return false;
        }
        let mut depth = 0;
        while depth < path.len() {
            if let Segment::Each = path[depth] {
                if let Segment::Each = path[depth - 1] {
                    return false;
                }
                let prefix = path.split_at(depth + 1).0;
                match array {
                    None => array = Some(prefix),
                    Some(known) => {
                        if !same_path(known, prefix) {
                            return false;
                        }
                    }
                }
            }
            depth += 1;
        }
        let mut j = 0;
        while j < all.len() {
            if i != j && !parted_by_keys(path, all[j].segments()) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Whether `a` and `b` have the same segments.
const fn same_path(a: &[Segment], b: &[Segment]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if !same_segment(a[index], b[index]) {
            return false;
        }
        index += 1;
    }
    true
}

const fn same_segment(a: Segment, b: Segment) -> bool {
    match (a, b) {
        (Segment::Key(a), Segment::Key(b)) => same_key(a, b),
        (Segment::Each, Segment::Each) => true,
        (Segment::Key(_), Segment::Each) | (Segment::Each, Segment::Key(_)) => false,
    }
}

/// Whether `a` and `b` part at some segment where both are keys.
const fn parted_by_keys(a: &[Segment], b: &[Segment]) -> bool {
    let mut index = 0;
    while index < a.len() && index < b.len() {
        if !same_segment(a[index], b[index]) {
            return matches!((a[index], b[index]), (Segment::Key(_), Segment::Key(_)));
        }
        index += 1;
    }
    false
}

const _: () = assert!(
    table_is_a_tree(),
    "the allowlist must be a tree of distinct leaves"
);
