// SPDX-License-Identifier: GPL-3.0-or-later

//! The parsers. [`Leaves`] is their only input: what the walk extracted,
//! readable only by [`NetgearLeaf`], so nothing here can name a JSON path
//! and the builders can read only allowlisted leaves (and, by the walk's
//! [`LeafSet`], only those of their own parse).

use std::collections::BTreeMap;

use mooring_model::Secret;
use serde::Deserializer;
use serde::de::{IgnoredAny, SeqAccess};

use super::allowlist::{LeafSet, NetgearLeaf};
use super::walk::{Element, Found, LeafValue, Scalar, Sink, walk};
use super::{ADMIN_ROLE, NETGEAR_API_VERSION, NETGEAR_MODEL};
use crate::error::{CarrierFaultKind, FieldFaultKind, RouterParseError, RouterValueError};
use crate::router::{
    Band, BandNumber, Battery, BatteryPercent, BatteryState, CarrierName, Celsius, ChargeSource,
    DataService, FirmwareVersion, LteBandwidth, LteCarrier, LteCarriers, LteSignal, Mcc, Mnc,
    NetworkService, NrSignal, Plmn, PowerState, Radio, RadioState, RouterPower, RouterSettings,
    RouterStatus, RouterStatusParts, RouterWifi, Rsrp, Rsrq, Rssi, Sinr, ThermalState,
    WebAppVersion, WifiApStatus, WwanCounters,
};

/// The value the M7 reports for a reading it does not have.
pub(crate) const NOT_REPORTED: i128 = -32_768;

/// The only `wwan.connection` value read: a data session is up.
const CONNECTED: &str = "Connected";

/// The prefix of an LTE band in `wwanadv.curBand`.
const LTE_BAND_PREFIX: &str = "LTE B";

/// The band the M7 lists for an unassigned secondary-carrier slot.
const UNASSIGNED_SLOT_BAND: u16 = 0;

/// The downlink bandwidth the M7 lists for an unassigned slot.
const UNASSIGNED_SLOT_BANDWIDTH: &str = "Unknown";

/// The leaves one walk extracted, and the carrier list's elements.
#[derive(Debug, Default)]
pub(crate) struct Leaves {
    values: BTreeMap<(NetgearLeaf, Option<u16>), LeafValue>,
    carriers: Option<Vec<Element>>,
}

impl Leaves {
    /// Walks `body` for the leaves of `set`.
    fn of(body: &[u8], set: LeafSet) -> Result<Self, RouterParseError> {
        let mut leaves = Self::default();
        walk(body, set, &mut leaves)?;
        Ok(leaves)
    }

    fn value(
        &self,
        leaf: NetgearLeaf,
        element: Option<u16>,
    ) -> Result<&LeafValue, RouterParseError> {
        self.values
            .get(&(leaf, element))
            .ok_or_else(|| field(leaf, element, FieldFaultKind::Missing))
    }

    fn bool_at(&self, leaf: NetgearLeaf, element: Option<u16>) -> Result<bool, RouterParseError> {
        match self.value(leaf, element)? {
            LeafValue::Bool(value) => Ok(*value),
            LeafValue::Int(_)
            | LeafValue::Text(_)
            | LeafValue::Line(_)
            | LeafValue::Digits(_)
            | LeafValue::Secret(_)
            | LeafValue::Empty => Err(field(leaf, element, FieldFaultKind::WrongType)),
        }
    }

    fn bool(&self, leaf: NetgearLeaf) -> Result<bool, RouterParseError> {
        self.bool_at(leaf, None)
    }

    fn int_at(&self, leaf: NetgearLeaf, element: Option<u16>) -> Result<i128, RouterParseError> {
        match self.value(leaf, element)? {
            LeafValue::Int(value) => Ok(*value),
            LeafValue::Bool(_)
            | LeafValue::Text(_)
            | LeafValue::Line(_)
            | LeafValue::Digits(_)
            | LeafValue::Secret(_)
            | LeafValue::Empty => Err(field(leaf, element, FieldFaultKind::WrongType)),
        }
    }

    fn text_at(&self, leaf: NetgearLeaf, element: Option<u16>) -> Result<&str, RouterParseError> {
        match self.value(leaf, element)? {
            LeafValue::Text(text) => Ok(text),
            LeafValue::Bool(_)
            | LeafValue::Int(_)
            | LeafValue::Line(_)
            | LeafValue::Digits(_)
            | LeafValue::Secret(_)
            | LeafValue::Empty => Err(field(leaf, element, FieldFaultKind::WrongType)),
        }
    }

    fn text(&self, leaf: NetgearLeaf) -> Result<&str, RouterParseError> {
        self.text_at(leaf, None)
    }

    fn line(&self, leaf: NetgearLeaf) -> Result<&str, RouterParseError> {
        match self.value(leaf, None)? {
            LeafValue::Line(text) => Ok(text),
            LeafValue::Bool(_)
            | LeafValue::Int(_)
            | LeafValue::Text(_)
            | LeafValue::Digits(_)
            | LeafValue::Secret(_)
            | LeafValue::Empty => Err(field(leaf, None, FieldFaultKind::WrongType)),
        }
    }

    fn digits(&self, leaf: NetgearLeaf) -> Result<&str, RouterParseError> {
        match self.value(leaf, None)? {
            LeafValue::Digits(text) => Ok(text),
            LeafValue::Bool(_)
            | LeafValue::Int(_)
            | LeafValue::Text(_)
            | LeafValue::Line(_)
            | LeafValue::Secret(_)
            | LeafValue::Empty => Err(field(leaf, None, FieldFaultKind::WrongType)),
        }
    }

    fn secret(&self, leaf: NetgearLeaf) -> Result<&Secret<String>, RouterParseError> {
        match self.value(leaf, None)? {
            LeafValue::Secret(secret) => Ok(secret),
            LeafValue::Bool(_)
            | LeafValue::Int(_)
            | LeafValue::Text(_)
            | LeafValue::Line(_)
            | LeafValue::Digits(_)
            | LeafValue::Empty => Err(field(leaf, None, FieldFaultKind::WrongType)),
        }
    }

    fn carriers(&self) -> Result<&[Element], RouterParseError> {
        self.carriers.as_deref().ok_or(RouterParseError::Carriers {
            fault: CarrierFaultKind::Absent,
        })
    }

    /// An integer leaf as `T` (`OutOfRange` if it does not fit).
    fn integer_at<T: TryFrom<i128>>(
        &self,
        leaf: NetgearLeaf,
        element: Option<u16>,
    ) -> Result<T, RouterParseError> {
        T::try_from(self.int_at(leaf, element)?)
            .map_err(|_| field(leaf, element, FieldFaultKind::OutOfRange))
    }

    fn integer<T: TryFrom<i128>>(&self, leaf: NetgearLeaf) -> Result<T, RouterParseError> {
        self.integer_at(leaf, None)
    }

    /// A text leaf as the device value it spells (`UnknownValue`
    /// otherwise).
    fn vocabulary<T>(
        &self,
        leaf: NetgearLeaf,
        element: Option<u16>,
        from_wire: fn(&str) -> Option<T>,
    ) -> Result<T, RouterParseError> {
        from_wire(self.text_at(leaf, element)?)
            .ok_or_else(|| field(leaf, element, FieldFaultKind::UnknownValue))
    }

    /// A reading in whole units as tenths; the not-reported value is
    /// `None` (`OutOfRange` if it fits no reading).
    fn reading<T>(
        &self,
        leaf: NetgearLeaf,
        from_tenths: fn(i16) -> Result<T, RouterValueError>,
    ) -> Result<Option<T>, RouterParseError> {
        let whole = self.int_at(leaf, None)?;
        if whole == NOT_REPORTED {
            return Ok(None);
        }
        let out_of_range = || field(leaf, None, FieldFaultKind::OutOfRange);
        let tenths = i16::try_from(whole)
            .ok()
            .and_then(|whole| whole.checked_mul(10))
            .ok_or_else(out_of_range)?;
        from_tenths(tenths).map(Some).map_err(|_| out_of_range())
    }

    /// A text leaf through a router text type (`InvalidText` if refused).
    fn router_text<T>(
        &self,
        leaf: NetgearLeaf,
        parse: fn(&str) -> Result<T, RouterValueError>,
    ) -> Result<T, RouterParseError> {
        parse(self.text(leaf)?).map_err(|_| field(leaf, None, FieldFaultKind::InvalidText))
    }

    /// A line leaf, without its line feed, through a router text type
    /// (`InvalidText` if refused).
    fn router_line<T>(
        &self,
        leaf: NetgearLeaf,
        parse: fn(&str) -> Result<T, RouterValueError>,
    ) -> Result<T, RouterParseError> {
        parse(self.line(leaf)?).map_err(|_| field(leaf, None, FieldFaultKind::InvalidText))
    }

    /// A leaf the M7 may report as the empty string (its shape is
    /// `OrEmpty`): `None` for exactly that, else `read` of the leaf.
    fn unless_empty<T>(
        &self,
        leaf: NetgearLeaf,
        read: impl FnOnce(NetgearLeaf) -> Result<T, RouterParseError>,
    ) -> Result<Option<T>, RouterParseError> {
        match self.value(leaf, None)? {
            LeafValue::Empty => Ok(None),
            LeafValue::Bool(_)
            | LeafValue::Int(_)
            | LeafValue::Text(_)
            | LeafValue::Line(_)
            | LeafValue::Digits(_)
            | LeafValue::Secret(_) => read(leaf).map(Some),
        }
    }

    /// A temperature leaf (`OutOfRange` outside -40..=125 °C).
    fn celsius(&self, leaf: NetgearLeaf) -> Result<Celsius, RouterParseError> {
        Celsius::new(self.integer(leaf)?).map_err(|_| field(leaf, None, FieldFaultKind::OutOfRange))
    }

    /// A decimal counter: canonical digits (no leading zero but `0`
    /// itself), within a `u64`.
    fn counter(&self, leaf: NetgearLeaf) -> Result<u64, RouterParseError> {
        let digits = self.digits(leaf)?;
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(field(leaf, None, FieldFaultKind::NotCanonical));
        }
        digits
            .parse::<u64>()
            .map_err(|_| field(leaf, None, FieldFaultKind::OutOfRange))
    }
}

impl Sink for Leaves {
    fn leaf(&mut self, leaf: NetgearLeaf, element: Option<u16>, value: LeafValue) {
        self.values.insert((leaf, element), value);
    }

    /// A refused value is the parse's error.
    fn refused(&mut self, fault: RouterParseError, _: Found) -> Result<(), RouterParseError> {
        Err(fault)
    }

    fn begin_object(&mut self) {}

    fn key(&mut self, _: &str) -> Result<(), RouterParseError> {
        Ok(())
    }

    fn end_object(&mut self) {}

    fn begin_carriers(&mut self) {
        self.carriers = Some(Vec::new());
    }

    fn carrier(&mut self, element: Element) {
        self.carriers.get_or_insert_with(Vec::new).push(element);
    }

    fn end_carriers(&mut self) {}

    fn outside<'de, D: Deserializer<'de>>(&mut self, value: D) -> Result<(), D::Error> {
        value.deserialize_ignored_any(IgnoredAny).map(|_| ())
    }

    fn outside_scalar(&mut self, _: Scalar) {}

    fn outside_seq<'de, A: SeqAccess<'de>>(&mut self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn take_fault(&mut self) -> Option<RouterParseError> {
        None
    }
}

fn field(leaf: NetgearLeaf, element: Option<u16>, fault: FieldFaultKind) -> RouterParseError {
    RouterParseError::Field {
        leaf,
        element,
        fault,
    }
}

/// The login form's token (`session.secToken`): redacted in `Debug`, with
/// neither `Display` nor `Serialize`.
#[derive(Debug)]
pub struct SecToken(Secret<String>);

impl SecToken {
    /// The token, for the login form's body only.
    #[must_use]
    pub fn expose_str(&self) -> &str {
        self.0.expose_secret()
    }
}

/// What the anonymous answer (or any answer) says about the session: who
/// it is, whether the M7 refuses passwords for now, and the login form's
/// token.
#[derive(Debug)]
pub struct NetgearSession {
    admin: bool,
    cooloff: u32,
    token: SecToken,
}

impl NetgearSession {
    /// Whether the session is an administrator's (`session.userRole` is
    /// exactly `Admin`).
    #[must_use]
    pub const fn is_admin(&self) -> bool {
        self.admin
    }

    /// The password cool-off the M7 reports (`session.passwordCooloff`);
    /// a password is sent only when it is 0 (inference: its unit and
    /// meaning are unverified, so any other value is read as a refusal).
    #[must_use]
    pub const fn cooloff(&self) -> u32 {
        self.cooloff
    }

    /// The login form's token.
    #[must_use]
    pub const fn token(&self) -> &SecToken {
        &self.token
    }
}

/// Reads the session leaves of a `model.json` answer, checking the model
/// first (`Unsupported{GeneralModel}` for another device). The status
/// leaves are not read.
pub fn parse_netgear_session(body: &[u8]) -> Result<NetgearSession, RouterParseError> {
    let leaves = Leaves::of(body, LeafSet::Session)?;
    check_model(&leaves)?;
    let admin = leaves.text(NetgearLeaf::SessionUserRole)? == ADMIN_ROLE;
    let cooloff = leaves.integer(NetgearLeaf::SessionPasswordCooloff)?;
    let token = SecToken(leaves.secret(NetgearLeaf::SessionToken)?.clone());
    Ok(NetgearSession {
        admin,
        cooloff,
        token,
    })
}

fn check_model(leaves: &Leaves) -> Result<(), RouterParseError> {
    if leaves.text(NetgearLeaf::GeneralModel)? == NETGEAR_MODEL {
        Ok(())
    } else {
        Err(RouterParseError::Unsupported {
            leaf: NetgearLeaf::GeneralModel,
        })
    }
}

/// Reads an administrator's `model.json` answer into the router status.
///
/// The checks run in a fixed order and the first failure is the error: the
/// session is an administrator's (`NotAdmin`), the device is an MR7450 and
/// speaks API 2.0 (`Unsupported`), then every field in the order of
/// [`RouterStatusParts`] (`Field` or `Carriers`), then the status's own
/// rule (`SessionExceedsUptime`). Every value outside the allowlist is
/// skipped unread, and the session token is not extracted.
pub fn parse_netgear_model_json(body: &[u8]) -> Result<RouterStatus, RouterParseError> {
    let leaves = Leaves::of(body, LeafSet::Status)?;
    if leaves.text(NetgearLeaf::SessionUserRole)? != ADMIN_ROLE {
        return Err(RouterParseError::NotAdmin);
    }
    check_model(&leaves)?;
    if leaves.text(NetgearLeaf::GeneralApiVersion)? != NETGEAR_API_VERSION {
        return Err(RouterParseError::Unsupported {
            leaf: NetgearLeaf::GeneralApiVersion,
        });
    }
    let parts = status_parts(&leaves)?;
    RouterStatus::new(parts).map_err(|_| RouterParseError::SessionExceedsUptime)
}

fn status_parts(leaves: &Leaves) -> Result<RouterStatusParts, RouterParseError> {
    use NetgearLeaf as L;
    Ok(RouterStatusParts {
        firmware: leaves.router_text(L::GeneralFirmware, FirmwareVersion::parse)?,
        web_app: leaves.unless_empty(L::GeneralWebAppVersion, |leaf| {
            leaves.router_line(leaf, WebAppVersion::parse)
        })?,
        uptime_secs: leaves.integer(L::GeneralUptime)?,
        temperature_c: leaves.celsius(L::GeneralTemperature)?,
        thermal: leaves.vocabulary(L::WwanThermalState, None, ThermalState::from_wire)?,
        power: RouterPower {
            state: leaves.vocabulary(L::PowerState, None, PowerState::from_wire)?,
            battery: Battery {
                charge: BatteryPercent::new(leaves.integer(L::BatteryCharge)?)
                    .map_err(|_| field(L::BatteryCharge, None, FieldFaultKind::OutOfRange))?,
                state: leaves.vocabulary(L::BatteryState, None, BatteryState::from_wire)?,
                charging: leaves.bool(L::BatteryCharging)?,
                source: leaves.vocabulary(L::BatteryChargeSource, None, ChargeSource::from_wire)?,
                temperature_c: leaves.celsius(L::BatteryTemperature)?,
            },
        },
        sim_spn: leaves.unless_empty(L::SimSpn, |leaf| {
            leaves.router_text(leaf, CarrierName::parse)
        })?,
        radio: radio(leaves)?,
        counters: WwanCounters {
            rx_bytes: leaves.counter(L::WwanRxBytes)?,
            tx_bytes: leaves.counter(L::WwanTxBytes)?,
        },
        wifi: RouterWifi {
            enabled: leaves.bool(L::WifiEnabled)?,
            main: leaves.vocabulary(L::WifiStatus, None, WifiApStatus::from_wire)?,
            guest: leaves.vocabulary(L::WifiGuestStatus, None, WifiApStatus::from_wire)?,
            aux: leaves.vocabulary(L::WifiAuxStatus, None, WifiApStatus::from_wire)?,
            clients: leaves.integer(L::WifiClientCount)?,
        },
        settings: RouterSettings {
            wifi_offload: leaves.bool(L::WifiOffloadEnabled)?,
            ethernet_offload: leaves.bool(L::EthernetOffloadEnabled)?,
            upnp: leaves.bool(L::UpnpEnabled)?,
            analytics: leaves.bool(L::AnalyticsEnabled)?,
            insight_active: leaves.bool(L::InsightActive)?,
        },
        unread_sms: leaves.integer(L::SmsUnread)?,
    })
}

fn radio(leaves: &Leaves) -> Result<RadioState, RouterParseError> {
    use NetgearLeaf as L;
    if leaves.text(L::WwanConnection)? != CONNECTED {
        return Err(field(L::WwanConnection, None, FieldFaultKind::UnknownValue));
    }
    Ok(RadioState::Attached(Radio {
        network_service: leaves.vocabulary(
            L::WwanNetworkService,
            None,
            NetworkService::from_wire,
        )?,
        data_service: leaves.vocabulary(L::WwanDataService, None, DataService::from_wire)?,
        band: current_band(leaves)?,
        lte_carriers: lte_carriers(leaves)?,
        ca_secondary_count: leaves.integer(L::WwanSecondaryCount)?,
        lte: LteSignal {
            rsrp: leaves.reading(L::SignalRsrp, Rsrp::from_tenths)?,
            rsrq: leaves.reading(L::SignalRsrq, Rsrq::from_tenths)?,
            sinr: leaves.reading(L::SignalSinr, Sinr::from_tenths)?,
            rssi: leaves.reading(L::SignalRssi, Rssi::from_tenths)?,
        },
        nr: NrSignal {
            rsrp: leaves.reading(L::SignalNrRsrp, Rsrp::from_tenths)?,
            rsrq: leaves.reading(L::SignalNrRsrq, Rsrq::from_tenths)?,
            sinr: leaves.reading(L::SignalNrSinr, Sinr::from_tenths)?,
        },
        network: leaves.router_text(L::WwanNetworkName, CarrierName::parse)?,
        plmn: Plmn {
            mcc: Mcc::parse(leaves.digits(L::PlmnMcc)?)
                .map_err(|_| field(L::PlmnMcc, None, FieldFaultKind::InvalidText))?,
            mnc: Mnc::parse(leaves.digits(L::PlmnMnc)?)
                .map_err(|_| field(L::PlmnMnc, None, FieldFaultKind::InvalidText))?,
        },
        session_secs: leaves.integer(L::WwanSessionDuration)?,
    }))
}

/// `wwanadv.curBand`: exactly `LTE B` and a band number without a leading
/// zero. The M7's spelling of an NR band is not yet observed, so any other
/// text is an unknown value.
fn current_band(leaves: &Leaves) -> Result<Band, RouterParseError> {
    let leaf = NetgearLeaf::CurrentBand;
    let unknown = || field(leaf, None, FieldFaultKind::UnknownValue);
    let digits = leaves
        .text(leaf)?
        .strip_prefix(LTE_BAND_PREFIX)
        .ok_or_else(unknown)?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return Err(unknown());
    }
    let number = digits
        .parse::<u16>()
        .ok()
        .and_then(|number| BandNumber::new(number).ok())
        .ok_or_else(|| field(leaf, None, FieldFaultKind::OutOfRange))?;
    Ok(Band::Lte(number))
}

/// `wwan.lteBandInfo`: the carriers, then exactly one empty object as a
/// terminator (`[{}]` alone: no carrier); the first carrier is the primary,
/// every other entry a secondary carrier or an unassigned slot (band 0 and
/// the bandwidth `Unknown` together; either alone is still refused).
fn lte_carriers(leaves: &Leaves) -> Result<Option<LteCarriers>, RouterParseError> {
    let carriers = |fault| RouterParseError::Carriers { fault };
    let (last, entries) = leaves
        .carriers()?
        .split_last()
        .ok_or_else(|| carriers(CarrierFaultKind::MissingTerminator))?;
    if *last != Element::Terminator {
        return Err(carriers(CarrierFaultKind::MissingTerminator));
    }
    let mut indices = Vec::with_capacity(entries.len());
    for element in entries {
        match element {
            Element::Entry(index) => indices.push(*index),
            Element::Terminator => return Err(carriers(CarrierFaultKind::MisplacedTerminator)),
        }
    }
    let Some((&first, rest)) = indices.split_first() else {
        return Ok(None);
    };
    if rest.len() > LteCarriers::MAX_SECONDARY {
        return Err(carriers(CarrierFaultKind::TooManySecondaries));
    }
    if !leaves.bool_at(NetgearLeaf::LteCarrierPrimary, Some(first))? {
        return Err(carriers(CarrierFaultKind::PrimaryNotFirst));
    }
    let primary = lte_carrier(leaves, first)?;
    let mut secondary = Vec::with_capacity(rest.len());
    let mut unassigned: usize = 0;
    for &index in rest {
        if leaves.bool_at(NetgearLeaf::LteCarrierPrimary, Some(index))? {
            return Err(carriers(CarrierFaultKind::SecondPrimary));
        }
        if is_unassigned_slot(leaves, index)? {
            unassigned += 1;
        } else {
            secondary.push(lte_carrier(leaves, index)?);
        }
    }
    let too_many = || carriers(CarrierFaultKind::TooManySecondaries);
    let unassigned = u8::try_from(unassigned).map_err(|_| too_many())?;
    LteCarriers::new(primary, secondary, unassigned)
        .map(Some)
        .map_err(|_| too_many())
}

/// Whether the secondary entry at `index` is an unassigned slot: band 0
/// and the bandwidth `Unknown`, both exactly. Any other entry is read as a
/// carrier, so band 0 with a bandwidth, or `Unknown` with a band, is still
/// refused there.
fn is_unassigned_slot(leaves: &Leaves, index: u16) -> Result<bool, RouterParseError> {
    let element = Some(index);
    Ok(
        leaves.integer_at::<u16>(NetgearLeaf::LteCarrierBand, element)? == UNASSIGNED_SLOT_BAND
            && leaves.text_at(NetgearLeaf::LteCarrierBandwidth, element)?
                == UNASSIGNED_SLOT_BANDWIDTH,
    )
}

fn lte_carrier(leaves: &Leaves, index: u16) -> Result<LteCarrier, RouterParseError> {
    let element = Some(index);
    let band_leaf = NetgearLeaf::LteCarrierBand;
    let band = leaves
        .integer_at::<u16>(band_leaf, element)
        .and_then(|number| {
            BandNumber::new(number)
                .map_err(|_| field(band_leaf, element, FieldFaultKind::OutOfRange))
        })?;
    Ok(LteCarrier {
        band,
        dl_bandwidth: leaves.vocabulary(
            NetgearLeaf::LteCarrierBandwidth,
            element,
            LteBandwidth::from_wire,
        )?,
    })
}
