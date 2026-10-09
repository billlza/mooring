// SPDX-License-Identifier: GPL-3.0-or-later

//! [`MacReportV1`]: what the Mac tells a node for remote viewers (design
//! §15.9, decision F5, 2026-10-08), sent with `PutMacReport` and read back
//! with `MacReport`.
//!
//! # What it cannot carry, and what keeps the rest out
//!
//! The report is an allowlist of the Mac's status: the exit's phase, the
//! SIM meter, the router's radio, the uplink's capacity, each user's status
//! and cycle bytes, and the open alerts by kind. It has no free-text field:
//! every string in it is a closed-enum name, a [`ReportUserId`] (exactly
//! ten characters of lowercase base32) or a [`NodeName`] (the node-id
//! grammar). The grammars alone refuse text with a space, a capital, a
//! `.`, a `@` or a character outside ASCII, so an address, a domain, an
//! e-mail address, a label written as people write one (`Alice Example`),
//! an IMEI or an ICCID written as text, and an SMS text cannot be decoded
//! into any string slot (the canary tests in `tests/wire/report.rs` try
//! each in every slot). The band number is a [`ReportBandNumber`],
//! 1..=999, so a physical cell id or a tracking-area code above 999 cannot
//! pose as a band either.
//!
//! The grammars are not the whole guarantee. A lowercase one-word string
//! (a label such as `phone`, a carrier name written in lowercase) fits a
//! [`NodeName`] slot, a ten-letter base32 word fits a [`ReportUserId`]
//! key, and a small identifier fits a numeric slot (a band number, a
//! signal reading, a byte count). What keeps those out is the projection
//! that builds the report (`mooring-daemon-core`'s `report::project`),
//! which fills every slot from a typed value of the Mac's status of the
//! same meaning, and whose own tests plant such canaries in the fields the
//! report drops.
//!
//! # Size
//!
//! A report holds at most [`MAX_REPORT_USERS`] users and
//! [`MAX_REPORT_ALERTS`] alerts, so its encoding is at most
//! [`MAX_MAC_REPORT_BYTES`]; compile-time assertions hold the
//! `PutMacReport` request and the `MacReport` reply carrying the largest
//! report within their frame limits.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::macros::{closed_enum, named_enum, text_newtype};
use crate::names::MAX_NODE_NAME_BYTES;
use crate::series::NUMBER_BYTES;
use crate::{
    MAX_REQUEST_LINE_BYTES, MAX_RESPONSE_LINE_BYTES, NodeName, Traffic, UnixTime, ValueError,
};

/// The most users one report carries.
pub const MAX_REPORT_USERS: usize = 1024;

/// The most open alerts one report carries.
pub const MAX_REPORT_ALERTS: usize = 256;

text_newtype!(
    /// A user's id as the report carries it: 10 characters of the lowercase
    /// RFC 4648 base32 alphabet (`^[a-z2-7]{10}$`), exactly the rule of
    /// `mooring-model`'s `UserId`, which `mooring-render` tests value by
    /// value. It is stricter than [`crate::OpaqueUserId`], so a number such
    /// as an IMEI or an ICCID cannot pose as a user id here.
    ReportUserId,
    ReportUserId,
    is_report_user_id
);

/// The length of every [`ReportUserId`].
const REPORT_USER_ID_BYTES: usize = 10;

/// The RFC 4648 base32 alphabet in lowercase.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn is_report_user_id(text: &str) -> bool {
    text.len() == REPORT_USER_ID_BYTES && text.bytes().all(|byte| BASE32_LOWER.contains(&byte))
}

named_enum! {
    /// The exit's state, without its details (the Mac's `ExitState`).
    pub enum ExitPhase {
        /// The operator disabled the exit.
        Disabled,
        /// Preflight is running.
        Preflight,
        /// The engine is starting.
        Starting,
        /// The engine runs and the first verdicts are pending.
        Verifying,
        /// Serving through a verified carrier address.
        Serving,
        /// Serving, with problems.
        Degraded,
        /// Not serving.
        Down,
        /// The Mac is asleep; the exit drained before it slept.
        Paused,
    }
}

/// The exit's phase and since when.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportExit {
    /// The phase.
    pub phase: ExitPhase,
    /// When the exit entered it (the Mac's clock).
    pub since: UnixTime,
}

named_enum! {
    /// Whether the SIM meter counts every byte.
    pub enum ReportAccuracy {
        /// The egress counters see all of the SIM's traffic.
        Exact,
        /// Some traffic may bypass them: the figures are a lower bound.
        LowerBound,
    }
}

/// The volume line of the SIM plan, if it has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReportPlanLine {
    /// A fair-use line, past which the carrier may deprioritise the line.
    FairUse {
        /// The line, in bytes.
        bytes: u64,
    },
    /// A data allowance per billing cycle.
    Allowance {
        /// The allowance, in bytes.
        bytes: u64,
    },
}

/// The SIM forecast for the cycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportForecast {
    /// The average bytes per day so far.
    pub daily_average_bytes: u64,
    /// The bytes projected for the whole cycle.
    pub projected_bytes: u64,
}

/// The SIM meter. The cycle's boundaries are the UTC-midnight instants of
/// its first day and of the next cycle's first day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSim {
    /// The start of the billing cycle.
    pub cycle_starts_at: UnixTime,
    /// The end of the billing cycle (exclusive).
    pub cycle_ends_at: UnixTime,
    /// Bytes received this cycle.
    pub rx_bytes: u64,
    /// Bytes sent this cycle.
    pub tx_bytes: u64,
    /// Whether the figures are exact.
    pub accuracy: ReportAccuracy,
    /// The warning threshold, in SIM bytes.
    pub warn_bytes: u64,
    /// The hard stop, in SIM bytes; `None` when the operator accepted
    /// deprioritisation instead.
    #[serde(deserialize_with = "Option::deserialize")]
    pub hard_stop_bytes: Option<u64>,
    /// The plan's line; `None` when the plan has none or is not recorded.
    #[serde(deserialize_with = "Option::deserialize")]
    pub line: Option<ReportPlanLine>,
    /// The forecast; `None` when none could be made.
    #[serde(deserialize_with = "Option::deserialize")]
    pub forecast: Option<ReportForecast>,
}

named_enum! {
    /// The radio access technology in use.
    pub enum ReportRadioAccess {
        /// 4G LTE.
        Lte,
        /// 5G non-standalone.
        NrNsa,
        /// 5G standalone.
        NrSa,
    }
}

named_enum! {
    /// The system a band number belongs to.
    pub enum ReportRadioSystem {
        /// An E-UTRA (LTE) band, `B<n>`.
        Lte,
        /// An NR (5G) band, `n<n>`.
        Nr,
    }
}

/// A radio band number, 1..=999: 3GPP numbers both LTE (E-UTRA) and NR
/// bands within it. It is exactly the rule of the Mac's band number
/// (`mooring-daemon-core`'s `BandNumber`, which that crate tests value by
/// value), so a value above 999, such as most physical cell ids
/// (0..=1007) and tracking-area codes, cannot be decoded as a band.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct ReportBandNumber(u16);

impl ReportBandNumber {
    /// The highest band number accepted.
    pub const MAX: u16 = 999;

    /// Accepts 1..=999 (`ReportBandNumber` otherwise).
    pub const fn new(number: u16) -> Result<Self, ValueError> {
        if number >= 1 && number <= Self::MAX {
            Ok(Self(number))
        } else {
            Err(ValueError::ReportBandNumber { number })
        }
    }

    /// The number.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for ReportBandNumber {
    type Error = ValueError;

    fn try_from(number: u16) -> Result<Self, Self::Error> {
        Self::new(number)
    }
}

impl From<ReportBandNumber> for u16 {
    fn from(number: ReportBandNumber) -> Self {
        number.0
    }
}

/// The radio band in use, such as LTE band 3 or NR band 78.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportBand {
    /// The system.
    pub system: ReportRadioSystem,
    /// The band number.
    pub number: ReportBandNumber,
}

/// The router's attachment to the mobile network. The carrier's name, the
/// cell and every device identifier are left out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReportRadio {
    /// Not attached: no service.
    NoService,
    /// Attached.
    Attached {
        /// The access technology.
        access: ReportRadioAccess,
        /// The band.
        band: ReportBand,
        /// RSRP in tenths of a dBm, if reported.
        #[serde(deserialize_with = "Option::deserialize")]
        rsrp_tenths: Option<i16>,
        /// RSRQ in tenths of a dB, if reported.
        #[serde(deserialize_with = "Option::deserialize")]
        rsrq_tenths: Option<i16>,
        /// SINR in tenths of a dB, if reported.
        #[serde(deserialize_with = "Option::deserialize")]
        sinr_tenths: Option<i16>,
        /// RSSI in tenths of a dBm, if reported.
        #[serde(deserialize_with = "Option::deserialize")]
        rssi_tenths: Option<i16>,
    },
}

/// The router panel: its latest poll, or that there is none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReportRouter {
    /// The latest poll.
    Available {
        /// When the Mac polled the router.
        polled_at: UnixTime,
        /// The radio.
        radio: ReportRadio,
        /// The device temperature in degrees Celsius.
        temperature_c: i16,
    },
    /// No status is available.
    Unavailable {
        /// The last successful poll, if any.
        #[serde(deserialize_with = "Option::deserialize")]
        last_polled_at: Option<UnixTime>,
    },
}

/// The saturation verdict of the uplink.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReportSaturation {
    /// No signal is available, so nothing can be said either way.
    NoEvidence,
    /// No available signal is at its threshold.
    Clear,
    /// A signal has been at its threshold since `since`, for less than the
    /// hold time.
    Building {
        /// When the current run started.
        since: UnixTime,
    },
    /// A signal has been at its threshold since `since`, for at least the
    /// hold time.
    Saturated {
        /// When the current run started.
        since: UnixTime,
    },
}

/// The uplink's latest capacity sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportCapacity {
    /// The sample's time.
    pub at: UnixTime,
    /// The egress transmit rate, in bit/s.
    pub tx_bps: u64,
    /// The egress receive rate, in bit/s.
    pub rx_bps: u64,
    /// The saturation verdict.
    pub saturation: ReportSaturation,
}

/// Whether the user rows carry cycle usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReportUsage {
    /// Every user carries its cycle usage, counted up to `through`.
    Available {
        /// The end of the counted period (exclusive).
        through: UnixTime,
    },
    /// No user carries usage.
    Unavailable,
}

named_enum! {
    /// A reported user's state. Revoked users are left out of the report.
    pub enum ReportUserStatus {
        /// The user may connect.
        Active,
        /// The user is suspended; the change can be undone.
        Suspended,
        /// The user is being revoked: its credentials are still on a node.
        RevokePending,
    }
}

/// One user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportUser {
    /// The user's state.
    pub status: ReportUserStatus,
    /// The user's bytes this billing cycle; present exactly when the
    /// report's usage is [`ReportUsage::Available`].
    #[serde(deserialize_with = "Option::deserialize")]
    pub cycle: Option<Traffic>,
    /// When the user's traffic last grew on any node, if ever.
    #[serde(deserialize_with = "Option::deserialize")]
    pub last_seen: Option<UnixTime>,
}

named_enum! {
    /// How urgent an alert is.
    pub enum ReportSeverity {
        /// Needs action now.
        Critical,
        /// Needs attention.
        Warning,
    }
}

named_enum! {
    /// The kind of an open alert on the Mac: the names of the Mac's alert
    /// condition kinds (design §15.8, console spec B.4), spelled the same.
    /// `mooring-daemon-core` maps its kinds onto these with an exhaustive
    /// match, so the lists cannot drift apart unnoticed.
    pub enum MacAlertKind {
        /// The exit latched a violation.
        ExitViolation,
        /// The SIM hard stop was reached.
        SimCapReached,
        /// The router's Wi-Fi offload is on.
        RouterOffloadActive,
        /// The router's Wi-Fi radio is on.
        RouterWifiRadioOn,
        /// The router is overheating.
        RouterOverheating,
        /// The router restarted.
        RouterRestarted,
        /// A node is halted.
        NodeHalted,
        /// A rollback failed on a node.
        RollbackFailed,
        /// Closing a node's gate failed.
        GateCloseFailed,
        /// An engine is crash-looping.
        EngineCrashLoop,
        /// A node's SSH host key did not match its pin.
        HostKeyMismatch,
        /// A node has not seen the Mac's handshake for too long.
        MacSilent,
        /// A node does not answer.
        NodeUnreachable,
        /// A node's disk is nearly full.
        NodeDiskLow,
        /// The SIM warning threshold was crossed.
        SimWarn,
        /// A SIM threshold is projected to be crossed this cycle.
        SimForecastCrossing,
        /// The exit is degraded.
        ExitDegraded,
        /// The Mac is attached to a network other than the router's.
        ForeignNetworkAttached,
        /// A node may be blocked.
        ReachabilitySuspect,
        /// A node's REALITY target is degraded.
        TargetDegraded,
        /// The router has no service.
        RouterNoService,
        /// The router is on LTE.
        RouterOnLte,
        /// The router stepped down for heat.
        RouterThermalStepDown,
        /// The router's signal is weak.
        RouterWeakSignal,
        /// The router's firmware changed.
        RouterFirmwareChanged,
        /// The router holds unread SMS.
        RouterUnreadSms,
        /// The router's counter disagrees with the SIM meter.
        RouterCounterMismatch,
        /// Users are near their quotas.
        UsersNearQuota,
        /// Users are over their quotas.
        UsersOverQuota,
        /// Users are suspended.
        UsersSuspended,
        /// Users expire soon.
        UsersExpiringSoon,
        /// Users have expired.
        UsersExpired,
        /// The uplink is saturated.
        CapacitySaturated,
        /// A node's exit flow cap rejected flows.
        ExitFlowCapHit,
        /// A node's clock is not synchronised.
        NodeClockUnsynced,
        /// A node has a reboot pending.
        NodeRebootPending,
        /// A node is behind the current generation.
        PendingApply,
        /// An operator hold has been set on a node for long.
        OperatorHoldLong,
        /// A node is not counting the probe's traffic.
        AccountingCanaryMissing,
    }
}

/// One open alert, by kind: the alert's details stay on the Mac.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportAlert {
    /// The kind.
    pub kind: MacAlertKind,
    /// Its severity.
    pub severity: ReportSeverity,
    /// The node it is about, if any.
    #[serde(deserialize_with = "Option::deserialize")]
    pub node: Option<NodeName>,
    /// When it became active.
    pub active_since: UnixTime,
}

closed_enum! {
    /// A rule every [`MacReportV1`] satisfies.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum MacReportRule {
        /// At most [`MAX_REPORT_USERS`] users.
        TooManyUsers,
        /// At most [`MAX_REPORT_ALERTS`] alerts.
        TooManyAlerts,
        /// Every user carries cycle usage exactly when the report's usage
        /// is available.
        UsageMismatch,
    }
}

impl fmt::Display for MacReportRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyUsers => write!(formatter, "at most {MAX_REPORT_USERS} users"),
            Self::TooManyAlerts => write!(formatter, "at most {MAX_REPORT_ALERTS} alerts"),
            Self::UsageMismatch => formatter
                .write_str("every user carries cycle usage exactly when usage is available"),
        }
    }
}

/// Every part of a [`MacReportV1`], unchecked. This is also the report's
/// wire shape.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacReportParts {
    /// When the Mac produced the report (the Mac's clock).
    pub at: UnixTime,
    /// The exit.
    pub exit: ReportExit,
    /// The SIM meter.
    pub sim: ReportSim,
    /// The router.
    pub router: ReportRouter,
    /// The latest capacity sample; `None` before the first.
    #[serde(deserialize_with = "Option::deserialize")]
    pub capacity: Option<ReportCapacity>,
    /// Whether the users carry cycle usage.
    pub usage: ReportUsage,
    /// Every user that is not revoked, by id.
    pub users: BTreeMap<ReportUserId, ReportUser>,
    /// The open alerts.
    pub alerts: Vec<ReportAlert>,
}

/// The Mac's report for remote viewers. Built only from
/// [`MacReportParts`] (also when decoded), which must satisfy every
/// [`MacReportRule`]; a breach is [`ValueError::MacReport`]. Two alerts may
/// share a kind and node (two engines' crash loops on one node), so the
/// alerts carry no uniqueness rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "MacReportParts", into = "MacReportParts")]
pub struct MacReportV1(MacReportParts);

impl MacReportV1 {
    /// Checks `parts` against every [`MacReportRule`], in declaration
    /// order.
    pub fn new(parts: MacReportParts) -> Result<Self, ValueError> {
        let usage_available = matches!(parts.usage, ReportUsage::Available { .. });
        let broken = if parts.users.len() > MAX_REPORT_USERS {
            Some(MacReportRule::TooManyUsers)
        } else if parts.alerts.len() > MAX_REPORT_ALERTS {
            Some(MacReportRule::TooManyAlerts)
        } else if parts
            .users
            .values()
            .any(|user| user.cycle.is_some() != usage_available)
        {
            Some(MacReportRule::UsageMismatch)
        } else {
            None
        };
        match broken {
            Some(rule) => Err(ValueError::MacReport { rule }),
            None => Ok(Self(parts)),
        }
    }

    /// The checked parts.
    pub const fn parts(&self) -> &MacReportParts {
        &self.0
    }

    /// The parts, to change and check again.
    pub fn into_parts(self) -> MacReportParts {
        self.0
    }
}

impl TryFrom<MacReportParts> for MacReportV1 {
    type Error = ValueError;

    fn try_from(parts: MacReportParts) -> Result<Self, Self::Error> {
        Self::new(parts)
    }
}

impl From<MacReportV1> for MacReportParts {
    fn from(report: MacReportV1) -> Self {
        report.0
    }
}

/// The report a node holds, the reply to `MacReport`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMacReport {
    /// When the node stored it (the node's clock).
    pub received_at: UnixTime,
    /// The report.
    pub report: MacReportV1,
}

/// The longest `i16` on the wire.
const I16_BYTES: usize = "-32768".len();
/// The longest [`ReportBandNumber`] on the wire.
const BAND_NUMBER_BYTES: usize = "999".len();

/// Everything but the users' and alerts' entries, with the longest shape of
/// every field: the longest phase, accuracy, access and system names; a
/// hard stop, an allowance line and a forecast; an attached radio with
/// every signal; a saturated capacity sample; available usage. The
/// literal leaves out every number and name, which are added after it.
const FIXED_BYTES: usize = concat!(
    "{\"at\":,\"exit\":{\"phase\":\"\",\"since\":},",
    "\"sim\":{\"cycle_starts_at\":,\"cycle_ends_at\":,\"rx_bytes\":,\"tx_bytes\":,",
    "\"accuracy\":\"\",\"warn_bytes\":,\"hard_stop_bytes\":,",
    "\"line\":{\"Allowance\":{\"bytes\":}},",
    "\"forecast\":{\"daily_average_bytes\":,\"projected_bytes\":}},",
    "\"router\":{\"Available\":{\"polled_at\":,\"radio\":{\"Attached\":{",
    "\"access\":\"\",\"band\":{\"system\":\"\",\"number\":},",
    "\"rsrp_tenths\":,\"rsrq_tenths\":,\"sinr_tenths\":,\"rssi_tenths\":}},",
    "\"temperature_c\":}},",
    "\"capacity\":{\"at\":,\"tx_bps\":,\"rx_bps\":,\"saturation\":{\"Saturated\":{\"since\":}}},",
    "\"usage\":{\"Available\":{\"through\":}},",
    "\"users\":{},\"alerts\":[]}"
)
.len()
    + 17 * NUMBER_BYTES
    + 5 * I16_BYTES
    + BAND_NUMBER_BYTES
    + ExitPhase::longest_name()
    + ReportAccuracy::longest_name()
    + ReportRadioAccess::longest_name()
    + ReportRadioSystem::longest_name();

/// One user entry with the comma that may follow it: the longest status,
/// usage and a last-seen time.
const USER_BYTES: usize = concat!(
    "\"\":{\"status\":\"\",\"cycle\":{\"uplink\":,\"downlink\":},\"last_seen\":}",
    ","
)
.len()
    + REPORT_USER_ID_BYTES
    + ReportUserStatus::longest_name()
    + 3 * NUMBER_BYTES;

/// One alert with the comma that may follow it: the longest kind and
/// severity, and the longest node name.
const ALERT_BYTES: usize = concat!(
    "{\"kind\":\"\",\"severity\":\"\",\"node\":\"\",\"active_since\":}",
    ","
)
.len()
    + MacAlertKind::longest_name()
    + ReportSeverity::longest_name()
    + MAX_NODE_NAME_BYTES
    + NUMBER_BYTES;

/// An upper bound on the length of an encoded [`MacReportV1`]: the longest
/// shape of every field, [`MAX_REPORT_USERS`] users and
/// [`MAX_REPORT_ALERTS`] alerts of the longest shape, every number at its
/// longest.
pub const MAX_MAC_REPORT_BYTES: usize =
    FIXED_BYTES + MAX_REPORT_USERS * USER_BYTES + MAX_REPORT_ALERTS * ALERT_BYTES;

/// The `PutMacReport` request around a report.
const PUT_MAC_REPORT_ENVELOPE_BYTES: usize = "{\"PutMacReport\":}".len();

/// The `MacReport` reply around a report, with the longest receipt time.
const MAC_REPORT_REPLY_ENVELOPE_BYTES: usize =
    "{\"Ok\":{\"MacReport\":{\"received_at\":,\"report\":}}}".len() + NUMBER_BYTES;

const _: () =
    assert!(PUT_MAC_REPORT_ENVELOPE_BYTES + MAX_MAC_REPORT_BYTES <= MAX_REQUEST_LINE_BYTES);
const _: () =
    assert!(MAC_REPORT_REPLY_ENVELOPE_BYTES + MAX_MAC_REPORT_BYTES <= MAX_RESPONSE_LINE_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bounds_are_the_documented_ones() {
        assert_eq!((MAX_REPORT_USERS, MAX_REPORT_ALERTS), (1024, 256));
        assert_eq!(
            (I16_BYTES, BAND_NUMBER_BYTES),
            (
                i16::MIN.to_string().len(),
                ReportBandNumber::MAX.to_string().len()
            )
        );
        assert_eq!(ExitPhase::longest_name(), "Preflight".len());
        assert_eq!(ReportAccuracy::longest_name(), "LowerBound".len());
        assert_eq!(ReportRadioAccess::longest_name(), "NrNsa".len());
        assert_eq!(ReportRadioSystem::longest_name(), "Lte".len());
        assert_eq!(ReportUserStatus::longest_name(), "RevokePending".len());
        assert_eq!(ReportSeverity::longest_name(), "Critical".len());
        assert_eq!(
            MacAlertKind::longest_name(),
            "AccountingCanaryMissing".len()
        );
        // Pinned so that a change to the bound is deliberate; it is far
        // below both frame limits (1 MiB).
        assert_eq!(MAX_MAC_REPORT_BYTES, 178_874);
    }

    /// A band number is 1..=999, every `u16` checked, on decode too.
    #[test]
    fn band_numbers_are_1_to_999() {
        for number in 0..=u16::MAX {
            let checked = ReportBandNumber::new(number);
            if (1..=999).contains(&number) {
                assert_eq!(checked.map(ReportBandNumber::get), Ok(number));
            } else {
                assert_eq!(checked, Err(ValueError::ReportBandNumber { number }));
            }
        }
        assert_eq!(serde_json::to_string(&ReportBandNumber(78)).unwrap(), "78");
        assert_eq!(
            serde_json::from_str::<ReportBandNumber>("78").unwrap(),
            ReportBandNumber(78)
        );
        for bad in ["0", "1000", "1007", "65535", "-1", "\"78\""] {
            assert!(
                serde_json::from_str::<ReportBandNumber>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn report_user_ids_are_ten_base32_characters() {
        for ok in ["fxuseraaab", "abcdefgh23", "zzzzzzzzzz", "2222277777"] {
            assert_eq!(ReportUserId::new(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            "fxuseraaa",
            "fxuseraaabb",
            "fxuseraaa1",
            "fxuseraaa8",
            "Fxuseraaab",
            "fxuser aab",
            "fxuser.aab",
            "356938035643809",
            "probe",
        ] {
            assert_eq!(
                ReportUserId::new(bad),
                Err(ValueError::ReportUserId),
                "{bad:?}"
            );
        }
    }
}
