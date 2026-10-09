// SPDX-License-Identifier: GPL-3.0-or-later

//! The console core's typed errors (design §14). Each enum has a fieldless
//! `Kind` companion declared with the model's `kinds!` macro, so its `ALL`
//! list cannot fall out of step with the variants, and every variant is
//! produced by a test (`cargo xtask kinds-coverage`).
//!
//! No error here carries a label, a secret or an address of a user; the
//! values they name are dates, instants, byte counts, node ids and the
//! opaque accounting names the VPS already holds.

use mooring_agent_proto::{StatsEmail, ValueError};
use mooring_model::{CalendarDate, ModelError, NodeId, UnixTime, UserId, kinds};
use serde::{Deserialize, Serialize};

use crate::alert::AlertKey;
use crate::router::{RouterTextField, SignalMetric};

/// The SIM forecast cannot be computed from its inputs
/// ([`crate::forecast::SimForecast::project`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForecastError {
    /// There are no daily bins: a forecast is never projected from nothing.
    #[error("no daily SIM bins: there is nothing to project from")]
    NoBins,
    /// The reading is at the very start of the cycle, so no time has passed
    /// to measure a rate over.
    #[error("no time has passed in the billing cycle at {as_of}")]
    NothingElapsed {
        /// The reading's time.
        as_of: UnixTime,
    },
    /// A bin is for a day outside the cycle's elapsed days.
    #[error("the bin for {date} is outside the elapsed days {first} to {last} of the cycle")]
    BinOutsideCycle {
        /// The bin's day.
        date: CalendarDate,
        /// The cycle's first day.
        first: CalendarDate,
        /// The last day with time elapsed before the reading.
        last: CalendarDate,
    },
    /// The bins are not in increasing date order, or a day is repeated.
    #[error("the bin for {date} repeats or precedes an earlier bin")]
    BinsOutOfOrder {
        /// The bin out of order.
        date: CalendarDate,
    },
    /// An elapsed day of the cycle has no bin; a missing day is never read
    /// as zero.
    #[error("the bin for {date} is missing")]
    MissingDay {
        /// The first day without a bin.
        date: CalendarDate,
    },
    /// The bytes do not fit a 64-bit counter.
    #[error("the SIM byte counts overflow a 64-bit counter")]
    CounterOverflow,
    /// The billing cycle could not be placed on the calendar.
    #[error(transparent)]
    Model(#[from] ModelError),
}

kinds! {
    /// The kind of a [`ForecastError`]. The status stream carries it when
    /// no forecast can be shown, so it is serialised as its name.
    #[derive(Serialize, Deserialize)]
    pub enum ForecastErrorKind {
        /// See [`ForecastError::NoBins`].
        NoBins,
        /// See [`ForecastError::NothingElapsed`].
        NothingElapsed,
        /// See [`ForecastError::BinOutsideCycle`].
        BinOutsideCycle,
        /// See [`ForecastError::BinsOutOfOrder`].
        BinsOutOfOrder,
        /// See [`ForecastError::MissingDay`].
        MissingDay,
        /// See [`ForecastError::CounterOverflow`].
        CounterOverflow,
        /// See [`ForecastError::Model`].
        Model,
    }
}

impl ForecastError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> ForecastErrorKind {
        match self {
            Self::NoBins => ForecastErrorKind::NoBins,
            Self::NothingElapsed { .. } => ForecastErrorKind::NothingElapsed,
            Self::BinOutsideCycle { .. } => ForecastErrorKind::BinOutsideCycle,
            Self::BinsOutOfOrder { .. } => ForecastErrorKind::BinsOutOfOrder,
            Self::MissingDay { .. } => ForecastErrorKind::MissingDay,
            Self::CounterOverflow => ForecastErrorKind::CounterOverflow,
            Self::Model(_) => ForecastErrorKind::Model,
        }
    }
}

/// A capacity sample cannot be taken in
/// ([`crate::capacity::CapacityMonitor::observe`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapacityError {
    /// The sample is not later than the previous one, so how long a
    /// condition held cannot be measured.
    #[error("the capacity sample at {at} is not after the previous one at {previous}")]
    SampleOutOfOrder {
        /// The previous sample's time.
        previous: UnixTime,
        /// This sample's time.
        at: UnixTime,
    },
}

kinds! {
    /// The kind of a [`CapacityError`].
    pub enum CapacityErrorKind {
        /// See [`CapacityError::SampleOutOfOrder`].
        SampleOutOfOrder,
    }
}

impl CapacityError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> CapacityErrorKind {
        match self {
            Self::SampleOutOfOrder { .. } => CapacityErrorKind::SampleOutOfOrder,
        }
    }
}

/// Usage cannot be aggregated from the ledgers ([`crate::usage`]). Every
/// variant refuses to report a figure that would otherwise silently miss
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    /// A node's series do not follow on from its lifetime base and from one
    /// another without a gap or an overlap.
    #[error(
        "{node}'s usage ledger has a gap or overlap: expected a series from {expected}, found one from {found}"
    )]
    LedgerGap {
        /// The node.
        node: NodeId,
        /// Where the next series had to start.
        expected: UnixTime,
        /// Where it starts.
        found: UnixTime,
    },
    /// Two ledgers are for the same node.
    #[error("two usage ledgers are for {node}")]
    DuplicateLedger {
        /// The node.
        node: NodeId,
    },
    /// A node that may have counted traffic (any node past `Planned`,
    /// retired ones included) has no ledger, so its users' bytes would read
    /// as zero.
    #[error("{node} may have counted traffic, but no usage ledger is given for it")]
    MissingLedger {
        /// The node.
        node: NodeId,
    },
    /// A ledger is for a node the deployment does not hold.
    #[error("a usage ledger is for {node}, which the deployment does not hold")]
    LedgerForUnknownNode {
        /// The node.
        node: NodeId,
    },
    /// A period starts before a ledger's lifetime base, whose earlier bins
    /// are folded into totals that cannot be split by period.
    #[error(
        "{node}'s usage ledger starts at {ledger_from}, after the period starting {period_start}"
    )]
    PeriodBeforeLedger {
        /// The node.
        node: NodeId,
        /// The earliest period start.
        period_start: UnixTime,
        /// The start of the ledger's bins.
        ledger_from: UnixTime,
    },
    /// An open ledger does not reach the report's end, so its node's
    /// latest bytes are unknown.
    #[error("{node}'s usage is recorded to {covered_to}, before {through}")]
    NotCoveredThrough {
        /// The node.
        node: NodeId,
        /// Where its ledger ends.
        covered_to: UnixTime,
        /// The report's end.
        through: UnixTime,
    },
    /// A bin starts before the report's end and finishes after it, so its
    /// bytes cannot be split at the end.
    #[error("{node}'s usage bin at {bin_start} straddles the report's end {through}")]
    BinStraddlesThrough {
        /// The node.
        node: NodeId,
        /// The bin's start.
        bin_start: UnixTime,
        /// The report's end.
        through: UnixTime,
    },
    /// An accounting email names a principal that is not a model user id;
    /// no rendered configuration produces one.
    #[error("{node} accounts traffic for {email}, which names no Mooring user id")]
    PrincipalNotAUser {
        /// The node.
        node: NodeId,
        /// The accounting email.
        email: StatsEmail,
    },
    /// An accounting email names a user the deployment does not hold.
    #[error("{node} accounts traffic for user {user}, which the deployment does not hold")]
    UnknownUser {
        /// The node.
        node: NodeId,
        /// The user id.
        user: UserId,
    },
    /// A total does not fit a 64-bit counter.
    #[error("a usage total overflows a 64-bit counter")]
    CounterOverflow,
    /// The periods could not be placed on the calendar.
    #[error(transparent)]
    Model(#[from] ModelError),
}

kinds! {
    /// The kind of a [`UsageError`]. The status stream carries it when no
    /// usage can be shown, so it is serialised as its name.
    #[derive(Serialize, Deserialize)]
    pub enum UsageErrorKind {
        /// See [`UsageError::LedgerGap`].
        LedgerGap,
        /// See [`UsageError::DuplicateLedger`].
        DuplicateLedger,
        /// See [`UsageError::MissingLedger`].
        MissingLedger,
        /// See [`UsageError::LedgerForUnknownNode`].
        LedgerForUnknownNode,
        /// See [`UsageError::PeriodBeforeLedger`].
        PeriodBeforeLedger,
        /// See [`UsageError::NotCoveredThrough`].
        NotCoveredThrough,
        /// See [`UsageError::BinStraddlesThrough`].
        BinStraddlesThrough,
        /// See [`UsageError::PrincipalNotAUser`].
        PrincipalNotAUser,
        /// See [`UsageError::UnknownUser`].
        UnknownUser,
        /// See [`UsageError::CounterOverflow`].
        CounterOverflow,
        /// See [`UsageError::Model`].
        Model,
    }
}

impl UsageError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> UsageErrorKind {
        match self {
            Self::LedgerGap { .. } => UsageErrorKind::LedgerGap,
            Self::DuplicateLedger { .. } => UsageErrorKind::DuplicateLedger,
            Self::MissingLedger { .. } => UsageErrorKind::MissingLedger,
            Self::LedgerForUnknownNode { .. } => UsageErrorKind::LedgerForUnknownNode,
            Self::PeriodBeforeLedger { .. } => UsageErrorKind::PeriodBeforeLedger,
            Self::NotCoveredThrough { .. } => UsageErrorKind::NotCoveredThrough,
            Self::BinStraddlesThrough { .. } => UsageErrorKind::BinStraddlesThrough,
            Self::PrincipalNotAUser { .. } => UsageErrorKind::PrincipalNotAUser,
            Self::UnknownUser { .. } => UsageErrorKind::UnknownUser,
            Self::CounterOverflow => UsageErrorKind::CounterOverflow,
            Self::Model(_) => UsageErrorKind::Model,
        }
    }
}

/// A usage figure a decoded status states contradicts the figures it is
/// derived from ([`crate::usage::UserUsage`], [`crate::share`]): a decoded
/// document is checked as the aggregation built it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FigureError {
    /// A share is above the whole, 10,000 basis points.
    #[error("a share of {points} basis points is above the whole of 10000")]
    ShareAboveWhole {
        /// The share.
        points: u16,
    },
    /// A set of shares does not add up to the whole.
    #[error("shares adding up to {sum} basis points are not the whole of 10000")]
    SharesNotWhole {
        /// What they add up to.
        sum: u32,
    },
    /// The cycle's split by node or by protocol does not add up to the
    /// cycle.
    #[error("the cycle's split by node or by protocol does not add up to the cycle")]
    SplitMismatch,
    /// The served bytes or the shares differ from those the cycle's
    /// figures give.
    #[error("the served bytes or the shares differ from those the cycle's figures give")]
    DerivedMismatch,
}

kinds! {
    /// The kind of a [`FigureError`].
    pub enum FigureErrorKind {
        /// See [`FigureError::ShareAboveWhole`].
        ShareAboveWhole,
        /// See [`FigureError::SharesNotWhole`].
        SharesNotWhole,
        /// See [`FigureError::SplitMismatch`].
        SplitMismatch,
        /// See [`FigureError::DerivedMismatch`].
        DerivedMismatch,
    }
}

impl FigureError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> FigureErrorKind {
        match self {
            Self::ShareAboveWhole { .. } => FigureErrorKind::ShareAboveWhole,
            Self::SharesNotWhole { .. } => FigureErrorKind::SharesNotWhole,
            Self::SplitMismatch => FigureErrorKind::SplitMismatch,
            Self::DerivedMismatch => FigureErrorKind::DerivedMismatch,
        }
    }
}

/// The alert machine refuses an observation
/// ([`crate::alert::AlertMachine::step`]); its state is left unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AlertError {
    /// The observation is earlier than the previous one, so debounce and
    /// reminder intervals cannot be measured.
    #[error("the alert observation at {now} is before the previous one at {previous}")]
    ClockWentBackwards {
        /// The previous observation's time.
        previous: UnixTime,
        /// This observation's time.
        now: UnixTime,
    },
    /// Two active conditions share a key, so which payload is current is
    /// ambiguous.
    #[error("two active conditions share the key {key}")]
    DuplicateCondition {
        /// The shared key.
        key: AlertKey,
    },
}

kinds! {
    /// The kind of an [`AlertError`].
    pub enum AlertErrorKind {
        /// See [`AlertError::ClockWentBackwards`].
        ClockWentBackwards,
        /// See [`AlertError::DuplicateCondition`].
        DuplicateCondition,
    }
}

impl AlertError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> AlertErrorKind {
        match self {
            Self::ClockWentBackwards { .. } => AlertErrorKind::ClockWentBackwards,
            Self::DuplicateCondition { .. } => AlertErrorKind::DuplicateCondition,
        }
    }
}

/// The quota and expiry evaluation refuses its inputs
/// ([`crate::policy::evaluate`], [`crate::policy::automatic_quota`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The usage covers another billing cycle than the one `now` is in.
    #[error(
        "the usage covers the cycle from {usage_cycle}, but now is in the cycle from {current_cycle}"
    )]
    UsageForOtherCycle {
        /// The first day of the usage's cycle.
        usage_cycle: CalendarDate,
        /// The first day of the current cycle.
        current_cycle: CalendarDate,
    },
    /// The usage runs past `now`.
    #[error("the usage runs to {through}, after now ({now})")]
    UsageAfterNow {
        /// The usage's end.
        through: UnixTime,
        /// The evaluation time.
        now: UnixTime,
    },
    /// A user with a quota (their own or the automatic one) has no usage
    /// row.
    #[error("user {user} has a quota but no usage")]
    UsageMissing {
        /// The user.
        user: UserId,
    },
    /// The automatic quota rounds down to zero served bytes: the budget is
    /// too small for the users sharing it, and a zero quota is never read
    /// as no quota.
    #[error(
        "the automatic quota from a budget of {budget_bytes} SIM bytes shared by {sharing} users rounds down to zero"
    )]
    AutomaticQuotaZero {
        /// The cycle's SIM budget.
        budget_bytes: u64,
        /// The users sharing it, N: those active now and those suspended
        /// for quota during the current cycle.
        sharing: usize,
    },
    /// A user's suspension for quota was made after `now`. The Mac's clock
    /// wrote that instant and gives `now`, so it stepped back since, or
    /// the record is corrupt; whether the suspension holds in the current
    /// cycle cannot be told, and it is never read as held or lapsed.
    #[error("user {user} was suspended for quota at {since}, after now ({now})")]
    QuotaSuspensionAfterNow {
        /// The user.
        user: UserId,
        /// When the suspension was made (`UserStatus::Suspended::since`).
        since: UnixTime,
        /// The evaluation time.
        now: UnixTime,
    },
    /// The current cycle could not be placed on the calendar.
    #[error(transparent)]
    Model(#[from] ModelError),
}

kinds! {
    /// The kind of a [`PolicyError`].
    pub enum PolicyErrorKind {
        /// See [`PolicyError::UsageForOtherCycle`].
        UsageForOtherCycle,
        /// See [`PolicyError::UsageAfterNow`].
        UsageAfterNow,
        /// See [`PolicyError::UsageMissing`].
        UsageMissing,
        /// See [`PolicyError::AutomaticQuotaZero`].
        AutomaticQuotaZero,
        /// See [`PolicyError::QuotaSuspensionAfterNow`].
        QuotaSuspensionAfterNow,
        /// See [`PolicyError::Model`].
        Model,
    }
}

impl PolicyError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> PolicyErrorKind {
        match self {
            Self::UsageForOtherCycle { .. } => PolicyErrorKind::UsageForOtherCycle,
            Self::UsageAfterNow { .. } => PolicyErrorKind::UsageAfterNow,
            Self::UsageMissing { .. } => PolicyErrorKind::UsageMissing,
            Self::AutomaticQuotaZero { .. } => PolicyErrorKind::AutomaticQuotaZero,
            Self::QuotaSuspensionAfterNow { .. } => PolicyErrorKind::QuotaSuspensionAfterNow,
            Self::Model(_) => PolicyErrorKind::Model,
        }
    }
}

/// A router value is outside what a device can report
/// ([`crate::router`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouterValueError {
    /// A signal reading is outside its plausible range.
    #[error("{metric} of {tenths} tenths is outside its plausible range")]
    SignalOutOfRange {
        /// Which reading.
        metric: SignalMetric,
        /// The value in tenths of a dB or dBm.
        tenths: i16,
    },
    /// The temperature is outside -40..=125 °C.
    #[error("a router temperature of {celsius} °C is outside -40..=125")]
    TemperatureOutOfRange {
        /// The temperature.
        celsius: i16,
    },
    /// The battery charge is above 100%.
    #[error("a battery charge of {percent}% is above 100")]
    BatteryPercentOutOfRange {
        /// The charge.
        percent: u8,
    },
    /// A text field is empty, too long or not printable; the text is not
    /// echoed.
    #[error("the router's {field} text is empty, too long or not printable")]
    InvalidText {
        /// Which text.
        field: RouterTextField,
    },
}

kinds! {
    /// The kind of a [`RouterValueError`].
    pub enum RouterValueErrorKind {
        /// See [`RouterValueError::SignalOutOfRange`].
        SignalOutOfRange,
        /// See [`RouterValueError::TemperatureOutOfRange`].
        TemperatureOutOfRange,
        /// See [`RouterValueError::BatteryPercentOutOfRange`].
        BatteryPercentOutOfRange,
        /// See [`RouterValueError::InvalidText`].
        InvalidText,
    }
}

impl RouterValueError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> RouterValueErrorKind {
        match self {
            Self::SignalOutOfRange { .. } => RouterValueErrorKind::SignalOutOfRange,
            Self::TemperatureOutOfRange { .. } => RouterValueErrorKind::TemperatureOutOfRange,
            Self::BatteryPercentOutOfRange { .. } => RouterValueErrorKind::BatteryPercentOutOfRange,
            Self::InvalidText { .. } => RouterValueErrorKind::InvalidText,
        }
    }
}

/// A [`crate::status::MacStatusV1`] is inconsistent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    /// The document is not version 1.
    #[error("a MacStatusV1 document has version 1, not {found}")]
    UnsupportedVersion {
        /// The version found.
        found: u32,
    },
    /// A user row or an alert names a node the status has no row for.
    #[error("the status refers to node {node}, which has no node row")]
    UnknownNode {
        /// The node.
        node: NodeId,
    },
    /// A user row carries usage while the status has no usage report, or
    /// lacks usage while it has one.
    #[error("user {user}'s usage does not match the status's usage report")]
    UsageMismatch {
        /// The user.
        user: UserId,
    },
    /// The open alerts are not in strictly increasing key order (a key is
    /// repeated or out of place).
    #[error("the open alert {key} repeats or precedes an earlier alert")]
    AlertsNotOrdered {
        /// The alert out of order.
        key: AlertKey,
    },
}

kinds! {
    /// The kind of a [`StatusError`].
    pub enum StatusErrorKind {
        /// See [`StatusError::UnsupportedVersion`].
        UnsupportedVersion,
        /// See [`StatusError::UnknownNode`].
        UnknownNode,
        /// See [`StatusError::UsageMismatch`].
        UsageMismatch,
        /// See [`StatusError::AlertsNotOrdered`].
        AlertsNotOrdered,
    }
}

impl StatusError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> StatusErrorKind {
        match self {
            Self::UnsupportedVersion { .. } => StatusErrorKind::UnsupportedVersion,
            Self::UnknownNode { .. } => StatusErrorKind::UnknownNode,
            Self::UsageMismatch { .. } => StatusErrorKind::UsageMismatch,
            Self::AlertsNotOrdered { .. } => StatusErrorKind::AlertsNotOrdered,
        }
    }
}

/// A notice cannot be rendered ([`crate::notify`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotifyError {
    /// A rendered title or body breaks the notice grammar
    /// (agent-proto's `NoticeTitle` or `NoticeBody`): a renderer bug,
    /// surfaced rather than sent. The text is not echoed.
    #[error("a rendered notice breaks the notice grammar: {0}")]
    Text(#[from] ValueError),
    /// A time in the notice lies outside the calendar (after 9999).
    #[error(transparent)]
    Model(#[from] ModelError),
}

kinds! {
    /// The kind of a [`NotifyError`].
    pub enum NotifyErrorKind {
        /// See [`NotifyError::Text`].
        Text,
        /// See [`NotifyError::Model`].
        Model,
    }
}

impl NotifyError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> NotifyErrorKind {
        match self {
            Self::Text(_) => NotifyErrorKind::Text,
            Self::Model(_) => NotifyErrorKind::Model,
        }
    }
}

/// A status cannot be projected into the remote viewer's report
/// ([`crate::report::project`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    /// The projection breaks a rule of the report (agent-proto's
    /// `MacReportV1`): more users or alerts than a report carries, or an
    /// id or band number outside the wire grammar.
    #[error("the status does not fit a report: {0}")]
    Wire(#[from] ValueError),
}

kinds! {
    /// The kind of a [`ReportError`].
    pub enum ReportErrorKind {
        /// See [`ReportError::Wire`].
        Wire,
    }
}

impl ReportError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> ReportErrorKind {
        match self {
            Self::Wire(_) => ReportErrorKind::Wire,
        }
    }
}
