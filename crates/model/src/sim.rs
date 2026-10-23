// SPDX-License-Identifier: GPL-3.0-or-later

//! The SIM line (design §7, §10.1 step 5): the plan record, the rule that
//! starts each billing cycle, and the thresholds the exit's SIM meter acts
//! on.
//!
//! [`SimThresholds`] holds the thresholds and checks them against the
//! plan's line, when the plan has one (a fair-use line, or a capped plan's
//! allowance): the warning comes before any hard stop, both stay below the
//! line, and running past a fair-use line is only ever an explicit choice
//! ([`StopPolicy`]). A plan without a line (SMARTY's Unlimited) and an
//! unrecorded plan bound nothing, so they need a hard stop. [`SimPolicy`]
//! adds the cycle rule and the plan record the line comes from, and checks
//! a hard stop against a rolling fair-use line over every cycle one window
//! of the line can overlap.
//!
//! Sources for SMARTY, the first exit line (decision F1, 2026-10-08; the
//! user dropped it on 2026-10-17 after M2):
//!
//! - [SMARTY-TC]: SMARTY Terms and Conditions V33, 30 July 2026,
//!   <https://sundaecdn.blob.core.windows.net/files/SMARTY-Terms-And-Conditions.pdf>;
//! - [SMARTY-PG]: SMARTY Price Guide V42, 25 August 2026,
//!   <https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf>;
//! - help-centre articles at `http://help.smarty.co.uk/en/articles/<id>`,
//!   with the page date in parentheses.
//!
//! All were read on 2026-10-08.
//!
//! Source for 1pMobile, the exit line since (F1, 2026-10-23):
//!
//! - [1PM-TC]: 1pMobile Terms and Conditions, updated 24 July 2026,
//!   <https://www.1pmobile.com/terms-and-conditions>, read on 2026-10-23.

use std::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};

use crate::date::{CalendarDate, days_in_month};
use crate::error::ModelError;
use crate::target::EvidenceUrl;

/// The SIM warning threshold the pilot runs with, 200 GB in decimal bytes,
/// and the value `exit init` records: decision F2 (2026-10-08: 240 GB on
/// SMARTY), lowered with the stop for 1pMobile on 2026-10-23, pending the
/// operator's confirmation before `exit init`.
pub const PILOT_SIM_WARN_BYTES: u64 = 200_000_000_000;

/// The SIM hard stop the pilot runs with, 240 GB in decimal bytes, and the
/// value `exit init` records: decision F2 (2026-10-08: 300 GB on SMARTY),
/// lowered on 2026-10-23 so that two cycles' stops stay below 1pMobile's
/// 500 GB per rolling 30 days ([`SimPolicy`]), pending the operator's
/// confirmation before `exit init`. At the stop the users lose service for
/// the rest of the cycle. It is about 114e9 served bytes at design §3's
/// estimate of about 2.1 SIM bytes per served byte
/// ([`crate::quota::SimFactor::SAME_AS_EXIT_ESTIMATE`]).
pub const PILOT_SIM_HARD_STOP_BYTES: u64 = 240_000_000_000;

// The pilot thresholds are ordered, and two cycles of them stay below
// 1pMobile's rolling line.
const _: () = assert!(0 < PILOT_SIM_WARN_BYTES && PILOT_SIM_WARN_BYTES < PILOT_SIM_HARD_STOP_BYTES);
const _: () = assert!(2 * PILOT_SIM_HARD_STOP_BYTES < ONE_P_MOBILE_FAIR_USE_BYTES.get());

/// 1pMobile's fair-use line, 500 GB in decimal bytes per rolling 30 days:
/// "we consider 30-day rolling data usage above 500GB to be non-personal
/// use" ([1PM-TC], Fair Usage Policy). Past it the carrier may charge,
/// move the line to a capped tariff, deprioritise it, throttle it (128 kbps
/// is the terms' example) or suspend the SIM.
pub const ONE_P_MOBILE_FAIR_USE_BYTES: NonZeroU64 = match NonZeroU64::new(500_000_000_000) {
    Some(bytes) => bytes,
    None => panic!("1pMobile's line is not zero"),
};

/// 1pMobile's Boosts run, and are charged, "on a 30-day rolling basis"
/// ([1PM-TC], Definitions), and its fair-use line counts 30-day rolling
/// usage.
pub const ONE_P_MOBILE_PERIOD_DAYS: u16 = 30;

/// The carrier whose SIM is in the M7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// SMARTY: Hutchison 3G UK Limited trading as SMARTY ([SMARTY-TC] 1.1),
    /// on Three's network, and since August 2025 on combined Three and
    /// Vodafone coverage, automatically and with the same SIM (help
    /// 10235435, 5 May 2026). The first exit line (decision F1,
    /// 2026-10-08), dropped on 2026-10-17.
    Smarty,
    /// 1pMobile: Telecommunications Management Limited trading as
    /// 1pMobile, with its Data Boosts agreed with Utility Warehouse Limited
    /// ([1PM-TC], opening paragraph); on EE's network when read, though its
    /// terms let it change networks without notice ([1PM-TC], The
    /// Services). The exit line since 2026-10-23 (F1).
    #[serde(rename = "1pmobile")]
    OnePMobile,
}

impl Carrier {
    /// The carrier's name as it writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Smarty => "SMARTY",
            Self::OnePMobile => "1pMobile",
        }
    }
}

/// What a capped plan does once its allowance is used up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AfterAllowance {
    /// Data continues at a throttled rate.
    Throttled {
        /// The throttled rate, in kbit/s.
        kbps: NonZeroU32,
    },
    /// Data stops until the next cycle (or until more is bought).
    Blocked,
}

/// How much data the plan includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanKind {
    /// Unlimited data with no fair-use line and no deprioritisation step.
    /// SMARTY's Unlimited plans publish no numeric fair-use volume and no
    /// speed restriction ([SMARTY-PG] p11; help 1155178, "no shaping or
    /// throttling", 27 Apr 2023). The carrier may still contact the
    /// customer about use it judges excessive, then restrict, suspend or
    /// end the line ([SMARTY-TC] 5.5(d), 5.15, 8.1(b), 9.4(d)), so the
    /// operator's hard stop is the only volume guard.
    Unlimited,
    /// Unlimited data under a fair-use line, past which the carrier may
    /// deprioritise the line.
    UnlimitedFairUse {
        /// The fair-use line per window, in bytes.
        fair_use_bytes: NonZeroU64,
        /// The span the line counts over.
        window: FairUseWindow,
    },
    /// A data allowance per billing cycle.
    Capped {
        /// The allowance per billing cycle, in bytes.
        allowance_bytes: NonZeroU64,
        /// What happens past the allowance.
        after: AfterAllowance,
    },
}

/// The span a fair-use line counts over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FairUseWindow {
    /// Each billing cycle.
    BillingCycle,
    /// Every span of `days` consecutive days, across cycle boundaries:
    /// 1pMobile's 30-day rolling usage ([`ONE_P_MOBILE_FAIR_USE_BYTES`]).
    Rolling {
        /// The span, in days.
        days: PeriodDays,
    },
}

impl PlanKind {
    /// The plan's line: the fair-use line or the allowance; `None` for an
    /// unlimited plan without a fair-use line.
    #[must_use]
    pub const fn line(&self) -> Option<PlanLine> {
        match self {
            Self::Unlimited => None,
            Self::UnlimitedFairUse { fair_use_bytes, .. } => Some(PlanLine {
                kind: PlanLineKind::FairUse,
                bytes: *fair_use_bytes,
            }),
            Self::Capped {
                allowance_bytes, ..
            } => Some(PlanLine {
                kind: PlanLineKind::Allowance,
                bytes: *allowance_bytes,
            }),
        }
    }
}

/// Which line a plan draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanLineKind {
    /// An unlimited plan's fair-use line ([`PlanKind::UnlimitedFairUse`]).
    FairUse,
    /// A capped plan's allowance ([`PlanKind::Capped`]).
    Allowance,
}

/// A recorded plan's line: per billing cycle, or for a rolling fair-use
/// line per window, which [`SimPolicy`] checks across the cycles a window
/// overlaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanLine {
    /// Which line.
    pub kind: PlanLineKind,
    /// The line, in bytes.
    pub bytes: NonZeroU64,
}

/// Where a recorded fact comes from: a document and the date it carries
/// (its issue or last-update date), so a later revision at the same URL is
/// told apart.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    /// The document; a bounded printable `https://` URL.
    pub url: EvidenceUrl,
    /// The date the document carries.
    pub dated: CalendarDate,
}

/// The SIM line's plan, as the operator recorded it from the carrier's
/// order confirmation and plan terms.
///
/// The decided line (F1, 2026-10-23) is 1pMobile's Unlimited Data Boost,
/// [`SimPlan::one_p_mobile_unlimited`]. The first one, SMARTY Unlimited Data
/// Only, was [`Carrier::Smarty`], [`PlanKind::Unlimited`],
/// `speed_cap_mbps: None` ([SMARTY-PG] p11), with [SMARTY-PG] as its terms.
/// SMARTY counts usage in binary units per full MB, re-sent packets included
/// ([SMARTY-PG] p23); that matters only when reconciling against SMARTY's
/// own usage view, because every threshold here is in decimal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimPlan {
    /// The carrier.
    pub carrier: Carrier,
    /// The data the plan includes.
    pub kind: PlanKind,
    /// The plan's speed cap in Mbit/s; `None` when the terms state none.
    /// The key is required: a lost key is a decode error.
    #[serde(deserialize_with = "Option::deserialize")]
    pub speed_cap_mbps: Option<NonZeroU32>,
    /// The plan terms the record was taken from.
    pub terms: EvidenceRef,
}

impl SimPlan {
    /// 1pMobile's Unlimited Data Boost, the decided line (F1, 2026-10-23):
    /// unlimited data under [`ONE_P_MOBILE_FAIR_USE_BYTES`] per rolling
    /// [`ONE_P_MOBILE_PERIOD_DAYS`] days, with no speed cap stated, recorded
    /// from [1PM-TC].
    pub fn one_p_mobile_unlimited() -> Result<Self, ModelError> {
        Ok(Self {
            carrier: Carrier::OnePMobile,
            kind: PlanKind::UnlimitedFairUse {
                fair_use_bytes: ONE_P_MOBILE_FAIR_USE_BYTES,
                window: FairUseWindow::Rolling {
                    days: PeriodDays::new(ONE_P_MOBILE_PERIOD_DAYS)?,
                },
            },
            speed_cap_mbps: None,
            terms: EvidenceRef {
                url: EvidenceUrl::parse("https://www.1pmobile.com/terms-and-conditions")?,
                dated: CalendarDate::new(2026, 7, 24)?,
            },
        })
    }
}

/// The SIM bill day of a monthly cycle rule ([`CycleRule::Monthly`]),
/// 1..=31: each billing cycle starts on this day of the month.
///
/// SMARTY bills upfront each month: the cycle starts at SIM activation and
/// renews on the same day each month, the Renewal Date ([SMARTY-TC] 5.20,
/// 5.21; help 952716, 4227332). A failed auto-renewal that is retried and
/// taken later moves the cycle start to the day payment was taken
/// ([SMARTY-PG] p3); the operator then records the new bill day. Activating
/// the SIM on a day up to the 28th keeps every month's boundary on the bill
/// day.
///
/// **Month-end clamp (inference; verify at the first short month).** A
/// month without the bill day starts its cycle on its last day: bill day 31
/// starts the April cycle on 30 April and the February cycle on 28 (in a
/// leap year 29) February, and bill days 29 and 30 start the February cycle
/// on 28 February in a common year. SMARTY states that a Renewal Date on the
/// 29th to 31st falls earlier in a shorter month, but not whether it returns
/// to that day in a longer month; this clamp assumes it does. If SMARTY
/// keeps the earlier day instead, Mooring's boundary differs from SMARTY's
/// by up to three days after a short month, so check the first short-month
/// renewal and keep reconciling against SMARTY's usage view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct BillDay(u8);

impl BillDay {
    /// Accepts 1..=31.
    pub fn new(day: u8) -> Result<Self, ModelError> {
        if (1..=31).contains(&day) {
            Ok(Self(day))
        } else {
            Err(ModelError::InvalidBillDay { day })
        }
    }

    /// The bill day.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The day the cycle starts in `month` of `year`: the bill day, or the
    /// month's last day when the month is shorter (the clamp rule above).
    pub fn boundary_in(self, year: u16, month: u8) -> Result<CalendarDate, ModelError> {
        CalendarDate::new(year, month, self.0.min(days_in_month(year, month)))
    }

    /// The start of the billing cycle that contains `on`: the latest cycle
    /// boundary on or before it. `InvalidDate` if that boundary would fall
    /// before 1970.
    pub fn cycle_start(self, on: CalendarDate) -> Result<CalendarDate, ModelError> {
        let this_month = self.boundary_in(on.year(), on.month())?;
        if on >= this_month {
            return Ok(this_month);
        }
        let (year, month) = if on.month() == 1 {
            (on.year().checked_sub(1).ok_or(ModelError::InvalidDate)?, 12)
        } else {
            (on.year(), on.month() - 1)
        };
        self.boundary_in(year, month)
    }

    /// The start of the cycle after the one that contains `on`: the
    /// earliest cycle boundary after it. `InvalidDate` if that boundary
    /// would fall after 9999.
    pub fn next_cycle_start(self, on: CalendarDate) -> Result<CalendarDate, ModelError> {
        let this_month = self.boundary_in(on.year(), on.month())?;
        if on < this_month {
            return Ok(this_month);
        }
        let (year, month) = if on.month() == 12 {
            (on.year().checked_add(1).ok_or(ModelError::InvalidDate)?, 1)
        } else {
            (on.year(), on.month() + 1)
        };
        self.boundary_in(year, month)
    }
}

impl TryFrom<u8> for BillDay {
    type Error = ModelError;

    fn try_from(day: u8) -> Result<Self, Self::Error> {
        Self::new(day)
    }
}

impl From<BillDay> for u8 {
    fn from(day: BillDay) -> Self {
        day.0
    }
}

/// A number of days, 1..=366: the length of a fixed billing cycle or of a
/// rolling fair-use window (1pMobile: 30 for both).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct PeriodDays(u16);

impl PeriodDays {
    /// Accepts 1..=366.
    pub fn new(days: u16) -> Result<Self, ModelError> {
        if (1..=366).contains(&days) {
            Ok(Self(days))
        } else {
            Err(ModelError::InvalidPeriodDays { days })
        }
    }

    /// The number of days.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for PeriodDays {
    type Error = ModelError;

    fn try_from(days: u16) -> Result<Self, Self::Error> {
        Self::new(days)
    }
}

impl From<PeriodDays> for u16 {
    fn from(days: PeriodDays) -> Self {
        days.0
    }
}

/// How the SIM's billing cycles fall. Every cycle starts at UTC midnight
/// of its first day (`daemon-core`'s `BillingCycle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CycleRule {
    /// A cycle starts on the bill day of every month: SMARTY's Renewal
    /// Date ([`BillDay`]).
    Monthly {
        /// The day of the month.
        bill_day: BillDay,
    },
    /// Back-to-back cycles of `days` days, one of which starts on `anchor`:
    /// 1pMobile's Boosts, charged "on a 30-day rolling basis" ([1PM-TC],
    /// Definitions), from the day the Boost was bought. A Boost that lapses
    /// and is bought again later starts a new run of cycles; the operator
    /// then records the new anchor.
    FixedDays {
        /// The length of every cycle.
        days: PeriodDays,
        /// The first day of one cycle.
        anchor: CalendarDate,
    },
}

impl CycleRule {
    /// The start of the cycle that contains `on`: the latest cycle start on
    /// or before it. `InvalidDate` if that start would fall before 1970.
    pub fn cycle_start(self, on: CalendarDate) -> Result<CalendarDate, ModelError> {
        match self {
            Self::Monthly { bill_day } => bill_day.cycle_start(on),
            Self::FixedDays { days, anchor } => {
                let length = i64::from(days.get());
                let offset =
                    i64::from(on.days_since_epoch()) - i64::from(anchor.days_since_epoch());
                date_of_day(
                    i64::from(anchor.days_since_epoch()) + offset.div_euclid(length) * length,
                )
            }
        }
    }

    /// The start of the cycle after the one that contains `on`: the
    /// earliest cycle start after it. `InvalidDate` if that start would
    /// fall outside 1970..=9999.
    pub fn next_cycle_start(self, on: CalendarDate) -> Result<CalendarDate, ModelError> {
        match self {
            Self::Monthly { bill_day } => bill_day.next_cycle_start(on),
            Self::FixedDays { days, .. } => date_of_day(
                i64::from(self.cycle_start(on)?.days_since_epoch()) + i64::from(days.get()),
            ),
        }
    }

    /// A lower bound on every cycle's length in days: 28 for a monthly rule
    /// (February, and bill day 31 into a common February), the length for a
    /// fixed one.
    #[must_use]
    pub const fn shortest_cycle_days(self) -> u16 {
        match self {
            Self::Monthly { .. } => 28,
            Self::FixedDays { days, .. } => days.get(),
        }
    }
}

/// The date `days` days after 1970-01-01, if it is one.
fn date_of_day(days: i64) -> Result<CalendarDate, ModelError> {
    CalendarDate::from_days_since_epoch(u32::try_from(days).map_err(|_| ModelError::InvalidDate)?)
}

/// The most billing cycles that a span of `window` consecutive days can
/// overlap when every cycle lasts at least `shortest` days: between a
/// partial cycle at each end, at least a day each, the span holds at most
/// `(window - 2) / shortest` whole ones.
const fn cycles_overlapped(window: u16, shortest: u16) -> u64 {
    if window <= 1 {
        1
    } else {
        ((window - 2) / shortest) as u64 + 2
    }
}

/// What the exit does when the cycle's SIM bytes approach the plan's line.
/// There is no "no stop" default: running past a fair-use line is the
/// explicit [`StopPolicy::AcceptDeprioritisation`] (critique C-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StopPolicy {
    /// The exit stops when the cycle's SIM bytes reach `bytes`, and stays
    /// stopped until the cycle resets (`SimCapReached`). The pilot stops at
    /// [`PILOT_SIM_HARD_STOP_BYTES`].
    HardStop {
        /// The hard stop, in bytes; above the warning and below the plan's
        /// line, when it has one.
        bytes: u64,
    },
    /// The operator's explicit choice to keep serving past an unlimited
    /// plan's fair-use line, accepting that the carrier may deprioritise
    /// the line until the cycle ends or contact the operator. Only valid
    /// with a recorded plan that has a fair-use line
    /// ([`PlanKind::UnlimitedFairUse`]); an unlimited plan without a line
    /// has no deprioritisation step, so it needs a hard stop.
    AcceptDeprioritisation,
}

impl StopPolicy {
    /// The hard stop in bytes, if there is one.
    #[must_use]
    pub const fn hard_stop_bytes(self) -> Option<u64> {
        match self {
            Self::HardStop { bytes } => Some(bytes),
            Self::AcceptDeprioritisation => None,
        }
    }
}

/// The thresholds the exit's SIM meter acts on, with the recorded plan's
/// line they are checked against. The status stream carries this value
/// as it is (`daemon-core`'s `SimMeterStatus`), so a decoded copy is
/// checked exactly as the policy was.
///
/// Invariant (checked by [`SimThresholds::new`] and on decode):
///
/// - `0 < warn_bytes < hard stop` (`InvalidSimThresholds`);
/// - `AcceptDeprioritisation` needs a fair-use line
///   (`DeprioritisationNeedsFairUseLine`): an unlimited plan without a
///   line, a capped plan and an unrecorded plan all need a hard stop;
/// - with a line, the highest threshold (the hard stop, or the warning when
///   there is none) lies below it (`SimThresholdAbovePlan`). Without a line
///   there is no upper bound: SMARTY publishes no volume, and any other
///   number would be invented. The stop is still mandatory and explicitly
///   recorded.
///
/// [`SimThresholds::budget_bytes`] follows from these: the SIM bytes the
/// cycle may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SimThresholdsRepr", into = "SimThresholdsRepr")]
pub struct SimThresholds {
    warn_bytes: u64,
    stop: StopPolicy,
    plan_line: Option<PlanLine>,
    // Derived from the three above in `new`; never serialised.
    budget_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimThresholdsRepr {
    warn_bytes: u64,
    stop: StopPolicy,
    // Required even when null: a lost key must not read as "no line".
    #[serde(deserialize_with = "Option::deserialize")]
    plan_line: Option<PlanLine>,
}

impl SimThresholds {
    /// Accepts ordered thresholds that respect the line; see the type's
    /// invariant.
    pub fn new(
        warn_bytes: u64,
        stop: StopPolicy,
        plan_line: Option<PlanLine>,
    ) -> Result<Self, ModelError> {
        let hard_stop_bytes = stop.hard_stop_bytes();
        if warn_bytes == 0 || hard_stop_bytes.is_some_and(|stop| warn_bytes >= stop) {
            return Err(ModelError::InvalidSimThresholds {
                warn_bytes,
                hard_stop_bytes,
            });
        }
        let budget_bytes = match (stop, plan_line) {
            (StopPolicy::HardStop { bytes }, _) => bytes,
            (StopPolicy::AcceptDeprioritisation, Some(line))
                if line.kind == PlanLineKind::FairUse =>
            {
                line.bytes.get()
            }
            (StopPolicy::AcceptDeprioritisation, _) => {
                return Err(ModelError::DeprioritisationNeedsFairUseLine);
            }
        };
        if let Some(line) = plan_line {
            let threshold_bytes = hard_stop_bytes.unwrap_or(warn_bytes);
            if threshold_bytes >= line.bytes.get() {
                return Err(ModelError::SimThresholdAbovePlan {
                    threshold_bytes,
                    line_bytes: line.bytes.get(),
                });
            }
        }
        Ok(Self {
            warn_bytes,
            stop,
            plan_line,
            budget_bytes,
        })
    }

    /// The usage at which the operator is warned.
    #[must_use]
    pub const fn warn_bytes(&self) -> u64 {
        self.warn_bytes
    }

    /// What happens at the plan's line.
    #[must_use]
    pub const fn stop(&self) -> StopPolicy {
        self.stop
    }

    /// The recorded plan's line; `None` when the plan has no line or is
    /// not recorded.
    #[must_use]
    pub const fn plan_line(&self) -> Option<PlanLine> {
        self.plan_line
    }

    /// The SIM bytes the cycle may use: the hard stop, or under
    /// [`StopPolicy::AcceptDeprioritisation`] the fair-use line the
    /// operator accepted running past.
    #[must_use]
    pub const fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

impl TryFrom<SimThresholdsRepr> for SimThresholds {
    type Error = ModelError;

    fn try_from(repr: SimThresholdsRepr) -> Result<Self, Self::Error> {
        Self::new(repr.warn_bytes, repr.stop, repr.plan_line)
    }
}

impl From<SimThresholds> for SimThresholdsRepr {
    fn from(thresholds: SimThresholds) -> Self {
        Self {
            warn_bytes: thresholds.warn_bytes,
            stop: thresholds.stop,
            plan_line: thresholds.plan_line,
        }
    }
}

/// SIM volume accounting: the cycle rule, the plan and the thresholds.
///
/// The thresholds are a [`SimThresholds`] checked against the recorded
/// plan's line, so its invariant holds here too (`InvalidSimThresholds`,
/// `DeprioritisationNeedsFairUseLine`, `SimThresholdAbovePlan`). A rolling
/// fair-use line ([`FairUseWindow::Rolling`]) is checked against every
/// cycle one window can overlap: a hard stop resets with each cycle, so a
/// window that holds the end of one cycle and the start of the next can see
/// both cycles' stops. The stop times that number of cycles must stay below
/// the line (`SimStopAboveRollingLine`): with 1pMobile's 30-day cycles and
/// 30-day window, twice the stop below 500 GB. Accepting deprioritisation
/// is the explicit choice to run past the line, so it is not bounded so.
///
/// [`SimPolicy::new`] takes the plan, so the API builds only recorded
/// policies. A policy without a plan exists only in a state lifted from
/// version 1, which kept no plan record, and in a document that holds such
/// a lifted policy (`"plan": null`); it needs a hard stop, and a fresh
/// deployment refuses it (`PlanNotRecorded`). Decoding still builds one, so
/// the state store refuses any change that edits the policy and leaves it
/// unrecorded (`mooring-store`'s `InvalidChange{PlanNotRecorded}`): a
/// recorded plan cannot be un-recorded by a configuration change, and a
/// lifted policy keeps no plan only while it is left as it is. Recording
/// the plan is an explicit operator action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SimPolicyRepr", into = "SimPolicyRepr")]
pub struct SimPolicy {
    cycle: CycleRule,
    plan: Option<SimPlan>,
    thresholds: SimThresholds,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimPolicyRepr {
    cycle: CycleRule,
    // Required even when null: a lost key must not read as "no plan".
    #[serde(deserialize_with = "Option::deserialize")]
    plan: Option<SimPlan>,
    warn_bytes: u64,
    stop: StopPolicy,
}

impl SimPolicy {
    /// A policy on the recorded `plan`; the thresholds are checked against
    /// its line, see [`SimThresholds`], and a hard stop against a rolling
    /// line over the cycles one window overlaps (the type's documentation).
    pub fn new(
        cycle: CycleRule,
        plan: SimPlan,
        warn_bytes: u64,
        stop: StopPolicy,
    ) -> Result<Self, ModelError> {
        let thresholds = SimThresholds::new(warn_bytes, stop, plan.kind.line())?;
        if let (
            PlanKind::UnlimitedFairUse {
                fair_use_bytes,
                window: FairUseWindow::Rolling { days },
            },
            StopPolicy::HardStop { bytes },
        ) = (plan.kind, stop)
        {
            let cycles = cycles_overlapped(days.get(), cycle.shortest_cycle_days());
            if bytes
                .checked_mul(cycles)
                .is_none_or(|worst| worst >= fair_use_bytes.get())
            {
                return Err(ModelError::SimStopAboveRollingLine {
                    stop_bytes: bytes,
                    cycles,
                    window_days: days.get(),
                    line_bytes: fair_use_bytes.get(),
                });
            }
        }
        Ok(Self {
            cycle,
            plan: Some(plan),
            thresholds,
        })
    }

    /// A policy whose plan is not recorded: what a version-1 policy lifts
    /// to, and what a document holding one decodes to. Only a hard stop is
    /// accepted (`DeprioritisationNeedsFairUseLine`).
    pub(crate) fn unrecorded(
        cycle: CycleRule,
        warn_bytes: u64,
        stop: StopPolicy,
    ) -> Result<Self, ModelError> {
        let thresholds = SimThresholds::new(warn_bytes, stop, None)?;
        Ok(Self {
            cycle,
            plan: None,
            thresholds,
        })
    }

    /// The rule that starts each cycle.
    #[must_use]
    pub const fn cycle(&self) -> CycleRule {
        self.cycle
    }

    /// The recorded plan. `None` only in a policy lifted from version 1,
    /// which kept no plan record; no public constructor builds one.
    #[must_use]
    pub const fn plan(&self) -> Option<&SimPlan> {
        self.plan.as_ref()
    }

    /// The thresholds and the line they are checked against.
    #[must_use]
    pub const fn thresholds(&self) -> SimThresholds {
        self.thresholds
    }

    /// The usage at which the operator is warned.
    #[must_use]
    pub const fn warn_bytes(&self) -> u64 {
        self.thresholds.warn_bytes
    }

    /// What happens at the plan's line.
    #[must_use]
    pub const fn stop(&self) -> StopPolicy {
        self.thresholds.stop
    }
}

impl TryFrom<SimPolicyRepr> for SimPolicy {
    type Error = ModelError;

    fn try_from(repr: SimPolicyRepr) -> Result<Self, Self::Error> {
        match repr.plan {
            Some(plan) => Self::new(repr.cycle, plan, repr.warn_bytes, repr.stop),
            None => Self::unrecorded(repr.cycle, repr.warn_bytes, repr.stop),
        }
    }
}

impl From<SimPolicy> for SimPolicyRepr {
    fn from(policy: SimPolicy) -> Self {
        Self {
            cycle: policy.cycle,
            plan: policy.plan,
            warn_bytes: policy.thresholds.warn_bytes,
            stop: policy.thresholds.stop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{TEST_FAIR_USE_BYTES, fair_use_plan, smarty_unlimited_plan};
    use proptest::prelude::*;

    fn date(text: &str) -> CalendarDate {
        CalendarDate::parse(text).unwrap()
    }

    fn day(day: u8) -> BillDay {
        BillDay::new(day).unwrap()
    }

    fn monthly(bill: u8) -> CycleRule {
        CycleRule::Monthly {
            bill_day: day(bill),
        }
    }

    fn every(days: u16, anchor: &str) -> CycleRule {
        CycleRule::FixedDays {
            days: PeriodDays::new(days).unwrap(),
            anchor: date(anchor),
        }
    }

    fn one_p_mobile() -> SimPlan {
        SimPlan::one_p_mobile_unlimited().unwrap()
    }

    fn capped(allowance: u64, after: AfterAllowance) -> SimPlan {
        SimPlan {
            kind: PlanKind::Capped {
                allowance_bytes: NonZeroU64::new(allowance).unwrap(),
                after,
            },
            ..smarty_unlimited_plan()
        }
    }

    fn hard_stop(bytes: u64) -> StopPolicy {
        StopPolicy::HardStop { bytes }
    }

    /// The pilot runs with decision F2's thresholds, exactly, and they are a
    /// valid policy on the decided SMARTY plan.
    #[test]
    fn the_pilot_thresholds_are_the_f2_decision() {
        assert_eq!(PILOT_SIM_WARN_BYTES, 200_000_000_000);
        assert_eq!(PILOT_SIM_HARD_STOP_BYTES, 240_000_000_000);
        for plan in [one_p_mobile(), smarty_unlimited_plan()] {
            let pilot = SimPolicy::new(
                every(30, "2026-10-28"),
                plan.clone(),
                PILOT_SIM_WARN_BYTES,
                hard_stop(PILOT_SIM_HARD_STOP_BYTES),
            )
            .unwrap();
            assert_eq!(pilot.warn_bytes(), PILOT_SIM_WARN_BYTES);
            assert_eq!(
                pilot.stop().hard_stop_bytes(),
                Some(PILOT_SIM_HARD_STOP_BYTES)
            );
            assert_eq!(pilot.thresholds().budget_bytes(), PILOT_SIM_HARD_STOP_BYTES);
            assert_eq!(pilot.thresholds().plan_line(), plan.kind.line());
        }
    }

    /// 1pMobile's plan as its terms state it: 500 GB per rolling 30 days, no
    /// speed cap, recorded from the terms of 24 July 2026.
    #[test]
    fn the_decided_plan_is_1pmobiles_unlimited_boost() {
        let plan = one_p_mobile();
        assert_eq!(plan.carrier, Carrier::OnePMobile);
        assert_eq!(
            plan.kind,
            PlanKind::UnlimitedFairUse {
                fair_use_bytes: NonZeroU64::new(500_000_000_000).unwrap(),
                window: FairUseWindow::Rolling {
                    days: PeriodDays::new(30).unwrap()
                },
            }
        );
        assert_eq!(plan.speed_cap_mbps, None);
        assert_eq!(
            plan.terms.url.as_str(),
            "https://www.1pmobile.com/terms-and-conditions"
        );
        assert_eq!(plan.terms.dated, date("2026-07-24"));
        assert_eq!(
            serde_json::to_string(&plan).unwrap(),
            r#"{"carrier":"1pmobile","kind":{"unlimited_fair_use":{"fair_use_bytes":500000000000,"window":{"rolling":{"days":30}}}},"speed_cap_mbps":null,"terms":{"url":"https://www.1pmobile.com/terms-and-conditions","dated":"2026-07-24"}}"#
        );
    }

    #[test]
    fn period_days_are_1_to_366() {
        for bad in [0, 367, u16::MAX] {
            assert_eq!(
                PeriodDays::new(bad),
                Err(ModelError::InvalidPeriodDays { days: bad })
            );
        }
        assert_eq!(PeriodDays::new(1).unwrap().get(), 1);
        assert_eq!(PeriodDays::new(366).unwrap().get(), 366);
        assert_eq!(
            serde_json::to_string(&PeriodDays::new(30).unwrap()).unwrap(),
            "30"
        );
        assert!(serde_json::from_str::<PeriodDays>("0").is_err());
        assert!(serde_json::from_str::<PeriodDays>("367").is_err());
    }

    #[test]
    fn bill_days_are_1_to_31() {
        for bad in [0, 32, 255] {
            assert_eq!(
                BillDay::new(bad),
                Err(ModelError::InvalidBillDay { day: bad })
            );
        }
        assert_eq!(BillDay::new(31).unwrap().get(), 31);
        assert_eq!(serde_json::to_string(&day(29)).unwrap(), "29");
        assert!(serde_json::from_str::<BillDay>("0").is_err());
        assert!(serde_json::from_str::<BillDay>("32").is_err());
    }

    /// The thresholds carry the plan's line and check themselves against
    /// it, exactly as the policy does, also when decoded on their own (the
    /// status stream carries them).
    #[test]
    fn thresholds_name_the_line_they_are_checked_against() {
        let fair_use = PlanLine {
            kind: PlanLineKind::FairUse,
            bytes: TEST_FAIR_USE_BYTES,
        };
        assert_eq!(fair_use_plan().kind.line(), Some(fair_use));
        assert_eq!(smarty_unlimited_plan().kind.line(), None);
        let allowance = capped(10_000, AfterAllowance::Blocked).kind.line().unwrap();
        assert_eq!(
            allowance,
            PlanLine {
                kind: PlanLineKind::Allowance,
                bytes: NonZeroU64::new(10_000).unwrap()
            }
        );
        let policy = SimPolicy::new(
            monthly(1),
            fair_use_plan(),
            PILOT_SIM_WARN_BYTES,
            hard_stop(PILOT_SIM_HARD_STOP_BYTES),
        )
        .unwrap();
        let thresholds = policy.thresholds();
        assert_eq!(thresholds.warn_bytes(), PILOT_SIM_WARN_BYTES);
        assert_eq!(thresholds.stop(), hard_stop(PILOT_SIM_HARD_STOP_BYTES));
        assert_eq!(thresholds.plan_line(), Some(fair_use));
        let json = serde_json::to_string(&thresholds).unwrap();
        assert_eq!(
            json,
            r#"{"warn_bytes":200000000000,"stop":{"hard_stop":{"bytes":240000000000}},"plan_line":{"kind":"fair_use","bytes":644245094400}}"#
        );
        assert_eq!(
            serde_json::from_str::<SimThresholds>(&json).unwrap(),
            thresholds
        );
        // Each rule of the invariant, on construction and on decode.
        assert_eq!(
            SimThresholds::new(5_000, StopPolicy::AcceptDeprioritisation, Some(allowance)),
            Err(ModelError::DeprioritisationNeedsFairUseLine)
        );
        assert_eq!(
            SimThresholds::new(5_000, hard_stop(10_000), Some(allowance)),
            Err(ModelError::SimThresholdAbovePlan {
                threshold_bytes: 10_000,
                line_bytes: 10_000
            })
        );
        assert_eq!(
            SimThresholds::new(5_000, hard_stop(5_000), None),
            Err(ModelError::InvalidSimThresholds {
                warn_bytes: 5_000,
                hard_stop_bytes: Some(5_000)
            })
        );
        assert!(SimThresholds::new(5_000, hard_stop(9_999), Some(allowance)).is_ok());
        let lineless = json.replace(r#"{"kind":"fair_use","bytes":644245094400}"#, "null");
        for bad in [
            // The stop at the line.
            json.replace("240000000000", "644245094400"),
            // Deprioritisation against an allowance, and with no line.
            json.replace(
                r#"{"hard_stop":{"bytes":240000000000}}"#,
                r#""accept_deprioritisation""#,
            )
            .replace("fair_use", "allowance"),
            lineless.replace(
                r#"{"hard_stop":{"bytes":240000000000}}"#,
                r#""accept_deprioritisation""#,
            ),
            // Missing and unknown keys.
            json.replace(
                r#","plan_line":{"kind":"fair_use","bytes":644245094400}"#,
                "",
            ),
            json.replace(r#""bytes":644245094400"#, r#""bytes":644245094400,"x":1"#),
            json.replace("fair_use", "unlimited"),
            // The derived budget is not a key.
            json.replace(
                r#""warn_bytes":200000000000"#,
                r#""warn_bytes":200000000000,"budget_bytes":240000000000"#,
            ),
        ] {
            assert_ne!(bad, json);
            assert!(
                serde_json::from_str::<SimThresholds>(&bad).is_err(),
                "{bad}"
            );
        }
        // Without a line, any ordered hard stop decodes.
        let absurd = lineless.replace("240000000000", &u64::MAX.to_string());
        assert_eq!(
            serde_json::from_str::<SimThresholds>(&absurd)
                .unwrap()
                .stop(),
            hard_stop(u64::MAX)
        );
        let deprioritised = json.replace(
            r#"{"hard_stop":{"bytes":240000000000}}"#,
            r#""accept_deprioritisation""#,
        );
        assert_eq!(
            serde_json::from_str::<SimThresholds>(&deprioritised)
                .unwrap()
                .stop(),
            StopPolicy::AcceptDeprioritisation
        );
    }

    /// The month-end clamp: a short month starts its cycle on its last day.
    #[test]
    fn a_bill_day_beyond_the_month_falls_on_its_last_day() {
        let boundary = |bill: u8, year: u16, month: u8| day(bill).boundary_in(year, month).unwrap();
        // February, common and leap years (2100 is a common year).
        for bill in [29, 30, 31] {
            assert_eq!(boundary(bill, 2026, 2), date("2026-02-28"), "{bill}");
            assert_eq!(boundary(bill, 2100, 2), date("2100-02-28"), "{bill}");
            assert_eq!(boundary(bill, 2028, 2), date("2028-02-29"), "{bill}");
            assert_eq!(boundary(bill, 2000, 2), date("2000-02-29"), "{bill}");
        }
        assert_eq!(boundary(28, 2028, 2), date("2028-02-28"));
        // 30-day months.
        for month in [4, 6, 9, 11] {
            assert_eq!(boundary(31, 2026, month).day(), 30, "{month}");
            assert_eq!(boundary(30, 2026, month).day(), 30, "{month}");
        }
        // 31-day months keep the bill day.
        for month in [1, 3, 5, 7, 8, 10, 12] {
            assert_eq!(boundary(31, 2026, month).day(), 31, "{month}");
        }
        assert_eq!(boundary(1, 2026, 2), date("2026-02-01"));
    }

    #[test]
    fn cycles_run_from_boundary_to_boundary() {
        let start = |bill: u8, on: &str| day(bill).cycle_start(date(on)).unwrap();
        let next = |bill: u8, on: &str| day(bill).next_cycle_start(date(on)).unwrap();
        // Bill day 31 across the short months.
        assert_eq!(start(31, "2026-02-27"), date("2026-01-31"));
        assert_eq!(start(31, "2026-02-28"), date("2026-02-28"));
        assert_eq!(start(31, "2026-03-01"), date("2026-02-28"));
        assert_eq!(next(31, "2026-02-28"), date("2026-03-31"));
        assert_eq!(start(31, "2026-04-29"), date("2026-03-31"));
        assert_eq!(start(31, "2026-04-30"), date("2026-04-30"));
        assert_eq!(next(31, "2026-04-30"), date("2026-05-31"));
        assert_eq!(next(31, "2026-01-31"), date("2026-02-28"));
        // Bill day 30 in a leap February.
        assert_eq!(start(30, "2028-02-28"), date("2028-01-30"));
        assert_eq!(start(30, "2028-02-29"), date("2028-02-29"));
        assert_eq!(next(30, "2028-02-29"), date("2028-03-30"));
        // Across the year end, and an ordinary bill day.
        assert_eq!(start(15, "2027-01-03"), date("2026-12-15"));
        assert_eq!(next(15, "2026-12-15"), date("2027-01-15"));
        assert_eq!(start(1, "2026-10-08"), date("2026-10-01"));
        assert_eq!(next(1, "2026-10-08"), date("2026-11-01"));
        // Outside the date range there is no boundary.
        assert_eq!(
            day(10).cycle_start(date("1970-01-05")),
            Err(ModelError::InvalidDate)
        );
        assert_eq!(
            day(1).next_cycle_start(date("9999-12-31")),
            Err(ModelError::InvalidDate)
        );
    }

    /// Fixed cycles run back to back from the anchor, before it as after
    /// it, whatever the months.
    #[test]
    fn fixed_cycles_run_back_to_back_from_their_anchor() {
        let rule = every(30, "2026-10-28");
        let start = |on: &str| rule.cycle_start(date(on)).unwrap();
        let next = |on: &str| rule.next_cycle_start(date(on)).unwrap();
        assert_eq!(start("2026-10-28"), date("2026-10-28"));
        assert_eq!(next("2026-10-28"), date("2026-11-27"));
        assert_eq!(start("2026-11-26"), date("2026-10-28"));
        assert_eq!(start("2026-11-27"), date("2026-11-27"));
        assert_eq!(next("2026-12-26"), date("2026-12-27"));
        // Across February and the year end.
        assert_eq!(start("2027-02-28"), date("2027-02-25"));
        assert_eq!(next("2027-02-28"), date("2027-03-27"));
        // Before the anchor.
        assert_eq!(start("2026-10-27"), date("2026-09-28"));
        assert_eq!(next("2026-10-27"), date("2026-10-28"));
        assert_eq!(start("2026-09-28"), date("2026-09-28"));
        assert_eq!(start("2026-09-27"), date("2026-08-29"));
        // Outside the date range there is no boundary.
        assert_eq!(
            every(30, "1970-01-20").cycle_start(date("1970-01-05")),
            Err(ModelError::InvalidDate)
        );
        assert_eq!(
            every(30, "9999-12-20").next_cycle_start(date("9999-12-25")),
            Err(ModelError::InvalidDate)
        );
        assert_eq!(rule.shortest_cycle_days(), 30);
        assert_eq!(monthly(31).shortest_cycle_days(), 28);
        assert_eq!(
            monthly(1).cycle_start(date("2026-10-08")).unwrap(),
            date("2026-10-01")
        );
        assert_eq!(
            monthly(1).next_cycle_start(date("2026-10-08")).unwrap(),
            date("2026-11-01")
        );
    }

    #[test]
    fn a_window_overlaps_its_partial_cycles_and_every_whole_one_between() {
        for (window, shortest, cycles) in [
            (1, 30, 1),
            (2, 30, 2),
            (30, 30, 2),
            (31, 30, 2),
            (32, 30, 3),
            (30, 28, 3),
            (30, 29, 2),
            (60, 30, 3),
            (62, 30, 4),
            (30, 1, 30),
            (366, 366, 2),
        ] {
            assert_eq!(
                cycles_overlapped(window, shortest),
                cycles,
                "{window} {shortest}"
            );
        }
    }

    /// A hard stop resets with each cycle, so a rolling window that holds
    /// the end of one cycle and the start of the next sees both stops:
    /// 1pMobile's 30-day line over 30-day cycles takes a stop below 250 GB,
    /// and over monthly cycles, which can be 28 days, one below a third of
    /// the line.
    #[test]
    fn a_hard_stop_stays_below_a_rolling_line_over_every_cycle_a_window_overlaps() {
        let policy =
            |cycle: CycleRule, stop: u64| SimPolicy::new(cycle, one_p_mobile(), 1, hard_stop(stop));
        let fixed = every(30, "2026-10-28");
        assert!(policy(fixed, 249_999_999_999).is_ok());
        for stop in [250_000_000_000, 499_999_999_999] {
            assert_eq!(
                policy(fixed, stop),
                Err(ModelError::SimStopAboveRollingLine {
                    stop_bytes: stop,
                    cycles: 2,
                    window_days: 30,
                    line_bytes: 500_000_000_000
                })
            );
        }
        assert!(policy(monthly(1), 166_666_666_666).is_ok());
        assert_eq!(
            policy(monthly(1), 166_666_666_667),
            Err(ModelError::SimStopAboveRollingLine {
                stop_bytes: 166_666_666_667,
                cycles: 3,
                window_days: 30,
                line_bytes: 500_000_000_000
            })
        );
        // Shorter cycles fit more of them in one window.
        assert_eq!(
            policy(every(7, "2026-10-28"), 100_000_000_000),
            Err(ModelError::SimStopAboveRollingLine {
                stop_bytes: 100_000_000_000,
                cycles: 6,
                window_days: 30,
                line_bytes: 500_000_000_000
            })
        );
        // The line itself still bounds a single stop first.
        assert_eq!(
            policy(fixed, 500_000_000_000),
            Err(ModelError::SimThresholdAbovePlan {
                threshold_bytes: 500_000_000_000,
                line_bytes: 500_000_000_000
            })
        );
        // Accepting deprioritisation is the choice to run past the line.
        let accepted = SimPolicy::new(
            fixed,
            one_p_mobile(),
            499_999_999_999,
            StopPolicy::AcceptDeprioritisation,
        )
        .unwrap();
        assert_eq!(accepted.thresholds().budget_bytes(), 500_000_000_000);
        // A stop so large that the cycles' sum overflows is above any line.
        let huge = SimPlan {
            kind: PlanKind::UnlimitedFairUse {
                fair_use_bytes: NonZeroU64::MAX,
                window: FairUseWindow::Rolling {
                    days: PeriodDays::new(30).unwrap(),
                },
            },
            ..one_p_mobile()
        };
        assert_eq!(
            SimPolicy::new(monthly(1), huge, 1, hard_stop(u64::MAX / 2)),
            Err(ModelError::SimStopAboveRollingLine {
                stop_bytes: u64::MAX / 2,
                cycles: 3,
                window_days: 30,
                line_bytes: u64::MAX
            })
        );
        // A per-cycle line is checked against one cycle only.
        assert!(
            SimPolicy::new(
                fixed,
                fair_use_plan(),
                1,
                hard_stop(TEST_FAIR_USE_BYTES.get() - 1)
            )
            .is_ok()
        );
        // Decoding runs the same check.
        let valid = serde_json::to_string(&policy(fixed, 240_000_000_000).unwrap()).unwrap();
        assert_eq!(
            valid,
            r#"{"cycle":{"fixed_days":{"days":30,"anchor":"2026-10-28"}},"plan":{"carrier":"1pmobile","kind":{"unlimited_fair_use":{"fair_use_bytes":500000000000,"window":{"rolling":{"days":30}}}},"speed_cap_mbps":null,"terms":{"url":"https://www.1pmobile.com/terms-and-conditions","dated":"2026-07-24"}},"warn_bytes":1,"stop":{"hard_stop":{"bytes":240000000000}}}"#
        );
        assert!(serde_json::from_str::<SimPolicy>(&valid).is_ok());
        for bad in [
            valid.replace("240000000000", "250000000000"),
            valid.replace(
                r#"{"fixed_days":{"days":30,"anchor":"2026-10-28"}}"#,
                r#"{"monthly":{"bill_day":28}}"#,
            ),
            valid.replace(r#""days":30,"anchor""#, r#""days":0,"anchor""#),
            valid.replace(r#""days":30,"anchor""#, r#""days":30,"x":1,"anchor""#),
            valid.replace(
                r#""window":{"rolling":{"days":30}}"#,
                r#""window":{"rolling":{"days":30,"x":1}}"#,
            ),
            valid.replace(r#","window":{"rolling":{"days":30}}"#, ""),
            valid.replace(r#""anchor":"2026-10-28""#, r#""anchor":"2026-02-30""#),
        ] {
            assert_ne!(bad, valid);
            assert!(serde_json::from_str::<SimPolicy>(&bad).is_err(), "{bad}");
        }
    }

    /// A fair-use line and a capped plan's allowance still bound every
    /// threshold.
    #[test]
    fn thresholds_must_sit_below_the_plan_line() {
        let plan = fair_use_plan();
        let fair_use = TEST_FAIR_USE_BYTES.get();
        let policy =
            |warn: u64, stop: StopPolicy| SimPolicy::new(monthly(1), plan.clone(), warn, stop);
        assert!(policy(PILOT_SIM_WARN_BYTES, hard_stop(PILOT_SIM_HARD_STOP_BYTES)).is_ok());
        assert!(policy(1, hard_stop(fair_use - 1)).is_ok());
        // A hard stop at or above the fair-use line.
        for stop in [fair_use, fair_use + 1, u64::MAX] {
            assert_eq!(
                policy(1, hard_stop(stop)),
                Err(ModelError::SimThresholdAbovePlan {
                    threshold_bytes: stop,
                    line_bytes: fair_use
                })
            );
        }
        // Accepting deprioritisation still warns before the line.
        assert!(policy(fair_use - 1, StopPolicy::AcceptDeprioritisation).is_ok());
        assert_eq!(
            policy(fair_use, StopPolicy::AcceptDeprioritisation),
            Err(ModelError::SimThresholdAbovePlan {
                threshold_bytes: fair_use,
                line_bytes: fair_use
            })
        );
        // A capped plan's allowance is its line.
        let capped_plan = capped(10_000, AfterAllowance::Blocked);
        assert!(SimPolicy::new(monthly(1), capped_plan.clone(), 5_000, hard_stop(9_999)).is_ok());
        assert_eq!(
            SimPolicy::new(monthly(1), capped_plan, 5_000, hard_stop(10_000)),
            Err(ModelError::SimThresholdAbovePlan {
                threshold_bytes: 10_000,
                line_bytes: 10_000
            })
        );
    }

    #[test]
    fn the_warning_precedes_the_hard_stop() {
        let unrecorded =
            |warn: u64, stop: StopPolicy| SimPolicy::unrecorded(monthly(1), warn, stop);
        for plan in [smarty_unlimited_plan(), fair_use_plan()] {
            for (warn, stop) in [(0, 5), (5, 5), (6, 5)] {
                let refused = Err(ModelError::InvalidSimThresholds {
                    warn_bytes: warn,
                    hard_stop_bytes: Some(stop),
                });
                assert_eq!(
                    SimPolicy::new(monthly(1), plan.clone(), warn, hard_stop(stop)),
                    refused
                );
                assert_eq!(unrecorded(warn, hard_stop(stop)), refused);
            }
        }
        assert_eq!(
            SimPolicy::new(
                monthly(1),
                fair_use_plan(),
                0,
                StopPolicy::AcceptDeprioritisation
            ),
            Err(ModelError::InvalidSimThresholds {
                warn_bytes: 0,
                hard_stop_bytes: None
            })
        );
    }

    /// Running past the line is a choice only a fair-use line offers: an
    /// unlimited plan without a line, a capped plan and an unrecorded plan
    /// need a hard stop.
    #[test]
    fn accepting_deprioritisation_needs_a_fair_use_line() {
        for plan in [
            smarty_unlimited_plan(),
            capped(10_000, AfterAllowance::Blocked),
            capped(
                10_000,
                AfterAllowance::Throttled {
                    kbps: NonZeroU32::new(128).unwrap(),
                },
            ),
        ] {
            assert_eq!(
                SimPolicy::new(
                    monthly(1),
                    plan.clone(),
                    5_000,
                    StopPolicy::AcceptDeprioritisation
                ),
                Err(ModelError::DeprioritisationNeedsFairUseLine),
                "{plan:?}"
            );
        }
        assert_eq!(
            SimPolicy::unrecorded(monthly(1), 5_000, StopPolicy::AcceptDeprioritisation),
            Err(ModelError::DeprioritisationNeedsFairUseLine)
        );
        let accepted = SimPolicy::new(
            monthly(1),
            fair_use_plan(),
            5_000,
            StopPolicy::AcceptDeprioritisation,
        )
        .unwrap();
        assert_eq!(accepted.stop().hard_stop_bytes(), None);
    }

    /// SMARTY's plan has no fair-use line and no deprioritisation step, so
    /// accepting deprioritisation is refused on it, built or decoded.
    #[test]
    fn a_lineless_plan_refuses_deprioritisation() {
        assert_eq!(
            SimPolicy::new(
                monthly(1),
                smarty_unlimited_plan(),
                PILOT_SIM_WARN_BYTES,
                StopPolicy::AcceptDeprioritisation
            ),
            Err(ModelError::DeprioritisationNeedsFairUseLine)
        );
        let valid = serde_json::to_string(
            &SimPolicy::new(
                monthly(1),
                smarty_unlimited_plan(),
                PILOT_SIM_WARN_BYTES,
                hard_stop(PILOT_SIM_HARD_STOP_BYTES),
            )
            .unwrap(),
        )
        .unwrap();
        let accepting = valid.replace(
            r#"{"hard_stop":{"bytes":240000000000}}"#,
            r#""accept_deprioritisation""#,
        );
        assert_ne!(accepting, valid);
        assert!(serde_json::from_str::<SimPolicy>(&accepting).is_err());
        let thresholds =
            r#"{"warn_bytes":200000000000,"stop":"accept_deprioritisation","plan_line":null}"#;
        assert!(serde_json::from_str::<SimThresholds>(thresholds).is_err());
        assert!(
            serde_json::from_str::<SimThresholds>(&thresholds.replace(
                r#""accept_deprioritisation""#,
                r#"{"hard_stop":{"bytes":240000000000}}"#
            ))
            .is_ok()
        );
    }

    /// Without a line there is no ceiling: SMARTY publishes no volume, so
    /// any ordered hard stop is accepted, recorded or not, `u64::MAX`
    /// included.
    #[test]
    fn a_lineless_plan_accepts_any_ordered_hard_stop() {
        let unrecorded =
            |warn: u64, stop: u64| SimPolicy::unrecorded(monthly(1), warn, hard_stop(stop));
        let smarty = |warn: u64, stop: u64| {
            SimPolicy::new(monthly(1), smarty_unlimited_plan(), warn, hard_stop(stop))
        };
        for (warn, stop) in [
            (1, u64::MAX),
            (u64::MAX - 1, u64::MAX),
            (PILOT_SIM_WARN_BYTES, PILOT_SIM_HARD_STOP_BYTES),
            (1, TEST_FAIR_USE_BYTES.get()),
        ] {
            for policy in [smarty(warn, stop), unrecorded(warn, stop)] {
                let policy = policy.unwrap();
                assert_eq!(policy.stop(), hard_stop(stop));
                assert_eq!(policy.thresholds().budget_bytes(), stop);
                assert_eq!(policy.thresholds().plan_line(), None);
                let json = serde_json::to_string(&policy).unwrap();
                assert_eq!(serde_json::from_str::<SimPolicy>(&json).unwrap(), policy);
            }
        }
        let refused = Err(ModelError::InvalidSimThresholds {
            warn_bytes: 5,
            hard_stop_bytes: Some(5),
        });
        assert_eq!(smarty(5, 5), refused);
        assert_eq!(unrecorded(5, 5), refused);
    }

    /// The budget is the hard stop, or the fair-use line the operator chose
    /// to run past.
    #[test]
    fn the_budget_is_the_stop_or_the_accepted_line() {
        let cases = [
            (
                SimPolicy::new(monthly(1), smarty_unlimited_plan(), 7, hard_stop(9)).unwrap(),
                9,
            ),
            (
                SimPolicy::unrecorded(monthly(1), 7, hard_stop(11)).unwrap(),
                11,
            ),
            (
                SimPolicy::new(monthly(1), fair_use_plan(), 7, hard_stop(13)).unwrap(),
                13,
            ),
            (
                SimPolicy::new(
                    monthly(1),
                    capped(100, AfterAllowance::Blocked),
                    7,
                    hard_stop(15),
                )
                .unwrap(),
                15,
            ),
            (
                SimPolicy::new(
                    monthly(1),
                    fair_use_plan(),
                    7,
                    StopPolicy::AcceptDeprioritisation,
                )
                .unwrap(),
                TEST_FAIR_USE_BYTES.get(),
            ),
        ];
        for (policy, budget) in cases {
            assert_eq!(policy.thresholds().budget_bytes(), budget, "{policy:?}");
            // Decoding derives the same budget.
            let json = serde_json::to_string(&policy.thresholds()).unwrap();
            assert_eq!(
                serde_json::from_str::<SimThresholds>(&json)
                    .unwrap()
                    .budget_bytes(),
                budget
            );
        }
    }

    /// The exact encoding of every SIM policy shape. A state document holds
    /// one policy, so the state goldens pin only some of these; this test
    /// pins the rest.
    #[test]
    fn every_policy_shape_has_a_fixed_encoding() {
        let smarty_terms = r#""terms":{"url":"https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf","dated":"2026-08-25"}"#;
        let throttled = capped(
            10_000,
            AfterAllowance::Throttled {
                kbps: NonZeroU32::new(128).unwrap(),
            },
        );
        let mut capped_with_speed = capped(10_000, AfterAllowance::Blocked);
        capped_with_speed.speed_cap_mbps = NonZeroU32::new(100);
        let mut fair_use_with_speed = fair_use_plan();
        fair_use_with_speed.speed_cap_mbps = NonZeroU32::new(100);
        let cases = [
            (
                SimPolicy::unrecorded(monthly(1), 450_000_000_000, hard_stop(560_000_000_000)).unwrap(),
                r#"{"cycle":{"monthly":{"bill_day":1}},"plan":null,"warn_bytes":450000000000,"stop":{"hard_stop":{"bytes":560000000000}}}"#.to_owned(),
            ),
            (
                SimPolicy::new(monthly(31), smarty_unlimited_plan(), PILOT_SIM_WARN_BYTES, hard_stop(PILOT_SIM_HARD_STOP_BYTES)).unwrap(),
                format!(r#"{{"cycle":{{"monthly":{{"bill_day":31}}}},"plan":{{"carrier":"smarty","kind":"unlimited","speed_cap_mbps":null,{smarty_terms}}},"warn_bytes":200000000000,"stop":{{"hard_stop":{{"bytes":240000000000}}}}}}"#),
            ),
            (
                SimPolicy::new(monthly(28), fair_use_plan(), PILOT_SIM_WARN_BYTES, hard_stop(PILOT_SIM_HARD_STOP_BYTES)).unwrap(),
                format!(r#"{{"cycle":{{"monthly":{{"bill_day":28}}}},"plan":{{"carrier":"smarty","kind":{{"unlimited_fair_use":{{"fair_use_bytes":644245094400,"window":"billing_cycle"}}}},"speed_cap_mbps":null,{smarty_terms}}},"warn_bytes":200000000000,"stop":{{"hard_stop":{{"bytes":240000000000}}}}}}"#),
            ),
            (
                SimPolicy::new(monthly(15), fair_use_with_speed, 600_000_000_000, StopPolicy::AcceptDeprioritisation).unwrap(),
                format!(r#"{{"cycle":{{"monthly":{{"bill_day":15}}}},"plan":{{"carrier":"smarty","kind":{{"unlimited_fair_use":{{"fair_use_bytes":644245094400,"window":"billing_cycle"}}}},"speed_cap_mbps":100,{smarty_terms}}},"warn_bytes":600000000000,"stop":"accept_deprioritisation"}}"#),
            ),
            (
                SimPolicy::new(monthly(2), throttled, 5_000, hard_stop(9_000)).unwrap(),
                format!(r#"{{"cycle":{{"monthly":{{"bill_day":2}}}},"plan":{{"carrier":"smarty","kind":{{"capped":{{"allowance_bytes":10000,"after":{{"throttled":{{"kbps":128}}}}}}}},"speed_cap_mbps":null,{smarty_terms}}},"warn_bytes":5000,"stop":{{"hard_stop":{{"bytes":9000}}}}}}"#),
            ),
            (
                SimPolicy::new(monthly(3), capped_with_speed, 5_000, hard_stop(9_000)).unwrap(),
                format!(r#"{{"cycle":{{"monthly":{{"bill_day":3}}}},"plan":{{"carrier":"smarty","kind":{{"capped":{{"allowance_bytes":10000,"after":"blocked"}}}},"speed_cap_mbps":100,{smarty_terms}}},"warn_bytes":5000,"stop":{{"hard_stop":{{"bytes":9000}}}}}}"#),
            ),
        ];
        for (policy, json) in &cases {
            assert_eq!(serde_json::to_string(policy).unwrap(), *json);
            assert_eq!(serde_json::from_str::<SimPolicy>(json).unwrap(), *policy);
        }
        // Every object of every shape refuses an unknown key, the capped
        // plan's `after` included (the state goldens hold no capped plan).
        for (_, json) in &cases {
            let mut objects = 0;
            for (at, _) in json.match_indices('{') {
                objects += 1;
                let mutated = format!("{}\"zz_unknown\":true,{}", &json[..=at], &json[at + 1..]);
                assert!(
                    serde_json::from_str::<SimPolicy>(&mutated).is_err(),
                    "{mutated}"
                );
            }
            assert!(objects >= 2, "{json}");
        }
    }

    #[test]
    fn decoding_checks_the_invariant_and_every_key() {
        let valid = serde_json::to_string(
            &SimPolicy::new(
                monthly(1),
                fair_use_plan(),
                PILOT_SIM_WARN_BYTES,
                hard_stop(PILOT_SIM_HARD_STOP_BYTES),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(serde_json::from_str::<SimPolicy>(&valid).is_ok());
        let fair_use_kind = r#""kind":{"unlimited_fair_use":{"fair_use_bytes":644245094400,"window":"billing_cycle"}}"#;
        assert!(valid.contains(fair_use_kind), "{valid}");
        let cases = [
            // A hard stop above the fair-use line.
            valid.replace("240000000000", "644245094400"),
            // No "no stop" encoding exists.
            valid.replace(r#"{"hard_stop":{"bytes":240000000000}}"#, "null"),
            valid.replace(r#""stop":{"hard_stop":{"bytes":240000000000}}"#, r#""stop":"none""#),
            // The unlimited plan has no line to carry: the earlier shape
            // of an unlimited plan with a line is refused, not read as one
            // without.
            valid.replace(fair_use_kind, r#""kind":{"unlimited":{"fair_use_bytes":644245094400}}"#),
            valid.replace(fair_use_kind, r#""kind":{"unlimited_fair_use":{}}"#),
            valid.replace(fair_use_kind, r#""kind":"unlimited_fair_use""#),
            // Missing keys are errors, not "no plan" or "no speed cap".
            valid.replace(r#""speed_cap_mbps":null,"#, ""),
            valid.replacen(&format!(r#""plan":{{"carrier":"smarty",{fair_use_kind},"speed_cap_mbps":null,"terms":{{"url":"https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf","dated":"2026-08-25"}}}},"#), "", 1),
            valid.replace(r#","stop":{"hard_stop":{"bytes":240000000000}}"#, ""),
            // Zero and unknown values.
            valid.replace("644245094400", "0"),
            valid.replace(r#""speed_cap_mbps":null"#, r#""speed_cap_mbps":0"#),
            valid.replace(r#""carrier":"smarty""#, r#""carrier":"ee""#),
            valid.replace(r#""carrier":"smarty""#, r#""carrier":"o2""#),
            valid.replace(r#""dated":"2026-08-25""#, r#""dated":"2026-02-30""#),
            valid.replace("https://", "http://"),
            valid.replace(r#""bill_day":1"#, r#""bill_day":32"#),
            // Unknown fields, at every level.
            valid.replace(r#""bytes":240000000000"#, r#""bytes":240000000000,"soft":true"#),
            valid.replace(r#""fair_use_bytes":644245094400"#, r#""fair_use_bytes":644245094400,"x":1"#),
            valid.replace(r#""dated":"2026-08-25""#, r#""dated":"2026-08-25","x":1"#),
            valid.replace(r#""carrier":"smarty""#, r#""carrier":"smarty","x":1"#),
            valid.replace(r#""bill_day":1"#, r#""bill_day":1,"cycle_day":1"#),
        ];
        for case in cases {
            assert_ne!(case, valid);
            assert!(serde_json::from_str::<SimPolicy>(&case).is_err(), "{case}");
        }
    }

    proptest! {
        /// With a fair-use line, every accepted policy keeps
        /// `0 < warn < stop < line`, and every such ordered triple is
        /// accepted.
        #[test]
        fn accepted_thresholds_are_ordered_below_a_line(warn in 0_u64..=700_000_000_000, stop in 0_u64..=700_000_000_000) {
            let line = TEST_FAIR_USE_BYTES.get();
            let result = SimPolicy::new(monthly(1), fair_use_plan(), warn, hard_stop(stop));
            prop_assert_eq!(result.is_ok(), 0 < warn && warn < stop && stop < line);
            let accepting = SimPolicy::new(monthly(1), fair_use_plan(), warn, StopPolicy::AcceptDeprioritisation);
            prop_assert_eq!(accepting.is_ok(), 0 < warn && warn < line);
        }

        /// Without a line, a policy is accepted exactly when
        /// `0 < warn < stop`, on the SMARTY plan and unrecorded alike, and
        /// its budget is the stop.
        #[test]
        fn without_a_line_only_the_order_counts(warn in any::<u64>(), stop in any::<u64>()) {
            let ordered = 0 < warn && warn < stop;
            let smarty = SimPolicy::new(monthly(1), smarty_unlimited_plan(), warn, hard_stop(stop));
            prop_assert_eq!(smarty.is_ok(), ordered);
            let unrecorded = SimPolicy::unrecorded(monthly(1), warn, hard_stop(stop));
            prop_assert_eq!(unrecorded.is_ok(), ordered);
            if let Ok(policy) = smarty {
                prop_assert_eq!(policy.thresholds().budget_bytes(), stop);
            }
        }

        /// Every date lies in exactly one cycle, between consecutive
        /// boundaries that follow the clamp rule.
        #[test]
        fn every_date_lies_in_one_clamped_cycle(bill in 1_u8..=31, year in 1971_u16..=9998, month in 1_u8..=12, dom in 1_u8..=31) {
            let bill = day(bill);
            let Ok(on) = CalendarDate::new(year, month, dom) else {
                return Ok(());
            };
            let start = bill.cycle_start(on).unwrap();
            let next = bill.next_cycle_start(on).unwrap();
            prop_assert!(start <= on && on < next);
            for boundary in [start, next] {
                prop_assert_eq!(
                    boundary.day(),
                    bill.get().min(days_in_month(boundary.year(), boundary.month()))
                );
            }
            let months = |date: CalendarDate| u32::from(date.year()) * 12 + u32::from(date.month());
            prop_assert_eq!(months(next), months(start) + 1);
            prop_assert_eq!(bill.cycle_start(next).unwrap(), next);
        }

        /// Every date lies in exactly one fixed cycle, a whole number of
        /// cycles from the anchor.
        #[test]
        fn every_date_lies_in_one_fixed_cycle(days in 1_u16..=366, anchor in 400_u32..=2_932_000, on in 400_u32..=2_932_000) {
            let rule = CycleRule::FixedDays {
                days: PeriodDays::new(days).unwrap(),
                anchor: CalendarDate::from_days_since_epoch(anchor).unwrap(),
            };
            let on = CalendarDate::from_days_since_epoch(on).unwrap();
            let start = rule.cycle_start(on).unwrap();
            let next = rule.next_cycle_start(on).unwrap();
            prop_assert!(start <= on && on < next);
            prop_assert_eq!(next.days_since_epoch() - start.days_since_epoch(), u32::from(days));
            let from_anchor = i64::from(start.days_since_epoch()) - i64::from(anchor);
            prop_assert_eq!(from_anchor.rem_euclid(i64::from(days)), 0);
            prop_assert_eq!(rule.cycle_start(next).unwrap(), next);
        }

        /// Over 1pMobile's 30-day cycles a policy is accepted exactly when
        /// it is ordered and twice its stop stays below the line.
        #[test]
        fn a_rolling_line_takes_twice_the_stop(warn in 0_u64..=600_000_000_000, stop in 0_u64..=600_000_000_000) {
            let result = SimPolicy::new(every(30, "2026-10-28"), one_p_mobile(), warn, hard_stop(stop));
            prop_assert_eq!(result.is_ok(), 0 < warn && warn < stop && 2 * stop < 500_000_000_000);
        }

        #[test]
        fn bill_day_bounds(value in any::<u8>()) {
            prop_assert_eq!(BillDay::new(value).is_ok(), (1..=31).contains(&value));
        }
    }
}
