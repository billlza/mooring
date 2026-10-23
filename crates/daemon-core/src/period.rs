// SPDX-License-Identifier: GPL-3.0-or-later

//! The calendar periods the console reports over, all on the **UTC**
//! calendar: the UTC day, the SIM billing cycle and the UTC month that
//! contain an instant.
//!
//! # Why UTC
//!
//! The agent's usage bins start on multiples of their width in Unix time
//! (agent-proto `Resolution`), so every bin lies inside one UTC day, and the
//! SIM meter keeps daily bins by UTC day. A local "today" for the operator
//! (Europe/London) is not a fixed offset from UTC: it is UTC+0 in winter and
//! UTC+1 under British Summer Time, with the changes set by statute rather
//! than by arithmetic. Nothing here carries a time-zone database, and a
//! hand-written copy of the UK rule would go stale silently if the law
//! changed, so the core never converts to local time. Every period below is
//! a UTC period and says so in its name; the app, which has the platform's
//! time-zone database, converts hour bins to Europe/London or Asia/Shanghai
//! when it draws them.
//!
//! A SIM billing cycle here starts at UTC midnight of its first day, as
//! the model's `CycleRule` gives it. Neither carrier states the time of day
//! or the time zone of its boundary: SMARTY renews on the same day each
//! month from activation ([SMARTY-TC] 5.20 and 5.21), and 1pMobile charges
//! its Boosts on a 30-day rolling basis ([1PM-TC], Definitions; both cited
//! in the model's `sim` module). UTC midnight is therefore an inference; if
//! the carrier's boundary is UK midnight, the two differ by one hour during
//! British Summer Time, which the reconciliation against the carrier's own
//! usage reading (console spec B.2.6) covers. A failed renewal taken later
//! moves the cycle's start; the operator then records the new rule.

use mooring_model::date::SECS_PER_DAY;
use mooring_model::{CalendarDate, CycleRule, ModelError, UnixTime};
use serde::{Deserialize, Serialize};

/// One SIM billing cycle on the UTC calendar: from UTC midnight of
/// `start` (inclusive) to UTC midnight of `next_start` (exclusive). See the
/// module documentation for how this relates to the carrier's boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "BillingCycleRepr", into = "BillingCycleRepr")]
pub struct BillingCycle {
    start: CalendarDate,
    next_start: CalendarDate,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BillingCycleRepr {
    start: CalendarDate,
    next_start: CalendarDate,
}

impl BillingCycle {
    /// The cycle that contains `date` under `rule` (the model's clamp rule
    /// for short months applies to a monthly one). `InvalidDate` when a
    /// boundary would fall outside 1970..=9999.
    pub fn containing(rule: CycleRule, date: CalendarDate) -> Result<Self, ModelError> {
        Ok(Self {
            start: rule.cycle_start(date)?,
            next_start: rule.next_cycle_start(date)?,
        })
    }

    /// The cycle that contains the UTC date of `at`.
    pub fn of_instant(rule: CycleRule, at: UnixTime) -> Result<Self, ModelError> {
        Self::containing(rule, CalendarDate::utc_of(at)?)
    }

    /// The first day of the cycle.
    #[must_use]
    pub const fn start(self) -> CalendarDate {
        self.start
    }

    /// The first day of the next cycle.
    #[must_use]
    pub const fn next_start(self) -> CalendarDate {
        self.next_start
    }

    /// The instant the cycle starts: UTC midnight of [`Self::start`].
    #[must_use]
    pub const fn starts_at(self) -> UnixTime {
        self.start.utc_start()
    }

    /// The instant the next cycle starts: UTC midnight of
    /// [`Self::next_start`]; the cycle holds every instant before it.
    #[must_use]
    pub const fn ends_at(self) -> UnixTime {
        self.next_start.utc_start()
    }

    /// Whether `at` lies in the cycle.
    #[must_use]
    pub fn contains(self, at: UnixTime) -> bool {
        self.starts_at() <= at && at < self.ends_at()
    }
}

/// A decoded cycle must end after it starts; nothing else about it can be
/// checked without the bill day.
impl TryFrom<BillingCycleRepr> for BillingCycle {
    type Error = ModelError;

    fn try_from(repr: BillingCycleRepr) -> Result<Self, Self::Error> {
        if repr.start < repr.next_start {
            Ok(Self {
                start: repr.start,
                next_start: repr.next_start,
            })
        } else {
            Err(ModelError::InvalidDate)
        }
    }
}

impl From<BillingCycle> for BillingCycleRepr {
    fn from(cycle: BillingCycle) -> Self {
        Self {
            start: cycle.start,
            next_start: cycle.next_start,
        }
    }
}

/// The periods a usage report covers, all ending at `through` (exclusive):
/// the UTC day, the billing cycle and the UTC month that contain it.
///
/// When `through` is exactly a UTC midnight, the day that starts then is
/// "today" and has no time in it yet, so its totals are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsagePeriods {
    /// The end of every period (exclusive).
    pub through: UnixTime,
    /// The UTC date of `through`: the "today" of the report.
    pub utc_day: CalendarDate,
    /// The billing cycle containing `utc_day`.
    pub cycle: BillingCycle,
    /// The first day of `utc_day`'s month.
    pub utc_month_start: CalendarDate,
}

impl UsagePeriods {
    /// The periods ending at `through` under the cycle `rule`.
    pub fn ending(rule: CycleRule, through: UnixTime) -> Result<Self, ModelError> {
        let utc_day = CalendarDate::utc_of(through)?;
        Ok(Self {
            through,
            utc_day,
            cycle: BillingCycle::containing(rule, utc_day)?,
            utc_month_start: utc_day.first_of_month(),
        })
    }

    /// The earliest instant any of the periods starts at.
    #[must_use]
    pub fn earliest_start(&self) -> UnixTime {
        self.cycle
            .starts_at()
            .min(self.utc_month_start.utc_start())
            .min(self.utc_day.utc_start())
    }
}

/// Whole days, rounded up, from `from` to `to`; zero when `to` is not
/// after `from`.
#[must_use]
pub(crate) const fn days_until(from: UnixTime, to: UnixTime) -> u64 {
    match to.as_secs().checked_sub(from.as_secs()) {
        Some(secs) => secs.div_ceil(SECS_PER_DAY),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_model::BillDay;
    use proptest::prelude::*;

    fn monthly(day: u8) -> CycleRule {
        CycleRule::Monthly {
            bill_day: BillDay::new(day).unwrap(),
        }
    }

    fn date(text: &str) -> CalendarDate {
        CalendarDate::parse(text).unwrap()
    }

    #[test]
    fn a_cycle_runs_from_bill_day_to_bill_day_in_utc() {
        let cycle = BillingCycle::containing(monthly(15), date("2026-10-08")).unwrap();
        assert_eq!(cycle.start(), date("2026-09-15"));
        assert_eq!(cycle.next_start(), date("2026-10-15"));
        assert_eq!(cycle.starts_at(), date("2026-09-15").utc_start());
        assert_eq!(cycle.ends_at(), date("2026-10-15").utc_start());
        assert!(cycle.contains(cycle.starts_at()));
        assert!(!cycle.contains(cycle.ends_at()));
        assert!(cycle.contains(UnixTime::from_secs(cycle.ends_at().as_secs() - 1)));
        // Bill day 31 in a 30-day month starts on the last day.
        let short = BillingCycle::containing(monthly(31), date("2026-11-30")).unwrap();
        assert_eq!(short.start(), date("2026-11-30"));
        assert_eq!(short.next_start(), date("2026-12-31"));
        assert_eq!(
            serde_json::to_string(&cycle).unwrap(),
            r#"{"start":"2026-09-15","next_start":"2026-10-15"}"#
        );
        assert!(
            serde_json::from_str::<BillingCycle>(
                r#"{"start":"2026-10-15","next_start":"2026-10-15"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<BillingCycle>(
                r#"{"start":"2026-09-15","next_start":"2026-10-15","bill_day":15}"#
            )
            .is_err()
        );
    }

    #[test]
    fn periods_end_at_through_and_start_at_utc_midnights() {
        // 2026-10-08T10:30:00Z.
        let through = UnixTime::from_secs(1_791_417_600 + 37_800);
        let periods = UsagePeriods::ending(monthly(20), through).unwrap();
        assert_eq!(periods.utc_day, date("2026-10-08"));
        assert_eq!(periods.cycle.start(), date("2026-09-20"));
        assert_eq!(periods.utc_month_start, date("2026-10-01"));
        assert_eq!(periods.earliest_start(), date("2026-09-20").utc_start());
        // At midnight, the new day is today.
        let midnight = date("2026-10-09").utc_start();
        let periods = UsagePeriods::ending(monthly(9), midnight).unwrap();
        assert_eq!(periods.utc_day, date("2026-10-09"));
        assert_eq!(periods.cycle.start(), date("2026-10-09"));
        assert_eq!(periods.earliest_start(), date("2026-10-01").utc_start());
        // Before 1970 there is no cycle.
        assert_eq!(
            UsagePeriods::ending(monthly(20), UnixTime::from_secs(0)),
            Err(ModelError::InvalidDate)
        );
    }

    #[test]
    fn days_are_rounded_up() {
        let t = |secs| UnixTime::from_secs(secs);
        assert_eq!(days_until(t(100), t(100)), 0);
        assert_eq!(days_until(t(100), t(50)), 0);
        assert_eq!(days_until(t(0), t(1)), 1);
        assert_eq!(days_until(t(0), t(86_400)), 1);
        assert_eq!(days_until(t(0), t(86_401)), 2);
    }

    proptest! {
        #[test]
        fn every_instant_lies_in_its_cycle(day in 1_u8..=31, secs in 2_678_400_u64..253_390_000_000) {
            let at = UnixTime::from_secs(secs);
            let cycle = BillingCycle::of_instant(monthly(day), at).unwrap();
            prop_assert!(cycle.contains(at));
            prop_assert!(cycle.start() < cycle.next_start());
        }
    }
}
