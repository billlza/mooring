// SPDX-License-Identifier: GPL-3.0-or-later

//! Calendar dates, for records that are days rather than instants: a SIM
//! bill cycle's boundaries, the date a carrier's terms carry, the day a
//! user accepted the agreement. The model never reads a clock; callers pass
//! dates in.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ModelError;
use crate::time::UnixTime;

/// The earliest year a date may have: Mooring records nothing before the
/// Unix epoch.
pub const MIN_YEAR: u16 = 1970;
/// The latest year a date may have: years have four digits.
pub const MAX_YEAR: u16 = 9999;
/// Seconds in a UTC day. Unix time has no leap seconds, so every UTC day
/// is exactly this long in it.
pub const SECS_PER_DAY: u64 = 86_400;
/// [`CalendarDate::days_since_epoch`] of 9999-12-31, the last date.
pub const MAX_DAYS_SINCE_EPOCH: u32 = 2_932_896;

/// Days from 0000-03-01 to 1970-01-01 in the proleptic Gregorian calendar,
/// the offset between the era arithmetic below and Unix days.
const EPOCH_SHIFT_DAYS: u64 = 719_468;
/// Days in one 400-year Gregorian era.
const DAYS_PER_ERA: u64 = 146_097;

/// A day of the proleptic Gregorian calendar between 1970-01-01 and
/// 9999-12-31, written as an ISO 8601 calendar date in extended format,
/// `YYYY-MM-DD`, and read only in that exact form.
///
/// The derived order is chronological: the fields are compared year first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CalendarDate {
    year: u16,
    month: u8,
    day: u8,
}

impl CalendarDate {
    /// Accepts a real day of `month` (1..=12) of `year`
    /// (`MIN_YEAR..=MAX_YEAR`); 29 February only in a leap year.
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, ModelError> {
        let valid = (MIN_YEAR..=MAX_YEAR).contains(&year)
            && (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day);
        if valid {
            Ok(Self { year, month, day })
        } else {
            Err(ModelError::InvalidDate)
        }
    }

    /// Parses exactly `YYYY-MM-DD` with ASCII digits.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = text.as_bytes();
        let shaped = bytes.len() == 10
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && [0, 1, 2, 3, 5, 6, 8, 9]
                .iter()
                .all(|&index| bytes[index].is_ascii_digit());
        if !shaped {
            return Err(ModelError::InvalidDate);
        }
        let year = decimal(&bytes[0..4]);
        let month = u8::try_from(decimal(&bytes[5..7])).map_err(|_| ModelError::InvalidDate)?;
        let day = u8::try_from(decimal(&bytes[8..10])).map_err(|_| ModelError::InvalidDate)?;
        Self::new(year, month, day)
    }

    /// The year.
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }

    /// The month, 1..=12.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, from 1.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// The number of days from 1970-01-01 (day 0) to this date.
    ///
    /// The era arithmetic is Howard Hinnant's `days_from_civil`
    /// (<https://howardhinnant.github.io/date_algorithms.html>): years are
    /// counted from March, so the leap day is the last day of its year.
    #[must_use]
    pub const fn days_since_epoch(self) -> u32 {
        let month = self.month as u64;
        let year = if month <= 2 {
            self.year as u64 - 1
        } else {
            self.year as u64
        };
        let era = year / 400;
        let year_of_era = year - era * 400;
        let month_from_march = (month + 9) % 12;
        let day_of_year = (153 * month_from_march + 2) / 5 + self.day as u64 - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        // 1970-01-01 is day 0 and 9999-12-31 is MAX_DAYS_SINCE_EPOCH, so the
        // value is never negative and always fits a u32.
        (era * DAYS_PER_ERA + day_of_era - EPOCH_SHIFT_DAYS) as u32
    }

    /// The date `days` after 1970-01-01; `InvalidDate` after 9999-12-31
    /// (`days` above [`MAX_DAYS_SINCE_EPOCH`]). The inverse of
    /// [`CalendarDate::days_since_epoch`] (Hinnant's `civil_from_days`).
    pub const fn from_days_since_epoch(days: u32) -> Result<Self, ModelError> {
        if days > MAX_DAYS_SINCE_EPOCH {
            return Err(ModelError::InvalidDate);
        }
        let shifted = days as u64 + EPOCH_SHIFT_DAYS;
        let era = shifted / DAYS_PER_ERA;
        let day_of_era = shifted - era * DAYS_PER_ERA;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_from_march = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
        let month = if month_from_march < 10 {
            month_from_march + 3
        } else {
            month_from_march - 9
        };
        let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
        // Bounded by MAX_DAYS_SINCE_EPOCH: the year is 1970..=9999, the
        // month 1..=12 and the day a real day of that month.
        Ok(Self {
            year: year as u16,
            month: month as u8,
            day: day as u8,
        })
    }

    /// The UTC date of `time`: the day whose UTC midnight is the latest one
    /// at or before it. `InvalidDate` after 9999-12-31.
    pub fn utc_of(time: UnixTime) -> Result<Self, ModelError> {
        let days =
            u32::try_from(time.as_secs() / SECS_PER_DAY).map_err(|_| ModelError::InvalidDate)?;
        Self::from_days_since_epoch(days)
    }

    /// The instant this date starts in UTC: its midnight, `00:00:00Z`.
    #[must_use]
    pub const fn utc_start(self) -> UnixTime {
        UnixTime::from_secs(self.days_since_epoch() as u64 * SECS_PER_DAY)
    }

    /// The date `days` later; `InvalidDate` after 9999-12-31.
    pub fn checked_add_days(self, days: u32) -> Result<Self, ModelError> {
        let shifted = self
            .days_since_epoch()
            .checked_add(days)
            .ok_or(ModelError::InvalidDate)?;
        Self::from_days_since_epoch(shifted)
    }

    /// The first day of this date's month.
    #[must_use]
    pub const fn first_of_month(self) -> Self {
        Self {
            year: self.year,
            month: self.month,
            day: 1,
        }
    }
}

/// The value of ASCII decimal digits; the caller checked every byte is a
/// digit and passes at most four, so the value fits a `u16`.
fn decimal(digits: &[u8]) -> u16 {
    digits
        .iter()
        .fold(0, |value, digit| value * 10 + u16::from(digit - b'0'))
}

/// Whether `year` is a Gregorian leap year: divisible by 4, except
/// centuries not divisible by 400.
#[must_use]
pub const fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// The number of days in `month` of `year`, or 0 when `month` is not
/// 1..=12 (so no day of it validates).
#[must_use]
pub const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

impl fmt::Display for CalendarDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl FromStr for CalendarDate {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl TryFrom<String> for CalendarDate {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<CalendarDate> for String {
    fn from(date: CalendarDate) -> Self {
        date.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn leap_years_follow_the_gregorian_rule() {
        for leap in [1972, 2000, 2024, 2028, 2400] {
            assert!(is_leap_year(leap), "{leap}");
        }
        for common in [1970, 2026, 2100, 2200, 2300] {
            assert!(!is_leap_year(common), "{common}");
        }
        assert_eq!(days_in_month(2028, 2), 29);
        assert_eq!(days_in_month(2026, 2), 28);
        assert_eq!(days_in_month(2100, 2), 28);
        assert_eq!(days_in_month(2026, 4), 30);
        assert_eq!(days_in_month(2026, 12), 31);
        assert_eq!(days_in_month(2026, 0), 0);
        assert_eq!(days_in_month(2026, 13), 0);
    }

    #[test]
    fn dates_parse_and_print_in_the_extended_form() {
        let date = CalendarDate::parse("2026-10-08").unwrap();
        assert_eq!((date.year(), date.month(), date.day()), (2026, 10, 8));
        assert_eq!(date.to_string(), "2026-10-08");
        assert_eq!(serde_json::to_string(&date).unwrap(), "\"2026-10-08\"");
        assert_eq!(
            serde_json::from_str::<CalendarDate>("\"2028-02-29\"").unwrap(),
            CalendarDate::new(2028, 2, 29).unwrap()
        );
        assert!(CalendarDate::new(1970, 1, 1).is_ok());
        assert!(CalendarDate::new(9999, 12, 31).is_ok());
    }

    #[test]
    fn only_real_days_in_range_are_dates() {
        for bad in [
            "2026-02-29",
            "2100-02-29",
            "2026-04-31",
            "2026-13-01",
            "2026-00-10",
            "2026-10-00",
            "2026-10-32",
            "1969-12-31",
            "20261008",
            "2026-1-08",
            "2026-10-8",
            "2026/10/08",
            " 2026-10-08",
            "2026-10-08Z",
            "+026-10-08",
            "２０２６-10-08",
            "",
        ] {
            assert_eq!(
                CalendarDate::parse(bad),
                Err(ModelError::InvalidDate),
                "{bad}"
            );
        }
        assert_eq!(
            CalendarDate::new(10_000, 1, 1),
            Err(ModelError::InvalidDate)
        );
        assert!(serde_json::from_str::<CalendarDate>("\"2026-02-30\"").is_err());
        assert!(serde_json::from_str::<CalendarDate>("20261008").is_err());
    }

    #[test]
    fn the_order_is_chronological() {
        let dates: Vec<CalendarDate> = ["2025-12-31", "2026-01-01", "2026-01-31", "2026-02-01"]
            .iter()
            .map(|text| text.parse().unwrap())
            .collect();
        assert!(dates.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn days_since_the_epoch_match_known_dates() {
        let cases = [
            ("1970-01-01", 0, 0),
            ("1970-01-02", 1, 86_400),
            ("1970-03-01", 59, 5_097_600),
            ("1972-02-29", 789, 68_169_600),
            ("2000-02-29", 11_016, 951_782_400),
            ("2000-03-01", 11_017, 951_868_800),
            ("2026-10-08", 20_734, 1_791_417_600),
            ("2100-03-01", 47_541, 4_107_542_400),
            ("9999-12-31", MAX_DAYS_SINCE_EPOCH, 253_402_214_400),
        ];
        for (text, days, midnight) in cases {
            let date = CalendarDate::parse(text).unwrap();
            assert_eq!(date.days_since_epoch(), days, "{text}");
            assert_eq!(
                CalendarDate::from_days_since_epoch(days),
                Ok(date),
                "{text}"
            );
            assert_eq!(date.utc_start(), UnixTime::from_secs(midnight), "{text}");
            assert_eq!(CalendarDate::utc_of(date.utc_start()), Ok(date), "{text}");
            assert_eq!(
                CalendarDate::utc_of(UnixTime::from_secs(midnight + SECS_PER_DAY - 1)),
                Ok(date),
                "the last second of {text}"
            );
        }
    }

    #[test]
    fn dates_after_9999_are_refused() {
        assert_eq!(
            CalendarDate::from_days_since_epoch(MAX_DAYS_SINCE_EPOCH + 1),
            Err(ModelError::InvalidDate)
        );
        assert_eq!(
            CalendarDate::utc_of(UnixTime::from_secs(253_402_300_800)),
            Err(ModelError::InvalidDate)
        );
        assert_eq!(
            CalendarDate::utc_of(UnixTime::from_secs(u64::MAX)),
            Err(ModelError::InvalidDate)
        );
        let last = CalendarDate::new(9999, 12, 31).unwrap();
        assert_eq!(last.checked_add_days(1), Err(ModelError::InvalidDate));
        assert_eq!(
            last.checked_add_days(u32::MAX),
            Err(ModelError::InvalidDate)
        );
        assert_eq!(last.checked_add_days(0), Ok(last));
    }

    #[test]
    fn days_are_added_across_months_and_years() {
        let date = |text: &str| CalendarDate::parse(text).unwrap();
        assert_eq!(
            date("2026-02-28").checked_add_days(1),
            Ok(date("2026-03-01"))
        );
        assert_eq!(
            date("2028-02-28").checked_add_days(1),
            Ok(date("2028-02-29"))
        );
        assert_eq!(
            date("2026-12-31").checked_add_days(1),
            Ok(date("2027-01-01"))
        );
        assert_eq!(
            date("2026-10-08").checked_add_days(366),
            Ok(date("2027-10-09"))
        );
        assert_eq!(date("2026-10-08").first_of_month(), date("2026-10-01"));
        assert_eq!(date("2026-10-01").first_of_month(), date("2026-10-01"));
    }

    proptest! {
        #[test]
        fn day_numbers_round_trip_and_count_up_by_one(days in 0..MAX_DAYS_SINCE_EPOCH) {
            let date = CalendarDate::from_days_since_epoch(days).unwrap();
            prop_assert_eq!(date.days_since_epoch(), days);
            let next = CalendarDate::from_days_since_epoch(days + 1).unwrap();
            prop_assert!(date < next);
            prop_assert_eq!(date.checked_add_days(1).unwrap(), next);
            // The next day is the next day of the month, or the first of the
            // next month.
            if next.day() == 1 {
                prop_assert_eq!(date.day(), days_in_month(date.year(), date.month()));
            } else {
                prop_assert_eq!((next.year(), next.month(), next.day()), (date.year(), date.month(), date.day() + 1));
            }
        }

        #[test]
        fn every_instant_falls_in_the_day_that_starts_before_it(secs in 0_u64..=253_402_300_799) {
            let date = CalendarDate::utc_of(UnixTime::from_secs(secs)).unwrap();
            let start = date.utc_start().as_secs();
            prop_assert!(start <= secs && secs < start + SECS_PER_DAY);
        }

        #[test]
        fn every_valid_date_round_trips(year in MIN_YEAR..=MAX_YEAR, month in 1_u8..=12, day in 1_u8..=31) {
            match CalendarDate::new(year, month, day) {
                Ok(date) => {
                    prop_assert!(day <= days_in_month(year, month));
                    prop_assert_eq!(CalendarDate::parse(&date.to_string()).unwrap(), date);
                }
                Err(error) => {
                    prop_assert!(day > days_in_month(year, month));
                    prop_assert_eq!(error, ModelError::InvalidDate);
                }
            }
        }
    }
}
