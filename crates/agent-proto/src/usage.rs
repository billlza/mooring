// SPDX-License-Identifier: GPL-3.0-or-later

//! Accounting (design §11.5): bytes per opaque accounting email per month.
//! No destinations and no addresses are recorded.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::macros::{closed_enum, string_serde, text_newtype};
use crate::{UnixTime, ValueError};

/// A calendar month, `YYYY-MM`, from 1970-01 to 9999-12. It names the
/// accounting file `/var/lib/mooring/usage/<YYYY-MM>.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsageMonth {
    year: u16,
    month: u8,
}

impl UsageMonth {
    /// Validates a year in 1970..=9999 and a month in 1..=12.
    pub const fn new(year: u16, month: u8) -> Result<Self, ValueError> {
        if year >= 1970 && year <= 9999 && month >= 1 && month <= 12 {
            Ok(Self { year, month })
        } else {
            Err(ValueError::UsageMonth)
        }
    }

    /// The year.
    pub const fn year(self) -> u16 {
        self.year
    }

    /// The month, 1 to 12.
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The UTC month holding `at`; [`ValueError::UsageMonth`] after
    /// 9999-12.
    pub const fn containing(at: UnixTime) -> Result<Self, ValueError> {
        let (year, month) = civil_from_days(at.as_secs() / SECS_PER_DAY);
        if year > 9999 {
            return Err(ValueError::UsageMonth);
        }
        // `civil_from_days` gives a month in 1..=12 and, from day 0, a year
        // from 1970.
        Self::new(year as u16, month as u8)
    }

    /// The month's first second, 00:00 UTC on its first day.
    pub const fn start(self) -> UnixTime {
        UnixTime::from_secs(days_from_civil(self.year as u64, self.month as u64) * SECS_PER_DAY)
    }

    /// The month after this one; `None` after 9999-12.
    pub const fn next(self) -> Option<Self> {
        let (year, month) = if self.month == 12 {
            (self.year + 1, 1)
        } else {
            (self.year, self.month + 1)
        };
        match Self::new(year, month) {
            Ok(next) => Some(next),
            Err(_) => None,
        }
    }
}

const SECS_PER_DAY: u64 = 86_400;
/// Days in one 400-year era of the Gregorian calendar.
const DAYS_PER_ERA: u64 = 146_097;
/// Days from 0000-03-01 to 1970-01-01.
const EPOCH_SHIFT_DAYS: u64 = 719_468;

/// The days from 1970-01-01 to the first of `month` in `year` (from 1970),
/// by Howard Hinnant's `days_from_civil`
/// (<https://howardhinnant.github.io/date_algorithms.html>), which counts
/// years from March so that the leap day ends its year. `mooring-model`'s
/// `CalendarDate` uses the same arithmetic; agent-proto depends on no
/// model crate (design §6.1), so it carries its own copy.
const fn days_from_civil(year: u64, month: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * DAYS_PER_ERA + day_of_era - EPOCH_SHIFT_DAYS
}

/// The year and month of the day `days` after 1970-01-01 (Hinnant's
/// `civil_from_days`, the inverse of [`days_from_civil`]).
const fn civil_from_days(days: u64) -> (u64, u64) {
    let shifted = days + EPOCH_SHIFT_DAYS;
    let era = shifted / DAYS_PER_ERA;
    let day_of_era = shifted - era * DAYS_PER_ERA;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month)
}

impl fmt::Display for UsageMonth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:04}-{:02}", self.year, self.month)
    }
}

impl FromStr for UsageMonth {
    type Err = ValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (year, month) = text.split_once('-').ok_or(ValueError::UsageMonth)?;
        if year.len() != 4
            || month.len() != 2
            || !(year
                .bytes()
                .chain(month.bytes())
                .all(|byte| byte.is_ascii_digit()))
        {
            return Err(ValueError::UsageMonth);
        }
        let year = year.parse().map_err(|_| ValueError::UsageMonth)?;
        let month = month.parse().map_err(|_| ValueError::UsageMonth)?;
        Self::new(year, month)
    }
}

string_serde!(UsageMonth);

text_newtype!(
    /// A user's opaque identifier as it appears in accounting emails: 1 to
    /// 32 ASCII letters and digits, never `probe`. Real names exist only on
    /// the Mac.
    OpaqueUserId,
    OpaqueUserId,
    is_opaque_user_id
);

const PROBE_PRINCIPAL: &str = "probe";
pub(crate) const MAX_OPAQUE_USER_ID_BYTES: usize = 32;

fn is_opaque_user_id(text: &str) -> bool {
    (1..=MAX_OPAQUE_USER_ID_BYTES).contains(&text.len())
        && text.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && text != PROBE_PRINCIPAL
}

/// Whose traffic an accounting email counts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Principal {
    /// The Mac's in-chain probe identity (`probe@…`), counted separately.
    Probe,
    /// A user.
    User(OpaqueUserId),
}

closed_enum! {
    /// The Xray inbound an accounting email belongs to.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Inbound {
        /// `reality-in` (`…@reality`).
        Reality,
        /// `hy2-loop-in`, the Hysteria2 handoff (`…@hy2`).
        Hy2,
    }
}

impl Inbound {
    /// The email domain: `reality` or `hy2`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reality => "reality",
            Self::Hy2 => "hy2",
        }
    }

    /// The inbound's bit in an [`InboundSet`].
    const fn bit(self) -> u8 {
        match self {
            Self::Reality => 1,
            Self::Hy2 => 2,
        }
    }
}

/// A non-empty set of inbounds. On the wire it is a list in
/// [`Inbound::ALL`] order with each inbound at most once; any other list,
/// the empty one included, is rejected ([`ValueError::InboundSet`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Vec<Inbound>", into = "Vec<Inbound>")]
pub struct InboundSet(u8);

impl InboundSet {
    /// The set holding `inbound`.
    pub const fn of(inbound: Inbound) -> Self {
        Self(inbound.bit())
    }

    /// The set with `inbound` added.
    pub const fn with(self, inbound: Inbound) -> Self {
        Self(self.0 | inbound.bit())
    }

    /// Whether `inbound` is in the set.
    pub const fn contains(self, inbound: Inbound) -> bool {
        self.0 & inbound.bit() != 0
    }

    /// The inbounds, in [`Inbound::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Inbound> {
        Inbound::ALL
            .iter()
            .copied()
            .filter(move |inbound| self.contains(*inbound))
    }
}

impl TryFrom<Vec<Inbound>> for InboundSet {
    type Error = ValueError;

    fn try_from(inbounds: Vec<Inbound>) -> Result<Self, Self::Error> {
        let ordered = inbounds.windows(2).all(|pair| pair[0] < pair[1]);
        match inbounds.split_first() {
            Some((first, rest)) if ordered => Ok(rest
                .iter()
                .fold(Self::of(*first), |set, inbound| set.with(*inbound))),
            _ => Err(ValueError::InboundSet),
        }
    }
}

impl From<InboundSet> for Vec<Inbound> {
    fn from(set: InboundSet) -> Self {
        set.iter().collect()
    }
}

impl fmt::Display for InboundSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, inbound) in self.iter().enumerate() {
            if index > 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(inbound.as_str())?;
        }
        Ok(())
    }
}

/// The `email` of an Xray client, `<principal>@<inbound>` (for example
/// `u01@reality` or `probe@hy2`); Xray keys its per-user traffic counters
/// by it (`user>>>EMAIL>>>traffic>>>uplink`). It travels as that string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatsEmail {
    /// Whose traffic.
    pub principal: Principal,
    /// Which inbound.
    pub inbound: Inbound,
}

impl fmt::Display for StatsEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.principal {
            Principal::Probe => formatter.write_str(PROBE_PRINCIPAL)?,
            Principal::User(user) => formatter.write_str(user.as_str())?,
        }
        write!(formatter, "@{}", self.inbound.as_str())
    }
}

impl FromStr for StatsEmail {
    type Err = ValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (principal, inbound) = text.split_once('@').ok_or(ValueError::StatsEmail)?;
        let inbound = Inbound::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_str() == inbound)
            .ok_or(ValueError::StatsEmail)?;
        let principal = if principal == PROBE_PRINCIPAL {
            Principal::Probe
        } else {
            Principal::User(OpaqueUserId::new(principal).map_err(|_| ValueError::StatsEmail)?)
        };
        Ok(Self { principal, inbound })
    }
}

string_serde!(StatsEmail);

/// Bytes counted for one accounting email.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Traffic {
    /// Bytes from the client towards the destination.
    pub uplink: u64,
    /// Bytes from the destination towards the client.
    pub downlink: u64,
}

/// One month of a node's accounting, the reply to `Usage{month}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageV1 {
    /// The month.
    pub month: UsageMonth,
    /// When the watch last added to the file.
    pub updated_at: UnixTime,
    /// Totals per accounting email.
    pub traffic: BTreeMap<StatsEmail, Traffic>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months_are_four_digit_years_and_two_digit_months() {
        let month: UsageMonth = "2026-10".parse().unwrap();
        assert_eq!((month.year(), month.month()), (2026, 10));
        assert_eq!(month.to_string(), "2026-10");
        assert_eq!(UsageMonth::new(1970, 1).unwrap().to_string(), "1970-01");
        for bad in [
            "2026-13",
            "2026-00",
            "1969-12",
            "2026-1",
            "26-10",
            "2026/10",
            "+202-10",
            "2026-+1",
            "2026-10-01",
            "",
        ] {
            assert_eq!(
                bad.parse::<UsageMonth>(),
                Err(ValueError::UsageMonth),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_time_lies_in_the_utc_month_that_starts_at_or_before_it() {
        // Month starts from Python's `calendar.timegm`.
        for (year, month, start) in [
            (1970, 1, 0),
            (2000, 2, 949_363_200),
            (2000, 3, 951_868_800),
            (2024, 2, 1_706_745_600),
            (2024, 3, 1_709_251_200),
            (2026, 10, 1_790_812_800),
            (2026, 11, 1_793_491_200),
            (2100, 2, 4_105_123_200),
            (2100, 3, 4_107_542_400),
            (9999, 12, 253_399_622_400),
        ] {
            let at = UnixTime::from_secs(start);
            let expected = UsageMonth::new(year, month).unwrap();
            assert_eq!(expected.start(), at, "{expected}");
            assert_eq!(UsageMonth::containing(at), Ok(expected), "{expected}");
            if start > 0 {
                let before = UsageMonth::containing(UnixTime::from_secs(start - 1)).unwrap();
                assert_eq!(before.next(), Some(expected), "{expected}");
            }
        }
        // 2000 and 2024 are leap years; 2100 is not.
        let days = |year, month| {
            let month = UsageMonth::new(year, month).unwrap();
            (month.next().unwrap().start().as_secs() - month.start().as_secs()) / 86_400
        };
        assert_eq!((days(2000, 2), days(2024, 2), days(2100, 2)), (29, 29, 28));
        assert_eq!(
            (days(2026, 10), days(2026, 11), days(2026, 12)),
            (31, 30, 31)
        );
        assert_eq!(UsageMonth::new(9999, 12).unwrap().next(), None);
        assert_eq!(
            UsageMonth::containing(UnixTime::from_secs(253_402_300_799)),
            Ok(UsageMonth::new(9999, 12).unwrap())
        );
        assert_eq!(
            UsageMonth::containing(UnixTime::from_secs(253_402_300_800)),
            Err(ValueError::UsageMonth)
        );
        assert_eq!(
            UsageMonth::containing(UnixTime::from_secs(u64::MAX)),
            Err(ValueError::UsageMonth)
        );
    }

    #[test]
    fn emails_separate_probe_and_users() {
        let user: StatsEmail = "u01@reality".parse().unwrap();
        assert_eq!(
            user.principal,
            Principal::User(OpaqueUserId::new("u01").unwrap())
        );
        assert_eq!(user.inbound, Inbound::Reality);
        let probe: StatsEmail = "probe@hy2".parse().unwrap();
        assert_eq!(
            (probe.principal.clone(), probe.inbound),
            (Principal::Probe, Inbound::Hy2)
        );
        for email in [user, probe] {
            assert_eq!(email.to_string().parse::<StatsEmail>(), Ok(email.clone()));
        }
        for bad in [
            "u01",
            "u01@vless",
            "@reality",
            "u 1@reality",
            "u01@reality@hy2",
            "Probe@hy2x",
        ] {
            assert_eq!(
                bad.parse::<StatsEmail>(),
                Err(ValueError::StatsEmail),
                "{bad:?}"
            );
        }
        assert_eq!(OpaqueUserId::new("probe"), Err(ValueError::OpaqueUserId));
    }

    #[test]
    fn usage_is_keyed_by_email_string() {
        let usage = UsageV1 {
            month: UsageMonth::new(2026, 10).unwrap(),
            updated_at: UnixTime::from_secs(1_790_000_000),
            traffic: BTreeMap::from([
                (
                    "u01@reality".parse().unwrap(),
                    Traffic {
                        uplink: 1,
                        downlink: 2,
                    },
                ),
                (
                    "probe@hy2".parse().unwrap(),
                    Traffic {
                        uplink: 3,
                        downlink: 4,
                    },
                ),
            ]),
        };
        let json = serde_json::to_string(&usage).unwrap();
        assert_eq!(
            json,
            r#"{"month":"2026-10","updated_at":1790000000,"traffic":{"probe@hy2":{"uplink":3,"downlink":4},"u01@reality":{"uplink":1,"downlink":2}}}"#
        );
        assert_eq!(serde_json::from_str::<UsageV1>(&json).unwrap(), usage);
    }
}
