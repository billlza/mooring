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
const MAX_OPAQUE_USER_ID_BYTES: usize = 32;

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
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
