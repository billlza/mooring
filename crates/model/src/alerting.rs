// SPDX-License-Identifier: GPL-3.0-or-later

//! The alert channels (design §15.8, decision F6, 2026-10-08): which nodes
//! have their channels set up, and when the daily digest goes out.
//!
//! The channels themselves are secrets, kept in the Keychain: the
//! deployment's one ntfy topic ([`crate::secret::SecretRef::AlertTopic`]),
//! which the operator's phone subscribes to and every channel node sends
//! to (a rotation keeps it when the replacement gets its channels before
//! the last channel node retires, design §13.4), and per channel node the
//! UUIDs of its two Healthchecks checks
//! ([`crate::secret::SecretRef::NodeDeadManCheck`],
//! [`crate::secret::SecretRef::NodeMacAliveCheck`]), because a dead-man
//! check watches one node. Nothing else about them belongs in the state:
//! the ntfy server and the Healthchecks ping origin are fixed by the
//! node's alert unit, and priorities and tags are code.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ModelError;
use crate::ids::NodeId;

const MINUTES_PER_HOUR: u16 = 60;
const MINUTES_PER_DAY: u16 = 24 * MINUTES_PER_HOUR;

/// A wall-clock time of day, 00:00..=23:59, written and read only as
/// `HH:MM` with ASCII digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WallClockTime(u16);

impl WallClockTime {
    /// Accepts an hour in 0..=23 and a minute in 0..=59.
    pub fn new(hour: u8, minute: u8) -> Result<Self, ModelError> {
        Self::checked(hour, minute).ok_or(ModelError::InvalidWallClockTime)
    }

    /// The time `hour:minute` if it exists; usable in constants.
    const fn checked(hour: u8, minute: u8) -> Option<Self> {
        if hour < 24 && minute < 60 {
            Some(Self(hour as u16 * MINUTES_PER_HOUR + minute as u16))
        } else {
            None
        }
    }

    /// Parses exactly `HH:MM`.
    pub fn parse(text: &str) -> Result<Self, ModelError> {
        let bytes = text.as_bytes();
        let shaped = bytes.len() == 5
            && bytes[2] == b':'
            && [0, 1, 3, 4]
                .iter()
                .all(|&index| bytes[index].is_ascii_digit());
        if !shaped {
            return Err(ModelError::InvalidWallClockTime);
        }
        let two_digits = |at: usize| (bytes[at] - b'0') * 10 + (bytes[at + 1] - b'0');
        Self::new(two_digits(0), two_digits(3))
    }

    /// The hour, 0..=23.
    #[must_use]
    pub const fn hour(self) -> u8 {
        // Below 24, because the value is below MINUTES_PER_DAY.
        (self.0 / MINUTES_PER_HOUR) as u8
    }

    /// The minute, 0..=59.
    #[must_use]
    pub const fn minute(self) -> u8 {
        // Below 60.
        (self.0 % MINUTES_PER_HOUR) as u8
    }

    /// The minutes since midnight, 0..=1439.
    #[must_use]
    pub const fn minutes_since_midnight(self) -> u16 {
        self.0
    }
}

const _: () = assert!(MINUTES_PER_DAY == 1440);

impl fmt::Display for WallClockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.hour(), self.minute())
    }
}

impl FromStr for WallClockTime {
    type Err = ModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl TryFrom<String> for WallClockTime {
    type Error = ModelError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<WallClockTime> for String {
    fn from(time: WallClockTime) -> Self {
        time.to_string()
    }
}

/// The zone a wall-clock time is read in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WallClockZone {
    /// Europe/London: the operator is in the UK, so a time follows the UK's
    /// switch between GMT and BST.
    EuropeLondon,
}

impl WallClockZone {
    /// The zone's IANA time zone database name, as a systemd calendar event
    /// names it.
    #[must_use]
    pub const fn tz_name(self) -> &'static str {
        match self {
            Self::EuropeLondon => "Europe/London",
        }
    }

    /// The earliest time of day a daily event such as the digest may be set
    /// to in this zone: from it to 23:59 every time of day occurs exactly
    /// once on every day, on the same date in UTC as in the zone.
    ///
    /// Europe/London: 02:00. The UK's clocks change at 01:00 UTC on the
    /// last Sundays of March and October, so on the first 01:00 to 01:59
    /// does not occur and on the second it occurs twice; and from 00:00 to
    /// 00:59 in summer time (UTC+1) the date in UTC is still the day
    /// before, while the digest is titled with the UTC date of the status
    /// it reports.
    #[must_use]
    pub const fn earliest_daily_time(self) -> WallClockTime {
        match self {
            Self::EuropeLondon => EUROPE_LONDON_EARLIEST_DAILY,
        }
    }
}

/// [`WallClockZone::earliest_daily_time`] for Europe/London.
const EUROPE_LONDON_EARLIEST_DAILY: WallClockTime = match WallClockTime::checked(2, 0) {
    Some(time) => time,
    None => panic!("02:00 is a time of day"),
};

/// When the daily digest goes out: 09:00 (decision F6, 2026-10-08).
pub const PILOT_DIGEST_AT: WallClockTime = match WallClockTime::checked(9, 0) {
    Some(time) => time,
    None => panic!("09:00 is a time of day"),
};

// The pilot's digest time is a valid one in its zone.
const _: () = assert!(
    PILOT_DIGEST_AT.minutes_since_midnight()
        >= WallClockZone::EuropeLondon
            .earliest_daily_time()
            .minutes_since_midnight()
);

/// The alert channels (design §15.8, decision F6, 2026-10-08).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertSettings {
    /// When the node sends the daily digest, on `digest_zone`'s wall clock;
    /// no earlier than the zone's
    /// [`WallClockZone::earliest_daily_time`] (02:00 in Europe/London), so
    /// it occurs exactly once every day, on the date its title names
    /// (`DigestTimeTooEarly`, checked with the deployment). The node's
    /// systemd timer renders it as `OnCalendar=*-*-* HH:MM:00
    /// Europe/London` (M4), so no Rust code converts time zones.
    pub digest_at: WallClockTime,
    /// The zone `digest_at` is read in.
    pub digest_zone: WallClockZone,
    /// The nodes whose channels are set up, each an active node. Each has
    /// the UUIDs of two Healthchecks checks in the Keychain (the node's own
    /// and its `MacAlive` check) and sends its notices to the deployment's
    /// one ntfy topic, which is in the Keychain while this set is not
    /// empty.
    pub channels: BTreeSet<NodeId>,
}

impl AlertSettings {
    /// Decision F6 as `exit init` records it: the digest at 09:00 UK time,
    /// and no node's channels set up yet.
    #[must_use]
    pub const fn pilot() -> Self {
        Self {
            digest_at: PILOT_DIGEST_AT,
            digest_zone: WallClockZone::EuropeLondon,
            channels: BTreeSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_clock_time_parses_exactly() {
        let nine = WallClockTime::parse("09:00").unwrap();
        assert_eq!(nine, PILOT_DIGEST_AT);
        assert_eq!((nine.hour(), nine.minute()), (9, 0));
        assert_eq!(nine.minutes_since_midnight(), 540);
        assert_eq!(nine.to_string(), "09:00");
        assert_eq!(serde_json::to_string(&nine).unwrap(), r#""09:00""#);
        assert_eq!(
            serde_json::from_str::<WallClockTime>(r#""09:00""#).unwrap(),
            nine
        );
        for (text, minutes) in [("00:00", 0), ("23:59", 1439), ("12:34", 754)] {
            let time = WallClockTime::parse(text).unwrap();
            assert_eq!(time.minutes_since_midnight(), minutes, "{text}");
            assert_eq!(time.to_string(), text);
            assert_eq!(text.parse::<WallClockTime>().unwrap(), time);
        }
        for bad in [
            "",
            "9:00",
            "24:00",
            "09:60",
            "09:00 ",
            " 09:00",
            "0900",
            "09-00",
            "09:0",
            "009:00",
            "+9:00",
            "09:+0",
            "٠٩:٠٠",
            "99:99",
        ] {
            assert_eq!(
                WallClockTime::parse(bad),
                Err(ModelError::InvalidWallClockTime),
                "{bad}"
            );
            assert!(
                serde_json::from_str::<WallClockTime>(&format!("{bad:?}")).is_err(),
                "{bad}"
            );
        }
        assert!(serde_json::from_str::<WallClockTime>("540").is_err());
        assert_eq!(
            WallClockTime::new(24, 0),
            Err(ModelError::InvalidWallClockTime)
        );
        assert_eq!(
            WallClockTime::new(0, 60),
            Err(ModelError::InvalidWallClockTime)
        );
    }

    #[test]
    fn the_zone_names_the_tz_database_entry() {
        assert_eq!(WallClockZone::EuropeLondon.tz_name(), "Europe/London");
        assert_eq!(
            WallClockZone::EuropeLondon.earliest_daily_time(),
            WallClockTime::parse("02:00").unwrap()
        );
        assert_eq!(
            serde_json::to_string(&WallClockZone::EuropeLondon).unwrap(),
            r#""europe_london""#
        );
        assert!(serde_json::from_str::<WallClockZone>(r#""Europe/London""#).is_err());
    }

    /// The record's exact encoding; every key is required and no other is
    /// accepted.
    #[test]
    fn the_alert_settings_record_has_a_fixed_encoding() {
        let pilot = AlertSettings::pilot();
        assert_eq!(pilot.digest_at.to_string(), "09:00");
        assert_eq!(pilot.digest_zone, WallClockZone::EuropeLondon);
        assert!(pilot.channels.is_empty());
        assert_eq!(
            serde_json::to_string(&pilot).unwrap(),
            r#"{"digest_at":"09:00","digest_zone":"europe_london","channels":[]}"#
        );
        let mut with_channels = pilot;
        with_channels
            .channels
            .extend(["lon1", "ams1"].map(|id| NodeId::parse(id).unwrap()));
        let json =
            r#"{"digest_at":"09:00","digest_zone":"europe_london","channels":["ams1","lon1"]}"#;
        assert_eq!(serde_json::to_string(&with_channels).unwrap(), json);
        assert_eq!(
            serde_json::from_str::<AlertSettings>(json).unwrap(),
            with_channels
        );
        for bad in [
            json.replacen('{', r#"{"zz_unknown":true,"#, 1),
            json.replace(r#""digest_at":"09:00","#, ""),
            json.replace(r#""digest_zone":"europe_london","#, ""),
            json.replace(r#","channels":["ams1","lon1"]"#, ""),
            json.replace(r#""09:00""#, r#""9:00""#),
            json.replace(r#""europe_london""#, r#""utc""#),
            json.replace(r#""ams1""#, r#""AMS1""#),
        ] {
            assert_ne!(bad, json);
            assert!(
                serde_json::from_str::<AlertSettings>(&bad).is_err(),
                "{bad}"
            );
        }
    }

    /// Every `HH:MM` text with two-digit fields round-trips exactly when it
    /// is a time of day: the 1440 of them, and none of the other 8560.
    #[test]
    fn wall_clock_times_round_trip() {
        let mut parsed = 0;
        for hour in 0_u8..=99 {
            for minute in 0_u8..=99 {
                let text = format!("{hour:02}:{minute:02}");
                let result = WallClockTime::parse(&text);
                assert_eq!(result.is_ok(), hour < 24 && minute < 60, "{text}");
                if let Ok(time) = result {
                    parsed += 1;
                    assert_eq!(time.to_string(), text);
                    assert_eq!((time.hour(), time.minute()), (hour, minute));
                }
            }
        }
        assert_eq!(parsed, 1440);
    }
}
