// SPDX-License-Identifier: GPL-3.0-or-later

//! The job's window (design §13.6): launchd fires it every hour at minute
//! 20 of the Mac's local time, and only the firing at 19:20 UTC runs.

use mooring_model::UnixTime;

use super::super::support::{at, date};
use crate::apply::{WINDOW_CLOSES_SECS, WINDOW_OPENS_SECS, in_window};

/// The UK's offset from UTC at `t`, in hours: one hour of summer time from
/// 01:00 UTC on the last Sunday of March to 01:00 UTC on the last Sunday
/// of October (the Summer Time Order's rule), none otherwise.
fn london_offset_hours(t: UnixTime) -> u64 {
    let year = mooring_model::CalendarDate::utc_of(t).unwrap().year();
    let last_sunday = |month: u8| {
        let mut day = mooring_model::date::days_in_month(year, month);
        loop {
            let date = mooring_model::CalendarDate::new(year, month, day).unwrap();
            // 1970-01-01 was a Thursday.
            if (date.days_since_epoch() + 4).is_multiple_of(7) {
                return date.utc_start().as_secs() + 3600;
            }
            day -= 1;
        }
    };
    u64::from((last_sunday(3)..last_sunday(10)).contains(&t.as_secs()))
}

/// Every instant of the UTC day `day` at which launchd fires a job set for
/// minute 20 of every hour of London's local time.
fn london_firings(day: &str) -> Vec<UnixTime> {
    let start = date(day).utc_start().as_secs();
    (start..start + 86_400)
        .step_by(60)
        .map(UnixTime::from_secs)
        .filter(|t| {
            let local = t.as_secs() + london_offset_hours(*t) * 3600;
            local % 3600 == 20 * 60
        })
        .collect()
}

/// In BST and in GMT, and on both days the clocks change, exactly one
/// firing a day runs the job, at 19:20 UTC (03:20 Beijing time).
#[test]
fn exactly_one_firing_a_day_runs_at_19_20_utc_in_summer_and_winter() {
    for day in [
        "2026-07-15",
        "2026-12-15",
        "2026-03-29",
        "2026-10-25",
        "2027-03-28",
    ] {
        let firings = london_firings(day);
        assert_eq!(firings.len(), 24, "{day}: one firing an hour");
        let running: Vec<UnixTime> = firings.into_iter().filter(|t| in_window(*t)).collect();
        assert_eq!(running, [at(day, (19 * 60 + 20) * 60)], "{day}");
    }
    assert_eq!(london_offset_hours(at("2026-07-15", 0)), 1);
    assert_eq!(london_offset_hours(at("2026-12-15", 0)), 0);
}

/// A firing launchd delivers late, after a sleep, runs while it is still
/// inside 19:15 to 19:45 UTC and does nothing outside it.
#[test]
fn a_late_firing_runs_only_inside_the_window() {
    let day = |secs: u64| at("2026-11-02", secs);
    for (secs, runs) in [
        (WINDOW_OPENS_SECS - 1, false),
        (WINDOW_OPENS_SECS, true),
        ((19 * 60 + 20) * 60, true),
        (WINDOW_CLOSES_SECS - 1, true),
        (WINDOW_CLOSES_SECS, false),
        ((19 * 60 + 46) * 60, false),
        ((3 * 60 + 20) * 60, false),
        (0, false),
        (86_399, false),
    ] {
        assert_eq!(in_window(day(secs)), runs, "{secs}");
    }
    assert_eq!(WINDOW_OPENS_SECS, 69_300);
    assert_eq!(WINDOW_CLOSES_SECS, 71_100);
}
