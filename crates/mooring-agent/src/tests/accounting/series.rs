// SPDX-License-Identifier: GPL-3.0-or-later

//! The usage series (design §11.5): a bin is held only inside one stretch
//! of polls; a poll the series cannot take, at or before the latest one it
//! took after the clock stepped back, counts in its month and in no bin,
//! and the polls after it start a stretch of their own; a range with more
//! entries than a reply carries names the bins that fit; an entry that did
//! not grow never costs a bin what it holds; hour and day ranges are
//! answered from their own bins; and a series stored out of order is
//! refused, not served.

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    AgentError, IoOp, MAX_SERIES_ENTRIES, Resolution, SeriesRange, SeriesSpan, StatsEmail, Traffic,
    UnixTime,
};

use super::{OCT, bytes, counters, email, five_min, poll, readings, usage};
use crate::accounting;
use crate::accounting::series::Series;
use crate::store::malformed;
use crate::tests::scratch;

fn span(from: u64, to: u64, resolution: Resolution) -> SeriesSpan {
    SeriesSpan::new(
        UnixTime::from_secs(from),
        UnixTime::from_secs(to),
        resolution,
    )
    .unwrap()
}

#[test]
fn the_series_holds_a_bin_only_inside_one_stretch_of_polls() {
    let (_dir, paths) = scratch();
    let day = OCT + 86_400;
    // Polls every minute from two minutes into a five-minute bin.
    for minute in 0..=12 {
        let grown = 10 * minute;
        poll(
            &paths,
            day + 120 + 60 * minute,
            readings(5, &[("u01@reality", grown, 10 * grown)], 0),
        );
    }
    let now = UnixTime::from_secs(day + 840);
    let reply = accounting::usage_series(&paths, now, five_min(day + 300, day + 600)).unwrap();
    // The polls at 360 to 600 s end inside [300, 600).
    assert_eq!(reply.bins().len(), 1);
    assert_eq!(reply.bins()[0].start(), UnixTime::from_secs(day + 300));
    assert_eq!(
        reply.bins()[0].traffic(),
        &counters(&[("u01@reality", 50, 500)])
    );
    let held = AgentError::SeriesNotRecorded {
        recorded: Some(span(day + 300, day + 600, Resolution::FiveMin)),
    };
    for (from, to) in [(0, 300), (300, 900), (600, 900)] {
        assert_eq!(
            accounting::usage_series(&paths, now, five_min(day + from, day + to)),
            Err(held.clone()),
            "{from}..{to}: the first bin began before the stretch, the third has not ended"
        );
    }
    let hour = SeriesRange::new(
        UnixTime::from_secs(day),
        UnixTime::from_secs(day + 3600),
        Resolution::Hour,
    )
    .unwrap();
    assert_eq!(
        accounting::usage_series(&paths, now, hour),
        Err(AgentError::SeriesNotRecorded { recorded: None })
    );

    // A gap longer than three intervals ends the stretch: what it counted
    // goes to the month only, and a new stretch starts.
    poll(
        &paths,
        day + 840 + 181,
        readings(5, &[("u01@reality", 500, 5000)], 0),
    );
    assert_eq!(
        usage(&paths, day + 1021, 2026, 10).unwrap().traffic,
        counters(&[("u01@reality", 500, 5000)])
    );
    for minute in 1..=10 {
        poll(
            &paths,
            day + 1021 + 60 * minute,
            readings(5, &[("u01@reality", 500, 5000)], 0),
        );
    }
    let later = UnixTime::from_secs(day + 1621);
    // 1021 to 1621 holds the bins [1200, 1500): nothing grew there.
    let quiet = accounting::usage_series(&paths, later, five_min(day + 1200, day + 1500)).unwrap();
    assert!(
        quiet.bins().is_empty(),
        "a held bin without growth is sent as none"
    );
    assert_eq!(
        accounting::usage_series(&paths, later, five_min(day + 600, day + 1500)),
        Err(AgentError::SeriesNotRecorded {
            recorded: Some(span(day + 1200, day + 1500, Resolution::FiveMin))
        }),
        "the gap's bins are not held; the latest stretch is named"
    );
    // A gap of exactly three intervals keeps the stretch, which now holds
    // [1500, 1800) too.
    poll(
        &paths,
        day + 1801,
        readings(5, &[("u01@reality", 500, 5000)], 0),
    );
    let after = accounting::usage_series(
        &paths,
        UnixTime::from_secs(day + 1801),
        five_min(day + 1200, day + 1800),
    )
    .unwrap();
    assert!(after.bins().is_empty());
}

#[test]
fn a_poll_before_the_latest_one_recorded_counts_only_in_its_month() {
    let (_dir, paths) = scratch();
    let day = OCT + 86_400;
    for minute in 0..=6 {
        poll(
            &paths,
            day + 60 * minute,
            readings(5, &[("u01@reality", minute, 0)], 0),
        );
    }
    // The clock stepped back two minutes.
    let stepped = poll(&paths, day + 300, readings(5, &[("u01@reality", 9, 0)], 0));
    assert!(stepped.grew.is_empty(), "not dated");
    let reply = accounting::usage_series(
        &paths,
        UnixTime::from_secs(day + 360),
        five_min(day, day + 300),
    )
    .unwrap();
    assert_eq!(
        reply.bins()[0].traffic(),
        &counters(&[("u01@reality", 5, 0)])
    );
    assert_eq!(
        usage(&paths, day + 360, 2026, 10).unwrap().traffic,
        counters(&[("u01@reality", 9, 0)])
    );
    let again = poll(&paths, day + 360, readings(5, &[("u01@reality", 10, 0)], 0));
    assert!(again.grew.is_empty(), "the latest second recorded, again");
    // The polls after start a stretch of their own: what the stepped poll
    // counted is in the month, and in no bin twice.
    for minute in 7..=11 {
        poll(
            &paths,
            day + 60 * minute,
            readings(5, &[("u01@reality", 10, 0)], 0),
        );
    }
    assert!(matches!(
        accounting::usage_series(
            &paths,
            UnixTime::from_secs(day + 660),
            five_min(day + 300, day + 600)
        ),
        Err(AgentError::SeriesNotRecorded { .. })
    ));
}

#[test]
fn a_poll_in_the_second_of_the_latest_one_taken_is_not_taken() {
    let mut series = Series::default();
    let at = |minute: u64| UnixTime::from_secs(OCT + 60 * minute);
    series.record(0, at(0), None, &BTreeMap::new());
    assert!(series.record(1, at(1), Some(0), &counters(&[("u01@reality", 3, 4)])));
    // The clock stepped back to the second of the poll before, which this
    // poll follows: what it counted cannot be dated, so it is in no bin,
    // and the polls after it start a stretch of their own.
    assert!(!series.record(2, at(1), Some(1), &counters(&[("u01@reality", 1, 1)])));
    assert!(!series.record(3, at(2), Some(2), &BTreeMap::new()));
    for minute in 4..=11 {
        assert!(series.record(minute, at(minute - 1), Some(minute - 1), &BTreeMap::new()));
    }
    assert!(matches!(
        series.answer(five_min(OCT, OCT + 300), at(10)),
        Err(AgentError::SeriesNotRecorded { .. })
    ));
    assert!(
        series
            .answer(five_min(OCT + 300, OCT + 600), at(10))
            .unwrap()
            .bins()
            .is_empty()
    );
}

#[test]
fn a_range_with_more_entries_than_a_reply_carries_names_the_bins_that_fit() {
    let mut series = Series::default();
    // 75 emails in each of 128 bins are exactly the bound.
    let added: BTreeMap<StatsEmail, Traffic> = (0..75)
        .map(|user| (email(&format!("u{user:03}@reality")), bytes(1, 1)))
        .collect();
    const { assert!(128 * 75 == MAX_SERIES_ENTRIES) };
    series.record(0, UnixTime::from_secs(OCT), None, &BTreeMap::new());
    for minute in 1..=144 * 5 {
        series.record(
            minute,
            UnixTime::from_secs(OCT + 60 * minute),
            Some(minute - 1),
            &added,
        );
    }
    let now = UnixTime::from_secs(OCT + 144 * 300);
    assert_eq!(
        series.answer(five_min(OCT, OCT + 144 * 300), now),
        Err(AgentError::SeriesTooLarge { fitting_bins: 128 })
    );
    assert_eq!(
        series
            .answer(five_min(OCT, OCT + 128 * 300), now)
            .unwrap()
            .bins()
            .len(),
        128
    );
}

#[test]
fn an_entry_that_did_not_grow_never_costs_a_bin_what_it_holds() {
    let mut series = Series::default();
    let at = |minute: u64| UnixTime::from_secs(OCT + 60 * minute);
    series.record(0, at(0), None, &BTreeMap::new());
    series.record(1, at(1), Some(0), &counters(&[("u01@reality", 3, 4)]));
    series.record(2, at(2), Some(1), &counters(&[("u02@reality", 0, 0)]));
    // Nor what grew beside it in the same poll.
    series.record(
        3,
        at(3),
        Some(2),
        &counters(&[("u01@reality", 1, 1), ("u02@reality", 0, 0)]),
    );
    for minute in 4..=5 {
        series.record(minute, at(minute), Some(minute - 1), &BTreeMap::new());
    }
    let reply = series.answer(five_min(OCT, OCT + 300), at(5)).unwrap();
    assert_eq!(
        reply.bins()[0].traffic(),
        &counters(&[("u01@reality", 4, 5)])
    );
}

#[test]
fn hour_and_day_ranges_are_answered_from_their_own_bins() {
    let mut series = Series::default();
    let added = counters(&[("u01@reality", 1, 2)]);
    series.record(0, UnixTime::from_secs(OCT), None, &BTreeMap::new());
    for minute in 1..=24 * 60 {
        series.record(
            minute,
            UnixTime::from_secs(OCT + 60 * minute),
            Some(minute - 1),
            &added,
        );
    }
    let now = UnixTime::from_secs(OCT + 86_400);
    let range = |hours: u64, resolution: Resolution| {
        SeriesRange::new(
            UnixTime::from_secs(OCT),
            UnixTime::from_secs(OCT + 3600 * hours),
            resolution,
        )
        .unwrap()
    };
    let hours = series.answer(range(2, Resolution::Hour), now).unwrap();
    let hourly: Vec<(UnixTime, BTreeMap<StatsEmail, Traffic>)> = hours
        .bins()
        .iter()
        .map(|bin| (bin.start(), bin.traffic().clone()))
        .collect();
    assert_eq!(
        hourly,
        [OCT, OCT + 3600].map(|start| (
            UnixTime::from_secs(start),
            counters(&[("u01@reality", 60, 120)])
        ))
    );
    let day = series.answer(range(24, Resolution::Day), now).unwrap();
    assert_eq!(day.bins().len(), 1);
    assert_eq!(
        day.bins()[0].traffic(),
        &counters(&[("u01@reality", 24 * 60, 24 * 120)])
    );
}

#[test]
fn a_series_stored_out_of_order_is_refused_not_served() {
    let (_dir, paths) = scratch();
    let day = OCT + 86_400;
    for minute in 0..=10 {
        poll(
            &paths,
            day + 60 * minute,
            readings(5, &[("u01@reality", minute, minute)], 0),
        );
    }
    let range = five_min(day, day + 600);
    let now = UnixTime::from_secs(day + 600);
    assert_eq!(
        accounting::usage_series(&paths, now, range)
            .unwrap()
            .bins()
            .len(),
        2
    );
    let mut stored: serde_json::Value =
        serde_json::from_slice(&fs::read(paths.accounting()).unwrap()).unwrap();
    stored["series"]["five_min"]
        .as_array_mut()
        .unwrap()
        .reverse();
    fs::write(paths.accounting(), serde_json::to_vec(&stored).unwrap()).unwrap();
    assert_eq!(
        accounting::usage_series(&paths, now, range),
        Err(malformed(IoOp::ReadState))
    );
}
