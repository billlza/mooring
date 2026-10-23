// SPDX-License-Identifier: GPL-3.0-or-later

//! Accounting (design §11.5): Xray's API output as the pinned source
//! prints it, every poll counted once in its month, the series and what it
//! holds, retention, and the requests that read them.

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    AgentError, LineRequest, MAX_SERIES_ENTRIES, Resolution, Response, Role, SeriesRange,
    SeriesSpan, StatsEmail, Traffic, UnixTime, UsageMonth, UsageV1,
};

use super::serve::{ask, frame};
use super::{FakeNode, scratch};
use crate::accounting::series::{SERIES_KEEP_SECS, Series};
use crate::accounting::stats::{QueryFailed, SysStats, parse_query, parse_sys};
use crate::accounting::{self, Canary, MONTH_KEEP_SECS, Polled, Readings, XrayRun};
use crate::paths::Paths;

/// 2026-10-01T00:00:00Z and 2026-11-01T00:00:00Z.
const OCT: u64 = 1_790_812_800;
const NOV: u64 = 1_793_491_200;

fn email(text: &str) -> StatsEmail {
    text.parse().unwrap()
}

const fn bytes(uplink: u64, downlink: u64) -> Traffic {
    Traffic { uplink, downlink }
}

fn counters(entries: &[(&str, u64, u64)]) -> BTreeMap<StatsEmail, Traffic> {
    entries
        .iter()
        .map(|(name, up, down)| (email(name), bytes(*up, *down)))
        .collect()
}

fn readings(started: u64, entries: &[(&str, u64, u64)], probe_flows: u64) -> Readings {
    Readings {
        run: XrayRun {
            boot_id: "boot-1".to_owned(),
            started_secs: started,
        },
        counters: counters(entries),
        probe_flows,
    }
}

fn poll(paths: &Paths, at: u64, readings: Readings) -> Polled {
    let stored = accounting::load(paths).unwrap();
    accounting::poll(paths, stored, UnixTime::from_secs(at), readings).unwrap()
}

fn month(year: u16, month: u8) -> UsageMonth {
    UsageMonth::new(year, month).unwrap()
}

fn usage(paths: &Paths, now: u64, year: u16, number: u8) -> Result<UsageV1, AgentError> {
    accounting::usage(paths, UnixTime::from_secs(now), month(year, number))
}

fn five_min(from: u64, to: u64) -> SeriesRange {
    SeriesRange::new(
        UnixTime::from_secs(from),
        UnixTime::from_secs(to),
        Resolution::FiveMin,
    )
    .unwrap()
}

fn span(from: u64, to: u64, resolution: Resolution) -> SeriesSpan {
    SeriesSpan::new(
        UnixTime::from_secs(from),
        UnixTime::from_secs(to),
        resolution,
    )
    .unwrap()
}

#[test]
fn statsquery_is_read_as_the_pinned_source_prints_it() {
    let printed = br#"{
    "stat": [
        {
            "name": "user>>>u01@reality>>>traffic>>>downlink",
            "value": 2048
        },
        {
            "name": "user>>>probe@hy2>>>traffic>>>uplink"
        },
        {
            "name": "user>>>u01@reality>>>traffic>>>uplink",
            "value": 512
        },
        {
            "name": "user>>>probe@hy2>>>traffic>>>downlink",
            "value": 15
        }
    ]
}

"#;
    assert_eq!(
        parse_query(printed),
        Ok(counters(&[
            ("u01@reality", 512, 2048),
            ("probe@hy2", 0, 15)
        ]))
    );
    assert_eq!(
        parse_query(b"{}\n\n"),
        Ok(BTreeMap::new()),
        "nothing matched"
    );
    let pair = |up: &str, down: &str| {
        format!(
            r#"{{"stat":[{{"name":"user>>>u01@reality>>>traffic>>>uplink"{up}}},{{"name":"user>>>u01@reality>>>traffic>>>downlink"{down}}}]}}"#
        )
    };
    assert_eq!(
        parse_query(pair(r#","value":3"#, "").as_bytes()),
        Ok(counters(&[("u01@reality", 3, 0)]))
    );
    for bad in [
        r#"{"stat":[{"name":"user>>>u01@reality>>>traffic>>>uplink","value":1}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>u01@reality>>>traffic>>>uplink"},{"name":"user>>>u01@reality>>>traffic>>>uplink"},{"name":"user>>>u01@reality>>>traffic>>>downlink"}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>u01@reality>>>online"}]}"#.to_owned(),
        r#"{"stat":[{"name":"inbound>>>reality-in>>>traffic>>>uplink"}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>U 1@reality>>>traffic>>>uplink"},{"name":"user>>>U 1@reality>>>traffic>>>downlink"}]}"#.to_owned(),
        r#"{"stat":[{"name":"user>>>u01@reality>>>traffic>>>sideways"}]}"#.to_owned(),
        pair(r#","value":-1"#, ""),
        pair(r#","value":"1""#, ""),
        pair(r#","extra":1"#, ""),
        r#"{"stats":[]}"#.to_owned(),
        "failed to dial 127.0.0.1:10085".to_owned(),
    ] {
        assert_eq!(parse_query(bad.as_bytes()), Err(QueryFailed), "{bad}");
    }
}

#[test]
fn statssys_is_read_for_its_uptime_and_heap() {
    let printed = b"{\n    \"Alloc\": 52428800,\n    \"Frees\": 9,\n    \"LiveObjects\": 3,\n    \"Mallocs\": 12,\n    \"NumGC\": 4,\n    \"NumGoroutine\": 41,\n    \"PauseTotalNs\": 77,\n    \"Sys\": 90000000,\n    \"TotalAlloc\": 99,\n    \"Uptime\": 3600\n}\n\n";
    assert_eq!(
        parse_sys(printed),
        Ok(SysStats {
            uptime_secs: 3600,
            alloc_bytes: 52_428_800
        })
    );
    assert_eq!(
        parse_sys(br#"{"NumGoroutine": 1}"#),
        Ok(SysStats {
            uptime_secs: 0,
            alloc_bytes: 0
        }),
        "a zero is left out"
    );
    for bad in ["[]", r#"{"Uptime":"1"}"#, r#"{"Alloc":-1}"#, "not json"] {
        assert_eq!(parse_sys(bad.as_bytes()), Err(QueryFailed), "{bad}");
    }
}

#[test]
fn the_first_poll_is_a_baseline_and_each_poll_adds_its_growth() {
    let (_dir, paths) = scratch();
    let start = OCT + 10 * 86_400;
    let first = poll(&paths, start, readings(5, &[("u01@reality", 100, 1000)], 0));
    assert!(first.grew.is_empty());
    let recorded = usage(&paths, start, 2026, 10).unwrap();
    assert!(recorded.traffic.is_empty(), "the baseline adds nothing");
    assert_eq!(recorded.updated_at, UnixTime::from_secs(start));

    let second = poll(
        &paths,
        start + 60,
        readings(5, &[("u01@reality", 150, 3000), ("u02@hy2", 0, 0)], 0),
    );
    assert_eq!(second.grew, vec![email("u01@reality")]);
    // Two readings of one start differ by at most their rounding.
    let third = poll(
        &paths,
        start + 120,
        readings(7, &[("u01@reality", 150, 3000), ("u02@hy2", 7, 9)], 0),
    );
    assert_eq!(third.grew, vec![email("u02@hy2")]);
    let recorded = usage(&paths, start + 120, 2026, 10).unwrap();
    assert_eq!(
        recorded.traffic,
        counters(&[("u01@reality", 50, 2000), ("u02@hy2", 7, 9)])
    );
    assert_eq!(recorded.updated_at, UnixTime::from_secs(start + 120));
    assert_eq!(recorded.month, month(2026, 10));
}

#[test]
fn after_a_restart_counters_count_whole_and_a_reset_counter_from_zero() {
    let (_dir, paths) = scratch();
    let start = OCT + 86_400;
    poll(&paths, start, readings(5, &[("u01@reality", 100, 1000)], 0));
    poll(
        &paths,
        start + 60,
        readings(5, &[("u01@reality", 200, 1500)], 0),
    );
    // Xray started again, three seconds later than the run before.
    poll(
        &paths,
        start + 120,
        readings(8, &[("u01@reality", 30, 40)], 0),
    );
    // A counter below its reading: reset, counted from zero.
    poll(
        &paths,
        start + 180,
        readings(8, &[("u01@reality", 10, 50)], 0),
    );
    // Another boot whose Xray started at the same second since boot.
    poll(
        &paths,
        start + 240,
        Readings {
            run: XrayRun {
                boot_id: "boot-2".to_owned(),
                started_secs: 8,
            },
            ..readings(8, &[("u01@reality", 40, 60)], 0)
        },
    );
    assert_eq!(
        usage(&paths, start + 240, 2026, 10).unwrap().traffic,
        counters(&[("u01@reality", 100 + 30 + 10 + 40, 500 + 40 + 10 + 60)])
    );
}

#[test]
fn a_poll_a_crash_kept_out_of_its_month_is_taken_in_once_at_the_next_poll() {
    let (_dir, paths) = scratch();
    let start = OCT + 86_400;
    poll(&paths, start, readings(5, &[("u01@reality", 0, 0)], 0));
    poll(
        &paths,
        start + 60,
        readings(5, &[("u01@reality", 10, 100)], 0),
    );
    let file = paths.usage_month(month(2026, 10));
    let before_crash = fs::read(&file).unwrap();
    poll(
        &paths,
        start + 120,
        readings(5, &[("u01@reality", 30, 300)], 0),
    );
    // The crash: the month's file as it was before that poll's write.
    fs::write(&file, &before_crash).unwrap();
    assert_eq!(
        usage(&paths, start + 120, 2026, 10).unwrap().traffic,
        counters(&[("u01@reality", 10, 100)])
    );
    poll(
        &paths,
        start + 180,
        readings(5, &[("u01@reality", 60, 600)], 0),
    );
    assert_eq!(
        usage(&paths, start + 180, 2026, 10).unwrap().traffic,
        counters(&[("u01@reality", 60, 600)]),
        "the lost poll once, then this one"
    );
    poll(
        &paths,
        start + 240,
        readings(5, &[("u01@reality", 60, 600)], 0),
    );
    assert_eq!(
        usage(&paths, start + 240, 2026, 10).unwrap().traffic,
        counters(&[("u01@reality", 60, 600)]),
        "a poll already taken in is not added again"
    );
    assert_eq!(
        usage(&paths, start + 240, 2026, 10).unwrap().updated_at,
        UnixTime::from_secs(start + 180),
        "nor is the file rewritten when nothing grew"
    );
}

#[test]
fn a_poll_counts_in_the_month_of_its_last_second() {
    let (_dir, paths) = scratch();
    poll(&paths, NOV - 60, readings(5, &[("u01@reality", 0, 0)], 0));
    poll(&paths, NOV, readings(5, &[("u01@reality", 1, 2)], 0));
    poll(&paths, NOV + 60, readings(5, &[("u01@reality", 4, 8)], 0));
    assert_eq!(
        usage(&paths, NOV + 60, 2026, 10).unwrap().traffic,
        counters(&[("u01@reality", 1, 2)])
    );
    assert_eq!(
        usage(&paths, NOV + 60, 2026, 11).unwrap().traffic,
        counters(&[("u01@reality", 3, 6)])
    );
    assert_eq!(
        usage(&paths, NOV + 60, 2026, 12),
        Err(AgentError::NoUsageRecorded {
            month: month(2026, 12)
        })
    );
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
fn a_bin_is_gone_48_hours_after_it_ends_and_a_month_7_days_after_it_ends() {
    let (_dir, paths) = scratch();
    // From ten minutes before November to a minute into it, which gives
    // November a file.
    for minute in 0..=11 {
        poll(
            &paths,
            NOV - 600 + 60 * minute,
            readings(5, &[("u01@reality", minute, 0)], 0),
        );
    }
    let bin = five_min(NOV - 300, NOV);
    let kept_until = NOV + SERIES_KEEP_SECS;
    accounting::prune(&paths, UnixTime::from_secs(kept_until - 1)).unwrap();
    let kept = accounting::usage_series(&paths, UnixTime::from_secs(kept_until - 1), bin).unwrap();
    assert_eq!(
        kept.bins()[0].traffic(),
        &counters(&[("u01@reality", 5, 0)]),
        "kept to its last second"
    );
    assert_eq!(
        accounting::usage_series(&paths, UnixTime::from_secs(kept_until), bin),
        Err(AgentError::SeriesNotRecorded { recorded: None }),
        "never served once expired, whether or not it was pruned"
    );
    accounting::prune(&paths, UnixTime::from_secs(kept_until)).unwrap();
    assert_eq!(
        accounting::usage_series(&paths, UnixTime::from_secs(kept_until - 1), bin),
        Err(AgentError::SeriesNotRecorded { recorded: None }),
        "pruned"
    );

    let gone = NOV + MONTH_KEEP_SECS;
    assert!(usage(&paths, gone - 1, 2026, 10).is_ok());
    assert_eq!(
        usage(&paths, gone, 2026, 10),
        Err(AgentError::NoUsageRecorded {
            month: month(2026, 10)
        })
    );
    let leftover = paths.usage_dir().join(".2026-10.json.4242.tmp");
    fs::write(&leftover, "{}").unwrap();
    accounting::prune(&paths, UnixTime::from_secs(gone - 1)).unwrap();
    assert!(paths.usage_month(month(2026, 10)).exists());
    assert!(!leftover.exists(), "a crash's temporary file");
    accounting::prune(&paths, UnixTime::from_secs(gone)).unwrap();
    assert!(!paths.usage_month(month(2026, 10)).exists());
    assert!(paths.usage_month(month(2026, 11)).exists());
    assert!(paths.accounting().exists());
}

#[test]
fn the_canary_needs_a_probe_flow_in_the_same_run_and_no_probe_counter() {
    let (_dir, paths) = scratch();
    let start = OCT + 86_400;
    let user = [("u01@reality", 1, 1)];
    assert_eq!(
        poll(&paths, start, readings(5, &user, 0)).canary,
        Canary::Unknown
    );
    assert_eq!(
        poll(&paths, start + 60, readings(5, &user, 1)).canary,
        Canary::Missing
    );
    assert_eq!(
        poll(&paths, start + 120, readings(5, &user, 1)).canary,
        Canary::Unknown,
        "no new flow"
    );
    assert_eq!(
        poll(&paths, start + 180, readings(5, &user, 0)).canary,
        Canary::Unknown,
        "the ruleset was loaded again, and no flow since"
    );
    assert_eq!(
        poll(&paths, start + 240, readings(5, &user, 2)).canary,
        Canary::Missing
    );
    let reloaded = poll(&paths, start + 300, readings(5, &user, 1));
    assert_eq!(
        reloaded.canary,
        Canary::Missing,
        "loaded again, then a flow"
    );
    assert_eq!(
        poll(&paths, start + 360, readings(9, &user, 5)).canary,
        Canary::Unknown,
        "the flow may predate Xray's restart"
    );
    let counted = [("u01@reality", 1, 1), ("probe@hy2", 0, 0)];
    assert_eq!(
        poll(&paths, start + 420, readings(9, &counted, 5)).canary,
        Canary::Counted
    );
}

#[test]
fn usage_and_series_are_served_to_ops_and_the_viewer() {
    let (_dir, paths) = scratch();
    let node = FakeNode::new(OCT + 86_400 + 400);
    let october = LineRequest::Usage {
        month: month(2026, 10),
    };
    let series = LineRequest::UsageSeries(five_min(OCT + 86_400, OCT + 86_400 + 300));
    for role in [Role::Ops, Role::Viewer] {
        assert_eq!(
            ask(&paths, &node, role, frame(&october)),
            Err(AgentError::NoUsageRecorded {
                month: month(2026, 10)
            })
        );
        assert_eq!(
            ask(&paths, &node, role, frame(&series)),
            Err(AgentError::SeriesNotRecorded { recorded: None })
        );
    }
    for minute in 0..=6 {
        poll(
            &paths,
            OCT + 86_400 + 60 * minute,
            readings(5, &[("u01@reality", minute, 2 * minute)], 0),
        );
    }
    for role in [Role::Ops, Role::Viewer] {
        let Ok(Response::Usage(recorded)) = ask(&paths, &node, role, frame(&october)) else {
            panic!("{role:?}");
        };
        assert_eq!(recorded.traffic, counters(&[("u01@reality", 6, 12)]));
        let Ok(Response::UsageSeries(reply)) = ask(&paths, &node, role, frame(&series)) else {
            panic!("{role:?}");
        };
        assert_eq!(
            reply.bins()[0].traffic(),
            &counters(&[("u01@reality", 5, 10)])
        );
    }
    assert!(node.calls().is_empty());
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
