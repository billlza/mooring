// SPDX-License-Identifier: GPL-3.0-or-later

//! Accounting (design §11.5): every poll counted once, in the month of
//! its last second: the first a baseline, counters whole after a restart
//! and a reset one from zero, a poll a crash kept out of its month taken
//! in once at the next, and one past the last month refused; the canary;
//! and the usage requests, served to ops and the viewer. Xray's API
//! output, the series and retention have files of their own, which share
//! the helpers here.

mod retention;
mod series;
mod stats;

use std::collections::BTreeMap;
use std::fs;

use mooring_agent_proto::{
    AgentError, IoOp, LineRequest, Resolution, Response, Role, SeriesRange, StatsEmail, Traffic,
    UnixTime, UsageMonth, UsageV1,
};

use super::serve::{ask, frame};
use super::{FakeNode, scratch};
use crate::accounting::{self, Canary, Polled, Readings, XrayRun};
use crate::paths::Paths;
use crate::store::malformed;

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
fn a_poll_whose_last_second_is_past_the_last_month_is_refused() {
    // 10000-01-01T00:00:00Z: its last second is 9999-12's.
    let (_dir, paths) = scratch();
    poll(&paths, 253_402_300_800, readings(5, &[], 0));
    assert!(paths.usage_month(month(9999, 12)).exists());
    let (_dir, paths) = scratch();
    assert_eq!(
        accounting::poll(
            &paths,
            None,
            UnixTime::from_secs(253_402_300_801),
            readings(5, &[], 0)
        ),
        Err(malformed(IoOp::WriteState))
    );
}
