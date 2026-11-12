// SPDX-License-Identifier: GPL-3.0-or-later

//! A user's use of the billing cycle before an instant (design §9.6: a
//! traffic pack refunded in full keeps what the user had used of it by the
//! refund's time). It is the cycle's figure less the closed bins that begin
//! at or after the first five-minute boundary a poll's longest gap after
//! the instant, so never fewer bytes than the nodes had counted for the
//! user by the instant; and no figure when the report does not reach that
//! boundary or cannot tell the cycle's.
//!
//! What a node counts as it flows is what the user had served. The
//! downlink of a REALITY connection is counted only when the connection
//! closes: of a download open at the instant and still open at the
//! boundary the counters tell nothing, and its bytes count after the
//! instant.

use std::collections::BTreeMap;

use mooring_agent_proto::{Inbound, MAX_POLL_GAP_SECS, Resolution};
use mooring_model::{Deployment, UnixTime, UserId};

use super::collected_usage::{empty_other, month, today_history};
use super::support::{at, deployment_billed_on, email, node, probe, series, traffic, user_ids};
use crate::error::{UsageError, UsageErrorKind};
use crate::usage::{CollectedUsage, NodeUsageHistory};

fn after(time: UnixTime, secs: u64) -> UnixTime {
    UnixTime::from_secs(time.as_secs() + secs)
}

/// What `history` tells at `now` of `user`'s use before `at`.
fn before(
    history: &CollectedUsage,
    deployment: &Deployment,
    now: UnixTime,
    user: &UserId,
    at: UnixTime,
) -> Option<u64> {
    history
        .cycle_served_before(deployment, now, user, at)
        .unwrap()
}

/// A poll's longest gap is three minutes: the bins taken off begin at
/// least that long after the instant.
#[test]
fn a_polls_longest_gap_is_three_minutes() {
    assert_eq!(MAX_POLL_GAP_SECS, 180);
}

/// The user served 100 bytes this cycle, 30 of them in the bin from 00:05
/// to 00:10 on the 5th. That bin can hold bytes served from 00:02 on, so
/// before an instant up to 00:02 the user had served 70, and from a second
/// later all 100: what a bin may hold from before the instant counts as
/// used. So do the bytes of detail that was never collected (before the
/// 5th), which nothing places after the instant. An instant before the
/// cycle began is its beginning. The probe's bytes in the same bin are no
/// user's.
#[test]
fn the_use_before_an_instant_is_the_cycles_less_the_bins_that_begin_a_polls_gap_after_it() {
    let deployment = deployment_billed_on(1);
    let (history, now) = today_history();
    let user = &user_ids()[0];
    for (instant, expected) in [
        (at("2026-11-05", 0), 70),
        (at("2026-11-05", 120), 70),
        (at("2026-11-05", 121), 100),
        (at("2026-11-05", 300), 100),
        (at("2026-11-05", 12 * 3600 - 180), 100),
        (at("2026-11-03", 0), 70),
        (at("2026-11-01", 0), 70),
        (at("2026-10-20", 0), 70),
    ] {
        assert_eq!(
            before(&history, &deployment, now, user, instant),
            Some(expected),
            "{instant:?}"
        );
    }
    // A user who served nothing had served nothing.
    assert_eq!(
        before(
            &history,
            &deployment,
            now,
            &user_ids()[1],
            at("2026-11-05", 0)
        ),
        Some(0)
    );
}

/// A report tells nothing of an instant unless it reaches the boundary a
/// poll's gap after it: every node's figures sampled at or after that
/// boundary, and the boundary not after `now`. Both nodes were sampled at
/// noon, which reaches an instant three minutes before and none later,
/// whenever the report is made. With one node sampled two minutes after
/// noon and the other five, the boundary at five past is reached by one
/// node only, and nothing is told of an instant that needs it.
#[test]
fn a_report_that_does_not_reach_a_polls_gap_past_the_instant_tells_nothing() {
    let deployment = deployment_billed_on(1);
    let (history, noon) = today_history();
    let user = &user_ids()[0];
    let reached = UnixTime::from_secs(noon.as_secs() - 180);
    for now in [noon, after(noon, 100)] {
        assert_eq!(before(&history, &deployment, now, user, reached), Some(100));
        assert_eq!(
            before(&history, &deployment, now, user, after(reached, 1)),
            None
        );
        assert_eq!(
            before(&history, &deployment, now, user, after(now, 1)),
            None
        );
    }
    // A report that cannot be made is its error, not a figure.
    assert_eq!(
        history
            .cycle_served_before(&deployment, after(noon, 181), user, reached)
            .unwrap_err()
            .kind(),
        UsageErrorKind::NotCoveredThrough
    );
    let mut lon = NodeUsageHistory::default();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-11",
            after(noon, 120),
            vec![(email(user, Inbound::Reality), traffic(40, 60))],
        ),
        after(noon, 120),
    )
    .unwrap();
    let mut ams = NodeUsageHistory::default();
    ams.record_month(
        &node("ams1"),
        month("2026-11", after(noon, 300), vec![]),
        after(noon, 300),
    )
    .unwrap();
    let mut apart = CollectedUsage::default();
    apart.set_node(node("lon1"), lon);
    apart.set_node(node("ams1"), ams);
    let now = after(noon, 300);
    assert_eq!(before(&apart, &deployment, now, user, reached), Some(100));
    assert_eq!(
        before(&apart, &deployment, now, user, after(noon, 100)),
        None
    );
}

/// Without a cycle figure there is no use to tell: the deployment does not
/// hold the user, or the split across the bill day was lost. The report
/// reaches the instant: it tells another user's use before it.
#[test]
fn a_cycle_figure_that_cannot_be_told_gives_no_use() {
    let (mut history, now) = today_history();
    let user = &user_ids()[0];
    let instant = at("2026-11-05", 11 * 3600);
    let billed_on_the_first = deployment_billed_on(1);
    let stranger = UserId::parse("strangerxx").unwrap();
    assert_eq!(
        before(&history, &billed_on_the_first, now, &stranger, instant),
        None
    );
    assert_eq!(
        before(&history, &billed_on_the_first, now, user, instant),
        Some(100)
    );
    let mut lon = history.node(&node("lon1")).unwrap().clone();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-10",
            at("2026-10-31", 86_399),
            vec![(email(user, Inbound::Reality), traffic(100, 100))],
        ),
        now,
    )
    .unwrap();
    history.set_node(node("lon1"), lon);
    let deployment = deployment_billed_on(28);
    assert_eq!(
        history.aggregate(&deployment, now).unwrap().users[user].cycle_served_bytes(),
        None
    );
    assert_eq!(before(&history, &deployment, now, user, instant), None);
    assert_eq!(
        before(&history, &deployment, now, &user_ids()[1], instant),
        Some(0)
    );
}

/// Every node's use counts, each less its own later bins: 100 bytes on
/// lon1 with 30 of them at 00:05, and 10 on ams1 with 2 of them at 06:00.
/// The history of a node the deployment no longer holds is in no figure,
/// and its bins take nothing off.
#[test]
fn every_node_counts_less_its_own_later_bins() {
    let deployment = deployment_billed_on(1);
    let (mut history, now) = today_history();
    let user = &user_ids()[0];
    let mut ams = NodeUsageHistory::default();
    ams.record_series(
        &node("ams1"),
        &series(
            at("2026-11-05", 0),
            now,
            Resolution::FiveMin,
            vec![(
                at("2026-11-05", 6 * 3600),
                vec![
                    (email(user, Inbound::Hy2), traffic(1, 1)),
                    (probe(Inbound::Hy2), traffic(0, 70)),
                ],
            )],
        ),
    )
    .unwrap();
    ams.record_month(
        &node("ams1"),
        month(
            "2026-11",
            now,
            vec![
                (email(user, Inbound::Hy2), traffic(7, 3)),
                (probe(Inbound::Hy2), traffic(0, 90)),
            ],
        ),
        now,
    )
    .unwrap();
    history.set_node(node("ams1"), ams.clone());
    history.set_node(node("par1"), ams);
    for (instant, expected) in [
        (at("2026-11-05", 0), 78),
        (at("2026-11-05", 3 * 3600), 108),
        (at("2026-11-05", 6 * 3600 - 180), 108),
        (at("2026-11-05", 6 * 3600 - 179), 110),
        (at("2026-11-05", 12 * 3600 - 180), 110),
    ] {
        assert_eq!(
            before(&history, &deployment, now, user, instant),
            Some(expected),
            "{instant:?}"
        );
    }
}

/// An instant before the cycle began is its beginning: the bins of the
/// cycle before take nothing off. The cycle begins on the 5th, with 30
/// bytes at 00:05; the 8 bytes of the 4th are the cycle before's.
#[test]
fn bins_before_the_cycle_began_take_nothing_off() {
    let deployment = deployment_billed_on(5);
    let (mut history, now) = today_history();
    let user = &user_ids()[0];
    let mut lon = history.node(&node("lon1")).unwrap().clone();
    lon.record_series(
        &node("lon1"),
        &series(
            at("2026-11-04", 12 * 3600),
            at("2026-11-05", 0),
            Resolution::FiveMin,
            vec![(
                at("2026-11-04", 23 * 3600),
                vec![(email(user, Inbound::Reality), traffic(4, 4))],
            )],
        ),
    )
    .unwrap();
    history.set_node(node("lon1"), lon);
    assert_eq!(
        history.aggregate(&deployment, now).unwrap().users[user].cycle_served_bytes(),
        Some(30)
    );
    for (instant, expected) in [
        (at("2026-11-04", 22 * 3600), 0),
        (at("2026-11-05", 0), 0),
        (at("2026-11-05", 121), 30),
    ] {
        assert_eq!(
            before(&history, &deployment, now, user, instant),
            Some(expected),
            "{instant:?}"
        );
    }
}

/// A bin the node's monthly figure does not reach takes nothing off. The
/// figure was read at 11:57, so it holds the 4 bytes of the bin from 11:50
/// and an unknown part of the 6 from 11:55: those count as used before any
/// instant the report reaches, and it reaches none after 11:52.
#[test]
fn a_bin_the_monthly_figure_does_not_reach_takes_nothing_off() {
    let deployment = deployment_billed_on(1);
    let user = &user_ids()[0];
    let now = at("2026-11-05", 12 * 3600);
    let read = at("2026-11-05", 12 * 3600 - 180);
    let mut lon = NodeUsageHistory::default();
    lon.record_series(
        &node("lon1"),
        &series(
            at("2026-11-05", 0),
            now,
            Resolution::FiveMin,
            vec![
                (
                    at("2026-11-05", 12 * 3600 - 600),
                    vec![(email(user, Inbound::Reality), traffic(1, 3))],
                ),
                (
                    at("2026-11-05", 12 * 3600 - 300),
                    vec![(email(user, Inbound::Reality), traffic(2, 4))],
                ),
            ],
        ),
    )
    .unwrap();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-11",
            read,
            vec![(email(user, Inbound::Reality), traffic(40, 60))],
        ),
        now,
    )
    .unwrap();
    let mut history = CollectedUsage::default();
    history.set_node(node("lon1"), lon);
    empty_other(&mut history, now);
    for (instant, expected) in [
        (at("2026-11-05", 11 * 3600), Some(96)),
        (at("2026-11-05", 12 * 3600 - 480), Some(100)),
        (at("2026-11-05", 12 * 3600 - 479), None),
    ] {
        assert_eq!(
            before(&history, &deployment, now, user, instant),
            expected,
            "{instant:?}"
        );
    }
}

/// The user served 100 bytes this cycle on lon1: 30 at 10:05 and 12 at
/// 10:40 on the 2nd, the rest never placed.
fn two_bins_on_the_second(now: UnixTime) -> CollectedUsage {
    let user = &user_ids()[0];
    let mut lon = NodeUsageHistory::default();
    lon.record_series(
        &node("lon1"),
        &series(
            at("2026-11-02", 0),
            at("2026-11-02", 12 * 3600),
            Resolution::FiveMin,
            vec![
                (
                    at("2026-11-02", 10 * 3600 + 300),
                    vec![(email(user, Inbound::Reality), traffic(10, 20))],
                ),
                (
                    at("2026-11-02", 10 * 3600 + 2400),
                    vec![(email(user, Inbound::Reality), traffic(5, 7))],
                ),
            ],
        ),
    )
    .unwrap();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-11",
            now,
            vec![(email(user, Inbound::Reality), traffic(40, 60))],
        ),
        now,
    )
    .unwrap();
    let mut history = CollectedUsage::default();
    history.set_node(node("lon1"), lon);
    empty_other(&mut history, now);
    history
}

/// While the five-minute bins are held, the use before 10:17 leaves out
/// the 12 bytes of 10:40. Once they have expired (seven days) only the
/// hour from 10:00 is held. An instant whose boundary is 10:00 still
/// leaves that hour out whole; a second later the boundary is 10:05, the
/// hour begins before it, and its bytes cannot be placed after it, so all
/// of them count as used.
#[test]
fn once_its_five_minute_bins_have_expired_the_hour_counts_as_used() {
    let deployment = deployment_billed_on(1);
    let user = &user_ids()[0];
    let now = at("2026-11-20", 12 * 3600);
    let mut history = two_bins_on_the_second(now);
    let ten = 10 * 3600;
    for (secs, expected) in [
        (ten - 180, 58),
        (ten + 1020, 88),
        (ten + 2220, 88),
        (ten + 2221, 100),
    ] {
        assert_eq!(
            before(&history, &deployment, now, user, at("2026-11-02", secs)),
            Some(expected),
            "{secs}"
        );
    }
    history.prune(&deployment, now).unwrap();
    for (secs, expected) in [(ten - 180, 58), (ten - 179, 100), (ten + 1020, 100)] {
        assert_eq!(
            before(&history, &deployment, now, user, at("2026-11-02", secs)),
            Some(expected),
            "{secs}"
        );
    }
}

/// Closed bins that hold more than the cycle's figure contradict it, and
/// are an error, not a use of nothing. The cycle began on 28 October;
/// October's total, read a second before the month ended, counts 100
/// bytes, and the last bin of the month, which that reading does not
/// bound, holds 1000.
#[test]
fn bins_that_hold_more_than_the_cycle_are_a_contradiction() {
    let deployment = deployment_billed_on(28);
    let now = at("2026-11-05", 12 * 3600);
    let user = &user_ids()[0];
    let mut lon = NodeUsageHistory::default();
    // Detail whole from the month's start to the cycle's: a proven prefix
    // of nothing.
    let mut from = at("2026-10-01", 0);
    while from < at("2026-10-28", 0) {
        let to = after(from, 12 * 3600);
        lon.record_series(
            &node("lon1"),
            &series(from, to, Resolution::FiveMin, vec![]),
        )
        .unwrap();
        from = to;
    }
    lon.record_series(
        &node("lon1"),
        &series(
            at("2026-10-31", 12 * 3600),
            at("2026-11-01", 0),
            Resolution::FiveMin,
            vec![(
                at("2026-10-31", 86_100),
                vec![(email(user, Inbound::Reality), traffic(0, 1000))],
            )],
        ),
    )
    .unwrap();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-10",
            at("2026-10-31", 86_399),
            vec![(email(user, Inbound::Reality), traffic(0, 100))],
        ),
        now,
    )
    .unwrap();
    lon.record_month(
        &node("lon1"),
        month(
            "2026-11",
            now,
            vec![(email(user, Inbound::Reality), traffic(0, 50))],
        ),
        now,
    )
    .unwrap();
    let mut history = CollectedUsage::default();
    history.set_node(node("lon1"), lon);
    empty_other(&mut history, now);
    assert_eq!(
        history.aggregate(&deployment, now).unwrap().users[user].cycle_served_bytes(),
        Some(150)
    );
    assert!(matches!(
        history.cycle_served_before(&deployment, now, user, at("2026-10-29", 0)),
        Err(UsageError::MonthlyInconsistent { node: contradicted }) if contradicted == node("lon1")
    ));
    // From November on, the bin is before the boundary, and is not asked.
    assert_eq!(
        before(&history, &deployment, now, user, at("2026-11-01", 0)),
        Some(150)
    );
}

/// A cycle that began after the month did, with the detail broken inside
/// it: its figure is the month's total less what the detail proves came
/// before the cycle. The user served 100 bytes in November, 40 of them on
/// the 2nd, before the cycle began on the 3rd; nothing was collected of
/// the 3rd and the 4th; 30 were counted in the bin from 00:05 on the 5th.
#[test]
fn a_cycle_begun_mid_month_counts_the_months_total_less_what_came_before_it() {
    let deployment = deployment_billed_on(3);
    let (mut history, now) = today_history();
    let user = &user_ids()[0];
    let mut lon = history.node(&node("lon1")).unwrap().clone();
    let mut from = at("2026-11-01", 0);
    while from < at("2026-11-03", 0) {
        let to = after(from, 12 * 3600);
        let bins = if from == at("2026-11-02", 0) {
            vec![(
                at("2026-11-02", 10 * 3600),
                vec![(email(user, Inbound::Reality), traffic(15, 25))],
            )]
        } else {
            Vec::new()
        };
        lon.record_series(&node("lon1"), &series(from, to, Resolution::FiveMin, bins))
            .unwrap();
        from = to;
    }
    history.set_node(node("lon1"), lon);
    assert_eq!(
        history.aggregate(&deployment, now).unwrap().users[user].cycle_served_bytes(),
        Some(60)
    );
    for (instant, expected) in [
        (at("2026-11-02", 0), 30),
        (at("2026-11-03", 0), 30),
        (at("2026-11-04", 12 * 3600), 30),
        (at("2026-11-05", 120), 30),
        (at("2026-11-05", 121), 60),
    ] {
        assert_eq!(
            before(&history, &deployment, now, user, instant),
            Some(expected),
            "{instant:?}"
        );
    }
}

/// Polls a minute apart from `from`, as many as end by `until`.
fn each_minute(from: u64, until: u64) -> Vec<u64> {
    (from..=until).step_by(60).collect()
}

/// What the Mac holds at `now` of a user whose bytes a node counts as they
/// flow, one a second from the first of `polls` on, by the agent's rules
/// (design §11.5; `mooring-agent`'s `accounting::series`):
///
/// - a poll adds what was counted since the poll before to the month;
/// - when it follows the poll before within the longest gap, it adds it
///   also to the five-minute bin holding the second before it; after a
///   longer gap it starts a new stretch, and what it added is in no bin;
/// - a bin is held only inside one stretch, from the bin's start to its
///   end, and the Mac holds the bins the agent held;
/// - the month's figure is the total by the last poll.
///
/// Hysteria2 is counted so; the downlink of a REALITY connection is
/// counted only when the connection closes.
fn counted_as_it_flows(polls: &[u64], now: UnixTime) -> CollectedUsage {
    let user = &user_ids()[0];
    let (first, last) = (polls[0], polls[polls.len() - 1]);
    let mut bins = BTreeMap::<u64, u64>::new();
    let mut stretches = vec![(first, first)];
    for pair in polls.windows(2) {
        if pair[1] - pair[0] <= MAX_POLL_GAP_SECS {
            *bins.entry((pair[1] - 1) / 300 * 300).or_default() += pair[1] - pair[0];
            stretches.last_mut().unwrap().1 = pair[1];
        } else {
            stretches.push((pair[1], pair[1]));
        }
    }
    let mut lon = NodeUsageHistory::default();
    for (from, through) in stretches {
        let (from, to) = (from.next_multiple_of(300), through / 300 * 300);
        if from >= to {
            continue;
        }
        lon.record_series(
            &node("lon1"),
            &series(
                UnixTime::from_secs(from),
                UnixTime::from_secs(to),
                Resolution::FiveMin,
                bins.range(from..to)
                    .map(|(start, bytes)| {
                        (
                            UnixTime::from_secs(*start),
                            vec![(email(user, Inbound::Hy2), traffic(0, *bytes))],
                        )
                    })
                    .collect(),
            ),
        )
        .unwrap();
    }
    lon.record_month(
        &node("lon1"),
        month(
            "2026-11",
            UnixTime::from_secs(last),
            vec![(email(user, Inbound::Hy2), traffic(0, last - first))],
        ),
        now,
    )
    .unwrap();
    let mut history = CollectedUsage::default();
    history.set_node(node("lon1"), lon);
    empty_other(&mut history, now);
    history
}

/// Traffic counted as it flows is never placed after an instant it was
/// served before: the figure is never less than what the user had served
/// by the instant. The agent polls from 23:50:07 on the 4th, a minute
/// apart; then at 01:02:00 and, after a gap of exactly three minutes, at
/// 01:05:00, and from then on the minute, so on every five-minute
/// boundary, to a minute before noon. The instants asked about lie a
/// second apart across that gap and the boundaries after it, and across
/// the end of what the report reaches.
///
/// It is so whether the cycle's figure is the month's total (billed on the
/// 1st) or the whole detail since midnight (billed on the 5th), which
/// stops at the last closed bin. The figure is at most thirteen minutes'
/// traffic more: eight to the boundary, and five that the last closed bin
/// leaves out. From eight minutes before noon on, the report does not
/// reach, and tells nothing.
#[test]
fn traffic_counted_as_it_flows_is_never_placed_after_an_instant_it_was_served_before() {
    let noon = at("2026-11-05", 12 * 3600);
    let midnight = at("2026-11-05", 0).as_secs();
    let first = midnight - 593;
    let mut polls = each_minute(first, midnight + 3667);
    polls.push(midnight + 3720);
    polls.extend(each_minute(midnight + 3900, noon.as_secs() - 60));
    let history = counted_as_it_flows(&polls, noon);
    let user = &user_ids()[0];
    let reached = noon.as_secs() - 480;
    for (bill_day, began, whole) in [(1, first, 43_733), (5, midnight, 42_953)] {
        let deployment = deployment_billed_on(bill_day);
        assert_eq!(
            history.aggregate(&deployment, noon).unwrap().users[user].cycle_served_bytes(),
            Some(whole)
        );
        let windows = [
            midnight + 3600..=midnight + 4320,
            noon.as_secs() - 900..=noon.as_secs(),
        ];
        for instant in windows.into_iter().flatten() {
            let served = instant - began;
            match before(
                &history,
                &deployment,
                noon,
                user,
                UnixTime::from_secs(instant),
            ) {
                Some(figure) => {
                    assert!(instant <= reached, "{bill_day} {instant}");
                    assert!(
                        (served..=served + 780).contains(&figure),
                        "{bill_day} {instant}: {figure} for {served}"
                    );
                }
                None => assert!(instant > reached, "{bill_day} {instant}"),
            }
        }
    }
}

/// A gap between two polls longer than three minutes, from 02:00:07 to
/// 02:06:47: what was counted across it is in the month's figure and in no
/// bin, and the bins from 02:00 to 02:10 are not held. Those bytes cannot
/// be placed, so they count as used before any instant, and the figure is
/// still never less than what the user had served by it. A cycle that
/// began on the 5th has no figure then: the detail since it began is
/// broken and nothing proves what came before it, so nothing is told.
#[test]
fn what_was_counted_across_a_gap_between_polls_counts_as_used() {
    let noon = at("2026-11-05", 12 * 3600);
    let midnight = at("2026-11-05", 0).as_secs();
    let first = midnight - 593;
    let mut polls = each_minute(first, midnight + 7207);
    polls.extend(each_minute(midnight + 7607, noon.as_secs()));
    let history = counted_as_it_flows(&polls, noon);
    let user = &user_ids()[0];
    let deployment = deployment_billed_on(1);
    assert_eq!(
        history.aggregate(&deployment, noon).unwrap().users[user].cycle_served_bytes(),
        Some(43_780)
    );
    for instant in midnight + 6600..=midnight + 8100 {
        let served = instant - first;
        let figure = before(
            &history,
            &deployment,
            noon,
            user,
            UnixTime::from_secs(instant),
        )
        .unwrap();
        assert!(
            (served..=served + 1_420).contains(&figure),
            "{instant}: {figure} for {served}"
        );
    }
    let begun_on_the_fifth = deployment_billed_on(5);
    assert_eq!(
        history.aggregate(&begun_on_the_fifth, noon).unwrap().users[user].cycle_served_bytes(),
        None
    );
    for instant in [midnight + 3600, midnight + 7300, midnight + 9000] {
        assert_eq!(
            before(
                &history,
                &begun_on_the_fifth,
                noon,
                user,
                UnixTime::from_secs(instant)
            ),
            None
        );
    }
}
