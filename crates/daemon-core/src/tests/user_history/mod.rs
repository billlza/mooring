// SPDX-License-Identifier: GPL-3.0-or-later

//! One user's retained usage (`CollectedUsage::user_history`, design
//! §15.3): the exact bytes per node, tier and protocol, nothing of the probe
//! or of another user, the stretches held and their gaps, the retention a
//! read applies as the prune would, the revoked user's deadline, and every
//! refusal. Every history is built as the collector builds it, through
//! `record_series`, `record_month`, `observe_unserved` and `prune`.

mod errors;
mod golden;
mod retention;

use mooring_agent_proto::{Inbound, Resolution, StatsEmail, Traffic, UsageMonth};
use mooring_model::{UnixTime, UserId};

use super::collected_usage::month;
use super::support::{at, deployment, email, node, probe, series, traffic, user_ids};
use crate::usage::ProtocolTraffic;
use crate::usage::history::{
    Bin, HeldRange, MonthTotal, NodeHistory, NodeStage, Retention, Tier, Totals, UsageScope,
    UserState,
};
use crate::usage::{CollectedUsage, NodeUsageHistory};

use Inbound::{Hy2, Reality};

/// The instant most tests read at: 2026-11-05T12:00:00Z.
fn now() -> UnixTime {
    at("2026-11-05", 12 * 3600)
}

/// `secs` seconds after `now`.
fn later(secs: u64) -> UnixTime {
    UnixTime::from_secs(now().as_secs() + secs)
}

/// A bin's or a month's entries.
type Entries = Vec<(StatsEmail, Traffic)>;

/// Records five-minute detail over `[from, to)` as the collector pulls it,
/// in pages of at most the agent's 144 bins, each bin of `entries` in its
/// page.
fn detail(
    history: &mut NodeUsageHistory,
    id: &str,
    from: UnixTime,
    to: UnixTime,
    entries: &[(UnixTime, Entries)],
) {
    let mut start = from.as_secs();
    while start < to.as_secs() {
        let end = to.as_secs().min(start + 144 * 300);
        let page = entries
            .iter()
            .filter(|(at, _)| (start..end).contains(&at.as_secs()))
            .cloned()
            .collect();
        history
            .record_series(
                &node(id),
                &series(
                    UnixTime::from_secs(start),
                    UnixTime::from_secs(end),
                    Resolution::FiveMin,
                    page,
                ),
            )
            .unwrap();
        start = end;
    }
}

/// Records the month `name` as sampled at `updated` and received at
/// `received`.
fn monthly(
    history: &mut NodeUsageHistory,
    id: &str,
    name: &str,
    updated: UnixTime,
    received: UnixTime,
    entries: Entries,
) {
    history
        .record_month(&node(id), month(name, updated, entries), received)
        .unwrap();
}

/// The fixture's first user, whose history the tests read.
fn subject() -> UserId {
    user_ids()[0].clone()
}

/// Its second user, whose traffic shares the subject's bins.
fn other() -> UserId {
    user_ids()[1].clone()
}

/// Its third user, which had no traffic anywhere.
fn idle() -> UserId {
    user_ids()[2].clone()
}

/// What the daemon would hold at [`now`]:
/// - lon1: detail from 2026-11-04 through now, so 36 hours and the day of
///   the 4th, with the subject on both protocols, the other user and the
///   probe sharing a bin of the 5th; and November so far.
/// - ams1: detail from midnight through now, the subject on Hysteria2
///   only; and November so far.
fn served() -> CollectedUsage {
    let (subject, other) = (subject(), other());
    let mut lon = NodeUsageHistory::default();
    detail(
        &mut lon,
        "lon1",
        at("2026-11-04", 0),
        now(),
        &[
            (
                at("2026-11-04", 3600),
                vec![(email(&subject, Reality), traffic(100, 1000))],
            ),
            (
                at("2026-11-04", 13 * 3600 + 300),
                vec![(email(&subject, Hy2), traffic(20, 200))],
            ),
            (
                at("2026-11-05", 6 * 3600 + 300),
                vec![
                    (email(&subject, Reality), traffic(1200, 34_000)),
                    (email(&subject, Hy2), traffic(5, 7)),
                ],
            ),
            (
                at("2026-11-05", 6 * 3600 + 600),
                vec![(email(&subject, Reality), traffic(100, 200))],
            ),
            (
                at("2026-11-05", 9 * 3600 + 1800),
                vec![
                    (email(&other, Reality), traffic(999, 9_999)),
                    (probe(Reality), traffic(0, 500)),
                    (probe(Hy2), traffic(0, 600)),
                ],
            ),
        ],
    );
    monthly(
        &mut lon,
        "lon1",
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later_than_midnight(11 * 3600 + 59 * 60),
        vec![
            (email(&subject, Reality), traffic(1400, 35_200)),
            (email(&subject, Hy2), traffic(25, 207)),
            (email(&other, Reality), traffic(999, 9_999)),
            (probe(Reality), traffic(0, 500)),
            (probe(Hy2), traffic(0, 600)),
        ],
    );
    let mut ams = NodeUsageHistory::default();
    detail(
        &mut ams,
        "ams1",
        at("2026-11-05", 0),
        now(),
        &[(
            at("2026-11-05", 3 * 3600),
            vec![(email(&subject, Hy2), traffic(7, 8))],
        )],
    );
    monthly(
        &mut ams,
        "ams1",
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later_than_midnight(11 * 3600 + 59 * 60),
        vec![(email(&subject, Hy2), traffic(7, 8))],
    );
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), lon);
    collected.set_node(node("ams1"), ams);
    collected
}

/// `secs` seconds after the midnight that starts 2026-11-05.
fn later_than_midnight(secs: u64) -> UnixTime {
    at("2026-11-05", secs)
}

/// `[from, to)`.
const fn range(from: UnixTime, to: UnixTime) -> HeldRange {
    HeldRange { from, to }
}

/// The user's bytes: REALITY's and Hysteria2's, each `(up, down)`.
const fn bytes(reality: (u64, u64), hy2: (u64, u64)) -> ProtocolTraffic {
    ProtocolTraffic {
        reality: traffic(reality.0, reality.1),
        hy2: traffic(hy2.0, hy2.1),
    }
}

const fn bin(start: UnixTime, bytes: ProtocolTraffic) -> Bin {
    Bin { start, bytes }
}

fn november(bytes: ProtocolTraffic) -> MonthTotal {
    MonthTotal {
        month: "2026-11".parse::<UsageMonth>().unwrap(),
        counted_through: later_than_midnight(11 * 3600 + 58 * 60),
        is_final: false,
        bytes,
    }
}

const fn nothing() -> Tier {
    Tier {
        held: Vec::new(),
        bins: Vec::new(),
    }
}

/// Every byte lands in the user's own bins, per node, tier and protocol:
/// an hour holds the sum of its five-minute bins and a day the sum of its
/// hours; the months are the nodes' own totals.
#[test]
fn the_bins_and_totals_hold_exactly_the_users_bytes_per_node_and_protocol() {
    let history = served()
        .user_history(&deployment(), &subject(), now(), UsageScope::All)
        .unwrap();
    assert_eq!(history.user(), &subject());
    assert_eq!(history.alias(), None);
    assert_eq!(history.status(), UserState::Active);
    assert_eq!(history.retention(), Retention::Tiered);
    assert_eq!(history.generated_at(), now());
    assert_eq!(history.scope(), UsageScope::All);
    assert_eq!(
        history.nodes(),
        [
            NodeHistory {
                node: node("ams1"),
                stage: NodeStage::Applied,
                hourly: Tier {
                    held: vec![range(at("2026-11-05", 0), now())],
                    bins: vec![bin(at("2026-11-05", 3 * 3600), bytes((0, 0), (7, 8)))],
                },
                daily: nothing(),
                totals: Some(Totals {
                    months: vec![november(bytes((0, 0), (7, 8)))],
                    folded: None,
                    lifetime: None,
                }),
            },
            NodeHistory {
                node: node("lon1"),
                stage: NodeStage::Applied,
                hourly: Tier {
                    held: vec![range(at("2026-11-04", 0), now())],
                    bins: vec![
                        bin(at("2026-11-04", 3600), bytes((100, 1000), (0, 0))),
                        bin(at("2026-11-04", 13 * 3600), bytes((0, 0), (20, 200))),
                        bin(at("2026-11-05", 6 * 3600), bytes((1300, 34_200), (5, 7))),
                    ],
                },
                daily: Tier {
                    held: vec![range(at("2026-11-04", 0), at("2026-11-05", 0))],
                    bins: vec![bin(at("2026-11-04", 0), bytes((100, 1000), (20, 200)))],
                },
                totals: Some(Totals {
                    months: vec![november(bytes((1400, 35_200), (25, 207)))],
                    folded: None,
                    lifetime: None,
                }),
            },
        ]
    );
}

/// Another user's bytes and the probe's never count as the user's, even in
/// a bin they share: that hour is held but not listed for the subject; the
/// other user sees only its own bytes; and a user with no traffic sees
/// every stretch held with no bin in it and its months as real zeros.
#[test]
fn probes_and_other_users_are_never_counted_as_the_users() {
    let collected = served();
    let deployment = deployment();
    let read = |user: &UserId| {
        collected
            .user_history(&deployment, user, now(), UsageScope::All)
            .unwrap()
    };
    let theirs = read(&other());
    let lon = &theirs.nodes()[1];
    assert_eq!(
        lon.hourly.bins,
        [bin(at("2026-11-05", 9 * 3600), bytes((999, 9_999), (0, 0)))]
    );
    assert_eq!(lon.daily.bins, []);
    assert_eq!(
        lon.totals.as_ref().unwrap().months,
        [november(bytes((999, 9_999), (0, 0)))]
    );
    let subjects = read(&subject());
    let idle = read(&idle());
    assert_eq!(idle.nodes().len(), 2);
    for (node, subjects) in idle.nodes().iter().zip(subjects.nodes()) {
        assert_eq!(node.node, subjects.node);
        assert_eq!(node.hourly.held, subjects.hourly.held);
        assert_eq!(node.daily.held, subjects.daily.held);
        assert_eq!(node.hourly.bins, []);
        assert_eq!(node.daily.bins, []);
        assert_eq!(
            node.totals.as_ref().unwrap().months,
            [november(bytes((0, 0), (0, 0)))]
        );
    }
}

/// A stretch the node does not hold splits the tier: the hours on either
/// side are two ranges, and a day with a gap in its hours is not held.
#[test]
fn a_gap_splits_the_held_range() {
    let subject = subject();
    let mut lon = NodeUsageHistory::default();
    detail(
        &mut lon,
        "lon1",
        at("2026-11-03", 0),
        at("2026-11-03", 12 * 3600),
        &[(
            at("2026-11-03", 11 * 3600 + 3300),
            vec![(email(&subject, Reality), traffic(1, 2))],
        )],
    );
    detail(
        &mut lon,
        "lon1",
        at("2026-11-04", 0),
        now(),
        &[(
            at("2026-11-04", 0),
            vec![(email(&subject, Hy2), traffic(3, 4))],
        )],
    );
    monthly(
        &mut lon,
        "lon1",
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later_than_midnight(11 * 3600 + 59 * 60),
        vec![
            (email(&subject, Reality), traffic(1, 2)),
            (email(&subject, Hy2), traffic(3, 4)),
        ],
    );
    let mut collected = served();
    collected.set_node(node("lon1"), lon);
    let history = collected
        .user_history(&deployment(), &subject, now(), UsageScope::All)
        .unwrap();
    let lon = &history.nodes()[1];
    assert_eq!(
        lon.hourly,
        Tier {
            held: vec![
                range(at("2026-11-03", 0), at("2026-11-03", 12 * 3600)),
                range(at("2026-11-04", 0), now()),
            ],
            bins: vec![
                bin(at("2026-11-03", 11 * 3600), bytes((1, 2), (0, 0))),
                bin(at("2026-11-04", 0), bytes((0, 0), (3, 4))),
            ],
        }
    );
    assert_eq!(
        lon.daily,
        Tier {
            held: vec![range(at("2026-11-04", 0), at("2026-11-05", 0))],
            bins: vec![bin(at("2026-11-04", 0), bytes((0, 0), (3, 4)))],
        }
    );
}

/// The bins alone: the same bins, and no node's totals.
#[test]
fn the_bins_alone_leave_every_total_out() {
    let collected = served();
    let all = collected
        .user_history(&deployment(), &subject(), now(), UsageScope::All)
        .unwrap();
    let bins = collected
        .user_history(&deployment(), &subject(), now(), UsageScope::BinsOnly)
        .unwrap();
    assert_eq!(bins.scope(), UsageScope::BinsOnly);
    assert_eq!(bins.nodes().len(), 2);
    for (bins, all) in bins.nodes().iter().zip(all.nodes()) {
        assert_eq!(bins.totals, None);
        assert!(all.totals.is_some());
        assert_eq!(
            (&bins.node, bins.stage, &bins.hourly, &bins.daily),
            (&all.node, all.stage, &all.hourly, &all.daily)
        );
    }
}

/// The stored document is read, never changed: the history is made from
/// a pruned copy.
#[test]
fn reading_a_history_leaves_the_document_as_it_was() {
    let collected = served();
    let before = collected.encode().unwrap();
    collected
        .user_history(&deployment(), &subject(), now(), UsageScope::All)
        .unwrap();
    assert_eq!(collected.encode().unwrap(), before);
}

/// The end of October 2026, the first second of November.
fn end_of_october() -> UnixTime {
    at("2026-11-01", 0)
}

/// `secs` seconds before [`end_of_october`].
fn before_october_ends(secs: u64) -> UnixTime {
    UnixTime::from_secs(end_of_october().as_secs() - secs)
}

/// October sampled a minute before its end, with `bytes`.
fn october(is_final: bool, bytes: ProtocolTraffic) -> MonthTotal {
    MonthTotal {
        month: "2026-10".parse::<UsageMonth>().unwrap(),
        counted_through: before_october_ends(60),
        is_final,
        bytes,
    }
}

/// A node's history with October received at `received` and November so
/// far, the subject's bytes on REALITY in October and on Hysteria2 in
/// November; observed before it served when `origin` says so.
fn two_months(id: &str, origin: bool, received: UnixTime) -> NodeUsageHistory {
    let subject = subject();
    let mut collected = CollectedUsage::default();
    if origin {
        collected.observe_unserved(node(id), at("2026-10-01", 0));
    }
    let mut history = collected.node(&node(id)).cloned().unwrap_or_default();
    monthly(
        &mut history,
        id,
        "2026-10",
        before_october_ends(60),
        received,
        vec![(email(&subject, Reality), traffic(10, 20))],
    );
    monthly(
        &mut history,
        id,
        "2026-11",
        later_than_midnight(11 * 3600 + 58 * 60),
        later_than_midnight(11 * 3600 + 59 * 60),
        vec![(email(&subject, Hy2), traffic(3, 4))],
    );
    history
}

/// The nodes' totals for the subject, lon1 and ams1 given.
fn totals_of(lon: NodeUsageHistory, ams: NodeUsageHistory) -> (Totals, Totals) {
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), lon);
    collected.set_node(node("ams1"), ams);
    let history = collected
        .user_history(&deployment(), &subject(), now(), UsageScope::All)
        .unwrap();
    let totals = |index: usize| history.nodes()[index].totals.clone().unwrap();
    (totals(1), totals(0))
}

/// A month received once it had ended is final, from its end's very
/// second; one received a second earlier may still grow. A node observed
/// before it served has a lifetime, the sum of its final months and the
/// one so far, unless a month of it is not final; one adopted before
/// origins were recorded has none.
#[test]
fn a_month_is_final_from_its_end_and_a_lifetime_needs_an_origin() {
    let november = november(bytes((0, 0), (3, 4)));
    let (lon, ams) = totals_of(
        two_months("lon1", true, end_of_october()),
        two_months("ams1", false, end_of_october()),
    );
    assert_eq!(
        lon,
        Totals {
            months: vec![october(true, bytes((10, 20), (0, 0))), november],
            folded: None,
            lifetime: Some(bytes((10, 20), (3, 4))),
        }
    );
    assert_eq!(
        ams,
        Totals {
            months: vec![october(true, bytes((10, 20), (0, 0))), november],
            folded: None,
            lifetime: None,
        }
    );
    let (lon, _) = totals_of(
        two_months("lon1", true, before_october_ends(1)),
        two_months("ams1", false, end_of_october()),
    );
    assert_eq!(
        lon,
        Totals {
            months: vec![october(false, bytes((10, 20), (0, 0))), november],
            folded: None,
            lifetime: None,
        }
    );
}

/// A month held from before a node's recorded origin was counted before it
/// (a VPS adopted again with its old files, or a clock that ran ahead when
/// the origin was recorded): a lifetime summed from the origin would leave
/// it out, so it is unknown, in the status line's aggregate as here.
#[test]
fn a_month_from_before_the_origin_leaves_the_lifetime_unknown() {
    let mut lon = two_months("lon1", true, end_of_october());
    monthly(
        &mut lon,
        "lon1",
        "2026-09",
        at("2026-09-30", 86_340),
        at("2026-10-01", 60),
        vec![(email(&subject(), Reality), traffic(7, 7))],
    );
    let ams = two_months("ams1", true, end_of_october());
    let (lon_totals, ams_totals) = totals_of(lon.clone(), ams.clone());
    assert_eq!(lon_totals.lifetime, None);
    assert_eq!(lon_totals.months.len(), 3);
    assert_eq!(ams_totals.lifetime, Some(bytes((10, 20), (3, 4))));
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), lon);
    collected.set_node(node("ams1"), ams);
    let report = collected.aggregate(&deployment(), now()).unwrap();
    assert_eq!(report.users[&subject()].lifetime(), None);
    assert_eq!(
        report.users[&subject()].month(),
        Some(traffic(6, 8)),
        "both nodes' November, which the origin does not touch"
    );
}

/// A node past `Planned` that the daemon has not collected from yet holds
/// nothing on this Mac. It is listed with its tiers held nowhere, no month,
/// nothing folded and its lifetime unknown, and the other nodes read as
/// ever. The aggregate refuses it, since it needs every node's figures.
#[test]
fn a_node_not_collected_from_yet_is_listed_with_nothing_held() {
    let mut collected = CollectedUsage::default();
    collected.set_node(node("lon1"), served().node(&node("lon1")).unwrap().clone());
    for scope in [UsageScope::All, UsageScope::BinsOnly] {
        let history = collected
            .user_history(&deployment(), &subject(), now(), scope)
            .unwrap();
        let [ams, lon] = history.nodes() else {
            panic!("two nodes: {:?}", history.nodes());
        };
        assert_eq!(
            *ams,
            NodeHistory {
                node: node("ams1"),
                stage: NodeStage::Applied,
                hourly: nothing(),
                daily: nothing(),
                totals: (scope == UsageScope::All).then(|| Totals {
                    months: Vec::new(),
                    folded: None,
                    lifetime: None,
                }),
            },
            "{scope:?}"
        );
        let full = served()
            .user_history(&deployment(), &subject(), now(), scope)
            .unwrap();
        assert_eq!(lon, &full.nodes()[1], "{scope:?}");
    }
    assert_eq!(
        collected.aggregate(&deployment(), now()).unwrap_err(),
        crate::error::UsageError::MissingLedger { node: node("ams1") }
    );
}

/// A node not yet past `Planned` never served and is not listed; every
/// other stage is, under its own name, a retired one included.
#[test]
fn every_node_past_planned_is_listed_under_its_stage() {
    let collected = served();
    let planned = super::support::edited(|parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|n| n.id == node("ams1"))
            .unwrap();
        ams1.lifecycle = mooring_model::node::NodeLifecycle::Planned;
    });
    let history = collected
        .user_history(&planned, &subject(), now(), UsageScope::All)
        .unwrap();
    assert_eq!(
        history
            .nodes()
            .iter()
            .map(|node| (node.node.clone(), node.stage))
            .collect::<Vec<_>>(),
        [(node("lon1"), NodeStage::Applied)]
    );
    let retired = super::support::edited(|parts| {
        for user in &mut parts.users {
            user.per_node.remove(&node("ams1"));
        }
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|n| n.id == node("ams1"))
            .unwrap();
        ams1.lifecycle = mooring_model::node::NodeLifecycle::Retired;
    });
    let history = collected
        .user_history(&retired, &subject(), now(), UsageScope::All)
        .unwrap();
    assert_eq!(
        history
            .nodes()
            .iter()
            .map(|node| (node.node.clone(), node.stage))
            .collect::<Vec<_>>(),
        [
            (node("ams1"), NodeStage::Retired),
            (node("lon1"), NodeStage::Applied)
        ]
    );
    assert_eq!(
        history.nodes()[0].hourly.bins,
        [bin(at("2026-11-05", 3 * 3600), bytes((0, 0), (7, 8)))]
    );
}
