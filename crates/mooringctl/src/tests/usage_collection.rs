// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon collector through its real file and pinned session boundaries.
//! Scripted remote replies exercise gaps and faults without changing a node.

use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, Instant};

use mooring_agent_proto::{
    AgentError, Inbound, LineRequest, Principal, RequestKind, Resolution, Response, SeriesRange,
    SeriesSpan, StatsEmail, Traffic, UsageBin, UsageMonth, UsageSeriesV1, UsageV1,
};
use mooring_daemon_core::error::UsageErrorKind;
use mooring_daemon_core::snapshot::Ledgers;
use mooring_daemon_core::usage::{CollectedUsage, NodeUsageHistory};
use mooring_model::node::NodeLifecycle;
use mooring_model::{Deployment, NodeId, UnixTime, UserStatus};
use mooring_store::{USAGE_DIRECTORY, USER_USAGE_FILE, read_user_usage, write_user_usage};

use super::deployed::status_reply;
use super::support::{Answered, Expected, ExpectedRemote, Harness, NOW, PINNED, Sent, lo0_name};
use super::user::{fixture, harness_with};
use crate::daemon::usage::{Collector, pull_budget};
use crate::error::LocalError;
use crate::node::NodeError;

const INTERVAL: Duration = Duration::ZERO;

#[test]
fn collection_uses_the_available_ssh_window_without_delaying_a_carrier_probe() {
    let request = Duration::from_secs(15);
    assert_eq!(pull_budget(None), Some(request));
    assert_eq!(pull_budget(Some(Duration::from_secs(300))), Some(request));
    assert_eq!(pull_budget(Some(Duration::from_secs(17))), Some(request));
    for left in [0, 1, 2] {
        assert_eq!(pull_budget(Some(Duration::from_secs(left))), None);
    }
    for (left, available) in [(3, 1), (5, 3), (10, 8), (16, 14)] {
        assert_eq!(
            pull_budget(Some(Duration::from_secs(left))),
            Some(Duration::from_secs(available))
        );
    }
    assert_eq!(pull_budget(Some(Duration::from_millis(2_999))), None);
    assert_eq!(
        pull_budget(Some(Duration::from_millis(16_999))),
        Some(Duration::from_millis(14_999))
    );
}

#[test]
fn a_scheduled_collection_does_not_cut_off_a_slow_but_live_management_path() {
    let (mut harness, deployment, mut collector) = ready();
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    let budget = pull_budget(Some(Duration::from_secs(20))).unwrap();
    let began = Instant::now();
    harness.with_env(|env| {
        collector.tick(env, &deployment, &lo0_name(), now(), budget, INTERVAL);
    });
    let seen = harness.nodes.seen.borrow();
    let (target, sent) = seen.last().unwrap();
    assert!(matches!(sent, Sent::Request(LineRequest::Status)));
    let deadline = target.deadline.unwrap();
    // A real M7-bound management request took 14.2 seconds during acceptance.
    assert!(deadline >= began + Duration::from_secs(15));
    assert!(deadline <= Instant::now() + Duration::from_secs(15));
    assert!(deadline < began + Duration::from_secs(18));
}

fn wire(at: u64) -> mooring_agent_proto::UnixTime {
    mooring_agent_proto::UnixTime::from_secs(at)
}

fn now() -> UnixTime {
    UnixTime::from_secs(NOW)
}

fn range(from: u64, to: u64) -> SeriesRange {
    SeriesRange::new(wire(from), wire(to), Resolution::FiveMin).unwrap()
}

fn month(at: u64, traffic: BTreeMap<StatsEmail, Traffic>) -> Response {
    Response::Usage(Box::new(UsageV1 {
        month: UsageMonth::containing(wire(at)).unwrap(),
        updated_at: wire(at),
        traffic,
    }))
}

fn series(range: SeriesRange, bins: Vec<UsageBin>) -> Response {
    Response::UsageSeries(Box::new(UsageSeriesV1::new(range, bins).unwrap()))
}

fn expect(harness: &Harness, kind: RequestKind, reply: Result<Response, NodeError>) {
    harness.nodes.expect(
        Expected::Request {
            identity: "ops_ed25519",
            remote: ExpectedRemote::Forced,
            kind,
        },
        Answered::Replied(reply),
    );
}

fn ready() -> (Harness, Deployment, Collector) {
    let deployment = fixture(|_| {});
    let mut harness = harness_with(deployment.clone());
    harness.pin(PINNED);
    let collector = Collector::open(&harness.support_dir(), INTERVAL);
    (harness, deployment, collector)
}

fn tick(harness: &mut Harness, collector: &mut Collector, deployment: &Deployment) {
    harness.with_env(|env| {
        collector.tick(
            env,
            deployment,
            &lo0_name(),
            now(),
            Duration::from_secs(2),
            INTERVAL,
        );
    });
}

fn complete(harness: &mut Harness, collector: &mut Collector, deployment: &Deployment) {
    for _ in 0..40 {
        if harness.nodes.script.borrow().is_empty() {
            return;
        }
        tick(harness, collector, deployment);
    }
    panic!("bounded script did not complete");
}

fn document(collector: &Collector) -> CollectedUsage {
    let Ledgers::Collected(history) = collector.ledgers() else {
        panic!("not durable");
    };
    history.clone()
}

fn page_ranges() -> Vec<SeriesRange> {
    (0..4)
        .map(|index| {
            range(
                NOW - 48 * 3600 + index * 12 * 3600,
                NOW - 48 * 3600 + (index + 1) * 12 * 3600,
            )
        })
        .collect()
}

fn script_batch(harness: &Harness, counters: &BTreeMap<StatsEmail, Traffic>) {
    expect(harness, RequestKind::Status, Ok(status_reply()));
    for (index, range) in page_ranges().into_iter().enumerate() {
        let bins = if index == 3 && !counters.is_empty() {
            vec![UsageBin::new(wire(NOW - 300), counters.clone()).unwrap()]
        } else {
            Vec::new()
        };
        expect(harness, RequestKind::UsageSeries, Ok(series(range, bins)));
    }
    expect(
        harness,
        RequestKind::Usage,
        Ok(month(NOW, counters.clone())),
    );
}

#[test]
fn a_batch_is_published_only_after_durable_completion_and_survives_restart_without_double_counting()
{
    let (mut harness, deployment, mut collector) = ready();
    let user = deployment.users().keys().next().unwrap().clone();
    let counters = BTreeMap::from([(
        StatsEmail {
            principal: Principal::User(user.as_str().parse().unwrap()),
            inbound: Inbound::Reality,
        },
        Traffic {
            uplink: 123,
            downlink: 456,
        },
    )]);
    script_batch(&harness, &counters);
    let started = Instant::now();
    tick(&mut harness, &mut collector, &deployment);
    assert!(
        document(&collector)
            .node(&NodeId::parse("ams1").unwrap())
            .is_none()
    );
    assert!(
        read_user_usage(&harness.support_dir(), 100)
            .unwrap()
            .is_none()
    );
    complete(&mut harness, &mut collector, &deployment);
    let bytes = read_user_usage(&harness.support_dir(), 100_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        CollectedUsage::decode(&bytes).unwrap(),
        document(&collector)
    );
    assert!(collector.failure().is_none());
    assert!(collector.take_gaps().is_empty());
    for (target, sent) in harness.nodes.seen.borrow().iter() {
        assert_eq!(target.egress.index(), super::support::lo0());
        let deadline = target.deadline.unwrap();
        assert!(deadline > started && deadline <= Instant::now() + Duration::from_secs(2));
        assert!(matches!(sent, Sent::Request(_)));
    }
    // The persisted cursor avoids replaying 48 hours after a daemon restart.
    let mut restored = Collector::open(&harness.support_dir(), INTERVAL);
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    expect(&harness, RequestKind::Usage, Ok(month(NOW, counters)));
    complete(&mut harness, &mut restored, &deployment);
    assert_eq!(document(&restored), document(&collector));
    // The second node is still collected, even after repeated first-node work.
    script_batch(&harness, &BTreeMap::new());
    complete(&mut harness, &mut restored, &deployment);
    let report = document(&restored).aggregate(&deployment, now()).unwrap();
    assert_eq!(
        report.users[&user].today(),
        Some(Traffic {
            uplink: 123,
            downlink: 456
        })
    );
}

#[test]
fn missing_ranges_are_clipped_once_and_the_unclosed_tail_is_not_logged_as_lost_history() {
    let (mut harness, deployment, mut collector) = ready();
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    let pages = page_ranges();
    let held = SeriesSpan::new(wire(NOW - 600), wire(NOW - 300), Resolution::FiveMin).unwrap();
    for _ in &pages {
        expect(
            &harness,
            RequestKind::UsageSeries,
            Err(NodeError::Agent(AgentError::SeriesNotRecorded {
                recorded: Some(held),
            })),
        );
    }
    expect(
        &harness,
        RequestKind::UsageSeries,
        Ok(series(range(NOW - 600, NOW - 300), vec![])),
    );
    expect(
        &harness,
        RequestKind::Usage,
        Ok(month(NOW, BTreeMap::new())),
    );
    complete(&mut harness, &mut collector, &deployment);
    assert_eq!(collector.take_gaps().len(), 4);
    // Next cycle starts with the other node; a restored collector starts
    // with this persisted node, now asking only for the still-open tail.
    let mut restored = Collector::open(&harness.support_dir(), INTERVAL);
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    expect(
        &harness,
        RequestKind::UsageSeries,
        Err(NodeError::Agent(AgentError::SeriesNotRecorded {
            recorded: Some(held),
        })),
    );
    expect(
        &harness,
        RequestKind::Usage,
        Ok(month(NOW, BTreeMap::new())),
    );
    complete(&mut harness, &mut restored, &deployment);
    assert!(restored.take_gaps().is_empty());
    assert_eq!(document(&restored), document(&collector));
}

#[test]
fn an_oversized_page_splits_at_the_advertised_bound_and_a_zero_bound_fails() {
    let (mut harness, deployment, mut collector) = ready();
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    expect(
        &harness,
        RequestKind::UsageSeries,
        Err(NodeError::Agent(AgentError::SeriesTooLarge {
            fitting_bins: 1,
        })),
    );
    let pages = page_ranges();
    let first = pages[0].span().from().as_secs();
    expect(
        &harness,
        RequestKind::UsageSeries,
        Ok(series(range(first, first + 300), vec![])),
    );
    expect(
        &harness,
        RequestKind::UsageSeries,
        Ok(series(
            range(first + 300, pages[0].span().to().as_secs()),
            vec![],
        )),
    );
    for page in &pages[1..] {
        expect(
            &harness,
            RequestKind::UsageSeries,
            Ok(series(*page, vec![])),
        );
    }
    expect(
        &harness,
        RequestKind::Usage,
        Ok(month(NOW, BTreeMap::new())),
    );
    complete(&mut harness, &mut collector, &deployment);
    assert!(collector.failure().is_none());
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    expect(
        &harness,
        RequestKind::UsageSeries,
        Err(NodeError::Agent(AgentError::SeriesTooLarge {
            fitting_bins: 0,
        })),
    );
    complete(&mut harness, &mut collector, &deployment);
    assert!(collector.failure().is_some());
    assert!(
        document(&collector)
            .node(&NodeId::parse("lon1").unwrap())
            .is_none()
    );
}

#[test]
fn failed_or_mismatched_replies_do_not_commit_partial_batches_or_report_recovery() {
    for reply in [
        Err(NodeError::PastDeadline),
        Ok(month(NOW, BTreeMap::new())),
        Ok(series(range(NOW - 300, NOW), vec![])),
    ] {
        let (mut harness, deployment, mut collector) = ready();
        expect(&harness, RequestKind::Status, Ok(status_reply()));
        expect(&harness, RequestKind::UsageSeries, reply);
        complete(&mut harness, &mut collector, &deployment);
        assert!(collector.failure().is_some());
        let failure = collector.failure().unwrap().to_owned();
        collector.maintain(&deployment, now(), INTERVAL);
        assert_eq!(collector.failure(), Some(failure.as_str()));
        assert!(
            document(&collector)
                .node(&NodeId::parse("ams1").unwrap())
                .is_none()
        );
    }
}

#[test]
fn unreadable_and_corrupt_ledgers_are_preserved_and_write_failure_retries_the_candidate() {
    let (harness, deployment, _) = ready();
    let support = harness.support_dir();
    write_user_usage(&support, b"broken ledger retained for diagnosis").unwrap();
    let mut corrupt = Collector::open(&support, INTERVAL);
    assert!(matches!(
        corrupt.ledgers(),
        Ledgers::Unavailable(UsageErrorKind::LedgerCorrupt)
    ));
    corrupt.maintain(&deployment, now(), INTERVAL);
    assert_eq!(
        read_user_usage(&support, 100).unwrap().unwrap(),
        b"broken ledger retained for diagnosis"
    );
    fs::remove_file(support.join(USAGE_DIRECTORY).join(USER_USAGE_FILE)).unwrap();
    fs::create_dir(support.join(USAGE_DIRECTORY).join(USER_USAGE_FILE)).unwrap();
    let unreadable = Collector::open(&support, INTERVAL);
    assert!(matches!(
        unreadable.ledgers(),
        Ledgers::Unavailable(UsageErrorKind::StoreUnavailable)
    ));
    fs::remove_dir_all(support.join(USAGE_DIRECTORY)).unwrap();
    let mut writable = Collector::open(&support, INTERVAL);
    fs::write(support.join(USAGE_DIRECTORY), b"blocked path").unwrap();
    writable.maintain(&deployment, now(), INTERVAL);
    assert!(matches!(
        writable.ledgers(),
        Ledgers::Unavailable(UsageErrorKind::StoreUnavailable)
    ));
    fs::remove_file(support.join(USAGE_DIRECTORY)).unwrap();
    writable.maintain(&deployment, now(), INTERVAL);
    assert!(matches!(writable.ledgers(), Ledgers::Collected(_)));
    assert!(writable.failure().is_none());
}

#[test]
fn a_failed_clock_cancels_the_batch_and_a_delayed_first_pull_sends_nothing() {
    let (mut harness, deployment, mut collector) = ready();
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    harness.with_env(|env| {
        env.clock = &|| Err(LocalError::Clock);
        collector.tick(
            env,
            &deployment,
            &lo0_name(),
            now(),
            Duration::from_secs(2),
            INTERVAL,
        );
    });
    assert!(collector.failure().unwrap().contains("clock"));
    let mut delayed = Collector::open(&harness.support_dir(), Duration::from_secs(60));
    tick(&mut harness, &mut delayed, &deployment);
    assert_eq!(harness.nodes.seen.borrow().len(), 1);
}

#[test]
fn expired_user_counters_are_removed_from_replies_and_do_not_reappear() {
    let (mut harness, deployment, mut collector) = ready();
    let mut parts = deployment.into_parts();
    let user = parts.users[0].id.clone();
    parts.users[0].status = UserStatus::Revoked;
    parts.users[0].per_node.clear();
    let deployment = Deployment::try_from(parts).unwrap();
    let counters = BTreeMap::from([(
        StatsEmail {
            principal: Principal::User(user.as_str().parse().unwrap()),
            inbound: Inbound::Hy2,
        },
        Traffic {
            uplink: 100,
            downlink: 200,
        },
    )]);
    script_batch(&harness, &counters);
    complete(&mut harness, &mut collector, &deployment);
    let bytes = document(&collector).encode().unwrap();
    assert!(!String::from_utf8(bytes).unwrap().contains(user.as_str()));
}

#[test]
fn a_previous_month_is_requested_only_during_the_nodes_seven_day_retention() {
    let (mut harness, deployment, mut collector) = ready();
    let first = mooring_model::CalendarDate::parse("2026-11-05")
        .unwrap()
        .utc_start();
    expect(&harness, RequestKind::Status, Ok(status_reply()));
    expect(
        &harness,
        RequestKind::Usage,
        Err(NodeError::Agent(AgentError::NoUsageRecorded {
            month: "2026-10".parse().unwrap(),
        })),
    );
    harness.with_env(|env| {
        env.clock = &|| {
            Ok(mooring_model::CalendarDate::parse("2026-11-05")
                .unwrap()
                .utc_start())
        };
        for _ in 0..2 {
            collector.tick(
                env,
                &deployment,
                &lo0_name(),
                first,
                Duration::from_secs(2),
                INTERVAL,
            );
        }
    });
    assert!(collector.take_gaps()[0].contains("2026-10"));
    assert!(matches!(&harness.nodes.seen.borrow()[1].1,
        Sent::Request(LineRequest::Usage { month }) if *month == "2026-10".parse().unwrap()));
}

#[test]
fn a_future_monthly_sample_and_an_unknown_principal_are_refused() {
    for reply in [
        month(NOW + 1, BTreeMap::new()),
        month(
            NOW,
            BTreeMap::from([(
                StatsEmail {
                    principal: Principal::User("unknown123".parse().unwrap()),
                    inbound: Inbound::Reality,
                },
                Traffic {
                    uplink: 1,
                    downlink: 1,
                },
            )]),
        ),
    ] {
        let (mut harness, deployment, _) = ready();
        // A valid saved cursor makes the batch status + month only.
        let node = NodeId::parse("ams1").unwrap();
        let mut collected = CollectedUsage::default();
        let mut history = NodeUsageHistory::default();
        let Response::UsageSeries(last) = series(range(NOW - 300, NOW), vec![]) else {
            unreachable!()
        };
        history.record_series(&node, &last).unwrap();
        collected.set_node(node, history);
        write_user_usage(&harness.support_dir(), &collected.encode().unwrap()).unwrap();
        let mut collector = Collector::open(&harness.support_dir(), INTERVAL);
        expect(&harness, RequestKind::Status, Ok(status_reply()));
        expect(&harness, RequestKind::Usage, Ok(reply));
        complete(&mut harness, &mut collector, &deployment);
        assert!(collector.failure().is_some());
        assert_eq!(document(&collector), collected);
    }
}

/// Each maintenance sees a planned or adopted node unserved, so its origin
/// follows the latest one until the Mac holds anything from it; an applied
/// node gets no origin.
#[test]
fn maintenance_moves_the_origin_of_a_planned_or_adopted_node_and_gives_an_applied_one_none() {
    let unserved = fixture(|parts| {
        for node in &mut parts.nodes {
            node.lifecycle = match &node.lifecycle {
                NodeLifecycle::Applied { site, .. } if node.id.as_str() == "ams1" => {
                    NodeLifecycle::Adopted { site: site.clone() }
                }
                _ => NodeLifecycle::Planned,
            };
        }
    });
    let harness = harness_with(unserved.clone());
    let mut collector = Collector::open(&harness.support_dir(), INTERVAL);
    let origins = |collector: &Collector| {
        let json = serde_json::to_value(document(collector)).unwrap();
        ["lon1", "ams1"].map(|node| json["nodes"][node]["origin"].clone())
    };
    let both = |at: u64| [serde_json::json!(at), serde_json::json!(at)];
    collector.maintain(&unserved, UnixTime::from_secs(NOW - 86_400), INTERVAL);
    assert_eq!(origins(&collector), both(NOW - 86_400));
    collector.maintain(&unserved, now(), INTERVAL);
    assert_eq!(origins(&collector), both(NOW));
    collector.maintain(&fixture(|_| {}), UnixTime::from_secs(NOW + 60), INTERVAL);
    assert_eq!(
        origins(&collector),
        both(NOW),
        "an applied node is not unserved"
    );

    // The harness keeps the support directory while it lives.
    let (_kept, applied, mut fresh) = ready();
    fresh.maintain(&applied, now(), INTERVAL);
    assert!(
        document(&fresh)
            .node(&NodeId::parse("lon1").unwrap())
            .is_none()
    );
}

/// The deployment with its applied nodes adopted instead.
fn adopted() -> Deployment {
    fixture(|parts| {
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &node.lifecycle {
                node.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
    })
}

/// A first apply's window: the agent polls while the Mac still says
/// adopted, so a batch can hold the node's first month, empty. From then
/// the origin stays, though the node is still adopted.
#[test]
fn an_adopted_node_keeps_its_origin_once_a_batch_held_anything() {
    let deployment = adopted();
    let mut harness = harness_with(deployment.clone());
    harness.pin(PINNED);
    let mut collector = Collector::open(&harness.support_dir(), INTERVAL);
    collector.maintain(&deployment, UnixTime::from_secs(NOW - 3600), INTERVAL);
    // ams1 sorts first, so the batch is its.
    script_batch(&harness, &BTreeMap::new());
    complete(&mut harness, &mut collector, &deployment);
    assert!(collector.failure().is_none(), "{:?}", collector.failure());
    let next_month = NOW + 30 * 86_400;
    collector.maintain(&deployment, UnixTime::from_secs(next_month), INTERVAL);
    let json = serde_json::to_value(document(&collector)).unwrap();
    assert_eq!(json["nodes"]["ams1"]["origin"], NOW - 3600);
    assert_eq!(
        json["nodes"]["lon1"]["origin"], next_month,
        "lon1 holds nothing"
    );
}

/// A batch copies a node's history when it starts and installs the copy
/// when it ends. A sighting made in between, while the node held nothing,
/// is kept: the latest sighting wins, so one taken with the clock fast just
/// before the batch does not outlast it.
#[test]
fn a_batch_keeps_a_sighting_made_while_it_ran() {
    let deployment = adopted();
    let mut harness = harness_with(deployment.clone());
    harness.pin(PINNED);
    let mut collector = Collector::open(&harness.support_dir(), INTERVAL);
    let origin = |collector: &Collector| {
        serde_json::to_value(document(collector)).unwrap()["nodes"]["ams1"]["origin"].clone()
    };
    // Six hours fast.
    collector.maintain(&deployment, UnixTime::from_secs(NOW + 6 * 3600), INTERVAL);
    // ams1 sorts first, so the batch is its; its first request is the status.
    script_batch(&harness, &BTreeMap::new());
    tick(&mut harness, &mut collector, &deployment);
    collector.maintain(&deployment, UnixTime::from_secs(NOW - 60), INTERVAL);
    assert_eq!(origin(&collector), NOW - 60);
    complete(&mut harness, &mut collector, &deployment);
    assert!(collector.failure().is_none(), "{:?}", collector.failure());
    assert_eq!(origin(&collector), NOW - 60);
    let held = serde_json::to_value(document(&collector)).unwrap();
    assert_eq!(
        held["nodes"]["ams1"]["months"]
            .as_object()
            .map(serde_json::Map::len),
        Some(1),
        "the batch's month is installed"
    );
}

/// A write that fails leaves its candidate to be retried at the next
/// maintenance, which sights the unserved nodes again: ams1, applied by
/// then, keeps the candidate's origin, and lon1, still adopted, gets the
/// retry's.
#[test]
fn a_retried_write_holds_the_retrys_sighting() {
    let deployment = adopted();
    let harness = harness_with(deployment.clone());
    let support = harness.support_dir();
    let mut collector = Collector::open(&support, INTERVAL);
    fs::write(support.join(USAGE_DIRECTORY), b"blocked path").unwrap();
    collector.maintain(&deployment, UnixTime::from_secs(NOW - 60), INTERVAL);
    assert!(matches!(
        collector.ledgers(),
        Ledgers::Unavailable(UsageErrorKind::StoreUnavailable)
    ));
    fs::remove_file(support.join(USAGE_DIRECTORY)).unwrap();
    let ams1_applied = fixture(|parts| {
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &node.lifecycle
                && node.id.as_str() == "lon1"
            {
                node.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
    });
    collector.maintain(&ams1_applied, now(), INTERVAL);
    let json = serde_json::to_value(document(&collector)).unwrap();
    assert_eq!(json["nodes"]["ams1"]["origin"], NOW - 60);
    assert_eq!(json["nodes"]["lon1"]["origin"], NOW);
}

/// `usage/users.json` as an earlier build wrote it: lon1 sighted planned a
/// month before, and ams1 collected while adopted, never sighted, holding
/// nothing. Each gets the next maintenance as its origin while unserved,
/// and keeps what it has once applied.
#[test]
fn a_stored_origin_moves_while_the_node_is_unserved_and_stays_once_it_is_applied() {
    let month_ago = NOW - 30 * 86_400;
    let empty = r#""months":{},"five_min":{},"hour":{},"day":{},"folded":{}"#;
    let bytes = format!(
        r#"{{"version":1,"nodes":{{"ams1":{{{empty},"origin":null,"folded_before":null,"lifetime_complete":false}},"lon1":{{{empty},"origin":{month_ago},"folded_before":null,"lifetime_complete":true}}}},"last_nonrevoked":{{}}}}"#
    );
    let unserved = fixture(|parts| {
        for node in &mut parts.nodes {
            node.lifecycle = match &node.lifecycle {
                NodeLifecycle::Applied { site, .. } if node.id.as_str() == "ams1" => {
                    NodeLifecycle::Adopted { site: site.clone() }
                }
                _ => NodeLifecycle::Planned,
            };
        }
    });
    let stored = |node: &str, json: &serde_json::Value| {
        let node = &json["nodes"][node];
        (node["origin"].clone(), node["lifetime_complete"].clone())
    };
    for (deployment, lon1, ams1) in [
        (
            unserved,
            (NOW.into(), true.into()),
            (NOW.into(), true.into()),
        ),
        (
            fixture(|_| {}),
            (month_ago.into(), true.into()),
            (serde_json::Value::Null, false.into()),
        ),
    ] {
        let harness = harness_with(deployment.clone());
        write_user_usage(&harness.support_dir(), bytes.as_bytes()).unwrap();
        let mut collector = Collector::open(&harness.support_dir(), INTERVAL);
        collector.maintain(&deployment, now(), INTERVAL);
        let json = serde_json::to_value(document(&collector)).unwrap();
        assert_eq!(stored("lon1", &json), lon1);
        assert_eq!(stored("ams1", &json), ams1);
    }
}
