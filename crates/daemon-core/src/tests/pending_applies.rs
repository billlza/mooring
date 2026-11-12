// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's record of pending applies (design §13.6, §15.3): a node
//! that confirmed a generation older than the deployment's is dated at the
//! first sighting and keeps that date until it catches up; one that
//! applied in between two sightings is dated anew; nodes not applied or
//! leaving have none; a date after `now` is brought back to it; and the
//! record's document round-trips and refuses anything else.

use std::collections::BTreeMap;

use mooring_model::node::{AppliedConfig, NodeLifecycle};
use mooring_model::{ConfigGeneration, Deployment, UnixTime};

use super::support::{edited, node};
use crate::pending_applies::{MAX_PENDING_APPLIES_BYTES, PendingApplies, PendingAppliesCorrupt};

fn generation(value: u64) -> ConfigGeneration {
    ConfigGeneration::new(value).unwrap()
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(1_791_919_200 + secs)
}

/// The fixture at generation `current`, lon1 having confirmed `lon1` and
/// ams1 `ams1`.
fn holding(current: u64, lon1: u64, ams1: u64) -> Deployment {
    edited(|parts| {
        parts.config_generation = generation(current);
        for node in &mut parts.nodes {
            let confirmed = match node.id.as_str() {
                "lon1" => lon1,
                _ => ams1,
            };
            if let NodeLifecycle::Applied { applied, .. } = &mut node.lifecycle {
                *applied = AppliedConfig {
                    config_generation: generation(confirmed),
                    digest: applied.digest,
                };
            }
        }
    })
}

fn since(record: &PendingApplies) -> Vec<(String, u64)> {
    record
        .since()
        .into_iter()
        .map(|(id, since)| (id.to_string(), since.as_secs() - at(0).as_secs()))
        .collect()
}

/// A node behind is dated at the first tick that sees it so, and keeps
/// that date while it stays behind with the same confirmed generation,
/// however many changes follow; one up to date has none.
#[test]
fn a_node_behind_keeps_the_date_it_was_first_seen_behind() {
    let first = PendingApplies::new().tracked(&holding(3, 2, 3), at(10));
    assert_eq!(since(&first), [("lon1".to_owned(), 10)]);
    let later = first.tracked(&holding(3, 2, 3), at(50));
    assert_eq!(later, first);
    // Another change: lon1 still waits from its first sighting, ams1 from
    // this one.
    let again = later.tracked(&holding(4, 2, 3), at(90));
    assert_eq!(
        since(&again),
        [("ams1".to_owned(), 90), ("lon1".to_owned(), 10)]
    );
    assert_eq!(
        again.since(),
        BTreeMap::from([(node("ams1"), at(90)), (node("lon1"), at(10))])
    );
}

/// A node that caught up has no pending apply, and one behind again is
/// dated anew; so is one that applied a later generation between two
/// sightings while still behind, which the record tells by the generation
/// it confirmed.
#[test]
fn a_node_that_applied_since_is_dated_anew() {
    let behind = PendingApplies::new().tracked(&holding(3, 2, 3), at(10));
    let caught_up = behind.tracked(&holding(3, 3, 3), at(20));
    assert_eq!(caught_up, PendingApplies::new());
    let behind_again = caught_up.tracked(&holding(4, 3, 4), at(30));
    assert_eq!(since(&behind_again), [("lon1".to_owned(), 30)]);
    // lon1 confirmed 2 when first seen behind; it has confirmed 4 since,
    // with 5 and 6 made meanwhile.
    let applied_between = behind.tracked(&holding(6, 4, 6), at(40));
    assert_eq!(since(&applied_between), [("lon1".to_owned(), 40)]);
}

/// Only a node that confirmed a generation can be behind: one adopted but
/// never applied, or one retiring, has no pending apply, and a node the
/// deployment no longer holds leaves the record.
#[test]
fn only_applied_nodes_are_pending() {
    let behind = PendingApplies::new().tracked(&holding(3, 2, 2), at(10));
    assert_eq!(behind.since().len(), 2);
    let leaving = edited(|parts| {
        parts.config_generation = generation(3);
        for node in &mut parts.nodes {
            if let NodeLifecycle::Applied { site, .. } = &node.lifecycle {
                node.lifecycle = match node.id.as_str() {
                    "lon1" => NodeLifecycle::Adopted { site: site.clone() },
                    _ => NodeLifecycle::Retiring { site: site.clone() },
                };
            }
        }
    });
    assert_eq!(behind.tracked(&leaving, at(20)), PendingApplies::new());
}

/// A date after `now` (a clock that stepped back since) is brought back to
/// `now`, so that no wait is negative.
#[test]
fn a_date_after_now_is_brought_back_to_now() {
    let behind = PendingApplies::new().tracked(&holding(3, 2, 3), at(100));
    let stepped_back = behind.tracked(&holding(3, 2, 3), at(40));
    assert_eq!(since(&stepped_back), [("lon1".to_owned(), 40)]);
}

/// The record round-trips through its document; a document of another
/// version, with a key it does not know, too long or not JSON is refused.
#[test]
fn the_record_round_trips_and_refuses_anything_else() {
    let record = PendingApplies::new().tracked(&holding(4, 2, 3), at(10));
    let bytes = record.encode().unwrap();
    assert_eq!(PendingApplies::decode(&bytes).unwrap(), record);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.ends_with('\n'));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "version": 1,
            "nodes": {
                "ams1": {"applied": 3, "since": at(10).as_secs()},
                "lon1": {"applied": 2, "since": at(10).as_secs()},
            },
        })
    );
    assert_eq!(
        PendingApplies::decode(b"{\"version\": 1, \"nodes\": {}}"),
        Ok(PendingApplies::new())
    );
    for refused in [
        &b"{\"version\": 2, \"nodes\": {}}"[..],
        b"{\"version\": 1, \"nodes\": {}, \"extra\": 0}",
        b"{\"version\": 1, \"nodes\": {\"lon1\": {\"applied\": 2, \"since\": 1, \"x\": 0}}}",
        b"{\"version\": 1, \"nodes\": {\"lon1\": {\"applied\": 0, \"since\": 1}}}",
        b"{\"version\": 1, \"nodes\": {\"Not A Node\": {\"applied\": 2, \"since\": 1}}}",
        b"{\"version\": 1}",
        b"not json",
    ] {
        assert_eq!(
            PendingApplies::decode(refused),
            Err(PendingAppliesCorrupt),
            "{}",
            String::from_utf8_lossy(refused)
        );
    }
    let mut long = br#"{"version": 1, "nodes": {}}"#.to_vec();
    long.resize(MAX_PENDING_APPLIES_BYTES + 1, b' ');
    assert_eq!(PendingApplies::decode(&long), Err(PendingAppliesCorrupt));
}
