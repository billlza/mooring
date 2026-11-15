// SPDX-License-Identifier: GPL-3.0-or-later

//! The direct probe's round trips over the last day, per node, whose 10th
//! percentile is a capacity sample's idle reference (console spec B.2.8):
//! the nearest rank, a reference per node, one round trip per slot, the
//! day's window, the bound, the nodes kept, and the record's document and
//! its refusals.

use mooring_model::{NodeId, UnixTime};
use serde_json::Value;

use crate::capacity::RttSample;
use crate::capacity::round_trips::{
    IDLE_WINDOW_SECS, MAX_ROUND_TRIPS_BYTES, MAX_ROUND_TRIPS_PER_NODE, ROUND_TRIP_SLOT_SECS,
    RoundTrips, RoundTripsCorrupt,
};

/// 2026-10-24T00:00:00Z, the start of a slot.
const AT: u64 = 1_792_800_000;

fn node(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(AT + secs)
}

fn sample(loaded_ms: u64, idle_p10_ms: u64) -> RttSample {
    RttSample {
        loaded_ms,
        idle_p10_ms,
    }
}

/// How many round trips the record holds for `name`, from its document.
fn held(trips: &RoundTrips, name: &str) -> usize {
    let document: Value = serde_json::from_slice(&trips.encode().unwrap()).unwrap();
    document["nodes"][name].as_array().map_or(0, Vec::len)
}

#[test]
fn the_idle_reference_is_the_nearest_rank_10th_percentile_of_the_day() {
    assert_eq!(ROUND_TRIP_SLOT_SECS, 30);
    let mut trips = RoundTrips::new();
    let lon1 = node("lon1");
    // Alone, a round trip is its own reference.
    assert_eq!(trips.record(&lon1, at(0), 300), sample(300, 300));
    // Ten: the smallest.
    let mut last = None;
    for (slot, ms) in [90, 80, 70, 60, 50, 40, 100, 110, 120]
        .into_iter()
        .enumerate()
    {
        last = Some(trips.record(&lon1, at(30 * (slot as u64 + 1)), ms));
    }
    assert_eq!(last, Some(sample(120, 40)));
    // Eleven: the second smallest.
    assert_eq!(trips.record(&lon1, at(300), 35), sample(35, 40));
    // Twenty-one: the third.
    for slot in 11..20 {
        trips.record(&lon1, at(30 * slot), 1_000);
    }
    assert_eq!(held(&trips, "lon1"), 20);
    assert_eq!(trips.record(&lon1, at(600), 1_000), sample(1_000, 50));
}

#[test]
fn each_node_has_a_reference_of_its_own() {
    let mut trips = RoundTrips::new();
    trips.record(&node("lon1"), at(0), 40);
    trips.record(&node("ams1"), at(0), 200);
    assert_eq!(trips.record(&node("lon1"), at(30), 400), sample(400, 40));
    assert_eq!(trips.record(&node("ams1"), at(30), 400), sample(400, 200));
}

#[test]
fn one_round_trip_is_kept_per_slot_and_the_later_one_wins() {
    let mut trips = RoundTrips::new();
    let lon1 = node("lon1");
    trips.record(&lon1, at(0), 100);
    // The same slot: the later one replaces it.
    assert_eq!(trips.record(&lon1, at(29), 500), sample(500, 500));
    assert_eq!(held(&trips, "lon1"), 1);
    assert_eq!(trips.record(&lon1, at(30), 50), sample(50, 50));
    assert_eq!(held(&trips, "lon1"), 2);
    // A clock that stepped back: the slots at and after it give way.
    assert_eq!(trips.record(&lon1, at(15), 70), sample(70, 70));
    assert_eq!(held(&trips, "lon1"), 1);
}

#[test]
fn round_trips_a_day_old_fall_out() {
    assert_eq!(IDLE_WINDOW_SECS, 86_400);
    let mut trips = RoundTrips::new();
    let lon1 = node("lon1");
    trips.record(&lon1, at(0), 10);
    assert_eq!(
        trips.record(&lon1, at(IDLE_WINDOW_SECS - 1), 500),
        sample(500, 10)
    );
    assert_eq!(
        trips.record(&lon1, at(IDLE_WINDOW_SECS), 400),
        sample(400, 400)
    );
    assert_eq!(held(&trips, "lon1"), 2);
}

/// A day holds a slot more than its bound when the first round trip lies
/// late in its slot and the last early in its own: the oldest goes, so
/// that the record never holds more than its document may.
#[test]
fn a_node_holds_at_most_a_day_of_slots() {
    assert_eq!(
        MAX_ROUND_TRIPS_PER_NODE as u64,
        IDLE_WINDOW_SECS / ROUND_TRIP_SLOT_SECS
    );
    let mut trips = RoundTrips::new();
    let lon1 = node("lon1");
    trips.record(&lon1, at(ROUND_TRIP_SLOT_SECS - 1), 7);
    for slot in 1..=MAX_ROUND_TRIPS_PER_NODE as u64 {
        trips.record(&lon1, at(slot * ROUND_TRIP_SLOT_SECS), 1_000);
    }
    assert_eq!(held(&trips, "lon1"), MAX_ROUND_TRIPS_PER_NODE);
    let document: Value = serde_json::from_slice(&trips.encode().unwrap()).unwrap();
    assert_eq!(
        document["nodes"]["lon1"][0],
        serde_json::json!([AT + ROUND_TRIP_SLOT_SECS, 1_000])
    );
    let decoded = RoundTrips::decode(&trips.encode().unwrap()).unwrap();
    assert_eq!(decoded, trips);
}

#[test]
fn nodes_not_kept_are_dropped() {
    let mut trips = RoundTrips::new();
    trips.record(&node("lon1"), at(0), 40);
    trips.record(&node("ams1"), at(0), 200);
    assert!(trips.retain(|id| id.as_str() == "lon1"));
    assert!(!trips.retain(|id| id.as_str() == "lon1"));
    assert_eq!(held(&trips, "ams1"), 0);
    assert_eq!(held(&trips, "lon1"), 1);
}

#[test]
fn the_document_round_trips_and_refuses_anything_else() {
    let mut trips = RoundTrips::new();
    assert_eq!(
        trips.encode().unwrap(),
        b"{\"version\":1,\"nodes\":{}}\n".to_vec()
    );
    trips.record(&node("lon1"), at(0), 40);
    trips.record(&node("lon1"), at(30), 52);
    let bytes = trips.encode().unwrap();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        "{\"version\":1,\"nodes\":{\"lon1\":[[1792800000,40],[1792800030,52]]}}\n"
    );
    assert_eq!(RoundTrips::decode(&bytes), Ok(trips));
    let too_many = format!(
        "{{\"version\":1,\"nodes\":{{\"lon1\":[{}]}}}}",
        (0..=MAX_ROUND_TRIPS_PER_NODE as u64)
            .map(|slot| format!("[{},40]", AT + 30 * slot))
            .collect::<Vec<_>>()
            .join(",")
    );
    for refused in [
        "not a record".to_owned(),
        "{\"version\":0,\"nodes\":{}}".to_owned(),
        "{\"version\":2,\"nodes\":{}}".to_owned(),
        "{\"version\":1,\"nodes\":{},\"more\":1}".to_owned(),
        "{\"version\":1}".to_owned(),
        "{\"version\":1,\"nodes\":{\"lon1\":[]}}".to_owned(),
        "{\"version\":1,\"nodes\":{\"lon1\":[[1792800030,40],[1792800000,52]]}}".to_owned(),
        "{\"version\":1,\"nodes\":{\"lon1\":[[1792800000,40],[1792800029,52]]}}".to_owned(),
        "{\"version\":1,\"nodes\":{\"lon1\":[[1792800000,40,1]]}}".to_owned(),
        "{\"version\":1,\"nodes\":{\"Not A Node\":[[1792800000,40]]}}".to_owned(),
        too_many,
    ] {
        assert_eq!(
            RoundTrips::decode(refused.as_bytes()),
            Err(RoundTripsCorrupt),
            "{refused}"
        );
    }
    let padded = [
        &b"{\"version\":1,\"nodes\":{}}"[..],
        &vec![b' '; MAX_ROUND_TRIPS_BYTES],
    ]
    .concat();
    assert_eq!(RoundTrips::decode(&padded), Err(RoundTripsCorrupt));
    assert_eq!(
        RoundTripsCorrupt.to_string(),
        "the record of direct-probe round trips is corrupt"
    );
}
