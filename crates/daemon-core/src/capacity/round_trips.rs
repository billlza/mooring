// SPDX-License-Identifier: GPL-3.0-or-later

//! The direct probe's round trips over the last day, per node (console
//! spec B.2.8): their 10th percentile is the idle reference a capacity
//! sample's round trip is compared with. The daemon records the round trip
//! of each direct-probe round that passed against the node that answered:
//! a fallback node is another path, with a reference of its own.
//!
//! A node keeps at most one round trip per [`ROUND_TRIP_SLOT_SECS`] (the
//! probe's default cadence; the operator may make it shorter), the latest
//! of the slot, and none a day or more older than its newest, so at most a
//! day of slots ([`MAX_ROUND_TRIPS_PER_NODE`]). A round trip recorded at
//! or before the slot of the newest (a clock that stepped back) replaces
//! the ones of those slots, so the record stays in time order.
//!
//! The daemon keeps the record in `run/round-trips.json`, so that a
//! restart in a busy hour does not make that hour's round trips the
//! reference. It is Level 0 (design §15.5): node ids, times and
//! milliseconds.

use std::collections::{BTreeMap, VecDeque};

use mooring_model::{NodeId, UnixTime};
use serde::{Deserialize, Serialize};

use super::RttSample;

/// The record's document version.
pub const ROUND_TRIPS_VERSION: u32 = 1;

/// The largest record read, in bytes: two nodes' days take about 100 kB.
pub const MAX_ROUND_TRIPS_BYTES: usize = 256 * 1024;

/// The slot a node keeps one round trip of, in seconds.
pub const ROUND_TRIP_SLOT_SECS: u64 = 30;

/// The span the idle reference is taken over, in seconds.
pub const IDLE_WINDOW_SECS: u64 = 86_400;

/// The most round trips a node keeps: a day of slots.
pub const MAX_ROUND_TRIPS_PER_NODE: usize = 2_880;

/// The record is not a version-1 record of round trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the record of direct-probe round trips is corrupt")]
pub struct RoundTripsCorrupt;

/// One round trip: when it was recorded, and how long it took in
/// milliseconds.
type Entry = (UnixTime, u64);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    nodes: BTreeMap<NodeId, Vec<Entry>>,
}

/// Every node's round trips of the last day.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundTrips {
    /// Each node's, in time order, one per slot at most.
    nodes: BTreeMap<NodeId, VecDeque<Entry>>,
}

impl RoundTrips {
    /// The record with no round trip.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `node`'s round trip of `ms` at `at`, and returns it with its
    /// idle reference: the 10th percentile, by nearest rank, of the node's
    /// round trips over the day up to `at`, this one among them. Those of
    /// `at`'s slot and of any later one give way to it, and those a day or
    /// more before it, or past [`MAX_ROUND_TRIPS_PER_NODE`], go.
    pub fn record(&mut self, node: &NodeId, at: UnixTime, ms: u64) -> RttSample {
        let entries = self.nodes.entry(node.clone()).or_default();
        while entries
            .back()
            .is_some_and(|&(newest, _)| slot(newest) >= slot(at))
        {
            entries.pop_back();
        }
        entries.push_back((at, ms));
        while entries.len() > MAX_ROUND_TRIPS_PER_NODE
            || entries
                .front()
                .is_some_and(|&(oldest, _)| at.as_secs() - oldest.as_secs() >= IDLE_WINDOW_SECS)
        {
            entries.pop_front();
        }
        let mut day: Vec<u64> = entries.iter().map(|&(_, ms)| ms).collect();
        day.sort_unstable();
        RttSample {
            loaded_ms: ms,
            // The nearest rank of the 10th percentile of n values is
            // ceil(n / 10); `day` holds this round trip at least.
            idle_p10_ms: day[day.len().div_ceil(10) - 1],
        }
    }

    /// Keeps only the nodes `keep` names; whether any went.
    pub fn retain(&mut self, mut keep: impl FnMut(&NodeId) -> bool) -> bool {
        let before = self.nodes.len();
        self.nodes.retain(|node, _| keep(node));
        self.nodes.len() != before
    }

    /// Reads a record the daemon wrote: version 1, each node's round trips
    /// one per slot in time order, at least one and at most
    /// [`MAX_ROUND_TRIPS_PER_NODE`]; anything else is corrupt.
    pub fn decode(bytes: &[u8]) -> Result<Self, RoundTripsCorrupt> {
        if bytes.len() > MAX_ROUND_TRIPS_BYTES {
            return Err(RoundTripsCorrupt);
        }
        let document: Document = serde_json::from_slice(bytes).map_err(|_| RoundTripsCorrupt)?;
        if document.version != ROUND_TRIPS_VERSION {
            return Err(RoundTripsCorrupt);
        }
        let mut nodes = BTreeMap::new();
        for (node, entries) in document.nodes {
            let ordered = entries
                .windows(2)
                .all(|pair| slot(pair[0].0) < slot(pair[1].0));
            if entries.is_empty() || entries.len() > MAX_ROUND_TRIPS_PER_NODE || !ordered {
                return Err(RoundTripsCorrupt);
            }
            nodes.insert(node, VecDeque::from(entries));
        }
        Ok(Self { nodes })
    }

    /// The record as the daemon writes it: one line of JSON.
    pub fn encode(&self) -> Result<Vec<u8>, RoundTripsCorrupt> {
        let mut bytes = serde_json::to_vec(&Document {
            version: ROUND_TRIPS_VERSION,
            nodes: self
                .nodes
                .iter()
                .map(|(node, entries)| (node.clone(), entries.iter().copied().collect()))
                .collect(),
        })
        .map_err(|_| RoundTripsCorrupt)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// The slot `at` lies in.
const fn slot(at: UnixTime) -> u64 {
    at.as_secs() / ROUND_TRIP_SLOT_SECS
}
