// SPDX-License-Identifier: GPL-3.0-or-later

//! Incremental Mac accounting: idempotent closed bins and authoritative
//! monthly snapshots. Missing detail remains missing; it is never filled
//! with invented zero bins. Aggregation and retention live separately.

mod aggregate;
mod retention;

use std::collections::BTreeMap;

use mooring_agent_proto::{Resolution, StatsEmail, Traffic, UsageMonth, UsageSeriesV1, UsageV1};
use mooring_model::{NodeId, UnixTime, UserId};
use serde::{Deserialize, Serialize};

use super::add;
use crate::error::UsageError;

/// Bound on the complete persisted document, including every node.
pub const MAX_COLLECTED_USAGE_BYTES: usize = 32 * 1024 * 1024;

/// One known bin. An empty map is a verified zero bin, not missing data.
type Counters = BTreeMap<StatsEmail, Traffic>;
type Bins = BTreeMap<u64, Counters>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MonthlyRecord {
    sample: UsageV1,
    received_at: UnixTime,
}

/// The Mac's history of a node. Constructors and ingestion validate the
/// typed wire data; decoding validates the persisted indexes again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeUsageHistory {
    months: BTreeMap<UsageMonth, MonthlyRecord>,
    five_min: Bins,
    hour: Bins,
    day: Bins,
    folded: Counters,
    #[serde(deserialize_with = "Option::deserialize")]
    origin: Option<UnixTime>,
    #[serde(deserialize_with = "Option::deserialize")]
    folded_before: Option<UsageMonth>,
    lifetime_complete: bool,
}

/// Versioned accounting, written only by the daemon under its instance lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedUsage {
    version: u32,
    nodes: BTreeMap<NodeId, NodeUsageHistory>,
    /// Last observation before revocation: an upper retention deadline
    /// derived from this never extends the actual revocation's deadline.
    last_nonrevoked: BTreeMap<UserId, UnixTime>,
}

impl Default for CollectedUsage {
    fn default() -> Self {
        Self {
            version: 1,
            nodes: BTreeMap::new(),
            last_nonrevoked: BTreeMap::new(),
        }
    }
}

fn corrupt(message: impl Into<String>) -> UsageError {
    UsageError::LedgerCorrupt {
        message: message.into(),
    }
}

impl CollectedUsage {
    /// Reads the bounded versioned document. No failure is converted into an empty ledger.
    pub fn decode(bytes: &[u8]) -> Result<Self, UsageError> {
        if bytes.len() > MAX_COLLECTED_USAGE_BYTES {
            return Err(corrupt("document exceeds 32 MiB"));
        }
        let history: Self = serde_json::from_slice(bytes).map_err(|e| corrupt(e.to_string()))?;
        if history.version != 1 {
            return Err(corrupt(format!("unsupported version {}", history.version)));
        }
        for node in history.nodes.values() {
            node.validate()?;
        }
        Ok(history)
    }

    /// Encodes with the same bound readers enforce.
    pub fn encode(&self) -> Result<Vec<u8>, UsageError> {
        for node in self.nodes.values() {
            node.validate()?;
        }
        let bytes = serde_json::to_vec(self).map_err(|e| corrupt(e.to_string()))?;
        if bytes.len() > MAX_COLLECTED_USAGE_BYTES {
            return Err(corrupt("document exceeds 32 MiB"));
        }
        Ok(bytes)
    }

    /// The recorded history, if any.
    pub fn node(&self, node: &NodeId) -> Option<&NodeUsageHistory> {
        self.nodes.get(node)
    }

    /// Installs one completely collected node batch after its durable write
    /// has been prepared by the caller.
    pub fn set_node(&mut self, node: NodeId, history: NodeUsageHistory) {
        self.nodes.insert(node, history);
    }

    /// Records a node observed while still planned, before it could serve.
    /// Existing applied nodes deliberately retain an unknown lifetime origin.
    pub fn observe_unserved(&mut self, node: NodeId, at: UnixTime) {
        self.nodes.entry(node).or_insert_with(|| NodeUsageHistory {
            origin: Some(at),
            lifetime_complete: true,
            ..NodeUsageHistory::default()
        });
    }
}

impl NodeUsageHistory {
    /// Latest fully received five-minute bin boundary, for the next pull.
    pub fn detail_through(&self) -> Option<u64> {
        self.five_min.last_key_value().map(|(at, _)| at + 300)
    }

    /// The latest monthly observation, retained for diagnostics and scheduling.
    pub fn latest_sample(&self) -> Option<UnixTime> {
        self.months
            .values()
            .map(|month| UnixTime::from_secs(month.sample.updated_at.as_secs()))
            .max()
    }

    /// Adds a monthly snapshot, rejecting time/counter regressions and wrong
    /// calendar placement. The monthly key is echoed by the wire reply.
    pub fn record_month(
        &mut self,
        node: &NodeId,
        sample: UsageV1,
        received_at: UnixTime,
    ) -> Result<(), UsageError> {
        if self
            .folded_before
            .is_some_and(|before| sample.month < before)
        {
            return Err(corrupt("month was already folded into lifetime"));
        }
        let start = sample.month.start().as_secs();
        let end = sample
            .month
            .next()
            .ok_or_else(|| corrupt("month has no successor"))?
            .start()
            .as_secs();
        let at = sample.updated_at.as_secs();
        if at < start || at > end {
            return Err(corrupt("monthly sample is outside its month"));
        }
        if sample.updated_at.as_secs() > received_at.as_secs() {
            return Err(corrupt("accounting sample is in the future"));
        }
        if let Some(record) = self.months.get(&sample.month) {
            if received_at < record.received_at {
                return Err(corrupt("collection clock moved backwards"));
            }
            let old = &record.sample;
            if sample.updated_at < old.updated_at
                || old.traffic.iter().any(|(email, bytes)| {
                    let next = sample.traffic.get(email).copied().unwrap_or_default();
                    next.uplink < bytes.uplink || next.downlink < bytes.downlink
                })
                || (sample.updated_at == old.updated_at && sample != *old)
            {
                return Err(UsageError::MonthlyInconsistent { node: node.clone() });
            }
        }
        self.months.insert(
            sample.month,
            MonthlyRecord {
                sample,
                received_at,
            },
        );
        Ok(())
    }

    /// Adds an echoed closed range. Replaying it is idempotent; a different
    /// value for an already closed bin is a contradiction, never an increment.
    pub fn record_series(
        &mut self,
        node: &NodeId,
        series: &UsageSeriesV1,
    ) -> Result<(), UsageError> {
        let span = series.range().span();
        if span.resolution() != Resolution::FiveMin {
            return Err(corrupt("collector requires five-minute source bins"));
        }
        let supplied: BTreeMap<_, _> = series
            .bins()
            .iter()
            .map(|bin| (bin.start().as_secs(), bin.traffic().clone()))
            .collect();
        let mut staged = self.five_min.clone();
        for index in 0..span.bins() {
            let at = span.from().as_secs() + index * 300;
            let traffic = supplied.get(&at).cloned().unwrap_or_default();
            if staged.get(&at).is_some_and(|old| old != &traffic) {
                return Err(UsageError::MonthlyInconsistent { node: node.clone() });
            }
            staged.insert(at, traffic);
        }
        let hours = fold_complete(&staged, 300, 3600)?;
        let mut all_hours = self.hour.clone();
        merge_bins(node, &mut all_hours, hours)?;
        let days = fold_complete(&all_hours, 3600, 86_400)?;
        let mut all_days = self.day.clone();
        merge_bins(node, &mut all_days, days)?;
        self.five_min = staged;
        self.hour = all_hours;
        self.day = all_days;
        Ok(())
    }

    fn validate(&self) -> Result<(), UsageError> {
        for (bins, width) in [
            (&self.five_min, 300),
            (&self.hour, 3600),
            (&self.day, 86_400),
        ] {
            if bins
                .keys()
                .any(|at| !at.is_multiple_of(width) || at.checked_add(width).is_none())
            {
                return Err(corrupt("bin index is unaligned or overflows"));
            }
        }
        for (month, record) in &self.months {
            let sample = &record.sample;
            if sample.updated_at.as_secs() > record.received_at.as_secs()
                || sample.month != *month
                || sample.updated_at < month.start()
                || month
                    .next()
                    .is_none_or(|next| sample.updated_at > next.start())
            {
                return Err(corrupt("monthly index and sample disagree"));
            }
        }
        if self.lifetime_complete && self.origin.is_none() {
            return Err(corrupt("complete lifetime has no origin"));
        }
        if (!self.folded.is_empty() && self.folded_before.is_none())
            || self
                .folded_before
                .is_some_and(|before| self.months.keys().any(|month| *month < before))
        {
            return Err(corrupt("folded lifetime overlaps retained months"));
        }
        for (fine, from, coarse, to) in [
            (&self.five_min, 300, &self.hour, 3600),
            (&self.hour, 3600, &self.day, 86_400),
        ] {
            for (at, bytes) in fold_complete(fine, from, to)? {
                if coarse.get(&at).is_some_and(|held| held != &bytes) {
                    return Err(corrupt("detail and its retained rollup disagree"));
                }
            }
        }
        Ok(())
    }

    /// A complete detailed range, choosing the coarsest available bins.
    /// None is a gap; an empty map is a range proven to contain no traffic.
    fn detailed(&self, mut from: u64, to: u64) -> Result<Option<Counters>, UsageError> {
        if from > to {
            return Ok(None);
        }
        let mut total = Counters::new();
        while from < to {
            let next = [
                (&self.day, 86_400),
                (&self.hour, 3600),
                (&self.five_min, 300),
            ]
            .into_iter()
            .find_map(|(bins, width)| {
                (from.is_multiple_of(width) && from.checked_add(width).is_some_and(|end| end <= to))
                    .then(|| bins.get(&from).map(|bytes| (width, bytes)))
                    .flatten()
            });
            let Some((width, bytes)) = next else {
                return Ok(None);
            };
            add_counters(&mut total, bytes)?;
            from += width;
        }
        Ok(Some(total))
    }
}

fn add_counters(total: &mut Counters, added: &Counters) -> Result<(), UsageError> {
    for (email, bytes) in added {
        add(total.entry(email.clone()).or_default(), *bytes)?;
    }
    Ok(())
}

fn merge_bins(node: &NodeId, into: &mut Bins, bins: Bins) -> Result<(), UsageError> {
    for (at, bytes) in bins {
        if into.get(&at).is_some_and(|old| old != &bytes) {
            return Err(UsageError::MonthlyInconsistent { node: node.clone() });
        }
        into.insert(at, bytes);
    }
    Ok(())
}

fn fold_complete(source: &Bins, from_width: u64, to_width: u64) -> Result<Bins, UsageError> {
    let mut folded = Bins::new();
    for &at in source.keys().filter(|at| at.is_multiple_of(to_width)) {
        let mut total = Counters::new();
        let mut complete = true;
        for offset in 0..to_width / from_width {
            let Some(bytes) = source.get(&(at + offset * from_width)) else {
                complete = false;
                break;
            };
            add_counters(&mut total, bytes)?;
        }
        if complete {
            folded.insert(at, total);
        }
    }
    Ok(folded)
}
