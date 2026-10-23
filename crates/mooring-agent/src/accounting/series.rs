// SPDX-License-Identifier: GPL-3.0-or-later

//! The usage series behind `UsageSeries` (design §11.5): what each poll
//! added per accounting email, in five-minute, hour and day bins, kept
//! for [`SERIES_KEEP_SECS`] after each bin ends (F7).
//!
//! A poll adds what Xray counted since the poll before to the bins holding
//! its last second, so a bin holds the polls that end inside it. A bin is
//! *held* only when one stretch of consecutive polls ([`Recorded`]) covers
//! it from before its start to its end: the first poll of a stretch is
//! only its baseline, and a gap between polls longer than
//! [`MAX_POLL_GAP_SECS`] (the watch stopped, Xray down) ends the stretch,
//! because a delta across it cannot be placed in bins. So does a poll the
//! series could not take (one at or before the latest it took, after the
//! clock stepped back): a stretch continues only from the very poll it
//! last took, by number.
//! A range with a bin that is not held is refused, never answered with
//! zeros. Expiry is judged at the later of now and the latest pruning, so
//! a pruned bin is never taken for one without traffic, even after the
//! clock stepped back.

use std::collections::BTreeMap;

use mooring_agent_proto::{
    AgentError, IoOp, MAX_SERIES_ENTRIES, Resolution, SeriesRange, SeriesSpan, StatsEmail, Traffic,
    UnixTime, UsageBin, UsageSeriesV1,
};
use serde::{Deserialize, Serialize};

use crate::store::malformed;

/// How long a bin is kept after it ends: 48 hours (F7, design §11.5).
pub(crate) const SERIES_KEEP_SECS: u64 = 48 * 3600;

/// The longest gap between two polls that one stretch spans: three
/// accounting intervals, so a missed poll or a quick restart of the watch
/// or of Xray (the nightly reboot included) keeps the series whole.
pub(crate) const MAX_POLL_GAP_SECS: u64 = 3 * mooring_agent_proto::ACCOUNTING_INTERVAL_SECS;

/// One stretch of consecutive polls: from its first, whose counters are
/// only a baseline, to its latest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Recorded {
    pub(crate) from: UnixTime,
    pub(crate) through: UnixTime,
}

/// The bins kept and the stretches they were recorded in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Series {
    /// Oldest first; each starts after the one before ends.
    recorded: Vec<Recorded>,
    five_min: Vec<UsageBin>,
    hour: Vec<UsageBin>,
    day: Vec<UsageBin>,
    /// The latest time the series was pruned at.
    #[serde(deserialize_with = "Option::deserialize")]
    pruned_at: Option<UnixTime>,
    /// The number of the latest poll the series took.
    #[serde(deserialize_with = "Option::deserialize")]
    latest_poll: Option<u64>,
}

impl Series {
    const fn bins(&self, resolution: Resolution) -> &Vec<UsageBin> {
        match resolution {
            Resolution::FiveMin => &self.five_min,
            Resolution::Hour => &self.hour,
            Resolution::Day => &self.day,
        }
    }

    const fn bins_mut(&mut self, resolution: Resolution) -> &mut Vec<UsageBin> {
        match resolution {
            Resolution::FiveMin => &mut self.five_min,
            Resolution::Hour => &mut self.hour,
            Resolution::Day => &mut self.day,
        }
    }

    /// The time expiry is judged at: the later of `now` and the latest
    /// pruning.
    fn judged_at(&self, now: UnixTime) -> UnixTime {
        self.pruned_at.map_or(now, |pruned| pruned.max(now))
    }

    /// Records poll number `poll`, at `at`, whose poll before was number
    /// `previous`: when that is the poll the series took last and `at`
    /// follows it within [`MAX_POLL_GAP_SECS`], the stretch continues to
    /// `at` and `added` goes into the bins; otherwise `at` starts a new
    /// stretch (and `added` is in no bin). A poll at or before the latest
    /// one taken is not taken. Returns whether the stretch continued.
    pub(crate) fn record(
        &mut self,
        poll: u64,
        at: UnixTime,
        previous: Option<u64>,
        added: &BTreeMap<StatsEmail, Traffic>,
    ) -> bool {
        let latest = self.recorded.last().map(|stretch| stretch.through);
        if latest.is_some_and(|through| at <= through) {
            return false;
        }
        let continues = previous.is_some()
            && previous == self.latest_poll
            && latest.is_some_and(|through| {
                at.secs_since(through)
                    .is_some_and(|gap| gap <= MAX_POLL_GAP_SECS)
            });
        self.latest_poll = Some(poll);
        match self.recorded.last_mut() {
            Some(stretch) if continues => stretch.through = at,
            _ => self.recorded.push(Recorded {
                from: at,
                through: at,
            }),
        }
        if continues {
            for &resolution in Resolution::ALL {
                self.add(resolution, at, added);
            }
        }
        continues
    }

    /// Adds the entries of `added` that grew to the bin of `resolution`
    /// holding the second before `at`.
    fn add(&mut self, resolution: Resolution, at: UnixTime, added: &BTreeMap<StatsEmail, Traffic>) {
        let width = resolution.bin_secs();
        let start = UnixTime::from_secs(at.as_secs().saturating_sub(1) / width * width);
        let bins = self.bins_mut(resolution);
        let position = bins.partition_point(|bin| bin.start() < start);
        let existing = bins.get(position).filter(|bin| bin.start() == start);
        let replaces = existing.is_some();
        let mut traffic = existing
            .map(|bin| bin.traffic().clone())
            .unwrap_or_default();
        for (email, bytes) in added {
            if bytes.uplink == 0 && bytes.downlink == 0 {
                continue;
            }
            let total = traffic.entry(email.clone()).or_default();
            total.uplink = total.uplink.saturating_add(bytes.uplink);
            total.downlink = total.downlink.saturating_add(bytes.downlink);
        }
        // Every entry grew, so the only bin refused is an empty one: no bin
        // before, and nothing that grew.
        let Ok(bin) = UsageBin::new(start, traffic) else {
            return;
        };
        if replaces {
            bins[position] = bin;
        } else {
            bins.insert(position, bin);
        }
    }

    /// Removes the bins that ended [`SERIES_KEEP_SECS`] or longer before
    /// `now`, and the stretches no kept bin can lie in; returns whether
    /// anything was removed.
    pub(crate) fn prune(&mut self, now: UnixTime) -> bool {
        let now = self.judged_at(now);
        self.pruned_at = Some(now);
        let before = (
            self.recorded.len(),
            self.five_min.len(),
            self.hour.len(),
            self.day.len(),
        );
        for &resolution in Resolution::ALL {
            let width = resolution.bin_secs();
            self.bins_mut(resolution)
                .retain(|bin| !expired(now, bin.start().as_secs().saturating_add(width)));
        }
        self.recorded
            .retain(|stretch| !expired(now, stretch.through.as_secs()));
        before
            != (
                self.recorded.len(),
                self.five_min.len(),
                self.hour.len(),
                self.day.len(),
            )
    }

    /// Whether the bin of `resolution` starting at `start` is held at
    /// `now`: kept, and inside one stretch.
    fn holds(&self, resolution: Resolution, start: u64, now: UnixTime) -> bool {
        let end = start.saturating_add(resolution.bin_secs());
        !expired(self.judged_at(now), end)
            && self
                .recorded
                .iter()
                .any(|stretch| stretch.from.as_secs() <= start && end <= stretch.through.as_secs())
    }

    /// The bins of the most recent stretch that holds any at
    /// `resolution`, as one span; `None` when none is held.
    fn recorded_span(&self, resolution: Resolution, now: UnixTime) -> Option<SeriesSpan> {
        let width = resolution.bin_secs();
        let horizon = self
            .judged_at(now)
            .as_secs()
            .saturating_sub(SERIES_KEEP_SECS);
        // The first bin still kept: the first whose end is after the horizon.
        let first_kept = horizon / width * width;
        self.recorded.iter().rev().find_map(|stretch| {
            let first = stretch.from.as_secs().div_ceil(width) * width;
            let to = stretch.through.as_secs() / width * width;
            SeriesSpan::new(
                UnixTime::from_secs(first.max(first_kept)),
                UnixTime::from_secs(to),
                resolution,
            )
            .ok()
        })
    }

    /// `UsageSeries{range}` at `now`: every bin of the range with traffic,
    /// when every bin of it is held (else `SeriesNotRecorded`, naming the
    /// latest span held) and their entries fit one reply (else
    /// `SeriesTooLarge`, naming how many bins from the start do).
    pub(crate) fn answer(
        &self,
        range: SeriesRange,
        now: UnixTime,
    ) -> Result<UsageSeriesV1, AgentError> {
        let span = range.span();
        let resolution = span.resolution();
        let width = resolution.bin_secs();
        let from = span.from().as_secs();
        let all_held =
            (0..span.bins()).all(|index| self.holds(resolution, from + index * width, now));
        if !all_held {
            return Err(AgentError::SeriesNotRecorded {
                recorded: self.recorded_span(resolution, now),
            });
        }
        let bins: Vec<UsageBin> = self
            .bins(resolution)
            .iter()
            .filter(|bin| span.has_bin_at(bin.start()))
            .cloned()
            .collect();
        let mut entries = 0_usize;
        for bin in &bins {
            entries += bin.traffic().len();
            if entries > MAX_SERIES_ENTRIES {
                let fitting = (bin.start().as_secs() - from) / width;
                return Err(AgentError::SeriesTooLarge {
                    fitting_bins: u32::try_from(fitting).map_err(|_| malformed(IoOp::ReadState))?,
                });
            }
        }
        UsageSeriesV1::new(range, bins).map_err(|_| malformed(IoOp::ReadState))
    }
}

/// Whether something that ended at `end` is past [`SERIES_KEEP_SECS`] at
/// `now`.
fn expired(now: UnixTime, end: u64) -> bool {
    now.as_secs() >= end.saturating_add(SERIES_KEEP_SECS)
}
