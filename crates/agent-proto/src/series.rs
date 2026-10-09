// SPDX-License-Identifier: GPL-3.0-or-later

//! Usage time series (design §11.5, console spec B.2): bytes per
//! accounting email per time bin, the reply to `UsageSeries`. Like the
//! monthly totals, it records no destinations and no addresses.
//!
//! # Size
//!
//! A reply must fit one frame ([`crate::MAX_RESPONSE_LINE_BYTES`]). The
//! model sets no upper bound on users (the admission cap is unset until the
//! operator chooses one, and even then may be up to 65,535), so no time
//! range alone bounds a reply. Two bounds do, together:
//!
//! - a request spans at most [`Resolution::max_bins`] bins, so the agent
//!   reads a bounded range;
//! - a reply carries at most [`MAX_SERIES_ENTRIES`] entries, so with the
//!   longest accounting emails and counters it is at most
//!   [`MAX_USAGE_SERIES_REPLY_BYTES`] long, which a compile-time assertion
//!   holds below the frame limit.
//!
//! A full range fits within the entry bound for up to 27 users active in
//! every bin of it, which covers the design's capacity estimate for one
//! mobile line (console spec D.1: about 26 light users at most). When a range
//! holds more entries, the agent refuses it with
//! [`crate::AgentError::SeriesTooLarge`], naming how many of its bins fit,
//! and the Mac asks for that shorter range.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::usage::MAX_OPAQUE_USER_ID_BYTES;
use crate::{Inbound, MAX_RESPONSE_LINE_BYTES, StatsEmail, Traffic, UnixTime, ValueError};

closed_enum! {
    /// The width of a usage bin. A bin starts on a multiple of its width in
    /// Unix time, so hour bins are UTC hours (whole hours in Europe/London
    /// and Asia/Shanghai too) and day bins are UTC days.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Resolution {
        /// Five minutes.
        FiveMin,
        /// One hour.
        Hour,
        /// One UTC day.
        Day,
    }
}

impl Resolution {
    /// The bin width in seconds.
    pub const fn bin_secs(self) -> u64 {
        match self {
            Self::FiveMin => 300,
            Self::Hour => 3600,
            Self::Day => 86_400,
        }
    }

    /// The most bins one `UsageSeries` request may span: 12 hours of
    /// five-minute bins, 7 days of hour bins and 35 days of day bins (the
    /// console's daily chart). Each is small enough that a full range of
    /// 27 users active in every bin stays within [`MAX_SERIES_ENTRIES`].
    pub const fn max_bins(self) -> u64 {
        match self {
            Self::FiveMin => 144,
            Self::Hour => 168,
            Self::Day => 35,
        }
    }
}

/// Whole bins of one resolution: `[from, to)`, both on bin boundaries, with
/// `from` before `to`. It has no length bound; [`SeriesRange`] adds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawSeriesSpan")]
pub struct SeriesSpan {
    from: UnixTime,
    to: UnixTime,
    resolution: Resolution,
}

impl SeriesSpan {
    /// Validates that `from` and `to` lie on bin boundaries of
    /// `resolution` and that `from` is before `to`.
    pub const fn new(
        from: UnixTime,
        to: UnixTime,
        resolution: Resolution,
    ) -> Result<Self, ValueError> {
        let width = resolution.bin_secs();
        if from.as_secs().is_multiple_of(width)
            && to.as_secs().is_multiple_of(width)
            && from.as_secs() < to.as_secs()
        {
            Ok(Self {
                from,
                to,
                resolution,
            })
        } else {
            Err(ValueError::SeriesSpan)
        }
    }

    /// The start of the first bin.
    pub const fn from(self) -> UnixTime {
        self.from
    }

    /// The end of the last bin (exclusive).
    pub const fn to(self) -> UnixTime {
        self.to
    }

    /// The bin width.
    pub const fn resolution(self) -> Resolution {
        self.resolution
    }

    /// The number of bins, at least 1.
    pub const fn bins(self) -> u64 {
        (self.to.as_secs() - self.from.as_secs()) / self.resolution.bin_secs()
    }

    /// Whether a bin of this span starts at `start`.
    pub const fn has_bin_at(self, start: UnixTime) -> bool {
        let start = start.as_secs();
        start >= self.from.as_secs()
            && start < self.to.as_secs()
            && start.is_multiple_of(self.resolution.bin_secs())
    }
}

/// The unvalidated wire shape of [`SeriesSpan`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSeriesSpan {
    from: UnixTime,
    to: UnixTime,
    resolution: Resolution,
}

impl TryFrom<RawSeriesSpan> for SeriesSpan {
    type Error = ValueError;

    fn try_from(raw: RawSeriesSpan) -> Result<Self, Self::Error> {
        Self::new(raw.from, raw.to, raw.resolution)
    }
}

/// The span of one `UsageSeries` request: whole bins, at most
/// [`Resolution::max_bins`] of them. On the wire it is its [`SeriesSpan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SeriesSpan", into = "SeriesSpan")]
pub struct SeriesRange(SeriesSpan);

impl SeriesRange {
    /// Validates a span (see [`SeriesSpan::new`]) of at most
    /// `resolution.max_bins()` bins; a longer one is
    /// [`ValueError::RangeTooLarge`].
    pub const fn new(
        from: UnixTime,
        to: UnixTime,
        resolution: Resolution,
    ) -> Result<Self, ValueError> {
        match SeriesSpan::new(from, to, resolution) {
            Ok(span) => Self::of(span),
            Err(error) => Err(error),
        }
    }

    const fn of(span: SeriesSpan) -> Result<Self, ValueError> {
        let bins = span.bins();
        if bins <= span.resolution.max_bins() {
            Ok(Self(span))
        } else {
            Err(ValueError::RangeTooLarge {
                resolution: span.resolution,
                bins,
            })
        }
    }

    /// The span.
    pub const fn span(self) -> SeriesSpan {
        self.0
    }
}

impl TryFrom<SeriesSpan> for SeriesRange {
    type Error = ValueError;

    fn try_from(span: SeriesSpan) -> Result<Self, Self::Error> {
        Self::of(span)
    }
}

impl From<SeriesRange> for SeriesSpan {
    fn from(range: SeriesRange) -> Self {
        range.0
    }
}

/// One bin's non-zero traffic: every accounting email whose counters grew
/// during the bin, and nothing else. A bin in which nothing grew is not
/// sent at all.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawUsageBin")]
pub struct UsageBin {
    start: UnixTime,
    traffic: BTreeMap<StatsEmail, Traffic>,
}

impl UsageBin {
    /// Validates that `traffic` is not empty and holds no all-zero entry
    /// ([`ValueError::UsageBin`] otherwise).
    pub fn new(
        start: UnixTime,
        traffic: BTreeMap<StatsEmail, Traffic>,
    ) -> Result<Self, ValueError> {
        if traffic.is_empty()
            || traffic
                .values()
                .any(|bytes| bytes.uplink == 0 && bytes.downlink == 0)
        {
            Err(ValueError::UsageBin)
        } else {
            Ok(Self { start, traffic })
        }
    }

    /// The bin's start.
    pub const fn start(&self) -> UnixTime {
        self.start
    }

    /// The bytes per accounting email.
    pub const fn traffic(&self) -> &BTreeMap<StatsEmail, Traffic> {
        &self.traffic
    }
}

/// The unvalidated wire shape of [`UsageBin`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUsageBin {
    start: UnixTime,
    traffic: BTreeMap<StatsEmail, Traffic>,
}

impl TryFrom<RawUsageBin> for UsageBin {
    type Error = ValueError;

    fn try_from(raw: RawUsageBin) -> Result<Self, Self::Error> {
        Self::new(raw.start, raw.traffic)
    }
}

/// The most traffic entries (accounting email × bin) one
/// [`UsageSeriesV1`] carries.
pub const MAX_SERIES_ENTRIES: usize = 9_600;

/// The usage of every bin of `range`, the reply to `UsageSeries`. It echoes
/// the request's range, so the Mac can check that the reply answers it.
///
/// The agent answers only for a range it holds every bin of: a bin of the
/// range that is absent here had no traffic. A range it does not hold
/// completely is refused with [`crate::AgentError::SeriesNotRecorded`],
/// never answered with zeros.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawUsageSeries")]
pub struct UsageSeriesV1 {
    range: SeriesRange,
    bins: Vec<UsageBin>,
}

impl UsageSeriesV1 {
    /// Validates that every bin starts on a bin boundary inside `range`, in
    /// increasing order with no bin repeated, and that the bins hold at
    /// most [`MAX_SERIES_ENTRIES`] entries ([`ValueError::UsageSeries`]
    /// otherwise).
    pub fn new(range: SeriesRange, bins: Vec<UsageBin>) -> Result<Self, ValueError> {
        let span = range.span();
        let mut entries = 0_usize;
        let mut previous: Option<UnixTime> = None;
        for bin in &bins {
            entries += bin.traffic.len();
            let in_order = previous.is_none_or(|previous| previous < bin.start);
            if !span.has_bin_at(bin.start) || !in_order || entries > MAX_SERIES_ENTRIES {
                return Err(ValueError::UsageSeries);
            }
            previous = Some(bin.start);
        }
        Ok(Self { range, bins })
    }

    /// The range the reply covers.
    pub const fn range(&self) -> SeriesRange {
        self.range
    }

    /// The bins with traffic, in time order.
    pub fn bins(&self) -> &[UsageBin] {
        &self.bins
    }
}

/// The unvalidated wire shape of [`UsageSeriesV1`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUsageSeries {
    range: SeriesRange,
    bins: Vec<UsageBin>,
}

impl TryFrom<RawUsageSeries> for UsageSeriesV1 {
    type Error = ValueError;

    fn try_from(raw: RawUsageSeries) -> Result<Self, Self::Error> {
        Self::new(raw.range, raw.bins)
    }
}

pub(crate) const fn decimal_digits(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

/// The longest wire number in a reply: a `u64`.
pub(crate) const NUMBER_BYTES: usize = decimal_digits(u64::MAX);

const fn longest_inbound() -> usize {
    let mut longest = 0;
    let mut index = 0;
    while index < Inbound::ALL.len() {
        let len = Inbound::ALL[index].as_str().len();
        if len > longest {
            longest = len;
        }
        index += 1;
    }
    longest
}

const fn most_bins() -> usize {
    let mut most = 0;
    let mut index = 0;
    while index < Resolution::ALL.len() {
        let bins = Resolution::ALL[index].max_bins() as usize;
        if bins > most {
            most = bins;
        }
        index += 1;
    }
    most
}

/// `"<principal>@<inbound>":{"uplink":N,"downlink":N}` and the comma that
/// may follow it, with the longest principal and inbound.
const ENTRY_BYTES: usize = "\"@\"".len()
    + MAX_OPAQUE_USER_ID_BYTES
    + longest_inbound()
    + ":{\"uplink\":,\"downlink\":}".len()
    + 2 * NUMBER_BYTES
    + ",".len();

/// `{"start":N,"traffic":{…}}` around a bin's entries, and the comma that
/// may follow it.
const BIN_BYTES: usize = "{\"start\":,\"traffic\":{}}".len() + NUMBER_BYTES + ",".len();

/// The reply around the bins, with the longest resolution name (`FiveMin`).
const ENVELOPE_BYTES: usize =
    "{\"Ok\":{\"UsageSeries\":{\"range\":{\"from\":,\"to\":,\"resolution\":\"FiveMin\"},\"bins\":[]}}}"
        .len()
        + 2 * NUMBER_BYTES;

/// An upper bound on the length of a reply line carrying a
/// [`UsageSeriesV1`]: the envelope, [`Resolution::max_bins`] bins of the
/// widest resolution, and [`MAX_SERIES_ENTRIES`] entries of the longest
/// accounting email with both counters at `u64::MAX`.
pub const MAX_USAGE_SERIES_REPLY_BYTES: usize =
    ENVELOPE_BYTES + most_bins() * BIN_BYTES + MAX_SERIES_ENTRIES * ENTRY_BYTES;

const _: () = assert!(MAX_USAGE_SERIES_REPLY_BYTES <= MAX_RESPONSE_LINE_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    fn time(secs: u64) -> UnixTime {
        UnixTime::from_secs(secs)
    }

    #[test]
    fn widths_and_bounds_are_the_documented_ones() {
        let widths: Vec<u64> = Resolution::ALL.iter().map(|r| r.bin_secs()).collect();
        assert_eq!(widths, [300, 3600, 86_400]);
        let bins: Vec<u64> = Resolution::ALL.iter().map(|r| r.max_bins()).collect();
        assert_eq!(bins, [144, 168, 35]);
        assert_eq!(NUMBER_BYTES, u64::MAX.to_string().len());
        assert_eq!(longest_inbound(), "reality".len());
        assert_eq!(most_bins(), 168);
        // The figure design §11.1 quotes.
        assert_eq!(MAX_USAGE_SERIES_REPLY_BYTES, 1_034_713);
    }

    /// 27 users and the probe, each counted on both inbounds in every bin
    /// of a full range, fit one reply at every resolution; 28 do not at
    /// the hour resolution.
    #[test]
    fn a_full_range_fits_for_the_designed_capacity() {
        let entries_per_bin = |users: u64| 2 * (users + 1);
        for resolution in Resolution::ALL {
            let full = resolution.max_bins() * entries_per_bin(27);
            assert!(full <= MAX_SERIES_ENTRIES as u64, "{resolution:?}");
        }
        assert!(Resolution::Hour.max_bins() * entries_per_bin(28) > MAX_SERIES_ENTRIES as u64);
    }

    #[test]
    fn spans_are_whole_bins_in_order() {
        let span = SeriesSpan::new(time(600), time(1500), Resolution::FiveMin).unwrap();
        assert_eq!(
            (span.from(), span.to(), span.bins()),
            (time(600), time(1500), 3)
        );
        assert!(span.has_bin_at(time(600)) && span.has_bin_at(time(1200)));
        assert!(!span.has_bin_at(time(300)) && !span.has_bin_at(time(1500)));
        assert!(!span.has_bin_at(time(900 + 1)));
        for (from, to) in [(600, 600), (900, 600), (601, 1500), (600, 1501)] {
            assert_eq!(
                SeriesSpan::new(time(from), time(to), Resolution::FiveMin),
                Err(ValueError::SeriesSpan),
                "{from}..{to}"
            );
        }
        assert_eq!(
            SeriesSpan::new(time(0), time(3600), Resolution::Day),
            Err(ValueError::SeriesSpan)
        );
    }

    #[test]
    fn ranges_hold_at_most_max_bins() {
        for resolution in Resolution::ALL.iter().copied() {
            let width = resolution.bin_secs();
            let longest = time(resolution.max_bins() * width);
            let range = SeriesRange::new(time(0), longest, resolution).unwrap();
            assert_eq!(range.span().bins(), resolution.max_bins());
            assert_eq!(
                SeriesRange::new(time(0), time(longest.as_secs() + width), resolution),
                Err(ValueError::RangeTooLarge {
                    resolution,
                    bins: resolution.max_bins() + 1
                })
            );
        }
        assert_eq!(
            SeriesRange::new(time(1), time(301), Resolution::FiveMin),
            Err(ValueError::SeriesSpan)
        );
    }

    #[test]
    fn a_range_travels_as_its_span_and_is_checked_on_receipt() {
        let range = SeriesRange::new(time(3600), time(7200), Resolution::Hour).unwrap();
        let json = serde_json::to_string(&range).unwrap();
        assert_eq!(json, r#"{"from":3600,"to":7200,"resolution":"Hour"}"#);
        assert_eq!(serde_json::from_str::<SeriesRange>(&json).unwrap(), range);
        let too_long = format!(r#"{{"from":0,"to":{},"resolution":"Hour"}}"#, 169 * 3600);
        assert!(serde_json::from_str::<SeriesRange>(&too_long).is_err());
        assert!(serde_json::from_str::<SeriesSpan>(&too_long).is_ok());
        assert!(
            serde_json::from_str::<SeriesRange>(r#"{"from":0,"to":0,"resolution":"Hour"}"#)
                .is_err()
        );
    }
}
