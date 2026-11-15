// SPDX-License-Identifier: GPL-3.0-or-later

//! The egress rates a capacity sample carries (console spec B.2.8): the
//! bytes the SIM meter counted over the last minute, per second. The
//! meter's thread hands over each count as it reads the counters, every
//! 2 s ([`crate::meter::Counted`]).
//!
//! The window keeps the shortest run of the latest counts that spans a
//! minute, so its span is a minute and at most one count more. No rate is
//! given while it spans less: after the meter started, after a count the
//! meter marked short (counters that restarted, counted whole; a gap a
//! wrap could hide in; a clock that stepped back), which says nothing of a
//! rate and starts the minute again, and after a count that does not
//! follow the one before it, whose bytes in between are not counted. Nor
//! is one given once the newest count is more than [`MAX_RATE_AGE_SECS`]
//! old: the meter has stopped reading (the egress went away, or the Mac
//! slept).
//!
//! The counts' times are whole seconds, so a rate over a minute is within
//! about 2% of the true one.

use std::collections::VecDeque;

use mooring_model::UnixTime;

use crate::meter::Counted;

/// The span the rates are averaged over, in seconds.
pub const RATE_WINDOW_SECS: u64 = 60;

/// The oldest the newest count may be for a rate, in seconds: five of the
/// meter's readings.
pub const MAX_RATE_AGE_SECS: u64 = 10;

/// The most counts the window keeps: a minute of readings every 2 s is 30.
/// Past it the oldest go, so counts that span no time (readings within one
/// second) cannot grow the window without bound.
pub const MAX_RATE_COUNTS: usize = 64;

/// The egress rates over the last minute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EgressRate {
    /// The transmit rate (towards the carrier), in bit/s.
    pub tx_bps: u64,
    /// The receive rate, in bit/s.
    pub rx_bps: u64,
}

/// The counts the rates are made of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressRates {
    /// Counts that follow each other: each starts when the one before it
    /// ended.
    counts: VecDeque<Counted>,
}

impl EgressRates {
    /// A window with no count.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes in the meter's next count. A short count, or one that ends
    /// before it starts, empties the window; one that does not start where
    /// the newest ended starts it again; and the oldest counts go while
    /// the rest still span a minute, or past [`MAX_RATE_COUNTS`].
    pub fn observe(&mut self, counted: Counted) {
        if counted.short || counted.at < counted.since {
            self.counts.clear();
            return;
        }
        if self
            .counts
            .back()
            .is_some_and(|newest| newest.at != counted.since)
        {
            self.counts.clear();
        }
        self.counts.push_back(counted);
        while self.counts.len() > MAX_RATE_COUNTS
            || self.counts.get(1).is_some_and(|second| {
                counted.at.as_secs() - second.since.as_secs() >= RATE_WINDOW_SECS
            })
        {
            self.counts.pop_front();
        }
    }

    /// The rates over the window at `now`: none while it spans less than a
    /// minute, or once its newest count is more than [`MAX_RATE_AGE_SECS`]
    /// before `now`. A rate beyond `u64::MAX` bit/s reads as `u64::MAX`.
    #[must_use]
    pub fn over_last_minute(&self, now: UnixTime) -> Option<EgressRate> {
        let (oldest, newest) = (self.counts.front()?, self.counts.back()?);
        if now.as_secs().saturating_sub(newest.at.as_secs()) > MAX_RATE_AGE_SECS {
            return None;
        }
        let span = newest.at.as_secs() - oldest.since.as_secs();
        if span < RATE_WINDOW_SECS {
            return None;
        }
        let (rx, tx) = self
            .counts
            .iter()
            .fold((0_u128, 0_u128), |(rx, tx), counted| {
                (rx + u128::from(counted.rx), tx + u128::from(counted.tx))
            });
        Some(EgressRate {
            tx_bps: per_second(tx, span),
            rx_bps: per_second(rx, span),
        })
    }
}

/// `bytes` over `span` seconds, in bit/s, rounded down; `span` is at least
/// a minute.
fn per_second(bytes: u128, span: u64) -> u64 {
    u64::try_from(bytes * 8 / u128::from(span)).unwrap_or(u64::MAX)
}
