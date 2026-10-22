// SPDX-License-Identifier: GPL-3.0-or-later

//! Percentiles and fairness, the arithmetic the summaries need.

use serde::Serialize;

/// The nearest-rank `percent`th percentile of `values` (0 < percent <=
/// 100): the smallest value with at least `percent`% of the values at or
/// below it. `None` for no values.
pub(crate) fn percentile(values: &[u64], percent: u8) -> Option<u64> {
    if values.is_empty() || percent == 0 || percent > 100 {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (usize::from(percent) * sorted.len()).div_ceil(100);
    sorted.get(rank.saturating_sub(1)).copied()
}

/// The 10th, 50th and 90th percentiles of a set of values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Spread {
    /// How many values.
    pub(crate) count: usize,
    /// The 10th percentile.
    pub(crate) p10: u64,
    /// The median.
    pub(crate) p50: u64,
    /// The 90th percentile.
    pub(crate) p90: u64,
}

impl Spread {
    /// The spread of `values`; `None` for no values.
    pub(crate) fn of(values: &[u64]) -> Option<Self> {
        Some(Self {
            count: values.len(),
            p10: percentile(values, 10)?,
            p50: percentile(values, 50)?,
            p90: percentile(values, 90)?,
        })
    }
}

/// Jain's fairness index of `shares`, (Σx)² / (n·Σx²), in thousandths,
/// rounded: 1000 when every share is equal, 1000/n when one takes
/// everything. `None` for no shares or shares that are all zero. Computed
/// in `f64`, which is exact enough for an index read to three digits.
pub(crate) fn jain_index_permille(shares: &[u64]) -> Option<u16> {
    if shares.iter().all(|&share| share == 0) {
        return None;
    }
    let sum: f64 = shares.iter().map(|&share| share as f64).sum();
    let squares: f64 = shares.iter().map(|&share| (share as f64).powi(2)).sum();
    let index = sum * sum / (shares.len() as f64 * squares);
    Some((index * 1000.0).round().clamp(0.0, 1000.0) as u16)
}
