// SPDX-License-Identifier: GPL-3.0-or-later

//! Percentiles, spreads and the fairness index.

use crate::stats::{Spread, jain_index_permille, percentile};

#[test]
fn percentiles_are_nearest_rank() {
    let values: Vec<u64> = (1..=10).rev().collect();
    assert_eq!(percentile(&values, 10), Some(1));
    assert_eq!(percentile(&values, 50), Some(5));
    assert_eq!(percentile(&values, 90), Some(9));
    assert_eq!(percentile(&values, 100), Some(10));
    assert_eq!(percentile(&values, 11), Some(2));
    assert_eq!(percentile(&[42], 10), Some(42));
    assert_eq!(percentile(&[42], 90), Some(42));
    assert_eq!(percentile(&[], 50), None);
    assert_eq!(percentile(&values, 0), None);
    assert_eq!(percentile(&values, 101), None);
    assert_eq!(percentile(&[3, 1], 50), Some(1));
}

#[test]
fn a_spread_gives_the_three_percentiles_and_the_count() {
    assert_eq!(
        Spread::of(&[5, 1, 4, 2, 3]),
        Some(Spread {
            count: 5,
            p10: 1,
            p50: 3,
            p90: 5,
        })
    );
    assert_eq!(Spread::of(&[]), None);
}

#[test]
fn jains_index_runs_from_1_over_n_to_1() {
    assert_eq!(jain_index_permille(&[5, 5, 5, 5]), Some(1000));
    assert_eq!(jain_index_permille(&[10, 0, 0, 0]), Some(250));
    assert_eq!(jain_index_permille(&[3, 1]), Some(800));
    assert_eq!(
        jain_index_permille(&[5, 1, 1]),
        Some(605),
        "49/81 rounds up"
    );
    assert_eq!(jain_index_permille(&[u64::MAX, u64::MAX]), Some(1000));
    assert_eq!(jain_index_permille(&[7]), Some(1000));
    assert_eq!(jain_index_permille(&[0, 0]), None);
    assert_eq!(jain_index_permille(&[]), None);
}
