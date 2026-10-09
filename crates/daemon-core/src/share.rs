// SPDX-License-Identifier: GPL-3.0-or-later

//! Shares of a total in basis points (hundredths of a percent), rounded so
//! that they always add up to exactly 10,000.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::FigureError;

/// The whole, in basis points.
pub const WHOLE_BASIS_POINTS: u16 = 10_000;

/// A share of a total in basis points, 0..=10,000; decoding refuses more
/// (`ShareAboveWhole`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct BasisPoints(u16);

impl BasisPoints {
    /// Accepts 0..=10,000 (`ShareAboveWhole` otherwise).
    pub const fn new(points: u16) -> Result<Self, FigureError> {
        if points <= WHOLE_BASIS_POINTS {
            Ok(Self(points))
        } else {
            Err(FigureError::ShareAboveWhole { points })
        }
    }

    /// The share in basis points.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for BasisPoints {
    type Error = FigureError;

    fn try_from(points: u16) -> Result<Self, Self::Error> {
        Self::new(points)
    }
}

impl From<BasisPoints> for u16 {
    fn from(points: BasisPoints) -> Self {
        points.0
    }
}

/// Whether `shares` add up to exactly the whole (`SharesNotWhole`
/// otherwise; an empty set adds up to nothing).
pub(crate) fn require_whole<'a>(
    shares: impl IntoIterator<Item = &'a BasisPoints>,
) -> Result<(), FigureError> {
    let sum: u32 = shares.into_iter().map(|share| u32::from(share.0)).sum();
    if sum == u32::from(WHOLE_BASIS_POINTS) {
        Ok(())
    } else {
        Err(FigureError::SharesNotWhole { sum })
    }
}

/// Each part's share of the parts' sum, by the largest-remainder method:
/// every part gets the floor of its exact share, and the basis points left
/// over go one each to the parts with the largest remainders (the earlier
/// key first on a tie). The shares add up to exactly 10,000, and each is
/// within one basis point of its exact value.
///
/// `None` when the sum is zero: there is no share of nothing.
#[must_use]
pub fn basis_points<K: Ord + Clone>(parts: &BTreeMap<K, u64>) -> Option<BTreeMap<K, BasisPoints>> {
    let whole = u128::from(WHOLE_BASIS_POINTS);
    let total: u128 = parts.values().map(|&part| u128::from(part)).sum();
    if total == 0 {
        return None;
    }
    let mut floors: Vec<(K, u128, u128)> = parts
        .iter()
        .map(|(key, &part)| {
            let scaled = u128::from(part) * whole;
            (key.clone(), scaled / total, scaled % total)
        })
        .collect();
    let assigned: u128 = floors.iter().map(|(_, floor, _)| floor).sum();
    // Fewer than `parts.len()` basis points are left over, since each floor
    // drops less than one.
    let mut left = whole - assigned;
    let mut order: Vec<usize> = (0..floors.len()).collect();
    order.sort_by(|&a, &b| floors[b].2.cmp(&floors[a].2).then(a.cmp(&b)));
    for index in order {
        if left == 0 {
            break;
        }
        floors[index].1 += 1;
        left -= 1;
    }
    Some(
        floors
            .into_iter()
            // Every share is at most the whole (10,000): the floors add up
            // to at most the whole and the left-over points complete it, so
            // the cast never truncates.
            .map(|(key, points, _)| (key, BasisPoints(points as u16)))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn shares_round_to_exactly_the_whole() {
        let parts = BTreeMap::from([("a", 1_u64), ("b", 1), ("c", 1)]);
        let shares = basis_points(&parts).unwrap();
        assert_eq!(
            shares.values().map(|share| share.get()).collect::<Vec<_>>(),
            [3334, 3333, 3333]
        );
        let parts = BTreeMap::from([("a", 0_u64), ("b", 5)]);
        let shares = basis_points(&parts).unwrap();
        assert_eq!(shares[&"a"].get(), 0);
        assert_eq!(shares[&"b"].get(), 10_000);
        assert_eq!(basis_points(&BTreeMap::from([("a", 0_u64)])), None);
        assert_eq!(basis_points::<&str>(&BTreeMap::new()), None);
        assert_eq!(serde_json::to_string(&shares[&"b"]).unwrap(), "10000");
    }

    /// A share above the whole is refused, also when decoded; a set of
    /// shares must add up to exactly the whole.
    #[test]
    fn a_share_is_at_most_the_whole_and_shares_add_up_to_it() {
        assert_eq!(BasisPoints::new(10_000).unwrap().get(), 10_000);
        for points in [10_001, u16::MAX] {
            assert_eq!(
                BasisPoints::new(points),
                Err(FigureError::ShareAboveWhole { points })
            );
            assert!(serde_json::from_str::<BasisPoints>(&points.to_string()).is_err());
        }
        assert_eq!(serde_json::from_str::<BasisPoints>("0").unwrap().get(), 0);
        let point = |points| BasisPoints::new(points).unwrap();
        assert_eq!(require_whole(&[point(4_000), point(6_000)]), Ok(()));
        assert_eq!(
            require_whole(&[point(4_000), point(5_999)]),
            Err(FigureError::SharesNotWhole { sum: 9_999 })
        );
        assert_eq!(
            require_whole(&[point(10_000), point(1)]),
            Err(FigureError::SharesNotWhole { sum: 10_001 })
        );
        assert_eq!(
            require_whole(&[]),
            Err(FigureError::SharesNotWhole { sum: 0 })
        );
    }

    proptest! {
        #[test]
        fn shares_add_up_and_stay_within_one_point(parts in proptest::collection::btree_map(0_u8..20, any::<u64>(), 1..12)) {
            let total: u128 = parts.values().map(|&part| u128::from(part)).sum();
            match basis_points(&parts) {
                None => prop_assert_eq!(total, 0),
                Some(shares) => {
                    prop_assert_eq!(shares.len(), parts.len());
                    let sum: u32 = shares.values().map(|share| u32::from(share.get())).sum();
                    prop_assert_eq!(sum, 10_000);
                    prop_assert_eq!(require_whole(shares.values()), Ok(()));
                    for (key, share) in &shares {
                        let exact = u128::from(parts[key]) * 10_000;
                        let points = u128::from(share.get());
                        // floor(exact / total) <= points <= floor + 1
                        prop_assert!(points * total <= exact + total);
                        prop_assert!(exact < (points + 1) * total);
                    }
                }
            }
        }
    }
}
