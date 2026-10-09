// SPDX-License-Identifier: GPL-3.0-or-later

//! Collections that always hold at least one element.

use std::collections::{BTreeSet, btree_set};
use std::num::NonZeroUsize;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ModelError;

/// An ordered list with at least one element; deserialising `[]` fails.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    /// A list holding exactly `first`.
    #[must_use]
    pub fn new(first: T) -> Self {
        Self(vec![first])
    }

    /// A list of `first` followed by `rest`.
    #[must_use]
    pub fn from_parts(first: T, rest: Vec<T>) -> Self {
        let mut items = Vec::with_capacity(rest.len() + 1);
        items.push(first);
        items.extend(rest);
        Self(items)
    }

    /// The first element, which always exists.
    #[must_use]
    pub fn first(&self) -> &T {
        &self.0[0]
    }

    /// The number of elements, which is never zero.
    #[must_use]
    pub fn len(&self) -> NonZeroUsize {
        NonZeroUsize::MIN.saturating_add(self.0.len().saturating_sub(1))
    }

    /// The elements as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Iterates over the elements in order.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Appends an element.
    pub fn push(&mut self, item: T) {
        self.0.push(item);
    }

    /// Appends every element of `other`, keeping order.
    pub fn append(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    /// Converts into the underlying vector, which is never empty.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> TryFrom<Vec<T>> for NonEmpty<T> {
    type Error = ModelError;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.is_empty() {
            Err(ModelError::EmptyCollection)
        } else {
            Ok(Self(items))
        }
    }
}

impl<T> From<NonEmpty<T>> for Vec<T> {
    fn from(list: NonEmpty<T>) -> Self {
        list.0
    }
}

impl<'a, T> IntoIterator for &'a NonEmpty<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Serialize> Serialize for NonEmpty<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NonEmpty<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(deserializer)?;
        Self::try_from(items).map_err(serde::de::Error::custom)
    }
}

/// A set with at least one element, in order; deserialising `[]` fails.
/// On the wire it is a list in increasing order, as `BTreeSet` writes it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NonEmptySet<T: Ord>(BTreeSet<T>);

impl<T: Ord> NonEmptySet<T> {
    /// A set holding exactly `first`.
    #[must_use]
    pub fn new(first: T) -> Self {
        Self(BTreeSet::from([first]))
    }

    /// Iterates over the elements in increasing order.
    pub fn iter(&self) -> btree_set::Iter<'_, T> {
        self.0.iter()
    }

    /// Adds an element; whether it was not already present.
    pub fn insert(&mut self, item: T) -> bool {
        self.0.insert(item)
    }
}

impl<T: Ord> TryFrom<BTreeSet<T>> for NonEmptySet<T> {
    type Error = ModelError;

    fn try_from(items: BTreeSet<T>) -> Result<Self, Self::Error> {
        if items.is_empty() {
            Err(ModelError::EmptyCollection)
        } else {
            Ok(Self(items))
        }
    }
}

impl<T: Ord> From<NonEmptySet<T>> for BTreeSet<T> {
    fn from(set: NonEmptySet<T>) -> Self {
        set.0
    }
}

impl<'a, T: Ord> IntoIterator for &'a NonEmptySet<T> {
    type Item = &'a T;
    type IntoIter = btree_set::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Ord + Serialize> Serialize for NonEmptySet<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Ord + Deserialize<'de>> Deserialize<'de> for NonEmptySet<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = BTreeSet::<T>::deserialize(deserializer)?;
        Self::try_from(items).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_non_empty_set_rejects_the_empty_set_and_keeps_order() {
        assert_eq!(
            NonEmptySet::<u8>::try_from(BTreeSet::new()),
            Err(ModelError::EmptyCollection)
        );
        assert!(serde_json::from_str::<NonEmptySet<u8>>("[]").is_err());
        let set: NonEmptySet<u8> = serde_json::from_str("[3,1]").unwrap();
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), [1, 3]);
        assert_eq!(serde_json::to_string(&set).unwrap(), "[1,3]");
        let mut grown = NonEmptySet::new(7_u8);
        assert!(grown.insert(2));
        assert!(!grown.insert(7));
        assert_eq!(BTreeSet::from(grown), BTreeSet::from([2, 7]));
        assert_eq!((&set).into_iter().count(), 2);
    }

    #[test]
    fn non_empty_rejects_empty_vec_and_json() {
        assert_eq!(
            NonEmpty::<u8>::try_from(Vec::new()),
            Err(ModelError::EmptyCollection)
        );
        assert!(serde_json::from_str::<NonEmpty<u8>>("[]").is_err());
        let list: NonEmpty<u8> = serde_json::from_str("[3,1,3]").unwrap();
        assert_eq!(list.as_slice(), &[3, 1, 3]);
        assert_eq!(list.first(), &3);
        assert_eq!(list.len().get(), 3);
        assert_eq!(serde_json::to_string(&list).unwrap(), "[3,1,3]");
    }

    proptest! {
        #[test]
        fn non_empty_from_parts_keeps_order(first in any::<u8>(), rest in proptest::collection::vec(any::<u8>(), 0..8)) {
            let list = NonEmpty::from_parts(first, rest.clone());
            prop_assert_eq!(list.first(), &first);
            prop_assert_eq!(list.len().get(), rest.len() + 1);
            prop_assert_eq!(&list.as_slice()[1..], rest.as_slice());
        }
    }
}
