// SPDX-License-Identifier: GPL-3.0-or-later

//! The two state counters (design §7): `ConfigGeneration` changes with any
//! rendered config, `RuntimeRevision` with Mac-only runtime intent.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::ModelError;

/// Which counter an error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CounterKind {
    /// [`ConfigGeneration`].
    ConfigGeneration,
    /// [`RuntimeRevision`].
    RuntimeRevision,
}

impl fmt::Display for CounterKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ConfigGeneration => "config generation",
            Self::RuntimeRevision => "runtime revision",
        })
    }
}

/// Bumped only by changes that alter a rendered VPS or Mac config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct ConfigGeneration(u64);

/// Bumped by Mac-only runtime changes, such as enabling the exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct RuntimeRevision(u64);

macro_rules! counter {
    ($name:ident, $kind:expr) => {
        impl $name {
            /// The value of a fresh state.
            pub const INITIAL: Self = Self(1);

            /// Accepts any value from 1.
            pub fn new(value: u64) -> Result<Self, ModelError> {
                if value == 0 {
                    Err(ModelError::InvalidCounter { counter: $kind })
                } else {
                    Ok(Self(value))
                }
            }

            /// The counter value.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// The following value; `CounterOverflow` at `u64::MAX`.
            pub fn next(self) -> Result<Self, ModelError> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(ModelError::CounterOverflow { counter: $kind })
            }
        }

        impl TryFrom<u64> for $name {
            type Error = ModelError;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for u64 {
            fn from(counter: $name) -> Self {
                counter.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

counter!(ConfigGeneration, CounterKind::ConfigGeneration);
counter!(RuntimeRevision, CounterKind::RuntimeRevision);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn counters_start_at_one_and_refuse_overflow() {
        assert_eq!(ConfigGeneration::INITIAL.get(), 1);
        assert_eq!(
            ConfigGeneration::new(0),
            Err(ModelError::InvalidCounter {
                counter: CounterKind::ConfigGeneration
            })
        );
        assert_eq!(
            RuntimeRevision::new(u64::MAX).unwrap().next(),
            Err(ModelError::CounterOverflow {
                counter: CounterKind::RuntimeRevision
            })
        );
        assert_eq!(RuntimeRevision::INITIAL.next().unwrap().get(), 2);
        assert!(serde_json::from_str::<ConfigGeneration>("0").is_err());
        assert!(serde_json::from_str::<ConfigGeneration>("-1").is_err());
    }

    proptest! {
        #[test]
        fn next_is_strictly_increasing(value in 1_u64..u64::MAX) {
            let generation = ConfigGeneration::new(value).unwrap();
            prop_assert!(generation.next().unwrap() > generation);
            let json = serde_json::to_string(&generation).unwrap();
            prop_assert_eq!(serde_json::from_str::<ConfigGeneration>(&json).unwrap(), generation);
        }
    }
}
