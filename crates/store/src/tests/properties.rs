// SPDX-License-Identifier: GPL-3.0-or-later

//! Property tests: decoding classifies any input, and the counters follow
//! any sequence of writes exactly as a reference model does.

use std::convert::Infallible;
use std::path::Path;

use mooring_model::counters::{ConfigGeneration, RuntimeRevision};
use proptest::prelude::*;

use super::builders::{adopted_store, applied_record};
use super::store_error;
use crate::error::{StoreError, StoreErrorKind};
use crate::migrate::decode;

/// One write with either the current token or a stale one.
#[derive(Debug, Clone, Copy)]
enum Write {
    Config { stale: bool },
    Record { stale: bool },
    Exit { enabled: bool, stale: bool },
}

fn write() -> impl Strategy<Value = Write> {
    prop_oneof![
        any::<bool>().prop_map(|stale| Write::Config { stale }),
        any::<bool>().prop_map(|stale| Write::Record { stale }),
        (any::<bool>(), any::<bool>()).prop_map(|(enabled, stale)| Write::Exit { enabled, stale }),
    ]
}

/// A token that is not `current`: the previous value, or the next one at 1.
fn stale(current: u64) -> u64 {
    if current > 1 {
        current - 1
    } else {
        current + 1
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn decoding_classifies_any_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        match decode(Path::new("state.json"), &bytes) {
            Ok(decoded) => prop_assert!(matches!(decoded.from, 1 | 2)),
            Err(error) => prop_assert!(
                matches!(
                    error.kind(),
                    StoreErrorKind::StateCorrupt
                        | StoreErrorKind::DowngradeRefused
                        | StoreErrorKind::MigrationFailed
                ),
                "{:?}", error
            ),
        }
    }

    #[test]
    fn any_newer_version_is_refused_before_parsing(version in any::<u32>()) {
        let bytes = format!(r#"{{"version": {version}, "unknown": true}}"#);
        let result = decode(Path::new("state.json"), bytes.as_bytes());
        let error = result.unwrap_err();
        if version > 2 {
            prop_assert!(
                matches!(error, StoreError::DowngradeRefused { found, newest: 2 } if found == version),
                "{:?}", error
            );
        } else {
            prop_assert_eq!(error.kind(), StoreErrorKind::StateCorrupt);
        }
    }
}

proptest! {
    // Each case performs real durable writes, so keep the count modest.
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn counters_follow_any_sequence_of_writes(writes in proptest::collection::vec(write(), 1..10)) {
        let (_dir, store, state, _secrets) = adopted_store();
        let mut generation = state.deployment.config_generation().get();
        let mut revision = state.runtime.revision.get();
        let mut exit_enabled = state.runtime.exit_enabled;
        for write in writes {
            match write {
                Write::Config { stale: is_stale } | Write::Record { stale: is_stale } => {
                    let token = if is_stale { stale(generation) } else { generation };
                    let token = ConfigGeneration::new(token).unwrap();
                    let result = if matches!(write, Write::Config { .. }) {
                        store.update_config(token, Ok::<_, Infallible>).map_err(store_error)
                    } else {
                        store.record(token, applied_record("lon1", token))
                    };
                    if is_stale {
                        prop_assert_eq!(
                            result.unwrap_err().kind(),
                            StoreErrorKind::GenerationConflict
                        );
                    } else {
                        if matches!(write, Write::Config { .. }) {
                            generation += 1;
                        }
                        let next = result.unwrap();
                        prop_assert_eq!(next.deployment.config_generation().get(), generation);
                        prop_assert_eq!(next.runtime.revision.get(), revision);
                    }
                }
                Write::Exit { enabled, stale: is_stale } => {
                    let token = if is_stale { stale(revision) } else { revision };
                    let result = store.set_exit_enabled(RuntimeRevision::new(token).unwrap(), enabled);
                    if is_stale {
                        prop_assert_eq!(result.unwrap_err().kind(), StoreErrorKind::RevisionConflict);
                    } else {
                        revision += 1;
                        exit_enabled = enabled;
                        let next = result.unwrap();
                        prop_assert_eq!(next.runtime.revision.get(), revision);
                        prop_assert_eq!(next.deployment.config_generation().get(), generation);
                    }
                }
            }
        }
        let last = store.load().unwrap();
        prop_assert_eq!(last.deployment.config_generation().get(), generation);
        prop_assert_eq!(last.runtime.revision.get(), revision);
        prop_assert_eq!(last.runtime.exit_enabled, exit_enabled);
    }
}
