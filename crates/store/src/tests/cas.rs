// SPDX-License-Identifier: GPL-3.0-or-later

//! Compare-and-swap on the two counters (design §7).

use std::cell::Cell;
use std::convert::Infallible;
use std::fs;

use mooring_model::counters::{ConfigGeneration, CounterKind, RuntimeRevision};
use mooring_model::deployment::Bookkeeping;
use mooring_model::deployment::DeploymentParts;
use mooring_model::digest::Sha256Digest;
use mooring_model::error::{EntityId, ModelError};
use mooring_model::node::{AppliedConfig, LifecycleStage, NodeLifecycle};
use mooring_model::user::UserStatus;

use super::builders::{
    adopted_store, applied_record, initialised, node_id, planned_node, site, user, with_lifecycle,
    with_node, with_user,
};
use super::{state_bytes, store_error};
use crate::error::{ChangeError, ChangeErrorKind, StoreError, StoreErrorKind};
use crate::ordered::{record_with_secrets, update_config_with_secrets};
use crate::secrets::SecretStore;

fn generation(value: u64) -> ConfigGeneration {
    ConfigGeneration::new(value).unwrap()
}

fn revision(value: u64) -> RuntimeRevision {
    RuntimeRevision::new(value).unwrap()
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("operator said no")]
struct OperatorSaidNo;

#[test]
fn config_updates_bump_only_the_generation() {
    let (_dir, store, before) = initialised();
    let after = store
        .update_config(before.deployment.config_generation(), |mut parts| {
            parts.policy.block_quic = false;
            Ok::<_, Infallible>(parts)
        })
        .unwrap();
    assert_eq!(after.deployment.config_generation(), generation(2));
    assert!(!after.deployment.policy().block_quic);
    assert_eq!(after.runtime, before.runtime, "runtime intent is untouched");
    assert_eq!(store.load().unwrap(), after);
}

#[test]
fn exit_toggles_bump_only_the_revision() {
    let (_dir, store, before) = initialised();
    let after = store
        .set_exit_enabled(before.runtime.revision, true)
        .unwrap();
    assert!(after.runtime.exit_enabled);
    assert_eq!(after.runtime.revision, revision(2));
    assert_eq!(
        after.deployment, before.deployment,
        "the deployment and its generation are untouched"
    );
    let disabled = store.set_exit_enabled(revision(2), false).unwrap();
    assert!(!disabled.runtime.exit_enabled);
    assert_eq!(disabled.runtime.revision, revision(3));
    assert_eq!(disabled.deployment.config_generation(), generation(1));
    assert_eq!(store.load().unwrap(), disabled);
}

#[test]
fn a_stale_generation_is_refused_and_nothing_is_written() {
    let (_dir, store, before) = initialised();
    store
        .update_config(before.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();
    let on_disk = state_bytes(&store);
    let called = Cell::new(false);
    let error = store
        .update_config(generation(1), |parts| {
            called.set(true);
            Ok::<_, Infallible>(parts)
        })
        .unwrap_err();
    assert!(
        matches!(
            error,
            ChangeError::Store(StoreError::GenerationConflict { expected, found })
                if expected == generation(1) && found == generation(2)
        ),
        "{error:?}"
    );
    assert_eq!(error.kind(), ChangeErrorKind::Store);
    assert!(!called.get(), "the change never sees a stale state");
    assert_eq!(state_bytes(&store), on_disk);
}

#[test]
fn a_stale_revision_is_refused_and_nothing_is_written() {
    let (_dir, store, before) = initialised();
    store
        .set_exit_enabled(before.runtime.revision, true)
        .unwrap();
    let on_disk = state_bytes(&store);
    let error = store
        .set_exit_enabled(before.runtime.revision, false)
        .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::RevisionConflict { expected, found }
                if expected == revision(1) && found == revision(2)
        ),
        "{error:?}"
    );
    assert_eq!(error.kind(), StoreErrorKind::RevisionConflict);
    assert_eq!(state_bytes(&store), on_disk);
}

#[test]
fn each_counter_only_guards_its_own_changes() {
    let (_dir, store, read) = initialised();
    // Enabling the exit leaves config tokens valid ...
    store.set_exit_enabled(read.runtime.revision, true).unwrap();
    let config = store
        .update_config(read.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();
    // ... and a config change leaves runtime tokens valid.
    assert_eq!(config.runtime.revision, revision(2));
    let runtime = store.set_exit_enabled(revision(2), false).unwrap();
    assert_eq!(runtime.deployment.config_generation(), generation(2));
}

#[test]
fn records_check_the_generation_without_bumping_it() {
    let (_dir, store, before, _secrets) = adopted_store();
    let current = before.deployment.config_generation();
    let recorded = store
        .record(current, applied_record("lon1", current))
        .unwrap();
    assert_eq!(recorded.deployment.config_generation(), current);
    let lon1 = recorded.deployment.node(&node_id("lon1")).unwrap();
    assert_eq!(
        lon1.lifecycle
            .applied()
            .map(|applied| applied.config_generation),
        Some(current)
    );
    assert_eq!(recorded.runtime, before.runtime);
    assert_eq!(store.load().unwrap(), recorded);
    // The token stays valid for further records and updates ...
    store
        .record(current, applied_record("lon1", current))
        .unwrap();
    store.update_config(current, Ok::<_, Infallible>).unwrap();
    // ... until a config change bumps it.
    let error = store
        .record(current, applied_record("lon1", current))
        .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::GenerationConflict { found, .. } if found == current.next().unwrap()
        ),
        "{error:?}"
    );
}

/// Only typed bookkeeping keeps the generation: a change made through a
/// closure always bumps it, even one that alters nothing at all, so no
/// change to what a node renders can keep a node looking current.
#[test]
fn every_closure_change_bumps_the_generation() {
    let (_dir, store, before, _secrets) = adopted_store();
    let current = before.deployment.config_generation();
    let recorded = store
        .record(current, applied_record("lon1", current))
        .unwrap();
    for edit in [
        |parts: DeploymentParts| parts,
        |mut parts: DeploymentParts| {
            parts.policy.deny_cn = false;
            parts
        },
    ] {
        let found = store.load().unwrap().deployment.config_generation();
        let next = store
            .update_config(found, |parts| Ok::<_, Infallible>(edit(parts)))
            .unwrap();
        assert_eq!(next.deployment.config_generation(), found.next().unwrap());
        // lon1 confirmed an older generation, so exports wait for it.
        let lon1 = next.deployment.node(&node_id("lon1")).unwrap();
        assert!(
            lon1.lifecycle.applied().unwrap().config_generation
                < next.deployment.config_generation()
        );
    }
    assert_eq!(recorded.deployment.config_generation(), current);
}

/// Only a `Bookkeeping::Applied` record sets a node's confirmed generation
/// (design §7). A closure can neither forge a confirmation, not even at the
/// generation the store is about to stamp, nor lower, raise or replace one,
/// through either write; it can still move a node out of `Applied`.
#[test]
fn only_a_record_sets_a_confirmed_generation() {
    let (_dir, store, before, mut secrets) = adopted_store();
    let current = before.deployment.config_generation();
    let stamped = current.next().unwrap();
    let lon1_applied = |applied: AppliedConfig| NodeLifecycle::Applied {
        site: site([45, 67, 89, 10]),
        applied,
    };
    let confirmed = |generation: ConfigGeneration| AppliedConfig {
        config_generation: generation,
        digest: Sha256Digest::from_bytes([0xab; 32]),
    };
    let refused = |error: StoreError| {
        assert!(
            matches!(&error, StoreError::AppliedEdited { node } if *node == node_id("lon1")),
            "{error:?}"
        );
        assert_eq!(error.kind(), StoreErrorKind::AppliedEdited);
    };

    // lon1 is adopted: no closure may mark it applied.
    let on_disk = state_bytes(&store);
    for forged in [stamped, current, generation(1)] {
        let set = |parts| {
            Ok::<_, Infallible>(with_lifecycle(
                parts,
                "lon1",
                lon1_applied(confirmed(forged)),
            ))
        };
        refused(store_error(store.update_config(current, set).unwrap_err()));
        refused(store_error(
            update_config_with_secrets(&store, &mut secrets, current, Vec::new(), set).unwrap_err(),
        ));
    }
    assert_eq!(state_bytes(&store), on_disk);

    // Once lon1 confirmed the current generation, no closure may edit that.
    let recorded = store
        .record(current, applied_record("lon1", current))
        .unwrap();
    let on_disk = state_bytes(&store);
    let held = *recorded
        .deployment
        .node(&node_id("lon1"))
        .unwrap()
        .lifecycle
        .applied()
        .unwrap();
    assert_eq!(held, confirmed(current));
    for edited in [
        confirmed(generation(2)),
        confirmed(stamped),
        AppliedConfig {
            digest: Sha256Digest::from_bytes([0xcd; 32]),
            ..held
        },
    ] {
        let set = |parts| Ok::<_, Infallible>(with_lifecycle(parts, "lon1", lon1_applied(edited)));
        refused(store_error(store.update_config(current, set).unwrap_err()));
    }
    assert_eq!(state_bytes(&store), on_disk);

    // A change that keeps the confirmation, or leaves Applied, is a
    // configuration change like any other.
    let kept = store
        .update_config(current, |mut parts| {
            parts.policy.deny_cn = false;
            Ok::<_, Infallible>(parts)
        })
        .unwrap();
    let lon1 = kept.deployment.node(&node_id("lon1")).unwrap();
    assert_eq!(lon1.lifecycle.applied(), Some(&held));
    let retiring = store
        .update_config(stamped, |parts| {
            Ok::<_, Infallible>(with_lifecycle(
                parts,
                "lon1",
                NodeLifecycle::Retiring {
                    site: site([45, 67, 89, 10]),
                },
            ))
        })
        .unwrap();
    let lon1 = retiring.deployment.node(&node_id("lon1")).unwrap();
    assert_eq!(lon1.lifecycle.stage(), LifecycleStage::Retiring);
}

/// A record that drops secrets is refused by the plain record, which
/// cannot order the deletions, and goes through `record_with_secrets`,
/// which keeps the generation and deletes them after the state stops
/// referencing them (design §13.5 step 3).
#[test]
fn records_that_drop_secrets_take_the_ordered_path() {
    let (_dir, store, before, mut secrets) = adopted_store();
    let current = before.deployment.config_generation();
    let applied = store
        .record(current, applied_record("lon1", current))
        .unwrap();
    let revoking = store
        .update_config(current, |mut parts| {
            parts.users[0].status = UserStatus::RevokePending;
            Ok::<_, Infallible>(parts)
        })
        .unwrap();
    let revoking_generation = revoking.deployment.config_generation();
    assert_eq!(revoking_generation, current.next().unwrap());
    store
        .record(
            revoking_generation,
            applied_record("lon1", revoking_generation),
        )
        .unwrap();
    let on_disk = state_bytes(&store);
    let commit = Bookkeeping::RevocationCommitted {
        user: applied.deployment.users().keys().next().unwrap().clone(),
        node: node_id("lon1"),
    };
    let error = store
        .record(revoking_generation, commit.clone())
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::SecretRefsChanged);
    assert_eq!(state_bytes(&store), on_disk);

    let user_secrets: Vec<_> = secrets
        .refs()
        .into_iter()
        .filter(|secret_ref| secret_ref.to_string().starts_with("user/"))
        .collect();
    assert_eq!(user_secrets.len(), 3);
    let revoked = record_with_secrets(&store, &mut secrets, revoking_generation, commit).unwrap();
    // The generation is kept, so lon1 still serves the current configuration.
    assert_eq!(revoked.deployment.config_generation(), revoking_generation);
    let lon1 = revoked.deployment.node(&node_id("lon1")).unwrap();
    assert_eq!(
        lon1.lifecycle.applied().unwrap().config_generation,
        revoked.deployment.config_generation()
    );
    assert_eq!(
        revoked.deployment.users().values().next().unwrap().status,
        UserStatus::Revoked
    );
    for secret_ref in user_secrets {
        assert!(
            secrets.get(&secret_ref).is_err(),
            "{secret_ref} not deleted"
        );
    }
    assert_eq!(secrets.refs(), revoked.deployment.required_secrets());
    assert_eq!(store.load().unwrap(), revoked);
}

#[test]
fn refused_changes_write_nothing() {
    let (_dir, store, before) = initialised();
    let on_disk = state_bytes(&store);
    let error = store
        .update_config(before.deployment.config_generation(), |_| {
            Err(OperatorSaidNo)
        })
        .unwrap_err();
    assert!(
        matches!(error, ChangeError::Refused(OperatorSaidNo)),
        "{error:?}"
    );
    assert_eq!(error.kind(), ChangeErrorKind::Refused);
    assert_eq!(state_bytes(&store), on_disk);
}

#[test]
fn only_the_store_sets_the_generation() {
    let (_dir, store, before) = initialised();
    let on_disk = state_bytes(&store);
    let edit = |mut parts: DeploymentParts| {
        parts.config_generation = generation(7);
        Ok::<_, Infallible>(parts)
    };
    let expected = before.deployment.config_generation();
    {
        let error = store_error(store.update_config(expected, edit).unwrap_err());
        assert!(
            matches!(
                error,
                StoreError::GenerationEdited { received, returned }
                    if received == generation(1) && returned == generation(7)
            ),
            "{error:?}"
        );
        assert_eq!(error.kind(), StoreErrorKind::GenerationEdited);
    }
    assert_eq!(state_bytes(&store), on_disk);
}

#[test]
fn changes_that_break_an_invariant_are_refused() {
    let (_dir, store, before) = initialised();
    let on_disk = state_bytes(&store);
    // A user without credentials references no secrets, so only the
    // duplicate id is wrong.
    let error = store
        .update_config(before.deployment.config_generation(), |parts| {
            Ok::<_, Infallible>(with_user(with_user(parts, user(1, &[])), user(1, &[])))
        })
        .unwrap_err();
    let error = store_error(error);
    assert_eq!(error.kind(), StoreErrorKind::InvalidChange);
    let StoreError::InvalidChange { source } = &error else {
        panic!("expected InvalidChange, got {error:?}");
    };
    assert!(
        matches!(
            source,
            ModelError::DuplicateId {
                id: EntityId::User(_)
            }
        ),
        "{source:?}"
    );
    assert_eq!(state_bytes(&store), on_disk);
}

#[test]
fn counters_refuse_to_overflow() {
    let (_dir, store, _) = initialised();
    let mut value: serde_json::Value = serde_json::from_slice(&state_bytes(&store)).unwrap();
    value["deployment"]["config_generation"] = u64::MAX.into();
    value["runtime"]["revision"] = u64::MAX.into();
    fs::write(store.state_path(), serde_json::to_vec(&value).unwrap()).unwrap();
    let on_disk = state_bytes(&store);

    let called = Cell::new(false);
    let error = store
        .update_config(generation(u64::MAX), |parts| {
            called.set(true);
            Ok::<_, Infallible>(parts)
        })
        .unwrap_err();
    let error = store_error(error);
    assert_eq!(error.kind(), StoreErrorKind::CounterOverflow);
    let StoreError::CounterOverflow { source } = &error else {
        panic!("expected CounterOverflow, got {error:?}");
    };
    assert_eq!(
        *source,
        ModelError::CounterOverflow {
            counter: CounterKind::ConfigGeneration
        }
    );
    assert!(!called.get());

    let error = store
        .set_exit_enabled(revision(u64::MAX), true)
        .unwrap_err();
    assert_eq!(error.kind(), StoreErrorKind::CounterOverflow);
    assert_eq!(state_bytes(&store), on_disk);

    // A record does not bump, so it still works at the limit.
    let (_dir, store, _, _secrets) = adopted_store();
    let mut value: serde_json::Value = serde_json::from_slice(&state_bytes(&store)).unwrap();
    value["deployment"]["config_generation"] = u64::MAX.into();
    fs::write(store.state_path(), serde_json::to_vec(&value).unwrap()).unwrap();
    let recorded = store
        .record(
            generation(u64::MAX),
            applied_record("lon1", generation(u64::MAX)),
        )
        .unwrap();
    assert_eq!(
        recorded.deployment.config_generation(),
        generation(u64::MAX)
    );
}

#[test]
fn plain_writes_refuse_to_change_secret_references() {
    let (_dir, store, before) = initialised();
    let on_disk = state_bytes(&store);
    let add_node = |parts| Ok::<_, Infallible>(with_node(parts, planned_node("lon1", 1, 10)));
    let expected = before.deployment.config_generation();
    {
        let error = store_error(store.update_config(expected, add_node).unwrap_err());
        assert_eq!(error.kind(), StoreErrorKind::SecretRefsChanged);
        let StoreError::SecretRefsChanged { added, removed } = &error else {
            panic!("expected SecretRefsChanged, got {error:?}");
        };
        assert_eq!(added.len(), 9, "{added:?}");
        assert!(removed.is_empty());
    }
    assert_eq!(state_bytes(&store), on_disk);
}
