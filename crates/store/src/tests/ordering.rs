// SPDX-License-Identifier: GPL-3.0-or-later

//! The §7 ordering of secret and state writes, observed from inside the
//! secret store while the update runs.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fs::{self, OpenOptions, TryLockError};
use std::path::PathBuf;

use mooring_model::alerting::AlertSettings;
use mooring_model::deployment::{Bookkeeping, DeploymentParts};
use mooring_model::error::ModelError;
use mooring_model::node::NodeLifecycle;
use mooring_model::ports::ListenerIdx;
use mooring_model::secret::{SecretEntry, SecretMaterial, SecretRef};
use mooring_model::state::StateV2;

use super::builders::{
    added_refs, adopted, entries_for, initialised, node_id, planned_node, site, user,
    with_lifecycle, with_node, with_user,
};
use super::{state_bytes, store_error};
use crate::error::{ChangeError, StoreError, StoreErrorKind};
use crate::migrate::{migrate, parse};
use crate::ordered::{record_with_secrets, update_config_with_secrets};
use crate::secrets::{
    InMemorySecretStore, SecretOp, SecretStore, SecretStoreError, SecretStoreErrorKind,
};
use crate::store::Store;

/// `errSecInteractionNotAllowed`.
const INTERACTION_NOT_ALLOWED: i32 = -25_308;

/// One call into the observed secret store.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observed {
    op: SecretOp,
    secret_ref: SecretRef,
    /// Whether `state.json` on disk referenced the secret at that moment.
    referenced_on_disk: bool,
    /// Whether another writer was locked out at that moment.
    lock_held: bool,
}

/// A secret store that records, for every write, what the state on disk
/// referenced and whether the state lock was held; it can be told to fail.
#[derive(Debug)]
struct Observer {
    inner: InMemorySecretStore,
    state_path: PathBuf,
    lock_path: PathBuf,
    log: Vec<Observed>,
    fail_put: Option<SecretRef>,
    fail_delete: BTreeSet<SecretRef>,
}

impl Observer {
    fn new(store: &Store) -> Self {
        Self {
            inner: InMemorySecretStore::new(),
            state_path: store.state_path(),
            lock_path: store.lock_path(),
            log: Vec::new(),
            fail_put: None,
            fail_delete: BTreeSet::new(),
        }
    }

    fn observe(&mut self, op: SecretOp, secret_ref: &SecretRef) {
        let file = parse(&fs::read(&self.state_path).unwrap()).unwrap();
        let referenced_on_disk = migrate(file)
            .unwrap()
            .deployment
            .required_secrets()
            .contains(secret_ref);
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .unwrap();
        let lock_held = matches!(probe.try_lock(), Err(TryLockError::WouldBlock));
        self.log.push(Observed {
            op,
            secret_ref: secret_ref.clone(),
            referenced_on_disk,
            lock_held,
        });
    }

    fn ops(&self, op: SecretOp) -> Vec<&Observed> {
        self.log.iter().filter(|seen| seen.op == op).collect()
    }
}

impl SecretStore for Observer {
    fn get(&self, secret_ref: &SecretRef) -> Result<SecretMaterial, SecretStoreError> {
        self.inner.get(secret_ref)
    }

    fn put(&mut self, entry: SecretEntry) -> Result<(), SecretStoreError> {
        let secret_ref = entry.secret_ref();
        self.observe(SecretOp::Put, &secret_ref);
        if self.fail_put.as_ref() == Some(&secret_ref) {
            return Err(SecretStoreError::Keychain {
                op: SecretOp::Put,
                status: INTERACTION_NOT_ALLOWED,
            });
        }
        self.inner.put(entry)
    }

    fn delete(&mut self, secret_ref: &SecretRef) -> Result<(), SecretStoreError> {
        self.observe(SecretOp::Delete, secret_ref);
        if self.fail_delete.contains(secret_ref) {
            return Err(SecretStoreError::Keychain {
                op: SecretOp::Delete,
                status: INTERACTION_NOT_ALLOWED,
            });
        }
        self.inner.delete(secret_ref)
    }
}

/// The nine secrets of a planned node with one Hysteria2 listener.
fn planned_node_refs(id: &str) -> BTreeSet<SecretRef> {
    let node = node_id(id);
    BTreeSet::from([
        SecretRef::NodeRealityPrivate(node.clone()),
        SecretRef::NodeWgVpsPrivate(node.clone()),
        SecretRef::NodeWgMacPrivate(node.clone()),
        SecretRef::NodeHy2Key(node.clone()),
        SecretRef::NodeHy2Obfs(node.clone(), ListenerIdx::FIRST),
        SecretRef::NodeSshBootstrapPrivate(node.clone()),
        SecretRef::ProbeVlessUuid(node.clone()),
        SecretRef::ProbeHy2Password(node.clone()),
        SecretRef::ProbeLoopUuid(node),
    ])
}

fn add_lon1(parts: DeploymentParts) -> Result<DeploymentParts, Infallible> {
    Ok(with_node(parts, planned_node("lon1", 1, 10)))
}

/// An initialised store with the planned node lon1 and its secrets.
fn with_planned_lon1() -> (tempfile::TempDir, Store, Observer, StateV2) {
    let (dir, store, state) = initialised();
    let mut secrets = Observer::new(&store);
    let next = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&planned_node_refs("lon1"), 1),
        add_lon1,
    )
    .unwrap();
    secrets.log.clear();
    (dir, store, secrets, next)
}

/// Every secret the state references is readable from `secrets`.
fn assert_references_resolve(state: &StateV2, secrets: &impl SecretStore) {
    for secret_ref in state.deployment.required_secrets() {
        let material = secrets.get(&secret_ref).unwrap();
        assert_eq!(material.kind(), secret_ref.kind());
    }
}

#[test]
fn new_secrets_are_written_before_the_state_that_references_them() {
    let (_dir, store, state) = initialised();
    let refs = planned_node_refs("lon1");
    assert_eq!(
        added_refs(&state.deployment, |parts| add_lon1(parts).unwrap()),
        refs
    );
    let entries = entries_for(&refs, 1);
    let mut secrets = Observer::new(&store);
    let next = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries.clone(),
        add_lon1,
    )
    .unwrap();

    assert_eq!(next.deployment.config_generation().get(), 2);
    assert_eq!(store.load().unwrap(), next);
    let puts = secrets.ops(SecretOp::Put);
    assert_eq!(puts.len(), 9);
    for seen in puts {
        assert!(
            !seen.referenced_on_disk,
            "written after the state: {seen:?}"
        );
        assert!(seen.lock_held, "written outside the lock: {seen:?}");
    }
    assert!(secrets.ops(SecretOp::Delete).is_empty());
    for entry in entries {
        let (secret_ref, material) = entry.into_parts();
        assert_eq!(secrets.get(&secret_ref).unwrap(), material);
    }
    assert_references_resolve(&next, &secrets);
}

#[test]
fn dropped_secrets_are_deleted_only_after_the_state_stops_referencing_them() {
    let (_dir, store, mut secrets, state) = with_planned_lon1();
    let bootstrap = SecretRef::NodeSshBootstrapPrivate(node_id("lon1"));
    // Adoption drops the one-time bootstrap key (design §13.2).
    let next = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        Vec::new(),
        |parts| Ok::<_, Infallible>(with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10]))),
    )
    .unwrap();

    assert_eq!(next.deployment.config_generation().get(), 3);
    assert_eq!(store.load().unwrap(), next);
    let deletes = secrets.ops(SecretOp::Delete);
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].secret_ref, bootstrap);
    assert!(
        !deletes[0].referenced_on_disk,
        "deleted before the state: {:?}",
        deletes[0]
    );
    assert!(deletes[0].lock_held, "deleted after the lock was released");
    assert!(!secrets.inner.refs().contains(&bootstrap));
    assert_references_resolve(&next, &secrets);
}

#[test]
fn one_update_can_add_and_drop_secrets_in_order() {
    let (_dir, store, mut secrets, state) = with_planned_lon1();
    let change = |parts| {
        with_user(
            with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10])),
            user(1, &[("lon1", 1)]),
        )
    };
    let refs = added_refs(&state.deployment, change);
    assert_eq!(refs.len(), 3, "{refs:?}");
    let next = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&refs, 2),
        |parts| Ok::<_, Infallible>(change(parts)),
    )
    .unwrap();

    let ops: Vec<SecretOp> = secrets.log.iter().map(|seen| seen.op).collect();
    assert_eq!(
        ops,
        [
            SecretOp::Put,
            SecretOp::Put,
            SecretOp::Put,
            SecretOp::Delete
        ]
    );
    assert!(secrets.log.iter().all(|seen| !seen.referenced_on_disk));
    assert!(secrets.log.iter().all(|seen| seen.lock_held));
    assert_references_resolve(&next, &secrets);
}

#[test]
fn the_secrets_supplied_must_be_exactly_the_new_references() {
    let (_dir, store, state) = initialised();
    let refs = planned_node_refs("lon1");
    let expected = state.deployment.config_generation();
    let missing = refs.first().unwrap().clone();
    let extra = SecretRef::ProbeVlessUuid(node_id("ams1"));
    let all_but_one: Vec<SecretRef> = refs.iter().skip(1).cloned().collect();
    let with_extra: Vec<SecretRef> = refs.iter().cloned().chain([extra.clone()]).collect();
    let twice: Vec<SecretRef> = refs.iter().cloned().chain([missing.clone()]).collect();
    let on_disk = state_bytes(&store);

    let mut secrets = Observer::new(&store);
    let mut attempt = |supplied: &[SecretRef]| {
        store_error(
            update_config_with_secrets(
                &store,
                &mut secrets,
                expected,
                entries_for(supplied, 1),
                add_lon1,
            )
            .unwrap_err(),
        )
    };

    let error = attempt(&all_but_one);
    assert_eq!(error.kind(), StoreErrorKind::SecretPlanMismatch);
    assert!(
        matches!(&error, StoreError::SecretPlanMismatch { missing: m, unreferenced: u }
            if *m == BTreeSet::from([missing.clone()]) && u.is_empty()),
        "{error:?}"
    );

    let error = attempt(&with_extra);
    assert!(
        matches!(&error, StoreError::SecretPlanMismatch { missing: m, unreferenced: u }
            if m.is_empty() && *u == BTreeSet::from([extra.clone()])),
        "{error:?}"
    );

    let error = attempt(&twice);
    assert_eq!(error.kind(), StoreErrorKind::DuplicateSecret);
    assert!(
        matches!(&error, StoreError::DuplicateSecret { secret_ref } if *secret_ref == missing),
        "{error:?}"
    );

    assert!(
        secrets.log.is_empty(),
        "nothing was written: {:?}",
        secrets.log
    );
    assert!(secrets.inner.is_empty());
    assert_eq!(state_bytes(&store), on_disk);
}

#[test]
fn refused_or_stale_updates_write_no_secrets() {
    let (_dir, store, state) = initialised();
    let entries = entries_for(&planned_node_refs("lon1"), 1);
    let mut secrets = Observer::new(&store);
    let error = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries.clone(),
        |_| Err(std::fmt::Error),
    )
    .unwrap_err();
    assert!(matches!(error, ChangeError::Refused(_)), "{error:?}");

    store
        .update_config(state.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();
    let error = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries,
        add_lon1,
    )
    .unwrap_err();
    assert_eq!(
        store_error(error).kind(),
        StoreErrorKind::GenerationConflict
    );
    assert!(secrets.log.is_empty());
}

#[test]
fn a_failed_secret_write_leaves_the_state_unchanged() {
    let (_dir, store, state) = initialised();
    let refs = planned_node_refs("lon1");
    let failing = refs.iter().nth(4).unwrap().clone();
    let on_disk = state_bytes(&store);
    let mut secrets = Observer::new(&store);
    secrets.fail_put = Some(failing.clone());

    let error = store_error(
        update_config_with_secrets(
            &store,
            &mut secrets,
            state.deployment.config_generation(),
            entries_for(&refs, 1),
            add_lon1,
        )
        .unwrap_err(),
    );
    assert_eq!(error.kind(), StoreErrorKind::SecretWrite);
    let StoreError::SecretWrite { secret_ref, source } = &error else {
        panic!("expected SecretWrite, got {error:?}");
    };
    assert_eq!(*secret_ref, failing);
    assert_eq!(source.kind(), SecretStoreErrorKind::Keychain);
    assert_eq!(
        *source,
        SecretStoreError::Keychain {
            op: SecretOp::Put,
            status: INTERACTION_NOT_ALLOWED
        }
    );
    assert_eq!(state_bytes(&store), on_disk, "the state was not written");
    // The secrets written before the failure are orphans, which nothing
    // references; a retry replaces them.
    assert_eq!(secrets.inner.len(), 4);
    secrets.fail_put = None;
    let next = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&refs, 1),
        add_lon1,
    )
    .unwrap();
    assert_eq!(secrets.inner.refs(), refs);
    assert_references_resolve(&next, &secrets);
}

#[test]
fn failed_deletions_are_reported_after_the_commit() {
    let (_dir, store, mut secrets, state) = with_planned_lon1();
    let refs = planned_node_refs("lon1");
    let stuck: BTreeSet<SecretRef> = refs.iter().take(2).cloned().collect();
    secrets.fail_delete = stuck.clone();

    let error = store_error(
        update_config_with_secrets(
            &store,
            &mut secrets,
            state.deployment.config_generation(),
            Vec::new(),
            |parts| Ok::<_, Infallible>(with_lifecycle(parts, "lon1", NodeLifecycle::Retired)),
        )
        .unwrap_err(),
    );
    assert_eq!(error.kind(), StoreErrorKind::SecretCleanup);
    let StoreError::SecretCleanup {
        committed,
        failures,
    } = &error
    else {
        panic!("expected SecretCleanup, got {error:?}");
    };
    assert_eq!(committed.get(), 3);
    let failed: BTreeSet<SecretRef> = failures
        .iter()
        .map(|failure| failure.secret_ref.clone())
        .collect();
    assert_eq!(failed, stuck);
    assert!(failures.iter().all(|failure| failure.error
        == SecretStoreError::Keychain {
            op: SecretOp::Delete,
            status: INTERACTION_NOT_ALLOWED
        }));

    // The state is committed, every other secret is gone, and only the
    // failed ones remain as orphans.
    let committed_state = store.load().unwrap();
    assert_eq!(committed_state.deployment.config_generation(), *committed);
    assert!(committed_state.deployment.required_secrets().is_empty());
    assert_eq!(secrets.ops(SecretOp::Delete).len(), refs.len());
    assert_eq!(secrets.inner.refs(), stuck);
}

#[test]
fn plain_writes_refuse_to_drop_secret_references() {
    let (_dir, store, _secrets, state) = with_planned_lon1();
    let on_disk = state_bytes(&store);
    let error = store_error(
        store
            .update_config(state.deployment.config_generation(), |parts| {
                Ok::<_, Infallible>(with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10])))
            })
            .unwrap_err(),
    );
    assert!(
        matches!(&error, StoreError::SecretRefsChanged { added, removed }
            if added.is_empty()
                && *removed == BTreeSet::from([SecretRef::NodeSshBootstrapPrivate(node_id("lon1"))])),
        "{error:?}"
    );
    assert_eq!(state_bytes(&store), on_disk);
}

#[test]
fn a_missing_secret_is_reported_by_the_store() {
    let (_dir, store, mut secrets, state) = with_planned_lon1();
    let bootstrap = SecretRef::NodeSshBootstrapPrivate(node_id("lon1"));
    // Someone removed the item behind the store's back.
    secrets.inner.delete(&bootstrap).unwrap();
    let error = store_error(
        update_config_with_secrets(
            &store,
            &mut secrets,
            state.deployment.config_generation(),
            Vec::new(),
            |parts| Ok::<_, Infallible>(with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10]))),
        )
        .unwrap_err(),
    );
    let StoreError::SecretCleanup { failures, .. } = &error else {
        panic!("expected SecretCleanup, got {error:?}");
    };
    assert_eq!(failures.len().get(), 1);
    assert_eq!(
        failures.first().error,
        SecretStoreError::SecretMissing {
            secret_ref: bootstrap
        }
    );
    assert_eq!(
        failures.first().error.kind(),
        SecretStoreErrorKind::SecretMissing
    );
}

/// The two Healthchecks checks of channel node `id` (decision F6).
fn check_refs(id: &str) -> BTreeSet<SecretRef> {
    let node = node_id(id);
    BTreeSet::from([
        SecretRef::NodeDeadManCheck(node.clone()),
        SecretRef::NodeMacAliveCheck(node),
    ])
}

/// The secrets lon1's alert channels reference as the only channel node:
/// the deployment's one ntfy topic and lon1's two checks.
fn lon1_alert_refs() -> BTreeSet<SecretRef> {
    let mut refs = check_refs("lon1");
    refs.insert(SecretRef::AlertTopic);
    refs
}

/// Parts with the alert channels of exactly `nodes` set up.
fn with_channels(mut parts: DeploymentParts, nodes: &[&str]) -> DeploymentParts {
    let mut alerting = AlertSettings::pilot();
    alerting.channels.extend(nodes.iter().map(|id| node_id(id)));
    parts.alerting = Some(alerting);
    parts
}

/// Parts with lon1's alert channels set up.
fn with_lon1_channels(parts: DeploymentParts) -> DeploymentParts {
    with_channels(parts, &["lon1"])
}

/// A node's alert-channel secrets follow the §7 ordering: written before
/// the state names the channels, and deleted after a shut-down retirement
/// drops them (lon1 is the only channel node, so the topic goes too). A
/// change that makes the node inactive while its channels remain is
/// refused, with nothing written.
#[test]
fn alert_channel_secrets_follow_their_node() {
    let (_dir, store, mut secrets, state) = with_planned_lon1();
    let alert_refs = lon1_alert_refs();
    assert_eq!(
        added_refs(&state.deployment, with_lon1_channels),
        alert_refs
    );
    let set_up = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&alert_refs, 3),
        |parts| Ok::<_, Infallible>(with_lon1_channels(parts)),
    )
    .unwrap();
    let puts = secrets.ops(SecretOp::Put);
    let put: BTreeSet<SecretRef> = puts.iter().map(|seen| seen.secret_ref.clone()).collect();
    assert_eq!(put, alert_refs);
    assert!(
        puts.iter()
            .all(|seen| !seen.referenced_on_disk && seen.lock_held),
        "{puts:?}"
    );
    assert_references_resolve(&set_up, &secrets);
    secrets.log.clear();

    // Cancelling the planned node without dropping its channels is refused.
    let on_disk = state_bytes(&store);
    let error = store_error(
        update_config_with_secrets(
            &store,
            &mut secrets,
            set_up.deployment.config_generation(),
            Vec::new(),
            |parts| Ok::<_, Infallible>(with_lifecycle(parts, "lon1", NodeLifecycle::Retired)),
        )
        .unwrap_err(),
    );
    assert!(
        matches!(
            &error,
            StoreError::InvalidChange {
                source: ModelError::AlertChannelsOnInactiveNode { node }
            } if *node == node_id("lon1")
        ),
        "{error:?}"
    );
    assert_eq!(state_bytes(&store), on_disk);
    assert!(secrets.log.is_empty());

    // Adopt lon1, start retiring it, then shut it down: the record drops
    // its channels, and their secrets are deleted after the commit.
    let adopted_state = update_config_with_secrets(
        &store,
        &mut secrets,
        set_up.deployment.config_generation(),
        Vec::new(),
        |parts| Ok::<_, Infallible>(with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10]))),
    )
    .unwrap();
    let retiring = store
        .update_config(adopted_state.deployment.config_generation(), |parts| {
            let site = match &parts.nodes[0].lifecycle {
                NodeLifecycle::Adopted { site } => site.clone(),
                other => panic!("lon1 is {other:?}"),
            };
            Ok::<_, Infallible>(with_lifecycle(
                parts,
                "lon1",
                NodeLifecycle::Retiring { site },
            ))
        })
        .unwrap();
    assert!(
        retiring
            .deployment
            .required_secrets()
            .is_superset(&alert_refs)
    );
    secrets.log.clear();
    let retired = record_with_secrets(
        &store,
        &mut secrets,
        retiring.deployment.config_generation(),
        Bookkeeping::RetirementShutDown {
            node: node_id("lon1"),
        },
    )
    .unwrap();
    assert_eq!(
        retired
            .deployment
            .alerting()
            .map(|alerting| alerting.channels.len()),
        Some(0)
    );
    let deletes = secrets.ops(SecretOp::Delete);
    let deleted: BTreeSet<SecretRef> = deletes.iter().map(|seen| seen.secret_ref.clone()).collect();
    assert!(deleted.is_superset(&alert_refs), "{deleted:?}");
    assert!(
        deletes
            .iter()
            .all(|seen| !seen.referenced_on_disk && seen.lock_held),
        "{deletes:?}"
    );
    assert!(secrets.inner.refs().is_disjoint(&alert_refs));
    assert_references_resolve(&retired, &secrets);
}

/// Planned lon1 and ams1 with their secrets, and lon1's alert channels set
/// up: the topic and lon1's checks written before the state names them.
fn with_lon1_channels_and_planned_ams1() -> (tempfile::TempDir, Store, Observer, StateV2) {
    let (dir, store, mut secrets, state) = with_planned_lon1();
    let two = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&planned_node_refs("ams1"), 2),
        |parts| Ok::<_, Infallible>(with_node(parts, planned_node("ams1", 2, 20))),
    )
    .unwrap();
    secrets.log.clear();
    let set_up = update_config_with_secrets(
        &store,
        &mut secrets,
        two.deployment.config_generation(),
        entries_for(&lon1_alert_refs(), 3),
        |parts| Ok::<_, Infallible>(with_lon1_channels(parts)),
    )
    .unwrap();
    let puts = secrets.ops(SecretOp::Put);
    let put: BTreeSet<SecretRef> = puts.iter().map(|seen| seen.secret_ref.clone()).collect();
    assert_eq!(put, lon1_alert_refs());
    assert!(
        puts.iter()
            .all(|seen| !seen.referenced_on_disk && seen.lock_held),
        "{puts:?}"
    );
    secrets.log.clear();
    (dir, store, secrets, set_up)
}

/// One ntfy topic serves every channel node (decision F6): a second
/// channel node adds only its two checks, and supplying the topic again is
/// refused with nothing written; retiring one of two channel nodes deletes
/// only that node's checks and keeps the topic, which still holds the
/// material first written. This is design §13.4's rotation order: the
/// replacement (here the planned ams1) gets its channels before the last
/// other channel node retires, so the phone's subscription stays valid.
#[test]
fn the_alert_topic_is_shared_and_outlives_one_channel_node() {
    let (_dir, store, mut secrets, set_up) = with_lon1_channels_and_planned_ams1();
    let topic = secrets.inner.get(&SecretRef::AlertTopic).unwrap();
    let both = |parts| with_channels(parts, &["lon1", "ams1"]);
    assert_eq!(added_refs(&set_up.deployment, both), check_refs("ams1"));

    let on_disk = state_bytes(&store);
    let mut again = entries_for(&check_refs("ams1"), 4);
    again.extend(entries_for(&[SecretRef::AlertTopic], 4));
    let error = store_error(
        update_config_with_secrets(
            &store,
            &mut secrets,
            set_up.deployment.config_generation(),
            again,
            |parts| Ok::<_, Infallible>(both(parts)),
        )
        .unwrap_err(),
    );
    assert!(
        matches!(&error, StoreError::SecretPlanMismatch { missing, unreferenced }
            if missing.is_empty() && *unreferenced == BTreeSet::from([SecretRef::AlertTopic])),
        "{error:?}"
    );
    assert_eq!(state_bytes(&store), on_disk);
    assert!(secrets.log.is_empty());

    let two_channels = update_config_with_secrets(
        &store,
        &mut secrets,
        set_up.deployment.config_generation(),
        entries_for(&check_refs("ams1"), 4),
        |parts| Ok::<_, Infallible>(both(parts)),
    )
    .unwrap();
    assert_eq!(secrets.inner.get(&SecretRef::AlertTopic).unwrap(), topic);
    secrets.log.clear();

    // Adopt lon1, start retiring it, then shut it down.
    let adopted_state = update_config_with_secrets(
        &store,
        &mut secrets,
        two_channels.deployment.config_generation(),
        Vec::new(),
        |parts| Ok::<_, Infallible>(with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10]))),
    )
    .unwrap();
    let retiring = store
        .update_config(adopted_state.deployment.config_generation(), |parts| {
            Ok::<_, Infallible>(with_lifecycle(
                parts,
                "lon1",
                NodeLifecycle::Retiring {
                    site: site([45, 67, 89, 10]),
                },
            ))
        })
        .unwrap();
    secrets.log.clear();
    let retired = record_with_secrets(
        &store,
        &mut secrets,
        retiring.deployment.config_generation(),
        Bookkeeping::RetirementShutDown {
            node: node_id("lon1"),
        },
    )
    .unwrap();
    let deleted: BTreeSet<SecretRef> = secrets
        .ops(SecretOp::Delete)
        .iter()
        .map(|seen| seen.secret_ref.clone())
        .collect();
    assert!(deleted.is_superset(&check_refs("lon1")), "{deleted:?}");
    assert!(!deleted.contains(&SecretRef::AlertTopic), "{deleted:?}");
    assert!(
        retired
            .deployment
            .required_secrets()
            .contains(&SecretRef::AlertTopic)
    );
    assert_eq!(secrets.inner.get(&SecretRef::AlertTopic).unwrap(), topic);
    assert!(secrets.inner.refs().is_disjoint(&check_refs("lon1")));
    assert_references_resolve(&retired, &secrets);
}

/// Removing the last channel node's channels drops the topic with its
/// checks: the state stops naming them first, and they are deleted after
/// the commit, under the lock. Removing one of two keeps the topic.
#[test]
fn the_alert_topic_is_deleted_after_the_commit_that_leaves_no_channel_node() {
    let (_dir, store, mut secrets, set_up) = with_lon1_channels_and_planned_ams1();
    let two_channels = update_config_with_secrets(
        &store,
        &mut secrets,
        set_up.deployment.config_generation(),
        entries_for(&check_refs("ams1"), 4),
        |parts| Ok::<_, Infallible>(with_channels(parts, &["lon1", "ams1"])),
    )
    .unwrap();
    secrets.log.clear();

    let ams1_only = update_config_with_secrets(
        &store,
        &mut secrets,
        two_channels.deployment.config_generation(),
        Vec::new(),
        |parts| Ok::<_, Infallible>(with_channels(parts, &["ams1"])),
    )
    .unwrap();
    let deleted: BTreeSet<SecretRef> = secrets
        .ops(SecretOp::Delete)
        .iter()
        .map(|seen| seen.secret_ref.clone())
        .collect();
    assert_eq!(deleted, check_refs("lon1"));
    assert!(secrets.inner.refs().contains(&SecretRef::AlertTopic));
    secrets.log.clear();

    let none = update_config_with_secrets(
        &store,
        &mut secrets,
        ams1_only.deployment.config_generation(),
        Vec::new(),
        |parts| Ok::<_, Infallible>(with_channels(parts, &[])),
    )
    .unwrap();
    let deletes = secrets.ops(SecretOp::Delete);
    let deleted: BTreeSet<SecretRef> = deletes.iter().map(|seen| seen.secret_ref.clone()).collect();
    let mut expected = check_refs("ams1");
    expected.insert(SecretRef::AlertTopic);
    assert_eq!(deleted, expected);
    assert!(
        deletes
            .iter()
            .all(|seen| !seen.referenced_on_disk && seen.lock_held),
        "{deletes:?}"
    );
    assert!(secrets.ops(SecretOp::Put).is_empty());
    assert_eq!(
        none.deployment
            .alerting()
            .map(|alerting| alerting.channels.len()),
        Some(0)
    );
    assert!(!secrets.inner.refs().contains(&SecretRef::AlertTopic));
    assert_references_resolve(&none, &secrets);
    assert_eq!(store.load().unwrap(), none);
}
