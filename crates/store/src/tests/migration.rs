// SPDX-License-Identifier: GPL-3.0-or-later

//! The migration chain and its backups (design §7). Version 1 is the
//! newest real version, so the backup path runs through a test chain with
//! a test-only version 0.

use std::convert::Infallible;
use std::fs;

use mooring_model::collections::NonEmpty;
use mooring_model::counters::ConfigGeneration;
use mooring_model::deployment::{Bookkeeping, Deployment, DeploymentParts};
use mooring_model::digest::Sha256Digest;
use mooring_model::exit::{CycleDay, Pairing, SimPolicy, Uplink};
use mooring_model::iface::{InterfaceSelector, MacAddr};
use mooring_model::node::{AppliedConfig, NodeLifecycle, NodeRole};
use mooring_model::ports::{
    DEBIAN_EPHEMERAL_PORTS, DEFAULT_REFLECTOR_PORT, DEFAULT_WG_PORT, HopInterval, Hy2Listener,
    Hy2Obfs, Port, PortPlan, PortRange,
};
use mooring_model::state::{RuntimeIntent, StateFile, StateHeader, StateV1};
use mooring_model::user::{Capability, ClientLine, UserStatus};
use mooring_model::wg::WgIndex;
use serde::Deserialize;

use super::builders::{
    added_refs, adopted, adopted_store, applied_record, entries_for, initialised, node_id,
    planned_node, site, target, user, with_lifecycle, with_node, with_user,
};
use super::{mode_of, state_bytes, store_error};
use crate::durable::temp_path;
use crate::error::{IoOp, StoreError, StoreErrorKind};
use crate::migrate::{Chain, lift_state_file, migrate};
use crate::ordered::update_config_with_secrets;
use crate::secrets::InMemorySecretStore;
use crate::store::Store;

/// A test-only predecessor of version 1: the same document without the
/// runtime intent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV0 {
    version: u32,
    deployment: Deployment,
}

/// The test step `V0 → V1`: the exit starts disabled.
fn v0_to_v1(state: StateV0) -> StateV1 {
    assert_eq!(state.version, 0);
    StateV1 {
        deployment: state.deployment,
        runtime: RuntimeIntent::new(),
    }
}

fn lift_with_v0(bytes: &[u8]) -> Result<StateV1, serde_json::Error> {
    let header: StateHeader = serde_json::from_slice(bytes)?;
    if header.version == 0 {
        serde_json::from_slice::<StateV0>(bytes).map(v0_to_v1)
    } else {
        lift_state_file(bytes)
    }
}

/// This build's chain plus the test version 0.
const WITH_V0: Chain = Chain {
    newest: 1,
    lift: lift_with_v0,
};

/// A store whose `state.json` is the version-0 form of a fresh state.
fn store_at_v0() -> (tempfile::TempDir, Store, StateV1, Vec<u8>) {
    let (dir, plain, state) = initialised();
    as_v0(dir, &plain, state)
}

/// Rewrites `plain`'s `state.json` as the version-0 form of `state`.
fn as_v0(
    dir: tempfile::TempDir,
    plain: &Store,
    state: StateV1,
) -> (tempfile::TempDir, Store, StateV1, Vec<u8>) {
    let v0 = serde_json::json!({ "version": 0, "deployment": &state.deployment });
    let bytes = serde_json::to_vec_pretty(&v0).unwrap();
    fs::write(plain.state_path(), &bytes).unwrap();
    let store = Store::with_chain(dir.path(), WITH_V0);
    (dir, store, state, bytes)
}

#[test]
fn version_one_is_the_newest_and_lifts_unchanged() {
    assert_eq!(Chain::CURRENT.newest, StateFile::CURRENT_VERSION);
    assert_eq!(StateFile::CURRENT_VERSION, 1);
    let (_dir, _store, state) = initialised();
    assert_eq!(migrate(StateFile::V1(state.clone())), state);
}

#[test]
fn older_documents_are_lifted_in_memory_without_writing() {
    let (_dir, store, state, v0) = store_at_v0();
    let lifted = store.load().unwrap();
    assert_eq!(lifted.deployment, state.deployment);
    assert_eq!(lifted.runtime, RuntimeIntent::new());
    assert_eq!(state_bytes(&store), v0, "a read never writes");
    assert!(!store.backup_path(0, 1).exists());
}

#[test]
fn the_first_write_backs_up_the_original_then_writes_the_newest_version() {
    let (_dir, store, state, v0) = store_at_v0();
    let next = store
        .update_config(state.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();

    let backup = store.backup_path(0, 1);
    assert_eq!(backup.file_name().unwrap(), "state.json.bak-0-1");
    assert_eq!(
        fs::read(&backup).unwrap(),
        v0,
        "the backup is the original document"
    );
    assert_eq!(mode_of(&backup), 0o600);
    assert!(!temp_path(&backup).exists());

    // state.json is now version 1, readable by this build's own chain.
    let written: StateFile = serde_json::from_slice(&state_bytes(&store)).unwrap();
    assert_eq!(written, StateFile::V1(next.clone()));
    assert_eq!(Store::new(store.dir()).load().unwrap(), next);

    // Later writes start from version 1 and leave the backup alone.
    store
        .update_config(next.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();
    assert_eq!(fs::read(&backup).unwrap(), v0);
    assert!(!store.backup_path(1, 1).exists());
}

#[test]
fn every_kind_of_write_backs_up_first() {
    let (_dir, store, state, v0) = store_at_v0();
    store
        .set_exit_enabled(state.runtime.revision, true)
        .unwrap();
    assert_eq!(fs::read(store.backup_path(0, 1)).unwrap(), v0);

    let (dir, plain, adopted, _secrets) = adopted_store();
    let (_dir, store, state, v0) = as_v0(dir, &plain, adopted);
    let generation = state.deployment.config_generation();
    store
        .record(generation, applied_record("lon1", generation))
        .unwrap();
    assert_eq!(fs::read(store.backup_path(0, 1)).unwrap(), v0);

    let (_dir, store, state, v0) = store_at_v0();
    let node = planned_node("lon1", 1, 10);
    let refs = added_refs(&state.deployment, |parts| with_node(parts, node.clone()));
    let mut secrets = InMemorySecretStore::new();
    update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&refs, 1),
        |parts| Ok::<_, Infallible>(with_node(parts, node)),
    )
    .unwrap();
    assert_eq!(fs::read(store.backup_path(0, 1)).unwrap(), v0);
}

#[test]
fn the_backup_is_durable_before_the_state_is_written() {
    let (_dir, store, state, v0) = store_at_v0();
    // Block only the state's own temporary file, so the state write fails
    // after the backup write.
    let temp = temp_path(&store.state_path());
    fs::create_dir(&temp).unwrap();
    fs::write(temp.join("keep"), b"x").unwrap();

    let error = store_error(
        store
            .update_config(state.deployment.config_generation(), Ok::<_, Infallible>)
            .unwrap_err(),
    );
    assert!(
        matches!(&error, StoreError::Io { op: IoOp::RemoveStaleTemp, path, .. } if *path == temp),
        "{error:?}"
    );
    assert_eq!(error.kind(), StoreErrorKind::Io);
    assert_eq!(fs::read(store.backup_path(0, 1)).unwrap(), v0);
    assert_eq!(state_bytes(&store), v0, "the state was not written");
}

#[test]
fn a_backup_left_by_an_interrupted_migration_is_replaced() {
    let (_dir, store, state, v0) = store_at_v0();
    // An earlier attempt backed up a document that was never migrated.
    fs::write(store.backup_path(0, 1), b"an older version 0 document").unwrap();
    store
        .update_config(state.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();
    assert_eq!(fs::read(store.backup_path(0, 1)).unwrap(), v0);
}

#[test]
fn a_newer_document_is_refused_by_the_test_chain_too() {
    let (_dir, store, _, _) = store_at_v0();
    fs::write(store.state_path(), br#"{"version": 2}"#).unwrap();
    let error = store.load().unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::DowngradeRefused {
                found: 2,
                newest: 1
            }
        ),
        "{error:?}"
    );
}

/// The version-1 golden pins the on-disk format: a model change that
/// alters it must come with a new version and a migration step.
#[test]
fn the_version_one_golden_lifts_unchanged_and_round_trips() {
    let golden = include_bytes!("golden/state-v1.json");
    let (dir, plain, state) = initialised();
    let lon1 = planned_node("lon1", 1, 10);
    let mut secrets = InMemorySecretStore::new();
    let refs = added_refs(&state.deployment, |parts| with_node(parts, lon1.clone()));
    let added = update_config_with_secrets(
        &plain,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&refs, 1),
        |parts| Ok::<_, Infallible>(with_node(parts, lon1)),
    )
    .unwrap();
    let change = |parts| {
        with_user(
            with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10])),
            user(1, &[("lon1", 1)]),
        )
    };
    let refs = added_refs(&added.deployment, change);
    let expected = update_config_with_secrets(
        &plain,
        &mut secrets,
        added.deployment.config_generation(),
        entries_for(&refs, 2),
        |parts| Ok::<_, Infallible>(change(parts)),
    )
    .unwrap();
    let expected = plain
        .set_exit_enabled(expected.runtime.revision, true)
        .unwrap();

    assert_eq!(
        String::from_utf8(state_bytes(&plain)).unwrap(),
        String::from_utf8(golden.to_vec()).unwrap(),
        "the store writes exactly the golden document"
    );
    fs::write(plain.state_path(), golden).unwrap();
    let store = Store::new(dir.path());
    assert_eq!(store.load().unwrap(), expected);
    let file: StateFile = serde_json::from_slice(golden).unwrap();
    assert_eq!(migrate(file), expected);
}

/// A deployment holding every persisted variant once [`lon1_applied`] is
/// recorded: an adopted node with a target and two Hysteria2 listeners, a
/// retiring node, a node pending provider deletion and a retired one; an
/// active user with a capability, one pending revocation and a revoked one;
/// a `Separate` uplink selected by its gateway, an unpaired carrier check
/// and no SIM hard stop.
fn every_variant(parts: DeploymentParts) -> DeploymentParts {
    let listener = |port: u16, hop_end: u16, seconds: u16| {
        Hy2Listener::new(
            Port::new(port).unwrap(),
            PortRange::new(port + 1, hop_end).unwrap(),
            HopInterval::from_seconds(seconds).unwrap(),
            Hy2Obfs::Salamander,
        )
        .unwrap()
    };
    let mut lon1 = planned_node("lon1", 1, 10);
    lon1.ports = PortPlan::new(
        DEFAULT_WG_PORT,
        DEFAULT_REFLECTOR_PORT,
        NonEmpty::from_parts(listener(61000, 62999, 30), vec![listener(63000, 64999, 5)]),
        Vec::new(),
        DEBIAN_EPHEMERAL_PORTS,
    )
    .unwrap();
    lon1.reality.target = Some(target());
    lon1.lifecycle = adopted([45, 67, 89, 10]);
    let mut ams1 = planned_node("ams1", 2, 20);
    ams1.role = NodeRole::Standby;
    ams1.reality.target = Some(target());
    ams1.lifecycle = NodeLifecycle::Retiring {
        site: site([46, 78, 90, 12]),
    };
    let mut par1 = planned_node("par1", 3, 30);
    par1.lifecycle = NodeLifecycle::RetiredPendingProviderDeletion {
        address: site([47, 1, 2, 3]).address,
    };
    let mut fra1 = planned_node("fra1", 4, 40);
    fra1.lifecycle = NodeLifecycle::Retired;
    let mut active = user(1, &[("lon1", 1), ("ams1", 1)]);
    active
        .client
        .capabilities
        .insert(Capability::RealityMlkemOptIn);
    let mut pending = user(2, &[("lon1", 2), ("ams1", 2)]);
    pending.client.line = ClientLine::Cfm04;
    pending.status = UserStatus::RevokePending;
    let mut revoked = user(3, &[]);
    revoked.status = UserStatus::Revoked;
    let mut exit = parts.exit;
    exit.uplink = Uplink::Separate(InterfaceSelector::GatewayLinkAddr {
        gw_lladdr: MacAddr::parse("02:68:6f:6d:65:01").unwrap(),
        subnet: "10.0.0.0/24".parse().unwrap(),
    });
    exit.egress_check.pairing = Pairing::Unpaired;
    exit.sim = SimPolicy::new(CycleDay::new(15).unwrap(), 1_000_000, None).unwrap();
    let mut policy = parts.policy;
    policy.block_quic = false;
    policy.camo_forward = false;
    DeploymentParts {
        config_generation: parts.config_generation,
        exit,
        policy,
        nodes: vec![lon1, ams1, par1, fra1],
        users: vec![active, pending, revoked],
        next_wg_index: WgIndex::new(5).unwrap(),
    }
}

/// lon1's confirmation of the first generation, which makes it the
/// golden's applied node; only a record can set it.
fn lon1_applied() -> Bookkeeping {
    Bookkeeping::Applied {
        node: node_id("lon1"),
        applied: AppliedConfig {
            config_generation: ConfigGeneration::INITIAL,
            digest: Sha256Digest::from_bytes([0xd1; 32]),
        },
    }
}

/// The second version-1 golden pins the encoding of every persisted
/// variant the first leaves out (`state-v1-every-variant.json`): a model
/// change to any of them needs a new version and a migration step.
#[test]
fn the_every_variant_golden_lifts_unchanged_and_round_trips() {
    let golden = include_bytes!("golden/state-v1-every-variant.json");
    let (dir, store, state) = initialised();
    let refs = added_refs(&state.deployment, every_variant);
    let mut secrets = InMemorySecretStore::new();
    let changed = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&refs, 3),
        |parts| Ok::<_, Infallible>(every_variant(parts)),
    )
    .unwrap();
    let expected = store
        .record(changed.deployment.config_generation(), lon1_applied())
        .unwrap();
    assert_eq!(
        String::from_utf8(state_bytes(&store)).unwrap(),
        String::from_utf8(golden.to_vec()).unwrap(),
        "the store writes exactly the golden document"
    );
    fs::write(store.state_path(), golden).unwrap();
    assert_eq!(Store::new(dir.path()).load().unwrap(), expected);
    let file: StateFile = serde_json::from_slice(golden).unwrap();
    assert_eq!(migrate(file), expected);
}
