// SPDX-License-Identifier: GPL-3.0-or-later

//! The migration chain and its backups (design §7): a version-1 document
//! lifts to version 2 in memory only, the first write backs up the
//! version-1 bytes, a document the chain cannot lift is refused and left
//! alone, and the goldens pin both versions' encodings and the lift between
//! them. A lifted state has no plan record, which no version-2 API builds,
//! so each lift is checked against the same history built through the
//! version-2 API once the plan is recorded on it.

use std::convert::Infallible;
use std::fs;
use std::num::{NonZeroU16, NonZeroU64};

use mooring_model::alerting::AlertSettings;
use mooring_model::collections::NonEmpty;
use mooring_model::counters::{ConfigGeneration, RuntimeRevision};
use mooring_model::date::CalendarDate;
use mooring_model::deployment::{
    Bookkeeping, CapacityPolicy, Deployment, DeploymentInit, DeploymentParts,
};
use mooring_model::digest::Sha256Digest;
use mooring_model::error::ModelError;
use mooring_model::exit::{Pairing, Uplink, UplinkBaseline};
use mooring_model::ids::{LocalLabel, PublicAlias, UserId};
use mooring_model::iface::{InterfaceSelector, MacAddr};
use mooring_model::keys::Ed25519Pub;
use mooring_model::node::{AppliedConfig, NodeLifecycle, NodeRole};
use mooring_model::ports::{
    DEBIAN_EPHEMERAL_PORTS, DEFAULT_REFLECTOR_PORT, DEFAULT_WG_PORT, HopInterval, Hy2Listener,
    Hy2Obfs, Port, PortPlan, PortRange,
};
use mooring_model::quota::AutoQuotaPolicy;
use mooring_model::secret::SecretRef;
use mooring_model::sim::{
    BillDay, CycleRule, PILOT_SIM_HARD_STOP_BYTES, PILOT_SIM_WARN_BYTES, PeriodDays, SimPlan,
    SimPolicy, StopPolicy,
};
use mooring_model::state::{StateFile, StateV2};
use mooring_model::time::UnixTime;
use mooring_model::user::{
    AgreementRecord, AgreementVersion, Capability, ClientLine, QuotaAction, SuspendReason, User,
    UserPolicy, UserQuota, UserStatus, WarnPercent,
};
use mooring_model::viewer::Viewer;
use mooring_model::wg::WgIndex;
use tempfile::TempDir;

use super::builders::{
    V1_GOLDEN_HARD_STOP_BYTES, V1_GOLDEN_WARN_BYTES, added_refs, adopted, applied_record,
    deployment_init, empty_store, entries_for, initialised, node_id, planned_node, site,
    smarty_plan, target, user, with_lifecycle, with_node, with_user,
};
use super::{mode_of, state_bytes, store_error};
use crate::durable::temp_path;
use crate::error::{IoOp, StoreError, StoreErrorKind};
use crate::migrate::{migrate, parse};
use crate::ordered::{record_with_secrets, update_config_with_secrets};
use crate::secrets::{InMemorySecretStore, SecretStore};
use crate::store::Store;

/// lon1 adopted with user 1 on it and the exit enabled, written by a
/// version-1 build.
const V1: &[u8] = include_bytes!("golden/state-v1.json");
/// Every version-1 variant; its SIM policy has no hard stop.
const V1_EVERY_VARIANT: &[u8] = include_bytes!("golden/state-v1-every-variant.json");
/// The version-2 form of [`V1`], exactly its lift: the same deployment,
/// plan unrecorded, and empty version-2 records.
const V2: &[u8] = include_bytes!("golden/state-v2.json");
/// Every version-2 variant one document can hold.
const V2_EVERY_VARIANT: &[u8] = include_bytes!("golden/state-v2-every-variant.json");

/// [`V1_EVERY_VARIANT`] with a hard stop of 2,000,000 bytes, which lifts.
fn v1_every_variant_with_stop() -> String {
    let text = String::from_utf8(V1_EVERY_VARIANT.to_vec()).unwrap();
    let with_stop = text.replacen(
        "\"hard_stop_bytes\": null",
        "\"hard_stop_bytes\": 2000000",
        1,
    );
    assert_ne!(with_stop, text);
    with_stop
}

/// A store whose `state.json` holds `bytes`, as an earlier build left it.
fn store_holding(bytes: &[u8]) -> (TempDir, Store) {
    let (dir, store) = empty_store();
    fs::write(store.state_path(), bytes).unwrap();
    (dir, store)
}

/// The on-disk encoding of `file`, as the store writes it.
fn pretty(file: &StateFile) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(file).unwrap();
    bytes.push(b'\n');
    bytes
}

/// The history both [`V1`] and [`V2`] record, built through the version-2
/// public API with the SMARTY plan recorded: lon1 planned then adopted at
/// 45.67.89.10 with user 1 on it, then the exit enabled (generation 3,
/// revision 2).
fn built_history() -> (TempDir, Store, StateV2) {
    let (dir, store, state) = initialised();
    let lon1 = planned_node("lon1", 1, 10);
    let mut secrets = InMemorySecretStore::new();
    let refs = added_refs(&state.deployment, |parts| with_node(parts, lon1.clone()));
    let added = update_config_with_secrets(
        &store,
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
    let adopted = update_config_with_secrets(
        &store,
        &mut secrets,
        added.deployment.config_generation(),
        entries_for(&refs, 2),
        |parts| Ok::<_, Infallible>(change(parts)),
    )
    .unwrap();
    let enabled = store
        .set_exit_enabled(adopted.runtime.revision, true)
        .unwrap();
    (dir, store, enabled)
}

/// `state` with the SMARTY plan recorded on its SIM policy, keeping the
/// bill day and thresholds: what `sim set-plan` does to a lifted state.
fn with_plan_recorded(state: StateV2) -> StateV2 {
    let mut parts = state.deployment.into_parts();
    let sim = &parts.exit.sim;
    assert_eq!(sim.plan(), None, "the plan was already recorded");
    parts.exit.sim =
        SimPolicy::new(sim.cycle(), smarty_plan(), sim.warn_bytes(), sim.stop()).unwrap();
    StateV2 {
        deployment: Deployment::try_from(parts).unwrap(),
        runtime: state.runtime,
    }
}

/// [`V1`] lifted, as every read of it returns it.
fn lifted_golden() -> StateV2 {
    migrate(parse(V1).unwrap()).unwrap()
}

#[test]
fn version_two_is_the_newest_and_lifts_unchanged() {
    assert_eq!(StateFile::CURRENT_VERSION, 2);
    let (_dir, _store, state) = initialised();
    assert_eq!(migrate(StateFile::V2(state.clone())).unwrap(), state);
}

#[test]
fn older_documents_are_lifted_in_memory_without_writing() {
    let (_dir, store) = store_holding(V1);
    let (_built_dir, _built, expected) = built_history();
    let lifted = store.load().unwrap();
    assert_eq!(lifted.deployment.exit().sim.plan(), None);
    assert_eq!(with_plan_recorded(lifted), expected);
    assert_eq!(state_bytes(&store), V1, "a read never writes");
    assert!(!store.backup_path(1, 2).exists());
}

/// P0-1: a fresh state records the plan. An exit site cloned from a lifted
/// state has none, so `init` refuses it and writes nothing; with the plan
/// recorded it initialises.
#[test]
fn init_refuses_an_unrecorded_plan() {
    let lifted_site = lifted_golden().deployment.exit().clone();
    assert_eq!(lifted_site.sim.plan(), None);
    let (_dir, store) = empty_store();
    let error = store
        .init(DeploymentInit {
            exit: lifted_site,
            ..deployment_init()
        })
        .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::InvalidChange {
                source: ModelError::PlanNotRecorded
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.kind(), StoreErrorKind::InvalidChange);
    // Refused before any file is touched: not even the lock file exists.
    let left: Vec<_> = fs::read_dir(store.dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "the refused init left {left:?}");
    let state = store.init(deployment_init()).unwrap();
    assert_eq!(state.deployment.exit().sim.plan(), Some(&smarty_plan()));
    assert_eq!(store.load().unwrap(), state);
}

/// A plan-less SIM policy, as only decoding (or the version-1 lift) builds
/// one: monthly on bill day 1, warning at `warn` and a hard stop at
/// `stop` bytes.
fn unrecorded_sim(warn: u64, stop: u64) -> SimPolicy {
    let policy: SimPolicy = serde_json::from_str(&format!(
        r#"{{"cycle":{{"monthly":{{"bill_day":1}}}},"plan":null,"warn_bytes":{warn},"stop":{{"hard_stop":{{"bytes":{stop}}}}}}}"#
    ))
    .unwrap();
    assert_eq!(policy.plan(), None);
    policy
}

/// P0-1 after init: a change that edits the exit's SIM policy must leave
/// its plan recorded. A closure cannot swap a decoded plan-less policy over
/// a recorded plan, nor give a lifted state new thresholds without
/// recording its plan, through either write; the refused change writes
/// nothing. A lifted state still takes a change that leaves its policy as
/// it is, and one that records the plan.
#[test]
fn an_edited_sim_policy_keeps_its_plan_recorded() {
    let refused = |error: StoreError| {
        assert!(
            matches!(
                error,
                StoreError::InvalidChange {
                    source: ModelError::PlanNotRecorded
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.kind(), StoreErrorKind::InvalidChange);
    };
    let mut secrets = InMemorySecretStore::new();

    // A recorded plan is never un-recorded, not even with the same
    // thresholds.
    let (_dir, store, state) = initialised();
    let current = state.deployment.config_generation();
    let sim = &state.deployment.exit().sim;
    let unrecord = unrecorded_sim(sim.warn_bytes(), sim.stop().hard_stop_bytes().unwrap());
    let on_disk = state_bytes(&store);
    let swap = |mut parts: DeploymentParts| {
        parts.exit.sim = unrecord.clone();
        Ok::<_, Infallible>(parts)
    };
    refused(store_error(store.update_config(current, swap).unwrap_err()));
    refused(store_error(
        update_config_with_secrets(&store, &mut secrets, current, Vec::new(), swap).unwrap_err(),
    ));
    assert_eq!(state_bytes(&store), on_disk);

    // A lifted policy is edited only by recording its plan.
    let (_dir, store) = store_holding(V1);
    let lifted = store.load().unwrap();
    let current = lifted.deployment.config_generation();
    let lifted_sim = lifted.deployment.exit().sim.clone();
    assert_eq!(lifted_sim.plan(), None);
    let retuned = unrecorded_sim(100_000_000_000, 200_000_000_000);
    assert_ne!(retuned, lifted_sim);
    let retune = |mut parts: DeploymentParts| {
        parts.exit.sim = retuned.clone();
        Ok::<_, Infallible>(parts)
    };
    refused(store_error(
        store.update_config(current, retune).unwrap_err(),
    ));
    refused(store_error(
        update_config_with_secrets(&store, &mut secrets, current, Vec::new(), retune).unwrap_err(),
    ));
    assert_eq!(state_bytes(&store), V1, "nothing was written");
    let other = store
        .update_config(current, |mut parts| {
            parts.policy.block_quic = !parts.policy.block_quic;
            Ok::<_, Infallible>(parts)
        })
        .unwrap();
    assert_eq!(other.deployment.exit().sim, lifted_sim);
    let recorded = store
        .update_config(other.deployment.config_generation(), |mut parts| {
            let sim = &parts.exit.sim;
            parts.exit.sim =
                SimPolicy::new(sim.cycle(), smarty_plan(), sim.warn_bytes(), sim.stop()).unwrap();
            Ok::<_, Infallible>(parts)
        })
        .unwrap();
    assert_eq!(recorded.deployment.exit().sim.plan(), Some(&smarty_plan()));
    assert_eq!(store.load().unwrap(), recorded);
}

#[test]
fn the_first_write_backs_up_the_original_then_writes_the_newest_version() {
    let (_dir, store) = store_holding(V1);
    let lifted = store.load().unwrap();
    let next = store
        .update_config(lifted.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();

    let backup = store.backup_path(1, 2);
    assert_eq!(backup.file_name().unwrap(), "state.json.bak-1-2");
    assert_eq!(
        fs::read(&backup).unwrap(),
        V1,
        "the backup is the original document"
    );
    assert_eq!(mode_of(&backup), 0o600);
    assert!(!temp_path(&backup).exists());

    // state.json is now version 2.
    let written = parse(&state_bytes(&store)).unwrap();
    assert_eq!(written, StateFile::V2(next.clone()));
    assert_eq!(Store::new(store.dir()).load().unwrap(), next);

    // Later writes start from version 2 and leave the backup alone.
    store
        .update_config(next.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();
    assert_eq!(fs::read(&backup).unwrap(), V1);
    assert!(!store.backup_path(2, 2).exists());
}

#[test]
fn every_kind_of_write_backs_up_first() {
    let backed_up = |store: &Store, original: &[u8]| {
        assert_eq!(fs::read(store.backup_path(1, 2)).unwrap(), original);
        assert_eq!(parse(&state_bytes(store)).unwrap().version(), 2);
    };

    let (_dir, store) = store_holding(V1);
    let state = store.load().unwrap();
    store
        .set_exit_enabled(state.runtime.revision, false)
        .unwrap();
    backed_up(&store, V1);

    // lon1 in the every-variant golden has a target, so it can record an
    // apply of the current generation.
    let with_stop = v1_every_variant_with_stop();
    let (_dir, store) = store_holding(with_stop.as_bytes());
    let generation = store.load().unwrap().deployment.config_generation();
    store
        .record(generation, applied_record("lon1", generation))
        .unwrap();
    backed_up(&store, with_stop.as_bytes());

    let (_dir, store) = store_holding(V1);
    let state = store.load().unwrap();
    let node = planned_node("ams1", 2, 20);
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
    backed_up(&store, V1);

    // The same golden with its user pending revocation, committed by lon1.
    let pending = String::from_utf8(V1.to_vec()).unwrap().replacen(
        "\"status\": \"active\"",
        "\"status\": \"revoke_pending\"",
        1,
    );
    let (_dir, store) = store_holding(pending.as_bytes());
    let state = store.load().unwrap();
    let mut secrets = InMemorySecretStore::new();
    for entry in entries_for(&state.deployment.required_secrets(), 1) {
        secrets.put(entry).unwrap();
    }
    let revoked = record_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        Bookkeeping::RevocationCommitted {
            user: UserId::from_low_bits(1),
            node: node_id("lon1"),
        },
    )
    .unwrap();
    assert_eq!(secrets.refs(), revoked.deployment.required_secrets());
    backed_up(&store, pending.as_bytes());
}

#[test]
fn the_backup_is_durable_before_the_state_is_written() {
    let (_dir, store) = store_holding(V1);
    let state = store.load().unwrap();
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
    assert_eq!(fs::read(store.backup_path(1, 2)).unwrap(), V1);
    assert_eq!(state_bytes(&store), V1, "the state was not written");
}

#[test]
fn a_backup_left_by_an_interrupted_migration_is_replaced() {
    let (_dir, store) = store_holding(V1);
    let state = store.load().unwrap();
    // An earlier attempt backed up a document that was never migrated.
    fs::write(store.backup_path(1, 2), b"an older version 1 document").unwrap();
    store
        .update_config(state.deployment.config_generation(), Ok::<_, Infallible>)
        .unwrap();
    assert_eq!(fs::read(store.backup_path(1, 2)).unwrap(), V1);
}

#[test]
fn a_newer_document_is_refused() {
    let (_dir, store) = store_holding(br#"{"version": 3}"#);
    let error = store.load().unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::DowngradeRefused {
                found: 3,
                newest: 2
            }
        ),
        "{error:?}"
    );
}

/// A version-1 policy without a hard stop does not lift: version 2 needs an
/// explicit stop policy. Every operation refuses with `MigrationFailed`,
/// and the document stays exactly as it was, with no backup.
#[test]
fn a_document_the_chain_cannot_lift_is_refused_and_left_as_it_is() {
    let (_dir, store) = store_holding(V1_EVERY_VARIANT);
    let unchosen = |error: &StoreError| {
        matches!(
            error,
            StoreError::MigrationFailed {
                from: 1,
                to: 2,
                source: ModelError::StopPolicyUnchosen
            }
        )
    };
    let error = store.load().unwrap_err();
    assert!(unchosen(&error), "{error:?}");
    assert_eq!(error.kind(), StoreErrorKind::MigrationFailed);
    assert_eq!(
        error.to_string(),
        "migrating the state from version 1 to 2 failed"
    );
    let generation = ConfigGeneration::new(2).unwrap();
    let errors = [
        store_error(
            store
                .update_config(generation, Ok::<_, Infallible>)
                .unwrap_err(),
        ),
        store
            .record(generation, applied_record("lon1", generation))
            .unwrap_err(),
        store
            .set_exit_enabled(RuntimeRevision::INITIAL, true)
            .unwrap_err(),
        record_with_secrets(
            &store,
            &mut InMemorySecretStore::new(),
            generation,
            applied_record("lon1", generation),
        )
        .unwrap_err(),
    ];
    for error in &errors {
        assert!(unchosen(error), "{error:?}");
    }
    assert_eq!(state_bytes(&store), V1_EVERY_VARIANT);
    assert!(!store.backup_path(1, 2).exists());
}

/// Every explicit version-1 hard stop lifts as it is, at any value: with
/// the plan unrecorded there is no line to check it against, and the stop
/// is the one the operator wrote. The operator then records the plan.
#[test]
fn every_explicit_version_one_stop_lifts_unchanged() {
    let text = String::from_utf8(V1.to_vec()).unwrap();
    for stop in [V1_GOLDEN_HARD_STOP_BYTES + 1, 644_245_094_400, u64::MAX] {
        let edited = text.replacen(
            "\"hard_stop_bytes\": 560000000000",
            &format!("\"hard_stop_bytes\": {stop}"),
            1,
        );
        assert_ne!(edited, text);
        let (_dir, store) = store_holding(edited.as_bytes());
        let lifted = store.load().unwrap();
        let sim = &lifted.deployment.exit().sim;
        assert_eq!(sim.plan(), None);
        assert_eq!(sim.warn_bytes(), V1_GOLDEN_WARN_BYTES);
        assert_eq!(sim.stop(), StopPolicy::HardStop { bytes: stop });
        // The first write backs the document up and keeps the stop.
        let next = store
            .update_config(lifted.deployment.config_generation(), Ok::<_, Infallible>)
            .unwrap();
        assert_eq!(
            fs::read(store.backup_path(1, 2)).unwrap(),
            edited.as_bytes()
        );
        assert_eq!(
            next.deployment.exit().sim.stop(),
            StopPolicy::HardStop { bytes: stop }
        );
        assert_eq!(Store::new(store.dir()).load().unwrap(), next);
    }
}

/// The version-1 golden still decodes with version 1's schema and
/// re-encodes to the same bytes, so the version-1 format stays pinned. It
/// lifts to exactly the version-2 golden, which with the plan recorded is
/// the same history built through the version-2 API.
#[test]
fn the_version_one_golden_decodes_and_lifts_to_the_version_two_golden() {
    let file = parse(V1).unwrap();
    assert_eq!(file.version(), 1);
    assert_eq!(pretty(&file), V1, "version 1 round-trips byte for byte");
    let (_dir, _store, expected) = built_history();
    let lifted = migrate(file).unwrap();
    assert_eq!(
        String::from_utf8(pretty(&StateFile::V2(lifted.clone()))).unwrap(),
        String::from_utf8(V2.to_vec()).unwrap()
    );
    assert_eq!(lifted.deployment.capacity(), CapacityPolicy::UNLIMITED);
    assert_eq!(lifted.deployment.auto_quota(), None);
    assert_eq!(lifted.deployment.alerting(), None);
    assert!(lifted.deployment.viewers().is_empty());
    assert_eq!(with_plan_recorded(lifted), expected);
}

/// The version-2 golden pins the on-disk format: a model change that alters
/// it must come with a new version and a migration step. The store writes
/// it byte for byte: [`V1`] with the exit still disabled, lifted, then
/// enabled, is exactly the golden.
#[test]
fn the_version_two_golden_round_trips() {
    let disabled = String::from_utf8(V1.to_vec()).unwrap().replacen(
        "\"exit_enabled\": true,\n    \"revision\": 2",
        "\"exit_enabled\": false,\n    \"revision\": 1",
        1,
    );
    assert_ne!(disabled.as_bytes(), V1);
    let (dir, store) = store_holding(disabled.as_bytes());
    let state = store.load().unwrap();
    let expected = store
        .set_exit_enabled(state.runtime.revision, true)
        .unwrap();
    assert_eq!(
        String::from_utf8(state_bytes(&store)).unwrap(),
        String::from_utf8(V2.to_vec()).unwrap(),
        "the store writes exactly the golden document"
    );
    assert_eq!(expected, lifted_golden());
    fs::write(store.state_path(), V2).unwrap();
    assert_eq!(Store::new(dir.path()).load().unwrap(), expected);
    assert_eq!(parse(V2).unwrap(), StateFile::V2(expected.clone()));
    assert_eq!(pretty(&parse(V2).unwrap()), V2, "byte for byte");
    assert_eq!(migrate(parse(V2).unwrap()).unwrap(), expected);
}

/// The nodes, users and exit of the version-1 every-variant golden, in
/// version-2 terms with `sim` as the SIM policy: an adopted node with a
/// target and two Hysteria2 listeners, a retiring node, a node pending
/// provider deletion and a retired one; an active user with a capability,
/// one pending revocation and a revoked one; a `Separate` uplink selected by
/// its gateway and an unpaired carrier check.
fn v1_variants(parts: DeploymentParts, sim: SimPolicy) -> DeploymentParts {
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
    exit.sim = sim;
    let mut policy = parts.policy;
    policy.block_quic = false;
    policy.camo_forward = false;
    DeploymentParts {
        config_generation: parts.config_generation,
        exit,
        policy,
        capacity: parts.capacity,
        auto_quota: parts.auto_quota,
        alerting: parts.alerting,
        viewers: parts.viewers,
        nodes: vec![lon1, ams1, par1, fra1],
        users: vec![active, pending, revoked],
        next_wg_index: WgIndex::new(5).unwrap(),
    }
}

/// lon1's confirmation of the first generation, which makes it the
/// goldens' applied node; only a record can set it.
fn lon1_applied() -> Bookkeeping {
    Bookkeeping::Applied {
        node: node_id("lon1"),
        applied: AppliedConfig {
            config_generation: ConfigGeneration::INITIAL,
            digest: Sha256Digest::from_bytes([0xd1; 32]),
        },
    }
}

/// Builds `change` on a fresh store, writing the secrets it references,
/// then records lon1's apply; returns the store and the final state.
fn built(change: impl Fn(DeploymentParts) -> DeploymentParts) -> (TempDir, Store, StateV2) {
    let (dir, store, state) = initialised();
    let refs = added_refs(&state.deployment, &change);
    let mut secrets = InMemorySecretStore::new();
    let changed = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&refs, 3),
        |parts| Ok::<_, Infallible>(change(parts)),
    )
    .unwrap();
    let expected = store
        .record(changed.deployment.config_generation(), lon1_applied())
        .unwrap();
    (dir, store, expected)
}

/// The version-1 every-variant golden still decodes with version 1's
/// schema and re-encodes to the same bytes. Its SIM policy has no hard
/// stop, so it does not lift; given one, it lifts to the same variants
/// built through the version-2 API, once the plan is recorded.
#[test]
fn the_version_one_every_variant_golden_decodes_but_needs_a_stop_policy() {
    let file = parse(V1_EVERY_VARIANT).unwrap();
    assert_eq!(file.version(), 1);
    assert_eq!(
        pretty(&file),
        V1_EVERY_VARIANT,
        "version 1 round-trips byte for byte"
    );
    assert!(matches!(
        migrate(file),
        Err(StoreError::MigrationFailed {
            from: 1,
            to: 2,
            source: ModelError::StopPolicyUnchosen
        })
    ));

    let with_stop = v1_every_variant_with_stop();
    let sim = SimPolicy::new(
        CycleRule::Monthly {
            bill_day: BillDay::new(15).unwrap(),
        },
        smarty_plan(),
        1_000_000,
        StopPolicy::HardStop { bytes: 2_000_000 },
    )
    .unwrap();
    let (_dir, _store, expected) = built(|parts| v1_variants(parts, sim.clone()));
    let lifted = migrate(parse(with_stop.as_bytes()).unwrap()).unwrap();
    assert_eq!(with_plan_recorded(lifted), expected);
}

/// A suspended user holding credentials on lon1 and ams1 with short id
/// byte `n`.
fn suspended(n: u8, reason: SuspendReason) -> User {
    let mut user = user(u64::from(n), &[("lon1", n), ("ams1", n)]);
    user.status = UserStatus::Suspended {
        reason,
        since: UnixTime::from_secs(1_791_417_600 + u64::from(n)),
    };
    user
}

/// Every version-2 variant one document can hold, on top of the version-1
/// variants: the decided 1pMobile plan with its rolling fair-use line,
/// 30-day cycles and the pilot's hard stop; an uplink baseline; the pilot's cap on active users,
/// its automatic quotas and its alert channels, set up for lon1; a viewer;
/// a user with every policy, an alias and an agreement; users suspended for
/// every reason, with and without a policy, alias or agreement. (The
/// unrecorded plan is in `state-v2.json`. One document holds one plan, so
/// `mooring-model`'s `sim` tests pin the encodings of a fair-use line,
/// `AcceptDeprioritisation`, a speed cap and a capped plan exactly.)
fn v2_variants(parts: DeploymentParts) -> DeploymentParts {
    let date = |text: &str| CalendarDate::parse(text).unwrap();
    let sim = SimPolicy::new(
        CycleRule::FixedDays {
            days: PeriodDays::new(30).unwrap(),
            anchor: date("2026-10-28"),
        },
        SimPlan::one_p_mobile_unlimited().unwrap(),
        PILOT_SIM_WARN_BYTES,
        StopPolicy::HardStop {
            bytes: PILOT_SIM_HARD_STOP_BYTES,
        },
    )
    .unwrap();
    let mut parts = v1_variants(parts, sim);
    parts.exit.uplink_baseline = Some(
        UplinkBaseline::new(5_000_000, 16_000_000, UnixTime::from_secs(1_791_331_200)).unwrap(),
    );
    parts.capacity = CapacityPolicy::PILOT;
    parts.auto_quota = Some(AutoQuotaPolicy::PILOT);
    let mut alerting = AlertSettings::pilot();
    alerting.channels.insert(node_id("lon1"));
    parts.alerting = Some(alerting);
    parts.viewers = vec![Viewer {
        key: Ed25519Pub::from_bytes(*b"mooring-golden-viewer-key-000001").unwrap(),
        label: LocalLabel::parse("phone").unwrap(),
        added_on: date("2026-10-08"),
    }];
    let active = &mut parts.users[0];
    active.policy = UserPolicy {
        expires_at: Some(UnixTime::from_secs(1_798_761_600)),
        quota: Some(UserQuota {
            cycle_served_bytes: NonZeroU64::new(40_000_000_000).unwrap(),
            warn_percent: WarnPercent::new(80).unwrap(),
            action: QuotaAction::Warn,
        }),
    };
    active.alias = Some(PublicAlias::from_random_bytes([
        0x57, 0xe0, 0x36, 0x6a, 0xe0,
    ]));
    active.agreement = Some(AgreementRecord {
        version: AgreementVersion::new(NonZeroU16::new(1).unwrap()),
        accepted_on: date("2026-10-08"),
    });
    let mut by_operator = suspended(4, SuspendReason::Operator);
    by_operator.alias = Some(PublicAlias::from_random_bytes([
        0xd0, 0x78, 0x3f, 0xde, 0x00,
    ]));
    let mut over_quota = suspended(
        5,
        SuspendReason::QuotaExceeded {
            // Bill day 31 starts the September cycle on the 30th.
            cycle_start: date("2026-09-30"),
        },
    );
    over_quota.policy.quota = Some(UserQuota {
        cycle_served_bytes: NonZeroU64::new(20_000_000_000).unwrap(),
        warn_percent: WarnPercent::new(90).unwrap(),
        action: QuotaAction::Suspend,
    });
    over_quota.agreement = Some(AgreementRecord {
        version: AgreementVersion::new(NonZeroU16::new(2).unwrap()),
        accepted_on: date("2026-09-01"),
    });
    let mut expired = suspended(6, SuspendReason::Expired);
    expired.policy.expires_at = Some(UnixTime::from_secs(1_791_331_200));
    let abuse = suspended(7, SuspendReason::AbuseReview);
    parts
        .users
        .extend([by_operator, over_quota, expired, abuse]);
    parts
}

/// The second version-2 golden pins the encoding of every persisted
/// variant the first leaves out (`state-v2-every-variant.json`): a model
/// change to any of them needs a new version and a migration step.
#[test]
fn the_version_two_every_variant_golden_round_trips() {
    let (dir, store, expected) = built(v2_variants);
    assert_eq!(
        String::from_utf8(state_bytes(&store)).unwrap(),
        String::from_utf8(V2_EVERY_VARIANT.to_vec()).unwrap(),
        "the store writes exactly the golden document"
    );
    // Suspended users keep their credentials, so their secrets stay referenced.
    let user7 = UserId::from_low_bits(7);
    assert!(
        expected
            .deployment
            .required_secrets()
            .contains(&SecretRef::UserVlessUuid(user7.clone(), node_id("lon1")))
    );
    assert_eq!(
        expected.deployment.served_users(&node_id("lon1")).count(),
        1
    );
    fs::write(store.state_path(), V2_EVERY_VARIANT).unwrap();
    assert_eq!(Store::new(dir.path()).load().unwrap(), expected);
    assert_eq!(
        parse(V2_EVERY_VARIANT).unwrap(),
        StateFile::V2(expected.clone())
    );
}

/// Every JSON object of both version-2 goldens refuses an unknown key, as
/// each type's `deny_unknown_fields` promises (the every-variant golden
/// holds an object of every version-2 record: plans, policies, quotas,
/// agreements, the cap, the baseline, automatic quotas, alert settings and
/// viewers). A field this build does not know is never dropped silently.
#[test]
fn every_object_of_the_version_two_goldens_denies_unknown_keys() {
    for golden in [V2, V2_EVERY_VARIANT] {
        let json: serde_json::Value = serde_json::from_slice(golden).unwrap();
        assert!(parse(golden).is_ok());
        let mut pointers = Vec::new();
        object_pointers(&json, String::new(), &mut pointers);
        assert!(pointers.len() > 20, "{} objects", pointers.len());
        for pointer in &pointers {
            let mut mutated = json.clone();
            mutated
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("zz_unknown".into(), serde_json::Value::Bool(true));
            assert!(
                parse(&serde_json::to_vec(&mutated).unwrap()).is_err(),
                "accepted an unknown key at {pointer:?}"
            );
        }
    }
}

/// The JSON pointer of every object in `value`.
fn object_pointers(value: &serde_json::Value, pointer: String, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            out.push(pointer.clone());
            for (key, child) in map {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                object_pointers(child, format!("{pointer}/{escaped}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                object_pointers(child, format!("{pointer}/{index}"), out);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}
