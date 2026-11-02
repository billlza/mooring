// SPDX-License-Identifier: GPL-3.0-or-later

//! Pruning and staging (design §11.2 steps 2 and 4): what each refuses,
//! with the error the transaction ends with, nothing switched.

use std::fs;

use mooring_agent_proto::{AgentError, Generation, IoOp, TxnState};

use super::world::{World, idle, same};
use crate::tests::{EACCES, EEXIST, EISDIR, ENOENT, ENOTDIR, ModeFault};
use crate::txn::record::pending;
use crate::txn::stage::{XRAY, copy_blob, store_path};
use crate::txn::{self, Launched};

/// The transaction ended with `error` before the swap: nothing switched,
/// nothing left staged or pending.
fn assert_unswitched(world: &World, generation: u64, current: Option<&str>, error: AgentError) {
    assert_eq!(world.state(generation), TxnState::Failed { error });
    assert_eq!(world.current().as_deref(), current);
    assert!(!world.paths.generation(Generation::new(generation)).is_dir());
    assert_eq!(pending(&world.paths).unwrap(), None);
}

#[test]
fn a_first_change_on_a_layout_without_an_engine_store_prunes_nothing() {
    let world = World::new();
    fs::create_dir_all(world.paths.etc()).unwrap();
    assert!(!world.paths.engine_store().exists());
    assert_eq!(
        world.apply_and_run(&world.node(1000), world.bundle(1, same)),
        TxnState::AwaitingConfirm
    );
}

/// `/etc/mooring` that cannot be listed (here a file, put there after the
/// `Apply` read `current` through it) fails the change at its pruning.
#[test]
fn generations_that_cannot_be_listed_fail_the_change_before_staging() {
    let world = World::new();
    let node = world.node(1000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(1, same)),
        Ok(Launched::Launched(Generation::new(1)))
    );
    fs::write(world.paths.etc(), "").unwrap();
    txn::run(&world.paths, &node, Generation::new(1)).unwrap();
    assert_eq!(
        world.state(1),
        TxnState::Failed {
            error: AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(ENOTDIR),
            }
        }
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
    assert!(
        !node.calls().iter().any(|call| call.contains("--on-active")),
        "no timer is armed for it"
    );
}

#[test]
fn an_engine_store_that_cannot_be_listed_fails_the_change_before_staging() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let store = world.paths.engine_store();
    fs::remove_dir_all(&store).unwrap();
    fs::write(&store, "").unwrap();
    world.apply_and_run(&world.node(2000), world.bundle(2, idle(301)));
    assert_unswitched(
        &world,
        2,
        Some("gen-1"),
        AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(ENOTDIR),
        },
    );
}

#[test]
fn a_directory_an_earlier_attempt_left_is_replaced() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let stray = world.paths.generation(Generation::new(2)).join("stray");
    fs::create_dir_all(stray.parent().unwrap()).unwrap();
    fs::write(&stray, "left by an attempt that died").unwrap();
    assert_eq!(
        world.apply_and_run(&world.node(2000), world.bundle(2, idle(301))),
        TxnState::AwaitingConfirm
    );
    assert!(!stray.exists());
}

#[test]
fn a_generation_that_cannot_be_staged_fails_the_change() {
    // A file where its directory goes cannot be removed as one.
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    fs::write(world.paths.generation(Generation::new(2)), "").unwrap();
    world.apply_and_run(&world.node(2000), world.bundle(2, idle(301)));
    assert_eq!(
        world.state(2),
        TxnState::Failed {
            error: AgentError::Io {
                op: IoOp::WriteState,
                errno: Some(ENOTDIR),
            }
        }
    );
    assert_eq!(world.current().as_deref(), Some("gen-1"));
    // A directory that cannot be written into: the generation is never
    // created.
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let fault = ModeFault::set(&world.paths.etc(), 0o555);
    world.apply_and_run(&world.node(2000), world.bundle(2, idle(301)));
    drop(fault);
    assert_unswitched(
        &world,
        2,
        Some("gen-1"),
        AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EACCES),
        },
    );
}

/// A stored artifact is checked before it is linked: one that cannot be
/// read fails the staging, named as a blob read.
#[test]
fn a_stored_artifact_that_cannot_be_read_fails_the_staging() {
    for (damage, errno) in [
        (
            (|stored: &std::path::Path| {
                fs::remove_file(stored).unwrap();
                fs::create_dir(stored).unwrap();
            }) as fn(&std::path::Path),
            EISDIR,
        ),
        (
            |stored: &std::path::Path| {
                let dir = stored.parent().unwrap();
                fs::remove_dir_all(dir).unwrap();
                fs::write(dir, "").unwrap();
            },
            ENOTDIR,
        ),
    ] {
        let world = World::new();
        world.commit(&world.node(1000), world.bundle(1, same));
        let next = world.bundle(2, idle(301));
        damage(&store_path(&world.paths, XRAY, &next.engines.xray));
        world.apply_and_run(&world.node(2000), next);
        assert_unswitched(
            &world,
            2,
            Some("gen-1"),
            AgentError::Io {
                op: IoOp::ReadBlob,
                errno: Some(errno),
            },
        );
    }
}

/// A new engine that cannot be put in the store fails the staging.
#[test]
fn an_engine_store_that_cannot_take_a_new_engine_fails_the_staging() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let mut next = world.bundle(2, idle(301));
    next.engines.xray = world.put(b"xray binary, a newer build");
    let fault = ModeFault::set(&world.paths.engine_store(), 0o555);
    world.apply_and_run(&world.node(2000), next);
    drop(fault);
    assert_unswitched(
        &world,
        2,
        Some("gen-1"),
        AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EACCES),
        },
    );
}

/// A blob copy names what failed: a blob that is gone is a blob read, and
/// a copy that cannot be written is a state write.
#[test]
fn a_blob_copy_says_what_failed() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("xray.json");
    assert_eq!(
        copy_blob(&dir.path().join("absent"), &target, 0o640),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(ENOENT),
        })
    );
    let blob = dir.path().join("blob");
    fs::write(&blob, "{}").unwrap();
    occupy_temporary_of_copy(&target);
    assert_eq!(
        copy_blob(&blob, &target, 0o640),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EEXIST),
        })
    );
    assert!(!target.exists());
}

/// Takes the temporary name a blob copy to `target` uses.
fn occupy_temporary_of_copy(target: &std::path::Path) {
    fs::create_dir(target.with_extension("staging")).unwrap();
}
