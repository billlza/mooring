// SPDX-License-Identifier: GPL-3.0-or-later

//! Pruning before staging (design §11.2 step 4): the current generation
//! and the two newest before it kept, with the engine artifacts they use,
//! and nothing to prune on a layout without an engine store; and what the
//! pruning cannot read, which fails the change before anything is staged.

use std::fs;

use mooring_agent_proto::{AgentError, Generation, IoOp, ManagedFile, TxnState};

use super::world::{World, assert_unswitched, idle, same};
use crate::tests::{EISDIR, ENOTDIR};
use crate::txn::record::pending;
use crate::txn::{self, Launched};

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

/// The pruning reads every generation it keeps, to keep the engines they
/// use: an older kept generation whose header cannot be read fails the
/// change before anything is staged, rather than prune what it may use.
#[test]
fn a_kept_generation_whose_header_cannot_be_read_fails_the_pruning() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    world.commit(&world.node(2000), world.bundle(2, idle(301)));
    world.commit(&world.node(3000), world.bundle(3, idle(302)));
    let header = world
        .paths
        .generation(Generation::new(1))
        .join(txn::stage::BUNDLE_FILE);
    fs::remove_file(&header).unwrap();
    fs::create_dir(&header).unwrap();
    world.apply_and_run(&world.node(4000), world.bundle(4, idle(303)));
    assert_unswitched(
        &world,
        4,
        Some("gen-3"),
        AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(EISDIR),
        },
    );
    assert!(world.paths.engine_store().is_dir());
}

#[test]
fn two_previous_generations_and_their_engines_are_kept() {
    let world = World::new();
    let old_xray = world.put(b"an older xray binary");
    for generation in 1..=5 {
        let node = world.node(1000 * generation);
        let mut header = world.bundle(generation, move |file, text| {
            if file == ManagedFile::WatchConfig {
                format!("{text} ") + &"x".repeat(generation as usize)
            } else {
                text
            }
        });
        if generation == 1 {
            header.engines.xray = old_xray;
        }
        world.commit(&node, header);
    }
    let kept: Vec<bool> = (1..=5)
        .map(|generation| world.paths.generation(Generation::new(generation)).exists())
        .collect();
    assert_eq!(
        kept,
        vec![false, true, true, true, true],
        "pruned before staging gen 5: gen 1 only"
    );
    assert_eq!(
        fs::read_dir(world.paths.engine_store()).unwrap().count(),
        4,
        "generation 1's own xray went with it"
    );
    assert!(
        !world
            .paths
            .engine_store()
            .join(old_xray.to_string())
            .exists()
    );
}
