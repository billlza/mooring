// SPDX-License-Identifier: GPL-3.0-or-later

//! Staging (design §11.2 step 2): a directory an earlier attempt left
//! replaced, each configuration in its reader's group and no one else's,
//! and each way staging fails, named by its error, with nothing switched;
//! and the previous generation's header, which the change reads before its
//! swap.

use std::fs;

use mooring_agent_proto::{AgentError, Generation, IoOp, ManagedFile, TxnState};

use super::world::{World, assert_unswitched, idle, same};
use crate::tests::{EACCES, EEXIST, EISDIR, ENOENT, ENOTDIR, EPERM, ModeFault, own_ids};
use crate::txn::stage::{XRAY, copy_blob, store_path};
use crate::txn::{self, Launched};

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

/// What the change changes is read from the previous generation before the
/// swap: a previous header that cannot be read fails the change with
/// nothing switched, no timer armed and nothing restarted.
#[test]
fn a_previous_header_that_cannot_be_read_fails_the_change_before_the_swap() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    let node = world.node(2000);
    assert_eq!(
        txn::apply(&world.paths, &node, world.bundle(2, idle(301))),
        Ok(Launched::Launched(Generation::new(2)))
    );
    let header = world
        .paths
        .generation(Generation::new(1))
        .join(txn::stage::BUNDLE_FILE);
    fs::remove_file(&header).unwrap();
    fs::create_dir(&header).unwrap();
    txn::run(&world.paths, &node, Generation::new(2)).unwrap();
    assert_unswitched(
        &world,
        2,
        Some("gen-1"),
        AgentError::Io {
            op: IoOp::ReadState,
            errno: Some(EISDIR),
        },
    );
    let calls = node.calls();
    assert!(
        !calls
            .iter()
            .any(|call| call.contains("--on-active") || call.contains("restart")),
        "{calls:#?}"
    );
}

/// A configuration that cannot be given its reader's group fails the
/// staging: here the engine's group is one this user is not in, which a
/// user other than root may not give a file (root may give any).
#[test]
fn a_configuration_that_cannot_be_given_its_readers_group_fails_the_staging() {
    let world = World::new();
    let (uid, gid) = own_ids(&world.paths);
    assert_ne!(
        uid, 0,
        "needs a user other than root: root may give any group"
    );
    let group = world.paths.group();
    let text = fs::read_to_string(&group).unwrap();
    let foreign = text.replace(
        &format!("mooring-xray:x:{gid}:"),
        "mooring-xray:x:4000000000:",
    );
    assert_ne!(foreign, text);
    fs::write(&group, foreign).unwrap();
    world.apply_and_run(&world.node(1000), world.bundle(1, same));
    assert_unswitched(
        &world,
        1,
        None,
        AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EPERM),
        },
    );
}

#[test]
fn a_missing_engine_group_fails_the_stage_with_its_account() {
    let world = World::new();
    let group = fs::read_to_string(world.paths.group()).unwrap();
    let kept: String = group
        .lines()
        .filter(|line| !line.starts_with("mooring-xray:"))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(world.paths.group(), kept).unwrap();
    assert_eq!(
        world.apply_and_run(&world.node(1000), world.bundle(1, same)),
        TxnState::Failed {
            error: AgentError::AccountMissing {
                account: mooring_agent_proto::HostAccount::Xray,
            }
        }
    );
}

/// The groups the tests' user is in besides its primary one.
fn other_groups(primary: u32) -> Vec<u32> {
    let output = std::process::Command::new("id").arg("-G").output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|gid| gid.parse().unwrap())
        .filter(|gid| *gid != primary)
        .collect()
}

#[test]
fn each_configuration_belongs_to_its_readers_group_and_no_one_elses() {
    use std::os::unix::fs::MetadataExt;
    let world = World::new();
    let (_, primary) = own_ids(&world.paths);
    let others = other_groups(primary);
    let [xray, hy2, state, ..] = others.as_slice() else {
        panic!("this test needs a user in three groups besides its own: {others:?}");
    };
    fs::write(
        world.paths.group(),
        format!(
            "root:x:{primary}:\nmooring:x:{state}:\nmooring-xray:x:{xray}:\nmooring-hy2:x:{hy2}:\n"
        ),
    )
    .unwrap();
    let dir = txn::stage::stage(&world.paths, Generation::new(1), &world.bundle(1, same)).unwrap();
    let owner = |file: ManagedFile| {
        let meta = fs::metadata(dir.join(file.file_name())).unwrap();
        (meta.gid(), meta.mode() & 0o777)
    };
    assert_eq!(owner(ManagedFile::XrayConfig), (*xray, 0o640));
    assert_eq!(owner(ManagedFile::Hy2Config), (*hy2, 0o640));
    assert_eq!(owner(ManagedFile::WatchConfig), (*state, 0o640));
    assert_eq!(owner(ManagedFile::WgConf), (primary, 0o600));
    assert_eq!(owner(ManagedFile::Nftables), (primary, 0o640));
    assert_eq!(owner(ManagedFile::ViewerKeys), (primary, 0o644));
}
