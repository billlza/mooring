// SPDX-License-Identifier: GPL-3.0-or-later

//! `ActivateAgent` (design §11.2): each way installing and switching to a
//! new agent can fail, leaving the forced command on the agent it had.

use std::fs;
use std::path::Path;

use mooring_agent_proto::{AgentError, Generation, IoOp, Sha256Hex};

use super::world::World;
use crate::tests::{EACCES, EEXIST, EISDIR, ENOENT, ENOTDIR, ModeFault, occupy_temporary};
use crate::txn::activate::{activate, install};
use crate::txn::record::{Change, Phase, pending};
use crate::txn::{self, Why};

/// A node whose forced command runs `old-agent`, with a new agent stored.
fn with_new_agent() -> (World, Sha256Hex) {
    let world = World::new();
    fs::create_dir_all(world.paths.agent_dir()).unwrap();
    std::os::unix::fs::symlink("old-agent", world.paths.agent_current()).unwrap();
    let sha = world.put(b"new agent binary");
    (world, sha)
}

/// The forced command still runs the agent it had, and nothing is pending.
fn assert_unswitched(world: &World) {
    assert_eq!(
        fs::read_link(world.paths.agent_current()).unwrap(),
        Path::new("old-agent")
    );
    assert_eq!(pending(&world.paths).unwrap(), None);
}

#[test]
fn an_agent_whose_self_test_cannot_be_started_is_not_activated() {
    let (world, sha) = with_new_agent();
    world.faults.borrow_mut().unstartable_programs = true;
    let node = world.node(1000);
    assert_eq!(
        activate(&world.paths, &node, sha),
        Err(AgentError::Io {
            op: IoOp::SpawnProcess,
            errno: Some(ENOENT),
        })
    );
    assert_unswitched(&world);
    assert!(
        !node.calls().iter().any(|call| call.contains("--on-active")),
        "no timer: {:#?}",
        node.calls()
    );
}

/// An installed copy is checked before it is trusted; one that cannot be
/// read is the activation's error, never a copy made over it blindly.
#[test]
fn an_installed_copy_that_cannot_be_read_fails_the_activation() {
    let (world, sha) = with_new_agent();
    let installed = world.paths.agent_dir().join(sha.to_string());
    fs::create_dir(&installed).unwrap();
    assert_eq!(
        activate(&world.paths, &world.node(1000), sha),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(EISDIR),
        })
    );
    assert_unswitched(&world);
    fs::remove_dir(&installed).unwrap();
    fs::write(&installed, "a copy no one may read").unwrap();
    let fault = ModeFault::set(&installed, 0o000);
    assert_eq!(
        activate(&world.paths, &world.node(1000), sha),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(EACCES),
        })
    );
    drop(fault);
    assert_unswitched(&world);
}

/// What installing an agent reports: the copy it cannot write, the source
/// it cannot read, the directory it cannot make, and a copy it cannot
/// check.
#[test]
fn an_agent_that_cannot_be_installed_says_why() {
    let (world, sha) = with_new_agent();
    let source = world.paths.blob(&sha);
    occupy_temporary(&world.paths.agent_dir().join(sha.to_string()));
    assert_eq!(
        install(&world.paths, &sha, &source),
        Err(AgentError::Io {
            op: IoOp::WriteBlob,
            errno: Some(EEXIST),
        })
    );
    assert_eq!(
        install(&world.paths, &sha, &world.paths.at("/absent")),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(ENOENT),
        })
    );
    let agents = world.paths.agent_dir();
    fs::remove_dir_all(&agents).unwrap();
    let fault = ModeFault::set(agents.parent().unwrap(), 0o555);
    assert_eq!(
        install(&world.paths, &sha, &source),
        Err(AgentError::Io {
            op: IoOp::WriteBlob,
            errno: Some(EACCES),
        })
    );
    drop(fault);
    // A file where the agents' directory goes: no copy there can be read.
    fs::write(&agents, "").unwrap();
    assert_eq!(
        install(&world.paths, &sha, &source),
        Err(AgentError::Io {
            op: IoOp::ReadBlob,
            errno: Some(ENOTDIR),
        })
    );
}

/// A revert that cannot put the forced command back says so, and leaves
/// the activation pending with its timer armed, so that a retried
/// `Rollback` or the timer still puts it back.
#[test]
fn an_activation_whose_link_cannot_be_put_back_stays_pending() {
    let (world, sha) = with_new_agent();
    assert_eq!(
        activate(&world.paths, &world.node(1000), sha),
        Ok(Generation::ZERO)
    );
    let fault = ModeFault::set(&world.paths.agent_dir(), 0o555);
    let node = world.node(1050);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EACCES),
        })
    );
    drop(fault);
    assert_eq!(
        fs::read_link(world.paths.agent_current()).unwrap(),
        Path::new(&sha.to_string())
    );
    assert!(matches!(
        pending(&world.paths).unwrap().map(|pending| pending.change),
        Some(Change::Activate { .. })
    ));
    assert!(
        !node
            .calls()
            .iter()
            .any(|call| call.contains("systemctl stop")),
        "the timer stays armed: {:#?}",
        node.calls()
    );
    let node = world.node(1060);
    assert_eq!(
        txn::revert_pending(&world.paths, &node, Why::Requested),
        Ok(Generation::ZERO)
    );
    assert_unswitched(&world);
}

/// A switch to the new agent that fails after its rename (the directory
/// cannot be synced) has switched: the activation stays pending with its
/// timer armed, which puts the previous agent back unless it is confirmed.
#[test]
fn an_activation_whose_switch_fails_after_its_rename_keeps_its_timer() {
    let (world, sha) = with_new_agent();
    // Installed once, so that installing it again writes nothing.
    activate(&world.paths, &world.node(1000), sha).unwrap();
    txn::revert_pending(&world.paths, &world.node(1010), Why::Requested).unwrap();
    let fault = ModeFault::set(&world.paths.agent_dir(), 0o300);
    let node = world.node(1050);
    assert_eq!(
        activate(&world.paths, &node, sha),
        Err(AgentError::Io {
            op: IoOp::WriteState,
            errno: Some(EACCES),
        })
    );
    drop(fault);
    assert_eq!(
        fs::read_link(world.paths.agent_current()).unwrap(),
        Path::new(&sha.to_string())
    );
    assert_eq!(
        pending(&world.paths).unwrap().map(|pending| pending.phase),
        Some(Phase::AwaitingConfirm)
    );
    assert!(
        !node
            .calls()
            .iter()
            .any(|call| call.contains("systemctl stop")),
        "{:#?}",
        node.calls()
    );
    assert_eq!(
        txn::revert_pending(
            &world.paths,
            &world.node(1170),
            Why::Unconfirmed(Generation::ZERO)
        ),
        Ok(Generation::ZERO)
    );
    assert_unswitched(&world);
}
