// SPDX-License-Identifier: GPL-3.0-or-later

//! `Resume` (design §11.3): only a halted node, and only for its current
//! generation, has its halt marker cleared and its engines restarted; an
//! engine that cannot be restarted, or a unit that does not come up within
//! the health gate's budget, is the request's error.

use mooring_agent_proto::{
    AgentError, EngineUser, Generation, HealthCheck, ShutdownReason, SystemdOp, UnitName,
};

use super::world::{World, index_of, same};
use super::xray_users::client;
use crate::txn;

#[test]
fn resume_restarts_the_current_generation_only_when_halted() {
    let world = World::new();
    let node = world.node(1000);
    world.commit(&node, world.bundle(1, same));
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(1)),
        Err(AgentError::NotHalted)
    );
    crate::gate::shutdown(&world.paths, &node, ShutdownReason::Operator).unwrap();
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(2)),
        Err(AgentError::GenerationMismatch {
            current: Generation::new(1)
        })
    );
    assert!(
        world.paths.halted().exists(),
        "a refused resume keeps the marker"
    );
    let node = world.node(2000);
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(1)),
        Ok(Generation::new(1))
    );
    assert!(!world.paths.halted().exists());
    index_of(&node.calls(), "systemctl restart mooring-xray.service");
    index_of(&node.calls(), "systemctl restart mooring-hy2.service");
    world.faults.borrow_mut().restart = true;
    crate::gate::shutdown(&world.paths, &node, ShutdownReason::Operator).unwrap();
    assert_eq!(
        txn::resume::resume(&world.paths, &world.node(3000), Generation::new(1)),
        Err(AgentError::Systemd {
            unit: UnitName::engine(EngineUser::Xray),
            op: SystemdOp::Restart,
        })
    );
}

/// An engine whose stop failed keeps running what it read at its start;
/// the resume's restart has it read the current generation.
#[test]
fn resume_has_an_engine_still_running_read_the_current_generation() {
    let world = World::new();
    world.commit(&world.node(1000), world.bundle(1, same));
    crate::gate::shutdown(&world.paths, &world.node(1500), ShutdownReason::Operator).unwrap();
    let held = |world: &World| world.faults.borrow().xray.held.borrow()["reality-in"].clone();
    let current = held(&world);
    world
        .faults
        .borrow()
        .xray
        .held
        .borrow_mut()
        .get_mut("reality-in")
        .unwrap()
        .push(client(9, "reality"));
    assert_eq!(
        txn::resume::resume(&world.paths, &world.node(2000), Generation::new(1)),
        Ok(Generation::new(1))
    );
    assert_eq!(held(&world), current);
}

#[test]
fn resume_reports_a_unit_that_does_not_come_up() {
    let world = World::new();
    let node = world.node(1000);
    world.commit(&node, world.bundle(1, same));
    crate::gate::shutdown(&world.paths, &node, ShutdownReason::Operator).unwrap();
    world.faults.borrow_mut().unit_failed = true;
    let node = world.node(2000);
    assert_eq!(
        txn::resume::resume(&world.paths, &node, Generation::new(1)),
        Err(AgentError::HealthGate {
            failed: HealthCheck::UnitsActive
        })
    );
    assert_eq!(node.slept(), 20);
}
