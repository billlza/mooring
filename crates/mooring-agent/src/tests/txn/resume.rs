// SPDX-License-Identifier: GPL-3.0-or-later

//! `Resume` (design §11.3): only a halted node, and only for its current
//! generation, has its halt marker cleared and its engines started; an
//! engine that cannot be started, or a unit that does not come up within
//! the health gate's budget, is the request's error.

use mooring_agent_proto::{AgentError, Generation, HealthCheck, ShutdownReason};

use super::world::{World, index_of, same};
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
    index_of(&node.calls(), "systemctl start mooring-xray.service");
    index_of(&node.calls(), "systemctl start mooring-hy2.service");
    world.faults.borrow_mut().restart = true;
    crate::gate::shutdown(&world.paths, &node, ShutdownReason::Operator).unwrap();
    let refused = txn::resume::resume(&world.paths, &world.node(3000), Generation::new(1));
    assert!(
        matches!(refused, Err(AgentError::Systemd { .. })),
        "{refused:?}"
    );
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
