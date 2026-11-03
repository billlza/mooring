// SPDX-License-Identifier: GPL-3.0-or-later

//! The confirm timer (design §11.2 step 7): a transient systemd timer that
//! runs `txn-revert <N>` unless the change under `N` is confirmed within
//! [`CONFIRM_SECS`]. A transaction arms it before its swap and an
//! activation before its switch, so that nothing is switched without it. A
//! change that ends stops it last, if it is still armed: not fired, and not
//! lost to a reboot.

use std::path::Path;

use mooring_agent_proto::{AgentError, Generation, SystemdOp, UnitName};

use crate::host::{Node, Tool, run_ok};

/// The confirm window (design §11.2 step 7).
const CONFIRM_SECS: u64 = 120;

/// Arms the timer that reverts the change under `generation` unless it is
/// confirmed within [`CONFIRM_SECS`], run by `agent`.
pub(super) fn arm_revert(
    node: &dyn Node,
    generation: Generation,
    agent: &Path,
) -> Result<(), AgentError> {
    let timer = UnitName::confirm_timer(generation);
    let unit_arg = format!("--unit={}", timer.stem());
    let delay = format!("--on-active={CONFIRM_SECS}");
    let generation_arg = generation.get().to_string();
    let agent = agent.display().to_string();
    match run_ok(
        node,
        Tool::SystemdRun,
        &[
            &unit_arg,
            &delay,
            "--collect",
            "--quiet",
            &agent,
            "txn-revert",
            &generation_arg,
        ],
    )? {
        Ok(_) => Ok(()),
        Err(_) => Err(AgentError::Systemd {
            unit: timer,
            op: SystemdOp::Run,
        }),
    }
}

/// Stops the revert timer of `generation`.
pub(super) fn disarm_revert(node: &dyn Node, generation: Generation) -> Result<(), AgentError> {
    let timer = UnitName::confirm_timer(generation);
    match run_ok(node, Tool::Systemctl, &["stop", timer.as_str()])? {
        Ok(_) => Ok(()),
        Err(_) => Err(AgentError::Systemd {
            unit: timer,
            op: SystemdOp::Stop,
        }),
    }
}
