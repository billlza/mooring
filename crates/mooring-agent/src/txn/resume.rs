// SPDX-License-Identifier: GPL-3.0-or-later

//! `Resume` (design §11.3): only an explicit request on the current
//! generation clears the halt marker; the engines are then started and the
//! local health gate must pass.

use mooring_agent_proto::{AgentError, EngineUser, Generation, SystemdOp};

use super::{exclusive, health};
use crate::gate::{self, engine_unit};
use crate::host::{Node, Tool, run_ok};
use crate::paths::Paths;

/// Resumes a halted node on `config_generation`, which must be current.
pub(crate) fn resume(
    paths: &Paths,
    node: &dyn Node,
    config_generation: Generation,
) -> Result<Generation, AgentError> {
    let _lock = exclusive(paths)?;
    if gate::halted(paths)?.is_none() {
        return Err(AgentError::NotHalted);
    }
    let current = gate::current_generation(paths)?;
    if current != config_generation {
        return Err(AgentError::GenerationMismatch { current });
    }
    crate::store::remove(&paths.halted())?;
    for engine in [EngineUser::Xray, EngineUser::Hy2] {
        let unit = engine_unit(engine)?;
        if run_ok(node, Tool::Systemctl, &["start", unit.as_str()])?.is_err() {
            return Err(AgentError::Systemd {
                unit,
                op: SystemdOp::Start,
            });
        }
    }
    health::wait(paths, node, &paths.generation(current), health::BUDGET)
        .map_err(|failed| AgentError::HealthGate { failed })?;
    Ok(current)
}
