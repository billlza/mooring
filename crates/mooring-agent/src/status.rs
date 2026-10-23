// SPDX-License-Identifier: GPL-3.0-or-later

//! `Status` (design §11.1): the watch's view at its latest tick, with the
//! holds (read under `gate.lock`), the halt marker and the last committed
//! generation read when answering. Before the watch's first tick there is
//! no view, and the reply is the OS's error for the missing file, never a
//! made-up status.

use mooring_agent_proto::{AgentError, StatusV1};

use crate::gate;
use crate::host::Node;
use crate::paths::Paths;
use crate::store::Lock;
use crate::txn::record::last_committed;
use crate::watch::status::latest;

/// `Status`.
pub(crate) fn status(paths: &Paths, node: &dyn Node) -> Result<StatusV1, AgentError> {
    let view = latest(paths)?;
    let holds = {
        let _lock = Lock::exclusive(&paths.gate_lock())?;
        gate::holds(paths)?
    };
    Ok(StatusV1 {
        now: node.now(),
        watch_at: view.at,
        gate: view.observed.gate,
        holds,
        halted: gate::halted(paths)?,
        latest_handshake: view.latest_handshake,
        applied: last_committed(paths)?,
        conditions: view.observed.conditions,
        accounting_at: view.accounting.at,
        last_active: view.accounting.last_active,
        engines: view.engines,
        host: view.host.health,
        transfer: view.transfer.reported,
    })
}
