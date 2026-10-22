// SPDX-License-Identifier: GPL-3.0-or-later

//! `ActivateAgent` (design §11.2): a new agent from the blob store is
//! installed beside the current one, must pass its own `self-test`, and
//! only then becomes the forced command, with the same 120 s revert timer
//! as a transaction. The timer runs the previous agent, which is known to
//! work, and the new agent must serve the `Confirm`.

use std::fs;
use std::io;
use std::path::Path;

use mooring_agent_proto::{AgentError, Generation, IoOp, PROTOCOL, Sha256Hex, StderrTail};

use super::record::{Change, Pending, Phase, set_pending};
use super::{abandon, arm_revert, exclusive, replace_link};
use crate::blobs::digest_of;
use crate::gate;
use crate::host::Node;
use crate::paths::Paths;
use crate::store::{ensure_dir, io_error};

/// Activates the stored agent `sha`; the node's generation, which an
/// activation does not change.
pub(crate) fn activate(
    paths: &Paths,
    node: &dyn Node,
    sha: Sha256Hex,
) -> Result<Generation, AgentError> {
    let _lock = exclusive(paths)?;
    let generation = gate::current_generation(paths)?;
    if !crate::blobs::present(paths, &[sha].into())?.contains(&sha) {
        return Err(AgentError::BlobMissing { sha256: sha });
    }
    // The forced command's target: a node without one cannot have
    // received this request, and has no agent to revert to.
    let previous = fs::read_link(paths.agent_current())
        .map_err(|error| io_error(IoOp::ReadState, &error))?
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(AgentError::Io {
            op: IoOp::ReadState,
            errno: None,
        })?
        .to_owned();
    let installed = install(paths, &sha)?;
    let output = node
        .run_program(&installed, &["self-test"], &[])
        .map_err(|error| io_error(IoOp::SpawnProcess, &error))?;
    if !output.success || output.stdout != format!("{PROTOCOL}\n").into_bytes() {
        return Err(AgentError::AgentSelfTestFailed {
            stderr_tail: StderrTail::scrubbed(&output.stderr, &[]),
        });
    }
    let reverter = production_path(paths, &paths.agent_dir().join(&previous));
    arm_revert(node, generation, &reverter)?;
    let switched = set_pending(
        paths,
        &Pending {
            generation,
            change: Change::Activate { sha, previous },
            phase: Phase::AwaitingConfirm,
        },
    )
    .and_then(|()| {
        replace_link(&paths.agent_current(), Path::new(&sha.to_string()))
            .map_err(|error| io_error(IoOp::WriteState, &error))
    });
    if let Err(error) = switched {
        abandon(paths, node, generation, true)?;
        return Err(error);
    }
    Ok(generation)
}

/// The path a transient unit runs: the agent's path on the node, whatever
/// root the layout has in tests.
fn production_path(paths: &Paths, path: &Path) -> std::path::PathBuf {
    let root = paths.at("/");
    Path::new("/").join(path.strip_prefix(&root).unwrap_or(path))
}

/// Copies the stored blob `sha` to `/usr/local/lib/mooring/agent/<sha>`
/// (0755), unless an intact copy is there already.
fn install(paths: &Paths, sha: &Sha256Hex) -> Result<std::path::PathBuf, AgentError> {
    let dir = paths.agent_dir();
    let target = dir.join(sha.to_string());
    let intact = match fs::File::open(&target) {
        Ok(file) => digest_of(file).map_err(|error| io_error(IoOp::ReadBlob, &error))? == *sha,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(io_error(IoOp::ReadBlob, &error)),
    };
    if !intact {
        ensure_dir(&dir).map_err(|error| io_error(IoOp::WriteBlob, &error))?;
        let bytes = fs::read(paths.blob(sha)).map_err(|error| io_error(IoOp::ReadBlob, &error))?;
        crate::store::write_atomic(&target, &bytes, 0o755)
            .map_err(|error| io_error(IoOp::WriteBlob, &error))?;
    }
    Ok(target)
}

/// Points the forced command back at `previous` (a revert of an
/// activation).
pub(crate) fn restore(paths: &Paths, previous: &str) -> Result<(), AgentError> {
    replace_link(&paths.agent_current(), Path::new(previous))
        .map_err(|error| io_error(IoOp::WriteState, &error))
}
