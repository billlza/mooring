// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's cut and lift (`AbuseCut`, `AbuseClear`, ops role; design
//! §11.8), as the root handler carries them out under `gate.lock`, the
//! lock the watch holds when it opens the gate or cuts.
//!
//! The abuse state is written first, then the cut set changed. A cut set
//! that nft refuses to change is [`AgentError::AbuseSetFailed`]: the state
//! holds the change all the same, and the watch sets the cut set from it at
//! its next re-read of the gate, within a minute, or before it next opens
//! the gate. The other order could leave a cut in the kernel that the state
//! does not hold, which the watch's next re-read would then undo.

use mooring_agent_proto::{
    AbuseAction, AbuseCutEntry, AbuseCuts, AbuseSeq, AgentError, Generation, InstalledWatchConfig,
    IoOp, OpaqueUserId, StderrTail, user_source,
};

use super::state::AbuseState;
use super::{add_words, as_args, cut_addresses, served_sources, sync_words};
use crate::gate;
use crate::host::{Node, Tool, run_ok};
use crate::paths::Paths;
use crate::store::{Lock, malformed, read_json};

/// `AbuseCut{user}`: cuts a user the installed generation serves, with an
/// `OperatorCut` record. A user cut already stays cut by the cut made
/// first, which is answered, and nothing is recorded.
pub(crate) fn cut(
    paths: &Paths,
    node: &dyn Node,
    user: &OpaqueUserId,
) -> Result<(AbuseSeq, AbuseCuts), AgentError> {
    let _lock = Lock::exclusive(&paths.gate_lock())?;
    let config = guarded_config(paths)?;
    if !served_sources(&config)
        .values()
        .any(|served| served == user)
    {
        return Err(AgentError::AbuseUserNotServed { user: user.clone() });
    }
    let mut state = AbuseState::read(paths)?;
    if let Some(existing) = state.cuts().get(user) {
        return Ok((existing.record, state.cuts().clone()));
    }
    let now = node.now();
    state.prune(now);
    let record = state.record(now, user, AbuseAction::OperatorCut, None);
    state.cut(AbuseCutEntry {
        user: user.clone(),
        since: now,
        record,
    })?;
    state.write(paths)?;
    set(node, &add_words(&[user_source(user)]))?;
    Ok((record, state.cuts().clone()))
}

/// `AbuseClear{user}`: lifts a user's cut, with a `Cleared` record. A user
/// who is not cut is answered with nothing recorded. The cut set is then
/// set from the state, as the watch's re-read sets it, so an address that
/// another cut user also has stays in it. It is changed only when the
/// installed generation carries the guard; one rendered before it has no
/// cut set.
pub(crate) fn clear(
    paths: &Paths,
    node: &dyn Node,
    user: &OpaqueUserId,
) -> Result<(Option<AbuseSeq>, AbuseCuts), AgentError> {
    let _lock = Lock::exclusive(&paths.gate_lock())?;
    let mut state = AbuseState::read(paths)?;
    if state.cuts().get(user).is_none() {
        return Ok((None, state.cuts().clone()));
    }
    let now = node.now();
    state.prune(now);
    let record = state.record(now, user, AbuseAction::Cleared, None);
    state.clear(user);
    state.write(paths)?;
    if let Some(config) = installed_config(paths)?.filter(|config| config.abuse_guard().is_some()) {
        let addresses = cut_addresses(state.cuts(), &served_sources(&config));
        set(node, &sync_words(&addresses))?;
    }
    Ok((Some(record), state.cuts().clone()))
}

/// The installed generation's `watch.json`, which must carry the guard
/// ([`AgentError::AbuseGuardNotInstalled`] otherwise, or with none
/// installed).
fn guarded_config(paths: &Paths) -> Result<InstalledWatchConfig, AgentError> {
    installed_config(paths)?
        .filter(|config| config.abuse_guard().is_some())
        .ok_or(AgentError::AbuseGuardNotInstalled)
}

/// The installed generation's `watch.json`; `None` with none installed.
fn installed_config(paths: &Paths) -> Result<Option<InstalledWatchConfig>, AgentError> {
    if gate::current_generation(paths)? == Generation::ZERO {
        return Ok(None);
    }
    read_json::<InstalledWatchConfig>(&paths.watch_config())?
        .map(Some)
        .ok_or(malformed(IoOp::ReadState))
}

/// Runs an nft command on the cut set: a refusal is
/// [`AgentError::AbuseSetFailed`] with nft's own message.
fn set(node: &dyn Node, words: &[String]) -> Result<(), AgentError> {
    match run_ok(node, Tool::Nft, &as_args(words))? {
        Ok(_) => Ok(()),
        Err(stderr) => Err(AgentError::AbuseSetFailed {
            stderr_tail: StderrTail::scrubbed(&stderr, &[]),
        }),
    }
}
