// SPDX-License-Identifier: GPL-3.0-or-later

//! What a transaction leaves on disk: its record (`txn/gen-<N>.json`, the
//! header it installs and its state, which `TxnStatus` reads) and the one
//! change in flight (`txn/pending.json`) with its phase, which makes every
//! other change `Busy`.

use std::fs;
use std::io;

use mooring_agent_proto::{
    AgentError, AppliedGeneration, BundleHeader, Generation, IoOp, Sha256Hex, TxnState,
};
use serde::{Deserialize, Serialize};

use crate::paths::{Paths, generation_name};
use crate::store::{io_error, read_json, write_json};

/// Records are read by the `mooring` group as well: the watch journals a
/// commit from the current generation's record. They hold digests, host
/// facts and scrubbed errors, no secret.
const MODE: u32 = 0o640;

/// A transaction's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TxnRecord {
    /// What it installs.
    pub(crate) header: BundleHeader,
    /// Where it stands.
    pub(crate) state: TxnState,
}

/// The change in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pending {
    /// For an `Apply`, the generation it installs; for an activation, the
    /// node's generation, which it does not change.
    pub(crate) generation: Generation,
    /// What it changes, and what reverting it restores.
    pub(crate) change: Change,
    /// How far it has got.
    pub(crate) phase: Phase,
}

/// How far a pending change has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Phase {
    /// `Apply` launched the transaction unit, which has not armed the
    /// confirm timer yet.
    Launched,
    /// The transaction unit armed the confirm timer.
    Armed,
    /// The change awaits `Confirm`; its timer is armed.
    AwaitingConfirm,
}

impl Phase {
    /// Whether a confirm timer was armed for the change.
    pub(crate) const fn armed(self) -> bool {
        matches!(self, Self::Armed | Self::AwaitingConfirm)
    }
}

/// What a pending change changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Change {
    /// A configuration generation; reverting restores `previous`
    /// ([`Generation::ZERO`]: none).
    Apply {
        /// The generation current before it.
        previous: Generation,
    },
    /// A new agent; reverting points the forced command back at
    /// `previous`, the file name the link named before.
    Activate {
        /// The new agent's digest.
        sha: Sha256Hex,
        /// The link's previous target.
        previous: String,
    },
}

/// The pending change, if any.
pub(crate) fn pending(paths: &Paths) -> Result<Option<Pending>, AgentError> {
    read_json(&paths.pending())
}

/// Records the pending change.
pub(crate) fn set_pending(paths: &Paths, pending: &Pending) -> Result<(), AgentError> {
    write_json(&paths.pending(), pending, MODE)
}

/// Removes the pending change.
pub(crate) fn clear_pending(paths: &Paths) -> Result<(), AgentError> {
    crate::store::remove(&paths.pending())
}

/// The record of the transaction for `generation`.
pub(crate) fn record(paths: &Paths, generation: Generation) -> Result<TxnRecord, AgentError> {
    read_json(&paths.txn_record(generation))?.ok_or(AgentError::UnknownTransaction { generation })
}

/// The newest generation whose transaction committed, with the digest it
/// was applied with (`StatusV1::applied`); `None` before the first commit.
/// Only the generations the node keeps have records.
pub(crate) fn last_committed(paths: &Paths) -> Result<Option<AppliedGeneration>, AgentError> {
    let entries = match fs::read_dir(paths.txn_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(IoOp::ReadState, &error)),
    };
    let mut newest: Option<AppliedGeneration> = None;
    for entry in entries {
        let entry = entry.map_err(|error| io_error(IoOp::ReadState, &error))?;
        let name = entry.file_name();
        // A record is `gen-<N>.json` exactly; `pending.json` and temporary
        // files are not records.
        let Some(generation) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .and_then(|stem| Some((stem, stem.strip_prefix("gen-")?.parse::<u64>().ok()?)))
            .and_then(|(stem, number)| {
                let generation = Generation::new(number);
                (generation_name(generation) == stem).then_some(generation)
            })
        else {
            continue;
        };
        if newest.is_some_and(|newest| newest.generation >= generation) {
            continue;
        }
        let record = record(paths, generation)?;
        if record.state == TxnState::Committed {
            newest = Some(AppliedGeneration {
                generation,
                digest: record.header.digest,
            });
        }
    }
    Ok(newest)
}

/// Writes the record for `generation`.
pub(crate) fn set_record(
    paths: &Paths,
    generation: Generation,
    record: &TxnRecord,
) -> Result<(), AgentError> {
    write_json(&paths.txn_record(generation), record, MODE)
}

/// Sets only the state of the record for `generation`.
pub(crate) fn set_state(
    paths: &Paths,
    generation: Generation,
    state: TxnState,
) -> Result<(), AgentError> {
    let mut current = record(paths, generation)?;
    current.state = state;
    set_record(paths, generation, &current)
}
