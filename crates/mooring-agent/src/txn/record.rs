// SPDX-License-Identifier: GPL-3.0-or-later

//! What a transaction leaves on disk: its record (`txn/gen-<N>.json`, the
//! header it installs and its state, which `TxnStatus` reads) and the one
//! change in flight (`txn/pending.json`) with its phase, which makes every
//! other change `Busy`.

use mooring_agent_proto::{AgentError, BundleHeader, Generation, Sha256Hex, TxnState};
use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::store::{read_json, write_json};

/// Records are read by root only.
const MODE: u32 = 0o600;

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
