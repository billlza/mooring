// SPDX-License-Identifier: GPL-3.0-or-later

//! [`Request`]: everything the Mac can ask an agent (design §11.1).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{
    AgentError, BlobLen, BundleHeader, ClearableHold, GateReason, Generation, Role, Sha256Hex,
    ShutdownReason, SshEd25519Key, TargetHost, UsageMonth,
};

/// One request: the JSON line on the agent's stdin, as the agent reads it.
///
/// `PutBlob` is the one request whose line is followed by a payload, so it is
/// kept apart from the [`LineRequest`]s: [`crate::write_request`] takes only
/// a `LineRequest`, and only [`crate::write_put_blob`] writes a `PutBlob`,
/// with its payload. On the wire the two levels are invisible: `PutBlob` is
/// `{"PutBlob":{…}}` and every other request is encoded as its
/// `LineRequest`.
///
/// The encodings of `Hello`, `HaveBlobs`, `PutBlob`, `ActivateAgent` and
/// `Confirm` are the frozen upgrade core: they never change across protocol
/// versions, so any Mac release can upload and activate any agent. They are
/// pinned byte for byte by golden tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    /// Frozen. Store a blob; exactly `len` raw bytes follow the line.
    PutBlob {
        /// The digest the payload must hash to.
        sha256: Sha256Hex,
        /// The payload length.
        len: BlobLen,
    },
    /// Every other request: one line with nothing after it.
    #[serde(untagged)]
    Line(LineRequest),
}

impl From<LineRequest> for Request {
    fn from(line: LineRequest) -> Self {
        Self::Line(line)
    }
}

/// Every request except `PutBlob`: one JSON line, which
/// [`crate::write_request`] writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum LineRequest {
    /// Frozen. Report the agent and host ([`crate::HelloInfo`]).
    Hello,
    /// Frozen. Which of these blobs are already stored?
    HaveBlobs {
        /// The blobs the Mac is about to need.
        blobs: BTreeSet<Sha256Hex>,
    },
    /// Frozen. Self-test the stored agent blob `sha`, switch the forced
    /// command to it and arm the 120 s revert timer.
    ActivateAgent {
        /// The new agent's digest.
        sha: Sha256Hex,
    },
    /// Frozen. Confirm the change awaiting confirmation under `generation`,
    /// from a new SSH session (which proves the change kept SSH working).
    Confirm {
        /// The generation reported by `AwaitingConfirm`.
        generation: Generation,
    },
    /// Bootstrap role only. Install packages, users, units, the host
    /// profile and the role-restricted `authorized_keys`, and regenerate the
    /// SSH host key.
    Bootstrap {
        /// The digest the running agent binary must have.
        expected_agent_sha: Sha256Hex,
        /// The operations key to authorise.
        ops_pubkey: SshEd25519Key,
    },
    /// Remove the bootstrap key's `authorized_keys` line.
    RevokeBootstrap,
    /// Launch a transaction installing this bundle (§11.2).
    Apply(Box<BundleHeader>),
    /// Report the state of the transaction for `generation`.
    TxnStatus {
        /// The transaction's generation.
        generation: Generation,
    },
    /// Revert the change awaiting confirmation now, exactly as the confirm
    /// timer would.
    Rollback,
    /// Report the node status ([`crate::StatusV1`]).
    Status,
    /// Report one month of accounting ([`crate::UsageV1`]).
    Usage {
        /// The month.
        month: UsageMonth,
    },
    /// Measure a candidate REALITY target ([`crate::TargetFacts`]).
    TargetCheck {
        /// The target's name.
        host: TargetHost,
    },
    /// Close the gate and record a hold. There is no way to open it.
    GateSet {
        /// Why.
        reason: GateReason,
    },
    /// Clear a hold that only an explicit request clears.
    ClearHold {
        /// The hold.
        hold: ClearableHold,
    },
    /// Halt the node: write the halt marker, close the gate, stop both
    /// engines.
    Shutdown {
        /// Why.
        reason: ShutdownReason,
    },
    /// Remove the halt marker and start the engines on the current
    /// generation, which must be `config_generation`.
    Resume {
        /// The generation the operator expects to be current.
        config_generation: Generation,
    },
}

closed_enum! {
    /// The variant of a [`Request`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum RequestKind {
        /// [`LineRequest::Hello`].
        Hello,
        /// [`LineRequest::HaveBlobs`].
        HaveBlobs,
        /// [`Request::PutBlob`].
        PutBlob,
        /// [`LineRequest::ActivateAgent`].
        ActivateAgent,
        /// [`LineRequest::Confirm`].
        Confirm,
        /// [`LineRequest::Bootstrap`].
        Bootstrap,
        /// [`LineRequest::RevokeBootstrap`].
        RevokeBootstrap,
        /// [`LineRequest::Apply`].
        Apply,
        /// [`LineRequest::TxnStatus`].
        TxnStatus,
        /// [`LineRequest::Rollback`].
        Rollback,
        /// [`LineRequest::Status`].
        Status,
        /// [`LineRequest::Usage`].
        Usage,
        /// [`LineRequest::TargetCheck`].
        TargetCheck,
        /// [`LineRequest::GateSet`].
        GateSet,
        /// [`LineRequest::ClearHold`].
        ClearHold,
        /// [`LineRequest::Shutdown`].
        Shutdown,
        /// [`LineRequest::Resume`].
        Resume,
    }
}

impl RequestKind {
    /// Whether the request belongs to the frozen upgrade core.
    pub const fn is_frozen_core(self) -> bool {
        matches!(
            self,
            Self::Hello | Self::HaveBlobs | Self::PutBlob | Self::ActivateAgent | Self::Confirm
        )
    }
}

impl Request {
    /// The variant, without its data.
    pub const fn kind(&self) -> RequestKind {
        match self {
            Self::PutBlob { .. } => RequestKind::PutBlob,
            Self::Line(line) => line.kind(),
        }
    }

    /// Checks that `role` may send this request (see [`Role::permits`]).
    pub const fn authorize(&self, role: Role) -> Result<(), AgentError> {
        let request = self.kind();
        if role.permits(request) {
            Ok(())
        } else {
            Err(AgentError::RoleNotPermitted { role, request })
        }
    }
}

impl LineRequest {
    /// The variant, without its data.
    pub const fn kind(&self) -> RequestKind {
        match self {
            Self::Hello => RequestKind::Hello,
            Self::HaveBlobs { .. } => RequestKind::HaveBlobs,
            Self::ActivateAgent { .. } => RequestKind::ActivateAgent,
            Self::Confirm { .. } => RequestKind::Confirm,
            Self::Bootstrap { .. } => RequestKind::Bootstrap,
            Self::RevokeBootstrap => RequestKind::RevokeBootstrap,
            Self::Apply(_) => RequestKind::Apply,
            Self::TxnStatus { .. } => RequestKind::TxnStatus,
            Self::Rollback => RequestKind::Rollback,
            Self::Status => RequestKind::Status,
            Self::Usage { .. } => RequestKind::Usage,
            Self::TargetCheck { .. } => RequestKind::TargetCheck,
            Self::GateSet { .. } => RequestKind::GateSet,
            Self::ClearHold { .. } => RequestKind::ClearHold,
            Self::Shutdown { .. } => RequestKind::Shutdown,
            Self::Resume { .. } => RequestKind::Resume,
        }
    }
}
