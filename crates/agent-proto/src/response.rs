// SPDX-License-Identifier: GPL-3.0-or-later

//! [`Response`]: the agent's successful replies, and [`Reply`], the line it
//! writes.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{
    AcceptLocal, AgentError, EventsV1, Generation, Halt, Holds, HostFacts, HostProfileVersion,
    RequestKind, Sha256Hex, SshEd25519Key, SshdDirective, StatusV1, StoredMacReport, TargetFacts,
    UnixTime, UsageSeriesV1, UsageV1,
};

/// The agent's one-line answer: `{"Ok": <Response>}` or
/// `{"Err": <AgentError>}`.
pub type Reply = Result<Response, AgentError>;

/// A successful reply. Each variant answers exactly one request kind
/// ([`ResponseKind::request`]); the Mac treats any other pairing as a
/// protocol error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Response {
    /// Frozen. Answers `Hello`.
    Hello(Box<HelloInfo>),
    /// Frozen. Answers `HaveBlobs`: the asked-about blobs that are stored
    /// and verified.
    Blobs {
        /// The subset of the requested digests that is present.
        present: BTreeSet<Sha256Hex>,
    },
    /// Frozen. Answers `PutBlob`: the payload hashed to `sha256` and is
    /// stored.
    BlobStored {
        /// The stored blob.
        sha256: Sha256Hex,
    },
    /// Frozen. Answers `ActivateAgent`: the new agent passed its self-test,
    /// serves the forced command, and reverts unless `Confirm{generation}`
    /// arrives within 120 s. Activation does not change the configuration,
    /// so `generation` is the node's current one ([`Generation::ZERO`] if
    /// nothing has been applied).
    AwaitingConfirm {
        /// The generation to confirm.
        generation: Generation,
    },
    /// Frozen. Answers `Confirm`: the change is committed.
    Confirmed {
        /// The confirmed generation.
        generation: Generation,
    },
    /// Answers `Bootstrap`.
    BootstrapDone {
        /// The newly generated SSH host key, to be pinned by the Mac.
        host_pubkey: SshEd25519Key,
    },
    /// Answers `RevokeBootstrap`: the bootstrap key can no longer log in.
    BootstrapRevoked,
    /// Answers `Apply`: the transaction runs as its own unit; poll it with
    /// `TxnStatus{generation}`.
    TxnLaunched {
        /// The bundle's generation.
        generation: Generation,
    },
    /// Answers `Apply` whose digest equals the current generation's:
    /// nothing was restarted and holds and the halt state are untouched.
    Unchanged {
        /// The node's current generation.
        generation: Generation,
    },
    /// Answers `TxnStatus`.
    TxnStatus {
        /// The transaction's generation.
        generation: Generation,
        /// Its state.
        state: TxnState,
    },
    /// Answers `Rollback`: the change awaiting confirmation was reverted.
    Reverted {
        /// The reverted generation.
        generation: Generation,
    },
    /// Answers `Status`.
    Status(Box<StatusV1>),
    /// Answers `Usage`.
    Usage(Box<UsageV1>),
    /// Answers `UsageSeries`.
    UsageSeries(Box<UsageSeriesV1>),
    /// Answers `Events`.
    Events(Box<EventsV1>),
    /// Answers `TargetCheck`.
    TargetFacts(Box<TargetFacts>),
    /// Answers `GateSet`: the gate is closed and the hold recorded. It is
    /// sent only once both are true: the ops role records the hold and
    /// closes the gate itself; a viewer's stop is done by the watch, and is
    /// answered `GateClosed` only after the handler has read the Operator
    /// hold back from `holds.json` and found the gate closed, or
    /// [`crate::AgentError::GateStopUnconfirmed`] when that does not happen
    /// within [`crate::VIEWER_STOP_WAIT_SECS`].
    GateClosed {
        /// The holds after recording this one.
        holds: Holds,
    },
    /// Answers `ClearHold`: the hold is absent (whether or not it was
    /// present before). The watch reopens the gate if nothing else holds it.
    HoldCleared {
        /// The holds that remain.
        holds: Holds,
    },
    /// Answers `Shutdown`: the marker is written, the gate closed and both
    /// engines stopped.
    Halted(Halt),
    /// Answers `Resume`: the marker is removed and the engines run
    /// `generation`.
    Resumed {
        /// The current generation.
        generation: Generation,
    },
    /// Answers `PutMacReport`: the report is stored, replacing the one
    /// stored before.
    MacReportStored {
        /// The stored report's `at`, echoed.
        at: UnixTime,
    },
    /// Answers `MacReport`: the stored report and when the node received
    /// it.
    MacReport(Box<StoredMacReport>),
}

closed_enum! {
    /// The variant of a [`Response`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum ResponseKind {
        /// [`Response::Hello`].
        Hello,
        /// [`Response::Blobs`].
        Blobs,
        /// [`Response::BlobStored`].
        BlobStored,
        /// [`Response::AwaitingConfirm`].
        AwaitingConfirm,
        /// [`Response::Confirmed`].
        Confirmed,
        /// [`Response::BootstrapDone`].
        BootstrapDone,
        /// [`Response::BootstrapRevoked`].
        BootstrapRevoked,
        /// [`Response::TxnLaunched`].
        TxnLaunched,
        /// [`Response::Unchanged`].
        Unchanged,
        /// [`Response::TxnStatus`].
        TxnStatus,
        /// [`Response::Reverted`].
        Reverted,
        /// [`Response::Status`].
        Status,
        /// [`Response::Usage`].
        Usage,
        /// [`Response::UsageSeries`].
        UsageSeries,
        /// [`Response::Events`].
        Events,
        /// [`Response::TargetFacts`].
        TargetFacts,
        /// [`Response::GateClosed`].
        GateClosed,
        /// [`Response::HoldCleared`].
        HoldCleared,
        /// [`Response::Halted`].
        Halted,
        /// [`Response::Resumed`].
        Resumed,
        /// [`Response::MacReportStored`].
        MacReportStored,
        /// [`Response::MacReport`].
        MacReport,
    }
}

impl ResponseKind {
    /// The request kind this response answers.
    pub const fn request(self) -> RequestKind {
        match self {
            Self::Hello => RequestKind::Hello,
            Self::Blobs => RequestKind::HaveBlobs,
            Self::BlobStored => RequestKind::PutBlob,
            Self::AwaitingConfirm => RequestKind::ActivateAgent,
            Self::Confirmed => RequestKind::Confirm,
            Self::BootstrapDone => RequestKind::Bootstrap,
            Self::BootstrapRevoked => RequestKind::RevokeBootstrap,
            Self::TxnLaunched | Self::Unchanged => RequestKind::Apply,
            Self::TxnStatus => RequestKind::TxnStatus,
            Self::Reverted => RequestKind::Rollback,
            Self::Status => RequestKind::Status,
            Self::Usage => RequestKind::Usage,
            Self::UsageSeries => RequestKind::UsageSeries,
            Self::Events => RequestKind::Events,
            Self::TargetFacts => RequestKind::TargetCheck,
            Self::GateClosed => RequestKind::GateSet,
            Self::HoldCleared => RequestKind::ClearHold,
            Self::Halted => RequestKind::Shutdown,
            Self::Resumed => RequestKind::Resume,
            Self::MacReportStored => RequestKind::PutMacReport,
            Self::MacReport => RequestKind::MacReport,
        }
    }
}

impl Response {
    /// The variant, without its data.
    pub const fn kind(&self) -> ResponseKind {
        match self {
            Self::Hello(_) => ResponseKind::Hello,
            Self::Blobs { .. } => ResponseKind::Blobs,
            Self::BlobStored { .. } => ResponseKind::BlobStored,
            Self::AwaitingConfirm { .. } => ResponseKind::AwaitingConfirm,
            Self::Confirmed { .. } => ResponseKind::Confirmed,
            Self::BootstrapDone { .. } => ResponseKind::BootstrapDone,
            Self::BootstrapRevoked => ResponseKind::BootstrapRevoked,
            Self::TxnLaunched { .. } => ResponseKind::TxnLaunched,
            Self::Unchanged { .. } => ResponseKind::Unchanged,
            Self::TxnStatus { .. } => ResponseKind::TxnStatus,
            Self::Reverted { .. } => ResponseKind::Reverted,
            Self::Status(_) => ResponseKind::Status,
            Self::Usage(_) => ResponseKind::Usage,
            Self::UsageSeries(_) => ResponseKind::UsageSeries,
            Self::Events(_) => ResponseKind::Events,
            Self::TargetFacts(_) => ResponseKind::TargetFacts,
            Self::GateClosed { .. } => ResponseKind::GateClosed,
            Self::HoldCleared { .. } => ResponseKind::HoldCleared,
            Self::Halted(_) => ResponseKind::Halted,
            Self::Resumed { .. } => ResponseKind::Resumed,
            Self::MacReportStored { .. } => ResponseKind::MacReportStored,
            Self::MacReport(_) => ResponseKind::MacReport,
        }
    }

    /// Whether this response is a valid answer to `request`.
    pub fn answers(&self, request: RequestKind) -> bool {
        self.kind().request() == request
    }
}

/// The answer to `Hello` (design §11.1). Part of the frozen upgrade core:
/// its encoding is fixed for protocol 1, so every later Mac can read every
/// agent's `Hello`. A later protocol that needs more facts adds a request
/// rather than changing this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloInfo {
    /// The agent's [`crate::PROTOCOL`].
    pub protocol: u32,
    /// The digest of the running agent binary.
    pub agent_sha: Sha256Hex,
    /// The host profile version installed on the node.
    pub host_profile_version: HostProfileVersion,
    /// Debian major release, kernel, arch, congestion control, qdisc,
    /// `ip_local_port_range`, the uplink and the IPv4 address on it.
    pub host: HostFacts,
    /// `net.ipv4.conf.<interface>.accept_local` of [`crate::WG_INTERFACE`].
    pub wgexit_accept_local: AcceptLocal,
    /// The profile's sshd directives whose effective value (`sshd -T`)
    /// differs from the profile; empty when sshd enforces all of them.
    pub sshd_mismatches: BTreeSet<SshdDirective>,
    /// The halt marker, if the node is halted.
    #[serde(deserialize_with = "Option::deserialize")]
    pub halted: Option<Halt>,
    /// The current holds.
    pub holds: Holds,
    /// The client address from `SSH_CONNECTION`: the Mac's public IPv4 as
    /// the VPS sees it.
    pub client_ip: Ipv4Addr,
}

closed_enum! {
    /// A stage of a running transaction (§11.2).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum TxnStage {
        /// Checking that the node is not halted, the host facts and port
        /// range, and the blobs.
        Preconditions,
        /// Staging the generation directory and engine store.
        Stage,
        /// Running the validators.
        Validate,
        /// Swapping the symlinks and installing the host profile.
        Swap,
        /// Applying what changed.
        Apply,
        /// Waiting for the local health gate.
        HealthGate,
    }
}

/// The state of a transaction, reported by `TxnStatus`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TxnState {
    /// The transaction unit is working.
    Running {
        /// The current stage.
        stage: TxnStage,
    },
    /// The health gate passed and the confirm timer is armed.
    AwaitingConfirm,
    /// `Confirm` arrived; the generation is current.
    Committed,
    /// A `Rollback` request reverted the transaction.
    Reverted,
    /// The transaction ended in a failure: a precondition or validation
    /// error (nothing was switched), [`AgentError::RolledBack`],
    /// [`AgentError::RollbackFailed`] or
    /// [`AgentError::RevertedUnconfirmed`].
    Failed {
        /// The failure.
        error: AgentError,
    },
}
