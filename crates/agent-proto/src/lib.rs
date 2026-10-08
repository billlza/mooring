// SPDX-License-Identifier: GPL-3.0-or-later

//! The wire protocol between `mooringctl` on the Mac and `mooring-agent` on
//! a VPS (design §11.1–§11.5), protocol version [`PROTOCOL`].
//!
//! # Framing
//!
//! One SSH session carries one request. The agent's stdin holds one JSON
//! line of at most [`MAX_REQUEST_LINE_BYTES`] bytes, followed for
//! [`Request::PutBlob`] by exactly `len` raw bytes (at most
//! [`MAX_BLOB_BYTES`]). The agent answers on stdout with one JSON line, a
//! [`Reply`]: `{"Ok": <Response>}` or `{"Err": <AgentError>}`. A non-zero
//! exit is a transport failure or crash, which the Mac classifies
//! separately. See [`read_request`], [`read_blob`], [`write_reply`] and
//! [`read_reply`].
//!
//! Every message type rejects unknown fields, and every validated value
//! ([`Sha256Hex`], [`TargetHost`], [`StderrTail`], …) is checked again on
//! receipt, so a decoded message always satisfies its types' rules.
//!
//! # Roles
//!
//! The forced command passes `--role bootstrap|ops`; [`Role::permits`] is
//! the permission table and [`Request::authorize`] the check the agent
//! applies before acting.
//!
//! # Frozen upgrade core
//!
//! `Hello`, `HaveBlobs`, `PutBlob`, `ActivateAgent` and `Confirm`, and their
//! successful responses, never change across protocol versions, so any Mac
//! can upload, activate and confirm any agent. Golden files in
//! `contract/agent-proto-golden/` pin their encodings byte for byte.
//! [`AgentError`] is not frozen: a Mac that meets an error variant it does
//! not know fails to decode the reply, which it reports as a protocol
//! mismatch.
//!
//! # Scope
//!
//! This crate has no internal dependencies: the VPS agent links it and never
//! renders configuration. It also holds the agent's fixed paths for
//! [`ManagedFile`]s, the [`HostProfile`], and the VPS-side names the rendered
//! files and the agent both use ([`WG_INTERFACE`], [`NFT_TABLE`],
//! [`NFT_GATE_SET`], [`NftCounter`], [`EngineUser`], [`EXIT_ROUTE_TABLE`]),
//! so the renderer and the agent share one definition of each.

#![deny(missing_docs)]

mod macros;

mod digest;
mod error;
mod framing;
mod gate;
mod host;
mod managed;
mod names;
mod profile;
mod request;
mod response;
mod role;
mod scalar;
mod status;
mod stderr;
mod target;
mod usage;
mod vps;
mod watch;

pub use digest::{BlobLen, MAX_BLOB_BYTES, Sha256Hex};
pub use error::{
    AgentError, AgentErrorKind, ApplyStep, HealthCheck, IoOp, RollbackCause, SystemdOp, TargetTool,
    ValidationTool, ValueError, ValueErrorKind,
};
pub use framing::{
    MAX_REQUEST_LINE_BYTES, MAX_RESPONSE_LINE_BYTES, MalformedCause, ReadError, ReadErrorKind,
    WriteError, WriteErrorKind, expect_end_of_input, read_blob, read_reply, read_request,
    write_put_blob, write_reply, write_request,
};
pub use gate::{
    ClearableHold, EgressViolationHold, GateReason, GateState, Halt, Holds, MacDrainHold,
    OperatorHold, ShutdownReason,
};
pub use host::{AcceptLocal, Arch, HostFact, HostFacts};
pub use managed::{BundleFiles, BundleHeader, CURRENT_DIR, ETC_DIR, EngineSet, ManagedFile};
pub use names::{
    CertName, IfName, KernelIdent, KernelRelease, RedirectUrl, SshEd25519Key, TargetHost, UnitName,
};
pub use profile::{
    HostFile, HostProfile, HostProfileVersion, JournaldSetting, SshdDirective, Sysctl,
    TmpfilesEntry, TmpfilesType, UnattendedUpgrades,
};
pub use request::{LineRequest, Request, RequestKind};
pub use response::{HelloInfo, Reply, Response, ResponseKind, TxnStage, TxnState};
pub use role::{AGENT_CURRENT_PATH, Role};
pub use scalar::{Generation, PortRange, UnixTime};
pub use status::{AppliedGeneration, StatusV1};
pub use stderr::{REDACTED, STDERR_TAIL_MAX_BYTES, StderrTail};
pub use target::{
    HttpProbe, HttpStatus, HttpVersion, TARGET_HANDSHAKE_SAMPLES, TargetFacts, TlsGroup, TlsProbe,
    TlsSession, TlsVersion,
};
pub use usage::{Inbound, OpaqueUserId, Principal, StatsEmail, Traffic, UsageMonth, UsageV1};
pub use vps::{
    EXIT_ROUTE_TABLE, EXIT_RULE_PRIORITY, EngineUser, NFT_GATE_SET, NFT_TABLE, NftCounter,
    WG_INTERFACE,
};
pub use watch::{
    ACCOUNTING_INTERVAL_SECS, GATE_SET_REREAD_SECS, HANDSHAKE_MAX_AGE_SECS, RX_GROWTH_KEEPALIVES,
    TARGET_CHECK_INTERVAL_SECS, WATCH_TICK_SECS, WatchConditions, WatchConfig, WatchError,
    WatchErrorKind, WatchTarget,
};

/// The protocol version this crate speaks, reported in
/// [`HelloInfo::protocol`].
pub const PROTOCOL: u32 = 1;
