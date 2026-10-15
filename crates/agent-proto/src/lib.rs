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
//! The forced command passes `--role bootstrap|ops|viewer`;
//! [`Role::permits`] is the permission table, [`Role::may_close_gate_for`]
//! limits a remote viewer's `GateSet` to the operator hold, and
//! [`Request::authorize`] is the check the agent applies before acting.
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
//! [`NFT_GATE_SET`], [`NftCounter`], [`EngineUser`], [`EXIT_ROUTE_TABLE`],
//! [`VIEWER_ACCOUNT`]), so the renderer and the agent share one definition
//! of each. For the remote viewer and the alert channels (decisions F5 and
//! F6) it holds the Mac's report ([`MacReportV1`]), the push-notice
//! grammar ([`NtfyMessage`]) and the node's dead-man rule
//! ([`dead_man_pings`]).

#![deny(missing_docs)]

mod macros;

mod deadman;
mod digest;
mod error;
mod event;
mod framing;
mod gate;
mod health;
mod host;
mod managed;
mod names;
mod notice;
mod profile;
mod report;
mod request;
mod response;
mod role;
mod scalar;
mod series;
mod status;
mod stderr;
mod target;
mod usage;
mod vps;
mod watch;

pub use deadman::{DeadManCheck, dead_man_pings};
pub use digest::{BlobLen, MAX_BLOB_BYTES, Sha256Hex};
pub use error::{
    AgentError, AgentErrorKind, ApplyStep, HealthCheck, IoOp, RollbackCause, SystemdOp, TargetTool,
    ValidationTool, ValueError, ValueErrorKind,
};
pub use event::{AgentEvent, AgentEventKind, EventSeq, EventsV1, MAX_EVENTS};
pub use framing::{
    MAX_REQUEST_LINE_BYTES, MAX_RESPONSE_LINE_BYTES, MalformedCause, ReadError, ReadErrorKind,
    WriteError, WriteErrorKind, expect_end_of_input, read_blob, read_reply, read_request,
    write_put_blob, write_reply, write_request,
};
pub use gate::{
    ClearableHold, EgressViolationHold, GateReason, GateState, Halt, Holds, MacDrainHold,
    OperatorHold, ShutdownReason,
};
pub use health::{EngineHealth, EngineRun, EngineState, HostHealth, UplinkTransfer};
pub use host::{AcceptLocal, Arch, HostFact, HostFacts};
pub use managed::{BundleFiles, BundleHeader, CURRENT_DIR, ETC_DIR, EngineSet, ManagedFile};
pub use names::{
    CertName, IfName, KernelIdent, KernelRelease, NodeName, RedirectUrl, SshEd25519Key, TargetHost,
    UnitName,
};
pub use notice::{
    MAX_NOTICE_BODY_BYTES, MAX_NOTICE_TITLE_BYTES, NoticeBody, NoticeTitle, NtfyMessage,
    NtfyPriority, NtfyTag,
};
pub use profile::{
    HostFile, HostProfile, HostProfileVersion, JournaldSetting, SshdDirective, Sysctl,
    TmpfilesEntry, TmpfilesType, UnattendedUpgrades, ViewerAccount,
};
pub use report::{
    ExitPhase, MAX_MAC_REPORT_BYTES, MAX_REPORT_ALERTS, MAX_REPORT_USERS, MacAlertKind,
    MacReportParts, MacReportRule, MacReportV1, ReportAccuracy, ReportAlert, ReportBand,
    ReportBandNumber, ReportCapacity, ReportDataService, ReportExit, ReportForecast,
    ReportLteSignal, ReportNrSignal, ReportPlanLine, ReportRadio, ReportRadioSystem, ReportRouter,
    ReportSaturation, ReportSeverity, ReportSim, ReportUsage, ReportUser, ReportUserId,
    ReportUserStatus, StoredMacReport,
};
pub use request::{LineRequest, Request, RequestKind};
pub use response::{HelloInfo, Reply, Response, ResponseKind, TxnStage, TxnState};
pub use role::{AGENT_CURRENT_PATH, Role};
pub use scalar::{Generation, PortRange, UnixTime};
pub use series::{
    MAX_SERIES_ENTRIES, MAX_USAGE_SERIES_REPLY_BYTES, Resolution, SeriesRange, SeriesSpan,
    UsageBin, UsageSeriesV1,
};
pub use status::{AppliedGeneration, StatusV1};
pub use stderr::{REDACTED, STDERR_TAIL_MAX_BYTES, StderrTail};
pub use target::{
    HttpProbe, HttpStatus, HttpVersion, TARGET_HANDSHAKE_SAMPLES, TargetFacts, TlsGroup, TlsProbe,
    TlsSession, TlsVersion,
};
pub use usage::{
    Inbound, InboundSet, OpaqueUserId, Principal, StatsEmail, Traffic, UsageMonth, UsageV1,
};
pub use vps::{
    EXIT_ROUTE_TABLE, EXIT_RULE_PRIORITY, EngineUser, NFT_GATE_SET, NFT_TABLE, NftCounter,
    VIEWER_ACCOUNT, WG_INTERFACE,
};
pub use watch::{
    ACCOUNTING_INTERVAL_SECS, DISK_LOW_FREE_BYTES, DISK_LOW_FREE_PERCENT, GATE_SET_REREAD_SECS,
    HANDSHAKE_MAX_AGE_SECS, MAC_SILENT_SECS, RX_GROWTH_KEEPALIVES, TARGET_CHECK_INTERVAL_SECS,
    VIEWER_STOP_WAIT_SECS, WATCH_STALE_SECS, WATCH_TICK_SECS, WatchConditions, WatchConfig,
    WatchError, WatchErrorKind, WatchTarget,
};

/// The protocol version this crate speaks, reported in
/// [`HelloInfo::protocol`].
pub const PROTOCOL: u32 = 1;
