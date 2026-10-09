// SPDX-License-Identifier: GPL-3.0-or-later

//! Error types: [`AgentError`], the agent's typed reply (design §14,
//! "agent (remote)"), and [`ValueError`], a wire value that breaks its
//! type's rule.

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{
    GateReason, Generation, HostFact, MAX_EVENTS, MAX_SERIES_ENTRIES, MacReportRule, ManagedFile,
    PortRange, RequestKind, Resolution, Role, SeriesSpan, Sha256Hex, StderrTail, UnitName,
    UsageMonth, WatchErrorKind,
};

/// A wire value that does not satisfy its type's rule. Deserialisation
/// reports it inside the decoder's error, so a received frame holding such a
/// value is rejected as a whole.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValueError {
    /// Not 64 lowercase hexadecimal characters.
    #[error("not a SHA-256 digest of 64 lowercase hexadecimal characters")]
    Sha256Hex,
    /// A blob longer than [`crate::MAX_BLOB_BYTES`].
    #[error("blob length {len} exceeds the {max} byte limit", max = crate::MAX_BLOB_BYTES)]
    BlobTooLarge {
        /// The rejected length.
        len: u64,
    },
    /// Not a valid [`crate::IfName`].
    #[error("not a Linux interface name")]
    IfName,
    /// Not a valid [`crate::KernelRelease`].
    #[error("not a kernel release")]
    KernelRelease,
    /// Not a valid [`crate::KernelIdent`].
    #[error("not a kernel identifier")]
    KernelIdent,
    /// A port range that is empty or includes port 0.
    #[error("port range is empty or includes port 0")]
    PortRange,
    /// Not a valid [`crate::TargetHost`].
    #[error("not an ASCII LDH DNS name")]
    TargetHost,
    /// Not a valid [`crate::UnitName`].
    #[error("not a systemd unit name")]
    UnitName,
    /// Not a valid [`crate::CertName`].
    #[error("not a certificate DNS name")]
    CertName,
    /// Not a valid [`crate::RedirectUrl`].
    #[error("not a redirect URL")]
    RedirectUrl,
    /// Not a valid [`crate::SshEd25519Key`].
    #[error("not an OpenSSH ed25519 public key")]
    SshEd25519Key,
    /// Text longer than [`crate::STDERR_TAIL_MAX_BYTES`] or holding control
    /// characters.
    #[error("not a bounded, escaped stderr tail")]
    StderrTail,
    /// Not a `YYYY-MM` month from 1970-01 to 9999-12.
    #[error("not a YYYY-MM month")]
    UsageMonth,
    /// Not a valid [`crate::OpaqueUserId`].
    #[error("not an opaque user id")]
    OpaqueUserId,
    /// Not `<principal>@reality` or `<principal>@hy2`.
    #[error("not an accounting email")]
    StatsEmail,
    /// An HTTP status outside 100..=599.
    #[error("HTTP status {status} is outside 100..=599")]
    HttpStatus {
        /// The rejected status.
        status: u16,
    },
    /// Not `bootstrap`, `ops` or `viewer`.
    #[error("role must be `bootstrap`, `ops` or `viewer`")]
    Role,
    /// A bundle file map that lacks a managed file.
    #[error("bundle lacks managed file {file:?}")]
    MissingManagedFile {
        /// The first missing file.
        file: ManagedFile,
    },
    /// Two watch conditions of the same kind.
    #[error("watch condition {kind:?} appears more than once")]
    DuplicateWatchCondition {
        /// The repeated kind.
        kind: WatchErrorKind,
    },
    /// A usage span that is not whole bins: `from` or `to` off a bin
    /// boundary, or `from` not before `to`.
    #[error("not whole bins: from and to must lie on bin boundaries, from before to")]
    SeriesSpan,
    /// A `UsageSeries` range longer than its resolution allows
    /// ([`crate::Resolution::max_bins`]).
    #[error("{bins} bins of {resolution:?} exceed the {max} one request may span", max = resolution.max_bins())]
    RangeTooLarge {
        /// The resolution.
        resolution: Resolution,
        /// The bins the range spans.
        bins: u64,
    },
    /// A usage bin that is empty or holds an entry with no traffic.
    #[error("a usage bin is empty or holds an entry with no traffic")]
    UsageBin,
    /// Usage bins out of order, repeated, off a bin boundary, outside the
    /// range, or holding more than [`MAX_SERIES_ENTRIES`] entries.
    #[error("usage bins are out of order, outside the range, or over {MAX_SERIES_ENTRIES} entries")]
    UsageSeries,
    /// Events not numbered consecutively upwards, numbered at or after the
    /// journal end, or more than [`MAX_EVENTS`] of them.
    #[error(
        "events are not numbered consecutively, are at or after the journal end, or are over {MAX_EVENTS}"
    )]
    Events,
    /// A set of inbounds that is empty, out of [`crate::Inbound::ALL`]
    /// order, or names an inbound twice.
    #[error("not a non-empty list of inbounds in order, each at most once")]
    InboundSet,
    /// Not a valid [`crate::NodeName`].
    #[error("not a node name")]
    NodeName,
    /// Not a valid [`crate::ReportUserId`].
    #[error("not a report user id")]
    ReportUserId,
    /// A band number outside [`crate::ReportBandNumber`]'s 1..=999.
    #[error("band number {number} is outside 1..=999")]
    ReportBandNumber {
        /// The rejected number.
        number: u16,
    },
    /// A Mac report that breaks one of its rules ([`crate::MacReportV1`]).
    #[error("the Mac report breaks its rule: {rule}")]
    MacReport {
        /// The rule.
        rule: MacReportRule,
    },
    /// Not a valid [`crate::NoticeTitle`].
    #[error("not a notice title")]
    NoticeTitle,
    /// Not a valid [`crate::NoticeBody`].
    #[error("not a notice body")]
    NoticeBody,
}

closed_enum! {
    /// The variant of a [`ValueError`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum ValueErrorKind {
        /// [`ValueError::Sha256Hex`].
        Sha256Hex,
        /// [`ValueError::BlobTooLarge`].
        BlobTooLarge,
        /// [`ValueError::IfName`].
        IfName,
        /// [`ValueError::KernelRelease`].
        KernelRelease,
        /// [`ValueError::KernelIdent`].
        KernelIdent,
        /// [`ValueError::PortRange`].
        PortRange,
        /// [`ValueError::TargetHost`].
        TargetHost,
        /// [`ValueError::UnitName`].
        UnitName,
        /// [`ValueError::CertName`].
        CertName,
        /// [`ValueError::RedirectUrl`].
        RedirectUrl,
        /// [`ValueError::SshEd25519Key`].
        SshEd25519Key,
        /// [`ValueError::StderrTail`].
        StderrTail,
        /// [`ValueError::UsageMonth`].
        UsageMonth,
        /// [`ValueError::OpaqueUserId`].
        OpaqueUserId,
        /// [`ValueError::StatsEmail`].
        StatsEmail,
        /// [`ValueError::HttpStatus`].
        HttpStatus,
        /// [`ValueError::Role`].
        Role,
        /// [`ValueError::MissingManagedFile`].
        MissingManagedFile,
        /// [`ValueError::DuplicateWatchCondition`].
        DuplicateWatchCondition,
        /// [`ValueError::SeriesSpan`].
        SeriesSpan,
        /// [`ValueError::RangeTooLarge`].
        RangeTooLarge,
        /// [`ValueError::UsageBin`].
        UsageBin,
        /// [`ValueError::UsageSeries`].
        UsageSeries,
        /// [`ValueError::Events`].
        Events,
        /// [`ValueError::InboundSet`].
        InboundSet,
        /// [`ValueError::NodeName`].
        NodeName,
        /// [`ValueError::ReportUserId`].
        ReportUserId,
        /// [`ValueError::ReportBandNumber`].
        ReportBandNumber,
        /// [`ValueError::MacReport`].
        MacReport,
        /// [`ValueError::NoticeTitle`].
        NoticeTitle,
        /// [`ValueError::NoticeBody`].
        NoticeBody,
    }
}

impl ValueError {
    /// The variant, without its data.
    pub const fn kind(&self) -> ValueErrorKind {
        match self {
            Self::Sha256Hex => ValueErrorKind::Sha256Hex,
            Self::BlobTooLarge { .. } => ValueErrorKind::BlobTooLarge,
            Self::IfName => ValueErrorKind::IfName,
            Self::KernelRelease => ValueErrorKind::KernelRelease,
            Self::KernelIdent => ValueErrorKind::KernelIdent,
            Self::PortRange => ValueErrorKind::PortRange,
            Self::TargetHost => ValueErrorKind::TargetHost,
            Self::UnitName => ValueErrorKind::UnitName,
            Self::CertName => ValueErrorKind::CertName,
            Self::RedirectUrl => ValueErrorKind::RedirectUrl,
            Self::SshEd25519Key => ValueErrorKind::SshEd25519Key,
            Self::StderrTail => ValueErrorKind::StderrTail,
            Self::UsageMonth => ValueErrorKind::UsageMonth,
            Self::OpaqueUserId => ValueErrorKind::OpaqueUserId,
            Self::StatsEmail => ValueErrorKind::StatsEmail,
            Self::HttpStatus { .. } => ValueErrorKind::HttpStatus,
            Self::Role => ValueErrorKind::Role,
            Self::MissingManagedFile { .. } => ValueErrorKind::MissingManagedFile,
            Self::DuplicateWatchCondition { .. } => ValueErrorKind::DuplicateWatchCondition,
            Self::SeriesSpan => ValueErrorKind::SeriesSpan,
            Self::RangeTooLarge { .. } => ValueErrorKind::RangeTooLarge,
            Self::UsageBin => ValueErrorKind::UsageBin,
            Self::UsageSeries => ValueErrorKind::UsageSeries,
            Self::Events => ValueErrorKind::Events,
            Self::InboundSet => ValueErrorKind::InboundSet,
            Self::NodeName => ValueErrorKind::NodeName,
            Self::ReportUserId => ValueErrorKind::ReportUserId,
            Self::ReportBandNumber { .. } => ValueErrorKind::ReportBandNumber,
            Self::MacReport { .. } => ValueErrorKind::MacReport,
            Self::NoticeTitle => ValueErrorKind::NoticeTitle,
            Self::NoticeBody => ValueErrorKind::NoticeBody,
        }
    }
}

/// The agent's typed failure, sent as `{"Err": …}` (design §14, "agent
/// (remote)"). After any of these the VPS is at its last good generation or
/// stopped; re-applying is idempotent.
///
/// Free text never appears: tool output travels only as a [`StderrTail`],
/// which is bounded, scrubbed of the bundle's secrets and escaped.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AgentError {
    /// A blob does not hash to its declared digest (Level 1: accidental
    /// corruption or the wrong artifact).
    #[error("blob hashes to {actual}, expected {expected}")]
    BlobHash {
        /// The digest the request or bundle declared.
        expected: Sha256Hex,
        /// The digest of the bytes received or stored.
        actual: Sha256Hex,
    },
    /// A blob named by `ActivateAgent` or a bundle is not in the blob store.
    #[error("blob {sha256} is not in the blob store")]
    BlobMissing {
        /// The missing blob.
        sha256: Sha256Hex,
    },
    /// The `PutBlob` payload ended before `len` bytes.
    #[error("blob payload ended after {received} of {expected} bytes")]
    BlobTruncated {
        /// The declared length.
        expected: u64,
        /// The bytes that arrived.
        received: u64,
    },
    /// Input continued after the request frame (after the line, or after
    /// the `PutBlob` payload).
    #[error("input continues after the request frame")]
    TrailingInput,
    /// A staged file failed its validator (§11.2 step 3); nothing was
    /// switched.
    #[error("staged configuration rejected by {tool:?}")]
    StageValidation {
        /// The validator that rejected the staged files.
        tool: ValidationTool,
        /// Its scrubbed stderr.
        stderr_tail: StderrTail,
    },
    /// `apt-get` failed during `Bootstrap`.
    #[error("apt failed")]
    Apt {
        /// Its scrubbed stderr.
        stderr_tail: StderrTail,
    },
    /// A systemd operation on one unit failed.
    #[error("systemd could not {op:?} {unit}")]
    Systemd {
        /// The unit.
        unit: UnitName,
        /// The operation.
        op: SystemdOp,
    },
    /// The local health gate (§11.2 step 6) failed outside a transaction,
    /// for example after `Resume` restarted the engines.
    #[error("local health gate failed at {failed:?}")]
    HealthGate {
        /// The first check, in gate order, that had not passed when the
        /// budget ran out.
        failed: HealthCheck,
    },
    /// The transaction failed after the swap and the previous generation was
    /// restored (§11.2 step 8).
    #[error("generation {generation} was rolled back")]
    RolledBack {
        /// The generation that failed.
        generation: Generation,
        /// Why it was rolled back.
        cause: RollbackCause,
    },
    /// The rollback itself failed; both engines are stopped and the gate is
    /// closed.
    #[error("rollback of generation {generation} failed; engines stopped, gate closed")]
    RollbackFailed {
        /// The generation that failed.
        generation: Generation,
        /// Why the rollback was started.
        cause: RollbackCause,
    },
    /// The confirm timer fired before `Confirm` arrived, and the change was
    /// reverted exactly as for a rollback.
    #[error("generation {generation} was reverted because it was not confirmed in time")]
    RevertedUnconfirmed {
        /// The generation (for an agent activation, the generation that was
        /// current while it was pending).
        generation: Generation,
    },
    /// The new agent's `self-test` failed; nothing was switched.
    #[error("new agent failed its self-test")]
    AgentSelfTestFailed {
        /// Its scrubbed stderr.
        stderr_tail: StderrTail,
    },
    /// The running agent's binary does not hash to `Bootstrap`'s
    /// `expected_agent_sha`.
    #[error("running agent hashes to {actual}, expected {expected}")]
    AgentShaMismatch {
        /// The digest the Mac expected.
        expected: Sha256Hex,
        /// The running agent's digest.
        actual: Sha256Hex,
    },
    /// Another transaction or activation is running or awaiting confirmation
    /// (`flock` on `/run/mooring/txn.lock`).
    #[error("generation {generation} holds the transaction lock")]
    Busy {
        /// The generation of the transaction holding the lock.
        generation: Generation,
    },
    /// `Apply` carried a generation that is not newer than the current one,
    /// with a different digest.
    #[error("generation is not newer than the current generation {current}")]
    GenerationNotNewer {
        /// The node's current generation.
        current: Generation,
    },
    /// `Resume` named a generation other than the current one.
    #[error("the current generation is {current}")]
    GenerationMismatch {
        /// The node's current generation.
        current: Generation,
    },
    /// `Confirm` or `Rollback` found no change awaiting confirmation under
    /// that generation.
    #[error("nothing awaits confirmation under that generation")]
    NotAwaitingConfirm,
    /// `TxnStatus` named a generation the agent has no record of.
    #[error("no transaction is recorded for generation {generation}")]
    UnknownTransaction {
        /// The generation asked about.
        generation: Generation,
    },
    /// The node is halted; only `Resume` clears it.
    #[error("the node is halted")]
    NodeHalted,
    /// `Resume` arrived while the node was not halted.
    #[error("the node is not halted")]
    NotHalted,
    /// A live host fact differs from the bundle's recorded facts. A changed
    /// `ip_local_port_range` is reported as [`AgentError::PortPlanConflict`]
    /// instead (see [`crate::HostFacts::check_live`]).
    #[error("host fact {field:?} changed")]
    HostFactsChanged {
        /// The first fact, in [`HostFact::ALL`] order, that differs.
        field: HostFact,
    },
    /// A live host fact could not be read, or is ambiguous (for example
    /// several IPv4 addresses on the uplink).
    #[error("host fact {field:?} could not be determined")]
    HostFactUnavailable {
        /// The fact.
        field: HostFact,
    },
    /// The live `ip_local_port_range` differs from the range the bundle's
    /// port plan was checked against, so the plan's guarantee (fixed ports
    /// outside it, hop ranges above it) no longer holds.
    #[error("ip_local_port_range is {live}, but the port plan was checked against {recorded}")]
    PortPlanConflict {
        /// The range in the bundle's host facts.
        recorded: PortRange,
        /// The node's live range.
        live: PortRange,
    },
    /// `TargetCheck` could not collect its facts.
    #[error("target facts could not be collected ({tool:?})")]
    TargetFactsUnavailable {
        /// The collector that failed.
        tool: TargetTool,
        /// Its scrubbed stderr.
        stderr_tail: StderrTail,
    },
    /// No accounting file exists for the month.
    #[error("no usage is recorded for {month}")]
    NoUsageRecorded {
        /// The month asked about.
        month: UsageMonth,
    },
    /// The `UsageSeries` range holds more entries than one reply carries
    /// ([`crate::MAX_SERIES_ENTRIES`]); its first `fitting_bins` bins fit,
    /// so the Mac asks for those. Zero means one bin alone holds more
    /// entries than a reply carries.
    #[error(
        "the range holds more usage entries than one reply carries; its first {fitting_bins} bins fit"
    )]
    SeriesTooLarge {
        /// How many bins from the start of the range fit one reply.
        fitting_bins: u32,
    },
    /// The agent does not hold every bin of the `UsageSeries` range: part
    /// of it is older than the bins it keeps, or not yet complete. A
    /// missing bin is never reported as zero traffic.
    #[error("the agent does not hold every bin of the requested range")]
    SeriesNotRecorded {
        /// The span, at the requested resolution, whose every bin the
        /// agent holds; `None` when it holds none.
        #[serde(deserialize_with = "Option::deserialize")]
        recorded: Option<SeriesSpan>,
    },
    /// `MacReport` found no stored report: the Mac has not sent one since
    /// the node was set up. It is never answered with an empty report.
    #[error("no Mac report is stored")]
    MacReportMissing,
    /// A viewer's `GateSet{Operator}` was handed to the watch, which did not
    /// record the Operator hold and close the gate within
    /// [`crate::VIEWER_STOP_WAIT_SECS`] (design §11.3): the viewer account
    /// cannot write either itself. The gate may still be open, so the stop
    /// is not done; it is never answered as `GateClosed`.
    #[error("the stop was not confirmed within {waited_secs} s; the gate may still be open")]
    GateStopUnconfirmed {
        /// How long the handler waited for the watch.
        waited_secs: u64,
    },
    /// `nft` failed while closing the gate.
    #[error("closing the gate failed")]
    GateCloseFailed {
        /// Its scrubbed stderr.
        stderr_tail: StderrTail,
    },
    /// An I/O operation on the agent's own state failed.
    #[error("{op:?} failed ({})", describe_errno(.errno))]
    Io {
        /// What the agent was doing.
        op: IoOp,
        /// The OS error number, when the failure came from the OS.
        #[serde(deserialize_with = "Option::deserialize")]
        errno: Option<i32>,
    },
    /// The request is not permitted for the role of the SSH key that sent it
    /// (see [`Role::permits`]).
    #[error("role {role} may not send {request:?}")]
    RoleNotPermitted {
        /// The role of the connecting key.
        role: Role,
        /// The refused request.
        request: RequestKind,
    },
    /// `GateSet` named a reason the role may not close the gate for (see
    /// [`Role::may_close_gate_for`]): a viewer may close it for the
    /// operator hold only. Nothing was changed.
    #[error("role {role} may not close the gate for {reason:?}")]
    GateReasonNotPermitted {
        /// The role of the connecting key.
        role: Role,
        /// The refused reason.
        reason: GateReason,
    },
    /// Input that is not a request this agent understands: empty, not
    /// newline-terminated, not JSON, an unknown request or field, or an
    /// invalid value. `ssh … true` against the forced command yields this.
    #[error("not a request this agent understands")]
    UnknownRequest,
    /// The request line exceeds [`crate::MAX_REQUEST_LINE_BYTES`].
    #[error("the request line exceeds the frame limit")]
    RequestTooLarge,
}

closed_enum! {
    /// The variant of an [`AgentError`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum AgentErrorKind {
        /// [`AgentError::BlobHash`].
        BlobHash,
        /// [`AgentError::BlobMissing`].
        BlobMissing,
        /// [`AgentError::BlobTruncated`].
        BlobTruncated,
        /// [`AgentError::TrailingInput`].
        TrailingInput,
        /// [`AgentError::StageValidation`].
        StageValidation,
        /// [`AgentError::Apt`].
        Apt,
        /// [`AgentError::Systemd`].
        Systemd,
        /// [`AgentError::HealthGate`].
        HealthGate,
        /// [`AgentError::RolledBack`].
        RolledBack,
        /// [`AgentError::RollbackFailed`].
        RollbackFailed,
        /// [`AgentError::RevertedUnconfirmed`].
        RevertedUnconfirmed,
        /// [`AgentError::AgentSelfTestFailed`].
        AgentSelfTestFailed,
        /// [`AgentError::AgentShaMismatch`].
        AgentShaMismatch,
        /// [`AgentError::Busy`].
        Busy,
        /// [`AgentError::GenerationNotNewer`].
        GenerationNotNewer,
        /// [`AgentError::GenerationMismatch`].
        GenerationMismatch,
        /// [`AgentError::NotAwaitingConfirm`].
        NotAwaitingConfirm,
        /// [`AgentError::UnknownTransaction`].
        UnknownTransaction,
        /// [`AgentError::NodeHalted`].
        NodeHalted,
        /// [`AgentError::NotHalted`].
        NotHalted,
        /// [`AgentError::HostFactsChanged`].
        HostFactsChanged,
        /// [`AgentError::HostFactUnavailable`].
        HostFactUnavailable,
        /// [`AgentError::PortPlanConflict`].
        PortPlanConflict,
        /// [`AgentError::TargetFactsUnavailable`].
        TargetFactsUnavailable,
        /// [`AgentError::NoUsageRecorded`].
        NoUsageRecorded,
        /// [`AgentError::SeriesTooLarge`].
        SeriesTooLarge,
        /// [`AgentError::SeriesNotRecorded`].
        SeriesNotRecorded,
        /// [`AgentError::MacReportMissing`].
        MacReportMissing,
        /// [`AgentError::GateStopUnconfirmed`].
        GateStopUnconfirmed,
        /// [`AgentError::GateCloseFailed`].
        GateCloseFailed,
        /// [`AgentError::Io`].
        Io,
        /// [`AgentError::RoleNotPermitted`].
        RoleNotPermitted,
        /// [`AgentError::GateReasonNotPermitted`].
        GateReasonNotPermitted,
        /// [`AgentError::UnknownRequest`].
        UnknownRequest,
        /// [`AgentError::RequestTooLarge`].
        RequestTooLarge,
    }
}

impl AgentError {
    /// The variant, without its data.
    pub const fn kind(&self) -> AgentErrorKind {
        match self {
            Self::BlobHash { .. } => AgentErrorKind::BlobHash,
            Self::BlobMissing { .. } => AgentErrorKind::BlobMissing,
            Self::BlobTruncated { .. } => AgentErrorKind::BlobTruncated,
            Self::TrailingInput => AgentErrorKind::TrailingInput,
            Self::StageValidation { .. } => AgentErrorKind::StageValidation,
            Self::Apt { .. } => AgentErrorKind::Apt,
            Self::Systemd { .. } => AgentErrorKind::Systemd,
            Self::HealthGate { .. } => AgentErrorKind::HealthGate,
            Self::RolledBack { .. } => AgentErrorKind::RolledBack,
            Self::RollbackFailed { .. } => AgentErrorKind::RollbackFailed,
            Self::RevertedUnconfirmed { .. } => AgentErrorKind::RevertedUnconfirmed,
            Self::AgentSelfTestFailed { .. } => AgentErrorKind::AgentSelfTestFailed,
            Self::AgentShaMismatch { .. } => AgentErrorKind::AgentShaMismatch,
            Self::Busy { .. } => AgentErrorKind::Busy,
            Self::GenerationNotNewer { .. } => AgentErrorKind::GenerationNotNewer,
            Self::GenerationMismatch { .. } => AgentErrorKind::GenerationMismatch,
            Self::NotAwaitingConfirm => AgentErrorKind::NotAwaitingConfirm,
            Self::UnknownTransaction { .. } => AgentErrorKind::UnknownTransaction,
            Self::NodeHalted => AgentErrorKind::NodeHalted,
            Self::NotHalted => AgentErrorKind::NotHalted,
            Self::HostFactsChanged { .. } => AgentErrorKind::HostFactsChanged,
            Self::HostFactUnavailable { .. } => AgentErrorKind::HostFactUnavailable,
            Self::PortPlanConflict { .. } => AgentErrorKind::PortPlanConflict,
            Self::TargetFactsUnavailable { .. } => AgentErrorKind::TargetFactsUnavailable,
            Self::NoUsageRecorded { .. } => AgentErrorKind::NoUsageRecorded,
            Self::SeriesTooLarge { .. } => AgentErrorKind::SeriesTooLarge,
            Self::SeriesNotRecorded { .. } => AgentErrorKind::SeriesNotRecorded,
            Self::MacReportMissing => AgentErrorKind::MacReportMissing,
            Self::GateStopUnconfirmed { .. } => AgentErrorKind::GateStopUnconfirmed,
            Self::GateCloseFailed { .. } => AgentErrorKind::GateCloseFailed,
            Self::Io { .. } => AgentErrorKind::Io,
            Self::RoleNotPermitted { .. } => AgentErrorKind::RoleNotPermitted,
            Self::GateReasonNotPermitted { .. } => AgentErrorKind::GateReasonNotPermitted,
            Self::UnknownRequest => AgentErrorKind::UnknownRequest,
            Self::RequestTooLarge => AgentErrorKind::RequestTooLarge,
        }
    }
}

closed_enum! {
    /// A validator run on staged files (§11.2 step 3).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum ValidationTool {
        /// `xray run -test` on a warn-level copy with the staged geodata.
        Xray,
        /// `mooring-hy2 check` on a warn-level copy.
        Hy2,
        /// `nft -c -f`.
        Nft,
        /// `wg-quick strip`.
        WgQuick,
        /// `sshd -t -f` on the staged configuration.
        Sshd,
        /// `systemd-analyze verify` on the staged units.
        SystemdAnalyze,
        /// Every staged sysctl key exists under `/proc/sys`.
        SysctlKeys,
    }
}

closed_enum! {
    /// A step of the apply phase (§11.2 step 5).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum ApplyStep {
        /// `nft -f`.
        Nftables,
        /// `wg syncconf`, or a restart of `wg-quick@wgexit` when the address
        /// or MTU changed.
        WireGuard,
        /// `systemctl daemon-reload`.
        DaemonReload,
        /// `sysctl --system`.
        Sysctl,
        /// Reloading sshd.
        SshdReload,
        /// Restarting `mooring-xray` and `mooring-hy2`.
        EngineRestart,
    }
}

/// Why a transaction was rolled back (§11.2 step 8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RollbackCause {
    /// Renaming the symlinks into place failed (§11.2 step 4).
    Swap {
        /// The OS error number, when the failure came from the OS.
        #[serde(deserialize_with = "Option::deserialize")]
        errno: Option<i32>,
    },
    /// A step of the apply phase failed.
    Apply {
        /// The step.
        step: ApplyStep,
        /// Its scrubbed stderr.
        stderr_tail: StderrTail,
    },
    /// The local health gate did not pass within its budget.
    HealthGate {
        /// The first check, in gate order, that had not passed.
        failed: HealthCheck,
    },
}

closed_enum! {
    /// A check of the local health gate (§11.2 step 6), in gate order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum HealthCheck {
        /// The engine and tunnel units are active.
        UnitsActive,
        /// `ss -Hltnu` shows the expected listeners.
        Listeners,
        /// `xray api statssys` responds.
        XrayApi,
        /// `nft -j list set inet` [`crate::NFT_TABLE`] [`crate::NFT_GATE_SET`]
        /// succeeds.
        ExitClosedSet,
        /// The owner-guard rules for each [`crate::EngineUser`] are present.
        OwnerGuard,
        /// `net.ipv4.conf.<interface>.accept_local` of [`crate::WG_INTERFACE`]
        /// is 1.
        AcceptLocal,
    }
}

closed_enum! {
    /// A systemd operation the agent performs on a unit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum SystemdOp {
        /// `systemctl start`.
        Start,
        /// `systemctl stop`.
        Stop,
        /// `systemctl restart`.
        Restart,
        /// `systemctl enable`.
        Enable,
        /// `systemd-run` of a transient unit or timer.
        Run,
    }
}

closed_enum! {
    /// A collector used by `TargetCheck` (§11.7).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum TargetTool {
        /// Resolving the target's IPv4 addresses.
        Resolver,
        /// `xray tls ping`.
        XrayTlsPing,
        /// `curl --http2`.
        Curl,
        /// The repeated-handshake latency and first-flight measurement.
        HandshakeSampler,
    }
}

/// Describes an optional OS error number for an error message.
pub(crate) fn describe_errno(errno: &Option<i32>) -> String {
    match errno {
        Some(errno) => format!("errno {errno}"),
        None => "not an OS error".to_owned(),
    }
}

closed_enum! {
    /// An operation on the agent's own state that can fail with an I/O
    /// error.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum IoOp {
        /// Reading the request from stdin.
        ReadRequest,
        /// Writing a received blob into the blob store.
        WriteBlob,
        /// Reading a blob from the blob store.
        ReadBlob,
        /// Reading agent state (holds, halted marker, status, usage, …).
        ReadState,
        /// Writing agent state atomically.
        WriteState,
        /// Starting a helper process.
        SpawnProcess,
    }
}
