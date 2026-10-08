// SPDX-License-Identifier: GPL-3.0-or-later

//! One sample value of every request, response and error variant. The
//! matches are exhaustive, so adding a variant fails to compile here until
//! it has a sample, which every test that iterates `ALL` then covers.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use mooring_agent_proto::{
    AcceptLocal, AgentError, AgentErrorKind, AppliedGeneration, ApplyStep, Arch, BlobLen,
    BundleFiles, BundleHeader, ClearableHold, EgressViolationHold, EngineSet, GateReason,
    GateState, Generation, Halt, HealthCheck, HelloInfo, Holds, HostFact, HostFacts,
    HostProfileVersion, HttpProbe, HttpStatus, HttpVersion, IfName, IoOp, KernelIdent,
    KernelRelease, LineRequest, MacDrainHold, OperatorHold, PROTOCOL, PortRange, Request,
    RequestKind, Response, ResponseKind, Role, RollbackCause, Sha256Hex, ShutdownReason,
    SshEd25519Key, SshdDirective, StatusV1, StderrTail, SystemdOp, TargetFacts, TargetHost,
    TargetTool, TlsGroup, TlsProbe, TlsSession, TlsVersion, Traffic, TxnStage, TxnState, UnitName,
    UnixTime, UsageMonth, UsageV1, ValidationTool, WatchConditions, WatchConfig, WatchError,
    WatchTarget,
};

pub(crate) fn digest(byte: u8) -> Sha256Hex {
    Sha256Hex::from_bytes([byte; 32])
}

pub(crate) fn ops_key() -> SshEd25519Key {
    SshEd25519Key::new(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH",
    )
    .unwrap()
}

pub(crate) fn tail(text: &str) -> StderrTail {
    let tail = StderrTail::scrubbed(text.as_bytes(), &[]);
    assert_eq!(tail.as_str(), text, "fixture tails need no escaping");
    tail
}

pub(crate) fn host_facts() -> HostFacts {
    HostFacts {
        uplink: IfName::new("eth0").unwrap(),
        vps4: Ipv4Addr::new(203, 0, 113, 10),
        arch: Arch::Amd64,
        ip_local_port_range: PortRange::new(32768, 60999).unwrap(),
        debian_major: 13,
        kernel: KernelRelease::new("6.12.48+deb13-amd64").unwrap(),
        congestion_control: KernelIdent::new("bbr").unwrap(),
        qdisc: KernelIdent::new("fq").unwrap(),
    }
}

pub(crate) fn bundle_header() -> BundleHeader {
    BundleHeader {
        config_generation: Generation::new(7),
        digest: digest(0xd1),
        host_facts: host_facts(),
        host_profile_version: HostProfileVersion::new(1),
        files: BundleFiles::from_fn(|file| digest(0x10 + file as u8)),
        engines: EngineSet {
            xray: digest(0x21),
            hy2: digest(0x22),
            geoip: digest(0x23),
            geosite: digest(0x24),
        },
    }
}

pub(crate) fn holds() -> Holds {
    Holds {
        mac_drain: Some(MacDrainHold {
            handshake_at_drain: Some(UnixTime::from_secs(1_790_000_000)),
        }),
        egress_violation: None,
        operator: Some(OperatorHold {
            at: UnixTime::from_secs(1_790_000_100),
        }),
    }
}

pub(crate) fn hello_info() -> HelloInfo {
    HelloInfo {
        protocol: PROTOCOL,
        agent_sha: digest(0xa9),
        host_profile_version: HostProfileVersion::new(1),
        host: host_facts(),
        wgexit_accept_local: AcceptLocal::Enabled,
        sshd_mismatches: BTreeSet::from([SshdDirective::MaxAuthTries]),
        halted: None,
        holds: holds(),
        client_ip: Ipv4Addr::new(198, 51, 100, 20),
    }
}

pub(crate) fn status() -> StatusV1 {
    StatusV1 {
        now: UnixTime::from_secs(1_790_000_200),
        watch_at: UnixTime::from_secs(1_790_000_197),
        gate: GateState::Closed,
        holds: Holds {
            egress_violation: Some(EgressViolationHold {
                at: UnixTime::from_secs(1_790_000_150),
                generation: Generation::new(7),
            }),
            ..Holds::NONE
        },
        halted: Some(Halt {
            at: UnixTime::from_secs(1_790_000_160),
            reason: ShutdownReason::EgressIsNodeAddress,
        }),
        latest_handshake: Some(UnixTime::from_secs(1_790_000_190)),
        applied: Some(AppliedGeneration {
            generation: Generation::new(7),
            digest: digest(0xd1),
        }),
        conditions: WatchConditions::new([
            WatchError::TargetDegraded,
            WatchError::ExitFlowCapHit { count: 12 },
        ])
        .unwrap(),
    }
}

pub(crate) fn usage() -> UsageV1 {
    UsageV1 {
        month: UsageMonth::new(2026, 10).unwrap(),
        updated_at: UnixTime::from_secs(1_790_000_000),
        traffic: BTreeMap::from([
            (
                "u01@reality".parse().unwrap(),
                Traffic {
                    uplink: 10,
                    downlink: 2000,
                },
            ),
            (
                "probe@hy2".parse().unwrap(),
                Traffic {
                    uplink: 5,
                    downlink: 7,
                },
            ),
        ]),
    }
}

pub(crate) fn target_facts() -> TargetFacts {
    TargetFacts {
        host: TargetHost::new("www.example.com").unwrap(),
        resolved: BTreeSet::from([Ipv4Addr::new(198, 51, 100, 7)]),
        tls: TlsProbe::Completed(TlsSession {
            version: TlsVersion::Tls13,
            group: Some(TlsGroup::X25519_MLKEM768),
            chain_bytes: 4100,
            chain_certs: 2,
            leaf_names: vec![
                "www.example.com".parse().unwrap(),
                "*.example.com".parse().unwrap(),
            ],
            handshake_p95_micros: 1800,
            first_flight_bytes: 5200,
        }),
        http: HttpProbe::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
            redirect: None,
        },
    }
}

pub(crate) fn watch_config() -> WatchConfig {
    WatchConfig {
        keepalive_secs: NonZeroU16::new(10).unwrap(),
        target: WatchTarget {
            host: TargetHost::new("www.example.com").unwrap(),
            ipv4: Ipv4Addr::new(198, 51, 100, 7),
        },
    }
}

/// The fixture request of `kind`.
pub(crate) fn request(kind: RequestKind) -> Request {
    match kind {
        RequestKind::PutBlob => Request::PutBlob {
            sha256: digest(3),
            len: BlobLen::new(5).unwrap(),
        },
        line => Request::Line(line_request(line)),
    }
}

/// The fixture line request of `kind`; `PutBlob` has none.
pub(crate) fn line_request(kind: RequestKind) -> LineRequest {
    match kind {
        RequestKind::PutBlob => panic!("PutBlob is not a line request"),
        RequestKind::Hello => LineRequest::Hello,
        RequestKind::HaveBlobs => LineRequest::HaveBlobs {
            blobs: BTreeSet::from([digest(1), digest(2)]),
        },
        RequestKind::ActivateAgent => LineRequest::ActivateAgent { sha: digest(4) },
        RequestKind::Confirm => LineRequest::Confirm {
            generation: Generation::new(7),
        },
        RequestKind::Bootstrap => LineRequest::Bootstrap {
            expected_agent_sha: digest(4),
            ops_pubkey: ops_key(),
        },
        RequestKind::RevokeBootstrap => LineRequest::RevokeBootstrap,
        RequestKind::Apply => LineRequest::Apply(Box::new(bundle_header())),
        RequestKind::TxnStatus => LineRequest::TxnStatus {
            generation: Generation::new(7),
        },
        RequestKind::Rollback => LineRequest::Rollback,
        RequestKind::Status => LineRequest::Status,
        RequestKind::Usage => LineRequest::Usage {
            month: UsageMonth::new(2026, 10).unwrap(),
        },
        RequestKind::TargetCheck => LineRequest::TargetCheck {
            host: TargetHost::new("www.example.com").unwrap(),
        },
        RequestKind::GateSet => LineRequest::GateSet {
            reason: GateReason::MacDrain,
        },
        RequestKind::ClearHold => LineRequest::ClearHold {
            hold: ClearableHold::EgressViolation,
        },
        RequestKind::Shutdown => LineRequest::Shutdown {
            reason: ShutdownReason::Operator,
        },
        RequestKind::Resume => LineRequest::Resume {
            config_generation: Generation::new(7),
        },
    }
}

pub(crate) fn response(kind: ResponseKind) -> Response {
    match kind {
        ResponseKind::Hello => Response::Hello(Box::new(hello_info())),
        ResponseKind::Blobs => Response::Blobs {
            present: BTreeSet::from([digest(1)]),
        },
        ResponseKind::BlobStored => Response::BlobStored { sha256: digest(3) },
        ResponseKind::AwaitingConfirm => Response::AwaitingConfirm {
            generation: Generation::new(7),
        },
        ResponseKind::Confirmed => Response::Confirmed {
            generation: Generation::new(7),
        },
        ResponseKind::BootstrapDone => Response::BootstrapDone {
            host_pubkey: ops_key(),
        },
        ResponseKind::BootstrapRevoked => Response::BootstrapRevoked,
        ResponseKind::TxnLaunched => Response::TxnLaunched {
            generation: Generation::new(8),
        },
        ResponseKind::Unchanged => Response::Unchanged {
            generation: Generation::new(7),
        },
        ResponseKind::TxnStatus => Response::TxnStatus {
            generation: Generation::new(8),
            state: TxnState::Failed {
                error: agent_error(AgentErrorKind::RolledBack),
            },
        },
        ResponseKind::Reverted => Response::Reverted {
            generation: Generation::new(8),
        },
        ResponseKind::Status => Response::Status(Box::new(status())),
        ResponseKind::Usage => Response::Usage(Box::new(usage())),
        ResponseKind::TargetFacts => Response::TargetFacts(Box::new(target_facts())),
        ResponseKind::GateClosed => Response::GateClosed { holds: holds() },
        ResponseKind::HoldCleared => Response::HoldCleared { holds: Holds::NONE },
        ResponseKind::Halted => Response::Halted(Halt {
            at: UnixTime::from_secs(1_790_000_160),
            reason: ShutdownReason::Retire,
        }),
        ResponseKind::Resumed => Response::Resumed {
            generation: Generation::new(7),
        },
    }
}

pub(crate) fn txn_states() -> Vec<TxnState> {
    vec![
        TxnState::Running {
            stage: TxnStage::Validate,
        },
        TxnState::AwaitingConfirm,
        TxnState::Committed,
        TxnState::Reverted,
        TxnState::Failed {
            error: agent_error(AgentErrorKind::RevertedUnconfirmed),
        },
    ]
}

pub(crate) fn agent_error(kind: AgentErrorKind) -> AgentError {
    match kind {
        AgentErrorKind::BlobHash => AgentError::BlobHash {
            expected: digest(3),
            actual: digest(9),
        },
        AgentErrorKind::BlobMissing => AgentError::BlobMissing { sha256: digest(3) },
        AgentErrorKind::BlobTruncated => AgentError::BlobTruncated {
            expected: 5,
            received: 2,
        },
        AgentErrorKind::TrailingInput => AgentError::TrailingInput,
        AgentErrorKind::StageValidation => AgentError::StageValidation {
            tool: ValidationTool::Xray,
            stderr_tail: tail("invalid \"privateKey\": <redacted>"),
        },
        AgentErrorKind::Apt => AgentError::Apt {
            stderr_tail: tail("E: Unable to locate package"),
        },
        AgentErrorKind::Systemd => AgentError::Systemd {
            unit: UnitName::new("mooring-xray.service").unwrap(),
            op: SystemdOp::Restart,
        },
        AgentErrorKind::HealthGate => AgentError::HealthGate {
            failed: HealthCheck::Listeners,
        },
        AgentErrorKind::RolledBack => AgentError::RolledBack {
            generation: Generation::new(8),
            cause: RollbackCause::HealthGate {
                failed: HealthCheck::Listeners,
            },
        },
        AgentErrorKind::RollbackFailed => AgentError::RollbackFailed {
            generation: Generation::new(8),
            cause: RollbackCause::Apply {
                step: ApplyStep::Nftables,
                stderr_tail: tail("Error: syntax error"),
            },
        },
        AgentErrorKind::RevertedUnconfirmed => AgentError::RevertedUnconfirmed {
            generation: Generation::new(8),
        },
        AgentErrorKind::AgentSelfTestFailed => AgentError::AgentSelfTestFailed {
            stderr_tail: tail("self-test: bad profile"),
        },
        AgentErrorKind::AgentShaMismatch => AgentError::AgentShaMismatch {
            expected: digest(4),
            actual: digest(5),
        },
        AgentErrorKind::Busy => AgentError::Busy {
            generation: Generation::new(8),
        },
        AgentErrorKind::GenerationNotNewer => AgentError::GenerationNotNewer {
            current: Generation::new(8),
        },
        AgentErrorKind::GenerationMismatch => AgentError::GenerationMismatch {
            current: Generation::new(8),
        },
        AgentErrorKind::NotAwaitingConfirm => AgentError::NotAwaitingConfirm,
        AgentErrorKind::UnknownTransaction => AgentError::UnknownTransaction {
            generation: Generation::new(9),
        },
        AgentErrorKind::NodeHalted => AgentError::NodeHalted,
        AgentErrorKind::NotHalted => AgentError::NotHalted,
        AgentErrorKind::HostFactsChanged => AgentError::HostFactsChanged {
            field: HostFact::Uplink,
        },
        AgentErrorKind::HostFactUnavailable => AgentError::HostFactUnavailable {
            field: HostFact::Vps4,
        },
        AgentErrorKind::PortPlanConflict => AgentError::PortPlanConflict {
            recorded: PortRange::new(32768, 60999).unwrap(),
            live: PortRange::new(1024, 65535).unwrap(),
        },
        AgentErrorKind::TargetFactsUnavailable => AgentError::TargetFactsUnavailable {
            tool: TargetTool::Curl,
            stderr_tail: tail("curl: (6) Could not resolve host"),
        },
        AgentErrorKind::NoUsageRecorded => AgentError::NoUsageRecorded {
            month: UsageMonth::new(2026, 9).unwrap(),
        },
        AgentErrorKind::GateCloseFailed => AgentError::GateCloseFailed {
            stderr_tail: tail("Error: No such file or directory"),
        },
        AgentErrorKind::Io => AgentError::Io {
            op: IoOp::WriteBlob,
            errno: Some(28),
        },
        AgentErrorKind::RoleNotPermitted => AgentError::RoleNotPermitted {
            role: Role::Bootstrap,
            request: RequestKind::Apply,
        },
        AgentErrorKind::UnknownRequest => AgentError::UnknownRequest,
        AgentErrorKind::RequestTooLarge => AgentError::RequestTooLarge,
    }
}
