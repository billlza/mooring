// SPDX-License-Identifier: GPL-3.0-or-later

//! Property tests: every request and reply round-trips through JSON and
//! through the frame, an unknown key anywhere in a message is rejected, and
//! arbitrary input never makes a reader panic.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use mooring_agent_proto::{
    AcceptLocal, AgentError, AgentErrorKind, AgentEvent, AgentEventKind, AppliedGeneration,
    ApplyStep, Arch, BlobLen, BootstrapStep, BundleFiles, BundleHeader, CertName, ClearableHold,
    EgressViolationHold, EngineHealth, EngineRun, EngineSet, EngineState, EngineUser, EventSeq,
    EventsV1, GateReason, GateState, Generation, Halt, HealthCheck, HelloInfo, Holds, HostAccount,
    HostFact, HostFacts, HostHealth, HostProfileVersion, HttpProbe, HttpStatus, HttpVersion,
    IfName, Inbound, InboundSet, IoOp, KernelIdent, KernelRelease, LineRequest, MAX_BLOB_BYTES,
    MacDrainHold, OpaqueUserId, OperatorHold, PortRange, Principal, ReadError, RedirectUrl, Reply,
    Request, RequestKind, Resolution, Response, ResponseKind, Role, RollbackCause, SeriesRange,
    SeriesSpan, Sha256Hex, ShutdownReason, SshEd25519Key, SshdDirective, StatsEmail, StatusV1,
    StderrTail, StoredMacReport, SystemdOp, TargetFacts, TargetHost, TargetTool, TlsGroup,
    TlsProbe, TlsSession, TlsVersion, Traffic, TxnStage, TxnState, UnitName, UnixTime,
    UplinkTransfer, UsageBin, UsageMonth, UsageSeriesV1, UsageV1, ValidationTool, WatchConditions,
    WatchConfig, WatchError, WatchErrorKind, WatchTarget, expect_end_of_input, read_blob,
    read_reply, read_request, write_put_blob, write_reply, write_request,
};
use proptest::collection::{btree_map, btree_set, vec};
use proptest::option;
use proptest::prelude::*;
use proptest::sample::select;
use serde_json::Value;

use crate::{fixtures, report};

// ---- scalar strategies --------------------------------------------------

fn digest() -> impl Strategy<Value = Sha256Hex> {
    any::<[u8; 32]>().prop_map(Sha256Hex::from_bytes)
}

fn generation() -> impl Strategy<Value = Generation> {
    any::<u64>().prop_map(Generation::new)
}

fn unix_time() -> impl Strategy<Value = UnixTime> {
    any::<u64>().prop_map(UnixTime::from_secs)
}

fn errno() -> impl Strategy<Value = Option<i32>> {
    option::of(any::<i32>())
}

fn port_range() -> impl Strategy<Value = PortRange> {
    (1_u16..=u16::MAX)
        .prop_flat_map(|low| (Just(low), low..=u16::MAX))
        .prop_map(|(low, high)| PortRange::new(low, high).unwrap())
}

fn if_name() -> impl Strategy<Value = IfName> {
    "[a-z][a-z0-9_.-]{0,14}".prop_map(|text| IfName::new(text).unwrap())
}

fn kernel_ident() -> impl Strategy<Value = KernelIdent> {
    "[a-z0-9_-]{1,32}".prop_map(|text| KernelIdent::new(text).unwrap())
}

fn kernel_release() -> impl Strategy<Value = KernelRelease> {
    "[!-~]{1,64}".prop_map(|text| KernelRelease::new(text).unwrap())
}

fn target_host() -> impl Strategy<Value = TargetHost> {
    "([a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?\\.){0,4}[a-z]([a-z0-9-]{0,10}[a-z0-9])?"
        .prop_map(|text| TargetHost::new(text).unwrap())
}

fn unit_name() -> impl Strategy<Value = UnitName> {
    "[a-zA-Z0-9:_.@][a-zA-Z0-9:_.@\\\\-]{0,40}".prop_map(|text| UnitName::new(text).unwrap())
}

fn cert_name() -> impl Strategy<Value = CertName> {
    "[!-~]{1,64}".prop_map(|text| CertName::new(text).unwrap())
}

fn redirect_url() -> impl Strategy<Value = RedirectUrl> {
    "[!-~]{1,128}".prop_map(|text| RedirectUrl::new(text).unwrap())
}

fn ssh_key() -> impl Strategy<Value = SshEd25519Key> {
    "[A-P][A-Za-z0-9+/]{42}".prop_map(|variable| {
        SshEd25519Key::new(format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{variable}")).unwrap()
    })
}

fn stderr_tail() -> impl Strategy<Value = StderrTail> {
    (vec(any::<u8>(), 0..256), vec(vec(any::<u8>(), 0..8), 0..3)).prop_map(|(raw, secrets)| {
        let secrets: Vec<&[u8]> = secrets.iter().map(Vec::as_slice).collect();
        StderrTail::scrubbed(&raw, &secrets)
    })
}

fn usage_month() -> impl Strategy<Value = UsageMonth> {
    (1970_u16..=9999, 1_u8..=12).prop_map(|(year, month)| UsageMonth::new(year, month).unwrap())
}

fn stats_email() -> impl Strategy<Value = StatsEmail> {
    let user = "[A-Za-z0-9]{1,32}"
        .prop_filter("probe is not a user", |text| text != "probe")
        .prop_map(|text| Principal::User(OpaqueUserId::new(text).unwrap()));
    (
        prop_oneof![Just(Principal::Probe), user],
        select(Inbound::ALL),
    )
        .prop_map(|(principal, inbound)| StatsEmail { principal, inbound })
}

// ---- composite strategies -----------------------------------------------

fn host_facts() -> impl Strategy<Value = HostFacts> {
    (
        if_name(),
        any::<u32>().prop_map(Ipv4Addr::from),
        select(Arch::ALL),
        port_range(),
        any::<u16>(),
        kernel_release(),
        kernel_ident(),
        kernel_ident(),
    )
        .prop_map(
            |(
                uplink,
                vps4,
                arch,
                ip_local_port_range,
                debian_major,
                kernel,
                congestion_control,
                qdisc,
            )| HostFacts {
                uplink,
                vps4,
                arch,
                ip_local_port_range,
                debian_major,
                kernel,
                congestion_control,
                qdisc,
            },
        )
}

fn holds() -> impl Strategy<Value = Holds> {
    (
        option::of(
            option::of(unix_time())
                .prop_map(|handshake_at_drain| MacDrainHold { handshake_at_drain }),
        ),
        option::of(
            (unix_time(), generation())
                .prop_map(|(at, generation)| EgressViolationHold { at, generation }),
        ),
        option::of(unix_time().prop_map(|at| OperatorHold { at })),
    )
        .prop_map(|(mac_drain, egress_violation, operator)| Holds {
            mac_drain,
            egress_violation,
            operator,
        })
}

fn halt() -> impl Strategy<Value = Halt> {
    (unix_time(), select(ShutdownReason::ALL)).prop_map(|(at, reason)| Halt { at, reason })
}

fn hello_info() -> impl Strategy<Value = HelloInfo> {
    (
        any::<u32>(),
        digest(),
        any::<u32>().prop_map(HostProfileVersion::new),
        host_facts(),
        select(AcceptLocal::ALL),
        btree_set(select(SshdDirective::ALL), 0..4),
        option::of(halt()),
        holds(),
        any::<u32>().prop_map(Ipv4Addr::from),
    )
        .prop_map(
            |(
                protocol,
                agent_sha,
                host_profile_version,
                host,
                wgexit_accept_local,
                sshd_mismatches,
                halted,
                holds,
                client_ip,
            )| {
                HelloInfo {
                    protocol,
                    agent_sha,
                    host_profile_version,
                    host,
                    wgexit_accept_local,
                    sshd_mismatches,
                    halted,
                    holds,
                    client_ip,
                }
            },
        )
}

fn bundle_header() -> impl Strategy<Value = BundleHeader> {
    (
        generation(),
        digest(),
        host_facts(),
        any::<u32>().prop_map(HostProfileVersion::new),
        [digest(), digest(), digest(), digest(), digest(), digest()],
        [digest(), digest(), digest(), digest()],
    )
        .prop_map(
            |(config_generation, digest, host_facts, host_profile_version, files, engines)| {
                let [
                    xray_config,
                    hy2_config,
                    wg_conf,
                    nftables,
                    watch_config,
                    viewer_keys,
                ] = files;
                let [xray, hy2, geoip, geosite] = engines;
                BundleHeader {
                    config_generation,
                    digest,
                    host_facts,
                    host_profile_version,
                    files: BundleFiles {
                        xray_config,
                        hy2_config,
                        wg_conf,
                        nftables,
                        watch_config,
                        viewer_keys,
                    },
                    engines: EngineSet {
                        xray,
                        hy2,
                        geoip,
                        geosite,
                    },
                }
            },
        )
}

fn watch_error() -> impl Strategy<Value = WatchError> {
    prop_oneof![
        Just(WatchError::WgReadFailed),
        Just(WatchError::NftFailed),
        Just(WatchError::StatsQueryFailed),
        Just(WatchError::TargetDegraded),
        any::<u64>().prop_map(|count| WatchError::ExitFlowCapHit { count }),
        errno().prop_map(|errno| WatchError::StateWrite { errno }),
        option::of(unix_time()).prop_map(|since| WatchError::MacSilent { since }),
        any::<u64>().prop_map(|free| WatchError::DiskLow { free }),
        Just(WatchError::ClockUnsynced),
        unix_time().prop_map(|since| WatchError::RebootPending { since }),
        inbound_set().prop_map(|inbounds| WatchError::AccountingCanaryMissing { inbounds }),
    ]
}

fn engine_state() -> impl Strategy<Value = EngineState> {
    let run = prop_oneof![
        Just(EngineRun::Inactive),
        (any::<u64>(), option::of(any::<u64>())).prop_map(|(uptime_secs, go_heap_bytes)| {
            EngineRun::Active {
                uptime_secs,
                go_heap_bytes,
            }
        }),
    ];
    (any::<u32>(), run).prop_map(|(restarts, run)| EngineState { restarts, run })
}

fn engine_health() -> impl Strategy<Value = EngineHealth> {
    (engine_state(), engine_state()).prop_map(|(xray, hy2)| EngineHealth { xray, hy2 })
}

fn host_health() -> impl Strategy<Value = HostHealth> {
    (
        any::<u64>(),
        any::<u32>(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        any::<bool>(),
        option::of(unix_time()),
        any::<bool>(),
    )
        .prop_map(
            |(
                uptime_secs,
                load_milli,
                mem_available_bytes,
                disk_free_bytes,
                journal_bytes,
                reboot_required,
                last_unattended_upgrade,
                ntp_synced,
            )| HostHealth {
                uptime_secs,
                load_milli,
                mem_available_bytes,
                disk_free_bytes,
                journal_bytes,
                reboot_required,
                last_unattended_upgrade,
                ntp_synced,
            },
        )
}

fn uplink_transfer() -> impl Strategy<Value = UplinkTransfer> {
    (
        usage_month(),
        unix_time(),
        any::<u64>(),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(
            |(month, counted_from, rx_bytes, tx_bytes, counter_resets)| UplinkTransfer {
                month,
                counted_from,
                rx_bytes,
                tx_bytes,
                counter_resets,
            },
        )
}

/// A span of `1..=most` whole bins anywhere in `u64` time.
fn series_span_up_to(most: impl Fn(Resolution) -> u64) -> impl Strategy<Value = SeriesSpan> {
    select(Resolution::ALL)
        .prop_flat_map(move |resolution| {
            let width = resolution.bin_secs();
            let bins = most(resolution);
            (Just(resolution), 1..=bins, 0..=(u64::MAX / width - bins))
        })
        .prop_map(|(resolution, bins, first)| {
            let width = resolution.bin_secs();
            SeriesSpan::new(
                UnixTime::from_secs(first * width),
                UnixTime::from_secs((first + bins) * width),
                resolution,
            )
            .unwrap()
        })
}

fn series_range() -> impl Strategy<Value = SeriesRange> {
    series_span_up_to(Resolution::max_bins)
        .prop_map(|span| SeriesRange::new(span.from(), span.to(), span.resolution()).unwrap())
}

fn nonzero_traffic() -> impl Strategy<Value = Traffic> {
    (any::<u64>(), any::<u64>())
        .prop_filter("zero traffic is omitted", |(up, down)| {
            *up != 0 || *down != 0
        })
        .prop_map(|(uplink, downlink)| Traffic { uplink, downlink })
}

fn usage_series() -> impl Strategy<Value = UsageSeriesV1> {
    series_range()
        .prop_flat_map(|range| {
            let bins = range.span().bins();
            (
                Just(range),
                btree_map(
                    0..bins,
                    btree_map(stats_email(), nonzero_traffic(), 1..4),
                    0..6,
                ),
            )
        })
        .prop_map(|(range, bins)| {
            let span = range.span();
            let width = span.resolution().bin_secs();
            let bins = bins
                .into_iter()
                .map(|(index, traffic)| {
                    UsageBin::new(
                        UnixTime::from_secs(span.from().as_secs() + index * width),
                        traffic,
                    )
                    .unwrap()
                })
                .collect();
            UsageSeriesV1::new(range, bins).unwrap()
        })
}

fn agent_event_kind() -> impl Strategy<Value = AgentEventKind> {
    prop_oneof![
        watch_error().prop_map(|condition| AgentEventKind::ConditionRaised { condition }),
        select(WatchErrorKind::ALL)
            .prop_map(|condition| AgentEventKind::ConditionCleared { condition }),
        Just(AgentEventKind::GateOpened),
        Just(AgentEventKind::GateClosed),
        select(GateReason::ALL).prop_map(|hold| AgentEventKind::HoldRecorded { hold }),
        select(GateReason::ALL).prop_map(|hold| AgentEventKind::HoldCleared { hold }),
        select(ShutdownReason::ALL).prop_map(|reason| AgentEventKind::Halted { reason }),
        generation().prop_map(|generation| AgentEventKind::Resumed { generation }),
        generation().prop_map(|generation| AgentEventKind::Committed { generation }),
        select(EngineUser::ALL).prop_map(|engine| AgentEventKind::EngineRestarted { engine }),
        Just(AgentEventKind::HostBooted),
    ]
}

/// Every non-empty set of inbounds.
fn inbound_set() -> impl Strategy<Value = InboundSet> {
    prop_oneof![
        Just(InboundSet::of(Inbound::Reality)),
        Just(InboundSet::of(Inbound::Hy2)),
        Just(InboundSet::of(Inbound::Reality).with(Inbound::Hy2)),
    ]
}

/// A page: events numbered consecutively upwards from anywhere, below
/// `end`.
fn events() -> impl Strategy<Value = EventsV1> {
    (
        0..=u64::MAX / 2,
        vec((unix_time(), agent_event_kind()), 0..8),
        0..=1000_u64,
    )
        .prop_map(|(first, entries, after)| {
            let count = u64::try_from(entries.len()).unwrap();
            let events: Vec<AgentEvent> = (first..)
                .zip(entries)
                .map(|(seq, (at, kind))| AgentEvent {
                    seq: EventSeq::new(seq),
                    at,
                    kind,
                })
                .collect();
            EventsV1::new(events, EventSeq::new(first + count + after)).unwrap()
        })
}

fn watch_conditions() -> impl Strategy<Value = WatchConditions> {
    vec(watch_error(), 0..8).prop_map(|errors| {
        let mut seen = BTreeSet::new();
        let unique: Vec<_> = errors
            .into_iter()
            .filter(|error| seen.insert(error.kind()))
            .collect();
        WatchConditions::new(unique).unwrap()
    })
}

fn status() -> impl Strategy<Value = StatusV1> {
    let watch = (
        unix_time(),
        unix_time(),
        select(GateState::ALL),
        holds(),
        option::of(halt()),
        option::of(unix_time()),
        option::of(
            (generation(), digest())
                .prop_map(|(generation, digest)| AppliedGeneration { generation, digest }),
        ),
        watch_conditions(),
    );
    let health = (
        option::of(unix_time()),
        btree_map(stats_email(), unix_time(), 0..6),
        engine_health(),
        host_health(),
        uplink_transfer(),
    );
    (watch, health).prop_map(
        |(
            (now, watch_at, gate, holds, halted, latest_handshake, applied, conditions),
            (accounting_at, last_active, engines, host, transfer),
        )| {
            StatusV1 {
                now,
                watch_at,
                gate,
                holds,
                halted,
                latest_handshake,
                applied,
                conditions,
                accounting_at,
                last_active,
                engines,
                host,
                transfer,
            }
        },
    )
}

fn usage() -> impl Strategy<Value = UsageV1> {
    (
        usage_month(),
        unix_time(),
        btree_map(
            stats_email(),
            (any::<u64>(), any::<u64>())
                .prop_map(|(uplink, downlink)| Traffic { uplink, downlink }),
            0..6,
        ),
    )
        .prop_map(|(month, updated_at, traffic)| UsageV1 {
            month,
            updated_at,
            traffic,
        })
}

fn target_facts() -> impl Strategy<Value = TargetFacts> {
    let session = (
        select(TlsVersion::ALL),
        option::of(any::<u16>().prop_map(TlsGroup::new)),
        any::<u32>(),
        any::<u16>(),
        vec(cert_name(), 0..4),
        any::<u64>(),
        any::<u32>(),
    )
        .prop_map(
            |(
                version,
                group,
                chain_bytes,
                chain_certs,
                leaf_names,
                handshake_p95_micros,
                first_flight_bytes,
            )| {
                TlsSession {
                    version,
                    group,
                    chain_bytes,
                    chain_certs,
                    leaf_names,
                    handshake_p95_micros,
                    first_flight_bytes,
                }
            },
        );
    let tls = prop_oneof![
        Just(TlsProbe::ConnectFailed),
        Just(TlsProbe::HandshakeFailed),
        session.prop_map(TlsProbe::Completed),
    ];
    let http = prop_oneof![
        Just(HttpProbe::Failed),
        (
            100_u16..=599,
            select(HttpVersion::ALL),
            option::of(redirect_url())
        )
            .prop_map(|(status, version, redirect)| {
                HttpProbe::Responded {
                    status: HttpStatus::new(status).unwrap(),
                    version,
                    redirect,
                }
            }),
    ];
    (
        target_host(),
        btree_set(any::<u32>().prop_map(Ipv4Addr::from), 0..4),
        tls,
        http,
    )
        .prop_map(|(host, resolved, tls, http)| TargetFacts {
            host,
            resolved,
            tls,
            http,
        })
}

fn rollback_cause() -> impl Strategy<Value = RollbackCause> {
    prop_oneof![
        errno().prop_map(|errno| RollbackCause::Swap { errno }),
        (select(ApplyStep::ALL), stderr_tail())
            .prop_map(|(step, stderr_tail)| RollbackCause::Apply { step, stderr_tail }),
        select(HealthCheck::ALL).prop_map(|failed| RollbackCause::HealthGate { failed }),
    ]
}

fn agent_error() -> impl Strategy<Value = AgentError> {
    prop_oneof![
        (digest(), digest())
            .prop_map(|(expected, actual)| AgentError::BlobHash { expected, actual }),
        digest().prop_map(|sha256| AgentError::BlobMissing { sha256 }),
        (any::<u64>(), any::<u64>())
            .prop_map(|(expected, received)| AgentError::BlobTruncated { expected, received }),
        Just(AgentError::TrailingInput),
        (select(ValidationTool::ALL), stderr_tail())
            .prop_map(|(tool, stderr_tail)| AgentError::StageValidation { tool, stderr_tail }),
        stderr_tail().prop_map(|stderr_tail| AgentError::Apt { stderr_tail }),
        (select(BootstrapStep::ALL), stderr_tail())
            .prop_map(|(step, stderr_tail)| AgentError::Bootstrap { step, stderr_tail }),
        select(HostAccount::ALL).prop_map(|account| AgentError::AccountMissing { account }),
        (unit_name(), select(SystemdOp::ALL))
            .prop_map(|(unit, op)| AgentError::Systemd { unit, op }),
        select(HealthCheck::ALL).prop_map(|failed| AgentError::HealthGate { failed }),
        (generation(), rollback_cause())
            .prop_map(|(generation, cause)| AgentError::RolledBack { generation, cause }),
        (generation(), rollback_cause())
            .prop_map(|(generation, cause)| AgentError::RollbackFailed { generation, cause }),
        generation().prop_map(|generation| AgentError::RevertedUnconfirmed { generation }),
        stderr_tail().prop_map(|stderr_tail| AgentError::AgentSelfTestFailed { stderr_tail }),
        (digest(), digest())
            .prop_map(|(expected, actual)| AgentError::AgentShaMismatch { expected, actual }),
        generation().prop_map(|generation| AgentError::Busy { generation }),
        generation().prop_map(|current| AgentError::GenerationNotNewer { current }),
        generation().prop_map(|current| AgentError::GenerationMismatch { current }),
        Just(AgentError::NotAwaitingConfirm),
        generation().prop_map(|generation| AgentError::UnknownTransaction { generation }),
        Just(AgentError::NodeHalted),
        Just(AgentError::NotHalted),
        select(HostFact::ALL).prop_map(|field| AgentError::HostFactsChanged { field }),
        select(HostFact::ALL).prop_map(|field| AgentError::HostFactUnavailable { field }),
        (port_range(), port_range())
            .prop_map(|(recorded, live)| AgentError::PortPlanConflict { recorded, live }),
        (any::<u32>(), any::<u32>()).prop_map(|(required, supported)| {
            AgentError::HostProfileUnsupported {
                required: HostProfileVersion::new(required),
                supported: HostProfileVersion::new(supported),
            }
        }),
        (select(TargetTool::ALL), stderr_tail()).prop_map(|(tool, stderr_tail)| {
            AgentError::TargetFactsUnavailable { tool, stderr_tail }
        }),
        usage_month().prop_map(|month| AgentError::NoUsageRecorded { month }),
        any::<u32>().prop_map(|fitting_bins| AgentError::SeriesTooLarge { fitting_bins }),
        option::of(series_span_up_to(|_| 10_000))
            .prop_map(|recorded| AgentError::SeriesNotRecorded { recorded }),
        stderr_tail().prop_map(|stderr_tail| AgentError::GateCloseFailed { stderr_tail }),
        (select(IoOp::ALL), errno()).prop_map(|(op, errno)| AgentError::Io { op, errno }),
        (select(Role::ALL), select(RequestKind::ALL))
            .prop_map(|(role, request)| AgentError::RoleNotPermitted { role, request }),
        (select(Role::ALL), select(GateReason::ALL))
            .prop_map(|(role, reason)| AgentError::GateReasonNotPermitted { role, reason }),
        Just(AgentError::MacReportMissing),
        Just(AgentError::UnknownRequest),
        Just(AgentError::RequestTooLarge),
    ]
}

fn txn_state() -> impl Strategy<Value = TxnState> {
    prop_oneof![
        select(TxnStage::ALL).prop_map(|stage| TxnState::Running { stage }),
        Just(TxnState::AwaitingConfirm),
        Just(TxnState::Committed),
        Just(TxnState::Reverted),
        agent_error().prop_map(|error| TxnState::Failed { error }),
    ]
}

fn line_request() -> impl Strategy<Value = LineRequest> {
    prop_oneof![
        Just(LineRequest::Hello),
        btree_set(digest(), 0..8).prop_map(|blobs| LineRequest::HaveBlobs { blobs }),
        digest().prop_map(|sha| LineRequest::ActivateAgent { sha }),
        generation().prop_map(|generation| LineRequest::Confirm { generation }),
        (digest(), ssh_key(), ssh_key()).prop_map(
            |(expected_agent_sha, bootstrap_pubkey, ops_pubkey)| LineRequest::Bootstrap {
                expected_agent_sha,
                bootstrap_pubkey,
                ops_pubkey,
            }
        ),
        Just(LineRequest::RevokeBootstrap),
        bundle_header().prop_map(|header| LineRequest::Apply(Box::new(header))),
        generation().prop_map(|generation| LineRequest::TxnStatus { generation }),
        Just(LineRequest::Rollback),
        Just(LineRequest::Status),
        usage_month().prop_map(|month| LineRequest::Usage { month }),
        series_range().prop_map(LineRequest::UsageSeries),
        any::<u64>().prop_map(|since| LineRequest::Events {
            since: EventSeq::new(since)
        }),
        (target_host(), digest()).prop_map(|(host, xray)| LineRequest::TargetCheck { host, xray }),
        select(GateReason::ALL).prop_map(|reason| LineRequest::GateSet { reason }),
        select(ClearableHold::ALL).prop_map(|hold| LineRequest::ClearHold { hold }),
        select(ShutdownReason::ALL).prop_map(|reason| LineRequest::Shutdown { reason }),
        generation().prop_map(|config_generation| LineRequest::Resume { config_generation }),
        report::mac_report().prop_map(|report| LineRequest::PutMacReport(Box::new(report))),
        Just(LineRequest::MacReport),
    ]
}

fn request() -> impl Strategy<Value = Request> {
    prop_oneof![
        1 => (digest(), 0..=MAX_BLOB_BYTES).prop_map(|(sha256, len)| Request::PutBlob {
            sha256,
            len: BlobLen::new(len).unwrap()
        }),
        16 => line_request().prop_map(Request::Line),
    ]
}

fn response() -> impl Strategy<Value = Response> {
    prop_oneof![
        hello_info().prop_map(|info| Response::Hello(Box::new(info))),
        btree_set(digest(), 0..8).prop_map(|present| Response::Blobs { present }),
        digest().prop_map(|sha256| Response::BlobStored { sha256 }),
        generation().prop_map(|generation| Response::AwaitingConfirm { generation }),
        generation().prop_map(|generation| Response::Confirmed { generation }),
        ssh_key().prop_map(|host_pubkey| Response::BootstrapDone { host_pubkey }),
        Just(Response::BootstrapRevoked),
        generation().prop_map(|generation| Response::TxnLaunched { generation }),
        generation().prop_map(|generation| Response::Unchanged { generation }),
        (generation(), txn_state())
            .prop_map(|(generation, state)| Response::TxnStatus { generation, state }),
        generation().prop_map(|generation| Response::Reverted { generation }),
        status().prop_map(|status| Response::Status(Box::new(status))),
        usage().prop_map(|usage| Response::Usage(Box::new(usage))),
        usage_series().prop_map(|series| Response::UsageSeries(Box::new(series))),
        events().prop_map(|page| Response::Events(Box::new(page))),
        target_facts().prop_map(|facts| Response::TargetFacts(Box::new(facts))),
        holds().prop_map(|holds| Response::GateClosed { holds }),
        holds().prop_map(|holds| Response::HoldCleared { holds }),
        halt().prop_map(Response::Halted),
        generation().prop_map(|generation| Response::Resumed { generation }),
        unix_time().prop_map(|at| Response::MacReportStored { at }),
        (unix_time(), report::mac_report()).prop_map(|(received_at, report)| {
            Response::MacReport(Box::new(StoredMacReport {
                received_at,
                report,
            }))
        }),
    ]
}

fn reply() -> impl Strategy<Value = Reply> {
    prop_oneof![response().prop_map(Ok), agent_error().prop_map(Err)]
}

fn watch_config() -> impl Strategy<Value = WatchConfig> {
    (
        1_u16..=u16::MAX,
        target_host(),
        any::<u32>().prop_map(Ipv4Addr::from),
        btree_set(stats_email(), 0..4),
    )
        .prop_map(|(keepalive, host, ipv4, emails)| WatchConfig {
            keepalive_secs: NonZeroU16::new(keepalive).unwrap(),
            target: WatchTarget { host, ipv4 },
            emails,
        })
}

// ---- helpers -------------------------------------------------------------

/// Every JSON object in `value`, depth first, as a path of keys and indices.
fn object_paths(value: &Value, path: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    match value {
        Value::Object(map) => {
            out.push(path.clone());
            for (key, child) in map {
                path.push(Step::Key(key.clone()));
                object_paths(child, path, out);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                path.push(Step::Index(index));
                object_paths(child, path, out);
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

fn with_unknown_key(mut value: Value, path: &[Step]) -> Value {
    let mut node = &mut value;
    for step in path {
        node = match step {
            Step::Key(key) => node.get_mut(key.as_str()).unwrap(),
            Step::Index(index) => node.get_mut(*index).unwrap(),
        };
    }
    node.as_object_mut()
        .unwrap()
        .insert("zz_unknown".into(), Value::Bool(true));
    value
}

/// Asserts that adding an unknown key to any one object of `value`'s JSON
/// makes it undecodable as `T`, and that the unmodified JSON decodes.
fn assert_every_object_denies_unknown_keys<T>(value: &T, pick: usize) -> Result<(), TestCaseError>
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_value(value).unwrap();
    prop_assert_eq!(&serde_json::from_value::<T>(json.clone()).unwrap(), value);
    let mut paths = Vec::new();
    object_paths(&json, &mut Vec::new(), &mut paths);
    if let Some(path) = paths.get(pick % paths.len().max(1)) {
        let mutated = with_unknown_key(json, path);
        prop_assert!(
            serde_json::from_value::<T>(mutated.clone()).is_err(),
            "accepted {}",
            mutated
        );
    }
    Ok(())
}

// ---- properties ----------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn requests_round_trip_through_json_and_the_frame(request in request()) {
        let json = serde_json::to_string(&request).unwrap();
        prop_assert_eq!(&serde_json::from_str::<Request>(&json).unwrap(), &request);
        if let Request::Line(line) = &request {
            let mut frame = Vec::new();
            write_request(&mut frame, line).unwrap();
            prop_assert_eq!(frame.iter().filter(|byte| **byte == b'\n').count(), 1);
            let mut reader = Cursor::new(frame.as_slice());
            prop_assert_eq!(read_request(&mut reader).unwrap(), request);
            prop_assert!(expect_end_of_input(&mut reader).is_ok());
        }
    }

    #[test]
    fn put_blob_frames_carry_their_payload(sha256 in digest(), payload in vec(any::<u8>(), 0..4096)) {
        let mut frame = Vec::new();
        write_put_blob(&mut frame, sha256, &payload).unwrap();
        let mut reader = Cursor::new(frame.as_slice());
        let request = read_request(&mut reader).unwrap();
        let Request::PutBlob { sha256: received_sha, len } = request else {
            return Err(TestCaseError::fail("not a PutBlob"));
        };
        prop_assert_eq!(received_sha, sha256);
        prop_assert_eq!(len.get(), payload.len() as u64);
        let mut sink = Vec::new();
        read_blob(&mut reader, len, &mut sink).unwrap();
        prop_assert_eq!(sink, payload);
    }

    #[test]
    fn replies_round_trip_through_json_and_the_frame(reply in reply()) {
        let mut frame = Vec::new();
        write_reply(&mut frame, &reply).unwrap();
        prop_assert_eq!(frame.iter().filter(|byte| **byte == b'\n').count(), 1);
        prop_assert_eq!(read_reply(&mut Cursor::new(frame.as_slice())).unwrap(), reply);
    }

    #[test]
    fn an_unknown_key_in_any_request_object_is_rejected(request in request(), pick in any::<usize>()) {
        assert_every_object_denies_unknown_keys(&request, pick)?;
    }

    #[test]
    fn an_unknown_key_in_any_reply_object_is_rejected(reply in reply(), pick in any::<usize>()) {
        assert_every_object_denies_unknown_keys(&reply, pick)?;
    }

    #[test]
    fn an_unknown_key_in_watch_config_is_rejected(config in watch_config(), pick in any::<usize>()) {
        assert_every_object_denies_unknown_keys(&config, pick)?;
    }

    #[test]
    fn arbitrary_bytes_decode_canonically_or_fail_typed(bytes in vec(any::<u8>(), 0..512)) {
        match read_request(&mut Cursor::new(bytes.as_slice())) {
            Ok(request) => {
                let json = serde_json::to_string(&request).unwrap();
                prop_assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), request);
            }
            // Short input from memory can only be "not a request".
            Err(error) => prop_assert_eq!(error.to_agent_error(), AgentError::UnknownRequest),
        }
        match read_reply(&mut Cursor::new(bytes.as_slice())) {
            Ok(reply) => {
                let json = serde_json::to_string(&reply).unwrap();
                prop_assert_eq!(serde_json::from_str::<Reply>(&json).unwrap(), reply);
            }
            Err(error) => prop_assert!(
                matches!(
                    error,
                    ReadError::Empty | ReadError::Unterminated { .. } | ReadError::Malformed { .. } | ReadError::TrailingBytes
                ),
                "{error:?}"
            ),
        }
    }

    #[test]
    fn arbitrary_json_lines_decode_or_fail_typed(value in arbitrary_json()) {
        let mut line = serde_json::to_vec(&value).unwrap();
        line.push(b'\n');
        if let Err(error) = read_request(&mut Cursor::new(line.as_slice())) {
            prop_assert_eq!(error.to_agent_error(), AgentError::UnknownRequest);
        }
    }

    /// A received series is refused when a bin repeats, comes out of
    /// order, starts outside its range or off a bin boundary, or holds an
    /// entry with no traffic: absent bins mean zero traffic, so a series
    /// must be unambiguous.
    #[test]
    fn a_received_series_must_be_ordered_whole_bins_with_traffic(
        series in usage_series().prop_filter("has bins", |series| !series.bins().is_empty()),
        pick in any::<usize>(),
        how in 0..5_u8,
    ) {
        let span = series.range().span();
        let mut json = serde_json::to_value(&series).unwrap();
        let bins = json["bins"].as_array_mut().unwrap();
        let index = pick % bins.len();
        let start = bins[index]["start"].as_u64().unwrap();
        match how {
            1 if bins.len() >= 2 => {
                let last = bins.len() - 1;
                bins.swap(0, last);
            }
            0 | 1 => {
                let copy = bins[index].clone();
                bins.insert(index, copy);
            }
            2 => bins[index]["start"] = Value::from(span.to().as_secs()),
            3 => bins[index]["start"] = Value::from(start + 1),
            _ => {
                let traffic = bins[index]["traffic"].as_object_mut().unwrap();
                let first = traffic.keys().next().unwrap().clone();
                traffic.insert(first, serde_json::json!({"uplink": 0, "downlink": 0}));
            }
        }
        prop_assert!(serde_json::from_value::<UsageSeriesV1>(json.clone()).is_err(), "accepted {}", json);
    }

    /// A received journal page is refused when an event repeats, comes
    /// out of order or is missing from the middle, or when its end does not
    /// lie after every event.
    #[test]
    fn a_received_page_must_be_numbered_upwards_below_its_end(
        page in events().prop_filter("has events", |page| !page.events().is_empty()),
        pick in any::<usize>(),
        how in 0..4_u8,
    ) {
        let mut json = serde_json::to_value(&page).unwrap();
        let last = page.events().last().unwrap().seq.get();
        let events = json["events"].as_array_mut().unwrap();
        let index = pick % events.len();
        match how {
            0 => {
                let copy = events[index].clone();
                events.insert(index, copy);
            }
            1 if events.len() >= 2 => {
                let end = events.len() - 1;
                events.swap(0, end);
            }
            2 if events.len() >= 3 => {
                let inner = 1 + pick % (events.len() - 2);
                events.remove(inner);
            }
            _ => json["end"] = Value::from(last),
        }
        prop_assert!(serde_json::from_value::<EventsV1>(json.clone()).is_err(), "accepted {}", json);
    }
}

fn arbitrary_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<u64>().prop_map(Value::from),
        select(vec![
            "Hello",
            "Status",
            "Confirm",
            "PutBlob",
            "generation",
            "len",
            "sha256"
        ])
        .prop_map(|text| Value::String(text.to_owned())),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..4).prop_map(Value::Array),
            btree_map(
                select(vec![
                    "Hello",
                    "Confirm",
                    "PutBlob",
                    "generation",
                    "len",
                    "sha256",
                    "x"
                ]),
                inner,
                0..3
            )
            .prop_map(|map| Value::Object(
                map.into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect()
            )),
        ]
    })
}

#[test]
fn fixture_values_round_trip() {
    let config = fixtures::watch_config();
    let json = serde_json::to_string(&config).unwrap();
    assert_eq!(serde_json::from_str::<WatchConfig>(&json).unwrap(), config);
    let header = fixtures::bundle_header();
    assert_eq!(
        header.blobs().len(),
        10,
        "six files and four engines, all distinct"
    );
}

/// Asserts that `value` round-trips and that adding an unknown key to each
/// of its JSON objects, one at a time, makes it undecodable. Returns the
/// number of objects checked.
fn assert_each_object_denies_unknown_keys<T>(value: &T) -> usize
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_value(value).unwrap();
    assert_eq!(&serde_json::from_value::<T>(json.clone()).unwrap(), value);
    let mut paths = Vec::new();
    object_paths(&json, &mut Vec::new(), &mut paths);
    for path in &paths {
        let mutated = with_unknown_key(json.clone(), path);
        assert!(
            serde_json::from_value::<T>(mutated.clone()).is_err(),
            "accepted an unknown key at {path:?}: {mutated}"
        );
    }
    paths.len()
}

/// The deterministic companion of the sampled properties above: every
/// object of every fixture message is tried, so a type that drops
/// `deny_unknown_fields` (the frozen-core `HelloInfo` included) fails here
/// on every run.
#[test]
fn every_object_of_every_fixture_message_denies_unknown_keys() {
    let mut objects = 0;
    for kind in RequestKind::ALL {
        objects += assert_each_object_denies_unknown_keys(&fixtures::request(*kind));
    }
    for kind in ResponseKind::ALL {
        let reply: Reply = Ok(fixtures::response(*kind));
        objects += assert_each_object_denies_unknown_keys(&reply);
    }
    for kind in AgentErrorKind::ALL {
        let reply: Reply = Err(fixtures::agent_error(*kind));
        objects += assert_each_object_denies_unknown_keys(&reply);
    }
    for state in fixtures::txn_states() {
        let reply: Reply = Ok(Response::TxnStatus {
            generation: Generation::new(7),
            state,
        });
        objects += assert_each_object_denies_unknown_keys(&reply);
    }
    objects += assert_each_object_denies_unknown_keys(&fixtures::hello_info());
    objects += assert_each_object_denies_unknown_keys(&fixtures::status());
    objects += assert_each_object_denies_unknown_keys(&fixtures::usage());
    objects += assert_each_object_denies_unknown_keys(&fixtures::target_facts());
    objects += assert_each_object_denies_unknown_keys(&fixtures::bundle_header());
    objects += assert_each_object_denies_unknown_keys(&fixtures::host_facts());
    objects += assert_each_object_denies_unknown_keys(&fixtures::holds());
    objects += assert_each_object_denies_unknown_keys(&fixtures::watch_config());
    objects += assert_each_object_denies_unknown_keys(&fixtures::series_range());
    objects += assert_each_object_denies_unknown_keys(&fixtures::usage_series());
    objects += assert_each_object_denies_unknown_keys(&fixtures::events());
    objects += assert_each_object_denies_unknown_keys(&fixtures::engine_health());
    objects += assert_each_object_denies_unknown_keys(&fixtures::host_health());
    objects += assert_each_object_denies_unknown_keys(&fixtures::uplink_transfer());
    objects += assert_each_object_denies_unknown_keys(&fixtures::mac_report());
    objects += assert_each_object_denies_unknown_keys(&fixtures::stored_mac_report());
    for kind in WatchErrorKind::ALL {
        objects += assert_each_object_denies_unknown_keys(&fixtures::watch_error(*kind));
    }
    for event in fixtures::events().events() {
        objects += assert_each_object_denies_unknown_keys(event);
    }
    assert!(objects > 100, "only {objects} objects were checked");
}

/// Every object the new protocol-1 types add is among those the test
/// above tries: each health, series and journal object, every condition
/// with data and every event kind with data.
#[test]
fn the_new_objects_are_all_reached() {
    let paths = |value: Value| {
        let mut out = Vec::new();
        object_paths(&value, &mut Vec::new(), &mut out);
        out.len()
    };
    let status = serde_json::to_value(fixtures::status()).unwrap();
    for key in ["engines", "host", "transfer", "last_active"] {
        assert!(status[key].is_object(), "{key}");
    }
    assert!(status["engines"]["xray"]["run"]["Active"].is_object());
    assert_eq!(
        paths(serde_json::to_value(fixtures::events()).unwrap()),
        1 + 11 + 2 * 8 + 2,
        "the page, each event, the tag and fields of the 8 kinds with data, \
         and the tag and fields of the raised condition"
    );
    assert_eq!(
        paths(serde_json::to_value(fixtures::usage_series()).unwrap()),
        1 + 1 + 2 * 2 + 3,
        "the series, its range, each bin and its traffic, each entry"
    );
}
