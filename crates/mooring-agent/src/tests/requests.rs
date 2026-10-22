// SPDX-License-Identifier: GPL-3.0-or-later

//! One well-formed request of each kind this slice does not serve yet.

use mooring_agent_proto::{
    Arch, BundleFiles, BundleHeader, EngineSet, EventSeq, Generation, HostFacts, HostProfile,
    IfName, KernelIdent, KernelRelease, LineRequest, PortRange, RequestKind, Resolution,
    SeriesRange, Sha256Hex, SshEd25519Key, TargetHost, UnixTime, UsageMonth,
};

fn sha(byte: u8) -> Sha256Hex {
    Sha256Hex::from_bytes([byte; 32])
}

fn header() -> BundleHeader {
    BundleHeader {
        config_generation: Generation::new(3),
        digest: sha(1),
        host_facts: HostFacts {
            uplink: IfName::new("eth0").unwrap(),
            vps4: "176.126.246.203".parse().unwrap(),
            arch: Arch::Amd64,
            ip_local_port_range: PortRange::new(32768, 60999).unwrap(),
            debian_major: 13,
            kernel: KernelRelease::new("6.12.113+deb13-cloud-amd64").unwrap(),
            congestion_control: KernelIdent::new("bbr").unwrap(),
            qdisc: KernelIdent::new("fq").unwrap(),
        },
        host_profile_version: HostProfile::CURRENT.version,
        files: BundleFiles::from_fn(|_| sha(2)),
        engines: EngineSet {
            xray: sha(3),
            hy2: sha(4),
            geoip: sha(5),
            geosite: sha(6),
        },
    }
}

/// A request of `kind`, which must be one this slice answers
/// `NotServedYet`.
pub(crate) fn of(kind: RequestKind) -> LineRequest {
    match kind {
        RequestKind::ActivateAgent => LineRequest::ActivateAgent { sha: sha(9) },
        RequestKind::Confirm => LineRequest::Confirm {
            generation: Generation::new(3),
        },
        RequestKind::Bootstrap => LineRequest::Bootstrap {
            expected_agent_sha: sha(9),
            ops_pubkey: SshEd25519Key::new(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJorFvPKBM2nffKXhBXe6XwDnyADfmqoqwkc/+lowutH",
            )
            .unwrap(),
        },
        RequestKind::RevokeBootstrap => LineRequest::RevokeBootstrap,
        RequestKind::Apply => LineRequest::Apply(Box::new(header())),
        RequestKind::TxnStatus => LineRequest::TxnStatus {
            generation: Generation::new(3),
        },
        RequestKind::Rollback => LineRequest::Rollback,
        RequestKind::Status => LineRequest::Status,
        RequestKind::Usage => LineRequest::Usage {
            month: UsageMonth::new(2026, 10).unwrap(),
        },
        RequestKind::UsageSeries => LineRequest::UsageSeries(
            SeriesRange::new(
                UnixTime::from_secs(1_791_331_200),
                UnixTime::from_secs(1_791_334_800),
                Resolution::Hour,
            )
            .unwrap(),
        ),
        RequestKind::Events => LineRequest::Events {
            since: EventSeq::FIRST,
        },
        RequestKind::TargetCheck => LineRequest::TargetCheck {
            host: TargetHost::new("www.example.org").unwrap(),
        },
        RequestKind::Resume => LineRequest::Resume {
            config_generation: Generation::new(3),
        },
        RequestKind::Hello
        | RequestKind::HaveBlobs
        | RequestKind::PutBlob
        | RequestKind::GateSet
        | RequestKind::ClearHold
        | RequestKind::Shutdown
        | RequestKind::PutMacReport
        | RequestKind::MacReport => panic!("{kind:?} is served"),
    }
}
