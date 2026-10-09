// SPDX-License-Identifier: GPL-3.0-or-later

//! Builders for unit tests of aggregate invariants. Test-only.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::num::NonZeroU64;

use crate::cert::CertificatePem;
use crate::collections::NonEmpty;
use crate::counters::ConfigGeneration;
use crate::date::CalendarDate;
use crate::deployment::{CapacityPolicy, DeploymentParts};
use crate::digest::Sha256Digest;
use crate::dns::DnsName;
use crate::exit::{EgressCheck, ExitSite, FlowCap, Pairing, ProbePolicy, TrafficPolicy, Uplink};
use crate::ids::{LocalLabel, NodeId, ShortId, UserId};
use crate::iface::{InterfaceSelector, LanSubnet, LinuxIfName, MacAddr};
use crate::ipv4::{CarrierPrefix, PublicIpv4};
use crate::keys::{Ed25519Pub, WgKey, X25519Pub};
use crate::node::{
    AppliedConfig, Arch, HostFacts, Hy2Server, Node, NodeAddress, NodeLifecycle, NodeRole,
    NodeSite, RealityServer, SshPin,
};
use crate::ports::{DEBIAN_EPHEMERAL_PORTS, PortPlan};
use crate::sim::{
    BillDay, Carrier, EvidenceRef, PILOT_SIM_HARD_STOP_BYTES, PILOT_SIM_WARN_BYTES, PlanKind,
    SimPlan, SimPolicy, StopPolicy,
};
use crate::target::{
    CertificateName, EvidenceUrl, HttpOutcome, HttpStatus, HttpVersion, KeyExchange,
    TargetAttestation, TargetFacts, TargetSpec, TlsHandshake, TlsOutcome, TlsVersion, qualify,
};
use crate::time::UnixTime;
use crate::user::{ClientLine, ClientProfile, User, UserNodePublic, UserPolicy, UserStatus};
use crate::wg::{Keepalive, WgIndex, WgLink};

pub(crate) fn node_id(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

pub(crate) fn user_id(n: u64) -> UserId {
    UserId::from_low_bits(n)
}

pub(crate) fn short_id(n: u8) -> ShortId {
    ShortId::from_bytes([0x5f, 0x1e, 0, 0, 0, 0, 0, n]).unwrap()
}

pub(crate) fn exit_site() -> ExitSite {
    ExitSite {
        egress: InterfaceSelector::LinkAddr {
            lladdr: MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
            subnet: LanSubnet::new("192.168.1.0/24".parse().unwrap()).unwrap(),
        },
        uplink: Uplink::SameAsExit,
        egress_check: EgressCheck {
            carrier_prefixes: NonEmpty::new(
                CarrierPrefix::new("31.120.0.0/14".parse().unwrap()).unwrap(),
            ),
            pairing: Pairing::Paired,
        },
        sim: SimPolicy::new(
            BillDay::new(1).unwrap(),
            smarty_unlimited_plan(),
            PILOT_SIM_WARN_BYTES,
            StopPolicy::HardStop {
                bytes: PILOT_SIM_HARD_STOP_BYTES,
            },
        )
        .unwrap(),
        probe: ProbePolicy::default(),
        flow_cap: FlowCap::new(4096).unwrap(),
        uplink_baseline: None,
    }
}

/// A fair-use line for tests that need one: 600 × 1024³ bytes.
pub(crate) const TEST_FAIR_USE_BYTES: NonZeroU64 = match NonZeroU64::new(600 << 30) {
    Some(bytes) => bytes,
    None => panic!("the test line is not zero"),
};

/// The decided line (F1): SMARTY Unlimited, no fair-use line, no speed cap,
/// recorded from SMARTY's Price Guide V42.
pub(crate) fn smarty_unlimited_plan() -> SimPlan {
    SimPlan {
        carrier: Carrier::Smarty,
        kind: PlanKind::Unlimited,
        speed_cap_mbps: None,
        terms: EvidenceRef {
            url: EvidenceUrl::parse(
                "https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf",
            )
            .unwrap(),
            dated: CalendarDate::parse("2026-08-25").unwrap(),
        },
    }
}

/// An unlimited plan with a fair-use line of [`TEST_FAIR_USE_BYTES`], for
/// the rules only a line exercises.
pub(crate) fn fair_use_plan() -> SimPlan {
    SimPlan {
        kind: PlanKind::UnlimitedFairUse {
            fair_use_bytes: TEST_FAIR_USE_BYTES,
        },
        ..smarty_unlimited_plan()
    }
}

pub(crate) fn site(addr: [u8; 4]) -> NodeSite {
    NodeSite {
        address: NodeAddress::Public(PublicIpv4::new(Ipv4Addr::from(addr)).unwrap()),
        host_facts: HostFacts {
            uplink_interface: LinuxIfName::parse("eth0").unwrap(),
            arch: Arch::Amd64,
            ephemeral_ports: DEBIAN_EPHEMERAL_PORTS,
        },
    }
}

pub(crate) fn applied(addr: [u8; 4], generation: u64) -> NodeLifecycle {
    NodeLifecycle::Applied {
        site: site(addr),
        applied: AppliedConfig {
            config_generation: ConfigGeneration::new(generation).unwrap(),
            digest: Sha256Digest::from_bytes([0xd1; 32]),
        },
    }
}

pub(crate) fn target_facts() -> TargetFacts {
    TargetFacts {
        host: DnsName::parse("www.harbour-target.test").unwrap(),
        resolved_ipv4: BTreeSet::from([Ipv4Addr::new(45, 67, 89, 200)]),
        tls: TlsOutcome::Completed(TlsHandshake {
            version: TlsVersion::Tls13,
            key_exchange: KeyExchange::X25519,
            certificate_names: BTreeSet::from([
                CertificateName::parse("www.harbour-target.test").unwrap()
            ]),
            handshake_p95_micros: 1_000,
            first_flight_bytes: 4_096,
        }),
        http: HttpOutcome::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
        },
    }
}

pub(crate) fn attestation() -> TargetAttestation {
    TargetAttestation {
        same_asn: true,
        not_cdn: true,
        evidence_url: EvidenceUrl::parse("https://evidence.mooring.test/target").unwrap(),
        at: UnixTime::from_secs(1_791_417_600),
    }
}

pub(crate) fn target() -> TargetSpec {
    qualify(&target_facts(), attestation())
        .unwrap()
        .into_target()
}

/// A node with a target; `seed` makes its keys distinct.
pub(crate) fn node(id: &str, wg_index: u8, seed: u8, lifecycle: NodeLifecycle) -> Node {
    Node {
        id: node_id(id),
        role: NodeRole::Primary,
        ports: PortPlan::with_defaults(DEBIAN_EPHEMERAL_PORTS).unwrap(),
        wg_index: WgIndex::new(wg_index).unwrap(),
        ssh: SshPin {
            host_ed25519: Ed25519Pub::from_bytes([seed; 32]).unwrap(),
        },
        reality: RealityServer {
            public_key: X25519Pub::from_bytes([seed.wrapping_add(1); 32]).unwrap(),
            probe_short_id: ShortId::from_bytes([0xa0, 0, 0, 0, 0, 0, 0, seed]).unwrap(),
            target: Some(target()),
        },
        hy2: Hy2Server {
            certificate: CertificatePem::from_der(&[0x30, 0x03, 0x02, 0x01, seed]).unwrap(),
        },
        wg: WgLink {
            vps_pub: WgKey::from_bytes([seed.wrapping_add(2); 32]).unwrap(),
            mac_pub: WgKey::from_bytes([seed.wrapping_add(3); 32]).unwrap(),
            keepalive: Keepalive::DEFAULT,
        },
        lifecycle,
    }
}

/// An active user holding credentials on `nodes` (`(node, short id byte)`).
pub(crate) fn user(n: u64, nodes: &[(&str, u8)]) -> User {
    User {
        id: user_id(n),
        label: LocalLabel::parse(&format!("User {n}")).unwrap(),
        client: ClientProfile {
            line: ClientLine::Cfm05,
            capabilities: BTreeSet::new(),
        },
        status: UserStatus::Active,
        per_node: nodes
            .iter()
            .map(|(node, short)| {
                (
                    node_id(node),
                    UserNodePublic {
                        short_id: short_id(*short),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        policy: UserPolicy::NONE,
        alias: None,
        agreement: None,
    }
}

/// Parts with lon1 and ams1 applied at generation 1 and two users on both.
pub(crate) fn two_node_parts() -> DeploymentParts {
    DeploymentParts {
        config_generation: ConfigGeneration::INITIAL,
        exit: exit_site(),
        policy: TrafficPolicy::default(),
        capacity: CapacityPolicy::UNLIMITED,
        auto_quota: None,
        alerting: None,
        viewers: Vec::new(),
        nodes: vec![
            node("lon1", 1, 10, applied([45, 67, 89, 10], 1)),
            node("ams1", 2, 20, applied([46, 78, 90, 12], 1)),
        ],
        users: vec![
            user(1, &[("lon1", 1), ("ams1", 1)]),
            user(2, &[("lon1", 2), ("ams1", 2)]),
        ],
        next_wg_index: WgIndex::new(3).unwrap(),
    }
}
