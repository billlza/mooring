// SPDX-License-Identifier: GPL-3.0-or-later

//! Builders shared by the store's tests.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::net::Ipv4Addr;

use mooring_model::cert::CertificatePem;
use mooring_model::collections::NonEmpty;
use mooring_model::counters::ConfigGeneration;
use mooring_model::date::CalendarDate;
use mooring_model::deployment::{
    Bookkeeping, CapacityPolicy, Deployment, DeploymentInit, DeploymentParts,
};
use mooring_model::digest::Sha256Digest;
use mooring_model::dns::DnsName;
use mooring_model::exit::{
    EgressCheck, ExitSite, FlowCap, Pairing, ProbePolicy, TrafficPolicy, Uplink,
};
use mooring_model::ids::{LocalLabel, NodeId, ShortId, UserId, Uuid};
use mooring_model::iface::{InterfaceSelector, LanSubnet, LinuxIfName, MacAddr};
use mooring_model::ipv4::{CarrierPrefix, PublicIpv4};
use mooring_model::keys::{Ed25519Pub, WgKey, X25519Pub};
use mooring_model::node::{
    AppliedConfig, Arch, HostFacts, Hy2Server, Node, NodeAddress, NodeLifecycle, NodeRole,
    NodeSite, RealityServer, SshPin,
};
use mooring_model::ports::{DEBIAN_EPHEMERAL_PORTS, PortPlan};
use mooring_model::secret::{
    Ed25519Seed, Hy2KeyPem, Password, RealityPrivateKey, RouterAdminPassword, Secret, SecretEntry,
    SecretKind, SecretMaterial, SecretRef, WgPrivateKey,
};
use mooring_model::sim::{BillDay, Carrier, EvidenceRef, PlanKind, SimPlan, SimPolicy, StopPolicy};
use mooring_model::state::StateV2;
use mooring_model::target::{
    CertificateName, EvidenceUrl, HttpOutcome, HttpStatus, HttpVersion, KeyExchange,
    TargetAttestation, TargetFacts, TargetSpec, TlsHandshake, TlsOutcome, TlsVersion, qualify,
};
use mooring_model::time::UnixTime;
use mooring_model::user::{
    ClientLine, ClientProfile, User, UserNodePublic, UserPolicy, UserStatus,
};
use mooring_model::wg::{Keepalive, WgIndex, WgLink};
use tempfile::TempDir;

use crate::ordered::update_config_with_secrets;
use crate::secrets::InMemorySecretStore;
use crate::store::Store;

/// The warning threshold of the version-1 goldens, 450e9 bytes.
pub(crate) const V1_GOLDEN_WARN_BYTES: u64 = 450_000_000_000;
/// The hard stop of the version-1 goldens, 560e9 bytes.
pub(crate) const V1_GOLDEN_HARD_STOP_BYTES: u64 = 560_000_000_000;

/// The decided line (F1): SMARTY Unlimited, no fair-use line, no speed cap,
/// recorded from SMARTY's Price Guide V42.
pub(crate) fn smarty_plan() -> SimPlan {
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

/// The exit site of the stores the tests build: the SMARTY plan on bill
/// day 1 with the version-1 goldens' thresholds, so a lifted golden whose
/// plan is then recorded equals the same history built here.
pub(crate) fn exit_site() -> ExitSite {
    ExitSite {
        egress: InterfaceSelector::LinkAddr {
            lladdr: MacAddr::parse("02:6d:6f:6f:72:01").unwrap(),
            subnet: "192.168.1.0/24".parse::<LanSubnet>().unwrap(),
        },
        uplink: Uplink::SameAsExit,
        egress_check: EgressCheck {
            carrier_prefixes: NonEmpty::new("31.120.0.0/14".parse::<CarrierPrefix>().unwrap()),
            pairing: Pairing::Paired,
        },
        sim: SimPolicy::new(
            BillDay::new(1).unwrap(),
            smarty_plan(),
            V1_GOLDEN_WARN_BYTES,
            StopPolicy::HardStop {
                bytes: V1_GOLDEN_HARD_STOP_BYTES,
            },
        )
        .unwrap(),
        probe: ProbePolicy::default(),
        flow_cap: FlowCap::new(4096).unwrap(),
        uplink_baseline: None,
    }
}

/// A store in a fresh temporary directory; keep the `TempDir` alive.
pub(crate) fn empty_store() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path());
    (dir, store)
}

/// What the tests initialise a store with: [`exit_site`], no cap, no
/// automatic quotas and no alert channels.
pub(crate) fn deployment_init() -> DeploymentInit {
    DeploymentInit {
        exit: exit_site(),
        policy: TrafficPolicy::default(),
        capacity: CapacityPolicy::UNLIMITED,
        auto_quota: None,
        alerting: None,
    }
}

/// A store initialised with an empty deployment.
pub(crate) fn initialised() -> (TempDir, Store, StateV2) {
    let (dir, store) = empty_store();
    let state = store.init(deployment_init()).unwrap();
    (dir, store, state)
}

pub(crate) fn node_id(text: &str) -> NodeId {
    NodeId::parse(text).unwrap()
}

/// A planned node with the default port plan (one Hysteria2 listener);
/// `seed` makes its keys distinct.
pub(crate) fn planned_node(id: &str, wg_index: u8, seed: u8) -> Node {
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
            target: None,
        },
        hy2: Hy2Server {
            certificate: CertificatePem::from_der(&[0x30, 0x03, 0x02, 0x01, seed]).unwrap(),
        },
        wg: WgLink {
            vps_pub: WgKey::from_bytes([seed.wrapping_add(2); 32]).unwrap(),
            mac_pub: WgKey::from_bytes([seed.wrapping_add(3); 32]).unwrap(),
            keepalive: Keepalive::DEFAULT,
        },
        lifecycle: NodeLifecycle::Planned,
    }
}

/// The site of a node adopted at `addr`.
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

/// The lifecycle of a node adopted at `addr`.
pub(crate) fn adopted(addr: [u8; 4]) -> NodeLifecycle {
    NodeLifecycle::Adopted { site: site(addr) }
}

/// An active user holding credentials on `nodes` (`(node, short id byte)`).
pub(crate) fn user(n: u64, nodes: &[(&str, u8)]) -> User {
    User {
        id: UserId::from_low_bits(n),
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
                        short_id: ShortId::from_bytes([0x5f, 0x1e, 0, 0, 0, 0, 0, *short]).unwrap(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        policy: UserPolicy::NONE,
        alias: None,
        agreement: None,
    }
}

/// Parts with `node` appended and the next WireGuard index moved past it.
pub(crate) fn with_node(mut parts: DeploymentParts, node: Node) -> DeploymentParts {
    parts.next_wg_index = node.wg_index.next().unwrap();
    parts.nodes.push(node);
    parts
}

/// Parts with `user` appended.
pub(crate) fn with_user(mut parts: DeploymentParts, user: User) -> DeploymentParts {
    parts.users.push(user);
    parts
}

/// Parts with node `id`'s lifecycle replaced.
pub(crate) fn with_lifecycle(
    mut parts: DeploymentParts,
    id: &str,
    lifecycle: NodeLifecycle,
) -> DeploymentParts {
    let node = parts
        .nodes
        .iter_mut()
        .find(|node| node.id == node_id(id))
        .unwrap();
    node.lifecycle = lifecycle;
    parts
}

/// The secrets `change` makes the deployment reference that it did not.
pub(crate) fn added_refs(
    current: &Deployment,
    change: impl FnOnce(DeploymentParts) -> DeploymentParts,
) -> BTreeSet<SecretRef> {
    let next = Deployment::try_from(change(current.clone().into_parts())).unwrap();
    let old = current.required_secrets();
    next.required_secrets().difference(&old).cloned().collect()
}

/// Material of the kind `secret_ref` names, distinct per `seed`.
pub(crate) fn material_for(secret_ref: &SecretRef, seed: u8) -> SecretMaterial {
    let bytes = [seed.max(1); 32];
    match secret_ref.kind() {
        SecretKind::RealityPrivateKey => {
            SecretMaterial::RealityPrivateKey(RealityPrivateKey::from_bytes(bytes).unwrap())
        }
        SecretKind::WgPrivateKey => {
            SecretMaterial::WgPrivateKey(WgPrivateKey::from_bytes(bytes).unwrap())
        }
        SecretKind::Hy2PrivateKey => {
            SecretMaterial::Hy2PrivateKey(Hy2KeyPem::from_der(&[0x30, 0x01, seed]).unwrap())
        }
        SecretKind::Password => SecretMaterial::Password(Password::from_bytes(bytes).unwrap()),
        SecretKind::Uuid => SecretMaterial::Uuid(Secret::new(Uuid::from_random_bytes([seed; 16]))),
        SecretKind::Ed25519Seed => {
            SecretMaterial::Ed25519Seed(Ed25519Seed::from_bytes(bytes).unwrap())
        }
        SecretKind::RouterAdminPassword => SecretMaterial::RouterAdminPassword(
            RouterAdminPassword::parse(&format!("router password {seed}")).unwrap(),
        ),
    }
}

/// One entry per reference, with material from [`material_for`].
pub(crate) fn entries_for<'a>(
    refs: impl IntoIterator<Item = &'a SecretRef>,
    seed: u8,
) -> Vec<SecretEntry> {
    refs.into_iter()
        .map(|secret_ref| {
            SecretEntry::new(secret_ref.clone(), material_for(secret_ref, seed)).unwrap()
        })
        .collect()
}

/// A qualified REALITY target, as `node target set` stores it.
pub(crate) fn target() -> TargetSpec {
    let host = DnsName::parse("www.harbour-target.test").unwrap();
    let facts = TargetFacts {
        host: host.clone(),
        resolved_ipv4: BTreeSet::from([Ipv4Addr::new(45, 67, 89, 200)]),
        tls: TlsOutcome::Completed(TlsHandshake {
            version: TlsVersion::Tls13,
            key_exchange: KeyExchange::X25519,
            certificate_names: BTreeSet::from([CertificateName::parse(host.as_str()).unwrap()]),
            handshake_p95_micros: 1_000,
            first_flight_bytes: 4_096,
        }),
        http: HttpOutcome::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
        },
    };
    let attestation = TargetAttestation {
        same_asn: true,
        not_cdn: true,
        evidence_url: EvidenceUrl::parse("https://evidence.mooring.test/lon1").unwrap(),
        at: UnixTime::from_secs(1_791_417_600),
    };
    qualify(&facts, attestation).unwrap().into_target()
}

/// A store whose deployment holds `lon1`, adopted at 45.67.89.10 with a
/// REALITY target, and user 1 on it, with every secret written; the
/// deployment is at generation 3.
pub(crate) fn adopted_store() -> (TempDir, Store, StateV2, InMemorySecretStore) {
    let (dir, store, state) = initialised();
    let mut secrets = InMemorySecretStore::new();
    let add = |parts| with_node(parts, planned_node("lon1", 1, 10));
    let refs = added_refs(&state.deployment, add);
    let planned = update_config_with_secrets(
        &store,
        &mut secrets,
        state.deployment.config_generation(),
        entries_for(&refs, 1),
        |parts| Ok::<_, Infallible>(add(parts)),
    )
    .unwrap();
    let adopt = |parts| {
        let mut parts = with_user(
            with_lifecycle(parts, "lon1", adopted([45, 67, 89, 10])),
            user(1, &[("lon1", 1)]),
        );
        parts.nodes[0].reality.target = Some(target());
        parts
    };
    let refs = added_refs(&planned.deployment, adopt);
    let adopted = update_config_with_secrets(
        &store,
        &mut secrets,
        planned.deployment.config_generation(),
        entries_for(&refs, 2),
        |parts| Ok::<_, Infallible>(adopt(parts)),
    )
    .unwrap();
    (dir, store, adopted, secrets)
}

/// The record that node `id` confirmed `generation`.
pub(crate) fn applied_record(id: &str, generation: ConfigGeneration) -> Bookkeeping {
    Bookkeeping::Applied {
        node: node_id(id),
        applied: AppliedConfig {
            config_generation: generation,
            digest: Sha256Digest::from_bytes([0xab; 32]),
        },
    }
}
