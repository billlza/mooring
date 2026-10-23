// SPDX-License-Identifier: GPL-3.0-or-later

//! Deterministic, network-free fixture deployments with matching secrets,
//! for golden tests. A test-only helper: never a normal dependency of a
//! runtime crate.
//!
//! Every value is fixed; nothing reads a clock or draws randomness. Node
//! keys and certificates are literals (`material.rs` records how they were
//! made). Per-user and probe credentials are a pure function of
//! `(slot, node ordinal, user number)`, so a 20-user fixture needs no table.
//! Node and target addresses are arbitrary public IPv4s outside
//! `SPECIAL_V4`: test values, not real allocations.
//!
//! The four fixtures are [`one_node_one_user`], [`one_node_three_users`],
//! [`two_nodes_three_users`] and [`two_nodes_twenty_users`]; [`all`] builds
//! them in that order. Each runs the first exit line, SMARTY Unlimited
//! (decision F1 as first made), at SMARTY's pilot thresholds
//! ([`FIXTURE_SIM_WARN_BYTES`], [`FIXTURE_SIM_HARD_STOP_BYTES`]), with no
//! cap on active users (the 20-user fixture would break the pilot's cap of
//! 5), no automatic quotas and no alert channels; [`two_nodes_three_users`]
//! also has one viewer. The fixtures check arithmetic and encodings, not
//! the decided values, which moved to 1pMobile on 2026-10-23, so they keep
//! SMARTY's.
//! Every user accepted the current agreement revision on 2026-10-08
//! (decision F9), so every user can be exported.

#![deny(missing_docs)]

mod material;

/// The SIM warning threshold every fixture runs with: SMARTY's pilot value
/// as decision F2 first set it, 240e9 (the crate documentation says why it
/// is not the decided `mooring_model::PILOT_SIM_WARN_BYTES`).
pub const FIXTURE_SIM_WARN_BYTES: u64 = 240_000_000_000;

/// The SIM hard stop every fixture runs with, 300e9, as
/// [`FIXTURE_SIM_WARN_BYTES`].
pub const FIXTURE_SIM_HARD_STOP_BYTES: u64 = 300_000_000_000;

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use mooring_model::cert::{CertPins, CertificatePem, Hy2Sni};
use mooring_model::collections::NonEmpty;
use mooring_model::counters::{ConfigGeneration, RuntimeRevision};
use mooring_model::date::CalendarDate;
use mooring_model::deployment::{CapacityPolicy, Deployment, DeploymentParts};
use mooring_model::digest::{Sha256Digest, SpkiSha256};
use mooring_model::dns::DnsName;
use mooring_model::error::ModelError;
use mooring_model::exit::{
    EgressCheck, ExitSite, FlowCap, Pairing, ProbePolicy, TrafficPolicy, Uplink,
};
use mooring_model::ids::{LocalLabel, NodeId, ShortId, UserId, Uuid};
use mooring_model::iface::{
    BsdName, InterfaceIndex, InterfaceSelector, LanSubnet, LinuxIfName, MacAddr, ResolvedInterface,
    ResolvedInterfaces, ResolvedUplink,
};
use mooring_model::ipv4::{CarrierPrefix, PublicIpv4};
use mooring_model::keys::{Ed25519Pub, WgKey, X25519Pub};
use mooring_model::node::{
    AppliedConfig, Arch, HostFacts, Hy2Server, Node, NodeAddress, NodeLifecycle, NodeRole,
    NodeSite, RealityServer, SshPin,
};
use mooring_model::ports::{DEBIAN_EPHEMERAL_PORTS, ListenerIdx, PortPlan};
use mooring_model::secret::{
    Hy2KeyPem, Password, RealityPrivateKey, Secret, SecretEntry, SecretSnapshot,
    SecretSnapshotError, WgPrivateKey,
};
use mooring_model::sim::{
    BillDay, Carrier, CycleRule, EvidenceRef, PlanKind, SimPlan, SimPolicy, StopPolicy,
};
use mooring_model::state::{RuntimeIntent, StateV2};
use mooring_model::target::{
    CertificateName, EvidenceUrl, HttpOutcome, HttpStatus, HttpVersion, KeyExchange,
    TargetAttestation, TargetFacts, TargetRejected, TlsHandshake, TlsOutcome, TlsVersion, qualify,
};
use mooring_model::time::UnixTime;
use mooring_model::user::{
    AgreementRecord, AgreementVersion, Capability, ClientLine, ClientProfile, User, UserNodePublic,
    UserPolicy, UserStatus,
};
use mooring_model::viewer::Viewer;
use mooring_model::wg::{Keepalive, WgIndex, WgLink};

use material::{AMS1, CERT_NOT_BEFORE, LON1, NodeMaterial};

/// The fixed "now" of every fixture, 2026-10-08T00:00:00Z, inside each
/// certificate's validity window.
pub const FIXTURE_NOW: UnixTime = UnixTime::from_secs(1_791_417_600);

/// One fixture: a validated deployment, exactly the secrets it requires, and
/// the Mac interfaces it resolves to.
#[derive(Debug)]
pub struct Fixture {
    /// A stable name, used as the golden directory name.
    pub name: &'static str,
    /// The deployment; every node is applied at generation 1.
    pub deployment: Deployment,
    /// Exactly the secrets `deployment.required_secrets()` lists.
    pub secrets: SecretSnapshot,
    /// The resolved egress (`en8`) with a `SameAsExit` uplink.
    pub interfaces: ResolvedInterfaces,
}

impl Fixture {
    /// The fixture as a state document, with the exit enabled.
    #[must_use]
    pub fn state(&self) -> StateV2 {
        StateV2 {
            deployment: self.deployment.clone(),
            runtime: RuntimeIntent {
                exit_enabled: true,
                revision: RuntimeRevision::INITIAL,
            },
        }
    }
}

/// A fixture could not be built, which means a fixture literal is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureError {
    /// A literal broke a model invariant.
    Model(ModelError),
    /// A fixture target failed qualification.
    Target(TargetRejected),
    /// A secret could not be added to the snapshot.
    Secrets(SecretSnapshotError),
}

/// The kind of a [`FixtureError`], without its details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FixtureErrorKind {
    /// See [`FixtureError::Model`].
    Model,
    /// See [`FixtureError::Target`].
    Target,
    /// See [`FixtureError::Secrets`].
    Secrets,
}

impl FixtureErrorKind {
    /// Every kind, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Model, Self::Target, Self::Secrets];
}

impl FixtureError {
    /// The kind of this error.
    #[must_use]
    pub const fn kind(&self) -> FixtureErrorKind {
        match self {
            Self::Model(_) => FixtureErrorKind::Model,
            Self::Target(_) => FixtureErrorKind::Target,
            Self::Secrets(_) => FixtureErrorKind::Secrets,
        }
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(f, "fixture literal is invalid: {error}"),
            Self::Target(error) => write!(f, "fixture target is invalid: {error}"),
            Self::Secrets(error) => write!(f, "fixture secret is invalid: {error}"),
        }
    }
}

impl std::error::Error for FixtureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Model(error) => Some(error),
            Self::Target(error) => Some(error),
            Self::Secrets(error) => Some(error),
        }
    }
}

impl From<ModelError> for FixtureError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<TargetRejected> for FixtureError {
    fn from(error: TargetRejected) -> Self {
        Self::Target(error)
    }
}

impl From<SecretSnapshotError> for FixtureError {
    fn from(error: SecretSnapshotError) -> Self {
        Self::Secrets(error)
    }
}

/// Fixture (a): lon1 (primary) and one user.
pub fn one_node_one_user() -> Result<Fixture, FixtureError> {
    build("1-node-1-user", &[&LON1], 1, Vec::new())
}

/// Fixture (b): lon1 (primary) and three users.
pub fn one_node_three_users() -> Result<Fixture, FixtureError> {
    build("1-node-3-users", &[&LON1], 3, Vec::new())
}

/// Fixture (c): lon1 (primary), ams1 (standby), three users and one viewer.
pub fn two_nodes_three_users() -> Result<Fixture, FixtureError> {
    build("2-nodes-3-users", &[&LON1, &AMS1], 3, vec![viewer()?])
}

/// Fixture (d): lon1 (primary), ams1 (standby) and twenty users.
pub fn two_nodes_twenty_users() -> Result<Fixture, FixtureError> {
    build("2-nodes-20-users", &[&LON1, &AMS1], 20, Vec::new())
}

/// Every fixture, (a) to (d).
pub fn all() -> Result<Vec<Fixture>, FixtureError> {
    Ok(vec![
        one_node_one_user()?,
        one_node_three_users()?,
        two_nodes_three_users()?,
        two_nodes_twenty_users()?,
    ])
}

/// The SNI and pins `/usr/bin/openssl` (LibreSSL 3.3.6) computed for a
/// fixture node's certificate when the material was made (`material.rs`): an
/// oracle independent of the code that derives them from the certificate.
pub fn recorded_pins(node: &NodeId) -> Result<CertPins, FixtureError> {
    let material = [&LON1, &AMS1]
        .into_iter()
        .find(|material| material.id == node.as_str())
        .ok_or_else(|| ModelError::UnknownNode { id: node.clone() })?;
    Ok(CertPins::new(
        Hy2Sni::parse(material.hy2_sni)?,
        SpkiSha256::parse(material.spki_sha256)?,
        Sha256Digest::parse(material.der_sha256)?,
    ))
}

/// Which derived credential a byte pattern is for.
#[derive(Clone, Copy)]
enum Slot {
    UserVless = 0x01,
    UserLoop = 0x02,
    UserHy2 = 0x03,
    ProbeVless = 0x11,
    ProbeLoop = 0x12,
    ProbeHy2 = 0x13,
    Obfs = 0x21,
    UserShortId = 0x31,
    ProbeShortId = 0x32,
}

/// A recognisable UUID: `6d6f6f72-SSNN-40UU-8000-0000SSNNUU` before the
/// version and variant bits are set ("moor", slot, node, user).
fn derived_uuid(slot: Slot, node: u8, user: u8) -> Uuid {
    let slot = slot as u8;
    Uuid::from_random_bytes([
        0x6d, 0x6f, 0x6f, 0x72, slot, node, 0x40, user, 0x80, 0, 0, 0, 0, slot, node, user,
    ])
}

/// 32 bytes: the ASCII `mooring-fixture-secret` followed by the slot, node
/// and user, then a fixed tail.
fn derived_bytes(slot: Slot, node: u8, user: u8) -> [u8; 32] {
    let mut bytes = [0x5a_u8; 32];
    let label = b"mooring-fixture-secret";
    bytes[..label.len()].copy_from_slice(label);
    bytes[label.len()] = slot as u8;
    bytes[label.len() + 1] = node;
    bytes[label.len() + 2] = user;
    bytes
}

fn derived_short_id(slot: Slot, node: u8, user: u8) -> Result<ShortId, ModelError> {
    ShortId::from_bytes([0x5f, 0x1e, slot as u8, node, 0, 0, 0, user])
}

fn derived_secret_uuid(slot: Slot, node: u8, user: u8) -> Secret<Uuid> {
    Secret::new(derived_uuid(slot, node, user))
}

fn derived_password(slot: Slot, node: u8, user: u8) -> Result<Password, ModelError> {
    Password::from_bytes(derived_bytes(slot, node, user))
}

fn ipv4(octets: [u8; 4]) -> Ipv4Addr {
    Ipv4Addr::from(octets)
}

fn exit_site() -> Result<ExitSite, ModelError> {
    Ok(ExitSite {
        egress: InterfaceSelector::LinkAddr {
            lladdr: MacAddr::parse("02:6d:6f:6f:72:01")?,
            subnet: "192.168.1.0/24".parse::<LanSubnet>()?,
        },
        uplink: Uplink::SameAsExit,
        egress_check: Some(EgressCheck {
            carrier_prefixes: NonEmpty::new("31.120.0.0/14".parse::<CarrierPrefix>()?),
            pairing: Pairing::Paired,
        }),
        sim: SimPolicy::new(
            CycleRule::Monthly {
                bill_day: BillDay::new(1)?,
            },
            sim_plan()?,
            FIXTURE_SIM_WARN_BYTES,
            StopPolicy::HardStop {
                bytes: FIXTURE_SIM_HARD_STOP_BYTES,
            },
        )?,
        probe: ProbePolicy::default(),
        flow_cap: FlowCap::new(4096)?,
        uplink_baseline: None,
    })
}

/// The decided line (F1): SMARTY Unlimited, with no fair-use line and no
/// speed cap, recorded from SMARTY's Price Guide V42 (25 August 2026).
fn sim_plan() -> Result<SimPlan, ModelError> {
    Ok(SimPlan {
        carrier: Carrier::Smarty,
        kind: PlanKind::Unlimited,
        speed_cap_mbps: None,
        terms: EvidenceRef {
            url: EvidenceUrl::parse(
                "https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf",
            )?,
            dated: CalendarDate::parse("2026-08-25")?,
        },
    })
}

/// The viewer of [`two_nodes_three_users`]: a literal public key (no
/// private half exists), labelled as the operator's phone.
fn viewer() -> Result<Viewer, ModelError> {
    Ok(Viewer {
        key: Ed25519Pub::from_bytes(*b"mooring-fixture-viewer-key-00001")?,
        label: LocalLabel::parse("Operator phone")?,
        added_on: CalendarDate::parse("2026-10-08")?,
    })
}

fn interfaces(site: &ExitSite) -> Result<ResolvedInterfaces, ModelError> {
    site.resolve(
        ResolvedInterface {
            bsd_name: BsdName::parse("en8")?,
            index: InterfaceIndex::new(21)?,
            lladdr: MacAddr::parse("02:6d:6f:6f:72:01")?,
            ipv4: Ipv4Addr::new(192, 168, 1, 20),
        },
        ResolvedUplink::SameAsExit,
    )
}

fn node(material: &NodeMaterial, role: NodeRole) -> Result<Node, FixtureError> {
    let facts = TargetFacts {
        host: DnsName::parse(material.target_host)?,
        resolved_ipv4: BTreeSet::from([ipv4(material.target_address)]),
        tls: TlsOutcome::Completed(TlsHandshake {
            version: TlsVersion::Tls13,
            key_exchange: if material.target_hybrid {
                KeyExchange::X25519MlKem768
            } else {
                KeyExchange::X25519
            },
            certificate_names: BTreeSet::from([CertificateName::parse(material.target_host)?]),
            handshake_p95_micros: 1_200,
            first_flight_bytes: 5_120,
        }),
        http: HttpOutcome::Responded {
            status: HttpStatus::new(200)?,
            version: HttpVersion::Http2,
        },
    };
    let attestation = TargetAttestation {
        same_asn: true,
        not_cdn: true,
        evidence_url: EvidenceUrl::parse(&format!(
            "https://evidence.mooring.test/{}",
            material.id
        ))?,
        at: UnixTime::from_secs(CERT_NOT_BEFORE),
    };
    let target = qualify(&facts, attestation)?.into_target();
    let site = NodeSite {
        address: NodeAddress::Public(PublicIpv4::new(ipv4(material.address))?),
        host_facts: HostFacts {
            uplink_interface: LinuxIfName::parse("eth0")?,
            arch: Arch::Amd64,
            ephemeral_ports: DEBIAN_EPHEMERAL_PORTS,
        },
    };
    Ok(Node {
        id: NodeId::parse(material.id)?,
        role,
        ports: PortPlan::with_defaults(DEBIAN_EPHEMERAL_PORTS)?,
        wg_index: WgIndex::new(material.ordinal)?,
        ssh: SshPin {
            host_ed25519: Ed25519Pub::parse(material.ssh_host_public)?,
        },
        reality: RealityServer {
            public_key: X25519Pub::parse(material.reality_public)?,
            probe_short_id: derived_short_id(Slot::ProbeShortId, material.ordinal, 0)?,
            target: Some(target),
        },
        hy2: Hy2Server {
            certificate: CertificatePem::parse(material.hy2_certificate)?,
        },
        wg: WgLink {
            vps_pub: WgKey::parse(material.wg_vps_public)?,
            mac_pub: WgKey::parse(material.wg_mac_public)?,
            keepalive: Keepalive::DEFAULT,
        },
        lifecycle: NodeLifecycle::Applied {
            site,
            applied: AppliedConfig {
                config_generation: ConfigGeneration::INITIAL,
                digest: Sha256Digest::parse(material.bundle_digest)?,
            },
        },
    })
}

/// The client profile cycles through every shape: 0.4, 0.5, and 0.5 with
/// the ML-KEM opt-in.
fn client(number: u8) -> ClientProfile {
    match number % 3 {
        1 => ClientProfile {
            line: ClientLine::Cfm04,
            capabilities: BTreeSet::new(),
        },
        2 => ClientProfile {
            line: ClientLine::Cfm05,
            capabilities: BTreeSet::new(),
        },
        _ => ClientProfile {
            line: ClientLine::Cfm05,
            capabilities: BTreeSet::from([Capability::RealityMlkemOptIn]),
        },
    }
}

/// User ids are `fxuseraa` followed by the user number in two base32 digits
/// (`fxuseraaab` is user 1).
fn user_id(number: u8) -> Result<UserId, ModelError> {
    const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let high = char::from(BASE32[usize::from(number >> 5)]);
    let low = char::from(BASE32[usize::from(number & 0x1f)]);
    UserId::parse(&format!("fxuseraa{high}{low}"))
}

fn user(number: u8, nodes: &[&NodeMaterial]) -> Result<User, ModelError> {
    let per_node = nodes
        .iter()
        .map(|node| {
            Ok((
                NodeId::parse(node.id)?,
                UserNodePublic {
                    short_id: derived_short_id(Slot::UserShortId, node.ordinal, number)?,
                },
            ))
        })
        .collect::<Result<_, ModelError>>()?;
    Ok(User {
        id: user_id(number)?,
        label: LocalLabel::parse(&format!("Fixture user {number:02}"))?,
        client: client(number),
        status: UserStatus::Active,
        per_node,
        policy: UserPolicy::NONE,
        alias: None,
        // Decision F9: exports require the current agreement revision.
        agreement: Some(AgreementRecord {
            version: AgreementVersion::CURRENT,
            accepted_on: CalendarDate::utc_of(FIXTURE_NOW)?,
        }),
    })
}

fn insert_node_secrets(
    secrets: &mut SecretSnapshot,
    material: &NodeMaterial,
) -> Result<(), FixtureError> {
    let id = NodeId::parse(material.id)?;
    let n = material.ordinal;
    let entries = [
        SecretEntry::NodeRealityPrivate(
            id.clone(),
            RealityPrivateKey::parse(material.reality_private)?,
        ),
        SecretEntry::NodeWgVpsPrivate(id.clone(), WgPrivateKey::parse(material.wg_vps_private)?),
        SecretEntry::NodeWgMacPrivate(id.clone(), WgPrivateKey::parse(material.wg_mac_private)?),
        SecretEntry::NodeHy2Key(id.clone(), Hy2KeyPem::parse(material.hy2_key)?),
        SecretEntry::NodeHy2Obfs(
            id.clone(),
            ListenerIdx::FIRST,
            derived_password(Slot::Obfs, n, 0)?,
        ),
        SecretEntry::ProbeVlessUuid(id.clone(), derived_secret_uuid(Slot::ProbeVless, n, 0)),
        SecretEntry::ProbeLoopUuid(id.clone(), derived_secret_uuid(Slot::ProbeLoop, n, 0)),
        SecretEntry::ProbeHy2Password(id, derived_password(Slot::ProbeHy2, n, 0)?),
    ];
    for entry in entries {
        secrets.insert(entry)?;
    }
    Ok(())
}

fn insert_user_secrets(
    secrets: &mut SecretSnapshot,
    number: u8,
    nodes: &[&NodeMaterial],
) -> Result<(), FixtureError> {
    let user = user_id(number)?;
    for node in nodes {
        let id = NodeId::parse(node.id)?;
        let n = node.ordinal;
        secrets.insert(SecretEntry::UserVlessUuid(
            user.clone(),
            id.clone(),
            derived_secret_uuid(Slot::UserVless, n, number),
        ))?;
        secrets.insert(SecretEntry::UserLoopUuid(
            user.clone(),
            id.clone(),
            derived_secret_uuid(Slot::UserLoop, n, number),
        ))?;
        secrets.insert(SecretEntry::UserHy2Password(
            user.clone(),
            id,
            derived_password(Slot::UserHy2, n, number)?,
        ))?;
    }
    Ok(())
}

fn build(
    name: &'static str,
    nodes: &[&NodeMaterial],
    users: u8,
    viewers: Vec<Viewer>,
) -> Result<Fixture, FixtureError> {
    let mut node_list = Vec::with_capacity(nodes.len());
    let mut secrets = SecretSnapshot::new();
    let mut next_wg_index = WgIndex::FIRST;
    for (position, material) in nodes.iter().enumerate() {
        let role = if position == 0 {
            NodeRole::Primary
        } else {
            NodeRole::Standby
        };
        let built = node(material, role)?;
        next_wg_index = next_wg_index.max(built.wg_index.next()?);
        node_list.push(built);
        insert_node_secrets(&mut secrets, material)?;
    }
    let mut user_list = Vec::with_capacity(usize::from(users));
    for number in 1..=users {
        user_list.push(user(number, nodes)?);
        insert_user_secrets(&mut secrets, number, nodes)?;
    }
    let site = exit_site()?;
    let interfaces = interfaces(&site)?;
    let deployment = Deployment::try_from(DeploymentParts {
        config_generation: ConfigGeneration::INITIAL,
        exit: site,
        policy: TrafficPolicy::default(),
        capacity: CapacityPolicy::UNLIMITED,
        auto_quota: None,
        alerting: None,
        viewers,
        nodes: node_list,
        users: user_list,
        next_wg_index,
    })?;
    Ok(Fixture {
        name,
        deployment,
        secrets,
        interfaces,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error as _;

    use super::*;
    use mooring_model::secret::SecretRef;
    use mooring_model::target::TargetKeyExchange;

    fn ids(fixture: &Fixture) -> (Vec<&str>, usize) {
        let nodes = fixture
            .deployment
            .nodes()
            .keys()
            .map(NodeId::as_str)
            .collect();
        (nodes, fixture.deployment.users().len())
    }

    #[test]
    fn the_four_fixtures_have_the_specified_shapes() {
        let fixtures = all().unwrap();
        let shapes: Vec<(&str, Vec<&str>, usize)> = fixtures
            .iter()
            .map(|fixture| {
                let (nodes, users) = ids(fixture);
                (fixture.name, nodes, users)
            })
            .collect();
        assert_eq!(
            shapes,
            vec![
                ("1-node-1-user", vec!["lon1"], 1),
                ("1-node-3-users", vec!["lon1"], 3),
                ("2-nodes-3-users", vec!["ams1", "lon1"], 3),
                ("2-nodes-20-users", vec!["ams1", "lon1"], 20),
            ]
        );
        let two = two_nodes_twenty_users().unwrap();
        let lon1 = two
            .deployment
            .node(&NodeId::parse("lon1").unwrap())
            .unwrap();
        let ams1 = two
            .deployment
            .node(&NodeId::parse("ams1").unwrap())
            .unwrap();
        assert_eq!(lon1.role, NodeRole::Primary);
        assert_eq!(ams1.role, NodeRole::Standby);
        assert_eq!(two.deployment.next_wg_index().get(), 3);
        assert_eq!(
            one_node_one_user()
                .unwrap()
                .deployment
                .next_wg_index()
                .get(),
            2
        );
    }

    /// Every fixture runs SMARTY's pilot thresholds on SMARTY's plan, and
    /// leaves the cap, automatic quotas, alert channels and every per-user
    /// record off, except the agreement: every user accepted the current
    /// revision on the fixtures' day, as exports require (F9).
    #[test]
    fn the_sim_policy_is_smartys_pilot() {
        for fixture in all().unwrap() {
            let sim = &fixture.deployment.exit().sim;
            assert_eq!(
                sim.cycle(),
                CycleRule::Monthly {
                    bill_day: BillDay::new(1).unwrap()
                }
            );
            let plan = sim.plan().unwrap();
            assert_eq!(plan.carrier, Carrier::Smarty);
            assert_eq!(plan.kind, PlanKind::Unlimited);
            assert_eq!(plan.speed_cap_mbps, None);
            assert_eq!(
                plan.terms.url.as_str(),
                "https://sundaecdn.blob.core.windows.net/files/SMARTY-Price-Guide.pdf"
            );
            assert_eq!(plan.terms.dated.to_string(), "2026-08-25");
            assert_eq!(sim.warn_bytes(), 240_000_000_000);
            assert_eq!(
                sim.stop(),
                StopPolicy::HardStop {
                    bytes: 300_000_000_000
                }
            );
            assert_eq!(sim.thresholds().plan_line(), None);
            assert_eq!(fixture.deployment.exit().uplink_baseline, None);
            assert_eq!(fixture.deployment.capacity(), CapacityPolicy::UNLIMITED);
            assert_eq!(fixture.deployment.auto_quota(), None);
            assert_eq!(fixture.deployment.alerting(), None);
            for user in fixture.deployment.users().values() {
                assert_eq!(user.policy, UserPolicy::NONE);
                assert_eq!(user.alias, None);
                assert_eq!(
                    user.agreement,
                    Some(AgreementRecord {
                        version: AgreementVersion::CURRENT,
                        accepted_on: CalendarDate::parse("2026-10-08").unwrap(),
                    })
                );
            }
        }
    }

    /// Only the two-node, three-user fixture has a viewer, so a viewer
    /// golden exists beside fixtures without one.
    #[test]
    fn one_fixture_has_a_viewer() {
        let viewers: Vec<(&str, usize)> = all()
            .unwrap()
            .iter()
            .map(|fixture| (fixture.name, fixture.deployment.viewers().len()))
            .collect();
        assert_eq!(
            viewers,
            vec![
                ("1-node-1-user", 0),
                ("1-node-3-users", 0),
                ("2-nodes-3-users", 1),
                ("2-nodes-20-users", 0),
            ]
        );
        let fixture = two_nodes_three_users().unwrap();
        let viewer = fixture.deployment.viewers().values().next().unwrap();
        assert_eq!(viewer.key.as_bytes(), b"mooring-fixture-viewer-key-00001");
        assert_eq!(viewer.label.as_str(), "Operator phone");
        assert_eq!(viewer.added_on.to_string(), "2026-10-08");
        assert_eq!(
            Ed25519Pub::parse_ssh_authorized_key(&viewer.key.ssh_authorized_key()).unwrap(),
            viewer.key
        );
    }

    #[test]
    fn secrets_are_exactly_the_required_set() {
        for fixture in all().unwrap() {
            let held: BTreeSet<SecretRef> = fixture.secrets.refs().into_iter().collect();
            assert_eq!(
                held,
                fixture.deployment.required_secrets(),
                "{}",
                fixture.name
            );
        }
    }

    #[test]
    fn fixtures_are_deterministic() {
        let first = two_nodes_twenty_users().unwrap();
        let second = two_nodes_twenty_users().unwrap();
        assert_eq!(first.deployment, second.deployment);
        assert_eq!(first.interfaces, second.interfaces);
        assert_eq!(first.secrets.refs(), second.secrets.refs());
        assert_eq!(first.secrets.needles(), second.secrets.needles());
    }

    #[test]
    fn every_credential_is_distinct() {
        let fixture = two_nodes_twenty_users().unwrap();
        let mut uuids = BTreeSet::new();
        let mut passwords = BTreeSet::new();
        for node in fixture.deployment.nodes().keys() {
            uuids.insert(
                fixture
                    .secrets
                    .probe_vless_uuid(node)
                    .unwrap()
                    .expose_secret()
                    .to_hyphenated()
                    .to_string(),
            );
            uuids.insert(
                fixture
                    .secrets
                    .probe_loop_uuid(node)
                    .unwrap()
                    .expose_secret()
                    .to_hyphenated()
                    .to_string(),
            );
            passwords.insert(
                fixture
                    .secrets
                    .probe_hy2_password(node)
                    .unwrap()
                    .expose_text()
                    .to_string(),
            );
            passwords.insert(
                fixture
                    .secrets
                    .hy2_obfs(node, ListenerIdx::FIRST)
                    .unwrap()
                    .expose_text()
                    .to_string(),
            );
            for user in fixture.deployment.users().keys() {
                uuids.insert(
                    fixture
                        .secrets
                        .user_vless_uuid(user, node)
                        .unwrap()
                        .expose_secret()
                        .to_hyphenated()
                        .to_string(),
                );
                uuids.insert(
                    fixture
                        .secrets
                        .user_loop_uuid(user, node)
                        .unwrap()
                        .expose_secret()
                        .to_hyphenated()
                        .to_string(),
                );
                passwords.insert(
                    fixture
                        .secrets
                        .user_hy2_password(user, node)
                        .unwrap()
                        .expose_text()
                        .to_string(),
                );
            }
        }
        assert_eq!(uuids.len(), 2 * (2 + 2 * 20));
        assert_eq!(passwords.len(), 2 * (2 + 20));
        assert!(
            uuids.contains("6d6f6f72-0101-4001-8000-000000010101"),
            "user 1 VLESS on lon1"
        );
        let user_ids: BTreeSet<&str> = fixture
            .deployment
            .users()
            .keys()
            .map(UserId::as_str)
            .collect();
        assert!(user_ids.contains("fxuseraaab") && user_ids.contains("fxuseraaau"));
    }

    #[test]
    fn users_cover_every_client_shape() {
        let fixture = one_node_three_users().unwrap();
        let profiles: BTreeSet<(ClientLine, bool)> = fixture
            .deployment
            .users()
            .values()
            .map(|user| {
                (
                    user.client.line,
                    user.client
                        .capabilities
                        .contains(&Capability::RealityMlkemOptIn),
                )
            })
            .collect();
        assert_eq!(
            profiles,
            BTreeSet::from([
                (ClientLine::Cfm04, false),
                (ClientLine::Cfm05, false),
                (ClientLine::Cfm05, true)
            ])
        );
        for user in fixture.deployment.users().values() {
            for capability in &user.client.capabilities {
                assert!(user.client.line.accepts(*capability));
            }
        }
        let node = NodeId::parse("lon1").unwrap();
        assert_eq!(fixture.deployment.served_users(&node).count(), 3);
    }

    #[test]
    fn certificates_match_their_pins_metadata() {
        for material in [&LON1, &AMS1] {
            let fixture = two_nodes_three_users().unwrap();
            let node = fixture
                .deployment
                .node(&NodeId::parse(material.id).unwrap())
                .unwrap();
            let der = node.hy2.certificate.der();
            let recorded = recorded_pins(&node.id).unwrap();
            // The SAN dNSName is stored verbatim in the DER.
            let sni = recorded.sni().as_str().as_bytes();
            assert!(
                der.windows(sni.len()).any(|window| window == sni),
                "{}",
                material.id
            );
            assert_eq!(node.hy2.certificate.as_str(), material.hy2_certificate);
            assert!(
                CERT_NOT_BEFORE <= FIXTURE_NOW.as_secs()
                    && FIXTURE_NOW.as_secs() <= material::CERT_NOT_AFTER
            );
            let key = fixture.secrets.hy2_key(&node.id).unwrap();
            assert_eq!(key.expose_pem(), material.hy2_key);
            assert_eq!(recorded.der_sha256(), Sha256Digest::of(der));
            assert_eq!(recorded.spki_sha256().to_string(), material.spki_sha256);
        }
    }

    #[test]
    fn targets_and_addresses() {
        let fixture = two_nodes_three_users().unwrap();
        let lon1 = fixture
            .deployment
            .node(&NodeId::parse("lon1").unwrap())
            .unwrap();
        let ams1 = fixture
            .deployment
            .node(&NodeId::parse("ams1").unwrap())
            .unwrap();
        let lon1_target = lon1.apply_inputs().unwrap().target;
        let ams1_target = ams1.apply_inputs().unwrap().target;
        assert_eq!(
            lon1_target.key_exchange(),
            TargetKeyExchange::X25519MlKem768
        );
        assert_eq!(ams1_target.key_exchange(), TargetKeyExchange::X25519);
        let addresses = fixture.deployment.node_addresses();
        assert_eq!(addresses[&lon1.id].ipv4(), Ipv4Addr::new(45, 67, 89, 10));
        assert_eq!(addresses[&ams1.id].ipv4(), Ipv4Addr::new(46, 78, 90, 12));
        assert_ne!(lon1_target.ipv4().get(), addresses[&lon1.id].ipv4());
        assert!(
            fixture
                .deployment
                .exit()
                .egress_check
                .as_ref()
                .unwrap()
                .in_carrier(Ipv4Addr::new(31, 121, 0, 1))
        );
        assert_eq!(
            fixture.interfaces.uplink_interface().bsd_name.as_str(),
            "en8"
        );
        assert!(fixture.state().runtime.exit_enabled);
    }

    #[test]
    fn literal_keys_parse_as_their_secret_kinds() {
        for material in [&LON1, &AMS1] {
            assert_eq!(
                RealityPrivateKey::parse(material.reality_private)
                    .unwrap()
                    .expose_text()
                    .as_str(),
                material.reality_private
            );
            assert_eq!(
                WgPrivateKey::parse(material.wg_vps_private)
                    .unwrap()
                    .expose_text()
                    .as_str(),
                material.wg_vps_private
            );
            assert_eq!(
                WgPrivateKey::parse(material.wg_mac_private)
                    .unwrap()
                    .expose_text()
                    .as_str(),
                material.wg_mac_private
            );
            // Every X25519 private literal is clamped, as `wg genkey` emits.
            for text in [material.wg_vps_private, material.wg_mac_private] {
                let key = WgPrivateKey::parse(text).unwrap();
                let bytes = key.expose_bytes();
                assert_eq!(bytes[0] & 7, 0);
                assert_eq!(bytes[31] & 0xc0, 0x40);
            }
        }
    }

    #[test]
    fn error_kinds_and_sources() {
        let model = FixtureError::from(ModelError::InvalidPort);
        assert_eq!(model.kind(), FixtureErrorKind::Model);
        assert!(model.source().is_some());
        assert_eq!(
            model.to_string(),
            "fixture literal is invalid: port must be in 1..=65535"
        );
        let secrets = FixtureError::from(SecretSnapshotError::Missing {
            secret_ref: SecretRef::NodeHy2Key(NodeId::parse("lon1").unwrap()),
        });
        assert_eq!(secrets.kind(), FixtureErrorKind::Secrets);
        let facts_failure = TargetFacts {
            host: DnsName::parse("www.apple.com").unwrap(),
            resolved_ipv4: BTreeSet::from([Ipv4Addr::new(45, 67, 89, 200)]),
            tls: TlsOutcome::ConnectFailed,
            http: HttpOutcome::Failed,
        };
        let attestation = TargetAttestation {
            same_asn: true,
            not_cdn: true,
            evidence_url: EvidenceUrl::parse("https://evidence.mooring.test/x").unwrap(),
            at: FIXTURE_NOW,
        };
        let target = FixtureError::from(qualify(&facts_failure, attestation).unwrap_err());
        assert_eq!(target.kind(), FixtureErrorKind::Target);
        let reached: BTreeSet<FixtureErrorKind> =
            [model.kind(), target.kind(), secrets.kind()].into();
        assert_eq!(reached, FixtureErrorKind::ALL.iter().copied().collect());
    }
}
