// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared test helpers: fixtures, an engine catalog, deployment edits and
//! users added with freshly generated credentials.

use std::collections::{BTreeMap, BTreeSet};

use mooring_agent_proto::{EngineSet, Sha256Hex, SshEd25519Key};
use mooring_fixtures::Fixture;
use mooring_keys::credentials;
use mooring_model::deployment::DeploymentParts;
use mooring_model::exit::Uplink;
use mooring_model::ids::{LocalLabel, NodeId, UserId};
use mooring_model::iface::{
    BsdName, InterfaceIndex, InterfaceSelector, MacAddr, ResolvedInterface, ResolvedUplink,
};
use mooring_model::keys::Ed25519Pub;
use mooring_model::secret::{SecretEntry, SecretMaterial, SecretRef, SecretSnapshot};
use mooring_model::user::{
    ClientLine, ClientProfile, User, UserNodePublic, UserPolicy, UserStatus,
};
use mooring_model::{Deployment, Secret};

use crate::mac::{ExitConfig, ProberConfig, exit, prober};
use crate::vps::{CloudInitKeys, EngineCatalog, OpensshHostKey, VpsBundle, bundle};

/// Every fixture, (a) to (d).
pub(crate) fn fixtures() -> Vec<Fixture> {
    mooring_fixtures::all().unwrap()
}

/// The 2-node, 20-user fixture.
pub(crate) fn big() -> Fixture {
    mooring_fixtures::two_nodes_twenty_users().unwrap()
}

/// A node id.
pub(crate) fn node(id: &str) -> NodeId {
    NodeId::parse(id).unwrap()
}

/// A fixed engine catalog: recognisable digests per architecture.
pub(crate) fn engines() -> EngineCatalog {
    let set = |base: u8| EngineSet {
        xray: Sha256Hex::from_bytes([base; 32]),
        hy2: Sha256Hex::from_bytes([base + 1; 32]),
        geoip: Sha256Hex::from_bytes([base + 2; 32]),
        geosite: Sha256Hex::from_bytes([base + 3; 32]),
    };
    EngineCatalog {
        amd64: set(0xa1),
        arm64: set(0xb1),
    }
}

/// The bundle of `node` in `fixture`.
pub(crate) fn vps(fixture: &Fixture, node_id: &NodeId) -> VpsBundle {
    bundle(&fixture.deployment, node_id, &fixture.secrets, &engines()).unwrap()
}

/// The exit config of `fixture`.
pub(crate) fn mac_exit(fixture: &Fixture) -> ExitConfig {
    exit(&fixture.deployment, &fixture.interfaces, &fixture.secrets).unwrap()
}

/// The prober config of `fixture`.
pub(crate) fn mac_prober(fixture: &Fixture) -> ProberConfig {
    prober(&fixture.deployment, &fixture.interfaces, &fixture.secrets).unwrap()
}

/// `deployment` with `change` applied to its parts.
pub(crate) fn edit(
    deployment: &Deployment,
    change: impl FnOnce(&mut DeploymentParts),
) -> Deployment {
    let mut parts = deployment.clone().into_parts();
    change(&mut parts);
    Deployment::try_from(parts).unwrap()
}

/// Adds an active CFM 0.5 user holding fresh credentials on every node the
/// fixture's users hold credentials on; returns its id.
pub(crate) fn add_user(fixture: &mut Fixture) -> UserId {
    let id = credentials::user_id().unwrap();
    let nodes: BTreeSet<NodeId> = fixture.deployment.nodes().keys().cloned().collect();
    let mut per_node = BTreeMap::new();
    for node in &nodes {
        per_node.insert(
            node.clone(),
            UserNodePublic {
                short_id: credentials::short_id().unwrap(),
            },
        );
        let entries = [
            (
                SecretRef::UserVlessUuid(id.clone(), node.clone()),
                SecretMaterial::Uuid(credentials::credential_uuid().unwrap()),
            ),
            (
                SecretRef::UserLoopUuid(id.clone(), node.clone()),
                SecretMaterial::Uuid(credentials::credential_uuid().unwrap()),
            ),
            (
                SecretRef::UserHy2Password(id.clone(), node.clone()),
                SecretMaterial::Password(credentials::password().unwrap()),
            ),
        ];
        for (secret_ref, material) in entries {
            fixture
                .secrets
                .insert(SecretEntry::new(secret_ref, material).unwrap())
                .unwrap();
        }
    }
    let user = User {
        id: id.clone(),
        label: LocalLabel::parse("Added user").unwrap(),
        client: ClientProfile {
            line: ClientLine::Cfm05,
            capabilities: BTreeSet::new(),
        },
        status: UserStatus::Active,
        per_node,
        policy: UserPolicy::NONE,
        alias: None,
        agreement: None,
    };
    fixture.deployment = edit(&fixture.deployment, |parts| parts.users.push(user));
    id
}

/// Gives `fixture` a separate tunnel uplink (`en0`) beside its egress.
pub(crate) fn separate_uplink(fixture: &mut Fixture) {
    let uplink = ResolvedInterface {
        bsd_name: BsdName::parse("en0").unwrap(),
        index: InterfaceIndex::new(4).unwrap(),
        lladdr: MacAddr::parse("02:6d:6f:6f:72:02").unwrap(),
        ipv4: std::net::Ipv4Addr::new(192, 168, 50, 20),
    };
    let selector = InterfaceSelector::LinkAddr {
        lladdr: uplink.lladdr,
        subnet: "192.168.50.0/24".parse().unwrap(),
    };
    fixture.deployment = edit(&fixture.deployment, |parts| {
        parts.exit.uplink = Uplink::Separate(selector);
    });
    fixture.interfaces = fixture
        .deployment
        .exit()
        .resolve(
            fixture.interfaces.egress().clone(),
            ResolvedUplink::Separate(uplink),
        )
        .unwrap();
}

/// A copy of `secrets` without `skip`.
pub(crate) fn secrets_without(secrets: &SecretSnapshot, skip: &SecretRef) -> SecretSnapshot {
    secrets_where(secrets, |secret_ref| secret_ref != skip)
}

/// A copy of the secrets `keep` selects.
pub(crate) fn secrets_where(
    secrets: &SecretSnapshot,
    keep: impl Fn(&SecretRef) -> bool,
) -> SecretSnapshot {
    let mut copy = SecretSnapshot::new();
    for secret_ref in secrets.refs() {
        if !keep(&secret_ref) {
            continue;
        }
        let material = match &secret_ref {
            SecretRef::AlertTopic => {
                SecretMaterial::Password(secrets.alert_topic().unwrap().clone())
            }
            SecretRef::RouterAdmin => {
                SecretMaterial::RouterAdminPassword(secrets.router_admin().unwrap().clone())
            }
            SecretRef::NodeRealityPrivate(n) => {
                SecretMaterial::RealityPrivateKey(secrets.reality_private(n).unwrap().clone())
            }
            SecretRef::NodeWgVpsPrivate(n) => {
                SecretMaterial::WgPrivateKey(secrets.wg_vps_private(n).unwrap().clone())
            }
            SecretRef::NodeWgMacPrivate(n) => {
                SecretMaterial::WgPrivateKey(secrets.wg_mac_private(n).unwrap().clone())
            }
            SecretRef::NodeHy2Key(n) => {
                SecretMaterial::Hy2PrivateKey(secrets.hy2_key(n).unwrap().clone())
            }
            SecretRef::NodeHy2Obfs(n, i) => {
                SecretMaterial::Password(secrets.hy2_obfs(n, *i).unwrap().clone())
            }
            SecretRef::NodeSshBootstrapPrivate(n) => {
                SecretMaterial::Ed25519Seed(secrets.ssh_bootstrap(n).unwrap().clone())
            }
            SecretRef::NodeDeadManCheck(n) => uuid(secrets.dead_man_check(n).unwrap()),
            SecretRef::NodeMacAliveCheck(n) => uuid(secrets.mac_alive_check(n).unwrap()),
            SecretRef::UserVlessUuid(u, n) => uuid(secrets.user_vless_uuid(u, n).unwrap()),
            SecretRef::UserHy2Password(u, n) => {
                SecretMaterial::Password(secrets.user_hy2_password(u, n).unwrap().clone())
            }
            SecretRef::UserLoopUuid(u, n) => uuid(secrets.user_loop_uuid(u, n).unwrap()),
            SecretRef::ProbeVlessUuid(n) => uuid(secrets.probe_vless_uuid(n).unwrap()),
            SecretRef::ProbeHy2Password(n) => {
                SecretMaterial::Password(secrets.probe_hy2_password(n).unwrap().clone())
            }
            SecretRef::ProbeLoopUuid(n) => uuid(secrets.probe_loop_uuid(n).unwrap()),
        };
        copy.insert(SecretEntry::new(secret_ref, material).unwrap())
            .unwrap();
    }
    copy
}

fn uuid(secret: &Secret<mooring_model::Uuid>) -> SecretMaterial {
    SecretMaterial::Uuid(secret.clone())
}

/// A test-only one-time host key, generated once with
/// `ssh-keygen -t ed25519 -N '' -C ''` (OpenSSH_10.3p1) so the cloud-init
/// golden is byte-stable. It protects nothing.
pub(crate) const HOST_PRIVATE: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC3Bac9vPvgiPoG81F04fKSXhwU6V1yazxUiBqkiOFH2AAAAIjQRcbz0EXG
8wAAAAtzc2gtZWQyNTUxOQAAACC3Bac9vPvgiPoG81F04fKSXhwU6V1yazxUiBqkiOFH2A
AAAEAuYUn1GwmQTE8NLLA2xdjvY49zECunogFllhnNXgdnxrcFpz28++CI+gbzUXTh8pJe
HBTpXXJrPFSIGqSI4UfYAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";

/// The public key of [`HOST_PRIVATE`].
pub(crate) const HOST_PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILcFpz28++CI+gbzUXTh8pJeHBTpXXJrPFSIGqSI4UfY";

/// A test-only bootstrap public key, generated the same way.
pub(crate) const BOOTSTRAP_PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL7LbLT+EDtpolE12r0wbVvyn8A/1YUWZ/WnXYHmnJy4";

/// The raw key inside an `ssh-ed25519` line.
pub(crate) fn ed25519_of(line: &str) -> Ed25519Pub {
    Ed25519Pub::parse_ssh_authorized_key(line).unwrap()
}

/// The user-data keys: `host_private` and [`BOOTSTRAP_PUBLIC`].
pub(crate) fn cloud_init_keys(host_private: &str) -> CloudInitKeys {
    CloudInitKeys {
        host_private: OpensshHostKey::parse(host_private).unwrap(),
        bootstrap_public: SshEd25519Key::new(BOOTSTRAP_PUBLIC).unwrap(),
    }
}

/// Fixture (a) with lon1 turned back into a planned node pinned to
/// [`HOST_PUBLIC`].
pub(crate) fn planned() -> Fixture {
    let mut fixture = mooring_fixtures::one_node_one_user().unwrap();
    fixture.deployment = edit(&fixture.deployment, |parts| {
        let lon1 = &mut parts.nodes[0];
        lon1.lifecycle = mooring_model::NodeLifecycle::Planned;
        lon1.ssh.host_ed25519 = ed25519_of(HOST_PUBLIC);
    });
    fixture
}
