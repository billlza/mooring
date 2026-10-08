// SPDX-License-Identifier: GPL-3.0-or-later

//! Every refusal path, the `Apply` header, and cloud-init.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mooring_agent_proto::{
    AgentError, Arch as WireArch, Generation, HostFact, HostFacts, IfName, KernelIdent,
    KernelRelease, ManagedFile, PortRange as WirePortRange,
};
use mooring_keys::ssh::{SshComment, SshKeyPair};
use mooring_model::error::ModelError;
use mooring_model::node::{Arch, NodeLifecycle};
use mooring_model::secret::{SecretRef, SecretSnapshotError};

use crate::error::{HostKeyRule, RenderError, RenderErrorKind, WireField};
use crate::mac::{exit, prober};
use crate::tests::support::{
    HOST_PRIVATE, HOST_PUBLIC, cloud_init_keys, ed25519_of, edit, engines, node, planned,
    secrets_without, vps,
};
use crate::vps::{OpensshHostKey, bundle, cloud_init};

fn kind<T: std::fmt::Debug>(result: Result<T, RenderError>) -> RenderErrorKind {
    result.unwrap_err().kind()
}

#[test]
fn bundles_need_a_known_adopted_node_with_a_target_and_its_secrets() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let catalog = engines();
    let error = bundle(
        &fixture.deployment,
        &node("par1"),
        &fixture.secrets,
        &catalog,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RenderError::Model(ModelError::UnknownNode { .. })
    ));
    assert_eq!(error.kind(), RenderErrorKind::Model);

    let planned = planned();
    let error = bundle(
        &planned.deployment,
        &node("lon1"),
        &planned.secrets,
        &catalog,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RenderError::Model(ModelError::NodeNotDeployable { .. })
    ));

    let targetless = edit(&fixture.deployment, |parts| {
        let lon1 = parts
            .nodes
            .iter_mut()
            .find(|n| n.id == node("lon1"))
            .unwrap();
        let site = lon1.lifecycle.site().unwrap().clone();
        lon1.lifecycle = NodeLifecycle::Adopted { site };
        lon1.reality.target = None;
    });
    let error = bundle(&targetless, &node("lon1"), &fixture.secrets, &catalog).unwrap_err();
    assert!(matches!(
        error,
        RenderError::Model(ModelError::TargetNotSet { .. })
    ));

    for missing in [
        SecretRef::NodeRealityPrivate(node("lon1")),
        SecretRef::NodeHy2Key(node("lon1")),
        SecretRef::NodeWgVpsPrivate(node("lon1")),
        SecretRef::NodeHy2Obfs(node("lon1"), mooring_model::ListenerIdx::FIRST),
        SecretRef::ProbeLoopUuid(node("lon1")),
        SecretRef::UserHy2Password(
            fixture.deployment.users().keys().next().unwrap().clone(),
            node("lon1"),
        ),
    ] {
        let secrets = secrets_without(&fixture.secrets, &missing);
        let error = bundle(&fixture.deployment, &node("lon1"), &secrets, &catalog).unwrap_err();
        assert_eq!(error.kind(), RenderErrorKind::Secret, "{missing}");
        let RenderError::Secret(SecretSnapshotError::Missing { secret_ref }) = error else {
            panic!("expected a missing secret");
        };
        assert_eq!(secret_ref, missing);
    }
    // The other node's bundle never needs this node's secrets.
    let secrets = secrets_without(
        &fixture.secrets,
        &SecretRef::NodeRealityPrivate(node("lon1")),
    );
    assert!(bundle(&fixture.deployment, &node("ams1"), &secrets, &catalog).is_ok());
}

#[test]
fn mac_configs_need_an_applied_node_and_its_secrets() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let unapplied = edit(&fixture.deployment, |parts| {
        for node in &mut parts.nodes {
            let site = node.lifecycle.site().unwrap().clone();
            node.lifecycle = NodeLifecycle::Adopted { site };
        }
    });
    let error = exit(&unapplied, &fixture.interfaces, &fixture.secrets).unwrap_err();
    assert!(matches!(error, RenderError::NoAppliedNodes));
    assert_eq!(error.kind(), RenderErrorKind::NoAppliedNodes);
    assert_eq!(
        kind(prober(&unapplied, &fixture.interfaces, &fixture.secrets)),
        RenderErrorKind::NoAppliedNodes
    );

    // A retiring node loses its tunnel and probes at once.
    let retiring = edit(&fixture.deployment, |parts| {
        let ams1 = parts
            .nodes
            .iter_mut()
            .find(|n| n.id == node("ams1"))
            .unwrap();
        let site = ams1.lifecycle.site().unwrap().clone();
        ams1.lifecycle = NodeLifecycle::Retiring { site };
    });
    let config = exit(&retiring, &fixture.interfaces, &fixture.secrets).unwrap();
    assert_eq!(config.nodes(), [node("lon1")]);
    let probes = prober(&retiring, &fixture.interfaces, &fixture.secrets).unwrap();
    assert!(
        probes
            .probes()
            .iter()
            .all(|probe| probe.node == node("lon1"))
    );
    // The retiring node's address is still denied.
    assert!(config.file().expose_text().contains("46.78.90.12/32"));

    let secrets = secrets_without(&fixture.secrets, &SecretRef::NodeWgMacPrivate(node("ams1")));
    assert_eq!(
        kind(exit(&fixture.deployment, &fixture.interfaces, &secrets)),
        RenderErrorKind::Secret
    );
    let secrets = secrets_without(&fixture.secrets, &SecretRef::ProbeVlessUuid(node("ams1")));
    let error = prober(&fixture.deployment, &fixture.interfaces, &secrets).unwrap_err();
    assert_eq!(error.kind(), RenderErrorKind::Export);
}

/// Mac configs bind only to interfaces resolved for the deployment's own
/// site: a `SameAsExit` site never binds a separate (home) uplink, and a
/// `Separate` site never binds its tunnel to the egress.
#[test]
fn mac_configs_refuse_interfaces_resolved_for_another_uplink_mode() {
    let same_site = mooring_fixtures::two_nodes_three_users().unwrap();
    let mut separate_site = mooring_fixtures::two_nodes_three_users().unwrap();
    crate::tests::support::separate_uplink(&mut separate_site);
    for (deployment, interfaces) in [
        (&same_site.deployment, &separate_site.interfaces),
        (&separate_site.deployment, &same_site.interfaces),
    ] {
        for error in [
            exit(deployment, interfaces, &same_site.secrets).unwrap_err(),
            prober(deployment, interfaces, &same_site.secrets).unwrap_err(),
        ] {
            assert!(
                matches!(
                    error,
                    RenderError::Model(ModelError::InterfacesForOtherSite)
                ),
                "{error:?}"
            );
        }
    }
    // Each site renders with its own interfaces.
    exit(
        &separate_site.deployment,
        &separate_site.interfaces,
        &separate_site.secrets,
    )
    .unwrap();
    prober(
        &same_site.deployment,
        &same_site.interfaces,
        &same_site.secrets,
    )
    .unwrap();
}

fn live_facts(bundle: &crate::vps::VpsBundle) -> HostFacts {
    let site = bundle.site();
    HostFacts {
        uplink: IfName::new(site.host_facts.uplink_interface.as_str()).unwrap(),
        vps4: site.address.ipv4(),
        arch: match site.host_facts.arch {
            Arch::Amd64 => WireArch::Amd64,
            Arch::Arm64 => WireArch::Arm64,
        },
        ip_local_port_range: WirePortRange::new(
            site.host_facts.ephemeral_ports.start().get(),
            site.host_facts.ephemeral_ports.end().get(),
        )
        .unwrap(),
        debian_major: 13,
        kernel: KernelRelease::new("6.12.48+deb13-amd64").unwrap(),
        congestion_control: KernelIdent::new("bbr").unwrap(),
        qdisc: KernelIdent::new("fq").unwrap(),
    }
}

#[test]
fn the_apply_header_carries_the_recorded_site_and_the_hellos_other_facts() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let bundle = vps(&fixture, &node("ams1"));
    let recorded = live_facts(&bundle);
    let header = bundle.header(&recorded).unwrap();
    assert_eq!(header.config_generation, Generation::new(1));
    assert_eq!(header.digest.as_bytes(), bundle.digest().as_bytes());
    assert_eq!(header.host_facts, recorded);
    assert_eq!(header.host_profile_version, bundle.host_profile());
    assert_eq!(&header.engines, &engines().amd64);
    for file in ManagedFile::ALL {
        assert_eq!(*header.files.get(*file), bundle.file(*file).sha256());
    }
    let blobs = header.blobs();
    assert_eq!(blobs.len(), 9);

    // A Hello from a host that changed since adoption does not change what
    // the bundle was rendered for: the header keeps the recorded facts, and
    // only the facts Mooring does not record come from the Hello.
    let mut hello = recorded.clone();
    hello.uplink = IfName::new("ens3").unwrap();
    hello.vps4 = "45.67.89.11".parse().unwrap();
    hello.arch = WireArch::Arm64;
    hello.ip_local_port_range = WirePortRange::new(32768, 61999).unwrap();
    hello.kernel = KernelRelease::new("6.12.50+deb13-amd64").unwrap();
    hello.congestion_control = KernelIdent::new("cubic").unwrap();
    let header = bundle.header(&hello).unwrap();
    let facts = &header.host_facts;
    assert_eq!(
        (
            &facts.uplink,
            facts.vps4,
            facts.arch,
            facts.ip_local_port_range
        ),
        (
            &recorded.uplink,
            recorded.vps4,
            recorded.arch,
            recorded.ip_local_port_range
        )
    );
    assert_eq!(
        (&facts.kernel, &facts.congestion_control, facts.debian_major),
        (&hello.kernel, &hello.congestion_control, hello.debian_major)
    );
    // So the agent's precondition names what changed since adoption: a
    // renamed NIC is HostFactsChanged{Uplink} (design §16 L5), a changed
    // range a PortPlanConflict.
    let mut renamed = header.host_facts.clone();
    renamed.uplink = IfName::new("ens3").unwrap();
    assert_eq!(
        header.host_facts.check_live(&renamed),
        Err(AgentError::HostFactsChanged {
            field: HostFact::Uplink
        })
    );
    let mut ranged = header.host_facts.clone();
    ranged.ip_local_port_range = WirePortRange::new(32768, 61999).unwrap();
    assert!(matches!(
        header.host_facts.check_live(&ranged),
        Err(AgentError::PortPlanConflict { .. })
    ));
}

#[test]
fn arm64_nodes_get_the_arm64_engines() {
    let mut fixture = mooring_fixtures::one_node_one_user().unwrap();
    fixture.deployment = edit(&fixture.deployment, |parts| {
        let NodeLifecycle::Applied { site, .. } = &mut parts.nodes[0].lifecycle else {
            unreachable!()
        };
        site.host_facts.arch = Arch::Arm64;
    });
    let arm = vps(&fixture, &node("lon1"));
    assert_eq!(arm.engines(), &engines().arm64);
    assert_ne!(arm.engines(), &engines().amd64);
}

#[test]
fn cloud_init_is_only_for_a_planned_node_with_its_pinned_host_key() {
    let fixture = planned();
    let lon1 = node("lon1");
    let pinned = cloud_init_keys(HOST_PRIVATE);
    assert_eq!(pinned.host_private.public_key(), ed25519_of(HOST_PUBLIC));
    assert!(cloud_init(&fixture.deployment, &lon1, &pinned).is_ok());

    // Another well-formed host key pair: its public key is not the pin.
    let other = SshKeyPair::generate().unwrap();
    let other_private = other.openssh_private_key(&SshComment::default()).unwrap();
    let error = cloud_init(
        &fixture.deployment,
        &lon1,
        &cloud_init_keys(other_private.expose_pem()),
    )
    .unwrap_err();
    assert!(matches!(&error, RenderError::HostKeyNotPinned { node } if *node == lon1));
    assert_eq!(error.kind(), RenderErrorKind::HostKeyNotPinned);

    let applied = mooring_fixtures::one_node_one_user().unwrap();
    let error = cloud_init(&applied.deployment, &lon1, &pinned).unwrap_err();
    assert_eq!(error.kind(), RenderErrorKind::NodeNotPlanned);
    assert!(matches!(
        error,
        RenderError::NodeNotPlanned {
            stage: mooring_model::node::LifecycleStage::Applied,
            ..
        }
    ));
    assert_eq!(
        kind(cloud_init(&fixture.deployment, &node("par1"), &pinned)),
        RenderErrorKind::Model
    );
}

#[test]
fn cloud_init_accepts_the_key_encoder_and_writes_the_pinned_public_key() {
    let pair = SshKeyPair::generate().unwrap();
    let public = pair.public().authorized_key();
    let mut fixture = planned();
    fixture.deployment = edit(&fixture.deployment, |parts| {
        parts.nodes[0].ssh.host_ed25519 = pair.public().key();
    });
    for comment in [
        SshComment::default(),
        SshComment::parse("mooring-host@lon1").unwrap(),
    ] {
        let private = pair.openssh_private_key(&comment).unwrap();
        let keys = cloud_init_keys(private.expose_pem());
        assert_eq!(keys.host_private.public_key(), pair.public().key());
        let user_data = cloud_init(&fixture.deployment, &node("lon1"), &keys).unwrap();
        let text = std::str::from_utf8(user_data.expose_bytes()).unwrap();
        for line in private.expose_pem().lines() {
            assert!(text.contains(&format!("\n    {line}\n")));
        }
        assert!(text.contains(&format!("ed25519_public: \"{public}\"\n")));
        assert_eq!(
            format!("{user_data:?}"),
            format!("UserData {{ len: {}, .. }}", text.len())
        );
        assert!(!format!("{keys:?}").contains("PRIVATE"));
    }
}

/// [`HOST_PRIVATE`] with its decoded bytes changed by `change`, armored
/// again as OpenSSH writes it.
fn host_private_with(change: impl FnOnce(&mut Vec<u8>)) -> String {
    let body: String = HOST_PRIVATE
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut bytes = STANDARD.decode(body).unwrap();
    change(&mut bytes);
    let mut text = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in STANDARD.encode(&bytes).as_bytes().chunks(70) {
        text.push_str(std::str::from_utf8(chunk).unwrap());
        text.push('\n');
    }
    text + "-----END OPENSSH PRIVATE KEY-----\n"
}

/// Offsets in the decoded [`HOST_PRIVATE`] (OpenSSH `PROTOCOL.key`): the
/// 43-byte header, the 51-byte public blob (key at 62), the private section
/// length at 94, then the section: check integers at 98 and 102, the key
/// type at 110, the public key at 125, seed and public key at 161 and 193,
/// an empty comment, and the padding `1..=5` at 229.
mod offsets {
    pub(super) const CIPHER: usize = 19;
    pub(super) const HEADER_KEY: usize = 62;
    pub(super) const CHECK: usize = 98;
    pub(super) const KEY_TYPE_END: usize = 120;
    pub(super) const SECTION_KEY: usize = 125;
    pub(super) const PRIVATE_PUBLIC: usize = 193;
    pub(super) const PADDING: usize = 229;
}

#[test]
fn cloud_init_rejects_host_keys_that_are_not_one_ed25519_key_pair() {
    use offsets::*;
    // The unchanged round trip parses, so each change below is the cause.
    assert_eq!(
        OpensshHostKey::parse(&host_private_with(|_| ()))
            .unwrap()
            .public_key(),
        ed25519_of(HOST_PUBLIC)
    );
    let flip = |at: usize| move |bytes: &mut Vec<u8>| bytes[at] ^= 1;
    let contents = [
        host_private_with(flip(CIPHER)),
        host_private_with(flip(HEADER_KEY)),
        host_private_with(flip(CHECK)),
        host_private_with(flip(KEY_TYPE_END)),
        host_private_with(flip(SECTION_KEY)),
        host_private_with(flip(PRIVATE_PUBLIC)),
        host_private_with(|bytes| bytes[PADDING + 4] = 6),
        host_private_with(|bytes| bytes.push(0)),
        host_private_with(|bytes| {
            bytes.pop();
        }),
        host_private_with(|bytes| bytes.truncate(HEADER_KEY)),
    ];
    let cases = [
        (String::new(), HostKeyRule::Armor),
        (
            HOST_PRIVATE.replace("OPENSSH PRIVATE", "RSA PRIVATE"),
            HostKeyRule::Armor,
        ),
        (HOST_PRIVATE.trim_end().to_owned(), HostKeyRule::Armor),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n".to_owned(),
            HostKeyRule::Body,
        ),
        (HOST_PRIVATE.replacen("b3Bl", "b3B!", 1), HostKeyRule::Body),
        (
            HOST_PRIVATE.replacen("\nQyNT", "\n\nQyNT", 1),
            HostKeyRule::Body,
        ),
        (
            HOST_PRIVATE.replacen("\nQyNT", "QyNT", 1),
            HostKeyRule::Body,
        ),
        (HOST_PRIVATE.replacen("b3Bl", "b3B=", 1), HostKeyRule::Body),
    ]
    .into_iter()
    .chain(contents.map(|text| (text, HostKeyRule::Contents)));
    for (bad, rule) in cases {
        let error = OpensshHostKey::parse(&bad).unwrap_err();
        assert_eq!(error.kind(), RenderErrorKind::InvalidHostKey);
        let RenderError::InvalidHostKey { rule: found } = error else {
            unreachable!()
        };
        assert_eq!(found, rule, "{bad:?}");
    }
}

#[test]
fn unreachable_variants_have_their_kinds_and_messages() {
    let wire = RenderError::WireValue {
        field: WireField::TargetHost(node("lon1")),
    };
    assert_eq!(wire.kind(), RenderErrorKind::WireValue);
    assert_eq!(
        wire.to_string(),
        "the REALITY target name of node lon1 does not satisfy both the model's and the agent protocol's rule"
    );
    for field in [
        WireField::AccountingName(mooring_model::UserId::parse("fxuseraaab").unwrap()),
        WireField::UplinkInterface,
        WireField::EphemeralPorts,
        WireField::CertificateName,
        WireField::HttpStatus,
        WireField::SshEd25519Key,
    ] {
        assert!(!field.to_string().is_empty());
    }
    for rule in [HostKeyRule::Armor, HostKeyRule::Body, HostKeyRule::Contents] {
        let error = RenderError::InvalidHostKey { rule };
        assert!(error.to_string().ends_with(&rule.to_string()));
    }
    let encode = RenderError::Encode(serde_json::from_str::<u8>("x").unwrap_err());
    assert_eq!(encode.kind(), RenderErrorKind::Encode);
    assert!(std::error::Error::source(&encode).is_some());
}

#[test]
fn every_error_kind_is_named_once() {
    let named = [
        RenderErrorKind::Model,
        RenderErrorKind::Secret,
        RenderErrorKind::Export,
        RenderErrorKind::NoAppliedNodes,
        RenderErrorKind::WireValue,
        RenderErrorKind::AddressNotOnUplink,
        RenderErrorKind::TargetFactsForOtherHost,
        RenderErrorKind::NodeNotPlanned,
        RenderErrorKind::HostKeyNotPinned,
        RenderErrorKind::InvalidHostKey,
        RenderErrorKind::Encode,
    ];
    assert_eq!(named.as_slice(), RenderErrorKind::ALL);
    let names: std::collections::BTreeSet<&str> = named.iter().map(|kind| kind.name()).collect();
    assert_eq!(names.len(), named.len());
    assert_eq!(
        RenderErrorKind::AddressNotOnUplink.to_string(),
        "AddressNotOnUplink"
    );
}
