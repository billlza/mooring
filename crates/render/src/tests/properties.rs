// SPDX-License-Identifier: GPL-3.0-or-later

//! Property tests of the render invariants (design §8.1, §16 L1).

use std::collections::BTreeMap;

use mooring_agent_proto::ManagedFile;
use mooring_keys::credentials;
use mooring_model::UserId;
use mooring_model::collections::NonEmpty;
use mooring_model::exit::TrafficPolicy;
use mooring_model::ports::{
    DEBIAN_EPHEMERAL_PORTS, HopInterval, Hy2Listener, Hy2Obfs, ListenerIdx, Port, PortPlan,
    PortRange,
};
use mooring_model::secret::SecretEntry;
use mooring_model::user::UserStatus;
use proptest::prelude::*;

use crate::mac::exit::ExitRule;
use crate::tests::invariants::{
    exit_of, hy2_of, is_node_deny, is_probe_allow, is_special_deny, position, xray_of,
};
use crate::tests::support::{add_user, big, edit, engines, mac_exit, mac_prober, node, vps};
use crate::vps::hy2::{Hy2Rule, LoopTag};
use crate::vps::served::Identity;
use crate::vps::testing::{digest_with, digest_with_files};
use crate::vps::xray::{OutboundTag, XrayOutbound};

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 48,
        ..ProptestConfig::default()
    }
}

/// What happens to one fixture user.
#[derive(Debug, Clone, Copy)]
enum Fate {
    Active,
    RevokePending,
    Revoked,
}

fn fate() -> impl Strategy<Value = Fate> {
    prop_oneof![
        Just(Fate::Active),
        Just(Fate::RevokePending),
        Just(Fate::Revoked)
    ]
}

proptest! {
    #![proptest_config(config())]

    /// Every active user holding credentials on a node appears exactly once
    /// in each place that node's configs list identities, in id order and
    /// followed by the probe; no other user appears at all.
    #[test]
    fn every_served_identity_appears_exactly_once_per_inbound(
        fates in proptest::collection::vec(fate(), 20)
    ) {
        let mut fixture = big();
        let fates: BTreeMap<UserId, Fate> =
            fixture.deployment.users().keys().cloned().zip(fates).collect();
        fixture.deployment = edit(&fixture.deployment, |parts| {
            for user in &mut parts.users {
                match fates[&user.id] {
                    Fate::Active => {}
                    Fate::RevokePending => user.status = UserStatus::RevokePending,
                    Fate::Revoked => {
                        user.status = UserStatus::Revoked;
                        user.per_node.clear();
                    }
                }
            }
        });
        let mut served: Vec<Identity> = fates
            .iter()
            .filter(|(_, fate)| matches!(fate, Fate::Active))
            .map(|(id, _)| Identity::User(id.clone()))
            .collect();
        served.push(Identity::Probe);
        let names: Vec<String> = served.iter().map(ToString::to_string).collect();
        for id in ["ams1", "lon1"] {
            let xray = xray_of(&fixture, id);
            let reality: Vec<String> = xray.inbounds.reality.settings.clients.iter()
                .map(|client| client.email.to_string()).collect();
            let loopback: Vec<String> = xray.inbounds.loopback.settings.clients.iter()
                .map(|client| client.email.to_string()).collect();
            prop_assert_eq!(&reality, &names.iter().map(|n| format!("{n}@reality")).collect::<Vec<_>>());
            prop_assert_eq!(&loopback, &names.iter().map(|n| format!("{n}@hy2")).collect::<Vec<_>>());
            prop_assert_eq!(
                xray.inbounds.reality.stream_settings.reality_settings.short_ids.len(),
                served.len()
            );
            let hy2 = hy2_of(&fixture, id);
            for inbound in &hy2.inbounds {
                let users: Vec<&Identity> = inbound.users.iter().map(|user| &user.name).collect();
                prop_assert_eq!(users, served.iter().collect::<Vec<_>>());
            }
            let outbounds: Vec<LoopTag> =
                hy2.outbounds.iter().map(|outbound| outbound.tag.clone()).collect();
            let expected: Vec<LoopTag> =
                served.iter().map(|identity| LoopTag(identity.clone())).collect();
            prop_assert_eq!(outbounds, expected);
            let routed: Vec<&Identity> = hy2.route.rules.iter().filter_map(|rule| match rule {
                Hy2Rule::Route(route) => Some(&route.auth_user[0]),
                Hy2Rule::Reject(_) => None,
            }).collect();
            prop_assert_eq!(routed, served.iter().collect::<Vec<_>>());
            prop_assert!(matches!(hy2.route.rules.last(), Some(Hy2Rule::Reject(_))));
            let bundle = vps(&fixture, &node(id));
            for (user, fate) in &fates {
                if !matches!(fate, Fate::Active) {
                    for (_, file) in bundle.files() {
                        prop_assert!(!file.expose_text().contains(user.as_str()));
                    }
                }
            }
        }
    }

    /// Under every traffic policy, `deny` is the first Xray outbound and the
    /// node-address rules (probe allow, then deny) precede the
    /// `SPECIAL_V4` deny in both layers; switches add or drop only their
    /// own rules.
    #[test]
    fn rule_order_holds_under_every_policy(
        flags in proptest::array::uniform5(any::<bool>())
    ) {
        let [deny_cn, block_quic, deny_smtp25, deny_bittorrent, camo_forward] = flags;
        let policy = TrafficPolicy { deny_cn, block_quic, deny_smtp25, deny_bittorrent, camo_forward };
        let mut fixture = big();
        fixture.deployment = edit(&fixture.deployment, |parts| parts.policy = policy);
        let addresses: Vec<std::net::Ipv4Addr> =
            fixture.deployment.node_addresses().values().map(|address| address.ipv4()).collect();
        for id in ["ams1", "lon1"] {
            let xray = xray_of(&fixture, id);
            let outbounds: Vec<XrayOutbound> = xray.outbounds.into();
            prop_assert_eq!(outbounds[0], XrayOutbound::Deny);
            prop_assert_eq!(outbounds.len(), if camo_forward { 4 } else { 2 });
            prop_assert_eq!(xray.inbounds.camo.is_some(), camo_forward);
            let rules = &xray.routing.rules;
            let allow = position(rules, is_probe_allow);
            let deny = position(rules, |rule| is_node_deny(rule, &addresses));
            let special = position(rules, is_special_deny);
            prop_assert!(allow < deny && deny < special);
            let count = |predicate: &dyn Fn(&crate::vps::xray::XrayRule) -> bool| {
                rules.iter().filter(|rule| predicate(rule)).count()
            };
            prop_assert_eq!(count(&|rule| rule.domain.is_some()), usize::from(deny_cn));
            prop_assert_eq!(count(&|rule| rule.protocol.is_some()), usize::from(deny_bittorrent));
            prop_assert_eq!(
                count(&|rule| rule.port.is_some_and(|port| port.0.get() == 25)),
                usize::from(deny_smtp25)
            );
            prop_assert_eq!(
                count(&|rule| rule.port.is_some_and(|port| port.0.get() == 443)),
                usize::from(block_quic)
            );
            prop_assert_eq!(
                count(&|rule| matches!(rule.outbound_tag, OutboundTag::CamoHttp | OutboundTag::CamoQuic)),
                2 * usize::from(camo_forward)
            );
            prop_assert_eq!(rules.last().map(|rule| rule.outbound_tag), Some(OutboundTag::Exit));
            let bundle = vps(&fixture, &node(id));
            let nft = bundle.file(ManagedFile::Nftables).expose_text();
            prop_assert_eq!(nft.contains("tcp dport 80"), camo_forward);
            prop_assert_eq!(nft.contains("udp dport 443"), camo_forward);
            prop_assert_eq!(nft.contains("@camo_targets tcp dport { 80, 443 }"), camo_forward);
            prop_assert!(nft.contains("@camo_targets tcp dport"));
        }
        let exit = exit_of(&fixture);
        let rules = &exit.route.rules;
        let hosts: Vec<ipnet::Ipv4Net> = addresses.iter().copied().map(ipnet::Ipv4Net::from).collect();
        let allow = position(rules, |rule| matches!(rule, ExitRule::Route(r) if r.ip_cidr.as_ref() == Some(&hosts)));
        let reject = position(rules, |rule| matches!(rule, ExitRule::Reject(r) if r.ip_cidr.as_ref() == Some(&hosts)));
        let ipv6 = position(rules, |rule| matches!(rule, ExitRule::Reject(r) if r.ip_version.is_some()));
        let smtp = rules.iter().filter(|rule| matches!(rule, ExitRule::Reject(r) if r.port.is_some())).count();
        prop_assert!(allow < reject && reject < ipv6);
        prop_assert_eq!(smtp, usize::from(deny_smtp25));
        prop_assert!(matches!(rules.last(), Some(ExitRule::Route(r)) if r.ip_cidr.is_none()));
    }

    /// Users never reach the Mac configs: adding users leaves the exit and
    /// prober digests unchanged, so neither engine restarts, while the
    /// VPS bundle and exactly the user-bearing files change.
    #[test]
    fn adding_users_changes_only_the_vps_user_files(
        which in 0usize..4,
        added in 1usize..=3,
    ) {
        let mut fixture = mooring_fixtures::all().unwrap().swap_remove(which);
        let exit = mac_exit(&fixture);
        let prober = mac_prober(&fixture);
        let before: Vec<_> = fixture.deployment.nodes().keys().map(|id| vps(&fixture, id)).collect();
        for _ in 0..added {
            add_user(&mut fixture);
        }
        prop_assert_eq!(mac_exit(&fixture).digest(), exit.digest());
        prop_assert_eq!(mac_prober(&fixture).digest(), prober.digest());
        for old in before {
            let new = vps(&fixture, old.node());
            prop_assert_ne!(new.digest(), old.digest());
            for file in ManagedFile::ALL {
                let changed = new.file(*file).sha256() != old.file(*file).sha256();
                let user_bearing = matches!(file, ManagedFile::XrayConfig | ManagedFile::Hy2Config);
                prop_assert_eq!(changed, user_bearing, "{}", file);
            }
        }
    }

    /// The node's `PortPlan` is the only source of its ports in every config
    /// that names them.
    #[test]
    fn port_plans_are_honoured(
        wg in 1024u16..=9_999,
        reflector in 11_000u16..=32_767,
        first in 61_000u16..=62_000,
        first_hop in 1u16..=1_000,
        second in proptest::option::of((63_100u16..=64_000, 1u16..=900)),
        interval in 5u16..=3_600,
    ) {
        let mut fixture = mooring_fixtures::one_node_three_users().unwrap();
        let listener = |port: u16, hop: u16| {
            Hy2Listener::new(
                Port::new(port).unwrap(),
                PortRange::new(port + 1, port + hop).unwrap(),
                HopInterval::from_seconds(interval).unwrap(),
                Hy2Obfs::Salamander,
            ).unwrap()
        };
        let mut listeners = NonEmpty::new(listener(first, first_hop));
        if let Some((port, hop)) = second {
            listeners.push(listener(port, hop));
            fixture.secrets.insert(SecretEntry::NodeHy2Obfs(
                node("lon1"),
                ListenerIdx::new(1),
                credentials::password().unwrap(),
            )).unwrap();
        }
        let plan = PortPlan::new(
            Port::new(wg).unwrap(),
            Port::new(reflector).unwrap(),
            listeners.clone(),
            Vec::new(),
            DEBIAN_EPHEMERAL_PORTS,
        ).unwrap();
        fixture.deployment = edit(&fixture.deployment, |parts| parts.nodes[0].ports = plan.clone());
        let bundle = vps(&fixture, &node("lon1"));
        let hy2 = hy2_of(&fixture, "lon1");
        prop_assert_eq!(hy2.inbounds.len(), listeners.len().get());
        for (inbound, listener) in hy2.inbounds.iter().zip(listeners.iter()) {
            prop_assert_eq!(inbound.listen_port, listener.port());
        }
        let nft = bundle.file(ManagedFile::Nftables).expose_text();
        let mut udp = vec![wg.to_string()];
        for listener in listeners.iter() {
            prop_assert!(nft.contains(&format!(
                "ip daddr $VPS4 udp dport {} redirect to :{}\n", listener.hop(), listener.port()
            )), "hop redirect");
            udp.push(listener.port().to_string());
        }
        let udp_line = format!("ip daddr $VPS4 udp dport {{ {} }} accept\n", udp.join(", "));
        prop_assert!(nft.contains(&udp_line), "udp accept");
        let reflector_line = format!("tcp dport {reflector} accept\n");
        prop_assert!(nft.contains(&reflector_line), "reflector accept");
        let wgexit = bundle.file(ManagedFile::WgConf).expose_text();
        let listen_line = format!("ListenPort = {wg}\n");
        prop_assert!(wgexit.contains(&listen_line), "ListenPort");
        let exit = exit_of(&fixture);
        prop_assert_eq!(exit.endpoints[0].peers[0].port.get(), wg);
        let xray = xray_of(&fixture, "lon1");
        let allow = &xray.routing.rules[position(&xray.routing.rules, is_probe_allow)];
        prop_assert_eq!(allow.port.unwrap().0.get(), reflector);
        let prober: crate::mac::prober::ProberDocument<serde_json::Value> =
            serde_json::from_slice(mac_prober(&fixture).file().expose_bytes()).unwrap();
        for inbound in &prober.inbounds {
            prop_assert_eq!(inbound.override_port.get(), reflector);
        }
    }

    /// The bundle digest changes with any single byte of any file.
    #[test]
    fn the_bundle_digest_changes_with_any_byte(
        file in 0usize..5,
        at in any::<proptest::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
        let bundle = vps(&fixture, &node("lon1"));
        let file = ManagedFile::ALL[file];
        let mut bytes = bundle.file(file).expose_bytes().to_vec();
        prop_assert_eq!(digest_with(&bundle, file, bytes.clone()), bundle.digest());
        let index = at.index(bytes.len());
        bytes[index] ^= flip;
        prop_assert_ne!(digest_with(&bundle, file, bytes), bundle.digest());
    }
}

#[test]
fn the_bundle_digest_is_deterministic_and_binds_file_boundaries() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let id = node("lon1");
    let first = vps(&fixture, &id);
    let second =
        crate::vps::bundle(&fixture.deployment, &id, &fixture.secrets, &engines()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.digest(), second.digest());
    // Two bundles whose files differ only in where one file ends and the
    // next begins, crafted so that the stream without length prefixes would
    // be identical: the length prefixes keep the digests apart.
    let header = "\nfile hy2.json\n";
    let split_early = vec![
        (ManagedFile::XrayConfig, b"a".to_vec()),
        (ManagedFile::Hy2Config, format!("b{header}c").into_bytes()),
    ];
    let split_late = vec![
        (ManagedFile::XrayConfig, format!("a{header}b").into_bytes()),
        (ManagedFile::Hy2Config, b"c".to_vec()),
    ];
    assert_ne!(
        digest_with_files(&first, split_early),
        digest_with_files(&first, split_late)
    );
    // Engines and the architecture are part of the digest.
    let mut other = engines();
    other.amd64.geoip = other.arm64.geoip;
    let changed = crate::vps::bundle(&fixture.deployment, &id, &fixture.secrets, &other).unwrap();
    assert_ne!(changed.digest(), first.digest());
    for file in ManagedFile::ALL {
        assert_eq!(changed.file(*file), first.file(*file));
    }
}
