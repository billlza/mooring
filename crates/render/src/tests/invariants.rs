// SPDX-License-Identifier: GPL-3.0-or-later

//! The invariants the renderers guarantee, checked on every fixture.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use mooring_agent_proto::ManagedFile;
use mooring_fixtures::Fixture;
use mooring_keys::x25519::{RealityKeyPair, WgKeyPair};
use mooring_model::exit::ProbeProtocol;
use mooring_model::ipv4::{SPECIAL_V4, SpecialClass};
use mooring_model::node::NodeAddress;
use mooring_model::secret::{RealityPrivateKey, WgPrivateKey};

use crate::mac::exit::{ExitDocument, ExitRule};
use crate::mac::prober::ProberDocument;
use crate::tests::support::{fixtures, mac_exit, mac_prober, node, separate_uplink, vps};
use crate::text_value::IpMatch;
use crate::vps::hy2::Hy2Config;
use crate::vps::xray::{OutboundTag, XrayConfig, XrayOutbound, XrayRule};

pub(crate) fn xray_of(fixture: &Fixture, id: &str) -> XrayConfig {
    let bundle = vps(fixture, &node(id));
    serde_json::from_slice(bundle.file(ManagedFile::XrayConfig).expose_bytes()).unwrap()
}

pub(crate) fn hy2_of(fixture: &Fixture, id: &str) -> Hy2Config {
    let bundle = vps(fixture, &node(id));
    serde_json::from_slice(bundle.file(ManagedFile::Hy2Config).expose_bytes()).unwrap()
}

pub(crate) fn exit_of(fixture: &Fixture) -> ExitDocument {
    serde_json::from_slice(mac_exit(fixture).file().expose_bytes()).unwrap()
}

fn special_nets() -> Vec<Ipv4Net> {
    SPECIAL_V4.iter().map(|class| class.net()).collect()
}

/// The position of the first rule matching `predicate`.
pub(crate) fn position<T>(rules: &[T], predicate: impl Fn(&T) -> bool) -> usize {
    rules.iter().position(predicate).unwrap()
}

pub(crate) fn is_probe_allow(rule: &XrayRule) -> bool {
    rule.user.is_some() && rule.outbound_tag == OutboundTag::Exit
}

pub(crate) fn is_node_deny(rule: &XrayRule, addresses: &[Ipv4Addr]) -> bool {
    rule.user.is_none()
        && rule.outbound_tag == OutboundTag::Deny
        && rule.ip.as_deref()
            == Some(
                &addresses
                    .iter()
                    .copied()
                    .map(IpMatch::Host)
                    .collect::<Vec<_>>(),
            )
}

pub(crate) fn is_special_deny(rule: &XrayRule) -> bool {
    rule.ip
        .as_ref()
        .is_some_and(|ip| ip.contains(&IpMatch::Net(SpecialClass::Loopback.net())))
}

fn node_addresses(fixture: &Fixture) -> Vec<Ipv4Addr> {
    fixture
        .deployment
        .node_addresses()
        .values()
        .map(|address| address.ipv4())
        .collect()
}

#[test]
fn deny_is_the_first_outbound_and_exit_is_bound_to_wgexit() {
    for fixture in fixtures() {
        for id in fixture.deployment.nodes().keys() {
            let xray = xray_of(&fixture, id.as_str());
            let outbounds: Vec<XrayOutbound> = xray.outbounds.into();
            assert_eq!(outbounds[0], XrayOutbound::Deny);
            assert!(matches!(outbounds[1], XrayOutbound::Exit(_)));
            let target = fixture
                .deployment
                .node(id)
                .unwrap()
                .reality
                .target
                .as_ref()
                .unwrap();
            for outbound in &outbounds[2..] {
                let XrayOutbound::CamoRedirect(camo) = outbound else {
                    panic!("only camouflage redirects follow exit");
                };
                assert_eq!(camo.ip, target.ipv4());
            }
        }
    }
}

#[test]
fn reordered_or_rebound_outbounds_do_not_read_back() {
    let fixture = mooring_fixtures::one_node_one_user().unwrap();
    let bundle = vps(&fixture, &node("lon1"));
    let text = std::str::from_utf8(bundle.file(ManagedFile::XrayConfig).expose_bytes()).unwrap();
    let mut no_camo = mooring_fixtures::one_node_one_user().unwrap();
    no_camo.deployment = crate::tests::support::edit(&no_camo.deployment, |parts| {
        parts.policy.camo_forward = false;
    });
    let no_camo = vps(&no_camo, &node("lon1"));
    let no_camo = no_camo.file(ManagedFile::XrayConfig).expose_bytes();
    // Every swap of two outbounds, or of two inbounds, with and without the
    // camouflage forwards, is refused.
    for bytes in [text.as_bytes(), no_camo] {
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert!(serde_json::from_value::<XrayConfig>(value.clone()).is_ok());
        for list in ["outbounds", "inbounds"] {
            let len = value[list].as_array().unwrap().len();
            for first in 0..len {
                for second in first + 1..len {
                    let mut swapped = value.clone();
                    swapped[list].as_array_mut().unwrap().swap(first, second);
                    assert!(
                        serde_json::from_value::<XrayConfig>(swapped).is_err(),
                        "{list} {first} and {second} swapped"
                    );
                }
            }
        }
    }
    for (from, to) in [
        ("\"interface\": \"wgexit\"", "\"interface\": \"eth0\""),
        (
            "\"domainStrategy\": \"ForceIPv4\"",
            "\"domainStrategy\": \"UseIPv4\"",
        ),
        ("\"tcpUserTimeout\": 30000", "\"tcpUserTimeout\": 1"),
        (
            "\"userLevel\": 1\n      }\n    },\n    {\n      \"tag\": \"camo-u443-out\"",
            "\"userLevel\": 0\n      }\n    },\n    {\n      \"tag\": \"camo-u443-out\"",
        ),
        (
            "\"redirect\": \"45.67.89.200:80\"",
            "\"redirect\": \"45.67.89.200:22\"",
        ),
        (
            "\"redirect\": \"45.67.89.200:443\"",
            "\"redirect\": \"10.0.0.1:443\"",
        ),
        ("\"loglevel\": \"none\"", "\"loglevel\": \"info\""),
        ("\"loglevel\": \"none\"", "\"loglevel\": \"debug\""),
        ("\"loglevel\": \"none\"", "\"loglevel\": \"warning\""),
        ("\"loglevel\": \"none\"", "\"loglevel\": \"error\""),
    ] {
        assert!(text.contains(from), "{from}");
        let edited = text.replacen(from, to, 1);
        assert!(
            serde_json::from_str::<XrayConfig>(&edited).is_err(),
            "{to} read back"
        );
    }
    let hy2 = std::str::from_utf8(bundle.file(ManagedFile::Hy2Config).expose_bytes()).unwrap();
    for level in ["info", "debug", "warn", "trace"] {
        let edited = hy2.replacen(
            "\"level\": \"fatal\"",
            &format!("\"level\": \"{level}\""),
            1,
        );
        assert!(
            serde_json::from_str::<Hy2Config>(&edited).is_err(),
            "{level}"
        );
    }
}

#[test]
fn special_v4_is_the_one_list_behind_every_deny() {
    let special = special_nets();
    assert!(special.contains(&"127.0.0.0/8".parse().unwrap()));
    assert!(special.contains(&"224.0.0.0/4".parse().unwrap()));
    for fixture in fixtures() {
        for id in fixture.deployment.nodes().keys() {
            let xray = xray_of(&fixture, id.as_str());
            for server in &xray.dns.servers {
                assert_eq!(server.unexpected_ips, special);
            }
            let rule = &xray.routing.rules[position(&xray.routing.rules, is_special_deny)];
            let mut expected: Vec<IpMatch> = special.iter().copied().map(IpMatch::Net).collect();
            expected.push(IpMatch::AllIpv6);
            assert_eq!(rule.ip.as_ref(), Some(&expected));
            assert_eq!(rule.outbound_tag, OutboundTag::Deny);
        }
        let exit = exit_of(&fixture);
        let special_rejects: Vec<_> = exit
            .route
            .rules
            .iter()
            .filter_map(|rule| match rule {
                ExitRule::Reject(reject) => reject.ip_cidr.as_ref(),
                ExitRule::Route(_) => None,
            })
            .filter(|cidr| cidr.contains(&SpecialClass::Multicast.net()))
            .collect();
        assert_eq!(special_rejects, [&special]);
    }
}

#[test]
fn node_addresses_are_reachable_only_by_the_probe_on_the_reflector_port() {
    for fixture in fixtures() {
        let addresses = node_addresses(&fixture);
        for (id, node) in fixture.deployment.nodes() {
            let rules = xray_of(&fixture, id.as_str()).routing.rules;
            let allow = position(&rules, is_probe_allow);
            let deny = position(&rules, |rule| is_node_deny(rule, &addresses));
            let special = position(&rules, is_special_deny);
            assert!(allow < deny && deny < special, "{allow} {deny} {special}");
            let rule = &rules[allow];
            assert_eq!(
                rule.user
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                ["probe@reality", "probe@hy2"]
            );
            assert_eq!(rule.port.unwrap().0, node.ports.reflector());
            assert_eq!(
                rule.ip.as_ref().unwrap(),
                &addresses
                    .iter()
                    .copied()
                    .map(IpMatch::Host)
                    .collect::<Vec<_>>()
            );
        }
        let exit = exit_of(&fixture);
        let rules = &exit.route.rules;
        let hosts: Vec<Ipv4Net> = addresses.iter().copied().map(Ipv4Net::from).collect();
        let allow = position(
            rules,
            |rule| matches!(rule, ExitRule::Route(route) if route.ip_cidr.as_ref() == Some(&hosts)),
        );
        let reject = position(
            rules,
            |rule| matches!(rule, ExitRule::Reject(reject) if reject.ip_cidr.as_ref() == Some(&hosts)),
        );
        let special = position(rules, |rule| {
            matches!(rule, ExitRule::Reject(reject)
                if reject.ip_cidr.as_ref().is_some_and(|cidr| cidr.contains(&SpecialClass::Loopback.net())))
        });
        assert!(allow < reject && reject < special);
        let ExitRule::Route(route) = &rules[allow] else {
            unreachable!()
        };
        let reflectors: BTreeSet<_> = fixture
            .deployment
            .nodes()
            .values()
            .map(|node| node.ports.reflector())
            .collect();
        assert_eq!(
            route.port.as_ref().unwrap(),
            &reflectors.into_iter().collect::<Vec<_>>()
        );
        assert!(route.network.is_some());
    }
}

#[test]
fn every_mac_socket_is_bound_to_a_resolved_interface() {
    let separate = fixtures().into_iter().map(|mut fixture| {
        separate_uplink(&mut fixture);
        fixture
    });
    for fixture in fixtures().into_iter().chain(separate) {
        let uplink = &fixture.interfaces.uplink_interface().bsd_name;
        let egress = &fixture.interfaces.egress().bsd_name;
        let exit = exit_of(&fixture);
        for endpoint in &exit.endpoints {
            assert_eq!(endpoint.bind_interface.name(), uplink);
        }
        assert_eq!(exit.outbounds[0].bind_interface.name(), egress);
        assert_eq!(&exit.route.default_interface, egress);
        assert!(!exit.route.auto_detect_interface);
        let prober: ProberDocument<serde_json::Value> =
            serde_json::from_slice(mac_prober(&fixture).file().expose_bytes()).unwrap();
        for outbound in &prober.outbounds {
            assert_eq!(outbound["bind_interface"], uplink.as_str());
        }
        assert_eq!(&prober.route.default_interface, uplink);
        assert!(!prober.route.auto_detect_interface);
    }
}

#[test]
fn rendered_keys_belong_to_the_published_public_keys() {
    for fixture in fixtures() {
        let exit = exit_of(&fixture);
        for (id, node) in fixture.deployment.nodes() {
            let xray = xray_of(&fixture, id.as_str());
            let reality = &xray.inbounds.reality.stream_settings.reality_settings;
            let private: &RealityPrivateKey = reality.private_key.expose();
            let pair = RealityKeyPair::from_private(private.clone()).unwrap();
            assert_eq!(pair.public(), node.reality.public_key, "{id} REALITY key");
            let bundle = vps(&fixture, id);
            let wgexit = bundle.file(ManagedFile::WgConf).expose_text();
            let vps_private = wgexit
                .lines()
                .find_map(|line| line.strip_prefix("PrivateKey = "))
                .unwrap();
            let vps_pair =
                WgKeyPair::from_private(WgPrivateKey::parse(vps_private).unwrap()).unwrap();
            assert_eq!(vps_pair.public(), node.wg.vps_pub, "{id} VPS WireGuard key");
            assert!(wgexit.contains(&format!("PublicKey = {}\n", node.wg.mac_pub)));
            let endpoint = exit
                .endpoints
                .iter()
                .find(|endpoint| &endpoint.tag.0 == id)
                .unwrap();
            let mac_pair = WgKeyPair::from_private(endpoint.private_key.expose().clone()).unwrap();
            assert_eq!(mac_pair.public(), node.wg.mac_pub, "{id} Mac WireGuard key");
            assert_eq!(endpoint.peers[0].public_key, node.wg.vps_pub);
            assert_eq!(endpoint.address[0], node.wg_index.mac_host());
            assert_eq!(endpoint.peers[0].allowed_ips[0], node.wg_index.vps_host());
            let NodeAddress::Public(vps4) = node.lifecycle.address().unwrap();
            assert_eq!(endpoint.peers[0].address, vps4);
            assert_eq!(endpoint.peers[0].port, node.ports.wg());
        }
    }
}

#[test]
fn hysteria2_tls_material_is_inline_and_pinned() {
    for fixture in fixtures() {
        for (id, node) in fixture.deployment.nodes() {
            let hy2 = hy2_of(&fixture, id.as_str());
            let text = serde_json::to_value(&hy2.inbounds[0].tls).unwrap();
            let lines: Vec<&str> = text["certificate"]
                .as_array()
                .unwrap()
                .iter()
                .map(|line| line.as_str().unwrap())
                .collect();
            assert_eq!(lines, node.hy2.certificate.lines().collect::<Vec<_>>());
            // The inline certificate is the one OpenSSL recorded pins for.
            assert_eq!(
                mooring_model::Sha256Digest::of(node.hy2.certificate.der()),
                mooring_fixtures::recorded_pins(id).unwrap().der_sha256()
            );
            let key = fixture.secrets.hy2_key(id).unwrap();
            assert_eq!(
                text["key"].as_array().unwrap().len(),
                key.expose_lines().count()
            );
        }
    }
}

#[test]
fn wgexit_steers_device_bound_sockets_and_accepts_local_replies() {
    for fixture in fixtures() {
        for id in fixture.deployment.nodes().keys() {
            let bundle = vps(&fixture, id);
            let text = bundle.file(ManagedFile::WgConf).expose_text();
            for line in [
                "Table = off\n",
                "MTU = 1280\n",
                "PostUp = sysctl -qw net.ipv4.conf.%i.accept_local=1\n",
                "PostUp = ip -4 rule add pref 10000 oif %i lookup 77\n",
                "PostUp = ip -4 route replace default dev %i table 77\n",
                "AllowedIPs = 0.0.0.0/0\n",
            ] {
                assert!(text.contains(line), "{line}");
            }
            assert!(!text.contains("Endpoint"));
        }
    }
}

#[test]
fn nftables_guards_the_engines_and_scopes_every_public_rule() {
    for fixture in fixtures() {
        for (id, node) in fixture.deployment.nodes() {
            let bundle = vps(&fixture, id);
            let text = bundle.file(ManagedFile::Nftables).expose_text();
            let target = node.reality.target.as_ref().unwrap().ipv4();
            let NodeAddress::Public(vps4) = node.lifecycle.address().unwrap();
            assert!(text.starts_with("flush ruleset\n"));
            assert!(text.contains(&format!("define VPS4 = {vps4}\n")));
            assert!(text.contains(&format!(
                "define FLOW_CAP = {}\n",
                fixture.deployment.exit().flow_cap.get()
            )));
            assert!(text.contains(&format!("elements = {{ {target} }}")));
            assert!(text.contains("elements = { \"wgexit\" }"));
            for line in text.lines().filter(|line| line.contains(" dport ")) {
                let scoped = line.contains("ip daddr $VPS4")
                    || line.contains("meta skuid")
                    || line.contains("ip daddr 127.0.0.1");
                assert!(scoped, "unscoped port rule {line:?}");
            }
            let hop = node.ports.hy2().first().hop();
            let port = node.ports.hy2().first().port();
            assert!(text.contains(&format!(
                "ip daddr $VPS4 udp dport {hop} redirect to :{port}\n"
            )));
            assert!(text.contains(&format!(
                "ip daddr $VPS4 udp dport {{ {}, {port} }} accept\n",
                node.ports.wg()
            )));
            assert!(text.contains(&format!(
                "ip daddr $VPS4 tcp dport {} accept\n",
                node.ports.reflector()
            )));
            let guard: Vec<&str> = text
                .lines()
                .filter(|line| line.contains("meta skuid"))
                .map(str::trim)
                .collect();
            assert_eq!(guard.len(), 6);
            assert!(
                guard[0].ends_with("oifname \"wgexit\" ip daddr != 10.77.0.0/16 jump exit_flow")
            );
            assert!(guard[3].ends_with("counter name xray_guard reject"));
            assert!(guard[5].ends_with("counter name hy2_guard reject"));
            // Each per-source set carries one kind of stateful expression.
            let set_of = |needle: &str| {
                let line = text.lines().find(|line| line.contains(needle)).unwrap();
                line.split("add @")
                    .nth(1)
                    .unwrap()
                    .split(' ')
                    .next()
                    .unwrap()
                    .to_owned()
            };
            let sets = [
                set_of("ct count over 64"),
                set_of("limit rate over 50/second"),
                set_of("limit rate over 5/second"),
            ];
            assert_eq!(sets, ["camo_tcp_src", "camo_udp_src", "refl_src"]);
            assert!(text.contains(
                "\tset camo_tcp_src {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic\n\t}\n"
            ));
            for (position, line) in text.lines().enumerate() {
                if line.contains("counter name") {
                    let name = line
                        .split("counter name ")
                        .nth(1)
                        .unwrap()
                        .split(' ')
                        .next()
                        .unwrap();
                    let declared = format!("\tcounter {name} {{");
                    let declared_at = text.lines().position(|other| other == declared);
                    assert!(
                        declared_at.is_some_and(|at| at < position),
                        "{name} declared"
                    );
                }
            }
        }
    }
}

#[test]
fn probes_follow_the_probe_policy_by_applied_position() {
    let one = mooring_fixtures::one_node_one_user().unwrap();
    let ports: Vec<(String, ProbeProtocol, u16)> = mac_prober(&one)
        .probes()
        .iter()
        .map(|probe| (probe.node.to_string(), probe.protocol, probe.port.get()))
        .collect();
    assert_eq!(
        ports,
        [
            ("lon1".to_owned(), ProbeProtocol::Reality, 47101),
            ("lon1".to_owned(), ProbeProtocol::Hy2, 47102),
        ]
    );
    let two = mooring_fixtures::two_nodes_three_users().unwrap();
    let ports: Vec<(String, u16)> = mac_prober(&two)
        .probes()
        .iter()
        .map(|probe| (probe.node.to_string(), probe.port.get()))
        .collect();
    assert_eq!(
        ports,
        [
            ("ams1".to_owned(), 47101),
            ("ams1".to_owned(), 47102),
            ("lon1".to_owned(), 47103),
            ("lon1".to_owned(), 47104),
        ]
    );
    let prober: ProberDocument<serde_json::Value> =
        serde_json::from_slice(mac_prober(&two).file().expose_bytes()).unwrap();
    for (inbound, probe) in prober.inbounds.iter().zip(mac_prober(&two).probes()) {
        let node = two.deployment.node(&probe.node).unwrap();
        assert_eq!(inbound.listen_port, probe.port);
        assert_eq!(inbound.override_port, node.ports.reflector());
        assert_eq!(
            Some(NodeAddress::Public(inbound.override_address)),
            node.lifecycle.address()
        );
    }
}

#[test]
fn the_mac_exit_never_names_a_user() {
    for fixture in fixtures() {
        let text = mac_exit(&fixture);
        let text = text.file().expose_text();
        for user in fixture.deployment.users().keys() {
            assert!(!text.contains(user.as_str()));
        }
        assert_eq!(
            mac_exit(&fixture).nodes(),
            fixture
                .deployment
                .nodes()
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn watch_config_pins_the_target_and_keepalive() {
    for fixture in fixtures() {
        for (id, node) in fixture.deployment.nodes() {
            let bundle = vps(&fixture, id);
            let watch: mooring_agent_proto::WatchConfig =
                serde_json::from_slice(bundle.file(ManagedFile::WatchConfig).expose_bytes())
                    .unwrap();
            let target = node.reality.target.as_ref().unwrap();
            assert_eq!(watch.keepalive_secs.get(), node.wg.keepalive.seconds());
            assert_eq!(watch.target.host.as_str(), target.host().as_str());
            assert_eq!(watch.target.ipv4, target.ipv4().get());
        }
    }
}

/// The rules of chain `name` in a rendered ruleset, trimmed, without the
/// chain's own header line or closing brace.
fn chain<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    let header = format!("\tchain {name} {{");
    let start = text
        .lines()
        .position(|line| line == header)
        .unwrap_or_else(|| panic!("no chain {name}"));
    text.lines()
        .skip(start + 1)
        .take_while(|line| *line != "\t}")
        .map(str::trim)
        .collect()
}

/// Fail-closed settings of `nftables.conf` that a re-accepted golden could
/// otherwise lose silently (design §8.5).
#[test]
fn nftables_drops_by_default_and_gates_exit_traffic_first() {
    for fixture in fixtures() {
        for id in fixture.deployment.nodes().keys() {
            let bundle = vps(&fixture, id);
            let text = bundle.file(ManagedFile::Nftables).expose_text();
            assert!(text.contains("\ntable inet mooring {\n"));
            assert!(text.contains(
                "\tset exit_closed {\n\t\ttype ifname\n\t\telements = { \"wgexit\" }\n\t}\n"
            ));

            let input = chain(text, "input");
            assert_eq!(
                input[0],
                "type filter hook input priority filter; policy drop;"
            );
            let wgexit_drop = input
                .iter()
                .position(|rule| *rule == "iifname \"wgexit\" drop")
                .expect("input drops everything that arrives on wgexit");
            let first_accept = input
                .iter()
                .position(|rule| rule.starts_with("ip daddr $VPS4") && rule.ends_with("accept"))
                .unwrap();
            assert!(
                wgexit_drop < first_accept,
                "the wgexit drop precedes public accepts"
            );

            let forward = chain(text, "forward");
            assert_eq!(
                forward,
                ["type filter hook forward priority filter; policy drop;"]
            );

            let output = chain(text, "output");
            assert_eq!(
                &output[..3],
                [
                    "type filter hook output priority filter; policy accept;",
                    "oifname @exit_closed meta l4proto tcp reject with tcp reset",
                    "oifname @exit_closed reject with icmpx host-unreachable",
                ],
                "the gate comes before any owner-guard accept"
            );
            assert!(output[3].starts_with("meta skuid"));

            let exit_flow = chain(text, "exit_flow");
            assert_eq!(
                exit_flow,
                [
                    "ct state new ct count over $FLOW_CAP counter name flow_cap reject",
                    "accept"
                ]
            );
        }
    }
}

/// Xray's log settings: no access log, no run-time log at all (a warning
/// level would still name every domain whose DoH lookup fails), and every
/// address masked should a level ever be raised (design §8.2, §15).
#[test]
fn xray_logs_nothing_at_run_time() {
    for fixture in fixtures() {
        for id in fixture.deployment.nodes().keys() {
            let bundle = vps(&fixture, id);
            let config: serde_json::Value =
                serde_json::from_slice(bundle.file(ManagedFile::XrayConfig).expose_bytes())
                    .unwrap();
            assert_eq!(
                config["log"],
                serde_json::json!({
                    "access": "none",
                    "loglevel": "none",
                    "dnsLog": false,
                    "maskAddress": "full"
                })
            );
        }
    }
}

/// Every LAN of the exit site, the M7's and a separate uplink's home
/// network, lies inside a range the Mac exit rejects for tunnelled flows,
/// so no VPS or user reaches the M7 admin page or a LAN host (design §8.7).
#[test]
fn every_site_lan_is_rejected_by_the_mac_exit() {
    let mut separate = mooring_fixtures::two_nodes_three_users().unwrap();
    separate_uplink(&mut separate);
    for fixture in fixtures().into_iter().chain([separate]) {
        let config: serde_json::Value =
            serde_json::from_slice(mac_exit(&fixture).file().expose_bytes()).unwrap();
        let rejected: Vec<Ipv4Net> = config["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| rule["action"] == "reject")
            .flat_map(|rule| rule["ip_cidr"].as_array().into_iter().flatten())
            .map(|cidr| cidr.as_str().unwrap().parse().unwrap())
            .collect();
        let site = fixture.deployment.exit();
        let mut lans = vec![site.egress.subnet().get()];
        if let mooring_model::exit::Uplink::Separate(selector) = site.uplink {
            lans.push(selector.subnet().get());
        }
        for lan in lans {
            assert!(
                rejected.iter().any(|range| range.contains(&lan)),
                "{}: LAN {lan} is not rejected",
                fixture.name
            );
        }
    }
}
