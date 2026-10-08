// SPDX-License-Identifier: GPL-3.0-or-later

//! What the emitted documents contain: every proxy conforms to an
//! enumerated shape for the user's line (so emitted ⊆ enumerated), every
//! leaf lies in its tag's domain, and every value comes from the deployment
//! and the secret snapshot.

use mooring_export::{ExportFormat, Shape, shapes};
use mooring_model::cert::Hy2Sni;
use mooring_model::ports::ListenerIdx;
use mooring_model::secret::{Password, SecretEntry};
use mooring_model::{DnsName, PublicIpv4, Sha256Digest, ShortId, SpkiSha256, Uuid, X25519Pub};
use saphyr::YamlOwned;

use crate::support::{export, fixtures, keys, node, parse, text, two_nodes};

/// The shape's proxy as an ordered tree, with each `<tag>` as a string.
fn shape_proxy(shape: &Shape) -> YamlOwned {
    let tree = shape.canonical().lines().nth(2).unwrap();
    let quoted = tree.replace('<', "\"<").replace('>', ">\"");
    let root = parse(&quoted);
    let key = match shape.format() {
        ExportFormat::SingBoxJson => "outbounds",
        ExportFormat::ClashYaml => "proxies",
    };
    root[key][0].clone()
}

/// Whether `value` lies in the domain of the leaf tag `tag`.
fn in_domain(tag: &str, value: &YamlOwned) -> bool {
    let text = value.as_str();
    let port = |text: &str| text.parse::<u16>().is_ok_and(|port| port > 0);
    let range = |text: &str, separator: char| {
        text.split_once(separator).is_some_and(|(start, end)| {
            port(start) && port(end) && start.parse::<u16>().ok() < end.parse::<u16>().ok()
        })
    };
    let hop = |seconds: i64| (5..=3600).contains(&seconds);
    match tag {
        "outbound-tag" => text.is_some_and(|t| mooring_export::OutboundTag::parse(t).is_ok()),
        "public-ipv4" => text.is_some_and(|t| t.parse::<PublicIpv4>().is_ok()),
        "port" => value.as_integer().is_some_and(|p| (1..=65535).contains(&p)),
        "port-range-colon" => text.is_some_and(|t| range(t, ':')),
        "port-range-dash" => text.is_some_and(|t| range(t, '-')),
        "hop-interval-duration" => text
            .and_then(|t| t.strip_suffix('s'))
            .and_then(|t| t.parse::<i64>().ok())
            .is_some_and(hop),
        "hop-interval-seconds" => value.as_integer().is_some_and(hop),
        "uuid-v4" => text.is_some_and(|t| Uuid::parse(t).is_ok()),
        "dns-name" => text.is_some_and(|t| DnsName::parse(t).is_ok()),
        "x25519-public-key" => text.is_some_and(|t| X25519Pub::parse(t).is_ok()),
        "short-id" => text.is_some_and(|t| ShortId::parse(t).is_ok()),
        "password" => text.is_some_and(|t| Password::parse(t).is_ok()),
        "hy2-sni" => text.is_some_and(|t| Hy2Sni::parse(t).is_ok()),
        "spki-sha256" => text.is_some_and(|t| SpkiSha256::parse(t).is_ok()),
        "der-sha256" => text.is_some_and(|t| Sha256Digest::parse(t).is_ok()),
        other => panic!("unknown leaf tag {other}"),
    }
}

/// Whether `value` has exactly the structure of `shape`: the same keys in
/// the same order, equal literals, and leaves in their tags' domains.
fn conforms(value: &YamlOwned, shape: &YamlOwned) -> bool {
    if let Some(tag) = shape
        .as_str()
        .and_then(|text| text.strip_prefix('<'))
        .and_then(|text| text.strip_suffix('>'))
    {
        return in_domain(tag, value);
    }
    if shape.is_mapping() {
        return value.is_mapping()
            && keys(value) == keys(shape)
            && keys(shape)
                .iter()
                .all(|key| conforms(&value[*key], &shape[*key]));
    }
    if let Some(items) = shape.as_vec() {
        return value.as_vec().is_some_and(|values| {
            values.len() == items.len() && values.iter().zip(items).all(|(v, s)| conforms(v, s))
        });
    }
    value == shape
}

#[test]
fn every_emitted_proxy_conforms_to_an_enumerated_shape() {
    let all = shapes();
    let mut used = std::collections::BTreeSet::new();
    for fixture in fixtures() {
        for user in fixture.deployment.users().values() {
            for format in ExportFormat::ALL {
                let document = export(&fixture, &fixture.deployment, &user.id, format);
                let root = parse(text(&document));
                let key = match format {
                    ExportFormat::SingBoxJson => "outbounds",
                    ExportFormat::ClashYaml => "proxies",
                };
                assert_eq!(keys(&root), [key]);
                for proxy in root[key].as_vec().unwrap() {
                    let matching: Vec<_> = all
                        .iter()
                        .filter(|shape| {
                            shape.line() == user.client.line && shape.format() == format
                        })
                        .filter(|shape| conforms(proxy, &shape_proxy(shape)))
                        .collect();
                    assert_eq!(matching.len(), 1, "{} {format:?}", user.id);
                    used.insert((matching[0].line_name(), matching[0].name()));
                }
            }
        }
    }
    // The fixtures cycle through every profile, so every shape is emitted.
    let enumerated: std::collections::BTreeSet<_> = all
        .iter()
        .map(|shape| (shape.line_name(), shape.name()))
        .collect();
    assert_eq!(used, enumerated);
}

#[test]
fn a_shape_rejects_a_document_that_differs() {
    let all = shapes();
    let reality = shape_proxy(&all[0]);
    let fixture = two_nodes();
    let user = crate::support::first_user(&fixture);
    let document = export(
        &fixture,
        &fixture.deployment,
        &user,
        ExportFormat::SingBoxJson,
    );
    let document = text(&document).to_owned();
    let proxy = |text: &str| parse(text)["outbounds"][0].clone();
    assert!(conforms(&proxy(&document), &reality));
    for (from, to) in [
        ("\"xudp\"", "\"packet_addr\""),
        ("\"chrome\"", "\"firefox\""),
        ("\"server_port\": 443", "\"server_port\": 444"),
        ("\"flow\"", "\"flaw\""),
    ] {
        assert!(
            !conforms(&proxy(&document.replacen(from, to, 1)), &reality),
            "{from}"
        );
    }
}

#[test]
fn values_come_from_the_deployment_and_the_secrets() {
    let fixture = two_nodes();
    // User 3 is a CFM 0.5 client with the ML-KEM opt-in.
    let user = fixture.deployment.users().keys().nth(2).unwrap().clone();
    let deployment = &fixture.deployment;
    let json = export(&fixture, deployment, &user, ExportFormat::SingBoxJson);
    let json = parse(text(&json));
    let clash = export(&fixture, deployment, &user, ExportFormat::ClashYaml);
    let clash = parse(text(&clash));
    let outbounds = json["outbounds"].as_vec().unwrap();
    let proxies = clash["proxies"].as_vec().unwrap();
    // The primary (lon1) comes first although "ams1" sorts before it.
    let tags: Vec<_> = outbounds
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        ["lon1-reality", "lon1-hy2", "ams1-reality", "ams1-hy2"]
    );
    let names: Vec<_> = proxies
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, tags);
    for (index, id) in ["lon1", "ams1"].into_iter().enumerate() {
        let id = node(id);
        let model = deployment.node(&id).unwrap();
        let address = model.lifecycle.address().unwrap().ipv4().to_string();
        let target = model.reality.target.as_ref().unwrap().host().as_str();
        let short_id = deployment.user(&user).unwrap().per_node[&id]
            .short_id
            .to_string();
        let uuid = fixture.secrets.user_vless_uuid(&user, &id).unwrap();
        let uuid = uuid.expose_secret().to_hyphenated();
        let password = fixture
            .secrets
            .user_hy2_password(&user, &id)
            .unwrap()
            .expose_text();
        let obfs = fixture
            .secrets
            .hy2_obfs(&id, ListenerIdx::FIRST)
            .unwrap()
            .expose_text();
        let pins = &mooring_fixtures::recorded_pins(&id).unwrap();

        let reality = &outbounds[2 * index];
        assert_eq!(reality["server"].as_str(), Some(address.as_str()));
        assert_eq!(reality["uuid"].as_str(), Some(uuid.as_str()));
        assert_eq!(reality["tls"]["server_name"].as_str(), Some(target));
        let public_key = model.reality.public_key.to_string();
        assert_eq!(
            reality["tls"]["reality"]["public_key"].as_str(),
            Some(public_key.as_str())
        );
        assert_eq!(
            reality["tls"]["reality"]["short_id"].as_str(),
            Some(short_id.as_str())
        );
        assert_eq!(
            reality["tls"]["reality"]["support_x25519mlkem768"].as_bool(),
            Some(true)
        );

        let hy2 = &outbounds[2 * index + 1];
        assert_eq!(hy2["server"].as_str(), Some(address.as_str()));
        assert_eq!(hy2["server_ports"][0].as_str(), Some("61000:62999"));
        assert_eq!(hy2["hop_interval"].as_str(), Some("30s"));
        assert_eq!(hy2["password"].as_str(), Some(password.as_str()));
        assert_eq!(hy2["obfs"]["password"].as_str(), Some(obfs.as_str()));
        assert_eq!(
            hy2["tls"]["server_name"].as_str(),
            Some(pins.sni().as_str())
        );
        let spki = pins.spki_sha256().to_string();
        assert_eq!(
            hy2["tls"]["certificate_public_key_sha256"][0].as_str(),
            Some(spki.as_str())
        );
        assert!(hy2.as_mapping_get("server_port").is_none());

        let clash_reality = &proxies[2 * index];
        assert_eq!(clash_reality["port"].as_integer(), Some(443));
        assert_eq!(clash_reality["servername"].as_str(), Some(target));
        assert_eq!(clash_reality["client-fingerprint"].as_str(), Some("chrome"));
        assert_eq!(
            clash_reality["reality-opts"]["support-x25519mlkem768"].as_bool(),
            Some(true)
        );
        let clash_hy2 = &proxies[2 * index + 1];
        assert_eq!(clash_hy2["port"].as_integer(), Some(61000));
        assert_eq!(clash_hy2["ports"].as_str(), Some("61000-62999"));
        assert_eq!(clash_hy2["hop-interval"].as_integer(), Some(30));
        assert_eq!(clash_hy2["obfs-password"].as_str(), Some(obfs.as_str()));
        assert_eq!(clash_hy2["sni"].as_str(), Some(pins.sni().as_str()));
        let der = pins.der_sha256().to_string();
        assert_eq!(clash_hy2["fingerprint"].as_str(), Some(der.as_str()));
    }
}

#[test]
fn documents_are_deterministic_and_redacted_in_debug() {
    let fixture = two_nodes();
    let user = crate::support::first_user(&fixture);
    for format in ExportFormat::ALL {
        let first = export(&fixture, &fixture.deployment, &user, format);
        let second = export(&fixture, &fixture.deployment, &user, format);
        assert_eq!(first.expose_bytes(), second.expose_bytes());
        assert_eq!(first.format(), format);
        let debug = format!("{first:?}");
        assert!(debug.starts_with("ExportDocument"), "{debug}");
        let uuid = fixture
            .secrets
            .user_vless_uuid(&user, &node("lon1"))
            .unwrap()
            .expose_secret()
            .to_hyphenated();
        assert!(!debug.contains(uuid.as_str()));
        assert!(text(&first).contains(uuid.as_str()));
    }
    assert_eq!(ExportFormat::SingBoxJson.file_extension(), "json");
    assert_eq!(ExportFormat::ClashYaml.file_extension(), "yaml");
}

#[test]
fn every_listener_becomes_one_hysteria2_outbound() {
    use mooring_export::{ExportErrorKind, export_user};
    use mooring_fixtures::FIXTURE_NOW;
    use mooring_model::collections::NonEmpty;
    use mooring_model::ports::{
        DEFAULT_HY2_HOP, DEFAULT_HY2_PORT, DEFAULT_REFLECTOR_PORT, DEFAULT_WG_PORT, Hy2Listener,
        Hy2Obfs, PortPlan, PortRange,
    };
    use mooring_model::{HopInterval, Port};

    let mut fixture = two_nodes();
    let user = crate::support::first_user(&fixture);
    let lon1 = node("lon1");
    let deployment = crate::support::edited(&fixture.deployment, |parts| {
        let model = parts.nodes.iter_mut().find(|n| n.id == lon1).unwrap();
        let interval = HopInterval::from_seconds(30).unwrap();
        let first = Hy2Listener::new(
            DEFAULT_HY2_PORT,
            DEFAULT_HY2_HOP,
            interval,
            Hy2Obfs::Salamander,
        )
        .unwrap();
        let second = Hy2Listener::new(
            Port::new(63000).unwrap(),
            PortRange::new(63001, 64999).unwrap(),
            interval,
            Hy2Obfs::Salamander,
        )
        .unwrap();
        model.ports = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::from_parts(first, vec![second]),
            Vec::new(),
            model.ports.ephemeral(),
        )
        .unwrap();
    });
    // The second listener's salamander password is not in the fixture yet.
    let missing = export_user(
        &deployment,
        &fixture.secrets,
        &user,
        ExportFormat::SingBoxJson,
        FIXTURE_NOW,
    )
    .unwrap_err();
    assert_eq!(missing.kind(), ExportErrorKind::Secret);
    let second_obfs = Password::from_bytes([9; 32]).unwrap();
    fixture
        .secrets
        .insert(SecretEntry::NodeHy2Obfs(
            lon1.clone(),
            ListenerIdx::new(1),
            second_obfs.clone(),
        ))
        .unwrap();
    let json = export(&fixture, &deployment, &user, ExportFormat::SingBoxJson);
    let json = parse(text(&json));
    let outbounds = json["outbounds"].as_vec().unwrap();
    let tags: Vec<_> = outbounds
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        [
            "lon1-reality",
            "lon1-hy2",
            "lon1-hy2-1",
            "ams1-reality",
            "ams1-hy2"
        ]
    );
    assert_eq!(
        outbounds[1]["server_ports"][0].as_str(),
        Some("61000:62999")
    );
    assert_eq!(
        outbounds[2]["server_ports"][0].as_str(),
        Some("63000:64999")
    );
    let obfs = second_obfs.expose_text();
    assert_eq!(
        outbounds[2]["obfs"]["password"].as_str(),
        Some(obfs.as_str())
    );
    let clash = export(&fixture, &deployment, &user, ExportFormat::ClashYaml);
    let clash = parse(text(&clash));
    assert_eq!(clash["proxies"][2]["port"].as_integer(), Some(63000));
    assert_eq!(clash["proxies"][2]["ports"].as_str(), Some("63000-64999"));
}
