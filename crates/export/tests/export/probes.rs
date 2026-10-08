// SPDX-License-Identifier: GPL-3.0-or-later

//! The probe outbounds the Mac prober wraps (design §8.8), and the
//! `SingBoxOutbound` value type `render` builds on.

use mooring_export::{
    ClientHello, ExportErrorKind, ExportFormat, OutboundTag, Protocol, ProxyShape, SingBoxOutbound,
    probe_outbounds, shapes,
};
use mooring_model::ports::ListenerIdx;
use mooring_model::{ModelError, NodeLifecycle};
use serde::Serialize;

use crate::support::{edited, keys, node, parse, two_nodes};

/// What `render`'s `MacProbeOutbound` does: the CFM outbound plus a
/// Mac-local dial field.
#[derive(Serialize)]
struct Wrapped<'a> {
    #[serde(flatten)]
    cfm: &'a SingBoxOutbound,
    bind_interface: &'static str,
}

#[test]
fn probe_outbounds_use_the_probe_credentials_and_the_classical_hello() {
    let fixture = two_nodes();
    for id in ["lon1", "ams1"] {
        let id = node(id);
        let probes = probe_outbounds(&fixture.deployment, &fixture.secrets, &id).unwrap();
        assert_eq!(probes.reality.protocol(), Protocol::VlessReality);
        assert_eq!(probes.hysteria2.protocol(), Protocol::Hysteria2);
        assert_eq!(probes.reality.tag(), &OutboundTag::reality(&id));
        assert_eq!(
            probes.hysteria2.tag(),
            &OutboundTag::hysteria2(&id, ListenerIdx::FIRST)
        );

        let reality = serde_json::to_string(&probes.reality).unwrap();
        let reality = parse(&reality);
        let uuid = fixture.secrets.probe_vless_uuid(&id).unwrap();
        let uuid = uuid.expose_secret().to_hyphenated();
        assert_eq!(reality["uuid"].as_str(), Some(uuid.as_str()));
        let probe_short_id = fixture.deployment.node(&id).unwrap().reality.probe_short_id;
        let probe_short_id = probe_short_id.to_string();
        assert_eq!(
            reality["tls"]["reality"]["short_id"].as_str(),
            Some(probe_short_id.as_str())
        );
        // Upstream sing-box has no support_x25519mlkem768.
        assert_eq!(
            keys(&reality["tls"]["reality"]),
            ["enabled", "public_key", "short_id"]
        );

        let hysteria2 = serde_json::to_string(&probes.hysteria2).unwrap();
        let hysteria2 = parse(&hysteria2);
        let password = fixture
            .secrets
            .probe_hy2_password(&id)
            .unwrap()
            .expose_text();
        assert_eq!(hysteria2["password"].as_str(), Some(password.as_str()));

        // Debug output never shows a credential.
        let debug = format!("{probes:?}");
        assert!(!debug.contains(uuid.as_str()) && !debug.contains(password.as_str()));
    }
}

#[test]
fn a_probe_outbound_is_exactly_an_export_outbound() {
    let fixture = two_nodes();
    let probes = probe_outbounds(&fixture.deployment, &fixture.secrets, &node("lon1")).unwrap();
    let classical = shapes()
        .into_iter()
        .find(|shape| {
            shape.format() == ExportFormat::SingBoxJson
                && shape.proxy() == ProxyShape::VlessReality(ClientHello::Chrome)
        })
        .unwrap();
    let document = format!(
        "{{\"outbounds\":[{}]}}",
        serde_json::to_string(&probes.reality).unwrap()
    );
    let expected = classical.canonical().lines().nth(2).unwrap();
    let ours = parse(&document);
    let shape = parse(&expected.replace('<', "\"<").replace('>', ">\""));
    assert_eq!(keys(&ours["outbounds"][0]), keys(&shape["outbounds"][0]));
}

#[test]
fn render_can_retag_and_wrap_an_outbound() {
    let fixture = two_nodes();
    let probes = probe_outbounds(&fixture.deployment, &fixture.secrets, &node("lon1")).unwrap();
    let tag = OutboundTag::parse("probe-lon1-reality-out").unwrap();
    let retagged = probes.reality.clone().with_tag(tag.clone());
    assert_eq!(retagged.tag(), &tag);
    let wrapped = serde_json::to_string(&Wrapped {
        cfm: &retagged,
        bind_interface: "en8",
    })
    .unwrap();
    let wrapped = parse(&wrapped);
    let mut expected = keys(&parse(&serde_json::to_string(&probes.reality).unwrap()))
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    expected.push("bind_interface".to_owned());
    assert_eq!(keys(&wrapped), expected);
    assert_eq!(wrapped["tag"].as_str(), Some("probe-lon1-reality-out"));
}

#[test]
fn a_node_without_a_site_has_no_probe() {
    let fixture = two_nodes();
    let deployment = edited(&fixture.deployment, |parts| {
        parts
            .nodes
            .iter_mut()
            .find(|n| n.id == node("ams1"))
            .unwrap()
            .lifecycle = NodeLifecycle::Planned;
    });
    let error = probe_outbounds(&deployment, &fixture.secrets, &node("ams1")).unwrap_err();
    assert_eq!(error.kind(), ExportErrorKind::Model);
    assert!(matches!(
        error,
        mooring_export::ExportError::Model(ModelError::NodeNotDeployable { .. })
    ));
}
