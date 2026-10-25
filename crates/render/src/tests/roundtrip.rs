// SPDX-License-Identifier: GPL-3.0-or-later

//! Every rendered JSON config reads back into its closed type, with unknown
//! fields rejected, and re-encodes to the same bytes; `wgexit.conf` reads
//! back through a strict parser of its one layout.

use mooring_agent_proto::{ManagedFile, WatchConfig};
use mooring_export::probe_outbounds;
use mooring_model::keys::WgKey;
use mooring_model::ports::Port;
use mooring_model::secret::WgPrivateKey;
use mooring_model::wg::WgIndex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::encode;
use crate::mac::exit::ExitDocument;
use crate::mac::prober::ProberDocument;
use crate::singbox::BindInterface;
use crate::tests::support::{fixtures, mac_exit, mac_prober, vps};
use crate::vps::hy2::Hy2Config;
use crate::vps::wg::{self, WgExitInput};
use crate::vps::xray::XrayConfig;

/// Reads `bytes` into `T` and re-encodes it; the bytes must not change.
fn round_trip<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> T {
    let value: T = serde_json::from_slice(bytes).unwrap();
    assert_eq!(encode::json(&value).unwrap().as_slice(), bytes);
    value
}

/// The same JSON with `extra` added to the object at `pointer`.
fn with_unknown_field(bytes: &[u8], pointer: &str) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    value
        .pointer_mut(pointer)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("mooring_unknown".to_owned(), serde_json::Value::Bool(true));
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn vps_json_configs_round_trip_through_closed_types() {
    for fixture in fixtures() {
        for node in fixture.deployment.nodes().keys() {
            let bundle = vps(&fixture, node);
            let xray = bundle.file(ManagedFile::XrayConfig).expose_bytes();
            round_trip::<XrayConfig>(xray);
            round_trip::<Hy2Config>(bundle.file(ManagedFile::Hy2Config).expose_bytes());
            round_trip::<WatchConfig>(bundle.file(ManagedFile::WatchConfig).expose_bytes());
        }
    }
}

#[test]
fn unknown_fields_are_rejected_at_every_level() {
    let fixture = mooring_fixtures::one_node_one_user().unwrap();
    let bundle = vps(&fixture, &crate::tests::support::node("lon1"));
    let xray = bundle.file(ManagedFile::XrayConfig).expose_bytes();
    for pointer in [
        "",
        "/log",
        "/api",
        "/stats",
        "/policy/levels/0",
        "/policy/levels/1",
        "/dns",
        "/dns/servers/0",
        "/inbounds/0",
        "/inbounds/0/settings",
        "/inbounds/0/settings/clients/0",
        "/inbounds/0/streamSettings",
        "/inbounds/0/streamSettings/realitySettings",
        "/inbounds/0/sniffing",
        "/inbounds/1",
        "/inbounds/1/streamSettings",
        "/inbounds/2",
        "/inbounds/2/settings",
        "/outbounds/0",
        "/outbounds/1",
        "/outbounds/1/streamSettings/sockopt",
        "/outbounds/2/settings",
        "/routing",
        "/routing/rules/0",
    ] {
        let edited = with_unknown_field(xray, pointer);
        assert!(
            serde_json::from_slice::<XrayConfig>(&edited).is_err(),
            "xray.json accepted an unknown field at {pointer:?}"
        );
    }
    let hy2 = bundle.file(ManagedFile::Hy2Config).expose_bytes();
    for pointer in [
        "",
        "/log",
        "/inbounds/0",
        "/inbounds/0/obfs",
        "/inbounds/0/users/0",
        "/inbounds/0/tls",
        "/outbounds/0",
        "/route",
        "/route/rules/0",
        "/route/rules/2",
    ] {
        let edited = with_unknown_field(hy2, pointer);
        assert!(
            serde_json::from_slice::<Hy2Config>(&edited).is_err(),
            "hy2.json accepted an unknown field at {pointer:?}"
        );
    }
    let exit = mac_exit(&fixture);
    for pointer in [
        "",
        "/endpoints/0",
        "/endpoints/0/peers/0",
        "/outbounds/0",
        "/route",
        "/route/rules/0",
        "/route/rules/2",
    ] {
        let edited = with_unknown_field(exit.file().expose_bytes(), pointer);
        assert!(
            serde_json::from_slice::<ExitDocument>(&edited).is_err(),
            "the exit config accepted an unknown field at {pointer:?}"
        );
    }
}

#[test]
fn mac_exit_configs_round_trip_through_closed_types() {
    for fixture in fixtures() {
        let document: ExitDocument = round_trip(mac_exit(&fixture).file().expose_bytes());
        assert!(!document.endpoints.is_empty());
    }
}

/// A probe outbound as read back: the Mac-only dial field, and the CFM
/// part compared exactly with what the export emitter writes.
#[derive(Debug, Deserialize)]
struct ProbeOutboundRecord {
    bind_interface: BindInterface,
    #[serde(flatten)]
    cfm: serde_json::Map<String, serde_json::Value>,
}

#[test]
fn prober_configs_read_back_with_the_export_emitters_outbounds() {
    for fixture in fixtures() {
        let prober = mac_prober(&fixture);
        let document: ProberDocument<ProbeOutboundRecord> =
            serde_json::from_slice(prober.file().expose_bytes()).unwrap();
        let uplink = &fixture.interfaces.uplink_interface().bsd_name;
        assert_eq!(document.outbounds.len(), prober.probes().len());
        for (record, probe) in document.outbounds.iter().zip(prober.probes()) {
            assert_eq!(record.bind_interface.name(), uplink);
            let exported =
                probe_outbounds(&fixture.deployment, &fixture.secrets, &probe.node).unwrap();
            let outbound = match probe.protocol {
                mooring_model::exit::ProbeProtocol::Reality => exported.reality,
                mooring_model::exit::ProbeProtocol::Hy2 => exported.hysteria2,
            };
            let mut expected = serde_json::to_value(&outbound).unwrap();
            let tag = format!(
                "probe-{}-{}-out",
                probe.node,
                match probe.protocol {
                    mooring_model::exit::ProbeProtocol::Reality => "reality",
                    mooring_model::exit::ProbeProtocol::Hy2 => "hy2",
                }
            );
            expected["tag"] = serde_json::Value::String(tag);
            assert_eq!(serde_json::Value::Object(record.cfm.clone()), expected);
        }
    }
}

/// `wgexit.conf` as read back: the variable values, with every fixed line
/// required verbatim.
#[derive(Debug, PartialEq, Eq)]
struct WgExitRead {
    address: String,
    listen_port: Port,
    private_key: WgPrivateKey,
    peer: WgKey,
}

fn value<'a>(lines: &mut impl Iterator<Item = &'a str>, key: &str) -> &'a str {
    let line = lines.next().unwrap();
    line.strip_prefix(key)
        .and_then(|rest| rest.strip_prefix(" = "))
        .unwrap_or_else(|| panic!("expected {key}, got {line:?}"))
}

fn fixed<'a>(lines: &mut impl Iterator<Item = &'a str>, expected: &str) {
    assert_eq!(lines.next(), Some(expected));
}

fn parse_wgexit(text: &str) -> WgExitRead {
    let lines = &mut text.lines();
    fixed(lines, "[Interface]");
    let address = value(lines, "Address").to_owned();
    let listen_port = Port::new(value(lines, "ListenPort").parse().unwrap()).unwrap();
    let private_key = WgPrivateKey::parse(value(lines, "PrivateKey")).unwrap();
    for line in [
        "MTU = 1280",
        "Table = off",
        "PostUp = sysctl -qw net.ipv4.conf.%i.accept_local=1",
        "PostUp = ip -4 rule list | grep '^10000:[[:space:]]*from all oif %i lookup 77$' >/dev/null || ip -4 rule add pref 10000 oif %i lookup 77",
        "PostUp = ip -4 route replace default dev %i table 77",
        "PreDown = ! ip -4 rule list | grep '^10000:[[:space:]]*from all oif %i lookup 77$' >/dev/null || ip -4 rule del pref 10000 oif %i lookup 77",
        "PreDown = ip -4 route flush table 77",
        "",
        "[Peer]",
    ] {
        fixed(lines, line);
    }
    let peer = WgKey::parse(value(lines, "PublicKey")).unwrap();
    fixed(lines, "AllowedIPs = 0.0.0.0/0");
    assert_eq!(lines.next(), None);
    WgExitRead {
        address,
        listen_port,
        private_key,
        peer,
    }
}

#[test]
fn wgexit_conf_round_trips_through_its_layout() {
    for fixture in fixtures() {
        for (id, node) in fixture.deployment.nodes() {
            let bundle = vps(&fixture, id);
            let rendered = bundle.file(ManagedFile::WgConf);
            let read = parse_wgexit(rendered.expose_text());
            let index: WgIndex = node.wg_index;
            assert_eq!(read.address, index.vps_interface().to_string());
            let input = WgExitInput {
                index,
                listen_port: read.listen_port,
                private_key: &read.private_key,
                peer: read.peer,
            };
            let again = encode::text(|sink| wg::write(&input, sink));
            assert_eq!(again.as_slice(), rendered.expose_bytes());
        }
    }
}
