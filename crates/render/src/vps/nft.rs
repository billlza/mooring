// SPDX-License-Identifier: GPL-3.0-or-later

//! `nftables.conf` (design §8.5): the whole ruleset of a dedicated VPS,
//! replaced atomically on every load.
//!
//! - `input` drops by default and opens public services by destination
//!   address `$VPS4`, never by interface name; camouflage and reflector
//!   ports carry per-source limits.
//! - `output` holds the gate (`@exit_closed`, closed at load; only
//!   `mooring-watch` opens it) and the owner guard: Xray may only originate
//!   connections out of `wgexit` to non-tunnel addresses (through the exit
//!   flow cap) or to the REALITY target's ports, and `mooring-hy2` only the
//!   loopback handoff. Every other engine-originated connection is
//!   counted and rejected.
//! - `exit_flow` counts the exit flows to `$VPS4`'s reflector, which only
//!   the Mac's in-chain probes open (the accounting canary's evidence,
//!   design §11.5), then applies the flow cap. The cap is written as the
//!   number: `ct count over` takes a number token, not a variable.
//! - `prerouting_nat` folds each Hysteria2 hop range onto its listener,
//!   only for traffic addressed to `$VPS4`.

use ipnet::Ipv4Net;
use mooring_agent_proto::{EngineUser, NFT_GATE_SET, NFT_TABLE, NftCounter, WG_INTERFACE};
use mooring_model::exit::FlowCap;
use mooring_model::ipv4::PublicIpv4;
use mooring_model::ports::{Port, PortRange};
use mooring_model::wg::WG_SUPERNET;

use mooring_model::exact::TextSink;
use mooring_model::ports::SYSTEM_PORTS;

/// Connections one source may hold to the TCP/80 camouflage forward.
pub(crate) const CAMO_TCP_PER_SOURCE: u32 = 64;

/// One Hysteria2 listener and the hop range redirected to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListenerPorts {
    pub(crate) port: Port,
    pub(crate) hop: PortRange,
}

/// What `nftables.conf` is rendered from.
#[derive(Debug)]
pub(crate) struct NftInput {
    pub(crate) vps4: PublicIpv4,
    pub(crate) flow_cap: FlowCap,
    /// The REALITY target, which is also the camouflage destination.
    pub(crate) target: PublicIpv4,
    pub(crate) camo_forward: bool,
    pub(crate) wg_port: Port,
    pub(crate) reflector: Port,
    pub(crate) listeners: Vec<ListenerPorts>,
}

/// Writes `nftables.conf`.
pub(crate) fn write(input: &NftInput, sink: &mut dyn TextSink) {
    sink.put("flush ruleset\n\ndefine VPS4 = ");
    sink.show(&input.vps4);
    sink.put("\n\ntable inet ");
    sink.put(NFT_TABLE);
    sink.put(" {\n");
    for counter in NftCounter::ALL {
        sink.put("\tcounter ");
        sink.put(counter.name());
        sink.put(" {\n\t\tpackets 0 bytes 0\n\t}\n\n");
    }
    write_sets(input, sink);
    write_input(input, sink);
    sink.put(
        "\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n\n",
    );
    write_output(input, sink);
    sink.put("\tchain exit_flow {\n");
    sink.put("\t\tip daddr $VPS4 tcp dport ");
    sink.show(&input.reflector);
    sink.put(" ct state new counter name ");
    sink.put(NftCounter::ProbeFlows.name());
    sink.put("\n");
    sink.put("\t\tct state new ct count over ");
    sink.show(&input.flow_cap.get());
    sink.put(" counter name ");
    sink.put(NftCounter::FlowCap.name());
    sink.put(" reject\n");
    sink.put("\t\taccept\n\t}\n\n");
    sink.put("\tchain prerouting_nat {\n");
    sink.put("\t\ttype nat hook prerouting priority dstnat; policy accept;\n");
    for listener in &input.listeners {
        sink.put("\t\tip daddr $VPS4 udp dport ");
        sink.show(&listener.hop);
        sink.put(" redirect to :");
        sink.show(&listener.port);
        sink.put("\n");
    }
    sink.put("\t}\n}\n");
}

fn write_sets(input: &NftInput, sink: &mut dyn TextSink) {
    sink.put("\tset ");
    sink.put(NFT_GATE_SET);
    sink.put(" {\n\t\ttype ifname\n\t\telements = { \"");
    sink.put(WG_INTERFACE);
    sink.put("\" }\n\t}\n\n");
    sink.put("\tset camo_targets {\n\t\ttype ipv4_addr\n\t\telements = { ");
    sink.show(&input.target);
    sink.put(" }\n\t}\n\n");
    if input.camo_forward {
        // Two sets: an element keeps the stateful expression it was created
        // with, so one set shared by `ct count` and `limit` would apply
        // whichever a source hit first to both ports.
        sink.put(
            "\tset camo_tcp_src {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic\n\t}\n\n",
        );
        sink.put("\tset camo_udp_src {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\ttimeout 2m\n\t}\n\n");
    }
    sink.put("\tset refl_src {\n\t\ttype ipv4_addr\n\t\tsize 4096\n\t\tflags dynamic,timeout\n\t\ttimeout 1m\n\t}\n\n");
}

fn write_input(input: &NftInput, sink: &mut dyn TextSink) {
    sink.put("\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n");
    sink.put("\t\tct state invalid drop\n");
    sink.put("\t\tct state established,related accept\n");
    sink.put("\t\tiifname \"lo\" accept\n");
    sink.put("\t\tiifname \"");
    sink.put(WG_INTERFACE);
    sink.put("\" drop\n");
    sink.put("\t\tmeta l4proto { icmp, ipv6-icmp } accept\n");
    rule(
        sink,
        "tcp",
        &[SYSTEM_PORTS.ssh, SYSTEM_PORTS.https],
        "accept",
    );
    if input.camo_forward {
        let http = SYSTEM_PORTS.http;
        rule(
            sink,
            "tcp",
            &[http],
            &format!(
                "ct state new add @camo_tcp_src {{ ip saddr ct count over {CAMO_TCP_PER_SOURCE} }} reject with tcp reset"
            ),
        );
        rule(sink, "tcp", &[http], "accept");
        let https = SYSTEM_PORTS.https;
        rule(
            sink,
            "udp",
            &[https],
            "ct state new add @camo_udp_src { ip saddr limit rate over 50/second burst 200 packets } drop",
        );
        rule(sink, "udp", &[https], "accept");
    }
    let mut udp = vec![input.wg_port];
    udp.extend(input.listeners.iter().map(|listener| listener.port));
    rule(sink, "udp", &udp, "accept");
    rule(
        sink,
        "tcp",
        &[input.reflector],
        "ct state new add @refl_src { ip saddr limit rate over 5/second burst 10 packets } drop",
    );
    rule(sink, "tcp", &[input.reflector], "accept");
    sink.put("\t}\n\n");
}

/// `ip daddr $VPS4 <proto> dport <ports> <verdict>`.
fn rule(sink: &mut dyn TextSink, proto: &str, ports: &[Port], tail: &str) {
    sink.put("\t\tip daddr $VPS4 ");
    sink.put(proto);
    sink.put(" dport ");
    put_ports(sink, ports);
    sink.put(" ");
    sink.put(tail);
    sink.put("\n");
}

/// One port, or an anonymous set of them.
fn put_ports(sink: &mut dyn TextSink, ports: &[Port]) {
    match ports {
        [port] => sink.show(port),
        _ => {
            sink.put("{ ");
            for (position, port) in ports.iter().enumerate() {
                if position > 0 {
                    sink.put(", ");
                }
                sink.show(port);
            }
            sink.put(" }");
        }
    }
}

fn write_output(input: &NftInput, sink: &mut dyn TextSink) {
    sink.put("\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n");
    for verdict in [
        "meta l4proto tcp reject with tcp reset",
        "reject with icmpx host-unreachable",
    ] {
        sink.put("\t\toifname @");
        sink.put(NFT_GATE_SET);
        sink.put(" ");
        sink.put(verdict);
        sink.put("\n");
    }
    guard(sink, EngineUser::Xray, &|sink| {
        sink.put("oifname \"");
        sink.put(WG_INTERFACE);
        sink.put("\" ip daddr != ");
        sink.show(&TUNNEL);
        sink.put(" jump exit_flow");
    });
    let target_tcp = if input.camo_forward {
        vec![SYSTEM_PORTS.http, SYSTEM_PORTS.https]
    } else {
        vec![SYSTEM_PORTS.https]
    };
    guard(sink, EngineUser::Xray, &|sink| {
        sink.put("ip daddr @camo_targets tcp dport ");
        put_ports(sink, &target_tcp);
        sink.put(" accept");
    });
    if input.camo_forward {
        guard(sink, EngineUser::Xray, &|sink| {
            sink.put("ip daddr @camo_targets udp dport ");
            sink.show(&SYSTEM_PORTS.https);
            sink.put(" accept");
        });
    }
    guard(sink, EngineUser::Xray, &|sink| {
        sink.put("counter name ");
        sink.put(NftCounter::XrayGuard.name());
        sink.put(" reject");
    });
    guard(sink, EngineUser::Hy2, &|sink| {
        sink.put("ip daddr 127.0.0.1 tcp dport ");
        sink.show(&SYSTEM_PORTS.hy2_loopback);
        sink.put(" accept");
    });
    guard(sink, EngineUser::Hy2, &|sink| {
        sink.put("counter name ");
        sink.put(NftCounter::Hy2Guard.name());
        sink.put(" reject");
    });
    sink.put("\t}\n\n");
}

/// The tunnel supernet: traffic to it is VPS-local or the Mac, never exit.
const TUNNEL: Ipv4Net = WG_SUPERNET;

/// One owner-guard rule: `meta skuid "<user>" ct direction original <body>`.
fn guard(sink: &mut dyn TextSink, user: EngineUser, body: &dyn Fn(&mut dyn TextSink)) {
    sink.put("\t\tmeta skuid \"");
    sink.put(user.name());
    sink.put("\" ct direction original ");
    body(sink);
    sink.put("\n");
}
