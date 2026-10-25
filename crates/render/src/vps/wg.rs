// SPDX-License-Identifier: GPL-3.0-or-later

//! `wgexit.conf` for `wg-quick` (design §8.4).
//!
//! `Table = off` keeps `wg-quick` from installing routes for `AllowedIPs`.
//! The `PostUp` lines enable `accept_local` (the in-chain probe's replies
//! carry the VPS's own address as source) and steer device-bound sockets
//! with an `oif` rule into table 77, whose only route is the default
//! route through `wgexit`. The peer has no `Endpoint`: the Mac dials out
//! and the VPS learns its address by roaming.
//!
//! The rule hooks are idempotent: wg-quick runs no `PreDown` for an `up`
//! that fails after a hook (its exit trap only deletes the interface),
//! and a rule that names an interface outlives it in the kernel
//! (detached, and attached again when an interface of that name
//! appears), so a plain `ip -4 rule add` is refused by every `up` after
//! such a failure, and a plain `ip -4 rule del` would abort every `down`
//! once the rule was gone. The rule is therefore added only when
//! `ip -4 rule list` does not show it, and deleted only when it does
//! (lon1, 2026-10-25).

use ipnet::Ipv4Net;
use mooring_agent_proto::{EXIT_ROUTE_TABLE, EXIT_RULE_PRIORITY};
use mooring_model::keys::WgKey;
use mooring_model::ports::Port;
use mooring_model::secret::WgPrivateKey;
use mooring_model::wg::WgIndex;

use mooring_model::exact::TextSink;

/// The tunnel MTU, fixed in v1 (design §3).
pub(crate) const MTU: u16 = 1280;

/// What `wgexit.conf` is rendered from.
#[derive(Debug)]
pub(crate) struct WgExitInput<'a> {
    /// The node's tunnel index; the VPS is `.1` of its /30.
    pub(crate) index: WgIndex,
    pub(crate) listen_port: Port,
    pub(crate) private_key: &'a WgPrivateKey,
    /// The Mac's public key.
    pub(crate) peer: WgKey,
}

impl WgExitInput<'_> {
    /// The VPS address with the /30 prefix.
    pub(crate) const fn address(&self) -> Ipv4Net {
        self.index.vps_interface()
    }
}

/// Writes `wgexit.conf`.
pub(crate) fn write(input: &WgExitInput<'_>, sink: &mut dyn TextSink) {
    sink.put("[Interface]\nAddress = ");
    sink.show(&input.address());
    sink.put("\nListenPort = ");
    sink.show(&input.listen_port);
    sink.put("\nPrivateKey = ");
    sink.put(&input.private_key.expose_text());
    sink.put("\nMTU = ");
    sink.show(&MTU);
    sink.put("\nTable = off\n");
    sink.put("PostUp = sysctl -qw net.ipv4.conf.%i.accept_local=1\n");
    for (hook, line) in hook_lines() {
        sink.put(hook);
        sink.put(" = ");
        sink.put(&line);
        sink.put("\n");
    }
    sink.put("\n[Peer]\nPublicKey = ");
    sink.show(&input.peer);
    sink.put("\nAllowedIPs = 0.0.0.0/0\n");
}

/// The routing hooks: the rule and the route added on up, removed on down.
/// The rule's hooks test for it first (the module doc says why); `grep`
/// reads its input to the end instead of quitting at the match, so `ip`
/// never gets `SIGPIPE` under wg-quick's `pipefail`.
fn hook_lines() -> [(&'static str, String); 4] {
    let listed =
        format!("^{EXIT_RULE_PRIORITY}:[[:space:]]*from all oif %i lookup {EXIT_ROUTE_TABLE}$");
    let rule = format!("pref {EXIT_RULE_PRIORITY} oif %i lookup {EXIT_ROUTE_TABLE}");
    [
        (
            "PostUp",
            format!("ip -4 rule list | grep '{listed}' >/dev/null || ip -4 rule add {rule}"),
        ),
        (
            "PostUp",
            format!("ip -4 route replace default dev %i table {EXIT_ROUTE_TABLE}"),
        ),
        (
            "PreDown",
            format!("! ip -4 rule list | grep '{listed}' >/dev/null || ip -4 rule del {rule}"),
        ),
        (
            "PreDown",
            format!("ip -4 route flush table {EXIT_ROUTE_TABLE}"),
        ),
    ]
}
