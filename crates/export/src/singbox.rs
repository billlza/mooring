// SPDX-License-Identifier: GPL-3.0-or-later

//! The default format: a sing-box JSON document whose root holds only
//! `outbounds` (design §9.1), which is all CFM's sing-box adapter accepts.

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::ExportError;
use crate::json::exact_json;
use crate::proxy::{ClientHello, Hy2Slot, Protocol, Proxy, REALITY_PORT, RealitySlot};
use crate::tag::OutboundTag;
use crate::tree::{Literal, Scalar, Tree};

/// The only root key.
const ROOT_KEY: &str = "outbounds";

fn lit(text: &'static str) -> Tree<RealitySlot> {
    Tree::Lit(Literal::Str(text))
}

/// The VLESS+REALITY+Vision outbound (CFM `sing_box.rs` `SourceOutbound::Vless`).
pub(crate) fn reality_item(hello: ClientHello) -> Tree<RealitySlot> {
    let mut reality = vec![
        ("enabled", Tree::Lit(Literal::Bool(true))),
        ("public_key", Tree::Leaf(RealitySlot::PublicKey)),
        ("short_id", Tree::Leaf(RealitySlot::ShortId)),
    ];
    if hello.offers_x25519mlkem768() {
        reality.push(("support_x25519mlkem768", Tree::Lit(Literal::Bool(true))));
    }
    Tree::Map(vec![
        ("type", lit("vless")),
        ("tag", Tree::Leaf(RealitySlot::Tag)),
        ("server", Tree::Leaf(RealitySlot::Server)),
        ("server_port", Tree::Lit(Literal::Int(REALITY_PORT.get()))),
        ("uuid", Tree::Leaf(RealitySlot::Uuid)),
        ("flow", lit("xtls-rprx-vision")),
        ("packet_encoding", lit("xudp")),
        (
            "tls",
            Tree::Map(vec![
                ("enabled", Tree::Lit(Literal::Bool(true))),
                ("server_name", Tree::Leaf(RealitySlot::ServerName)),
                (
                    "utls",
                    Tree::Map(vec![
                        ("enabled", Tree::Lit(Literal::Bool(true))),
                        ("fingerprint", lit(hello.fingerprint().as_str())),
                    ]),
                ),
                ("reality", Tree::Map(reality)),
            ]),
        ),
    ])
}

/// The Hysteria2 outbound (CFM `sing_box.rs` `SourceOutbound::Hysteria2`).
/// There is no `server_port`: CFM takes the first port of `server_ports`.
/// There is no `alpn`: h3 is the default on both sides.
pub(crate) fn hysteria2_item() -> Tree<Hy2Slot> {
    Tree::Map(vec![
        ("type", Tree::Lit(Literal::Str("hysteria2"))),
        ("tag", Tree::Leaf(Hy2Slot::Tag)),
        ("server", Tree::Leaf(Hy2Slot::Server)),
        (
            "server_ports",
            Tree::List(vec![Tree::Leaf(Hy2Slot::PortsColon)]),
        ),
        ("hop_interval", Tree::Leaf(Hy2Slot::HopDuration)),
        ("password", Tree::Leaf(Hy2Slot::Password)),
        (
            "obfs",
            Tree::Map(vec![
                ("type", Tree::Lit(Literal::Str("salamander"))),
                ("password", Tree::Leaf(Hy2Slot::ObfsPassword)),
            ]),
        ),
        (
            "tls",
            Tree::Map(vec![
                ("enabled", Tree::Lit(Literal::Bool(true))),
                ("server_name", Tree::Leaf(Hy2Slot::Sni)),
                (
                    "certificate_public_key_sha256",
                    Tree::List(vec![Tree::Leaf(Hy2Slot::SpkiPin)]),
                ),
            ]),
        ),
    ])
}

/// The document around `items`.
pub(crate) fn document<S>(items: Vec<Tree<S>>) -> Tree<S> {
    Tree::Map(vec![(ROOT_KEY, Tree::List(items))])
}

/// One sing-box outbound exactly as CFM imports it: the single value type
/// that user exports emit and that the Mac prober config wraps
/// (`render`'s `MacProbeOutbound`).
///
/// It serialises as one JSON object with a fixed key order. Its `Debug`
/// output redacts every credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxOutbound {
    tag: OutboundTag,
    proxy: Proxy,
}

impl SingBoxOutbound {
    pub(crate) const fn new(tag: OutboundTag, proxy: Proxy) -> Self {
        Self { tag, proxy }
    }

    /// The outbound tag.
    #[must_use]
    pub const fn tag(&self) -> &OutboundTag {
        &self.tag
    }

    /// The same outbound under another tag.
    #[must_use]
    pub fn with_tag(self, tag: OutboundTag) -> Self {
        Self { tag, ..self }
    }

    /// The protocol.
    #[must_use]
    pub const fn protocol(&self) -> Protocol {
        self.proxy.protocol()
    }

    pub(crate) const fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// The outbound as a tree with every slot resolved.
    pub(crate) fn tree(&self) -> Tree<Scalar> {
        match &self.proxy {
            Proxy::Reality(proxy) => {
                reality_item(proxy.hello()).map(&mut |slot| proxy.resolve(&self.tag, slot))
            }
            Proxy::Hysteria2(proxy) => {
                hysteria2_item().map(&mut |slot| proxy.resolve(&self.tag, slot))
            }
        }
    }
}

impl Serialize for SingBoxOutbound {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.tree().serialize(serializer)
    }
}

/// Renders `outbounds` as a pretty-printed document with a trailing newline,
/// into a zeroizing buffer of exactly the needed capacity.
pub(crate) fn render(outbounds: &[SingBoxOutbound]) -> Result<Zeroizing<Vec<u8>>, ExportError> {
    let tree = document(outbounds.iter().map(SingBoxOutbound::tree).collect());
    exact_json(&tree).map_err(ExportError::Encode)
}
