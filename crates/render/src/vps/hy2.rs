// SPDX-License-Identifier: GPL-3.0-or-later

//! `hy2.json` for sing-box 1.14.2 (design §8.3), as closed types: one
//! Hysteria2 inbound per listener, each user handed to Xray's
//! `hy2-loop-in` over loopback with its own loopback UUID, and a final
//! reject. sing-box rejects unknown keys (`option/options.go:39-41`).

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use mooring_model::cert::CertificatePem;
use mooring_model::ids::Uuid;
use mooring_model::ipv4::PublicIpv4;
use mooring_model::ports::{Hy2Listener, ListenerIdx, Port};
use mooring_model::secret::{Hy2KeyPem, Password, Secret};
use serde::{Deserialize, Serialize};

use crate::literal::literal;
use crate::secret_text::{PemLines, Rendered};
use crate::singbox::{Log, RejectAction, RouteAction};
use crate::text_value::{TextValueError, display_serde};
use crate::vps::served::{Identity, Served};
use mooring_model::ports::SYSTEM_PORTS;

/// `hy2.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hy2Config {
    pub(crate) log: Log,
    pub(crate) inbounds: Vec<Hy2Inbound>,
    pub(crate) outbounds: Vec<LoopOutbound>,
    pub(crate) route: Hy2Route,
}

literal!(
    /// The Hysteria2 inbound type.
    Hysteria2Type = "hysteria2"
);
literal!(
    /// The only obfuscation (`option/hysteria2.go:64-68`).
    SalamanderType = "salamander"
);
literal!(
    /// The only ALPN.
    H3 = "h3"
);
literal!(
    /// The VLESS outbound type.
    VlessType = "vless"
);
literal!(
    /// VLESS UDP over XUDP (`option/vless.go:26`).
    Xudp = "xudp"
);

/// The tag of a listener's inbound: `hy2-in`, then `hy2-in-<n>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Hy2InboundTag(pub(crate) ListenerIdx);

const HY2_IN: &str = "hy2-in";

impl fmt::Display for Hy2InboundTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ListenerIdx::FIRST => f.write_str(HY2_IN),
            index => write!(f, "{HY2_IN}-{index}"),
        }
    }
}

impl FromStr for Hy2InboundTag {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let index = match text.strip_prefix(HY2_IN) {
            Some("") => Some(ListenerIdx::FIRST),
            Some(rest) => rest
                .strip_prefix('-')
                .and_then(|n| n.parse::<u8>().ok())
                .filter(|&n| n > 0)
                .map(ListenerIdx::new),
            None => None,
        };
        index
            .map(Self)
            .filter(|tag| tag.to_string() == text)
            .ok_or(TextValueError("hy2-in or hy2-in-<n>"))
    }
}

display_serde!(Hy2InboundTag);

/// `obfs` (`option/hysteria2.go:64-70`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Salamander {
    #[serde(rename = "type")]
    pub(crate) kind: SalamanderType,
    pub(crate) password: Rendered<Password>,
}

/// One `users` entry (`option/hysteria2.go:115-118`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hy2User {
    pub(crate) name: Identity,
    pub(crate) password: Rendered<Password>,
}

/// `tls` with the certificate and key inline (`option/tls.go:13-40`), so
/// `check` of a staged generation reads that generation's own material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hy2Tls {
    pub(crate) enabled: bool,
    pub(crate) alpn: [H3; 1],
    pub(crate) certificate: PemLines<CertificatePem>,
    pub(crate) key: PemLines<Hy2KeyPem>,
}

/// One Hysteria2 inbound (`option/hysteria2.go:17-30`, `option/inbound.go:79-82`).
/// `up_mbps`/`down_mbps` stay unset, so the server replies "auto" and BBR
/// is used; `masquerade` is omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hy2Inbound {
    #[serde(rename = "type")]
    pub(crate) kind: Hysteria2Type,
    pub(crate) tag: Hy2InboundTag,
    pub(crate) listen: PublicIpv4,
    pub(crate) listen_port: Port,
    pub(crate) obfs: Salamander,
    pub(crate) users: Vec<Hy2User>,
    pub(crate) ignore_client_bandwidth: bool,
    pub(crate) tls: Hy2Tls,
}

/// The tag of an identity's loopback outbound: `x-<identity>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LoopTag(pub(crate) Identity);

const LOOP_PREFIX: &str = "x-";

impl fmt::Display for LoopTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{LOOP_PREFIX}{}", self.0)
    }
}

impl FromStr for LoopTag {
    type Err = TextValueError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.strip_prefix(LOOP_PREFIX)
            .ok_or(TextValueError("x-<identity>"))?
            .parse()
            .map(Self)
    }
}

display_serde!(LoopTag);

/// One identity's VLESS handoff to `hy2-loop-in` (`option/vless.go:17-27`,
/// `option/outbound.go:183-186`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoopOutbound {
    #[serde(rename = "type")]
    pub(crate) kind: VlessType,
    pub(crate) tag: LoopTag,
    pub(crate) server: Ipv4Addr,
    pub(crate) server_port: Port,
    pub(crate) uuid: Rendered<Secret<Uuid>>,
    pub(crate) packet_encoding: Xudp,
}

/// Routes one authenticated identity to its loopback outbound
/// (`option/rule.go:141-144`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hy2RouteRule {
    pub(crate) inbound: Vec<Hy2InboundTag>,
    pub(crate) auth_user: [Identity; 1],
    pub(crate) action: RouteAction,
    pub(crate) outbound: LoopTag,
}

/// The final reject. It names the inbounds, because a rule without a
/// condition is refused with "missing conditions"
/// (`route/rule/rule_default.go:15-19`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hy2RejectRule {
    pub(crate) inbound: Vec<Hy2InboundTag>,
    pub(crate) action: RejectAction,
}

/// One route rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Hy2Rule {
    Route(Hy2RouteRule),
    Reject(Hy2RejectRule),
}

/// `route`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hy2Route {
    pub(crate) rules: Vec<Hy2Rule>,
}

/// One listener with its salamander password.
#[derive(Debug)]
pub(crate) struct ListenerInput<'a> {
    pub(crate) index: ListenerIdx,
    pub(crate) listener: &'a Hy2Listener,
    pub(crate) obfs: &'a Password,
}

/// What one node's `hy2.json` is rendered from.
#[derive(Debug)]
pub(crate) struct Hy2Input<'a> {
    pub(crate) vps4: PublicIpv4,
    pub(crate) listeners: Vec<ListenerInput<'a>>,
    pub(crate) certificate: &'a CertificatePem,
    pub(crate) key: &'a Hy2KeyPem,
    pub(crate) served: &'a [Served],
}

/// Builds `hy2.json`.
pub(crate) fn config(input: &Hy2Input<'_>) -> Hy2Config {
    let tags: Vec<Hy2InboundTag> = input
        .listeners
        .iter()
        .map(|listener| Hy2InboundTag(listener.index))
        .collect();
    let inbounds = input
        .listeners
        .iter()
        .map(|listener| Hy2Inbound {
            kind: Hysteria2Type::Value,
            tag: Hy2InboundTag(listener.index),
            listen: input.vps4,
            listen_port: listener.listener.port(),
            obfs: Salamander {
                kind: SalamanderType::Value,
                password: Rendered::new(listener.obfs.clone()),
            },
            users: input
                .served
                .iter()
                .map(|served| Hy2User {
                    name: served.identity.clone(),
                    password: Rendered::new(served.hy2.clone()),
                })
                .collect(),
            ignore_client_bandwidth: true,
            tls: Hy2Tls {
                enabled: true,
                alpn: [H3::Value],
                certificate: PemLines::new(input.certificate.clone()),
                key: PemLines::new(input.key.clone()),
            },
        })
        .collect();
    let outbounds = input
        .served
        .iter()
        .map(|served| LoopOutbound {
            kind: VlessType::Value,
            tag: LoopTag(served.identity.clone()),
            server: Ipv4Addr::LOCALHOST,
            server_port: SYSTEM_PORTS.hy2_loopback,
            uuid: Rendered::new(served.loopback.clone()),
            packet_encoding: Xudp::Value,
        })
        .collect();
    let mut rules: Vec<Hy2Rule> = input
        .served
        .iter()
        .map(|served| {
            Hy2Rule::Route(Hy2RouteRule {
                inbound: tags.clone(),
                auth_user: [served.identity.clone()],
                action: RouteAction::Value,
                outbound: LoopTag(served.identity.clone()),
            })
        })
        .collect();
    rules.push(Hy2Rule::Reject(Hy2RejectRule {
        inbound: tags,
        action: RejectAction::Value,
    }));
    Hy2Config {
        log: Log::default(),
        inbounds,
        outbounds,
        route: Hy2Route { rules },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_round_trip_and_reject_other_spellings() {
        for (index, text) in [(0, "hy2-in"), (1, "hy2-in-1"), (12, "hy2-in-12")] {
            let tag = Hy2InboundTag(ListenerIdx::new(index));
            assert_eq!(tag.to_string(), text);
            assert_eq!(text.parse::<Hy2InboundTag>().unwrap(), tag);
        }
        for bad in ["hy2-in-0", "hy2-in-01", "hy2-in-", "hy2-inx", "hy2"] {
            assert!(bad.parse::<Hy2InboundTag>().is_err(), "{bad}");
        }
        assert_eq!(
            "x-probe".parse::<LoopTag>().unwrap(),
            LoopTag(Identity::Probe)
        );
        assert!("x-nobody".parse::<LoopTag>().is_err());
        assert!("probe".parse::<LoopTag>().is_err());
    }
}
