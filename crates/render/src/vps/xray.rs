// SPDX-License-Identifier: GPL-3.0-or-later

//! `xray.json` for Xray-core v26.9.30 (design §8.2), as closed types.
//!
//! Xray ignores unknown keys (`infra/conf/serial/loader.go`), so every key
//! here was checked against the pinned source; `docs/engines.md` lists each
//! with its `file:line`. Invalid configurations cannot be expressed:
//!
//! - [`XrayOutbound`] is `Deny`, `Exit(ExitBinding)` or
//!   `CamoRedirect(CamoTarget)`. An [`ExitBinding`] always binds to
//!   `wgexit`; a [`CamoTarget`] is the REALITY target's public address on
//!   port 80 or 443. [`XrayOutbounds`] always serialises `deny` first, which
//!   makes it the default outbound.
//! - The run-time log level is `none`, its only value; validation copies are
//!   forced to `warning` by the agent.

use std::net::{Ipv4Addr, SocketAddrV4};

use ipnet::Ipv4Net;
use mooring_agent_proto::{Inbound, StatsEmail, WG_INTERFACE};
use mooring_model::dns::DnsName;
use mooring_model::exit::TrafficPolicy;
use mooring_model::ids::{ShortId, Uuid};
use mooring_model::ipv4::{PublicIpv4, SPECIAL_V4};
use mooring_model::ports::Port;
use mooring_model::secret::{RealityPrivateKey, Secret};
use mooring_model::target::TargetSpec;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

use crate::error::RenderError;
use crate::literal::literal;
use crate::reach::NodeReach;
use crate::secret_text::Rendered;
use crate::system::SMTP_PORT;
use crate::text_value::{IpMatch, PortText, PublicSocket, TextValueError};
use crate::vps::served::{Identity, Served};
use mooring_model::ports::SYSTEM_PORTS;

/// `xray.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrayConfig {
    pub(crate) log: XrayLog,
    pub(crate) api: XrayApi,
    pub(crate) stats: XrayStats,
    pub(crate) policy: XrayPolicy,
    pub(crate) dns: XrayDns,
    pub(crate) inbounds: XrayInbounds,
    pub(crate) outbounds: XrayOutbounds,
    pub(crate) routing: XrayRouting,
}

literal!(
    /// `log.access`: no access log.
    AccessLog = "none"
);
literal!(
    /// `log.loglevel` at run time: `none`, which turns off both logs
    /// (`infra/conf/log.go:57-59`). At `warning` Xray still logs every failed
    /// DoH lookup at ERROR with the queried domain
    /// (`app/dns/nameserver_doh.go:155,199,207,215`) and resolution failures
    /// (`transport/internet/dialer.go:258`), which `maskAddress` does not
    /// mask, and DoH fails for every uncached domain whenever the gate is
    /// closed. Start-up failures still reach stdout (`main/run.go:84,95`),
    /// and validation runs on a copy forced to `warning` (design §11.2).
    /// There is no other value.
    XrayLogLevel = "none"
);
literal!(
    /// `log.maskAddress`: mask every IP address in log lines (`app/log/log.go:170-196`).
    MaskAddress = "full"
);

/// `log` (`infra/conf/log.go:18-24`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct XrayLog {
    pub(crate) access: AccessLog,
    pub(crate) loglevel: XrayLogLevel,
    pub(crate) dns_log: bool,
    pub(crate) mask_address: MaskAddress,
}

literal!(
    /// `api.tag`.
    ApiTag = "api"
);
literal!(
    /// The one API service: per-user traffic counters for accounting.
    StatsService = "StatsService"
);

/// `api` (`infra/conf/api.go:16-20`): StatsService on loopback only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrayApi {
    pub(crate) tag: ApiTag,
    pub(crate) listen: SocketAddrV4,
    pub(crate) services: [StatsService; 1],
}

/// `stats`: an empty object enables the stats manager (`infra/conf/xray.go:387`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrayStats {}

/// The policy level of a VLESS client or a camouflage handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PolicyLevel {
    /// Level 0: users and the probe, with per-user traffic counters.
    User,
    /// Level 1: camouflage forwards, with short timeouts.
    Camo,
}

impl Serialize for PolicyLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            Self::User => 0,
            Self::Camo => 1,
        })
    }
}

impl<'de> Deserialize<'de> for PolicyLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u8::deserialize(deserializer)? {
            0 => Ok(Self::User),
            1 => Ok(Self::Camo),
            other => Err(de::Error::custom(format_args!(
                "policy level {other} is not 0 or 1"
            ))),
        }
    }
}

/// `policy.levels."0"` (`infra/conf/policy.go:7-16`). `statsUserOnline`
/// stays off: it keeps client IP lists readable through the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct UserLevelPolicy {
    pub(crate) handshake: u32,
    pub(crate) conn_idle: u32,
    pub(crate) uplink_only: u32,
    pub(crate) downlink_only: u32,
    pub(crate) stats_user_uplink: bool,
    pub(crate) stats_user_downlink: bool,
}

/// `policy.levels."1"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CamoLevelPolicy {
    pub(crate) handshake: u32,
    pub(crate) conn_idle: u32,
    pub(crate) uplink_only: u32,
    pub(crate) downlink_only: u32,
}

/// `policy.levels`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyLevels {
    #[serde(rename = "0")]
    pub(crate) user: UserLevelPolicy,
    #[serde(rename = "1")]
    pub(crate) camo: CamoLevelPolicy,
}

/// `policy` (`infra/conf/policy.go:73-76`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct XrayPolicy {
    pub(crate) levels: PolicyLevels,
}

literal!(
    /// `dns.tag`: DoH queries enter routing with this inbound tag
    /// (`app/dns/nameserver.go:183`), which routes them through `exit`.
    DnsTag = "dns-exit"
);
literal!(
    /// `dns.queryStrategy` (`infra/conf/dns.go:381-394`): IPv4 only.
    UseIpv4 = "UseIPv4"
);

/// The two DoH servers, one operator: both are queried in parallel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum DohUrl {
    /// Cloudflare 1.1.1.1.
    #[serde(rename = "https://1.1.1.1/dns-query")]
    Cloudflare1111,
    /// Cloudflare 1.0.0.1.
    #[serde(rename = "https://1.0.0.1/dns-query")]
    Cloudflare1001,
}

/// One `dns.servers` entry (`infra/conf/dns.go:19-35`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DohServer {
    pub(crate) address: DohUrl,
    /// Answers inside `SPECIAL_V4` are dropped.
    #[serde(rename = "unexpectedIPs")]
    pub(crate) unexpected_ips: Vec<Ipv4Net>,
}

/// `dns` (`infra/conf/dns.go:160-173`). No `disableFallback`: with no
/// domain-scoped servers it would leave only the first server and log a
/// WARNING naming every domain (`app/dns/dns.go:321-344`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct XrayDns {
    pub(crate) tag: DnsTag,
    pub(crate) query_strategy: UseIpv4,
    pub(crate) enable_parallel_query: bool,
    pub(crate) serve_stale: bool,
    #[serde(rename = "serveExpiredTTL")]
    pub(crate) serve_expired_ttl: u32,
    pub(crate) servers: Vec<DohServer>,
}

literal!(
    /// The VLESS protocol.
    VlessProtocol = "vless"
);
literal!(
    /// The `tunnel` inbound protocol, an alias of `dokodemo-door`
    /// (`infra/conf/xray.go:25-26`).
    TunnelProtocol = "tunnel"
);
literal!(
    /// VLESS `decryption` (`infra/conf/vless.go:149-153`).
    Decryption = "none"
);
literal!(
    /// The Vision flow, required with REALITY.
    Vision = "xtls-rprx-vision"
);
literal!(
    /// No flow: the loopback handoff has no TLS to splice.
    NoFlow = ""
);
literal!(
    /// `streamSettings.network` (`infra/conf/transport_internet.go:16-19`).
    RawNetwork = "raw"
);
literal!(
    /// `streamSettings.security` for `reality-in`.
    RealitySecurity = "reality"
);
literal!(
    /// `streamSettings.security` for the loopback handoff.
    NoSecurity = "none"
);
literal!(
    /// `realitySettings.minClientVer`: sing-box clients, including both CFM
    /// lines, always announce 1.8.1 (design §4.2).
    MinClientVer = "1.8.1"
);

/// One VLESS client (`proxy/vless/account.pb.go:80-82`,
/// `common/protocol/user.pb.go:28-29`); `F` is its flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VlessClient<F> {
    pub(crate) id: Rendered<Secret<Uuid>>,
    pub(crate) flow: F,
    pub(crate) level: PolicyLevel,
    pub(crate) email: StatsEmail,
}

/// VLESS inbound `settings` (`infra/conf/vless.go:33-40`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VlessSettings<F> {
    pub(crate) decryption: Decryption,
    pub(crate) clients: Vec<VlessClient<F>>,
}

/// A sniffed protocol (`infra/conf/xray.go:68-84`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SniffProtocol {
    Http,
    Tls,
    Quic,
}

/// `sniffing` (`infra/conf/xray.go:59-66`): `routeOnly` feeds routing and
/// never rewrites the destination. Sniffing also always runs the
/// BitTorrent sniffers (`app/dispatcher/sniffer.go:41,43`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Sniffing {
    pub(crate) enabled: bool,
    pub(crate) dest_override: Vec<SniffProtocol>,
    pub(crate) route_only: bool,
}

/// `realitySettings` for a server (`infra/conf/transport_security.go:27-52,
/// 54-178`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RealitySettings {
    pub(crate) show: bool,
    pub(crate) target: PublicSocket,
    pub(crate) xver: u8,
    pub(crate) server_names: Vec<DnsName>,
    pub(crate) private_key: Rendered<RealityPrivateKey>,
    pub(crate) min_client_ver: MinClientVer,
    /// Milliseconds (`transport/internet/reality/config.go:29`).
    pub(crate) max_time_diff: u64,
    pub(crate) short_ids: Vec<ShortId>,
}

/// `streamSettings` of `reality-in`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RealityStream {
    pub(crate) network: RawNetwork,
    pub(crate) security: RealitySecurity,
    pub(crate) reality_settings: RealitySettings,
}

/// `streamSettings` of `hy2-loop-in`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlainStream {
    pub(crate) network: RawNetwork,
    pub(crate) security: NoSecurity,
}

/// `reality-in`: VLESS+REALITY+Vision on `<VPS4>:443`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RealityInbound {
    pub(crate) listen: PublicIpv4,
    pub(crate) port: Port,
    pub(crate) protocol: VlessProtocol,
    pub(crate) settings: VlessSettings<Vision>,
    pub(crate) stream_settings: RealityStream,
    pub(crate) sniffing: Sniffing,
}

/// `hy2-loop-in`: the Hysteria2 handoff on loopback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct LoopbackInbound {
    pub(crate) listen: Ipv4Addr,
    pub(crate) port: Port,
    pub(crate) protocol: VlessProtocol,
    pub(crate) settings: VlessSettings<NoFlow>,
    pub(crate) stream_settings: PlainStream,
    pub(crate) sniffing: Sniffing,
}

/// A network name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum XrayNetwork {
    Tcp,
    Udp,
}

/// `tunnel` settings (`infra/conf/dokodemo.go:10-20`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct TunnelSettings {
    pub(crate) address: PublicIpv4,
    pub(crate) port: Port,
    pub(crate) network: XrayNetwork,
    pub(crate) user_level: PolicyLevel,
}

/// `camo-80` or `camo-u443`: forwards to the REALITY target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CamoInbound {
    pub(crate) listen: PublicIpv4,
    pub(crate) port: Port,
    pub(crate) protocol: TunnelProtocol,
    pub(crate) settings: TunnelSettings,
}

/// One inbound, tagged by `tag` (`infra/conf/xray.go:130-138`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag")]
pub(crate) enum XrayInbound {
    #[serde(rename = "reality-in")]
    Reality(RealityInbound),
    #[serde(rename = "hy2-loop-in")]
    Loopback(LoopbackInbound),
    #[serde(rename = "camo-80")]
    CamoHttp(CamoInbound),
    #[serde(rename = "camo-u443")]
    CamoQuic(CamoInbound),
}

/// The camouflage forwards, which exist together or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CamoInbounds {
    pub(crate) http: CamoInbound,
    pub(crate) quic: CamoInbound,
}

/// `inbounds`: `reality-in`, `hy2-loop-in`, then the camouflage forwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<XrayInbound>", into = "Vec<XrayInbound>")]
pub(crate) struct XrayInbounds {
    pub(crate) reality: RealityInbound,
    pub(crate) loopback: LoopbackInbound,
    pub(crate) camo: Option<CamoInbounds>,
}

impl From<XrayInbounds> for Vec<XrayInbound> {
    fn from(inbounds: XrayInbounds) -> Self {
        let mut list = vec![
            XrayInbound::Reality(inbounds.reality),
            XrayInbound::Loopback(inbounds.loopback),
        ];
        if let Some(camo) = inbounds.camo {
            list.push(XrayInbound::CamoHttp(camo.http));
            list.push(XrayInbound::CamoQuic(camo.quic));
        }
        list
    }
}

impl TryFrom<Vec<XrayInbound>> for XrayInbounds {
    type Error = TextValueError;

    fn try_from(list: Vec<XrayInbound>) -> Result<Self, Self::Error> {
        let mut list = list.into_iter();
        match (
            list.next(),
            list.next(),
            list.next(),
            list.next(),
            list.next(),
        ) {
            (
                Some(XrayInbound::Reality(reality)),
                Some(XrayInbound::Loopback(loopback)),
                None,
                None,
                None,
            ) => Ok(Self {
                reality,
                loopback,
                camo: None,
            }),
            (
                Some(XrayInbound::Reality(reality)),
                Some(XrayInbound::Loopback(loopback)),
                Some(XrayInbound::CamoHttp(http)),
                Some(XrayInbound::CamoQuic(quic)),
                None,
            ) => Ok(Self {
                reality,
                loopback,
                camo: Some(CamoInbounds { http, quic }),
            }),
            _ => Err(TextValueError(
                "reality-in, hy2-loop-in, then optionally camo-80 and camo-u443",
            )),
        }
    }
}

/// An outbound tag; also the target of routing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum OutboundTag {
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "exit")]
    Exit,
    #[serde(rename = "camo-80-out")]
    CamoHttp,
    #[serde(rename = "camo-u443-out")]
    CamoQuic,
}

/// An outbound protocol (`infra/conf/xray.go:40-49`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OutboundProtocol {
    Blackhole,
    Freedom,
}

/// `sockopt.interface`: SO_BINDTODEVICE (`transport/internet/sockopt_linux.go:23-27`)
/// to the agent protocol's [`WG_INTERFACE`], the one name the agent manages.
/// It serialises as that name and deserialises nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WgExitInterface;

impl Serialize for WgExitInterface {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(WG_INTERFACE)
    }
}

impl<'de> Deserialize<'de> for WgExitInterface {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        if name == WG_INTERFACE {
            Ok(Self)
        } else {
            Err(de::Error::custom(format_args!(
                "exit interface {name:?} is not {WG_INTERFACE:?}"
            )))
        }
    }
}
literal!(
    /// `sockopt.domainStrategy` (`infra/conf/transport_sockopt.go:96-121`):
    /// resolve through Xray's DoH and fail on a DNS error rather than fall
    /// back to the system resolver (`transport/internet/dialer.go:251-261`).
    ForceIpv4 = "ForceIPv4"
);

/// The `TCP_USER_TIMEOUT` of exit sockets, in milliseconds.
pub(crate) const EXIT_TCP_USER_TIMEOUT_MS: u32 = 30_000;

/// `streamSettings.sockopt` of `exit` (`infra/conf/transport_sockopt.go:45-66`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ExitSockopt {
    pub(crate) interface: WgExitInterface,
    pub(crate) tcp_user_timeout: u32,
    pub(crate) domain_strategy: ForceIpv4,
}

/// `streamSettings` of `exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExitStream {
    pub(crate) sockopt: ExitSockopt,
}

/// The `exit` binding. It can only be built bound to `wgexit`, with the TCP
/// user timeout and the forced-IPv4 resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ExitBinding(());

impl ExitBinding {
    /// The one exit binding.
    pub(crate) const WGEXIT: Self = Self(());

    const fn stream(self) -> ExitStream {
        ExitStream {
            sockopt: ExitSockopt {
                interface: WgExitInterface,
                tcp_user_timeout: EXIT_TCP_USER_TIMEOUT_MS,
                domain_strategy: ForceIpv4::Value,
            },
        }
    }
}

/// A camouflage port: TCP 80 or UDP 443 of the REALITY target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CamoPort {
    /// TCP 80 (`camo-80`).
    Http,
    /// UDP 443 (`camo-u443`).
    Quic,
}

impl CamoPort {
    pub(crate) const fn port(self) -> Port {
        match self {
            Self::Http => SYSTEM_PORTS.http,
            Self::Quic => SYSTEM_PORTS.https,
        }
    }

    pub(crate) const fn network(self) -> XrayNetwork {
        match self {
            Self::Http => XrayNetwork::Tcp,
            Self::Quic => XrayNetwork::Udp,
        }
    }

    const fn tag(self) -> OutboundTag {
        match self {
            Self::Http => OutboundTag::CamoHttp,
            Self::Quic => OutboundTag::CamoQuic,
        }
    }
}

/// Where a camouflage redirect goes: only ever the REALITY target's public
/// address, on port 80 or 443.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CamoTarget {
    pub(crate) ip: PublicIpv4,
    pub(crate) port: CamoPort,
}

/// freedom `settings` of a camouflage outbound (`infra/conf/freedom.go:19-30`).
/// `userLevel` 1 gives the outbound side the camouflage timeouts as well:
/// freedom applies its own level's policy (`proxy/freedom/freedom.go:210-211`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RedirectSettings {
    pub(crate) redirect: PublicSocket,
    pub(crate) user_level: PolicyLevel,
}

/// One outbound as written (`infra/conf/xray.go:220-229`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutboundWire {
    tag: OutboundTag,
    protocol: OutboundProtocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    settings: Option<RedirectSettings>,
    #[serde(rename = "streamSettings", skip_serializing_if = "Option::is_none")]
    stream_settings: Option<ExitStream>,
}

/// An outbound: the only three Mooring ever renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "OutboundWire", into = "OutboundWire")]
pub(crate) enum XrayOutbound {
    /// `deny`: blackhole.
    Deny,
    /// `exit`: freedom bound to `wgexit`.
    Exit(ExitBinding),
    /// `camo-80-out` or `camo-u443-out`: freedom redirected to the target.
    CamoRedirect(CamoTarget),
}

impl From<XrayOutbound> for OutboundWire {
    fn from(outbound: XrayOutbound) -> Self {
        match outbound {
            XrayOutbound::Deny => Self {
                tag: OutboundTag::Deny,
                protocol: OutboundProtocol::Blackhole,
                settings: None,
                stream_settings: None,
            },
            XrayOutbound::Exit(binding) => Self {
                tag: OutboundTag::Exit,
                protocol: OutboundProtocol::Freedom,
                settings: None,
                stream_settings: Some(binding.stream()),
            },
            XrayOutbound::CamoRedirect(target) => Self {
                tag: target.port.tag(),
                protocol: OutboundProtocol::Freedom,
                settings: Some(RedirectSettings {
                    redirect: PublicSocket {
                        ip: target.ip,
                        port: target.port.port(),
                    },
                    user_level: PolicyLevel::Camo,
                }),
                stream_settings: None,
            },
        }
    }
}

impl TryFrom<OutboundWire> for XrayOutbound {
    type Error = TextValueError;

    fn try_from(wire: OutboundWire) -> Result<Self, Self::Error> {
        let camo = |port: CamoPort, settings: RedirectSettings| {
            (settings.redirect.port == port.port() && settings.user_level == PolicyLevel::Camo)
                .then_some(Self::CamoRedirect(CamoTarget {
                    ip: settings.redirect.ip,
                    port,
                }))
        };
        let outbound = match (wire.tag, wire.protocol, wire.settings, wire.stream_settings) {
            (OutboundTag::Deny, OutboundProtocol::Blackhole, None, None) => Some(Self::Deny),
            (OutboundTag::Exit, OutboundProtocol::Freedom, None, Some(stream))
                if stream == ExitBinding::WGEXIT.stream() =>
            {
                Some(Self::Exit(ExitBinding::WGEXIT))
            }
            (OutboundTag::CamoHttp, OutboundProtocol::Freedom, Some(settings), None) => {
                camo(CamoPort::Http, settings)
            }
            (OutboundTag::CamoQuic, OutboundProtocol::Freedom, Some(settings), None) => {
                camo(CamoPort::Quic, settings)
            }
            _ => None,
        };
        outbound.ok_or(TextValueError(
            "a deny blackhole, the wgexit exit or a camouflage redirect",
        ))
    }
}

/// `outbounds`: `deny` first, which makes it the default, then `exit`, then
/// the camouflage redirects to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<XrayOutbound>", into = "Vec<XrayOutbound>")]
pub(crate) struct XrayOutbounds {
    pub(crate) exit: ExitBinding,
    /// The target the camouflage outbounds redirect to, when camouflage
    /// forwarding is on.
    pub(crate) camo: Option<PublicIpv4>,
}

impl From<XrayOutbounds> for Vec<XrayOutbound> {
    fn from(outbounds: XrayOutbounds) -> Self {
        let mut list = vec![XrayOutbound::Deny, XrayOutbound::Exit(outbounds.exit)];
        if let Some(ip) = outbounds.camo {
            for port in [CamoPort::Http, CamoPort::Quic] {
                list.push(XrayOutbound::CamoRedirect(CamoTarget { ip, port }));
            }
        }
        list
    }
}

impl TryFrom<Vec<XrayOutbound>> for XrayOutbounds {
    type Error = TextValueError;

    fn try_from(list: Vec<XrayOutbound>) -> Result<Self, Self::Error> {
        match list.as_slice() {
            [XrayOutbound::Deny, XrayOutbound::Exit(exit)] => Ok(Self {
                exit: *exit,
                camo: None,
            }),
            [
                XrayOutbound::Deny,
                XrayOutbound::Exit(exit),
                XrayOutbound::CamoRedirect(http),
                XrayOutbound::CamoRedirect(quic),
            ] if http.port == CamoPort::Http
                && quic.port == CamoPort::Quic
                && http.ip == quic.ip =>
            {
                Ok(Self {
                    exit: *exit,
                    camo: Some(http.ip),
                })
            }
            _ => Err(TextValueError(
                "deny, exit, then optionally camo-80-out and camo-u443-out to one target",
            )),
        }
    }
}

/// A routing rule's `inboundTag` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum RuleInbound {
    #[serde(rename = "reality-in")]
    Reality,
    #[serde(rename = "hy2-loop-in")]
    Loopback,
    #[serde(rename = "camo-80")]
    CamoHttp,
    #[serde(rename = "camo-u443")]
    CamoQuic,
    /// The DoH queries of `dns`.
    #[serde(rename = "dns-exit")]
    Dns,
}

literal!(
    /// `geosite:cn`, from the pinned `geosite.dat`.
    GeositeCn = "geosite:cn"
);
literal!(
    /// The BitTorrent protocol as sniffed.
    Bittorrent = "bittorrent"
);

/// One routing rule (`infra/conf/router.go:120-153`); absent conditions are
/// omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct XrayRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) inbound_tag: Option<Vec<RuleInbound>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<Vec<StatsEmail>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<Vec<IpMatch>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) domain: Option<Vec<GeositeCn>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network: Option<XrayNetwork>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) port: Option<PortText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) protocol: Option<Vec<Bittorrent>>,
    pub(crate) outbound_tag: OutboundTag,
}

impl XrayRule {
    const fn to(outbound_tag: OutboundTag) -> Self {
        Self {
            inbound_tag: None,
            user: None,
            ip: None,
            domain: None,
            network: None,
            port: None,
            protocol: None,
            outbound_tag,
        }
    }
}

literal!(
    /// `routing.domainStrategy`: IP rules match only IP-literal
    /// destinations; domains are covered by the DoH filter and the Mac.
    AsIs = "AsIs"
);

/// `routing` (`infra/conf/router.go:70-74`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct XrayRouting {
    pub(crate) domain_strategy: AsIs,
    pub(crate) rules: Vec<XrayRule>,
}

/// What one node's `xray.json` is rendered from.
#[derive(Debug)]
pub(crate) struct XrayInput<'a> {
    pub(crate) vps4: PublicIpv4,
    pub(crate) target: &'a TargetSpec,
    pub(crate) private_key: &'a RealityPrivateKey,
    pub(crate) served: &'a [Served],
    pub(crate) reach: &'a NodeReach,
    pub(crate) policy: &'a TrafficPolicy,
}

/// Builds `xray.json`.
pub(crate) fn config(input: &XrayInput<'_>) -> Result<XrayConfig, RenderError> {
    Ok(XrayConfig {
        log: XrayLog::default(),
        api: XrayApi {
            tag: ApiTag::Value,
            listen: SocketAddrV4::new(Ipv4Addr::LOCALHOST, SYSTEM_PORTS.xray_stats.get()),
            services: [StatsService::Value],
        },
        stats: XrayStats {},
        policy: policy(),
        dns: dns(),
        inbounds: inbounds(input)?,
        outbounds: XrayOutbounds {
            exit: ExitBinding::WGEXIT,
            camo: input.policy.camo_forward.then_some(input.target.ipv4()),
        },
        routing: XrayRouting {
            domain_strategy: AsIs::Value,
            rules: rules(input)?,
        },
    })
}

const fn policy() -> XrayPolicy {
    XrayPolicy {
        levels: PolicyLevels {
            user: UserLevelPolicy {
                handshake: 4,
                conn_idle: 300,
                uplink_only: 2,
                downlink_only: 5,
                stats_user_uplink: true,
                stats_user_downlink: true,
            },
            camo: CamoLevelPolicy {
                handshake: 2,
                conn_idle: 30,
                uplink_only: 1,
                downlink_only: 1,
            },
        },
    }
}

/// `SPECIAL_V4`, the single deny list, as prefixes.
fn special_v4() -> Vec<Ipv4Net> {
    SPECIAL_V4.iter().map(|class| class.net()).collect()
}

fn dns() -> XrayDns {
    XrayDns {
        tag: DnsTag::Value,
        query_strategy: UseIpv4::Value,
        enable_parallel_query: true,
        serve_stale: true,
        serve_expired_ttl: 600,
        servers: [DohUrl::Cloudflare1111, DohUrl::Cloudflare1001]
            .into_iter()
            .map(|address| DohServer {
                address,
                unexpected_ips: special_v4(),
            })
            .collect(),
    }
}

fn sniffing() -> Sniffing {
    Sniffing {
        enabled: true,
        dest_override: vec![SniffProtocol::Http, SniffProtocol::Tls, SniffProtocol::Quic],
        route_only: true,
    }
}

fn clients<F: Copy>(
    served: &[Served],
    flow: F,
    inbound: Inbound,
    id: impl Fn(&Served) -> &Secret<Uuid>,
) -> Result<Vec<VlessClient<F>>, RenderError> {
    served
        .iter()
        .map(|served| {
            Ok(VlessClient {
                id: Rendered::new(id(served).clone()),
                flow,
                level: PolicyLevel::User,
                email: served.identity.email(inbound)?,
            })
        })
        .collect()
}

fn inbounds(input: &XrayInput<'_>) -> Result<XrayInbounds, RenderError> {
    let target = input.target;
    let reality = RealityInbound {
        listen: input.vps4,
        port: SYSTEM_PORTS.https,
        protocol: VlessProtocol::Value,
        settings: VlessSettings {
            decryption: Decryption::Value,
            clients: clients(input.served, Vision::Value, Inbound::Reality, |served| {
                &served.vless
            })?,
        },
        stream_settings: RealityStream {
            network: RawNetwork::Value,
            security: RealitySecurity::Value,
            reality_settings: RealitySettings {
                show: false,
                target: PublicSocket {
                    ip: target.ipv4(),
                    port: SYSTEM_PORTS.https,
                },
                xver: 0,
                server_names: vec![target.host().clone()],
                private_key: Rendered::new(input.private_key.clone()),
                min_client_ver: MinClientVer::Value,
                max_time_diff: 60_000,
                short_ids: input.served.iter().map(|served| served.short_id).collect(),
            },
        },
        sniffing: sniffing(),
    };
    let loopback = LoopbackInbound {
        listen: Ipv4Addr::LOCALHOST,
        port: SYSTEM_PORTS.hy2_loopback,
        protocol: VlessProtocol::Value,
        settings: VlessSettings {
            decryption: Decryption::Value,
            clients: clients(input.served, NoFlow::Value, Inbound::Hy2, |served| {
                &served.loopback
            })?,
        },
        stream_settings: PlainStream::default(),
        sniffing: sniffing(),
    };
    let camo = |port: CamoPort| CamoInbound {
        listen: input.vps4,
        port: port.port(),
        protocol: TunnelProtocol::Value,
        settings: TunnelSettings {
            address: target.ipv4(),
            port: port.port(),
            network: port.network(),
            user_level: PolicyLevel::Camo,
        },
    };
    Ok(XrayInbounds {
        reality,
        loopback,
        camo: input.policy.camo_forward.then(|| CamoInbounds {
            http: camo(CamoPort::Http),
            quic: camo(CamoPort::Quic),
        }),
    })
}

fn rules(input: &XrayInput<'_>) -> Result<Vec<XrayRule>, RenderError> {
    let policy = input.policy;
    let mut rules = Vec::new();
    if policy.camo_forward {
        rules.push(XrayRule {
            inbound_tag: Some(vec![RuleInbound::CamoHttp]),
            ..XrayRule::to(OutboundTag::CamoHttp)
        });
        rules.push(XrayRule {
            inbound_tag: Some(vec![RuleInbound::CamoQuic]),
            ..XrayRule::to(OutboundTag::CamoQuic)
        });
    }
    rules.push(XrayRule {
        inbound_tag: Some(vec![RuleInbound::Dns]),
        ..XrayRule::to(OutboundTag::Exit)
    });
    let probe = vec![
        Identity::Probe.email(Inbound::Reality)?,
        Identity::Probe.email(Inbound::Hy2)?,
    ];
    for (port, addresses) in &input.reach.reflectors {
        rules.push(XrayRule {
            user: Some(probe.clone()),
            ip: Some(addresses.iter().copied().map(IpMatch::Host).collect()),
            network: Some(XrayNetwork::Tcp),
            port: Some(PortText(*port)),
            ..XrayRule::to(OutboundTag::Exit)
        });
    }
    rules.push(XrayRule {
        ip: Some(
            input
                .reach
                .addresses
                .iter()
                .copied()
                .map(IpMatch::Host)
                .collect(),
        ),
        ..XrayRule::to(OutboundTag::Deny)
    });
    let mut special: Vec<IpMatch> = special_v4().into_iter().map(IpMatch::Net).collect();
    special.push(IpMatch::AllIpv6);
    rules.push(XrayRule {
        ip: Some(special),
        ..XrayRule::to(OutboundTag::Deny)
    });
    if policy.deny_cn {
        rules.push(XrayRule {
            ip: Some(vec![IpMatch::GeoipCn]),
            ..XrayRule::to(OutboundTag::Deny)
        });
        rules.push(XrayRule {
            domain: Some(vec![GeositeCn::Value]),
            ..XrayRule::to(OutboundTag::Deny)
        });
    }
    if policy.block_quic {
        rules.push(XrayRule {
            network: Some(XrayNetwork::Udp),
            port: Some(PortText(SYSTEM_PORTS.https)),
            ..XrayRule::to(OutboundTag::Deny)
        });
    }
    if policy.deny_smtp25 {
        rules.push(XrayRule {
            network: Some(XrayNetwork::Tcp),
            port: Some(PortText(Port::new(SMTP_PORT)?)),
            ..XrayRule::to(OutboundTag::Deny)
        });
    }
    if policy.deny_bittorrent {
        rules.push(XrayRule {
            protocol: Some(vec![Bittorrent::Value]),
            ..XrayRule::to(OutboundTag::Deny)
        });
    }
    rules.push(XrayRule {
        inbound_tag: Some(vec![RuleInbound::Reality, RuleInbound::Loopback]),
        ..XrayRule::to(OutboundTag::Exit)
    });
    Ok(rules)
}
