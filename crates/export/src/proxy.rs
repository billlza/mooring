// SPDX-License-Identifier: GPL-3.0-or-later

//! Typed proxies: the format-neutral values every emitter renders
//! (design §9.2 "Guarantees enforced by types").
//!
//! - A REALITY proxy cannot exist without a [`Fingerprint`]: its
//!   [`ClientHello`] always names one.
//! - A Hysteria2 proxy cannot exist without a [`CertificatePin`].
//! - `server` is a `PublicIpv4`; salamander is the only obfuscation.
//! - The hop interval is the model's `HopInterval` (5..=3600 s, which every
//!   CFM line imports and sing-quic dials) and the client port range is one
//!   contiguous `start < end` range.
//! - No field exists for a feature CFM rejects.
//!
//! The proxies are built only inside this crate, from a validated
//! `Deployment` and `SecretSnapshot`.

use std::collections::BTreeSet;

use mooring_model::ports::{Hy2Listener, Hy2Obfs, PortRange, SYSTEM_PORTS};
use mooring_model::secret::Password;
use mooring_model::target::TargetSpec;
use mooring_model::{
    Capability, CertPins, ClientLine, ClientProfile, DnsName, HopInterval, Hy2Sni, Node,
    NodeAddress, Port, PublicIpv4, Secret, Sha256Digest, ShortId, SpkiSha256, Uuid, X25519Pub,
};

use crate::error::ExportError;
use crate::tag::OutboundTag;
use crate::tree::{LeafTag, Scalar};

/// The REALITY listener port: the model's HTTPS system port.
pub(crate) const REALITY_PORT: Port = SYSTEM_PORTS.https;

/// The protocol of one exported proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// VLESS over REALITY with the Vision flow.
    VlessReality,
    /// Hysteria2 with salamander and a pinned certificate.
    Hysteria2,
}

impl Protocol {
    /// Every protocol, in export order.
    pub const ALL: [Self; 2] = [Self::VlessReality, Self::Hysteria2];

    /// The stable name used in shape names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VlessReality => "vless-reality",
            Self::Hysteria2 => "hysteria2",
        }
    }
}

/// The uTLS fingerprint a REALITY outbound presents (design §7
/// `Fingerprint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Fingerprint {
    /// The uTLS `chrome` hello.
    Chrome,
}

impl Fingerprint {
    /// The name sing-box and Clash use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
        }
    }
}

/// The REALITY ClientHello: a fingerprint and whether it offers the
/// X25519MLKEM768 key share. CFM 0.5 allows the hybrid share only with the
/// chrome fingerprint, so no other pairing can be expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClientHello {
    /// The chrome hello with the classical X25519 share only.
    Chrome,
    /// The chrome hello offering X25519MLKEM768 ahead of X25519
    /// (`support_x25519mlkem768`).
    ChromeX25519Mlkem768,
}

impl ClientHello {
    /// Every hello.
    pub const ALL: [Self; 2] = [Self::Chrome, Self::ChromeX25519Mlkem768];

    /// The uTLS fingerprint.
    #[must_use]
    pub const fn fingerprint(self) -> Fingerprint {
        match self {
            Self::Chrome | Self::ChromeX25519Mlkem768 => Fingerprint::Chrome,
        }
    }

    /// Whether the hello offers the X25519MLKEM768 key share.
    #[must_use]
    pub const fn offers_x25519mlkem768(self) -> bool {
        match self {
            Self::Chrome => false,
            Self::ChromeX25519Mlkem768 => true,
        }
    }

    /// The stable name used in shape names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::ChromeX25519Mlkem768 => "chrome-x25519mlkem768",
        }
    }

    /// The hello a client profile selects. Every capability must be one the
    /// profile's line accepts (`ClientLine::accepts`, which matches the CFM
    /// importers: see `docs/cfm-contract.md`).
    pub fn for_profile(profile: &ClientProfile) -> Result<Self, ExportError> {
        if let Some(&cap) = profile
            .capabilities
            .iter()
            .find(|cap| !profile.line.accepts(**cap))
        {
            return Err(ExportError::CapabilityUnsupported {
                line: profile.line,
                cap,
            });
        }
        Ok(Self::for_capabilities(&profile.capabilities))
    }

    /// The hello a capability set selects, whatever the line.
    pub(crate) fn for_capabilities(capabilities: &BTreeSet<Capability>) -> Self {
        let mut hello = Self::Chrome;
        for cap in capabilities {
            match cap {
                Capability::RealityMlkemOptIn => hello = Self::ChromeX25519Mlkem768,
            }
        }
        hello
    }
}

/// Every capability, in declaration order. The successor is an exhaustive
/// match, so a new capability does not compile until it is placed here.
pub(crate) fn capabilities() -> impl Iterator<Item = Capability> {
    std::iter::successors(Some(Capability::RealityMlkemOptIn), |cap| match cap {
        Capability::RealityMlkemOptIn => None,
    })
}

/// Every CFM client line, oldest first. The successor is an exhaustive
/// match, so a new line does not compile until it is placed here.
pub(crate) fn client_lines() -> impl Iterator<Item = ClientLine> {
    std::iter::successors(Some(ClientLine::Cfm04), |line| match line {
        ClientLine::Cfm04 => Some(ClientLine::Cfm05),
        ClientLine::Cfm05 => None,
    })
}

/// The stable name of a client line.
#[must_use]
pub const fn line_name(line: ClientLine) -> &'static str {
    match line {
        ClientLine::Cfm04 => "cfm04",
        ClientLine::Cfm05 => "cfm05",
    }
}

/// The certificate pins a Hysteria2 proxy carries: the SPKI pin for
/// sing-box JSON and the DER pin for Clash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CertificatePin {
    spki: SpkiSha256,
    der: Sha256Digest,
}

impl CertificatePin {
    fn of(pins: &CertPins) -> Self {
        Self {
            spki: pins.spki_sha256(),
            der: pins.der_sha256(),
        }
    }
}

/// The ports a Hysteria2 client hops across: the listener port through the
/// end of its hop range. `start < end` holds because the model's hop range
/// starts at `port + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientPorts(PortRange);

impl ClientPorts {
    fn of(listener: &Hy2Listener) -> Self {
        Self(listener.client_ports())
    }
}

/// The salamander obfuscation of a Hysteria2 listener; the only variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Salamander {
    password: Password,
}

/// Where a node is reached: its public address and its REALITY target.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Endpoint<'a> {
    server: PublicIpv4,
    target: &'a TargetSpec,
}

impl<'a> Endpoint<'a> {
    /// The endpoint of an adopted or applied node with a target.
    pub(crate) fn of(node: &'a Node) -> Result<Self, ExportError> {
        let inputs = node.apply_inputs()?;
        let NodeAddress::Public(server) = inputs.site.address;
        Ok(Self {
            server,
            target: inputs.target,
        })
    }
}

/// A VLESS+REALITY+Vision proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RealityProxy {
    server: PublicIpv4,
    uuid: Secret<Uuid>,
    server_name: DnsName,
    public_key: X25519Pub,
    short_id: ShortId,
    hello: ClientHello,
}

impl RealityProxy {
    pub(crate) fn new(
        endpoint: Endpoint<'_>,
        node: &Node,
        uuid: &Secret<Uuid>,
        short_id: ShortId,
        hello: ClientHello,
    ) -> Self {
        Self {
            server: endpoint.server,
            uuid: uuid.clone(),
            server_name: endpoint.target.host().clone(),
            public_key: node.reality.public_key,
            short_id,
            hello,
        }
    }

    /// The hello, which selects the template variant.
    pub(crate) const fn hello(&self) -> ClientHello {
        self.hello
    }

    /// The value of one slot.
    pub(crate) fn resolve(&self, tag: &OutboundTag, slot: RealitySlot) -> Scalar {
        match slot {
            RealitySlot::Tag => Scalar::text(tag.as_str()),
            RealitySlot::Server => Scalar::text(self.server.to_string()),
            RealitySlot::Uuid => Scalar::Text(self.uuid.expose_secret().to_hyphenated()),
            RealitySlot::ServerName => Scalar::text(self.server_name.as_str()),
            RealitySlot::PublicKey => Scalar::text(self.public_key.to_string()),
            RealitySlot::ShortId => Scalar::text(self.short_id.to_string()),
        }
    }
}

/// A Hysteria2 proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hysteria2Proxy {
    server: PublicIpv4,
    ports: ClientPorts,
    hop_interval: HopInterval,
    password: Password,
    obfs: Salamander,
    sni: Hy2Sni,
    pin: CertificatePin,
}

impl Hysteria2Proxy {
    pub(crate) fn new(
        endpoint: Endpoint<'_>,
        pins: &CertPins,
        listener: &Hy2Listener,
        password: &Password,
        obfs_password: &Password,
    ) -> Self {
        let obfs = match listener.obfs() {
            Hy2Obfs::Salamander => Salamander {
                password: obfs_password.clone(),
            },
        };
        Self {
            server: endpoint.server,
            ports: ClientPorts::of(listener),
            hop_interval: listener.hop_interval(),
            password: password.clone(),
            obfs,
            sni: pins.sni().clone(),
            pin: CertificatePin::of(pins),
        }
    }

    /// The value of one slot.
    pub(crate) fn resolve(&self, tag: &OutboundTag, slot: Hy2Slot) -> Scalar {
        let ports = self.ports.0;
        match slot {
            Hy2Slot::Tag => Scalar::text(tag.as_str()),
            Hy2Slot::Server => Scalar::text(self.server.to_string()),
            Hy2Slot::Port => Scalar::Int(ports.start().get()),
            Hy2Slot::PortsColon => Scalar::text(format!("{}:{}", ports.start(), ports.end())),
            Hy2Slot::PortsDash => Scalar::text(format!("{}-{}", ports.start(), ports.end())),
            Hy2Slot::HopDuration => Scalar::text(format!("{}s", self.hop_interval.seconds())),
            Hy2Slot::HopSeconds => Scalar::Int(self.hop_interval.seconds()),
            Hy2Slot::Password => Scalar::Text(self.password.expose_text()),
            Hy2Slot::ObfsPassword => Scalar::Text(self.obfs.password.expose_text()),
            Hy2Slot::Sni => Scalar::text(self.sni.as_str()),
            Hy2Slot::SpkiPin => Scalar::text(self.pin.spki.to_string()),
            Hy2Slot::DerPin => Scalar::text(self.pin.der.to_string()),
        }
    }
}

/// A proxy of either protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Proxy {
    /// VLESS+REALITY+Vision.
    Reality(RealityProxy),
    /// Hysteria2.
    Hysteria2(Hysteria2Proxy),
}

impl Proxy {
    pub(crate) const fn protocol(&self) -> Protocol {
        match self {
            Self::Reality(_) => Protocol::VlessReality,
            Self::Hysteria2(_) => Protocol::Hysteria2,
        }
    }
}

/// The variable leaves of a REALITY proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RealitySlot {
    /// The outbound tag or Clash name.
    Tag,
    /// The node address.
    Server,
    /// The user's VLESS UUID.
    Uuid,
    /// The REALITY target host, sent as SNI.
    ServerName,
    /// The node's REALITY public key.
    PublicKey,
    /// The user's short id.
    ShortId,
}

impl RealitySlot {
    /// The shape tag of the slot.
    pub(crate) const fn leaf(self) -> LeafTag {
        match self {
            Self::Tag => LeafTag::OutboundTag,
            Self::Server => LeafTag::PublicIpv4,
            Self::Uuid => LeafTag::Uuid,
            Self::ServerName => LeafTag::DnsName,
            Self::PublicKey => LeafTag::X25519PublicKey,
            Self::ShortId => LeafTag::ShortId,
        }
    }
}

/// The variable leaves of a Hysteria2 proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hy2Slot {
    /// The outbound tag or Clash name.
    Tag,
    /// The node address.
    Server,
    /// The listener port (Clash `port`).
    Port,
    /// The client ports as `start:end` (sing-box `server_ports`).
    PortsColon,
    /// The client ports as `start-end` (Clash `ports`).
    PortsDash,
    /// The hop interval as `<n>s` (sing-box).
    HopDuration,
    /// The hop interval in seconds (Clash).
    HopSeconds,
    /// The user's Hysteria2 password.
    Password,
    /// The listener's salamander password.
    ObfsPassword,
    /// The certificate SNI.
    Sni,
    /// The SPKI pin.
    SpkiPin,
    /// The DER pin.
    DerPin,
}

impl Hy2Slot {
    /// The shape tag of the slot.
    pub(crate) const fn leaf(self) -> LeafTag {
        match self {
            Self::Tag => LeafTag::OutboundTag,
            Self::Server => LeafTag::PublicIpv4,
            Self::Port => LeafTag::Port,
            Self::PortsColon => LeafTag::PortRangeColon,
            Self::PortsDash => LeafTag::PortRangeDash,
            Self::HopDuration => LeafTag::HopIntervalDuration,
            Self::HopSeconds => LeafTag::HopIntervalSeconds,
            Self::Password | Self::ObfsPassword => LeafTag::Password,
            Self::Sni => LeafTag::Hy2Sni,
            Self::SpkiPin => LeafTag::SpkiSha256,
            Self::DerPin => LeafTag::DerSha256,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use mooring_model::Capability;
    use mooring_model::ports::DEFAULT_HY2_HOP;

    use super::*;

    #[test]
    fn reality_port_is_the_https_system_port() {
        assert_eq!(REALITY_PORT, SYSTEM_PORTS.https);
        assert_eq!(REALITY_PORT.get(), 443);
    }

    #[test]
    fn every_line_and_capability_is_listed_once() {
        assert_eq!(
            client_lines().collect::<Vec<_>>(),
            [ClientLine::Cfm04, ClientLine::Cfm05]
        );
        assert_eq!(
            capabilities().collect::<Vec<_>>(),
            [Capability::RealityMlkemOptIn]
        );
        assert_eq!(line_name(ClientLine::Cfm04), "cfm04");
        assert_eq!(line_name(ClientLine::Cfm05), "cfm05");
    }

    #[test]
    fn profiles_select_the_hello() {
        let profile = |line, caps: &[Capability]| ClientProfile {
            line,
            capabilities: caps.iter().copied().collect::<BTreeSet<_>>(),
        };
        assert_eq!(
            ClientHello::for_profile(&profile(ClientLine::Cfm04, &[])).unwrap(),
            ClientHello::Chrome
        );
        assert_eq!(
            ClientHello::for_profile(&profile(ClientLine::Cfm05, &[])).unwrap(),
            ClientHello::Chrome
        );
        assert_eq!(
            ClientHello::for_profile(&profile(
                ClientLine::Cfm05,
                &[Capability::RealityMlkemOptIn]
            ))
            .unwrap(),
            ClientHello::ChromeX25519Mlkem768
        );
        let refused = ClientHello::for_profile(&profile(
            ClientLine::Cfm04,
            &[Capability::RealityMlkemOptIn],
        ))
        .unwrap_err();
        assert!(matches!(
            refused,
            ExportError::CapabilityUnsupported {
                line: ClientLine::Cfm04,
                cap: Capability::RealityMlkemOptIn
            }
        ));
    }

    #[test]
    fn hellos_always_use_chrome() {
        for hello in ClientHello::ALL {
            assert_eq!(hello.fingerprint(), Fingerprint::Chrome);
            assert_eq!(hello.fingerprint().as_str(), "chrome");
        }
        assert!(!ClientHello::Chrome.offers_x25519mlkem768());
        assert!(ClientHello::ChromeX25519Mlkem768.offers_x25519mlkem768());
    }

    #[test]
    fn client_ports_span_listener_and_hop_range() {
        let listener = Hy2Listener::new(
            Port::new(61000).unwrap(),
            DEFAULT_HY2_HOP,
            HopInterval::from_seconds(30).unwrap(),
            Hy2Obfs::Salamander,
        )
        .unwrap();
        let ports = ClientPorts::of(&listener).0;
        assert_eq!((ports.start().get(), ports.end().get()), (61000, 62999));
        assert!(ports.start() < ports.end());
    }
}
