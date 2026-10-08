// SPDX-License-Identifier: GPL-3.0-or-later

//! Ports, port ranges, Hysteria2 listeners and the per-node `PortPlan`
//! (design §5.3).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::collections::NonEmpty;
use crate::error::ModelError;

/// A TCP or UDP port in 1..=65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Port(u16);

impl Port {
    /// Accepts any port except zero.
    pub fn new(port: u16) -> Result<Self, ModelError> {
        if port == 0 {
            Err(ModelError::InvalidPort)
        } else {
            Ok(Self(port))
        }
    }

    /// The port number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for Port {
    type Error = ModelError;

    fn try_from(port: u16) -> Result<Self, Self::Error> {
        Self::new(port)
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> Self {
        port.0
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// An inclusive, non-empty range of ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "PortRangeRepr", into = "PortRangeRepr")]
pub struct PortRange {
    start: Port,
    end: Port,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortRangeRepr {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Accepts `start..=end` with `1 <= start <= end`.
    pub fn new(start: u16, end: u16) -> Result<Self, ModelError> {
        if start == 0 || start > end {
            return Err(ModelError::InvalidPortRange { start, end });
        }
        Ok(Self {
            start: Port(start),
            end: Port(end),
        })
    }

    /// A range holding exactly `port`.
    #[must_use]
    pub const fn single(port: Port) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// The first port.
    #[must_use]
    pub const fn start(self) -> Port {
        self.start
    }

    /// The last port.
    #[must_use]
    pub const fn end(self) -> Port {
        self.end
    }

    /// The number of ports in the range, at least 1.
    #[must_use]
    pub const fn port_count(self) -> u32 {
        self.end.0 as u32 - self.start.0 as u32 + 1
    }

    /// Whether `port` lies inside the range.
    #[must_use]
    pub const fn contains(self, port: Port) -> bool {
        self.start.0 <= port.0 && port.0 <= self.end.0
    }

    /// Whether the two ranges share at least one port.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.start.0 <= other.end.0 && other.start.0 <= self.end.0
    }
}

impl TryFrom<PortRangeRepr> for PortRange {
    type Error = ModelError;

    fn try_from(repr: PortRangeRepr) -> Result<Self, Self::Error> {
        Self::new(repr.start, repr.end)
    }
}

impl From<PortRange> for PortRangeRepr {
    fn from(range: PortRange) -> Self {
        Self {
            start: range.start.0,
            end: range.end.0,
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

/// The Hysteria2 client port-hopping interval: 5..=3600 seconds.
///
/// The floor is the pinned sing-quic dialer's (`hysteria/hop.go:55-56`, "hop
/// interval must be at least 5 seconds") and CFM 0.5's import bound
/// (`cfw-singbox-config` `profile_validation.rs:17-18`, 5..=3600); CFM 0.4
/// accepts 1..=3600, so 5..=3600 is the range every client line both
/// imports and dials. A plan the exports could not serve cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct HopInterval(u16);

impl HopInterval {
    /// The smallest accepted interval in seconds.
    pub const MIN_SECONDS: u16 = 5;
    /// The largest accepted interval in seconds.
    pub const MAX_SECONDS: u16 = 3600;

    /// Accepts 5..=3600 seconds.
    pub fn from_seconds(seconds: u16) -> Result<Self, ModelError> {
        if (Self::MIN_SECONDS..=Self::MAX_SECONDS).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(ModelError::InvalidHopInterval { seconds })
        }
    }

    /// The interval in seconds.
    #[must_use]
    pub const fn seconds(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for HopInterval {
    type Error = ModelError;

    fn try_from(seconds: u16) -> Result<Self, Self::Error> {
        Self::from_seconds(seconds)
    }
}

impl From<HopInterval> for u16 {
    fn from(interval: HopInterval) -> Self {
        interval.0
    }
}

/// The index of a Hysteria2 listener within a node's `PortPlan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ListenerIdx(u8);

impl ListenerIdx {
    /// Listener 0, the only listener in v1.
    pub const FIRST: Self = Self(0);

    /// The listener with this index.
    #[must_use]
    pub const fn new(index: u8) -> Self {
        Self(index)
    }

    /// The index.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Display for ListenerIdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Hysteria2 obfuscation; salamander is the only variant in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hy2Obfs {
    /// Salamander, keyed by the listener's `NodeHy2Obfs` secret.
    Salamander,
}

/// One Hysteria2 listener: a UDP port plus the hop range redirected to it.
///
/// The hop range starts right after the listener port, so the client's port
/// set `port..=hop.end` is one contiguous range (`"61000:62999"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Hy2ListenerRepr", into = "Hy2ListenerRepr")]
pub struct Hy2Listener {
    port: Port,
    hop: PortRange,
    hop_interval: HopInterval,
    obfs: Hy2Obfs,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hy2ListenerRepr {
    port: Port,
    hop: PortRange,
    hop_interval: HopInterval,
    obfs: Hy2Obfs,
}

impl Hy2Listener {
    /// Accepts a listener whose hop range starts at `port + 1`.
    pub fn new(
        port: Port,
        hop: PortRange,
        hop_interval: HopInterval,
        obfs: Hy2Obfs,
    ) -> Result<Self, ModelError> {
        if port.0.checked_add(1) == Some(hop.start.0) {
            Ok(Self {
                port,
                hop,
                hop_interval,
                obfs,
            })
        } else {
            Err(ModelError::InvalidHy2Listener { port, hop })
        }
    }

    /// The UDP port the server listens on.
    #[must_use]
    pub const fn port(&self) -> Port {
        self.port
    }

    /// The UDP ports redirected to the listener port.
    #[must_use]
    pub const fn hop(&self) -> PortRange {
        self.hop
    }

    /// The interval at which clients hop between ports.
    #[must_use]
    pub const fn hop_interval(&self) -> HopInterval {
        self.hop_interval
    }

    /// The obfuscation scheme.
    #[must_use]
    pub const fn obfs(&self) -> Hy2Obfs {
        self.obfs
    }

    /// Every port a client may use: the listener port through the end of the hop range.
    #[must_use]
    pub const fn client_ports(&self) -> PortRange {
        PortRange {
            start: self.port,
            end: self.hop.end,
        }
    }
}

impl TryFrom<Hy2ListenerRepr> for Hy2Listener {
    type Error = ModelError;

    fn try_from(repr: Hy2ListenerRepr) -> Result<Self, Self::Error> {
        Self::new(repr.port, repr.hop, repr.hop_interval, repr.obfs)
    }
}

impl From<Hy2Listener> for Hy2ListenerRepr {
    fn from(listener: Hy2Listener) -> Self {
        Self {
            port: listener.port,
            hop: listener.hop,
            hop_interval: listener.hop_interval,
            obfs: listener.obfs,
        }
    }
}

/// What a port or range in a `PortPlan` is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortUse {
    /// TCP 22, sshd.
    Ssh,
    /// TCP 80, the camouflage forward.
    Http,
    /// TCP and UDP 443, REALITY and the camouflage forward.
    Https,
    /// TCP 10085 on loopback, the Xray stats API.
    XrayStats,
    /// TCP 10443 on loopback, the Hysteria2 handoff into Xray.
    Hy2Loopback,
    /// UDP, kernel WireGuard.
    WireGuard,
    /// TCP, the reflector.
    Reflector,
    /// UDP, a Hysteria2 listener port.
    Hy2Listener(ListenerIdx),
    /// UDP, a Hysteria2 hop range.
    Hy2Hop(ListenerIdx),
    /// UDP, a range reserved for a future listener.
    Reserved(u8),
}

impl fmt::Display for PortUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssh => f.write_str("ssh"),
            Self::Http => f.write_str("http camouflage"),
            Self::Https => f.write_str("https"),
            Self::XrayStats => f.write_str("xray stats api"),
            Self::Hy2Loopback => f.write_str("hysteria2 loopback handoff"),
            Self::WireGuard => f.write_str("wireguard"),
            Self::Reflector => f.write_str("reflector"),
            Self::Hy2Listener(index) => write!(f, "hysteria2 listener {index}"),
            Self::Hy2Hop(index) => write!(f, "hysteria2 hop range {index}"),
            Self::Reserved(index) => write!(f, "reserved range {index}"),
        }
    }
}

/// Why a port plan was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortConflict {
    /// Two uses share a port.
    Overlap {
        /// The earlier use.
        first: PortUse,
        /// The later use.
        second: PortUse,
    },
    /// A fixed port lies inside the ephemeral range.
    InsideEphemeral {
        /// The offending use.
        port_use: PortUse,
    },
    /// A hop or reserved range does not lie wholly above the ephemeral range.
    NotAboveEphemeral {
        /// The offending use.
        port_use: PortUse,
    },
    /// The plan has more Hysteria2 listeners than v1 supports.
    TooManyHy2Listeners {
        /// The supported maximum.
        max: usize,
    },
    /// The plan has more reserved ranges than v1 supports.
    TooManyReservedRanges {
        /// The supported maximum.
        max: usize,
    },
    /// The plan was validated against a different ephemeral range than the host reports.
    EphemeralRangeChanged {
        /// The range the plan was validated against.
        planned: PortRange,
        /// The range the host reports.
        live: PortRange,
    },
}

impl fmt::Display for PortConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overlap { first, second } => write!(f, "{first} overlaps {second}"),
            Self::InsideEphemeral { port_use } => {
                write!(f, "{port_use} lies inside the ephemeral port range")
            }
            Self::NotAboveEphemeral { port_use } => {
                write!(f, "{port_use} does not lie above the ephemeral port range")
            }
            Self::TooManyHy2Listeners { max } => write!(f, "more than {max} hysteria2 listeners"),
            Self::TooManyReservedRanges { max } => write!(f, "more than {max} reserved ranges"),
            Self::EphemeralRangeChanged { planned, live } => write!(
                f,
                "the plan was checked against ephemeral range {planned}, the host reports {live}"
            ),
        }
    }
}

/// The ports every VPS uses whatever its plan (design §5.3), by role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SystemPorts {
    /// TCP, sshd.
    pub ssh: Port,
    /// TCP, Xray's `camo-80` forward.
    pub http: Port,
    /// TCP REALITY and the UDP `camo-u443` forward; also the REALITY
    /// target's port.
    pub https: Port,
    /// TCP on loopback, the Xray StatsService.
    pub xray_stats: Port,
    /// TCP on loopback, Xray's `hy2-loop-in`.
    pub hy2_loopback: Port,
}

impl SystemPorts {
    /// Every system port with its use, for the plan's disjointness checks.
    const fn uses(self) -> [(PortUse, Port); 5] {
        [
            (PortUse::Ssh, self.ssh),
            (PortUse::Http, self.http),
            (PortUse::Https, self.https),
            (PortUse::XrayStats, self.xray_stats),
            (PortUse::Hy2Loopback, self.hy2_loopback),
        ]
    }
}

/// The system ports: 22, 80, 443, 10085 and 10443.
pub const SYSTEM_PORTS: SystemPorts = SystemPorts {
    ssh: Port(22),
    http: Port(80),
    https: Port(443),
    xray_stats: Port(10085),
    hy2_loopback: Port(10443),
};

/// Debian's default `net.ipv4.ip_local_port_range`.
pub const DEBIAN_EPHEMERAL_PORTS: PortRange = PortRange {
    start: Port(32768),
    end: Port(60999),
};
/// The default kernel WireGuard port.
pub const DEFAULT_WG_PORT: Port = Port(27820);
/// The default reflector port.
pub const DEFAULT_REFLECTOR_PORT: Port = Port(27900);
/// The default Hysteria2 listener 0 port.
pub const DEFAULT_HY2_PORT: Port = Port(61000);
/// The default hop range redirected to listener 0.
pub const DEFAULT_HY2_HOP: PortRange = PortRange {
    start: Port(61001),
    end: Port(62999),
};
/// The default range reserved for a future listener 1.
pub const DEFAULT_RESERVED_RANGE: PortRange = PortRange {
    start: Port(63000),
    end: Port(64999),
};
/// The default client hop interval.
pub const DEFAULT_HOP_INTERVAL: HopInterval = HopInterval(30);
/// The most Hysteria2 listeners a plan may hold (listener 0 plus the reserved listener 1).
pub const MAX_HY2_LISTENERS: usize = 2;
/// The most reserved ranges a plan may hold.
pub const MAX_RESERVED_RANGES: usize = 2;

/// Every port a node uses, checked against an ephemeral port range.
///
/// Invariants: all fixed ports (including [`SYSTEM_PORTS`]) and ranges are
/// pairwise disjoint; fixed ports lie outside `ephemeral`; hop and reserved
/// ranges lie wholly above it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "PortPlanRepr", into = "PortPlanRepr")]
pub struct PortPlan {
    wg: Port,
    reflector: Port,
    hy2: NonEmpty<Hy2Listener>,
    reserved: Vec<PortRange>,
    ephemeral: PortRange,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortPlanRepr {
    wg: Port,
    reflector: Port,
    hy2: NonEmpty<Hy2Listener>,
    reserved: Vec<PortRange>,
    ephemeral: PortRange,
}

/// Whether a span is a single fixed port or a range.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SpanKind {
    Fixed,
    Range,
}

impl PortPlan {
    /// Validates a plan against `ephemeral`.
    pub fn new(
        wg: Port,
        reflector: Port,
        hy2: NonEmpty<Hy2Listener>,
        reserved: Vec<PortRange>,
        ephemeral: PortRange,
    ) -> Result<Self, ModelError> {
        let plan = Self {
            wg,
            reflector,
            hy2,
            reserved,
            ephemeral,
        };
        plan.check()
            .map_err(|conflict| ModelError::PortPlanConflict { conflict })?;
        Ok(plan)
    }

    /// The design §5.3 defaults, validated against `ephemeral`.
    pub fn with_defaults(ephemeral: PortRange) -> Result<Self, ModelError> {
        Self::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(Hy2Listener {
                port: DEFAULT_HY2_PORT,
                hop: DEFAULT_HY2_HOP,
                hop_interval: DEFAULT_HOP_INTERVAL,
                obfs: Hy2Obfs::Salamander,
            }),
            vec![DEFAULT_RESERVED_RANGE],
            ephemeral,
        )
    }

    /// The same ports, re-validated against a host's live ephemeral range.
    pub fn rebase(&self, ephemeral: PortRange) -> Result<Self, ModelError> {
        Self::new(
            self.wg,
            self.reflector,
            self.hy2.clone(),
            self.reserved.clone(),
            ephemeral,
        )
    }

    /// The kernel WireGuard UDP port.
    #[must_use]
    pub const fn wg(&self) -> Port {
        self.wg
    }

    /// The reflector TCP port.
    #[must_use]
    pub const fn reflector(&self) -> Port {
        self.reflector
    }

    /// The Hysteria2 listeners, listener 0 first.
    #[must_use]
    pub const fn hy2(&self) -> &NonEmpty<Hy2Listener> {
        &self.hy2
    }

    /// The Hysteria2 listeners with their indices.
    pub fn hy2_listeners(&self) -> impl Iterator<Item = (ListenerIdx, &Hy2Listener)> {
        (0..=u8::MAX).map(ListenerIdx).zip(self.hy2.iter())
    }

    /// The listener with index `index`, if the plan has one.
    #[must_use]
    pub fn listener(&self, index: ListenerIdx) -> Option<&Hy2Listener> {
        self.hy2.as_slice().get(usize::from(index.0))
    }

    /// Ranges reserved for future listeners; nothing listens on them.
    #[must_use]
    pub fn reserved(&self) -> &[PortRange] {
        &self.reserved
    }

    /// The ephemeral port range the plan was validated against.
    #[must_use]
    pub const fn ephemeral(&self) -> PortRange {
        self.ephemeral
    }

    fn spans(&self) -> Vec<(PortUse, PortRange, SpanKind)> {
        let mut spans: Vec<(PortUse, PortRange, SpanKind)> = SYSTEM_PORTS
            .uses()
            .into_iter()
            .map(|(port_use, port)| (port_use, PortRange::single(port), SpanKind::Fixed))
            .collect();
        spans.push((
            PortUse::WireGuard,
            PortRange::single(self.wg),
            SpanKind::Fixed,
        ));
        spans.push((
            PortUse::Reflector,
            PortRange::single(self.reflector),
            SpanKind::Fixed,
        ));
        for (index, listener) in self.hy2_listeners() {
            spans.push((
                PortUse::Hy2Listener(index),
                PortRange::single(listener.port),
                SpanKind::Fixed,
            ));
            spans.push((PortUse::Hy2Hop(index), listener.hop, SpanKind::Range));
        }
        for (index, range) in (0..=u8::MAX).zip(self.reserved.iter()) {
            spans.push((PortUse::Reserved(index), *range, SpanKind::Range));
        }
        spans
    }

    fn check(&self) -> Result<(), PortConflict> {
        if self.hy2.len().get() > MAX_HY2_LISTENERS {
            return Err(PortConflict::TooManyHy2Listeners {
                max: MAX_HY2_LISTENERS,
            });
        }
        if self.reserved.len() > MAX_RESERVED_RANGES {
            return Err(PortConflict::TooManyReservedRanges {
                max: MAX_RESERVED_RANGES,
            });
        }
        let spans = self.spans();
        for (position, &(first, first_range, _)) in spans.iter().enumerate() {
            for &(second, second_range, _) in &spans[position + 1..] {
                if first_range.overlaps(second_range) {
                    return Err(PortConflict::Overlap { first, second });
                }
            }
        }
        for &(port_use, range, kind) in &spans {
            match kind {
                SpanKind::Fixed if range.overlaps(self.ephemeral) => {
                    return Err(PortConflict::InsideEphemeral { port_use });
                }
                SpanKind::Range if range.start.0 <= self.ephemeral.end.0 => {
                    return Err(PortConflict::NotAboveEphemeral { port_use });
                }
                SpanKind::Fixed | SpanKind::Range => {}
            }
        }
        Ok(())
    }
}

impl TryFrom<PortPlanRepr> for PortPlan {
    type Error = ModelError;

    fn try_from(repr: PortPlanRepr) -> Result<Self, Self::Error> {
        Self::new(
            repr.wg,
            repr.reflector,
            repr.hy2,
            repr.reserved,
            repr.ephemeral,
        )
    }
}

impl From<PortPlan> for PortPlanRepr {
    fn from(plan: PortPlan) -> Self {
        Self {
            wg: plan.wg,
            reflector: plan.reflector,
            hy2: plan.hy2,
            reserved: plan.reserved,
            ephemeral: plan.ephemeral,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn port(n: u16) -> Port {
        Port::new(n).unwrap()
    }

    fn range(start: u16, end: u16) -> PortRange {
        PortRange::new(start, end).unwrap()
    }

    fn listener(port_number: u16, hop_end: u16) -> Hy2Listener {
        Hy2Listener::new(
            port(port_number),
            range(port_number + 1, hop_end),
            DEFAULT_HOP_INTERVAL,
            Hy2Obfs::Salamander,
        )
        .unwrap()
    }

    fn conflict(result: Result<PortPlan, ModelError>) -> PortConflict {
        match result {
            Err(ModelError::PortPlanConflict { conflict }) => conflict,
            other => panic!("expected a port plan conflict, got {other:?}"),
        }
    }

    #[test]
    fn constants_are_valid_values() {
        for (_, system) in SYSTEM_PORTS.uses() {
            assert_eq!(Port::new(system.get()), Ok(system));
        }
        assert_eq!(
            SYSTEM_PORTS
                .uses()
                .map(|(port_use, port)| (port_use, port.get())),
            [
                (PortUse::Ssh, 22),
                (PortUse::Http, 80),
                (PortUse::Https, 443),
                (PortUse::XrayStats, 10085),
                (PortUse::Hy2Loopback, 10443),
            ]
        );
        for constant in [DEFAULT_WG_PORT, DEFAULT_REFLECTOR_PORT, DEFAULT_HY2_PORT] {
            assert_eq!(Port::new(constant.get()), Ok(constant));
        }
        for constant in [
            DEBIAN_EPHEMERAL_PORTS,
            DEFAULT_HY2_HOP,
            DEFAULT_RESERVED_RANGE,
        ] {
            assert_eq!(
                PortRange::new(constant.start().get(), constant.end().get()),
                Ok(constant)
            );
        }
        assert_eq!(HopInterval::from_seconds(30), Ok(DEFAULT_HOP_INTERVAL));
    }

    #[test]
    fn defaults_match_design_and_pass() {
        let plan = PortPlan::with_defaults(DEBIAN_EPHEMERAL_PORTS).unwrap();
        assert_eq!(plan.wg().get(), 27820);
        assert_eq!(plan.reflector().get(), 27900);
        let first = plan.hy2().first();
        assert_eq!(first.port().get(), 61000);
        assert_eq!(first.hop(), range(61001, 62999));
        assert_eq!(first.client_ports(), range(61000, 62999));
        assert_eq!(first.hop_interval().seconds(), 30);
        assert_eq!(plan.reserved(), &[range(63000, 64999)]);
        assert_eq!(plan.listener(ListenerIdx::FIRST), Some(first));
        assert_eq!(plan.listener(ListenerIdx::new(1)), None);
    }

    #[test]
    fn fixed_port_inside_ephemeral_is_rejected() {
        let plan = PortPlan::new(
            port(47820),
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(listener(61000, 62999)),
            vec![],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(plan),
            PortConflict::InsideEphemeral {
                port_use: PortUse::WireGuard
            }
        );
        // The first and last ephemeral ports are both inside.
        for edge in [32768, 60999] {
            let plan = PortPlan::new(
                DEFAULT_WG_PORT,
                port(edge),
                NonEmpty::new(listener(61000, 62999)),
                vec![],
                DEBIAN_EPHEMERAL_PORTS,
            );
            assert_eq!(
                conflict(plan),
                PortConflict::InsideEphemeral {
                    port_use: PortUse::Reflector
                }
            );
        }
        // The neighbours just outside are accepted.
        for edge in [32767, 61001] {
            assert!(
                PortPlan::new(
                    DEFAULT_WG_PORT,
                    port(edge),
                    NonEmpty::new(listener(63000, 64999)),
                    vec![],
                    DEBIAN_EPHEMERAL_PORTS,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn hop_range_must_lie_above_ephemeral() {
        // A listener on 20000 with hops 20001-21000 sits below the range.
        let plan = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(listener(20000, 21000)),
            vec![],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(plan),
            PortConflict::NotAboveEphemeral {
                port_use: PortUse::Hy2Hop(ListenerIdx::FIRST)
            }
        );
        // A reserved range starting at the last ephemeral port is rejected.
        let plan = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(listener(61000, 62999)),
            vec![range(60999, 60999)],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(plan),
            PortConflict::NotAboveEphemeral {
                port_use: PortUse::Reserved(0)
            }
        );
    }

    #[test]
    fn overlaps_are_rejected() {
        let wg_on_reflector = PortPlan::new(
            DEFAULT_REFLECTOR_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(listener(61000, 62999)),
            vec![],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(wg_on_reflector),
            PortConflict::Overlap {
                first: PortUse::WireGuard,
                second: PortUse::Reflector
            }
        );
        let wg_on_ssh = PortPlan::new(
            port(22),
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(listener(61000, 62999)),
            vec![],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(wg_on_ssh),
            PortConflict::Overlap {
                first: PortUse::Ssh,
                second: PortUse::WireGuard
            }
        );
        let reserved_overlaps_hop = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(listener(61000, 62999)),
            vec![range(62999, 64999)],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(reserved_overlaps_hop),
            PortConflict::Overlap {
                first: PortUse::Hy2Hop(ListenerIdx::FIRST),
                second: PortUse::Reserved(0)
            }
        );
        let second_listener_in_first_hop = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::from_parts(listener(61000, 62999), vec![listener(62000, 64999)]),
            vec![],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(second_listener_in_first_hop),
            PortConflict::Overlap {
                first: PortUse::Hy2Hop(ListenerIdx::FIRST),
                second: PortUse::Hy2Listener(ListenerIdx::new(1))
            }
        );
    }

    #[test]
    fn two_listeners_fit_when_the_reserved_range_is_used() {
        let plan = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::from_parts(listener(61000, 62999), vec![listener(63000, 64999)]),
            vec![],
            DEBIAN_EPHEMERAL_PORTS,
        )
        .unwrap();
        let indices: Vec<u8> = plan.hy2_listeners().map(|(index, _)| index.get()).collect();
        assert_eq!(indices, vec![0, 1]);
    }

    #[test]
    fn listener_and_range_counts_are_bounded() {
        let three = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::from_parts(
                listener(61000, 61999),
                vec![listener(62000, 62999), listener(63000, 63999)],
            ),
            vec![],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(three),
            PortConflict::TooManyHy2Listeners { max: 2 }
        );
        let reserved = PortPlan::new(
            DEFAULT_WG_PORT,
            DEFAULT_REFLECTOR_PORT,
            NonEmpty::new(listener(61000, 61999)),
            vec![
                range(62000, 62999),
                range(63000, 63999),
                range(64000, 64999),
            ],
            DEBIAN_EPHEMERAL_PORTS,
        );
        assert_eq!(
            conflict(reserved),
            PortConflict::TooManyReservedRanges { max: 2 }
        );
    }

    #[test]
    fn rebase_rechecks_against_the_live_range() {
        let plan = PortPlan::with_defaults(DEBIAN_EPHEMERAL_PORTS).unwrap();
        let wide = range(1024, 65535);
        assert_eq!(
            conflict(plan.rebase(wide)),
            PortConflict::InsideEphemeral {
                port_use: PortUse::XrayStats
            }
        );
        let narrow = range(40000, 50000);
        assert_eq!(plan.rebase(narrow).unwrap().ephemeral(), narrow);
    }

    #[test]
    fn hy2_listener_requires_contiguous_hop_range() {
        assert_eq!(
            Hy2Listener::new(
                port(61000),
                range(61002, 62999),
                DEFAULT_HOP_INTERVAL,
                Hy2Obfs::Salamander
            ),
            Err(ModelError::InvalidHy2Listener {
                port: port(61000),
                hop: range(61002, 62999)
            })
        );
        assert!(
            Hy2Listener::new(
                port(65535),
                range(65535, 65535),
                DEFAULT_HOP_INTERVAL,
                Hy2Obfs::Salamander
            )
            .is_err()
        );
    }

    #[test]
    fn serde_round_trip_and_rejection() {
        let plan = PortPlan::with_defaults(DEBIAN_EPHEMERAL_PORTS).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert_eq!(
            json,
            r#"{"wg":27820,"reflector":27900,"hy2":[{"port":61000,"hop":{"start":61001,"end":62999},"hop_interval":30,"obfs":"salamander"}],"reserved":[{"start":63000,"end":64999}],"ephemeral":{"start":32768,"end":60999}}"#
        );
        assert_eq!(serde_json::from_str::<PortPlan>(&json).unwrap(), plan);
        let inside = json.replace("\"wg\":27820", "\"wg\":47820");
        assert!(serde_json::from_str::<PortPlan>(&inside).is_err());
        let empty = json.replace(
            r#""hy2":[{"port":61000,"hop":{"start":61001,"end":62999},"hop_interval":30,"obfs":"salamander"}]"#,
            r#""hy2":[]"#,
        );
        assert!(serde_json::from_str::<PortPlan>(&empty).is_err());
        let unknown = json.replace("\"wg\":27820", "\"wg\":27820,\"extra\":1");
        assert!(serde_json::from_str::<PortPlan>(&unknown).is_err());
        assert!(serde_json::from_str::<PortRange>(r#"{"start":5,"end":4}"#).is_err());
        assert!(serde_json::from_str::<PortRange>(r#"{"start":0,"end":4}"#).is_err());
        assert!(serde_json::from_str::<Port>("0").is_err());
        assert!(serde_json::from_str::<HopInterval>("0").is_err());
        assert!(serde_json::from_str::<HopInterval>("4").is_err());
        assert_eq!(
            serde_json::from_str::<HopInterval>("5").unwrap().seconds(),
            5
        );
        assert!(serde_json::from_str::<HopInterval>("3601").is_err());
    }

    proptest! {
        #[test]
        fn port_rejects_only_zero(n in any::<u16>()) {
            prop_assert_eq!(Port::new(n).is_ok(), n != 0);
        }

        #[test]
        fn port_range_bounds(start in any::<u16>(), end in any::<u16>()) {
            match PortRange::new(start, end) {
                Ok(range) => {
                    prop_assert!(start >= 1 && start <= end);
                    prop_assert_eq!(range.port_count(), u32::from(end) - u32::from(start) + 1);
                    prop_assert!(range.contains(range.start()) && range.contains(range.end()));
                }
                Err(err) => {
                    prop_assert!(start == 0 || start > end);
                    prop_assert_eq!(err, ModelError::InvalidPortRange { start, end });
                }
            }
        }

        #[test]
        fn hop_interval_bounds(seconds in any::<u16>()) {
            prop_assert_eq!(HopInterval::from_seconds(seconds).is_ok(), (5..=3600).contains(&seconds));
        }

        #[test]
        fn overlap_is_symmetric_and_matches_brute_force(
            a in 1_u16..200, b in 1_u16..200, c in 1_u16..200, d in 1_u16..200,
        ) {
            let first = range(a.min(b), a.max(b));
            let second = range(c.min(d), c.max(d));
            let brute = (first.start().get()..=first.end().get())
                .any(|p| second.contains(port(p)));
            prop_assert_eq!(first.overlaps(second), brute);
            prop_assert_eq!(second.overlaps(first), brute);
        }

        #[test]
        fn accepted_plans_satisfy_every_invariant(
            wg in 1_u16..=65535,
            reflector in 1_u16..=65535,
            listen in 1_u16..65000,
            hop_len in 1_u16..500,
        ) {
            let hop_end = listen.saturating_add(hop_len);
            let Ok(hop) = PortRange::new(listen + 1, hop_end) else { return Ok(()) };
            let Ok(listener) = Hy2Listener::new(port(listen), hop, DEFAULT_HOP_INTERVAL, Hy2Obfs::Salamander) else {
                return Ok(());
            };
            if let Ok(plan) = PortPlan::new(port(wg), port(reflector), NonEmpty::new(listener), vec![], DEBIAN_EPHEMERAL_PORTS) {
                let fixed = [wg, reflector, listen, 22, 80, 443, 10085, 10443];
                for (i, a) in fixed.iter().enumerate() {
                    prop_assert!(!DEBIAN_EPHEMERAL_PORTS.contains(port(*a)));
                    prop_assert!(!hop.contains(port(*a)));
                    for b in &fixed[i + 1..] {
                        prop_assert_ne!(a, b);
                    }
                }
                prop_assert!(hop.start().get() > 60999);
                prop_assert_eq!(serde_json::from_str::<PortPlan>(&serde_json::to_string(&plan).unwrap()).unwrap(), plan);
            }
        }
    }
}
