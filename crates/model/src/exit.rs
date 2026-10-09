// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac exit site and the deployment-wide policies (design §7).

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::collections::NonEmpty;
use crate::deployment::MAX_ACTIVE_NODES;
use crate::error::ModelError;
use crate::iface::{
    InterfaceSelector, ResolvedInterface, ResolvedInterfaces, ResolvedUplink, UplinkMode,
};
use crate::ipv4::CarrierPrefix;
use crate::ports::Port;
use crate::sim::SimPolicy;
use crate::time::UnixTime;

/// Whether in-chain probes are bracketed by direct probes (design §10.2);
/// fixed from the M2 pooling measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pairing {
    /// The in-chain egress IP must equal a bracketing direct probe's IP.
    Paired,
    /// Only the carrier-prefix check applies.
    Unpaired,
}

/// The mandatory carrier check: every observed egress IP must lie in one of
/// the carrier's public pool prefixes recorded in M2.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressCheck {
    /// The carrier's public pool prefixes (RIPE inetnum evidence), never ASN-wide.
    pub carrier_prefixes: NonEmpty<CarrierPrefix>,
    /// The bracketing mode.
    pub pairing: Pairing,
}

impl EgressCheck {
    /// Whether `addr` lies inside a carrier prefix.
    #[must_use]
    pub fn in_carrier(&self, addr: Ipv4Addr) -> bool {
        self.carrier_prefixes
            .iter()
            .any(|prefix| prefix.contains(addr))
    }
}

/// The tunnel uplink; Mooring never switches between modes on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Uplink {
    /// The tunnel leaves through the egress interface (the M7). The default.
    SameAsExit,
    /// The tunnel leaves through a different interface, chosen explicitly.
    Separate(InterfaceSelector),
}

impl Uplink {
    /// The mode, without the selector.
    #[must_use]
    pub const fn mode(&self) -> UplinkMode {
        match self {
            Self::SameAsExit => UplinkMode::SameAsExit,
            Self::Separate(_) => UplinkMode::Separate,
        }
    }
}

/// A probe interval, 1..=86400 seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ProbeInterval(u32);

impl ProbeInterval {
    /// Accepts 1..=86400 seconds.
    pub fn from_seconds(seconds: u32) -> Result<Self, ModelError> {
        if (1..=86_400).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(ModelError::InvalidProbeInterval { seconds })
        }
    }

    /// The interval in seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ProbeInterval {
    type Error = ModelError;

    fn try_from(seconds: u32) -> Result<Self, Self::Error> {
        Self::from_seconds(seconds)
    }
}

impl From<ProbeInterval> for u32 {
    fn from(interval: ProbeInterval) -> Self {
        interval.0
    }
}

/// The protocol an in-chain probe exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeProtocol {
    /// VLESS + REALITY + Vision.
    Reality,
    /// Hysteria2.
    Hy2,
}

impl ProbeProtocol {
    /// Both protocols, in port order.
    pub const ALL: [Self; 2] = [Self::Reality, Self::Hy2];

    const fn offset(self) -> u16 {
        match self {
            Self::Reality => 0,
            Self::Hy2 => 1,
        }
    }
}

/// The first port of the macOS ephemeral range (49152-65535).
pub const MACOS_EPHEMERAL_START: u16 = 49152;
/// Loopback probe ports needed per node: one per protocol.
pub const PROBE_PORTS_PER_NODE: u16 = 2;
/// Loopback probe ports needed for the most nodes v1 supports.
pub const PROBE_PORT_SPAN: u16 = PROBE_PORTS_PER_NODE * MAX_ACTIVE_NODES as u16;

// `MAX_ACTIVE_NODES as u16` above is lossless only while the constant is small.
const _: () = assert!(MAX_ACTIVE_NODES <= 16);

/// The first Mac loopback port of the in-chain probe inbounds.
///
/// Invariant: every probe port (`MAX_ACTIVE_NODES` nodes × 2 protocols)
/// lies in 1024..49152, below the macOS ephemeral range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct ProbeBasePort(u16);

impl ProbeBasePort {
    /// The design default, 47101.
    pub const DEFAULT: Self = Self(47101);

    /// Accepts a base port that leaves every probe port in 1024..49152.
    pub fn new(port: u16) -> Result<Self, ModelError> {
        let last = u32::from(port) + u32::from(PROBE_PORT_SPAN) - 1;
        if port >= 1024 && last < u32::from(MACOS_EPHEMERAL_START) {
            Ok(Self(port))
        } else {
            Err(ModelError::InvalidProbeBasePort { port })
        }
    }

    /// The base port.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for ProbeBasePort {
    type Error = ModelError;

    fn try_from(port: u16) -> Result<Self, Self::Error> {
        Self::new(port)
    }
}

impl From<ProbeBasePort> for u16 {
    fn from(port: ProbeBasePort) -> Self {
        port.0
    }
}

/// Probe cadence and the Mac loopback ports of the probe inbounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbePolicy {
    /// The interval between direct probes (default 30 s).
    pub direct_every: ProbeInterval,
    /// The interval between in-chain probes (default 300 s).
    pub in_chain_every: ProbeInterval,
    /// The first loopback probe port (default 47101).
    pub base_port: ProbeBasePort,
}

impl ProbePolicy {
    /// The loopback port for node slot `slot` (0-based, at most
    /// `MAX_ACTIVE_NODES - 1`) and `protocol`: `base + 2 × slot + protocol`.
    pub fn port_for(&self, slot: usize, protocol: ProbeProtocol) -> Result<Port, ModelError> {
        let port = (0..PROBE_PORT_SPAN)
            .step_by(usize::from(PROBE_PORTS_PER_NODE))
            .nth(slot)
            .map(|slot_offset| self.base_port.0 + slot_offset + protocol.offset())
            .ok_or(ModelError::TooManyNodes {
                max: MAX_ACTIVE_NODES,
            })?;
        // The base port invariant keeps `port` in 1024..49152, so it is non-zero.
        Port::new(port)
    }
}

impl Default for ProbePolicy {
    fn default() -> Self {
        Self {
            direct_every: ProbeInterval(30),
            in_chain_every: ProbeInterval(300),
            base_port: ProbeBasePort::DEFAULT,
        }
    }
}

/// The node-wide cap on new flows into `wgexit`, 1..=65535; sized from the
/// M2 CGNAT port-ceiling estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct FlowCap(u32);

impl FlowCap {
    /// Accepts 1..=65535.
    pub fn new(value: u32) -> Result<Self, ModelError> {
        if (1..=65_535).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidFlowCap { value })
        }
    }

    /// The cap.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for FlowCap {
    type Error = ModelError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FlowCap> for u32 {
    fn from(cap: FlowCap) -> Self {
        cap.0
    }
}

/// Destination policy switches; every one is on by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficPolicy {
    /// Deny `geoip:cn` and `geosite:cn` destinations.
    pub deny_cn: bool,
    /// Deny UDP/443 to destinations, so browsers fall back to TCP.
    pub block_quic: bool,
    /// Deny TCP/25.
    pub deny_smtp25: bool,
    /// Deny sniffed BitTorrent.
    pub deny_bittorrent: bool,
    /// Forward TCP/80 and UDP/443 on the VPS address to the REALITY target.
    pub camo_forward: bool,
}

impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            deny_cn: true,
            block_quic: true,
            deny_smtp25: true,
            deny_bittorrent: true,
            camo_forward: true,
        }
    }
}

/// The tunnel uplink's measured capacity (`fieldkit uplink`, design §22
/// M2): the 10th and 50th percentiles of the upload rate over the
/// measurement, against which the console reports uplink use.
///
/// Invariant: `0 < p10_bps <= p50_bps`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "UplinkBaselineRepr", into = "UplinkBaselineRepr")]
pub struct UplinkBaseline {
    p10_bps: u64,
    p50_bps: u64,
    measured_at: UnixTime,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UplinkBaselineRepr {
    p10_bps: u64,
    p50_bps: u64,
    measured_at: UnixTime,
}

impl UplinkBaseline {
    /// Accepts positive percentiles with `p10_bps <= p50_bps`.
    pub fn new(p10_bps: u64, p50_bps: u64, measured_at: UnixTime) -> Result<Self, ModelError> {
        if p10_bps == 0 || p10_bps > p50_bps {
            return Err(ModelError::InvalidUplinkBaseline { p10_bps, p50_bps });
        }
        Ok(Self {
            p10_bps,
            p50_bps,
            measured_at,
        })
    }

    /// The 10th percentile of the upload rate, in bit/s.
    #[must_use]
    pub const fn p10_bps(&self) -> u64 {
        self.p10_bps
    }

    /// The median upload rate, in bit/s.
    #[must_use]
    pub const fn p50_bps(&self) -> u64 {
        self.p50_bps
    }

    /// When the measurement ended.
    #[must_use]
    pub const fn measured_at(&self) -> UnixTime {
        self.measured_at
    }
}

impl TryFrom<UplinkBaselineRepr> for UplinkBaseline {
    type Error = ModelError;

    fn try_from(repr: UplinkBaselineRepr) -> Result<Self, Self::Error> {
        Self::new(repr.p10_bps, repr.p50_bps, repr.measured_at)
    }
}

impl From<UplinkBaseline> for UplinkBaselineRepr {
    fn from(baseline: UplinkBaseline) -> Self {
        Self {
            p10_bps: baseline.p10_bps,
            p50_bps: baseline.p50_bps,
            measured_at: baseline.measured_at,
        }
    }
}

/// The Mac side of the exit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitSite {
    /// The wired interface facing the M7.
    pub egress: InterfaceSelector,
    /// The tunnel uplink.
    pub uplink: Uplink,
    /// The carrier check; changed only by explicit operator action.
    pub egress_check: EgressCheck,
    /// SIM accounting: the bill day, the plan and the thresholds.
    pub sim: SimPolicy,
    /// Probe cadence and ports.
    pub probe: ProbePolicy,
    /// The node-wide new-flow cap.
    pub flow_cap: FlowCap,
    /// The uplink's measured capacity, once measured. The key is required.
    #[serde(deserialize_with = "Option::deserialize")]
    pub uplink_baseline: Option<UplinkBaseline>,
}

impl ExitSite {
    /// Checks interfaces the Mac resolved against this site and returns
    /// them as the [`ResolvedInterfaces`] every Mac render takes: the egress
    /// (and a separate uplink) must be selected by their selectors
    /// (`InterfaceNotSelected`), the uplink mode must be the configured one
    /// (`UplinkModeMismatch`; Mooring never switches modes, design §0), and a
    /// separate uplink must be another interface (`UplinkEqualsEgress`).
    pub fn resolve(
        &self,
        egress: ResolvedInterface,
        uplink: ResolvedUplink,
    ) -> Result<ResolvedInterfaces, ModelError> {
        ResolvedInterfaces::resolve(self.egress, self.uplink, egress, uplink)
    }

    /// Requires `interfaces` to have been resolved for this site's current
    /// egress selector and uplink configuration, so a render never binds a
    /// socket to an interface another configuration chose (for example a
    /// home uplink for a `SameAsExit` site, which would reveal the home
    /// address to the VPS, design §1.2).
    pub fn require_resolved(&self, interfaces: &ResolvedInterfaces) -> Result<(), ModelError> {
        if interfaces.resolved_for(&self.egress, &self.uplink) {
            Ok(())
        } else {
            Err(ModelError::InterfacesForOtherSite)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn uplink_baselines_are_ordered_and_positive() {
        let at = UnixTime::from_secs(1_791_417_600);
        let baseline = UplinkBaseline::new(5_000_000, 16_000_000, at).unwrap();
        assert_eq!(
            (
                baseline.p10_bps(),
                baseline.p50_bps(),
                baseline.measured_at()
            ),
            (5_000_000, 16_000_000, at)
        );
        assert!(UplinkBaseline::new(1, 1, at).is_ok());
        for (p10, p50) in [(0, 0), (0, 5), (6, 5)] {
            assert_eq!(
                UplinkBaseline::new(p10, p50, at),
                Err(ModelError::InvalidUplinkBaseline {
                    p10_bps: p10,
                    p50_bps: p50
                })
            );
        }
        let json = serde_json::to_string(&baseline).unwrap();
        assert_eq!(
            json,
            r#"{"p10_bps":5000000,"p50_bps":16000000,"measured_at":1791417600}"#
        );
        assert_eq!(
            serde_json::from_str::<UplinkBaseline>(&json).unwrap(),
            baseline
        );
        for bad in [
            json.replace("5000000,", "17000000,"),
            json.replace("5000000,", "0,"),
            json.replace(r#","measured_at":1791417600"#, ""),
            json.replace("1791417600", "1791417600,\"p90_bps\":1"),
        ] {
            assert!(
                serde_json::from_str::<UplinkBaseline>(&bad).is_err(),
                "{bad}"
            );
        }
        // The site's key is required even when there is no baseline yet.
        let site = serde_json::to_value(crate::testing::exit_site()).unwrap();
        assert_eq!(site["uplink_baseline"], serde_json::Value::Null);
        let mut missing = site;
        missing.as_object_mut().unwrap().remove("uplink_baseline");
        assert!(serde_json::from_value::<ExitSite>(missing).is_err());
    }

    #[test]
    fn probe_ports_follow_the_design_layout() {
        let policy = ProbePolicy::default();
        assert_eq!(policy.direct_every.seconds(), 30);
        assert_eq!(policy.in_chain_every.seconds(), 300);
        let ports: Vec<u16> = (0..MAX_ACTIVE_NODES)
            .flat_map(|slot| {
                ProbeProtocol::ALL.map(|protocol| policy.port_for(slot, protocol).unwrap().get())
            })
            .collect();
        assert_eq!(ports, vec![47101, 47102, 47103, 47104]);
        assert_eq!(
            policy.port_for(MAX_ACTIVE_NODES, ProbeProtocol::Reality),
            Err(ModelError::TooManyNodes {
                max: MAX_ACTIVE_NODES
            })
        );
    }

    #[test]
    fn probe_base_port_bounds() {
        assert!(ProbeBasePort::new(1024).is_ok());
        assert!(ProbeBasePort::new(49148).is_ok());
        for bad in [0, 1023, 49149, 49152, 65535] {
            assert_eq!(
                ProbeBasePort::new(bad),
                Err(ModelError::InvalidProbeBasePort { port: bad })
            );
        }
        assert_eq!(
            ProbeInterval::from_seconds(0),
            Err(ModelError::InvalidProbeInterval { seconds: 0 })
        );
        assert!(ProbeInterval::from_seconds(86_400).is_ok());
        assert!(ProbeInterval::from_seconds(86_401).is_err());
    }

    #[test]
    fn flow_cap_bounds() {
        assert_eq!(
            FlowCap::new(0),
            Err(ModelError::InvalidFlowCap { value: 0 })
        );
        assert_eq!(
            FlowCap::new(65_536),
            Err(ModelError::InvalidFlowCap { value: 65_536 })
        );
        assert_eq!(FlowCap::new(65_535).unwrap().get(), 65_535);
    }

    #[test]
    fn egress_check_and_policy_serde() {
        let check: EgressCheck =
            serde_json::from_str(r#"{"carrier_prefixes":["31.120.0.0/14"],"pairing":"paired"}"#)
                .unwrap();
        assert!(check.in_carrier(Ipv4Addr::new(31, 123, 255, 255)));
        assert!(!check.in_carrier(Ipv4Addr::new(31, 124, 0, 0)));
        assert!(
            serde_json::from_str::<EgressCheck>(r#"{"carrier_prefixes":[],"pairing":"paired"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<EgressCheck>(
                r#"{"carrier_prefixes":["31.120.0.0/14"],"pairing":"sometimes"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<EgressCheck>(
                r#"{"carrier_prefixes":["100.64.0.0/10"],"pairing":"paired"}"#
            )
            .is_err()
        );
        let policy = TrafficPolicy::default();
        assert!(
            policy.deny_cn
                && policy.block_quic
                && policy.deny_smtp25
                && policy.deny_bittorrent
                && policy.camo_forward
        );
        assert!(serde_json::from_str::<TrafficPolicy>(
            r#"{"deny_cn":true,"block_quic":true,"deny_smtp25":true,"deny_bittorrent":true,"camo_forward":true,"log":true}"#
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn probe_ports_stay_below_the_macos_ephemeral_range(base in 1024_u16..49149) {
            let policy = ProbePolicy { base_port: ProbeBasePort::new(base).unwrap(), ..ProbePolicy::default() };
            for slot in 0..MAX_ACTIVE_NODES {
                for protocol in ProbeProtocol::ALL {
                    let port = policy.port_for(slot, protocol).unwrap().get();
                    prop_assert!((1024..MACOS_EPHEMERAL_START).contains(&port));
                }
            }
        }
    }
}
