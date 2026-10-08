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

/// The SIM billing cycle start day, 1..=28 so that it exists in every month.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct CycleDay(u8);

impl CycleDay {
    /// Accepts 1..=28.
    pub fn new(day: u8) -> Result<Self, ModelError> {
        if (1..=28).contains(&day) {
            Ok(Self(day))
        } else {
            Err(ModelError::InvalidCycleDay { day })
        }
    }

    /// The day of the month.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for CycleDay {
    type Error = ModelError;

    fn try_from(day: u8) -> Result<Self, Self::Error> {
        Self::new(day)
    }
}

impl From<CycleDay> for u8 {
    fn from(day: CycleDay) -> Self {
        day.0
    }
}

/// The design default SIM warning threshold, 450 GB.
pub const DEFAULT_SIM_WARN_BYTES: u64 = 450_000_000_000;
/// The design default SIM hard stop, 560 GB.
pub const DEFAULT_SIM_HARD_STOP_BYTES: u64 = 560_000_000_000;

/// SIM volume accounting.
///
/// Invariant: `warn_bytes > 0` and, with a hard stop, `warn_bytes < hard_stop_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "SimPolicyRepr", into = "SimPolicyRepr")]
pub struct SimPolicy {
    cycle_day: CycleDay,
    warn_bytes: u64,
    hard_stop_bytes: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SimPolicyRepr {
    cycle_day: CycleDay,
    warn_bytes: u64,
    // Required even when null: a lost key must not silently disable the hard stop.
    #[serde(deserialize_with = "Option::deserialize")]
    hard_stop_bytes: Option<u64>,
}

impl SimPolicy {
    /// Accepts positive thresholds with the warning below any hard stop.
    pub fn new(
        cycle_day: CycleDay,
        warn_bytes: u64,
        hard_stop_bytes: Option<u64>,
    ) -> Result<Self, ModelError> {
        let ordered = hard_stop_bytes.is_none_or(|stop| warn_bytes < stop);
        if warn_bytes == 0 || !ordered {
            return Err(ModelError::InvalidSimThresholds {
                warn_bytes,
                hard_stop_bytes,
            });
        }
        Ok(Self {
            cycle_day,
            warn_bytes,
            hard_stop_bytes,
        })
    }

    /// The design defaults (450 GB warning, 560 GB hard stop) for `cycle_day`.
    #[must_use]
    pub const fn with_defaults(cycle_day: CycleDay) -> Self {
        Self {
            cycle_day,
            warn_bytes: DEFAULT_SIM_WARN_BYTES,
            hard_stop_bytes: Some(DEFAULT_SIM_HARD_STOP_BYTES),
        }
    }

    /// The billing cycle start day.
    #[must_use]
    pub const fn cycle_day(&self) -> CycleDay {
        self.cycle_day
    }

    /// The usage at which the operator is warned.
    #[must_use]
    pub const fn warn_bytes(&self) -> u64 {
        self.warn_bytes
    }

    /// The usage at which the exit stops until the cycle resets, if any.
    #[must_use]
    pub const fn hard_stop_bytes(&self) -> Option<u64> {
        self.hard_stop_bytes
    }
}

impl TryFrom<SimPolicyRepr> for SimPolicy {
    type Error = ModelError;

    fn try_from(repr: SimPolicyRepr) -> Result<Self, Self::Error> {
        Self::new(repr.cycle_day, repr.warn_bytes, repr.hard_stop_bytes)
    }
}

impl From<SimPolicy> for SimPolicyRepr {
    fn from(policy: SimPolicy) -> Self {
        Self {
            cycle_day: policy.cycle_day,
            warn_bytes: policy.warn_bytes,
            hard_stop_bytes: policy.hard_stop_bytes,
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
    /// SIM accounting.
    pub sim: SimPolicy,
    /// Probe cadence and ports.
    pub probe: ProbePolicy,
    /// The node-wide new-flow cap.
    pub flow_cap: FlowCap,
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
    fn sim_policy_thresholds() {
        let day = CycleDay::new(1).unwrap();
        let defaults = SimPolicy::with_defaults(day);
        assert_eq!(
            SimPolicy::new(
                day,
                DEFAULT_SIM_WARN_BYTES,
                Some(DEFAULT_SIM_HARD_STOP_BYTES)
            ),
            Ok(defaults)
        );
        assert!(SimPolicy::new(day, 1, None).is_ok());
        for (warn, stop) in [(0, None), (0, Some(5)), (5, Some(5)), (6, Some(5))] {
            assert_eq!(
                SimPolicy::new(day, warn, stop),
                Err(ModelError::InvalidSimThresholds {
                    warn_bytes: warn,
                    hard_stop_bytes: stop
                })
            );
        }
        for bad in [0, 29, 31] {
            assert_eq!(
                CycleDay::new(bad),
                Err(ModelError::InvalidCycleDay { day: bad })
            );
        }
        let json = serde_json::to_string(&defaults).unwrap();
        assert_eq!(
            json,
            r#"{"cycle_day":1,"warn_bytes":450000000000,"hard_stop_bytes":560000000000}"#
        );
        assert!(serde_json::from_str::<SimPolicy>(&json.replace("560000000000", "1")).is_err());
    }

    #[test]
    fn a_missing_hard_stop_key_is_a_decode_error_not_no_hard_stop() {
        let no_stop: SimPolicy = serde_json::from_str(
            r#"{"cycle_day":1,"warn_bytes":450000000000,"hard_stop_bytes":null}"#,
        )
        .unwrap();
        assert_eq!(no_stop.hard_stop_bytes(), None);
        let error =
            serde_json::from_str::<SimPolicy>(r#"{"cycle_day":1,"warn_bytes":450000000000}"#)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing field `hard_stop_bytes`"),
            "{error}"
        );
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

        #[test]
        fn cycle_day_bounds(day in any::<u8>()) {
            prop_assert_eq!(CycleDay::new(day).is_ok(), (1..=28).contains(&day));
        }
    }
}
