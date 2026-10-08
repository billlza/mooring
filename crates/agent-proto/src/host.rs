// SPDX-License-Identifier: GPL-3.0-or-later

//! [`HostFacts`]: what the agent measures about its VPS, reported by every
//! `Hello` and checked before every transaction.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{AgentError, IfName, KernelIdent, KernelRelease, PortRange};

closed_enum! {
    /// A VPS CPU architecture; it selects the agent and engine builds.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Arch {
        /// x86-64 (`x86_64-unknown-linux-musl`).
        Amd64,
        /// AArch64 (`aarch64-unknown-linux-musl`).
        Arm64,
    }
}

/// Facts about a VPS that its rendered configuration depends on. `Hello`
/// reports them. At adoption the Mac records the uplink, the architecture
/// and the port range in the node's site, and checks that `vps4` is the
/// address it adopted; the other facts are asserted, not recorded. Every
/// [`crate::BundleHeader`] carries the recorded facts and, for the rest, the
/// values of the `Hello` just before it; the agent refuses a bundle whose
/// facts differ from the live ones (§11.2 step 1).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFacts {
    /// The interface that holds the default route.
    pub uplink: IfName,
    /// The single IPv4 address configured on the uplink: the node's public
    /// address. The Mac checks that it equals the address it dialled, which
    /// proves VPS4 is on the uplink.
    pub vps4: Ipv4Addr,
    /// The CPU architecture.
    pub arch: Arch,
    /// `net.ipv4.ip_local_port_range`.
    pub ip_local_port_range: PortRange,
    /// The Debian major release (`VERSION_ID` in `/etc/os-release`).
    pub debian_major: u16,
    /// `uname -r`.
    pub kernel: KernelRelease,
    /// `net.ipv4.tcp_congestion_control`.
    pub congestion_control: KernelIdent,
    /// `net.core.default_qdisc`.
    pub qdisc: KernelIdent,
}

closed_enum! {
    /// One field of [`HostFacts`], in field order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum HostFact {
        /// [`HostFacts::uplink`].
        Uplink,
        /// [`HostFacts::vps4`].
        Vps4,
        /// [`HostFacts::arch`].
        Arch,
        /// [`HostFacts::ip_local_port_range`].
        IpLocalPortRange,
        /// [`HostFacts::debian_major`].
        DebianMajor,
        /// [`HostFacts::kernel`].
        Kernel,
        /// [`HostFacts::congestion_control`].
        CongestionControl,
        /// [`HostFacts::qdisc`].
        Qdisc,
    }
}

impl HostFacts {
    /// The facts that differ between `self` and `other`, in
    /// [`HostFact::ALL`] order. The destructuring names every field, so a
    /// new fact cannot be added without being compared.
    pub fn differences(&self, other: &Self) -> Vec<HostFact> {
        let Self {
            uplink,
            vps4,
            arch,
            ip_local_port_range,
            debian_major,
            kernel,
            congestion_control,
            qdisc,
        } = self;
        [
            (HostFact::Uplink, *uplink == other.uplink),
            (HostFact::Vps4, *vps4 == other.vps4),
            (HostFact::Arch, *arch == other.arch),
            (
                HostFact::IpLocalPortRange,
                *ip_local_port_range == other.ip_local_port_range,
            ),
            (HostFact::DebianMajor, *debian_major == other.debian_major),
            (HostFact::Kernel, *kernel == other.kernel),
            (
                HostFact::CongestionControl,
                *congestion_control == other.congestion_control,
            ),
            (HostFact::Qdisc, *qdisc == other.qdisc),
        ]
        .into_iter()
        .filter_map(|(fact, same)| (!same).then_some(fact))
        .collect()
    }

    /// The transaction precondition of §11.2 step 1: `self` holds the
    /// recorded facts from the bundle header and `live` the node's current
    /// facts. The first difference decides the error: a changed
    /// `ip_local_port_range` is [`AgentError::PortPlanConflict`], because
    /// the bundle's port plan was checked against the recorded range; any
    /// other field is [`AgentError::HostFactsChanged`].
    pub fn check_live(&self, live: &Self) -> Result<(), AgentError> {
        match self.differences(live).first() {
            None => Ok(()),
            Some(HostFact::IpLocalPortRange) => Err(AgentError::PortPlanConflict {
                recorded: self.ip_local_port_range,
                live: live.ip_local_port_range,
            }),
            Some(field) => Err(AgentError::HostFactsChanged { field: *field }),
        }
    }
}

closed_enum! {
    /// `net.ipv4.conf.<interface>.accept_local` of [`crate::WG_INTERFACE`], as
    /// `Hello` reports it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum AcceptLocal {
        /// `wgexit` does not exist (for example before the first `Apply`).
        NoInterface,
        /// The value is 0.
        Disabled,
        /// The value is 1, which the in-chain probe requires (§8.4).
        Enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> HostFacts {
        HostFacts {
            uplink: IfName::new("eth0").unwrap(),
            vps4: Ipv4Addr::new(203, 0, 113, 10),
            arch: Arch::Amd64,
            ip_local_port_range: PortRange::new(32768, 60999).unwrap(),
            debian_major: 13,
            kernel: KernelRelease::new("6.12.48+deb13-amd64").unwrap(),
            congestion_control: KernelIdent::new("bbr").unwrap(),
            qdisc: KernelIdent::new("fq").unwrap(),
        }
    }

    /// One variation of `facts()` per field, labelled with that field.
    fn variations() -> Vec<(HostFact, HostFacts)> {
        let base = facts();
        let mut out = Vec::new();
        for fact in HostFact::ALL {
            let mut changed = base.clone();
            match fact {
                HostFact::Uplink => changed.uplink = IfName::new("ens3").unwrap(),
                HostFact::Vps4 => changed.vps4 = Ipv4Addr::new(203, 0, 113, 11),
                HostFact::Arch => changed.arch = Arch::Arm64,
                HostFact::IpLocalPortRange => {
                    changed.ip_local_port_range = PortRange::new(1024, 65535).unwrap()
                }
                HostFact::DebianMajor => changed.debian_major = 12,
                HostFact::Kernel => changed.kernel = KernelRelease::new("6.1.0-25-amd64").unwrap(),
                HostFact::CongestionControl => {
                    changed.congestion_control = KernelIdent::new("cubic").unwrap()
                }
                HostFact::Qdisc => changed.qdisc = KernelIdent::new("fq_codel").unwrap(),
            }
            out.push((*fact, changed));
        }
        out
    }

    #[test]
    fn identical_facts_pass() {
        assert_eq!(facts().differences(&facts()), Vec::new());
        assert_eq!(facts().check_live(&facts()), Ok(()));
    }

    #[test]
    fn every_field_is_compared() {
        for (fact, changed) in variations() {
            assert_eq!(facts().differences(&changed), vec![fact]);
        }
    }

    #[test]
    fn a_changed_fact_is_reported_by_field_and_the_port_range_as_a_plan_conflict() {
        for (fact, changed) in variations() {
            let expected = if fact == HostFact::IpLocalPortRange {
                AgentError::PortPlanConflict {
                    recorded: facts().ip_local_port_range,
                    live: changed.ip_local_port_range,
                }
            } else {
                AgentError::HostFactsChanged { field: fact }
            };
            assert_eq!(facts().check_live(&changed), Err(expected));
        }
    }

    #[test]
    fn the_first_difference_in_field_order_decides() {
        let mut changed = facts();
        changed.qdisc = KernelIdent::new("fq_codel").unwrap();
        changed.ip_local_port_range = PortRange::new(1024, 65535).unwrap();
        changed.uplink = IfName::new("ens3").unwrap();
        assert_eq!(
            facts().differences(&changed),
            vec![
                HostFact::Uplink,
                HostFact::IpLocalPortRange,
                HostFact::Qdisc
            ]
        );
        assert_eq!(
            facts().check_live(&changed),
            Err(AgentError::HostFactsChanged {
                field: HostFact::Uplink
            })
        );
    }

    #[test]
    fn host_facts_reject_unknown_fields() {
        let mut value = serde_json::to_value(facts()).unwrap();
        assert_eq!(
            serde_json::from_value::<HostFacts>(value.clone()).unwrap(),
            facts()
        );
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<HostFacts>(value).is_err());
    }
}
