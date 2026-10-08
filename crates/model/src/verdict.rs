// SPDX-License-Identifier: GPL-3.0-or-later

//! Egress verdicts (design §10.2): the precedence of the in-chain checks as
//! pure functions over observed addresses.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::exit::{EgressCheck, Pairing};
use crate::ids::NodeId;
use crate::kinds;
use crate::node::NodeAddress;

/// The two direct probes bracketing an in-chain probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bracket {
    /// The direct probe's egress IP immediately before the in-chain probe.
    pub d1: Ipv4Addr,
    /// The direct probe's egress IP immediately after the in-chain probe.
    pub d2: Ipv4Addr,
}

/// Whether this bracket is the first attempt or the single immediate re-run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BracketAttempt {
    /// The scheduled bracket.
    First,
    /// The one re-run after an inconclusive first bracket.
    Rerun,
}

/// The tunnel uplink's public address as the uplink probe observed it: none
/// when the uplink is the egress, the home IP in `Separate` mode.
///
/// Only `ResolvedInterfaces::uplink_address` builds one, from interfaces
/// resolved against the exit site, so the mode always matches the site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkAddress(Option<Ipv4Addr>);

impl UplinkAddress {
    /// The uplink is the egress; there is no separate address.
    pub(crate) const fn same_as_exit() -> Self {
        Self(None)
    }

    /// The `Separate` uplink's public address (the home IP).
    pub(crate) const fn separate(ip: Ipv4Addr) -> Self {
        Self(Some(ip))
    }

    /// The `Separate` uplink's public address, if the uplink is separate.
    #[must_use]
    pub const fn separate_ip(self) -> Option<Ipv4Addr> {
        self.0
    }
}

/// A violation: the engine is stopped and latched (design §10.2 steps 1-4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Violation {
    /// The egress IP is a node's address; that node is also sent `Shutdown`.
    EgressIsNodeAddress {
        /// The node whose address was observed.
        node: NodeId,
        /// The observed address.
        ip: Ipv4Addr,
    },
    /// The egress IP is outside every carrier prefix.
    OutsideCarrierPrefixes {
        /// The observed address.
        ip: Ipv4Addr,
    },
    /// The egress IP equals the `Separate` uplink's IP.
    EgressEqualsUplink {
        /// The observed address.
        ip: Ipv4Addr,
    },
    /// Paired mode: the egress IP differs from two equal bracketing probes.
    EgressMismatch {
        /// The direct probe before.
        d1: Ipv4Addr,
        /// The direct probe after.
        d2: Ipv4Addr,
        /// The in-chain observation.
        observed: Ipv4Addr,
    },
}

kinds! {
    /// The kind of a [`Violation`], without its details.
    pub enum ViolationKind {
        /// See [`Violation::EgressIsNodeAddress`].
        EgressIsNodeAddress,
        /// See [`Violation::OutsideCarrierPrefixes`].
        OutsideCarrierPrefixes,
        /// See [`Violation::EgressEqualsUplink`].
        EgressEqualsUplink,
        /// See [`Violation::EgressMismatch`].
        EgressMismatch,
    }
}

impl Violation {
    /// The kind of this violation.
    #[must_use]
    pub const fn kind(&self) -> ViolationKind {
        match self {
            Self::EgressIsNodeAddress { .. } => ViolationKind::EgressIsNodeAddress,
            Self::OutsideCarrierPrefixes { .. } => ViolationKind::OutsideCarrierPrefixes,
            Self::EgressEqualsUplink { .. } => ViolationKind::EgressEqualsUplink,
            Self::EgressMismatch { .. } => ViolationKind::EgressMismatch,
        }
    }

    /// The node to send `Shutdown` to, for `EgressIsNodeAddress`.
    #[must_use]
    pub const fn shutdown_node(&self) -> Option<&NodeId> {
        match self {
            Self::EgressIsNodeAddress { node, .. } => Some(node),
            Self::OutsideCarrierPrefixes { .. }
            | Self::EgressEqualsUplink { .. }
            | Self::EgressMismatch { .. } => None,
        }
    }
}

/// The outcome of one in-chain probe.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// The egress is verified.
    Verified {
        /// The verified egress IP.
        ip: Ipv4Addr,
    },
    /// A violation; stop the engine and latch.
    Violation(Violation),
    /// The first bracket was inconclusive (`d1 != d2`); re-run it once, immediately.
    RerunBracket,
    /// The re-run was inconclusive too: `NodeProbeFailed{stage: CarrierAddressUnstable}`,
    /// which degrades the node but is not a violation.
    CarrierAddressUnstable {
        /// The re-run's brackets.
        bracket: Bracket,
        /// The re-run's in-chain observation.
        observed: Ipv4Addr,
    },
}

/// Everything an in-chain verdict depends on.
#[derive(Debug, Clone, Copy)]
pub struct InChainInputs<'a> {
    /// The egress IP the reflector saw through the chain.
    pub observed: Ipv4Addr,
    /// The bracketing direct probes.
    pub bracket: Bracket,
    /// The address of every node whose VM still exists.
    pub nodes: &'a BTreeMap<NodeId, NodeAddress>,
    /// The carrier prefixes and pairing mode.
    pub egress_check: &'a EgressCheck,
    /// The uplink address.
    pub uplink: UplinkAddress,
    /// Which attempt this bracket is.
    pub attempt: BracketAttempt,
}

fn node_owning(nodes: &BTreeMap<NodeId, NodeAddress>, ip: Ipv4Addr) -> Option<&NodeId> {
    nodes
        .iter()
        .find(|(_, address)| address.ipv4() == ip)
        .map(|(node, _)| node)
}

/// Checks applied to every direct probe and at preflight, in precedence
/// order: a node address first, then the carrier prefixes.
pub fn direct_verdict(
    observed: Ipv4Addr,
    nodes: &BTreeMap<NodeId, NodeAddress>,
    egress_check: &EgressCheck,
) -> Result<(), Violation> {
    if let Some(node) = node_owning(nodes, observed) {
        return Err(Violation::EgressIsNodeAddress {
            node: node.clone(),
            ip: observed,
        });
    }
    if !egress_check.in_carrier(observed) {
        return Err(Violation::OutsideCarrierPrefixes { ip: observed });
    }
    Ok(())
}

/// The in-chain verdict for `inputs.observed`, applying design §10.2 in order:
/// node address, carrier prefixes, `Separate` uplink address, then the
/// `Paired` bracket with its single immediate re-run.
#[must_use]
pub fn in_chain_verdict(inputs: &InChainInputs<'_>) -> Verdict {
    let x = inputs.observed;
    if let Err(violation) = direct_verdict(x, inputs.nodes, inputs.egress_check) {
        return Verdict::Violation(violation);
    }
    if inputs.uplink.separate_ip() == Some(x) {
        return Verdict::Violation(Violation::EgressEqualsUplink { ip: x });
    }
    let Bracket { d1, d2 } = inputs.bracket;
    match inputs.egress_check.pairing {
        Pairing::Paired if x != d1 && x != d2 => {
            if d1 == d2 {
                Verdict::Violation(Violation::EgressMismatch {
                    d1,
                    d2,
                    observed: x,
                })
            } else {
                match inputs.attempt {
                    BracketAttempt::First => Verdict::RerunBracket,
                    BracketAttempt::Rerun => Verdict::CarrierAddressUnstable {
                        bracket: inputs.bracket,
                        observed: x,
                    },
                }
            }
        }
        Pairing::Paired | Pairing::Unpaired => Verdict::Verified { ip: x },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::NonEmpty;
    use crate::ipv4::{CarrierPrefix, PublicIpv4};
    use proptest::prelude::*;

    const CARRIER_A: Ipv4Addr = Ipv4Addr::new(31, 120, 0, 7);
    const CARRIER_B: Ipv4Addr = Ipv4Addr::new(31, 120, 0, 8);
    const CARRIER_C: Ipv4Addr = Ipv4Addr::new(31, 121, 4, 9);
    const OUTSIDE: Ipv4Addr = Ipv4Addr::new(81, 2, 3, 4);
    const LON1: Ipv4Addr = Ipv4Addr::new(45, 67, 89, 10);

    fn nodes() -> BTreeMap<NodeId, NodeAddress> {
        BTreeMap::from([(
            NodeId::parse("lon1").unwrap(),
            NodeAddress::Public(PublicIpv4::new(LON1).unwrap()),
        )])
    }

    fn check(pairing: Pairing) -> EgressCheck {
        EgressCheck {
            carrier_prefixes: NonEmpty::new(
                CarrierPrefix::new("31.120.0.0/14".parse().unwrap()).unwrap(),
            ),
            pairing,
        }
    }

    fn verdict(
        observed: Ipv4Addr,
        d1: Ipv4Addr,
        d2: Ipv4Addr,
        pairing: Pairing,
        uplink: UplinkAddress,
        attempt: BracketAttempt,
    ) -> Verdict {
        let nodes = nodes();
        let egress_check = check(pairing);
        in_chain_verdict(&InChainInputs {
            observed,
            bracket: Bracket { d1, d2 },
            nodes: &nodes,
            egress_check: &egress_check,
            uplink,
            attempt,
        })
    }

    #[test]
    fn precedence_table() {
        use BracketAttempt::{First, Rerun};
        use Pairing::{Paired, Unpaired};
        let lon1 = NodeId::parse("lon1").unwrap();
        let same = UplinkAddress::same_as_exit();
        let home_is = UplinkAddress::separate;
        let rows: Vec<(
            Ipv4Addr,
            Ipv4Addr,
            Ipv4Addr,
            Pairing,
            UplinkAddress,
            BracketAttempt,
            Verdict,
        )> = vec![
            // 1. A node address wins over everything, even when it would also
            // fail the carrier check, equal the uplink and mismatch the bracket.
            (
                LON1,
                CARRIER_A,
                CARRIER_A,
                Paired,
                home_is(LON1),
                First,
                Verdict::Violation(Violation::EgressIsNodeAddress {
                    node: lon1.clone(),
                    ip: LON1,
                }),
            ),
            // 2. Outside the carrier prefixes wins over uplink equality and the bracket.
            (
                OUTSIDE,
                CARRIER_A,
                CARRIER_A,
                Paired,
                home_is(OUTSIDE),
                First,
                Verdict::Violation(Violation::OutsideCarrierPrefixes { ip: OUTSIDE }),
            ),
            (
                OUTSIDE,
                OUTSIDE,
                OUTSIDE,
                Unpaired,
                same,
                First,
                Verdict::Violation(Violation::OutsideCarrierPrefixes { ip: OUTSIDE }),
            ),
            // 3. Equal to the Separate uplink wins over the bracket.
            (
                CARRIER_C,
                CARRIER_A,
                CARRIER_A,
                Paired,
                home_is(CARRIER_C),
                First,
                Verdict::Violation(Violation::EgressEqualsUplink { ip: CARRIER_C }),
            ),
            (
                CARRIER_A,
                CARRIER_A,
                CARRIER_A,
                Unpaired,
                home_is(CARRIER_A),
                Rerun,
                Verdict::Violation(Violation::EgressEqualsUplink { ip: CARRIER_A }),
            ),
            // 4a. Paired, outside an agreeing bracket: mismatch on either attempt.
            (
                CARRIER_C,
                CARRIER_A,
                CARRIER_A,
                Paired,
                same,
                First,
                Verdict::Violation(Violation::EgressMismatch {
                    d1: CARRIER_A,
                    d2: CARRIER_A,
                    observed: CARRIER_C,
                }),
            ),
            (
                CARRIER_C,
                CARRIER_A,
                CARRIER_A,
                Paired,
                home_is(OUTSIDE),
                Rerun,
                Verdict::Violation(Violation::EgressMismatch {
                    d1: CARRIER_A,
                    d2: CARRIER_A,
                    observed: CARRIER_C,
                }),
            ),
            // 4b. Paired, outside a disagreeing bracket: rerun once, then unstable.
            (
                CARRIER_C,
                CARRIER_A,
                CARRIER_B,
                Paired,
                same,
                First,
                Verdict::RerunBracket,
            ),
            (
                CARRIER_C,
                CARRIER_A,
                CARRIER_B,
                Paired,
                same,
                Rerun,
                Verdict::CarrierAddressUnstable {
                    bracket: Bracket {
                        d1: CARRIER_A,
                        d2: CARRIER_B,
                    },
                    observed: CARRIER_C,
                },
            ),
            // 5. Verified: matches either bracket probe, or Unpaired.
            (
                CARRIER_A,
                CARRIER_A,
                CARRIER_B,
                Paired,
                same,
                First,
                Verdict::Verified { ip: CARRIER_A },
            ),
            (
                CARRIER_B,
                CARRIER_A,
                CARRIER_B,
                Paired,
                same,
                Rerun,
                Verdict::Verified { ip: CARRIER_B },
            ),
            (
                CARRIER_A,
                CARRIER_A,
                CARRIER_A,
                Paired,
                home_is(OUTSIDE),
                First,
                Verdict::Verified { ip: CARRIER_A },
            ),
            (
                CARRIER_C,
                CARRIER_A,
                CARRIER_A,
                Unpaired,
                same,
                First,
                Verdict::Verified { ip: CARRIER_C },
            ),
            (
                CARRIER_C,
                CARRIER_A,
                CARRIER_B,
                Unpaired,
                same,
                First,
                Verdict::Verified { ip: CARRIER_C },
            ),
        ];
        for (observed, d1, d2, pairing, uplink, attempt, expected) in rows {
            assert_eq!(
                verdict(observed, d1, d2, pairing, uplink, attempt),
                expected,
                "x={observed} d1={d1} d2={d2} {pairing:?} {uplink:?} {attempt:?}"
            );
        }
    }

    #[test]
    fn direct_verdict_precedence() {
        let nodes = nodes();
        let egress = check(Pairing::Paired);
        assert_eq!(direct_verdict(CARRIER_A, &nodes, &egress), Ok(()));
        let node_violation = direct_verdict(LON1, &nodes, &egress).unwrap_err();
        assert_eq!(node_violation.kind(), ViolationKind::EgressIsNodeAddress);
        assert_eq!(
            node_violation.shutdown_node().map(NodeId::as_str),
            Some("lon1")
        );
        let outside = direct_verdict(OUTSIDE, &nodes, &egress).unwrap_err();
        assert_eq!(outside, Violation::OutsideCarrierPrefixes { ip: OUTSIDE });
        assert_eq!(outside.shutdown_node(), None);
    }

    #[test]
    fn every_violation_kind_is_reachable() {
        let reached: Vec<ViolationKind> = [
            verdict(
                LON1,
                LON1,
                LON1,
                Pairing::Paired,
                UplinkAddress::same_as_exit(),
                BracketAttempt::First,
            ),
            verdict(
                OUTSIDE,
                CARRIER_A,
                CARRIER_A,
                Pairing::Paired,
                UplinkAddress::same_as_exit(),
                BracketAttempt::First,
            ),
            verdict(
                CARRIER_A,
                CARRIER_A,
                CARRIER_A,
                Pairing::Paired,
                UplinkAddress::separate(CARRIER_A),
                BracketAttempt::First,
            ),
            verdict(
                CARRIER_C,
                CARRIER_A,
                CARRIER_A,
                Pairing::Paired,
                UplinkAddress::same_as_exit(),
                BracketAttempt::First,
            ),
        ]
        .into_iter()
        .map(|verdict| match verdict {
            Verdict::Violation(violation) => violation.kind(),
            other => panic!("expected a violation, got {other:?}"),
        })
        .collect();
        let named = [
            ViolationKind::EgressIsNodeAddress,
            ViolationKind::OutsideCarrierPrefixes,
            ViolationKind::EgressEqualsUplink,
            ViolationKind::EgressMismatch,
        ];
        assert_eq!(reached, named);
        assert_eq!(named.as_slice(), ViolationKind::ALL, "every kind, in order");
    }

    /// A pool small enough that every branch is drawn often.
    fn address() -> impl Strategy<Value = Ipv4Addr> {
        proptest::sample::select(vec![CARRIER_A, CARRIER_B, CARRIER_C, OUTSIDE, LON1])
    }

    proptest! {
        #[test]
        fn verdicts_respect_the_precedence(
            x in address(),
            d1 in address(),
            d2 in address(),
            paired in any::<bool>(),
            separate in proptest::option::of(address()),
            rerun in any::<bool>(),
        ) {
            let pairing = if paired { Pairing::Paired } else { Pairing::Unpaired };
            let uplink = separate.map_or(UplinkAddress::same_as_exit(), UplinkAddress::separate);
            let attempt = if rerun { BracketAttempt::Rerun } else { BracketAttempt::First };
            let in_carrier = check(pairing).in_carrier(x);
            let outcome = verdict(x, d1, d2, pairing, uplink, attempt);
            let expected = if x == LON1 {
                Verdict::Violation(Violation::EgressIsNodeAddress { node: NodeId::parse("lon1").unwrap(), ip: x })
            } else if !in_carrier {
                Verdict::Violation(Violation::OutsideCarrierPrefixes { ip: x })
            } else if uplink == UplinkAddress::separate(x) {
                Verdict::Violation(Violation::EgressEqualsUplink { ip: x })
            } else if paired && x != d1 && x != d2 {
                if d1 == d2 {
                    Verdict::Violation(Violation::EgressMismatch { d1, d2, observed: x })
                } else if rerun {
                    Verdict::CarrierAddressUnstable { bracket: Bracket { d1, d2 }, observed: x }
                } else {
                    Verdict::RerunBracket
                }
            } else {
                Verdict::Verified { ip: x }
            };
            prop_assert_eq!(outcome, expected);
        }
    }
}
