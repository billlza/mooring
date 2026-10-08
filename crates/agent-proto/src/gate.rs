// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit gate, its holds and the halt marker (design §11.3).
//!
//! The agent and `ExecStopPost` may only close the gate; only the watch
//! opens it. Nothing in this protocol can ask for the gate to open.

use serde::{Deserialize, Serialize};

use crate::macros::closed_enum;
use crate::{Generation, UnixTime};

closed_enum! {
    /// Why the Mac closes a node's gate with `GateSet` (which only ever
    /// closes it).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum GateReason {
        /// The Mac is about to sleep and has stopped its exit engine.
        MacDrain,
        /// The Mac found an egress violation.
        EgressViolation,
        /// The operator closed the gate.
        Operator,
    }
}

closed_enum! {
    /// A hold that `ClearHold` may clear. `MacDrain` is absent on purpose:
    /// it clears itself when a new handshake completes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum ClearableHold {
        /// [`Holds::egress_violation`], cleared by the Mac's Retry.
        EgressViolation,
        /// [`Holds::operator`].
        Operator,
    }
}

closed_enum! {
    /// Whether `wgexit` is in the `exit_closed` set.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum GateState {
        /// Exit traffic may leave through `wgexit`.
        Open,
        /// Exit traffic is rejected.
        Closed,
    }
}

/// A sleep-drain hold. It clears when WireGuard's latest handshake differs
/// from the value recorded here and rx has grown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacDrainHold {
    /// `latest-handshake` of the Mac's peer when the drain arrived; `None`
    /// when no handshake had completed.
    #[serde(deserialize_with = "Option::deserialize")]
    pub handshake_at_drain: Option<UnixTime>,
}

/// An egress-violation hold, cleared only by
/// `ClearHold{EgressViolation}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressViolationHold {
    /// When the agent recorded the hold.
    pub at: UnixTime,
    /// The node's generation at that time.
    pub generation: Generation,
}

/// An operator hold, cleared only by `ClearHold{Operator}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorHold {
    /// When the agent recorded the hold.
    pub at: UnixTime,
}

/// The holds on a node's gate, at most one of each kind
/// (`/var/lib/mooring/gate/holds.json`). The gate stays closed while any is
/// present.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holds {
    /// The sleep-drain hold.
    #[serde(deserialize_with = "Option::deserialize")]
    pub mac_drain: Option<MacDrainHold>,
    /// The egress-violation hold.
    #[serde(deserialize_with = "Option::deserialize")]
    pub egress_violation: Option<EgressViolationHold>,
    /// The operator hold.
    #[serde(deserialize_with = "Option::deserialize")]
    pub operator: Option<OperatorHold>,
}

impl Holds {
    /// No holds.
    pub const NONE: Self = Self {
        mac_drain: None,
        egress_violation: None,
        operator: None,
    };

    /// Whether no hold is present.
    pub const fn is_empty(&self) -> bool {
        self.mac_drain.is_none() && self.egress_violation.is_none() && self.operator.is_none()
    }
}

closed_enum! {
    /// Why a node is halted with `Shutdown`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum ShutdownReason {
        /// An in-chain probe saw a node address as the egress
        /// (`EgressIsNodeAddress`).
        EgressIsNodeAddress,
        /// The operator halted the node.
        Operator,
        /// The node is being retired.
        Retire,
    }
}

/// The halt marker (`/var/lib/mooring/halted.json`). While present, both
/// engines stay stopped, `Apply` fails with `NodeHalted`, and only
/// `Resume` removes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Halt {
    /// When the node was halted.
    pub at: UnixTime,
    /// Why.
    pub reason: ShutdownReason,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_spell_out_absent_holds_and_require_them() {
        assert!(Holds::NONE.is_empty());
        assert_eq!(Holds::default(), Holds::NONE);
        let json = serde_json::to_string(&Holds::NONE).unwrap();
        assert_eq!(
            json,
            r#"{"mac_drain":null,"egress_violation":null,"operator":null}"#
        );
        assert!(
            serde_json::from_str::<Holds>(r#"{"mac_drain":null,"egress_violation":null}"#).is_err()
        );

        let held = Holds {
            operator: Some(OperatorHold {
                at: UnixTime::from_secs(5),
            }),
            ..Holds::NONE
        };
        assert!(!held.is_empty());
        assert_eq!(
            serde_json::from_str::<Holds>(&serde_json::to_string(&held).unwrap()).unwrap(),
            held
        );
    }

    #[test]
    fn a_drain_without_a_handshake_is_explicit() {
        let json = serde_json::to_string(&MacDrainHold {
            handshake_at_drain: None,
        })
        .unwrap();
        assert_eq!(json, r#"{"handshake_at_drain":null}"#);
        assert!(serde_json::from_str::<MacDrainHold>("{}").is_err());
    }
}
