// SPDX-License-Identifier: GPL-3.0-or-later

//! Users and their CFM client profiles (design §7, §9.1).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ids::{LocalLabel, NodeId, ShortId, UserId};

/// The CFM release line a user's client belongs to; it selects the export shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientLine {
    /// CFM 0.4 (sing-box 1.14.1).
    Cfm04,
    /// CFM 0.5 (sing-box 1.14.2).
    Cfm05,
}

/// An optional client capability that changes the export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Emit `support_x25519mlkem768` (sing-box) or `support-x25519mlkem768`
    /// (Clash); requires a CFM build whose importer accepts it.
    RealityMlkemOptIn,
}

impl ClientLine {
    /// Whether this line's importer accepts `capability`. `mooring-export`
    /// refuses an unsupported pair with `CapabilityUnsupported`.
    #[must_use]
    pub const fn accepts(self, capability: Capability) -> bool {
        match (self, capability) {
            (Self::Cfm04, Capability::RealityMlkemOptIn) => false,
            (Self::Cfm05, Capability::RealityMlkemOptIn) => true,
        }
    }
}

/// A user's client: its CFM line and opted-in capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProfile {
    /// The CFM line.
    pub line: ClientLine,
    /// The capabilities the user's build supports.
    pub capabilities: BTreeSet<Capability>,
}

/// A user's revocation state (design §13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    /// The user is served.
    Active,
    /// Being revoked: served nowhere, and `per_node` lists exactly the nodes
    /// that have not yet committed the removal (at least one). A node's
    /// entry and its credentials are removed once it commits; with none
    /// left the user is `Revoked`. The remaining set is never stored apart
    /// from `per_node`, so the two cannot disagree.
    RevokePending,
    /// Revoked on every node; the user holds no credentials.
    Revoked,
}

/// A user's public data on one node; the credentials are secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserNodePublic {
    /// The user's REALITY short id on the node.
    pub short_id: ShortId,
}

/// One user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// The opaque id; the only user identifier sent to a VPS.
    pub id: UserId,
    /// The Mac-only label; never exported or sent.
    pub label: LocalLabel,
    /// The user's client.
    pub client: ClientProfile,
    /// Revocation state.
    pub status: UserStatus,
    /// The nodes the user holds credentials on.
    pub per_node: BTreeMap<NodeId, UserNodePublic>,
}

impl User {
    /// Whether the user is served on `node`: active and holding credentials there.
    #[must_use]
    pub fn is_served_on(&self, node: &NodeId) -> bool {
        self.status == UserStatus::Active && self.per_node.contains_key(node)
    }

    /// The nodes that still have to commit this user's revocation, in id
    /// order: every node holding credentials while `RevokePending`, and none
    /// otherwise.
    pub fn revocation_remaining(&self) -> impl Iterator<Item = &NodeId> {
        let pending = self.status == UserStatus::RevokePending;
        self.per_node.keys().filter(move |_| pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_support_by_line() {
        assert!(!ClientLine::Cfm04.accepts(Capability::RealityMlkemOptIn));
        assert!(ClientLine::Cfm05.accepts(Capability::RealityMlkemOptIn));
    }

    #[test]
    fn status_serde_is_closed() {
        for (status, json) in [
            (UserStatus::Active, "\"active\""),
            (UserStatus::RevokePending, "\"revoke_pending\""),
            (UserStatus::Revoked, "\"revoked\""),
        ] {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(serde_json::from_str::<UserStatus>(json).unwrap(), status);
        }
        // The pre-structural form carried a separate `remaining` list.
        assert!(
            serde_json::from_str::<UserStatus>(r#"{"revoke_pending":{"remaining":["lon1"]}}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<UserStatus>("\"suspended\"").is_err());
        assert!(
            serde_json::from_str::<ClientProfile>(r#"{"line":"cfm06","capabilities":[]}"#).is_err()
        );
    }

    #[test]
    fn the_remaining_revocations_are_the_nodes_holding_credentials() {
        let short_id = UserNodePublic {
            short_id: ShortId::parse("5f1e000100000001").unwrap(),
        };
        let mut user = User {
            id: UserId::parse("abcdefghij").unwrap(),
            label: LocalLabel::parse("User").unwrap(),
            client: ClientProfile {
                line: ClientLine::Cfm05,
                capabilities: BTreeSet::new(),
            },
            status: UserStatus::Active,
            per_node: ["lon1", "ams1"]
                .into_iter()
                .map(|node| (NodeId::parse(node).unwrap(), short_id))
                .collect(),
        };
        assert_eq!(user.revocation_remaining().count(), 0);
        assert!(user.is_served_on(&NodeId::parse("lon1").unwrap()));
        user.status = UserStatus::RevokePending;
        let remaining: Vec<&str> = user.revocation_remaining().map(NodeId::as_str).collect();
        assert_eq!(remaining, ["ams1", "lon1"]);
        assert!(!user.is_served_on(&NodeId::parse("lon1").unwrap()));
    }
}
