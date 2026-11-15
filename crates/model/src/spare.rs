// SPDX-License-Identifier: GPL-3.0-or-later

//! Spare users (design §13.6): user ids drawn ahead of need, each with its
//! credentials on the nodes, so that adding a user changes nothing an
//! engine reads only at its start.
//!
//! A node's REALITY short ids and its sing-box users, loopback outbounds
//! and `auth_user` rules are read only when its engines start; Xray's
//! clients can be added to the running engine. Every spare is therefore
//! rendered on each node it holds credentials on, as a suspended user is,
//! and served nowhere: no Xray client admits it, and nobody holds its
//! credentials. `user add` takes a spare, so the user it adds keeps the
//! spare's id and credentials, the nodes' start-time files stay byte for
//! byte the same, and the node adds the user's two clients to the running
//! Xray. The nightly apply job draws new spares inside its window, where a
//! restart is expected.
//!
//! A spare's credentials are kept under the user id it will have
//! (`SecretRef::UserVlessUuid` and the like), so taking one moves no
//! secret.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{NodeId, UserId};
use crate::user::UserNodePublic;

/// How many spare users the nightly apply job keeps ready: the users that
/// can be added in one day without restarting a node's engines. A spare
/// costs a short id, a sing-box user, an outbound and a route rule on each
/// node, and three keychain items per node.
pub const SPARE_USERS: usize = 3;

/// A user id drawn ahead of need, with its credentials on the nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpareUser {
    /// The id the user that takes this spare will have.
    pub id: UserId,
    /// The nodes it holds credentials on.
    pub per_node: BTreeMap<NodeId, UserNodePublic>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::{Bookkeeping, Deployment, DeploymentParts};
    use crate::error::{EntityId, ModelError};
    use crate::node::NodeLifecycle;
    use crate::removal::ForgottenUser;
    use crate::secret::SecretRef;
    use crate::testing::{node_id, site, spare, two_node_parts, user, user_id};
    use crate::time::UnixTime;
    use crate::user::{SuspendReason, UserStatus};

    const AT: UnixTime = UnixTime::from_secs(1_794_441_600);

    /// `two_node_parts` with spare users 7 and 8 on both nodes.
    fn with_spares() -> DeploymentParts {
        let mut parts = two_node_parts();
        parts.spares = vec![
            spare(8, &[("lon1", 8), ("ams1", 8)]),
            spare(7, &[("lon1", 7), ("ams1", 7)]),
        ];
        parts
    }

    fn build(parts: DeploymentParts) -> Result<Deployment, ModelError> {
        Deployment::try_from(parts)
    }

    /// Spares are kept by id, round-trip, and their credentials are
    /// required under the user ids they will have.
    #[test]
    fn spares_round_trip_and_their_credentials_are_required() {
        let deployment = build(with_spares()).unwrap();
        let ids: Vec<UserId> = deployment.spares().keys().cloned().collect();
        assert_eq!(ids, [user_id(7), user_id(8)]);
        let json = serde_json::to_string(&deployment).unwrap();
        assert!(json.contains(r#""spares":[{"id":"#), "{json}");
        assert_eq!(
            serde_json::from_str::<Deployment>(&json).unwrap(),
            deployment
        );
        assert_eq!(build(deployment.clone().into_parts()).unwrap(), deployment);
        let without = build(two_node_parts()).unwrap().required_secrets();
        let added: Vec<SecretRef> = deployment
            .required_secrets()
            .difference(&without)
            .cloned()
            .collect();
        let mut expected = Vec::new();
        for n in [7, 8] {
            for node in ["ams1", "lon1"] {
                expected.push(SecretRef::UserVlessUuid(user_id(n), node_id(node)));
                expected.push(SecretRef::UserHy2Password(user_id(n), node_id(node)));
                expected.push(SecretRef::UserLoopUuid(user_id(n), node_id(node)));
            }
        }
        expected.sort();
        assert_eq!(added, expected);
    }

    /// A spare's id is a user's to come: it may be no user's, no kept
    /// removed id, and no other spare's.
    #[test]
    fn a_spare_id_is_no_user_s_no_kept_id_and_unique() {
        let duplicate = |n| {
            Err(ModelError::DuplicateId {
                id: EntityId::User(user_id(n)),
            })
        };
        let mut parts = with_spares();
        parts.spares.push(spare(1, &[]));
        assert_eq!(build(parts), duplicate(1));
        let mut parts = with_spares();
        parts.spares.push(spare(7, &[]));
        assert_eq!(build(parts), duplicate(7));
        let mut parts = with_spares();
        parts.forgotten.push(ForgottenUser {
            user: user_id(8),
            until: AT,
        });
        assert_eq!(build(parts), duplicate(8));
        // A spare holding no credentials is valid; it is drawn where none
        // is active, and the nightly job gives it some.
        let mut parts = with_spares();
        parts.spares.push(spare(9, &[]));
        assert!(build(parts).is_ok());
    }

    /// A spare's short id is unique on its node: not the probe's, not a
    /// user's, not another spare's.
    #[test]
    fn a_spare_short_id_is_unique_on_its_node() {
        let lon1 = || {
            Err(ModelError::DuplicateShortId {
                node: node_id("lon1"),
            })
        };
        let mut parts = with_spares();
        parts.spares.push(spare(9, &[("lon1", 1)]));
        assert_eq!(build(parts), lon1(), "a user's");
        let mut parts = with_spares();
        parts.spares.push(spare(9, &[("lon1", 7)]));
        assert_eq!(build(parts), lon1(), "another spare's");
        let mut parts = with_spares();
        assert_eq!(parts.nodes[0].id, node_id("lon1"));
        let probe = parts.nodes[0].reality.probe_short_id;
        parts.spares[0]
            .per_node
            .get_mut(&node_id("lon1"))
            .unwrap()
            .short_id = probe;
        assert_eq!(
            build(parts),
            Err(ModelError::DuplicateShortId {
                node: node_id("lon1")
            }),
            "the probe's"
        );
        // The same short id on another node is fine.
        let mut parts = with_spares();
        parts.spares.push(spare(9, &[("lon1", 9)]));
        parts.users.push(user(10, &[("ams1", 9)]));
        assert!(build(parts).is_ok());
    }

    /// A spare holds credentials only on known, active nodes.
    #[test]
    fn a_spare_holds_credentials_only_on_active_nodes() {
        let mut parts = with_spares();
        parts.spares.push(spare(9, &[("par1", 9)]));
        assert_eq!(
            build(parts),
            Err(ModelError::UnknownNode {
                id: node_id("par1")
            })
        );
        let mut parts = with_spares();
        for user in &mut parts.users {
            user.per_node.remove(&node_id("ams1"));
        }
        parts.nodes[1].lifecycle = NodeLifecycle::Retired;
        assert_eq!(
            build(parts),
            Err(ModelError::CredentialsOnInactiveNode {
                user: user_id(7),
                node: node_id("ams1")
            })
        );
    }

    /// A node that renders nothing any more takes the spares' credentials
    /// on it with it, as it takes the users'.
    #[test]
    fn a_released_node_drops_the_spares_credentials() {
        let held = |deployment: &Deployment| -> Vec<Vec<String>> {
            deployment
                .spares()
                .values()
                .map(|spare| spare.per_node.keys().map(ToString::to_string).collect())
                .collect()
        };
        let mut parts = with_spares();
        parts.nodes[0].lifecycle = NodeLifecycle::Retiring {
            site: site([45, 67, 89, 10]),
        };
        let retired = build(parts)
            .unwrap()
            .record(Bookkeeping::RetirementShutDown {
                node: node_id("lon1"),
                at: AT,
            })
            .unwrap();
        assert_eq!(held(&retired), [["ams1"], ["ams1"]]);
        let mut parts = with_spares();
        parts.nodes[0].lifecycle = NodeLifecycle::Planned;
        parts.nodes[0].reality.target = None;
        let cancelled = build(parts)
            .unwrap()
            .record(Bookkeeping::PlanCancelled {
                node: node_id("lon1"),
                at: AT,
            })
            .unwrap();
        assert_eq!(held(&cancelled), [["ams1"], ["ams1"]]);
        assert!(
            cancelled
                .required_secrets()
                .iter()
                .all(|secret_ref| secret_ref.node().map(NodeId::as_str) != Some("lon1"))
        );
    }

    /// `take_spare` removes the spare it names and returns it whole.
    #[test]
    fn taking_a_spare_removes_and_returns_it() {
        let mut parts = with_spares();
        let taken = parts.take_spare(&user_id(7)).unwrap();
        assert_eq!(taken, spare(7, &[("lon1", 7), ("ams1", 7)]));
        let left: Vec<UserId> = parts.spares.iter().map(|spare| spare.id.clone()).collect();
        assert_eq!(left, [user_id(8)]);
        assert_eq!(
            parts.take_spare(&user_id(7)),
            Err(ModelError::UnknownSpare { id: user_id(7) })
        );
        assert_eq!(
            ModelError::UnknownSpare { id: user_id(7) }.kind(),
            crate::error::ModelErrorKind::UnknownSpare
        );
    }

    /// The nodes keep an active or suspended user's credentials in the
    /// files their engines read at start, and serve only the active one;
    /// a user being revoked or revoked is kept nowhere.
    #[test]
    fn only_active_and_suspended_users_are_kept_on_their_nodes() {
        let lon1 = node_id("lon1");
        let mut held = user(1, &[("lon1", 1)]);
        let mut not_held = user(2, &[]);
        for (status, kept, served) in [
            (UserStatus::Active, true, true),
            (
                UserStatus::Suspended {
                    reason: SuspendReason::Expired,
                    since: AT,
                },
                true,
                false,
            ),
            (UserStatus::RevokePending, false, false),
            (UserStatus::Revoked { since: AT }, false, false),
        ] {
            held.status = status;
            not_held.status = status;
            assert_eq!(held.is_kept_on(&lon1), kept, "{status:?}");
            assert_eq!(held.is_served_on(&lon1), served, "{status:?}");
            assert!(!not_held.is_kept_on(&lon1), "{status:?}");
            assert!(!held.is_kept_on(&node_id("ams1")), "{status:?}");
        }
    }
}
