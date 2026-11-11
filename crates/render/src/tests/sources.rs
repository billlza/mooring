// SPDX-License-Identifier: GPL-3.0-or-later

//! The users' source addresses inside a node (design §11.8): one per served
//! user, a pure function of the user id, never shared on one node.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_agent_proto::{OpaqueUserId, is_user_source, user_source};
use mooring_model::ids::UserId;

use crate::error::{RenderError, RenderErrorKind};
use crate::tests::support::{fixtures, node};
use crate::vps::served::{Identity, served, user_exits};

fn source_of(user: &UserId) -> Ipv4Addr {
    user_source(&OpaqueUserId::new(user.as_str()).unwrap())
}

/// The first two user ids, in the order `UserId::from_low_bits` draws them,
/// whose source addresses are the same.
fn colliding_pair() -> (UserId, UserId) {
    let mut seen: BTreeMap<Ipv4Addr, UserId> = BTreeMap::new();
    for bits in 0..1_000_000_u64 {
        let user = UserId::from_low_bits(bits);
        if let Some(first) = seen.insert(source_of(&user), user.clone()) {
            return (first, user);
        }
    }
    panic!("no two of a million ids share an address");
}

/// Every fixture node's served users get their own address, in served order,
/// and the probe none: it leaves from the tunnel's own address.
#[test]
fn each_served_user_has_its_own_source_and_the_probe_none() {
    for fixture in fixtures() {
        for (id, node) in fixture.deployment.nodes() {
            let served = served(&fixture.deployment, node, &fixture.secrets).unwrap();
            let exits = user_exits(id, &served).unwrap();
            let users: Vec<&UserId> = served
                .iter()
                .filter_map(|served| match &served.identity {
                    Identity::User(user) => Some(user),
                    Identity::Probe => None,
                })
                .collect();
            assert_eq!(exits.len(), users.len());
            for (exit, user) in exits.iter().zip(&users) {
                assert_eq!(exit.source.address(), source_of(user));
                assert!(is_user_source(exit.source.address()));
                assert_eq!(
                    exit.emails.clone().map(|email| email.to_string()),
                    [format!("{user}@reality"), format!("{user}@hy2")]
                );
            }
        }
    }
}

/// Two served users with the same address are refused, naming the node and
/// both users in served order; with either one alone the node renders.
#[test]
fn two_users_sharing_an_address_on_a_node_are_refused() {
    let (first, second) = colliding_pair();
    assert_ne!(first, second);
    assert_eq!(source_of(&first), source_of(&second));
    let fixture = mooring_fixtures::one_node_one_user().unwrap();
    let lon1 = node("lon1");
    let mut served = served(
        &fixture.deployment,
        fixture.deployment.node(&lon1).unwrap(),
        &fixture.secrets,
    )
    .unwrap();
    let template = served[0].clone();
    assert!(matches!(template.identity, Identity::User(_)));
    served.clear();
    for user in [&first, &second] {
        let mut entry = template.clone();
        entry.identity = Identity::User(user.clone());
        served.push(entry);
    }
    let error = user_exits(&lon1, &served).unwrap_err();
    assert_eq!(error.kind(), RenderErrorKind::UserSourceCollision);
    let RenderError::UserSourceCollision {
        node: found,
        first: earlier,
        second: later,
    } = &error
    else {
        unreachable!()
    };
    assert_eq!((found, earlier, later), (&lon1, &first, &second));
    assert_eq!(
        error.to_string(),
        format!("{first} and {second} have the same source address on node lon1")
    );
    for alone in [&served[..1], &served[1..]] {
        assert_eq!(user_exits(&lon1, alone).unwrap().len(), 1);
    }
}
