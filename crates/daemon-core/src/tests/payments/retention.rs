// SPDX-License-Identifier: GPL-3.0-or-later

//! The ledger's retention (design §9.6; the agreement's clause 4): the
//! payment records of a user go with the user, 13 months after the
//! revocation or at once on the user's request. Orders of an id the
//! deployment never held stay, for the operator to settle at Stripe.

use mooring_model::{Bookkeeping, Deployment, UnixTime, User, UserStatus};

use super::{NOW, Terms, id, live, order, secs, user};
use crate::payments::{PaymentLedger, Pruned};

/// The fixture deployment holding `users`.
fn holding(users: Vec<User>) -> Deployment {
    super::super::support::edited(|parts| parts.users = users)
}

/// A ledger for users a (active), b (revoked) and c (active): a month and
/// a pack granted to a, a month to b held as revoked, a month to c, and a
/// month for an id the deployment never held.
fn ledger(deployment: &Deployment) -> PaymentLedger {
    PaymentLedger::new()
        .apply(
            &live(
                0,
                vec![
                    Terms::month("aaaaaaaaaaaaaaaaaaaa", "pilotusera").grant(1),
                    Terms::pack("bbbbbbbbbbbbbbbbbbbb", "pilotusera").grant(2),
                    Terms::month("cccccccccccccccccccc", "pilotuserb").grant(3),
                    Terms::month("dddddddddddddddddddd", "pilotuserc").grant(4),
                    Terms::month("eeeeeeeeeeeeeeeeeeee", "strangerxx").grant(5),
                ],
            ),
            deployment.users(),
            NOW,
            false,
        )
        .unwrap()
        .ledger
}

fn revoked(text: &str) -> User {
    user(
        text,
        UserStatus::Revoked {
            since: secs(NOW.as_secs() - 86_400),
        },
        None,
    )
}

fn users() -> Vec<User> {
    vec![
        user("pilotusera", UserStatus::Active, None),
        revoked("pilotuserb"),
        user("pilotuserc", UserStatus::Active, None),
    ]
}

fn orders(ledger: &PaymentLedger) -> Vec<String> {
    ledger.orders().keys().map(ToString::to_string).collect()
}

/// While every user is held, the revoked one too, nothing goes.
#[test]
fn nothing_goes_while_the_deployment_holds_every_user() {
    let deployment = holding(users());
    let ledger = ledger(&deployment);
    assert_eq!(ledger.orders().len(), 5);
    assert_eq!(ledger.without_removed_users(&deployment), None);
}

/// A user removed at its request, whose bare id the deployment keeps: every
/// order naming it goes, granted, held or known from a refund alone; the
/// cursor and the last pull stay.
#[test]
fn a_forgotten_users_every_order_goes() {
    let deployment = holding(users());
    let ledger = ledger(&deployment);
    let refunded = ledger
        .apply(
            &live(
                5,
                vec![Terms::month("ffffffffffffffffffff", "pilotuserb").refund(6, 800, true)],
            ),
            deployment.users(),
            NOW,
            false,
        )
        .unwrap()
        .ledger;
    let removed = deployment
        .record(Bookkeeping::RevokedUserRemoved {
            user: id("pilotuserb"),
            at: NOW,
        })
        .unwrap();
    assert!(removed.forgotten().contains_key(&id("pilotuserb")));
    let (pruned, counts) = refunded.without_removed_users(&removed).unwrap();
    assert_eq!(
        orders(&pruned),
        [
            "aaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbb",
            "dddddddddddddddddddd",
            "eeeeeeeeeeeeeeeeeeee"
        ]
    );
    assert_eq!(
        counts,
        Pruned {
            users: 1,
            orders: 2
        }
    );
    assert_eq!(pruned.cursor(), refunded.cursor());
    assert_eq!(pruned.pulled_at(), refunded.pulled_at());
    assert_eq!(pruned.stopped(), refunded.stopped());
    assert!(
        !String::from_utf8(pruned.encode().unwrap())
            .unwrap()
            .contains("pilotuserb")
    );
    // Applying it again finds nothing more.
    assert_eq!(pruned.without_removed_users(&removed), None);
}

/// A user removed 13 months on keeps no id: the orders the ledger granted
/// it, or held while it was revoked, go; an order for an id the deployment
/// never held stays, and so does an order known only from a refund, whose
/// user cannot be told apart from such an id.
#[test]
fn a_removed_users_granted_and_held_orders_go_and_strangers_orders_stay() {
    let deployment = holding(users());
    let ledger = ledger(&deployment)
        .apply(
            &live(
                5,
                vec![Terms::month("ffffffffffffffffffff", "pilotuserb").refund(6, 800, true)],
            ),
            deployment.users(),
            NOW,
            false,
        )
        .unwrap()
        .ledger;
    let late = UnixTime::from_secs(NOW.as_secs() + 400 * 86_400);
    let removed = deployment
        .record(Bookkeeping::RevokedUserRemoved {
            user: id("pilotuserb"),
            at: late,
        })
        .unwrap();
    assert!(removed.forgotten().is_empty());
    let (pruned, counts) = ledger.without_removed_users(&removed).unwrap();
    assert_eq!(
        orders(&pruned),
        [
            "aaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbb",
            "dddddddddddddddddddd",
            "eeeeeeeeeeeeeeeeeeee",
            "ffffffffffffffffffff"
        ]
    );
    assert_eq!(
        counts,
        Pruned {
            users: 1,
            orders: 1
        }
    );
    assert!(pruned.orders().contains_key(&order("eeeeeeeeeeeeeeeeeeee")));
}
