// SPDX-License-Identifier: GPL-3.0-or-later

//! Payments (design §9.6): the portal's document and its goldens, the
//! payment ledger and its rules, what paid orders give users, the pull's
//! settings, the check against Stripe, and the plans on the Mac.
//!
//! The goldens in `contract/portal-fixtures/entitlements-v1/` are copies of
//! the portal repository's `contract/fixtures/entitlements-v1/` at its
//! commit 8b7c170, synthetic data only.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use mooring_model::{
    ClientLine, ClientProfile, LocalLabel, NodeId, UnixTime, User, UserId, UserPolicy, UserStatus,
};
use serde_json::{Value, json};

use crate::payments::{FeedError, FeedPage, OrderId, RefundUsage, RunBegan};
use crate::usage::{DownlinkCount, ServedBefore};

mod check;
mod feed;
mod ledger;
mod open_downloads;
mod plans;
mod policy;
mod refunds;
mod retention;
mod settings;
mod stripe;

/// The contract's `pilot.json`: six entries of all three kinds, in
/// Stripe's test mode.
pub(super) const PILOT: &str =
    include_str!("../../../../../contract/portal-fixtures/entitlements-v1/pilot.json");

/// The contract's `empty.json`: the answer after entry 6 when there is no
/// newer entry, in live mode.
pub(super) const EMPTY: &str =
    include_str!("../../../../../contract/portal-fixtures/entitlements-v1/empty.json");

/// A day, in seconds.
pub(super) const DAY: u64 = 86_400;

/// The time the tests apply pages at: just after `pilot.json` was made.
pub(super) const NOW: UnixTime = UnixTime::from_secs(1_797_000_100);

pub(super) fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

/// What the usage collected and the nodes' statuses tell in a test, of
/// whichever user is asked about, and how often each was asked.
#[derive(Default)]
pub(in crate::tests) struct Told {
    /// The use before any instant; `None`: the usage cannot tell.
    pub(in crate::tests) served: Option<ServedBefore>,
    /// The REALITY downlink of the cycle on every node; `None`: the usage
    /// cannot tell.
    pub(in crate::tests) downlink: Option<BTreeMap<NodeId, DownlinkCount>>,
    /// When each node's run of Xray began; a node left out shows none.
    pub(in crate::tests) began: BTreeMap<NodeId, RunBegan>,
    /// How often the use was asked for.
    pub(in crate::tests) asked_served: Cell<u32>,
    /// The users whose downlink was asked for, in order.
    pub(in crate::tests) asked_downlink: RefCell<Vec<UserId>>,
}

impl RefundUsage for Told {
    fn served_before(&self, _: &UserId, _: UnixTime) -> Option<ServedBefore> {
        self.asked_served.set(self.asked_served.get() + 1);
        self.served.clone()
    }

    fn reality_downlink(&self, user: &UserId) -> Option<BTreeMap<NodeId, DownlinkCount>> {
        self.asked_downlink.borrow_mut().push(user.clone());
        self.downlink.clone()
    }

    fn xray_began(&self, node: &NodeId) -> Option<RunBegan> {
        self.began.get(node).copied()
    }
}

/// The usage that tells only the bytes a user had served before an
/// instant: no node's REALITY downlink, and no status.
pub(in crate::tests) struct Serving<'a>(
    pub(in crate::tests) &'a dyn Fn(&UserId, UnixTime) -> Option<u64>,
);

impl RefundUsage for Serving<'_> {
    fn served_before(&self, user: &UserId, at: UnixTime) -> Option<ServedBefore> {
        (self.0)(user, at).map(|bytes| ServedBefore {
            bytes,
            reality_downlink: BTreeMap::new(),
        })
    }

    fn reality_downlink(&self, _: &UserId) -> Option<BTreeMap<NodeId, DownlinkCount>> {
        None
    }

    fn xray_began(&self, _: &NodeId) -> Option<RunBegan> {
        None
    }
}

pub(super) fn order(text: &str) -> OrderId {
    OrderId::parse(text).unwrap()
}

pub(super) fn secs(seconds: u64) -> UnixTime {
    UnixTime::from_secs(seconds)
}

/// A user with `id`, in `status`, with `expires_at` as their own record
/// and no quota of their own.
pub(super) fn user(id_text: &str, status: UserStatus, expires_at: Option<u64>) -> User {
    User {
        id: id(id_text),
        label: LocalLabel::parse("Payer").unwrap(),
        client: ClientProfile {
            line: ClientLine::Cfm05,
            capabilities: Default::default(),
        },
        status,
        per_node: BTreeMap::new(),
        policy: UserPolicy {
            expires_at: expires_at.map(UnixTime::from_secs),
            quota: None,
        },
        alias: None,
        agreement: None,
    }
}

/// `list` by id.
pub(super) fn by_id(list: Vec<User>) -> BTreeMap<UserId, User> {
    list.into_iter()
        .map(|user| (user.id.clone(), user))
        .collect()
}

/// The pilot golden's users, both active and without an expiry of their
/// own.
pub(super) fn pilot_users() -> BTreeMap<UserId, User> {
    by_id(vec![
        user("pilotusera", UserStatus::Active, None),
        user("pilotuserb", UserStatus::Active, None),
    ])
}

/// The pilot golden, to edit.
pub(super) fn pilot_value() -> Value {
    serde_json::from_str(PILOT).unwrap()
}

/// `value` decoded as the answer to `after=asked`.
pub(super) fn decode(value: &Value, asked: u64) -> Result<FeedPage, FeedError> {
    FeedPage::decode(&serde_json::to_vec(value).unwrap(), asked)
}

/// An order's terms as the tests write them.
#[derive(Debug, Clone)]
pub(super) struct Terms {
    pub(super) order: &'static str,
    pub(super) user: &'static str,
    pub(super) kind: &'static str,
    pub(super) days: u64,
    pub(super) gigabytes: u64,
    pub(super) renewal_of: Option<&'static str>,
}

impl Terms {
    /// A month for `user` of 30 days and 100 GB.
    pub(super) const fn month(order: &'static str, user: &'static str) -> Self {
        Self {
            order,
            user,
            kind: "month",
            days: 30,
            gigabytes: 100,
            renewal_of: None,
        }
    }

    /// A traffic pack for `user` of 50 GB for 30 days.
    pub(super) const fn pack(order: &'static str, user: &'static str) -> Self {
        Self {
            order,
            user,
            kind: "traffic",
            days: 30,
            gigabytes: 50,
            renewal_of: None,
        }
    }

    /// The entry `seq` of these terms, of `kind` with its amounts.
    fn entry(
        &self,
        seq: u64,
        kind: &str,
        refund: Option<(u64, bool)>,
        dispute: Option<u64>,
    ) -> Value {
        json!({
            "seq": seq,
            "kind": kind,
            "order": self.order,
            "user": self.user,
            "plan": format!("plan-{}", self.kind.replace('_', "-")),
            "plan_kind": self.kind,
            "days": self.days,
            "traffic_bytes": self.gigabytes * 1_000_000_000,
            "amount": 800,
            "currency": "gbp",
            "paid_at": 1_796_990_000,
            "renewal_of": self.renewal_of,
            "amount_refunded": refund.map(|(amount, _)| amount),
            "refunded_in_full": refund.map(|(_, in_full)| in_full),
            "amount_disputed": dispute,
            "recorded_at": 1_796_990_100,
        })
    }

    pub(super) fn grant(&self, seq: u64) -> Value {
        self.entry(seq, "grant", None, None)
    }

    pub(super) fn refund(&self, seq: u64, amount: u64, in_full: bool) -> Value {
        self.entry(seq, "refund", Some((amount, in_full)), None)
    }

    pub(super) fn dispute(&self, seq: u64, amount: u64) -> Value {
        self.entry(seq, "dispute", None, Some(amount))
    }
}

/// A document of `entries` after `after`, in live mode or not.
pub(super) fn document(livemode: bool, after: u64, entries: Vec<Value>, more: bool) -> Value {
    let next = entries
        .last()
        .map_or(after, |entry| entry["seq"].as_u64().unwrap());
    json!({
        "format": "mooring-portal-entitlements",
        "version": 1,
        "generated_at": 1_797_000_000,
        "livemode": livemode,
        "after": after,
        "entries": entries,
        "next": next,
        "more": more,
    })
}

/// The live page of `entries` after `after`, decoded.
pub(super) fn live(after: u64, entries: Vec<Value>) -> FeedPage {
    decode(&document(true, after, entries, false), after).unwrap()
}
