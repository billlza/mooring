// SPDX-License-Identifier: GPL-3.0-or-later

//! What a refund in full takes back (design §9.6; the operator's decision
//! of 2026-11-12): from the time the portal recorded it, the time and the
//! traffic the order gave that the user had not used yet. What the user
//! used is not taken back; a partial refund and a dispute take nothing.
//!
//! - **A service period** counts no more from the refund on: the time from
//!   then is taken back, all of it when the period had not begun, and none
//!   when it had ended. Each period that followed it moves as much earlier,
//!   and so does each that followed those, so that no gap opens: a period
//!   granted before the refund, starting where it ended, a live period only
//!   after a live one (as a grant builds on them). The order's quota per
//!   billing cycle goes with its time.
//! - **A traffic pack** counts, once Mooring has learned the user's use at
//!   the refund's time, only what the user had used of it: their bytes
//!   served in its billing cycle by then beyond the rest of their quota, at
//!   most the pack's bytes
//!   ([`UserEntitlements::pack_bytes_in`](super::UserEntitlements::pack_bytes_in)).
//!   The first usage report that covers the refund's time tells the use
//!   ([`PaymentLedger::settle`](super::PaymentLedger::settle)). Until one
//!   does, the refund waits and the pack counts in full, so that nothing
//!   the user used is taken back ([`PackUse::Awaiting`]); and nothing is
//!   taken back once the pack's cycle has ended.
//! - **A REALITY download that was open at a pack's refund** is counted
//!   only when its connection closes, and no count tells it from one
//!   begun later. So the use learned takes in what each node counts of
//!   the user's REALITY downlink from then on
//!   ([`PackUse::Served`]'s `open_downloads`), until that node's Xray is
//!   seen to have started again since the refund ([`RunBegan`]) or the
//!   pack's cycle ends. Until then such a download begun after the refund
//!   counts as used of the pack too, which is the price of never taking
//!   back what the user had used.
//!
//! The time taken back is not recorded: it follows from the grants and the
//! refunds the ledger holds, replayed in the order of their entries
//! ([`TakeBacks`]), so that the daemon and `portal payments` read the same.

use std::collections::{BTreeMap, BTreeSet};

use mooring_agent_proto::{EngineRun, HOST_READING_SECS, StatusV1};
use mooring_model::{NodeId, UnixTime, UserId};
use serde::{Deserialize, Serialize};

use super::ids::OrderId;
use super::ledger::{GrantOutcome, OrderRecord};
use crate::usage::{DownlinkCount, ServedBefore};

/// What Mooring knows of a user's use of a traffic pack at the time of the
/// refund in full that takes the pack back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PackUse {
    /// The user's bytes served in the pack's billing cycle by the refund's
    /// time, as the nodes had counted them, at most: never fewer than they
    /// had counted. The first usage report that covered the refund's time
    /// told them, at `learned_at`; from then on the pack counts only what
    /// the user had used of it.
    Served {
        /// The bytes.
        bytes: u64,
        /// When Mooring learned them.
        learned_at: UnixTime,
        /// The nodes that may still count a download that was open at the
        /// refund: Xray counts the downlink of a REALITY connection only
        /// when the connection closes. For each, the user's REALITY
        /// downlink of the cycle that `bytes` holds from it. What the node
        /// counts beyond that counts as used too: it is added at every
        /// reading while the node is here
        /// ([`PaidPack::taken_back_by`](super::PaidPack::taken_back_by)),
        /// and into `bytes` when the node leaves, which it does once its
        /// Xray is seen to have started again since the refund, or when
        /// the pack's cycle ends
        /// ([`PaymentLedger::settle`](super::PaymentLedger::settle)).
        open_downloads: BTreeMap<NodeId, u64>,
    },
    /// No usage report has covered the refund's time yet: a node cannot be
    /// reached, the collection is behind, or it has no figure for the user.
    /// The pack counts in full meanwhile, so that nothing the user used is
    /// taken back.
    Awaiting,
    /// The pack's billing cycle ended before a report covered the refund's
    /// time, or had ended when Mooring learned of the refund: nothing of
    /// the pack is taken back.
    CycleEnded,
}

/// When the run of Xray that a node's latest status shows began, between
/// two bounds: the status tells it to the watch's reading, not to the
/// second ([`RunBegan::of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunBegan {
    /// The run began at this instant or later.
    pub no_earlier_than: UnixTime,
    /// The run began at this instant or earlier.
    pub no_later_than: UnixTime,
}

impl RunBegan {
    /// When the run of Xray that `status` shows began, by the node's
    /// clock; `None` while its Xray does not run.
    ///
    /// The status carries the watch's latest reading of the unit. The
    /// reading is dated by the tick that took it, less than
    /// [`HOST_READING_SECS`] before `watch_at`; the watch reads the unit
    /// later in that tick; and the time since the unit became active is
    /// the difference of two figures each rounded down to a second.
    ///
    /// - The run began no earlier than `watch_at` less that time, less
    ///   the reading's interval and a second.
    /// - It began no later than `watch_at` less that time, plus a second
    ///   and what the tick took to reach the unit, for which the
    ///   reading's interval is allowed: a tick runs a handful of local
    ///   commands, and one that took as long would be the watch's fault
    ///   to report.
    ///
    /// Figures that go before the epoch tell nothing.
    #[must_use]
    pub fn of(status: &StatusV1) -> Option<Self> {
        let EngineRun::Active { uptime_secs, .. } = status.engines.xray.run else {
            return None;
        };
        let read_by = status.watch_at.as_secs().checked_sub(uptime_secs)?;
        Some(Self {
            no_earlier_than: UnixTime::from_secs(read_by.checked_sub(HOST_READING_SECS + 1)?),
            no_later_than: UnixTime::from_secs(read_by.checked_add(HOST_READING_SECS + 1)?),
        })
    }
}

/// What the nodes of `open` have counted of a user's REALITY downlink
/// beyond what the use at a refund held from each
/// ([`PackUse::Served`]'s `open_downloads`), given `counted`, what each
/// node has counted of it in the cycle; a node `counted` leaves out has
/// counted none. Saturates at `u64::MAX`.
pub(super) fn counted_since(open: &BTreeMap<NodeId, u64>, counted: &BTreeMap<NodeId, u64>) -> u64 {
    open.iter().fold(0, |total: u64, (node, held)| {
        let now = counted.get(node).copied().unwrap_or(0);
        total.saturating_add(now.saturating_sub(*held))
    })
}

/// Takes out of `open` the nodes whose Xray is seen to have started again
/// since a refund, for `user`'s pack, and returns them, in id order, with
/// the bytes they had counted of the user's REALITY downlink beyond what
/// the use held from them.
///
/// A node leaves when both hold:
///
/// - the run of Xray its latest status shows began at `boundary` or later
///   ([`boundary_after`](crate::usage::boundary_after) the refund's time),
///   as far as the status tells: every connection that was open at the
///   refund ended with the run before, and Xray counts nothing of a
///   connection it was stopped with;
/// - the node's figures were sampled when the run had begun for certain,
///   so that they hold all the node counted before it.
///
/// The usage is asked only when a status shows such a run.
pub(super) fn close_restarted(
    open: &mut BTreeMap<NodeId, u64>,
    boundary: UnixTime,
    user: &UserId,
    usage: &dyn RefundUsage,
) -> (Vec<NodeId>, u64) {
    let began: Vec<(NodeId, RunBegan)> = open
        .keys()
        .filter_map(|node| {
            usage
                .xray_began(node)
                .filter(|run| run.no_earlier_than >= boundary)
                .map(|run| (node.clone(), run))
        })
        .collect();
    let mut left = Vec::new();
    let mut added = 0_u64;
    if began.is_empty() {
        return (left, added);
    }
    let Some(counted) = usage.reality_downlink(user) else {
        return (left, added);
    };
    for (node, run) in began {
        let Some(count) = counted
            .get(&node)
            .filter(|count| count.sampled_at >= run.no_later_than)
        else {
            continue;
        };
        if let Some(held) = open.remove(&node) {
            added = added.saturating_add(count.bytes.saturating_sub(held));
            left.push(node);
        }
    }
    (left, added)
}

/// What the usage collected and the nodes' statuses tell at one instant of
/// the traffic packs refunded in full (design §9.6), as
/// [`PaymentLedger::settle`](super::PaymentLedger::settle) reads them.
pub trait RefundUsage {
    /// What the nodes had counted for `user` in the billing cycle before
    /// `at`, at most
    /// ([`CollectedUsage::cycle_served_before`](crate::usage::CollectedUsage::cycle_served_before));
    /// `None` while the usage cannot tell.
    fn served_before(&self, user: &UserId, at: UnixTime) -> Option<ServedBefore>;

    /// `user`'s REALITY downlink of the billing cycle on every node
    /// ([`CollectedUsage::cycle_reality_downlink`](crate::usage::CollectedUsage::cycle_reality_downlink));
    /// `None` while the usage cannot tell.
    fn reality_downlink(&self, user: &UserId) -> Option<BTreeMap<NodeId, DownlinkCount>>;

    /// When the run of Xray that `node`'s latest status shows began;
    /// `None` without a status that shows Xray running.
    fn xray_began(&self, node: &NodeId) -> Option<RunBegan>;
}

/// What a refund in full took back of its order's service period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeTakenBack {
    /// The instant from which the period counts no more: the refund's
    /// time, or the period's start when it had not begun.
    pub from: UnixTime,
    /// The end the period had before the refund. The time from `from`
    /// until then is taken back: none when the two are equal, the period
    /// having ended before the refund.
    pub until: UnixTime,
    /// The periods that followed it, by order, each moved as much earlier.
    pub moved: Vec<OrderId>,
}

/// What a refund did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefundEffect {
    /// Nothing: a refund not in full, one after the order's first in full,
    /// or one of an order Mooring did not grant.
    Nothing,
    /// The first refund in full of a service period.
    Time(TimeTakenBack),
    /// The first refund in full of a traffic pack, with what Mooring knows
    /// of the user's use at its time.
    Pack(PackUse),
}

/// A granted period as it counts.
#[derive(Debug, Clone)]
struct Span {
    user: UserId,
    from: UnixTime,
    until: UnixTime,
    livemode: bool,
    /// The grant's entry number.
    granted: u64,
}

/// What the refunds in full did to the ledger's orders, replayed from its
/// grants and refunds in the order of their entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TakeBacks {
    periods: BTreeMap<OrderId, (UnixTime, UnixTime)>,
    effects: BTreeMap<u64, RefundEffect>,
}

impl TakeBacks {
    /// Replays the refunds in full of `orders`. Only a user with a refund
    /// in full has periods that may move, so only theirs are held.
    pub(super) fn of<'a, I>(orders: I) -> Self
    where
        I: IntoIterator<Item = &'a OrderRecord>,
        I::IntoIter: Clone,
    {
        let orders = orders.into_iter();
        let mut refunds: Vec<(u64, &OrderRecord, UnixTime)> = orders
            .clone()
            .filter_map(|record| {
                record
                    .first_refund_in_full()
                    .map(|refund| (refund.seq, record, refund.recorded_at))
            })
            .collect();
        refunds.sort_by_key(|(seq, ..)| *seq);
        let reached: BTreeSet<&UserId> = refunds
            .iter()
            .map(|(_, record, _)| &record.terms.user)
            .collect();
        let mut spans = BTreeMap::new();
        for record in orders.filter(|record| reached.contains(&record.terms.user)) {
            if let (Some(grant), Some((from, until))) = (record.grant, granted_period(record)) {
                spans.insert(
                    record.order.clone(),
                    Span {
                        user: record.terms.user.clone(),
                        from,
                        until,
                        livemode: record.livemode,
                        granted: grant.seq,
                    },
                );
            }
        }
        let mut effects = BTreeMap::new();
        for (seq, record, at) in refunds {
            let effect = match spans.get(&record.order).cloned() {
                Some(span) => {
                    RefundEffect::Time(take_time(&mut spans, &record.order, span, seq, at))
                }
                None => pack_taken_back(record)
                    .cloned()
                    .map_or(RefundEffect::Nothing, RefundEffect::Pack),
            };
            effects.insert(seq, effect);
        }
        Self {
            periods: spans
                .into_iter()
                .map(|(order, span)| (order, (span.from, span.until)))
                .collect(),
            effects,
        }
    }

    /// The period `record`'s grant gave, as it counts after the refunds in
    /// full: its first instant and the instant after its last, the two
    /// equal when all of its time was taken back; as granted where no
    /// refund in full reached it. `None` for an order whose grant gave no
    /// period.
    #[must_use]
    pub fn period(&self, record: &OrderRecord) -> Option<(UnixTime, UnixTime)> {
        granted_period(record)
            .map(|granted| self.periods.get(&record.order).copied().unwrap_or(granted))
    }

    /// What the refund of entry `seq` did; [`RefundEffect::Nothing`] for a
    /// number that is no refund's.
    #[must_use]
    pub fn effect(&self, seq: u64) -> RefundEffect {
        self.effects
            .get(&seq)
            .cloned()
            .unwrap_or(RefundEffect::Nothing)
    }
}

/// The period `record`'s grant gave, as granted.
fn granted_period(record: &OrderRecord) -> Option<(UnixTime, UnixTime)> {
    match record.grant?.outcome {
        GrantOutcome::Period { from, until } => Some((from, until)),
        GrantOutcome::Pack | GrantOutcome::Held { .. } => None,
    }
}

/// What `record`'s refund in full records of the use of the pack it takes
/// back; `None` for an order that gave no pack, or has no refund in full.
/// The ledger records a use on the first refund in full of a granted pack
/// and on no other refund
/// ([`PaymentLedger::decode`](super::PaymentLedger::decode) refuses a file
/// that breaks either).
pub(super) fn pack_taken_back(record: &OrderRecord) -> Option<&PackUse> {
    record.first_refund_in_full()?.pack_use.as_ref()
}

/// Takes back the time of `order`'s period, `span`, from `at` on, for the
/// refund of entry `seq`, and moves the periods that followed it as much
/// earlier.
fn take_time(
    spans: &mut BTreeMap<OrderId, Span>,
    order: &OrderId,
    span: Span,
    seq: u64,
    at: UnixTime,
) -> TimeTakenBack {
    let from = at.max(span.from).min(span.until);
    let mut moved = Vec::new();
    if from < span.until {
        spans.insert(
            order.clone(),
            Span {
                until: from,
                ..span.clone()
            },
        );
        // Each boundary reached: where the periods that follow it started,
        // where they start now, and whether the period before it is live.
        let mut boundaries = vec![(span.until, from, span.livemode)];
        let mut reached = BTreeSet::from([order.clone()]);
        while let Some((was, now, live)) = boundaries.pop() {
            let followers: Vec<(OrderId, Span)> = spans
                .iter()
                .filter(|(id, other)| {
                    !reached.contains(*id)
                        && other.user == span.user
                        && other.granted < seq
                        && other.from == was
                        && (live || !other.livemode)
                })
                .map(|(id, other)| (id.clone(), other.clone()))
                .collect();
            for (id, follower) in followers {
                // A period never ends before it starts, and it moves
                // earlier, so neither sum below can overflow.
                let length = follower.until.as_secs() - follower.from.as_secs();
                let until = UnixTime::from_secs(now.as_secs() + length);
                boundaries.push((follower.until, until, follower.livemode));
                spans.insert(
                    id.clone(),
                    Span {
                        from: now,
                        until,
                        ..follower
                    },
                );
                reached.insert(id.clone());
                moved.push(id);
            }
        }
        moved.sort();
    }
    TimeTakenBack {
        from,
        until: span.until,
        moved,
    }
}
