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
//!
//! The time taken back is not recorded: it follows from the grants and the
//! refunds the ledger holds, replayed in the order of their entries
//! ([`TakeBacks`]), so that the daemon and `portal payments` read the same.

use std::collections::{BTreeMap, BTreeSet};

use mooring_model::{UnixTime, UserId};
use serde::{Deserialize, Serialize};

use super::ids::OrderId;
use super::ledger::{GrantOutcome, OrderRecord};

/// What Mooring knows of a user's use of a traffic pack at the time of the
/// refund in full that takes the pack back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
                None => pack_taken_back(record).map_or(RefundEffect::Nothing, RefundEffect::Pack),
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
pub(super) fn pack_taken_back(record: &OrderRecord) -> Option<PackUse> {
    record.first_refund_in_full()?.pack_use
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
