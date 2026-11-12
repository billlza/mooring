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
//! - **A traffic pack** counts, from the refund on, only what the user had
//!   used of it: their bytes served in its billing cycle beyond the rest of
//!   their quota, at most the pack's bytes
//!   ([`UserEntitlements::pack_bytes_in`](super::UserEntitlements::pack_bytes_in)).
//!   The ledger records what the daemon's usage report said of the user's
//!   use when it applied the refund ([`PackUse`]); when the report could
//!   not tell, the pack is taken back whole, and nothing is taken back once
//!   the pack's cycle had ended.
//!
//! The time taken back is not recorded: it follows from the grants and the
//! refunds the ledger holds, replayed in the order of their entries
//! ([`TakeBacks`]), so that the daemon and `portal payments` read the same.

use std::collections::{BTreeMap, BTreeSet};

use mooring_model::{UnixTime, UserId};
use serde::{Deserialize, Serialize};

use super::ids::OrderId;
use super::ledger::{GrantOutcome, OrderRecord};
use crate::usage::CycleUsage;

/// What Mooring knew of a user's use of a traffic pack's billing cycle when
/// it applied the refund in full that takes the pack back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PackUse {
    /// The user's bytes served in the pack's billing cycle, by the daemon's
    /// usage report then.
    Served {
        /// The bytes.
        bytes: u64,
    },
    /// The report could not tell: it was behind (a node not collected
    /// lately, as while one cannot be reached), or it did not know the
    /// user's figure. The pack is taken back whole.
    Unknown,
    /// The report was of a later billing cycle: the pack's had ended, and
    /// nothing of it is taken back.
    CycleEnded,
}

impl PackUse {
    /// What `usage`, the daemon's report of the billing cycle when it
    /// applies the refund (`None` when it has none), says of `user`'s use
    /// of a pack granted at `granted_at`.
    pub(super) fn of(usage: Option<&CycleUsage>, user: &UserId, granted_at: UnixTime) -> Self {
        match usage {
            Some(usage) if usage.cycle.contains(granted_at) => usage
                .served
                .get(user)
                .copied()
                .flatten()
                .map_or(Self::Unknown, |bytes| Self::Served { bytes }),
            Some(usage) if granted_at < usage.cycle.starts_at() => Self::CycleEnded,
            _ => Self::Unknown,
        }
    }
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
    /// The first refund in full of a traffic pack, with what Mooring knew
    /// of the user's use.
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

/// What the first refund in full of `record` recorded of the use of the
/// pack it takes back, if the order's grant gave a pack and a refund in
/// full names it. The ledger records a use on every such refund
/// ([`PaymentLedger::decode`](super::PaymentLedger::decode) refuses one
/// without); none would be a use Mooring did not know.
pub(super) fn pack_taken_back(record: &OrderRecord) -> Option<PackUse> {
    let grant = record.grant?;
    if grant.outcome != GrantOutcome::Pack {
        return None;
    }
    record
        .first_refund_in_full()
        .map(|refund| refund.pack_use.unwrap_or(PackUse::Unknown))
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
