// SPDX-License-Identifier: GPL-3.0-or-later

//! What the orders that count give each user (design §9.6): the service
//! periods and traffic packs recorded in the payment ledger. Built by
//! [`PaymentLedger::entitlements`](super::PaymentLedger::entitlements);
//! `policy::effective_policy` combines it with each user's own record.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use mooring_model::{NodeId, UnixTime, UserId};

use super::ids::OrderId;
use super::refund::{PackUse, counted_since};
use crate::period::BillingCycle;

/// A service period a paid order gave: from `from` until `until`, with a
/// quota of `quota_bytes` per billing cycle while it lasts. A refund in
/// full shortens it or moves it earlier (design §9.6); one whose time was
/// all taken back covers no instant (`from` equals `until`), and still
/// ends the user's paid time there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidPeriod {
    /// The order.
    pub order: OrderId,
    /// The first instant of service.
    pub from: UnixTime,
    /// The instant after the last.
    pub until: UnixTime,
    /// The quota of each billing cycle while the period lasts.
    pub quota_bytes: NonZeroU64,
    /// Whether it was paid in Stripe's live mode.
    pub livemode: bool,
}

/// A traffic pack a paid order gave, granted at `granted_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidPack {
    /// The order.
    pub order: OrderId,
    /// When Mooring granted it.
    pub granted_at: UnixTime,
    /// Its bytes.
    pub bytes: NonZeroU64,
    /// Whether it was paid in Stripe's live mode.
    pub livemode: bool,
    /// Its order's refund in full, if any.
    pub refund: Option<PackRefund>,
}

/// A refund in full of a traffic pack (design §9.6): once Mooring has
/// learned the user's use at `at`, the pack counts only what the user had
/// used of it, as `used` tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackRefund {
    /// When the portal recorded the refund.
    pub at: UnixTime,
    /// What Mooring knows of the user's use then.
    pub used: PackUse,
}

impl PaidPack {
    /// When the pack's refund in full was recorded and the user's bytes
    /// served in the pack's cycle by then, if the refund has taken back by
    /// `now` what the user had not used of the pack: Mooring had learned
    /// that use by `now`. A pack whose refund still waits for the usage,
    /// or whose cycle ended first, is not taken back: it counts in full.
    ///
    /// `downlink` is what each node has counted of the user's REALITY
    /// downlink in the pack's cycle, per node that counted any, by the
    /// usage report the caller reads the user's use from; `None` without
    /// a figure for the user. What a node still open has counted beyond
    /// what the use held from it may be a download that was open at the
    /// refund, and is part of the use ([`PackUse::Served`]); whether the
    /// pack is taken back does not depend on it.
    #[must_use]
    pub fn taken_back_by(
        &self,
        now: UnixTime,
        downlink: Option<&BTreeMap<NodeId, u64>>,
    ) -> Option<(UnixTime, u64)> {
        match self.refund.as_ref()? {
            PackRefund {
                at,
                used:
                    PackUse::Served {
                        bytes,
                        learned_at,
                        open_downloads,
                    },
            } if *learned_at <= now => {
                let since = downlink.map_or(0, |counted| counted_since(open_downloads, counted));
                Some((*at, bytes.saturating_add(since)))
            }
            PackRefund { .. } => None,
        }
    }
}

/// The periods and packs one user's orders gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserEntitlements {
    periods: Vec<PaidPeriod>,
    packs: Vec<PaidPack>,
}

impl UserEntitlements {
    /// The periods, in the ledger's order of their orders.
    #[must_use]
    pub fn periods(&self) -> &[PaidPeriod] {
        &self.periods
    }

    /// The packs, in the ledger's order of their orders.
    #[must_use]
    pub fn packs(&self) -> &[PaidPack] {
        &self.packs
    }

    /// The end of the last period, if there is one.
    #[must_use]
    pub fn paid_until(&self) -> Option<UnixTime> {
        self.periods.iter().map(|period| period.until).max()
    }

    /// The period that covers `at`, if one does; of two (a live one and a
    /// rehearsal's), the live one, and then the one that started last.
    #[must_use]
    pub fn period_at(&self, at: UnixTime) -> Option<&PaidPeriod> {
        self.periods
            .iter()
            .filter(|period| period.from <= at && at < period.until)
            .max_by_key(|period| (period.livemode, period.from))
    }

    /// The bytes the packs granted within `cycle` add at `now` to a quota
    /// of `base` bytes, the quota that applies without them (design §9.6,
    /// the operator's decisions of 2026-11-12: a pack counts in the billing
    /// cycle it is granted in, and in no other, and its order's `days` is
    /// not applied). A pack refunded in full counts, once Mooring has
    /// learned the user's use at the refund's time
    /// ([`PaidPack::taken_back_by`]), only what the user had used of it:
    /// the bytes they had used in the cycle by then beyond the rest of
    /// their quota (`base` and the cycle's other packs granted by the
    /// refund, as they counted then), at most its own. Until then it counts
    /// in full, and it does for good when its cycle ended first: nothing
    /// the user used is taken back. Refunds count in the order they were
    /// recorded. `downlink` is what each node has counted of the user's
    /// REALITY downlink in `cycle` ([`PaidPack::taken_back_by`]).
    /// Saturates at `u64::MAX`.
    #[must_use]
    pub fn pack_bytes_in(
        &self,
        cycle: BillingCycle,
        now: UnixTime,
        base: u64,
        downlink: Option<&BTreeMap<NodeId, u64>>,
    ) -> u64 {
        let packs: Vec<&PaidPack> = self
            .packs
            .iter()
            .filter(|pack| cycle.contains(pack.granted_at))
            .collect();
        let mut counted: Vec<u64> = packs.iter().map(|pack| pack.bytes.get()).collect();
        // Each pack taken back by `now`: when its refund was recorded, and
        // the user's use then.
        let mut refunded: Vec<(usize, &PaidPack, UnixTime, u64)> = packs
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, pack)| {
                pack.taken_back_by(now, downlink)
                    .map(|(at, used)| (index, pack, at, used))
            })
            .collect();
        refunded.sort_by(|(_, left, earlier, _), (_, right, later, _)| {
            (earlier, &left.order).cmp(&(later, &right.order))
        });
        for (index, pack, at, used) in refunded {
            let rest = packs
                .iter()
                .zip(&counted)
                .enumerate()
                .filter(|(other, (other_pack, _))| *other != index && other_pack.granted_at <= at)
                .fold(base, |total, (_, (_, bytes))| total.saturating_add(*bytes));
            counted[index] = used.saturating_sub(rest).min(pack.bytes.get());
        }
        counted
            .into_iter()
            .fold(0_u64, |total, bytes| total.saturating_add(bytes))
    }
}

/// The periods and packs of every user with an order that counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entitlements {
    users: BTreeMap<UserId, UserEntitlements>,
}

impl Entitlements {
    /// No paid order: every user is as their own record says.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// What `user`'s orders gave, if any counts.
    #[must_use]
    pub fn user(&self, user: &UserId) -> Option<&UserEntitlements> {
        self.users.get(user)
    }

    /// The users with an order that counts, and what it gave each.
    #[must_use]
    pub const fn users(&self) -> &BTreeMap<UserId, UserEntitlements> {
        &self.users
    }

    pub(super) fn add_period(&mut self, user: UserId, period: PaidPeriod) {
        self.users.entry(user).or_default().periods.push(period);
    }

    pub(super) fn add_pack(&mut self, user: UserId, pack: PaidPack) {
        self.users.entry(user).or_default().packs.push(pack);
    }
}
