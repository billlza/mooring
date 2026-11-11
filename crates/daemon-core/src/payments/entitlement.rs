// SPDX-License-Identifier: GPL-3.0-or-later

//! What the orders that count give each user (design §9.6): the service
//! periods and traffic packs recorded in the payment ledger. Built by
//! [`PaymentLedger::entitlements`](super::PaymentLedger::entitlements);
//! `policy::effective_policy` combines it with each user's own record.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use mooring_model::{UnixTime, UserId};

use super::ids::OrderId;
use crate::period::BillingCycle;

/// A service period a paid order gave: from `from` until `until`, with a
/// quota of `quota_bytes` per billing cycle while it lasts.
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

    /// The bytes of the packs granted within `cycle`, which raise its quota
    /// (design §9.6: a pack is counted in the billing cycle it is granted
    /// in, and in no other). Saturates at `u64::MAX`.
    #[must_use]
    pub fn pack_bytes_in(&self, cycle: BillingCycle) -> u64 {
        self.packs
            .iter()
            .filter(|pack| cycle.contains(pack.granted_at))
            .fold(0_u64, |total, pack| total.saturating_add(pack.bytes.get()))
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
