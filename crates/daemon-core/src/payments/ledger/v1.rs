// SPDX-License-Identifier: GPL-3.0-or-later

//! The ledger's version 1 (2026-11-11), when a refund changed nothing and
//! recorded nothing of a pack's use. Read and lifted to the current
//! version, never written.
//!
//! The lift records, on the refund that takes a granted pack back (its
//! order's first in full), a use not known ([`PackUse::Unknown`]): what the
//! user had used then was not recorded, so the pack is taken back whole,
//! as when the daemon's usage report cannot tell. The time a refund in full
//! takes back follows from the grants and refunds, which version 1 holds
//! already, so its refunds in full take back what they would now.

use mooring_model::UnixTime;
use serde::Deserialize;

use super::{DisputeRecord, GrantOutcome, GrantRecord, OrderTerms, PackUse, Stop};
use crate::payments::ids::OrderId;

/// The version this module reads.
pub(super) const VERSION: u32 = 1;

/// A version-1 document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LedgerFile {
    /// [`VERSION`], read first.
    #[serde(rename = "version")]
    _version: u32,
    cursor: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pulled_at: Option<UnixTime>,
    #[serde(deserialize_with = "Option::deserialize")]
    stopped: Option<Stop>,
    orders: Vec<OrderRecord>,
}

/// A version-1 order: its refunds record no use.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderRecord {
    order: OrderId,
    terms: OrderTerms,
    livemode: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    grant: Option<GrantRecord>,
    refunds: Vec<RefundRecord>,
    #[serde(deserialize_with = "Option::deserialize")]
    dispute: Option<DisputeRecord>,
}

/// A version-1 refund.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefundRecord {
    seq: u64,
    amount_refunded: u64,
    refunded_in_full: bool,
    recorded_at: UnixTime,
    applied_at: UnixTime,
}

impl LedgerFile {
    /// The document as the current version holds it.
    pub(super) fn lift(self) -> super::LedgerFile {
        super::LedgerFile {
            _version: super::LEDGER_VERSION,
            cursor: self.cursor,
            pulled_at: self.pulled_at,
            stopped: self.stopped,
            orders: self.orders.into_iter().map(OrderRecord::lift).collect(),
        }
    }
}

impl OrderRecord {
    fn lift(self) -> super::OrderRecord {
        let pack = self
            .grant
            .is_some_and(|grant| grant.outcome == GrantOutcome::Pack);
        let first_in_full = self
            .refunds
            .iter()
            .position(|refund| refund.refunded_in_full);
        let refunds = self
            .refunds
            .into_iter()
            .enumerate()
            .map(|(index, refund)| super::RefundRecord {
                seq: refund.seq,
                amount_refunded: refund.amount_refunded,
                refunded_in_full: refund.refunded_in_full,
                recorded_at: refund.recorded_at,
                applied_at: refund.applied_at,
                pack_use: (pack && first_in_full == Some(index)).then_some(PackUse::Unknown),
            })
            .collect();
        super::OrderRecord {
            order: self.order,
            terms: self.terms,
            livemode: self.livemode,
            grant: self.grant,
            refunds,
            dispute: self.dispute,
        }
    }
}
