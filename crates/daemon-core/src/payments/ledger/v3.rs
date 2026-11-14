// SPDX-License-Identifier: GPL-3.0-or-later

//! The ledger's version 3 (2026-11-12), before the check against Stripe,
//! when a grant recorded nothing of Stripe. Read and lifted to the current
//! version, never written; versions 1 and 2 are lifted to it first.
//!
//! The lift records every grant as not confirmed at Stripe: no build that
//! wrote version 3 asked Stripe, so none of its grants was confirmed.

use mooring_model::UnixTime;
use serde::Deserialize;

use super::{DisputeRecord, GrantOutcome, OrderTerms, RefundRecord, Stop};
use crate::payments::ids::OrderId;

/// The version this module reads.
pub(super) const VERSION: u32 = 3;

/// A version-3 document.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LedgerFile {
    /// [`VERSION`], read first.
    #[serde(rename = "version")]
    pub(super) _version: u32,
    pub(super) cursor: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(super) pulled_at: Option<UnixTime>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(super) stopped: Option<Stop>,
    pub(super) orders: Vec<OrderRecord>,
}

/// A version-3 order: its grant records nothing of Stripe.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OrderRecord {
    pub(super) order: OrderId,
    pub(super) terms: OrderTerms,
    pub(super) livemode: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(super) grant: Option<GrantRecord>,
    pub(super) refunds: Vec<RefundRecord>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(super) dispute: Option<DisputeRecord>,
}

/// A grant as versions 1 to 3 recorded it.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantRecord {
    pub(super) seq: u64,
    pub(super) recorded_at: UnixTime,
    pub(super) applied_at: UnixTime,
    pub(super) outcome: GrantOutcome,
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
        super::OrderRecord {
            order: self.order,
            terms: self.terms,
            livemode: self.livemode,
            grant: self.grant.map(GrantRecord::lift),
            refunds: self.refunds,
            dispute: self.dispute,
        }
    }
}

impl GrantRecord {
    const fn lift(self) -> super::GrantRecord {
        super::GrantRecord {
            seq: self.seq,
            recorded_at: self.recorded_at,
            applied_at: self.applied_at,
            outcome: self.outcome,
            confirmed: false,
        }
    }
}
