// SPDX-License-Identifier: GPL-3.0-or-later

//! The ledger's version 2 (2026-11-12), when the refund that takes a pack
//! back recorded what the daemon's usage report said as it was applied, and
//! took the pack back whole when the report could not tell. Read and lifted
//! to the current version, never written.
//!
//! The lift, for the refund that takes a granted pack back:
//!
//! - **A use not known** becomes a refund that waits for the usage
//!   ([`PackUse::Awaiting`](super::PackUse::Awaiting)). The pack, which
//!   version 2 took back whole, counts in full again until a usage report
//!   covers the refund's time, or its billing cycle ends: a pack taken
//!   back whole made a later pack pay for what the user had used of it.
//! - **A use recorded** stays as it is, learned when the refund was
//!   applied, or at the refund's own time were that later, so that it
//!   counts from when version 2 counted it.
//! - **A cycle that had ended** stays so.

use std::collections::BTreeMap;

use mooring_model::UnixTime;
use serde::Deserialize;

use super::{DisputeRecord, GrantRecord, OrderTerms, Stop};
use crate::payments::ids::OrderId;

/// The version this module reads.
pub(super) const VERSION: u32 = 2;

/// A version-2 document.
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

/// A version-2 order.
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

/// A version-2 refund.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefundRecord {
    pub(super) seq: u64,
    pub(super) amount_refunded: u64,
    pub(super) refunded_in_full: bool,
    pub(super) recorded_at: UnixTime,
    pub(super) applied_at: UnixTime,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(super) pack_use: Option<PackUse>,
}

/// What version 2 recorded of a user's use of a pack when it applied the
/// refund that takes the pack back.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PackUse {
    /// The user's bytes served in the pack's cycle, by the usage report
    /// then.
    Served {
        /// The bytes.
        bytes: u64,
    },
    /// The report could not tell.
    Unknown,
    /// The pack's cycle had ended.
    CycleEnded,
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
            grant: self.grant,
            refunds: self.refunds.into_iter().map(RefundRecord::lift).collect(),
            dispute: self.dispute,
        }
    }
}

impl RefundRecord {
    fn lift(self) -> super::RefundRecord {
        let pack_use = self.pack_use.map(|used| match used {
            PackUse::Served { bytes } => super::PackUse::Served {
                bytes,
                learned_at: self.applied_at.max(self.recorded_at),
                open_downloads: BTreeMap::new(),
            },
            PackUse::Unknown => super::PackUse::Awaiting,
            PackUse::CycleEnded => super::PackUse::CycleEnded,
        });
        super::RefundRecord {
            seq: self.seq,
            amount_refunded: self.amount_refunded,
            refunded_in_full: self.refunded_in_full,
            recorded_at: self.recorded_at,
            applied_at: self.applied_at,
            pack_use,
        }
    }
}
