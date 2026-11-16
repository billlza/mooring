// SPDX-License-Identifier: GPL-3.0-or-later

//! The ledger's version 3 (2026-11-12 to 2026-11-15), before make-ups: the
//! orders of version 4 as they are, and nothing else. Read and lifted to
//! the current version, with no make-up and none numbered yet; never
//! written.

use mooring_model::UnixTime;
use serde::Deserialize;

use super::{OrderRecord, Stop};

/// The version this module reads.
pub(super) const VERSION: u32 = 3;

/// The document on disk, as version 3 wrote it.
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

impl LedgerFile {
    /// The document as the current version holds it.
    pub(super) fn lift(self) -> super::LedgerFile {
        super::LedgerFile {
            _version: super::LEDGER_VERSION,
            cursor: self.cursor,
            pulled_at: self.pulled_at,
            stopped: self.stopped,
            orders: self.orders,
            make_ups: Vec::new(),
            last_make_up: 0,
        }
    }
}
