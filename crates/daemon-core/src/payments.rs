// SPDX-License-Identifier: GPL-3.0-or-later

//! Payments (design §9.6): the entitlements the user portal lists for
//! Mooring, the ledger the daemon keeps of them, and what a user may use
//! because of them.
//!
//! - [`FeedPage`]: one page of the portal's journal
//!   (`docs/portal-contract.md` §5), decoded strictly and checked whole
//!   before anything of it is used.
//! - [`PaymentLedger`]: `payments/ledger.json`, the cursor and every order
//!   the portal named with what Mooring did about it; a page is applied to
//!   a copy ([`PaymentLedger::apply`]), which the daemon writes before it
//!   keeps it, so the cursor and the grants are one write.
//! - [`Entitlements`]: the service periods and traffic packs of the orders
//!   that count, which `policy::effective_policy` combines with each
//!   user's own record.
//! - [`PullSettings`]: `payment-pull.json`, where to pull from and
//!   whether the operator rehearses.
//!
//! Nothing here reads a clock or does I/O: the daemon passes `now`, the
//! deployment's users and the bytes it read, and writes what comes back.
//! A traffic pack counts in the billing cycle it is granted in only (the
//! operator's decision of 2026-11-12). Refunds and disputes are recorded
//! and change nothing. A dispute never suspends the user (the operator's
//! decision of 2026-11-11); what a refund in full takes back is the
//! operator's to decide (design §9.6).

mod entitlement;
mod error;
mod feed;
mod ids;
mod ledger;
mod settings;

pub use entitlement::{Entitlements, PaidPack, PaidPeriod, UserEntitlements};
pub use error::{
    ApplyRefusal, Contradiction, EntryFault, FeedError, LedgerError, MAX_DETAIL_CHARS, printable,
};
pub use feed::{
    EntryEvent, FEED_FORMAT, FEED_VERSION, FeedEntry, FeedPage, MAX_FEED_BYTES, MAX_FEED_ENTRIES,
    OrderTerms, PortalPlanKind,
};
pub use ids::{Currency, IdError, MAX_PLAN_ID_CHARS, ORDER_ID_CHARS, OrderId, PlanId};
pub use ledger::{
    Applied, DisputeRecord, GrantOutcome, GrantRecord, HeldReason, LEDGER_VERSION, LedgerEvent,
    MAX_LEDGER_BYTES, OrderRecord, PaymentLedger, Pruned, RefundRecord, Stop, StopReason,
};
pub use settings::{
    ENTITLEMENTS_PATH, MAX_SETTINGS_BYTES, OriginError, PortalOrigin, PullSettings,
    SETTINGS_VERSION, SettingsError,
};
