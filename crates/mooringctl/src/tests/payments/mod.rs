// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull (design §9.6): curl's request, the daemon's pull and
//! its every outcome, the check against Stripe, the operator's commands,
//! and the daemon's loop.
//! Nothing here reaches a portal: the system's curl is run only against a
//! stub on the loopback interface.

use std::fs;

use mooring_daemon_core::payments::{MAX_LEDGER_BYTES, PaymentLedger, PortalOrigin, PullSettings};
use mooring_model::PortalPullToken;
use mooring_model::secret::SecretEntry;
use mooring_store::{read_payment_ledger, update_payment_pull};
use serde_json::{Value, json};

use super::support::Harness;
use super::user::{fixture, harness_with};

mod check;
mod command;
mod curl;
mod daemon;
mod listing;
mod open_downloads;
mod prune;
mod pull;
mod settle;
mod stripe_check;

/// The first fixture user, `fxuseraaab`.
pub(crate) const FIRST: &str = "fxuseraaab";

/// The second fixture user, `fxuseraaac`.
pub(crate) const SECOND: &str = "fxuseraaac";

/// The token the tests store.
pub(crate) fn token(byte: u8) -> PortalPullToken {
    PortalPullToken::parse(&format!("{byte:02x}").repeat(32)).unwrap()
}

/// A harness holding the fixture deployment, its support directory made.
pub(crate) fn harness() -> Harness {
    harness_with(fixture(|_| {}))
}

/// Points the pull at the test portal at `revision`, in rehearsal or not,
/// and stores token `byte`.
pub(crate) fn connect(harness: &mut Harness, revision: u64, rehearsal: bool, byte: u8) {
    use mooring_store::SecretStore;
    harness
        .secrets
        .put(SecretEntry::PortalPullToken(token(byte)))
        .unwrap();
    let origin = PortalOrigin::parse("https://portal.example.org").unwrap();
    let settings = PullSettings::connected(revision, origin, rehearsal, false);
    update_payment_pull::<()>(&harness.support_dir(), 4096, |_| {
        Ok(Some(settings.encode().unwrap()))
    })
    .unwrap();
}

/// The ledger on disk, if any.
pub(crate) fn ledger_on_disk(harness: &Harness) -> Option<PaymentLedger> {
    read_payment_ledger(&harness.support_dir(), MAX_LEDGER_BYTES + 1)
        .unwrap()
        .map(|bytes| PaymentLedger::decode(&bytes).unwrap())
}

/// A month for `user` as entry `seq`, order `order`.
pub(crate) fn grant(seq: u64, order: &str, user: &str) -> Value {
    json!({
        "seq": seq, "kind": "grant", "order": order, "user": user,
        "plan": "month-100", "plan_kind": "month", "days": 30,
        "traffic_bytes": 100_000_000_000_u64, "amount": 800, "currency": "gbp",
        "paid_at": super::support::NOW - 60, "renewal_of": null,
        "amount_refunded": null, "refunded_in_full": null, "amount_disputed": null,
        "recorded_at": super::support::NOW - 30
    })
}

/// A 50 GB traffic pack for `user` as entry `seq`, order `order`.
pub(crate) fn pack(seq: u64, order: &str, user: &str) -> Value {
    let mut entry = grant(seq, order, user);
    entry["plan"] = json!("pack-50");
    entry["plan_kind"] = json!("traffic");
    entry["traffic_bytes"] = json!(50_000_000_000_u64);
    entry
}

/// The refund in full of `granted`'s order as entry `seq`, recorded by the
/// portal at `recorded_at`.
pub(crate) fn refund_in_full(granted: &Value, seq: u64, recorded_at: u64) -> Value {
    let mut entry = granted.clone();
    entry["seq"] = json!(seq);
    entry["kind"] = json!("refund");
    entry["amount_refunded"] = json!(800);
    entry["refunded_in_full"] = json!(true);
    entry["recorded_at"] = json!(recorded_at);
    entry
}

/// The document of `entries` after `after`.
pub(crate) fn page(livemode: bool, after: u64, entries: Vec<Value>, more: bool) -> Vec<u8> {
    let next = entries
        .last()
        .map_or(after, |entry| entry["seq"].as_u64().unwrap());
    serde_json::to_vec(&json!({
        "format": "mooring-portal-entitlements",
        "version": 1,
        "generated_at": super::support::NOW,
        "livemode": livemode,
        "after": after,
        "entries": entries,
        "next": next,
        "more": more,
    }))
    .unwrap()
}

/// Makes `payments` a file, so that no ledger can be written there.
pub(crate) fn block_the_ledger(harness: &Harness) {
    fs::write(harness.support_dir().join("payments"), b"not a directory").unwrap();
}
