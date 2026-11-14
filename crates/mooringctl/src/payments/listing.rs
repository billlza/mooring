// SPDX-License-Identifier: GPL-3.0-or-later

//! What `portal payments` prints: the pull's settings, the check against
//! Stripe among them, the ledger's cursor, last pull and stop, how many
//! refunds wait for the usage or still take in downloads, and every order
//! with what Mooring did about it, a grant Stripe confirmed marked so. It
//! names users by id only, as the ledger does.

use mooring_daemon_core::payments::{
    GrantOutcome, LedgerError, OrderRecord, PaymentLedger, PullSettings, StopReason, TakeBacks,
};
use serde::Serialize;

use super::error::PaymentFileError;
use super::notes::{stamp, taken_back};

/// The text summary.
pub(crate) fn text(settings: Option<&PullSettings>, ledger: Option<&PaymentLedger>) -> String {
    let mut lines = Vec::new();
    match settings {
        None => lines.push("payment pull: not set up (`mooringctl portal connect`)".to_owned()),
        Some(settings) => {
            match settings.origin() {
                Some(origin) => lines.push(format!(
                    "payment pull: {origin} (settings revision {})",
                    settings.revision()
                )),
                None => lines.push(format!(
                    "payment pull: disconnected (settings revision {})",
                    settings.revision()
                )),
            }
            lines.push(format!(
                "  rehearsal: {}",
                if settings.rehearsal() {
                    "on: Stripe test-mode payments are granted and count"
                } else {
                    "off"
                }
            ));
            lines.push(format!(
                "  check against Stripe: {}",
                if settings.stripe_check() {
                    "on: each live payment is confirmed at Stripe before it is granted"
                } else {
                    "off: payments are granted as the portal lists them"
                }
            ));
        }
    }
    let Some(ledger) = ledger else {
        lines.push("payment ledger: none yet; nothing has been pulled".to_owned());
        return finish(lines);
    };
    lines.push(format!(
        "payment ledger: cursor {}; last pull {}",
        ledger.cursor(),
        ledger.pulled_at().map_or_else(|| "never".to_owned(), stamp)
    ));
    if let Some(stop) = ledger.stopped() {
        let why = match stop.reason {
            StopReason::Conflict => "409, the portal's journal ends before the cursor",
            StopReason::Unauthorized => "401, the token was refused",
            StopReason::BadRequest => "400, the portal refused the request",
            StopReason::Inconsistent => "a page did not fit the ledger",
            StopReason::StripeUnauthorized => "Stripe's 401, the read key was refused",
            StopReason::StripeForbidden => {
                "Stripe's 403, the read key may not read checkouts or invoices"
            }
            StopReason::StripeBadRequest => "Stripe's 400 or 404, Stripe refused the request",
        };
        let changed = settings.is_some_and(|settings| settings.revision() > stop.settings_revision);
        let then = if changed {
            "the settings have changed since, and the daemon pulls again at its next tick"
        } else {
            "it pulls again once the settings change"
        };
        lines.push(format!(
            "  stopped since {} ({why}) under settings revision {}: {then}",
            stamp(stop.at),
            stop.settings_revision
        ));
    }
    let orders = ledger.orders();
    let held = orders
        .values()
        .filter(|record| {
            matches!(
                record.grant.map(|grant| grant.outcome),
                Some(GrantOutcome::Held { .. })
            )
        })
        .count();
    let refunded = orders
        .values()
        .filter(|record| !record.refunds.is_empty())
        .count();
    let disputed = orders
        .values()
        .filter(|record| record.dispute.is_some())
        .count();
    lines.push(format!(
        "orders: {} ({held} held, {refunded} refunded, {disputed} disputed)",
        orders.len()
    ));
    let waiting = ledger.awaiting_usage().count();
    if waiting > 0 {
        lines.push(format!(
            "  {waiting} refund(s) in full of traffic packs wait for the usage: the daemon records the user's use at the refund once the usage collected covers its time"
        ));
    }
    let open = ledger.open_downloads().count();
    if open > 0 {
        lines.push(format!(
            "  {open} refund(s) in full of traffic packs still take in REALITY downloads: one that was open at the refund is counted only when it ends, so what a node counts since counts as used at the refund, until that node's Xray has started again or the billing cycle ends"
        ));
    }
    let take_backs = ledger.take_backs();
    for record in orders.values() {
        order_lines(record, &take_backs, &mut lines);
    }
    finish(lines)
}

fn finish(lines: Vec<String>) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// The lines of one order, with what the refunds in full took back.
fn order_lines(record: &OrderRecord, take_backs: &TakeBacks, lines: &mut Vec<String>) {
    let terms = &record.terms;
    lines.push(format!(
        "  {} user {} plan {} ({}, {} days, {} bytes, {} {}){}",
        record.order,
        terms.user,
        terms.plan,
        terms.plan_kind.as_str(),
        terms.days,
        terms.traffic_bytes,
        terms.amount,
        terms.currency,
        if record.livemode {
            ""
        } else {
            " [Stripe test mode]"
        }
    ));
    match record.grant {
        None => lines.push("    no grant: known only from a refund or dispute".to_owned()),
        Some(grant) => {
            let what = match grant.outcome {
                GrantOutcome::Period { from, until } => {
                    let counted = match take_backs.period(record) {
                        Some((now_from, now_until)) if (now_from, now_until) == (from, until) => {
                            String::new()
                        }
                        Some((now_from, now_until)) if now_from == now_until => {
                            "; a refund in full took all of it back".to_owned()
                        }
                        Some((now_from, now_until)) => format!(
                            "; after refunds in full it counts from {} until {}",
                            stamp(now_from),
                            stamp(now_until)
                        ),
                        None => String::new(),
                    };
                    format!(
                        "service from {} until {}{counted}",
                        stamp(from),
                        stamp(until)
                    )
                }
                GrantOutcome::Pack => {
                    format!(
                        "traffic pack for the billing cycle of {}",
                        stamp(grant.applied_at)
                    )
                }
                GrantOutcome::Held { reason } => {
                    format!(
                        "held, not granted ({}): settle it at Stripe",
                        reason.as_str()
                    )
                }
            };
            lines.push(format!(
                "    grant, entry {}, applied {}: {what}{}",
                grant.seq,
                stamp(grant.applied_at),
                if grant.confirmed {
                    "; confirmed at Stripe"
                } else {
                    ""
                }
            ));
        }
    }
    for refund in &record.refunds {
        lines.push(format!(
            "    refund, entry {}: {} {} so far{}; {}",
            refund.seq,
            refund.amount_refunded,
            terms.currency,
            if refund.refunded_in_full {
                ", in full"
            } else {
                ""
            },
            taken_back(&take_backs.effect(refund.seq))
        ));
    }
    if let Some(dispute) = record.dispute {
        lines.push(format!(
            "    dispute, entry {}: {} {}; changes nothing",
            dispute.seq, dispute.amount_disputed, terms.currency
        ));
    }
}

/// The settings and the ledger as one JSON line, each as its file holds
/// it, or `null`.
pub(crate) fn json_line(
    settings: Option<&PullSettings>,
    ledger: Option<&PaymentLedger>,
) -> Result<String, PaymentFileError> {
    let mut line = serde_json::to_string(&Listed { settings, ledger })
        .map_err(|error| PaymentFileError::Ledger(LedgerError::Encode(error)))?;
    line.push('\n');
    Ok(line)
}

/// What `--json` prints.
#[derive(Serialize)]
struct Listed<'a> {
    settings: Option<&'a PullSettings>,
    ledger: Option<&'a PaymentLedger>,
}
