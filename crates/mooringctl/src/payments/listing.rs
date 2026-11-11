// SPDX-License-Identifier: GPL-3.0-or-later

//! What `portal payments` prints: the pull's settings, the ledger's cursor,
//! last pull and stop, and every order with what Mooring did about it. It
//! names users by id only, as the ledger does.

use mooring_daemon_core::payments::{
    GrantOutcome, LedgerError, OrderRecord, PaymentLedger, PullSettings, StopReason,
};
use serde::Serialize;

use super::error::PaymentFileError;
use super::notes::stamp;

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
    for record in orders.values() {
        order_lines(record, &mut lines);
    }
    finish(lines)
}

fn finish(lines: Vec<String>) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// The lines of one order.
fn order_lines(record: &OrderRecord, lines: &mut Vec<String>) {
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
                    format!("service from {} until {}", stamp(from), stamp(until))
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
                "    grant, entry {}, applied {}: {what}",
                grant.seq,
                stamp(grant.applied_at)
            ));
        }
    }
    for refund in &record.refunds {
        lines.push(format!(
            "    refund, entry {}: {} {} so far{}; changes nothing",
            refund.seq,
            refund.amount_refunded,
            terms.currency,
            if refund.refunded_in_full {
                ", in full"
            } else {
                ""
            }
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
