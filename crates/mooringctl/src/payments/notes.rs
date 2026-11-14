// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines the payment pull and `portal payments` write: instants in UTC
//! and each event of an applied page, by order id and user id (both
//! opaque), never with the token, Stripe's read key or a label. A grant's
//! line says when Stripe confirmed its payment, a grant held for what
//! Stripe said says what that was, and one held for the plans kept on the
//! Mac says which way it is not theirs. A refund's line names the order only,
//! with what it took back or that it waits for the usage; so do the line
//! that ends such a wait and the lines that say which nodes no longer hold
//! a download that was open at the refund.

use mooring_daemon_core::payments::{
    Closed, GrantOutcome, HeldReason, LedgerEvent, OrderId, PackUse, RefundEffect, TimeTakenBack,
};
use mooring_model::user::SuspendReason;
use mooring_model::{NodeId, UnixTime};

use crate::router::output::utc_stamp;

/// `at` as `YYYY-MM-DD hh:mm:ss UTC`, or its seconds when it is past the
/// calendar, which only a clock gone wrong gives.
pub(crate) fn stamp(at: UnixTime) -> String {
    utc_stamp(at).unwrap_or_else(|_| at.to_string())
}

/// What a grant held for `reason` comes to, after the reason, when the
/// reason is the plans kept on the Mac; nothing for the others, which
/// need no more or come with what Stripe said.
pub(crate) const fn held_meaning(reason: HeldReason) -> &'static str {
    match reason {
        HeldReason::PlanUnknown => {
            ": the plans kept on the Mac have none of its plan's id; if the portal sells it, keep the portal's plan file first (`mooringctl portal plans set`)"
        }
        HeldReason::PlanDiffers => {
            ": no plan kept on the Mac of its plan's id is at its kind, days, traffic, amount and currency"
        }
        HeldReason::UnknownUser
        | HeldReason::UserRevoked
        | HeldReason::BeyondCalendar
        | HeldReason::StripeNoPayment
        | HeldReason::StripeNoFirstOrder
        | HeldReason::StripeUnpaid
        | HeldReason::StripeDiffers => "",
    }
}

/// One event of an applied page, as the daemon logs it.
pub(crate) fn describe(event: &LedgerEvent) -> String {
    match event {
        LedgerEvent::Granted {
            order,
            user,
            outcome,
            livemode,
            suspended,
            confirmed,
        } => {
            let what = match outcome {
                GrantOutcome::Period { from, until } => {
                    format!("service from {} until {}", stamp(*from), stamp(*until))
                }
                GrantOutcome::Pack => "a traffic pack for this billing cycle".to_owned(),
                GrantOutcome::Held { reason } => format!("nothing ({})", reason.as_str()),
            };
            let mode = if *livemode {
                ""
            } else {
                " (rehearsal, Stripe test mode)"
            };
            let suspended = match suspended {
                None => "",
                Some(SuspendReason::Expired) => {
                    "; the user is suspended at expiry, and the nightly apply job resumes them once their paid time covers it, while the cap on active users leaves room"
                }
                Some(SuspendReason::QuotaExceeded { .. }) => {
                    "; the user is suspended for quota, and the nightly apply job resumes them once their quota covers what they used this cycle, or in the next billing cycle"
                }
                Some(SuspendReason::Operator | SuspendReason::AbuseReview) => {
                    "; the user is suspended, and only the operator resumes them"
                }
            };
            let confirmed = if *confirmed {
                "; Stripe confirmed its payment"
            } else {
                ""
            };
            format!("payment: order {order} granted user {user} {what}{mode}{confirmed}{suspended}")
        }
        LedgerEvent::Held {
            order,
            user,
            reason,
            refusal,
        } => format!(
            "payment: order {order} for user {user} is held, not granted ({}{}{}); settle it at Stripe",
            reason.as_str(),
            held_meaning(*reason),
            refusal
                .as_ref()
                .map_or_else(String::new, |refusal| format!(": {refusal}"))
        ),
        LedgerEvent::Refunded {
            order,
            amount_refunded,
            in_full,
            granted,
            effect,
        } => format!(
            "payment: order {order} refunded {amount_refunded} so far{}{}; {}",
            if *in_full { ", in full" } else { "" },
            never_granted(*granted),
            taken_back(effect)
        ),
        LedgerEvent::Disputed {
            order,
            user,
            amount_disputed,
            granted,
        } => format!(
            "payment: order {order} of user {user} disputed ({amount_disputed}){}; recorded, nothing changed",
            never_granted(*granted)
        ),
        LedgerEvent::Repeated { seq, order } => {
            format!("payment: entry {seq} of order {order} is in the ledger already; skipped")
        }
        LedgerEvent::Settled { order, used } => format!(
            "payment: order {order}'s refund in full no longer waits for the usage; {}",
            taken_back(&RefundEffect::Pack(used.clone()))
        ),
        LedgerEvent::DownloadsClosed {
            order,
            why: Closed::XrayBegan,
            nodes,
            added,
            bytes,
            open,
        } => format!(
            "payment: order {order}'s refunded pack: Xray on {} has started again since the refund, so no download that was open at it is left there; the {added} bytes of REALITY downloads counted there since the use was learned are part of it for good, {bytes} bytes now; {}",
            names(nodes),
            if *open == 0 {
                "no node may still count such a download".to_owned()
            } else {
                format!("{open} node(s) may still count such a download")
            }
        ),
        LedgerEvent::DownloadsClosed {
            order,
            why: Closed::CycleEnded,
            bytes,
            ..
        } => format!(
            "payment: order {order}'s refunded pack: its billing cycle has ended, so its use at the refund's time takes in nothing more ({bytes} bytes)"
        ),
    }
}

/// `nodes` by id, as a list.
fn names<'a>(nodes: impl IntoIterator<Item = &'a NodeId>) -> String {
    nodes
        .into_iter()
        .map(NodeId::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a refund took back (design §9.6), as the log and `portal payments`
/// say it.
pub(crate) fn taken_back(effect: &RefundEffect) -> String {
    match effect {
        RefundEffect::Nothing => "nothing is taken back".to_owned(),
        RefundEffect::Time(TimeTakenBack { from, until, .. }) if from == until => {
            "its service had ended, so nothing is taken back".to_owned()
        }
        RefundEffect::Time(TimeTakenBack { from, until, moved }) => format!(
            "its service from {} until {} is taken back{}",
            stamp(*from),
            stamp(*until),
            followers(moved)
        ),
        RefundEffect::Pack(PackUse::Served {
            bytes,
            learned_at,
            open_downloads,
        }) => format!(
            "its pack counts from {} on only what the user had used of it beyond the rest of their quota: {bytes} bytes served this cycle by the refund's time{}",
            stamp(*learned_at),
            if open_downloads.is_empty() {
                String::new()
            } else {
                format!(
                    "; a REALITY download that was open then is counted only when it ends, so what {} count(s) of the user's REALITY downloads beyond that counts as used then too, until that node's Xray has started again or the billing cycle ends",
                    names(open_downloads.keys())
                )
            }
        ),
        RefundEffect::Pack(PackUse::Awaiting) => {
            "it waits for the usage: its pack counts in full until the usage collected covers the refund's time, or the pack's billing cycle ends".to_owned()
        }
        RefundEffect::Pack(PackUse::CycleEnded) => {
            "its pack's billing cycle has ended, so nothing is taken back".to_owned()
        }
    }
}

/// The periods a refund in full moved earlier, as a clause.
fn followers(moved: &[OrderId]) -> String {
    let orders = moved
        .iter()
        .map(OrderId::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    match moved.len() {
        0 => String::new(),
        1 => format!(", and the period of order {orders} that followed it moves as much earlier"),
        _ => format!(", and the periods of orders {orders} that followed it move as much earlier"),
    }
}

/// What a refund or dispute of an order the ledger never granted adds.
const fn never_granted(granted: bool) -> &'static str {
    if granted {
        ""
    } else {
        " (an order Mooring never granted)"
    }
}
