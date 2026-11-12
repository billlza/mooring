// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines the payment pull and `portal payments` write: instants in UTC
//! and each event of an applied page, by order id and user id (both
//! opaque), never with the token or a label. A refund's line names the
//! order only, with what it took back or that it waits for the usage; so
//! does the line that ends such a wait.

use mooring_daemon_core::payments::{
    GrantOutcome, LedgerEvent, OrderId, PackUse, RefundEffect, TimeTakenBack,
};
use mooring_model::UnixTime;
use mooring_model::user::SuspendReason;

use crate::router::output::utc_stamp;

/// `at` as `YYYY-MM-DD hh:mm:ss UTC`, or its seconds when it is past the
/// calendar, which only a clock gone wrong gives.
pub(crate) fn stamp(at: UnixTime) -> String {
    utc_stamp(at).unwrap_or_else(|_| at.to_string())
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
            format!("payment: order {order} granted user {user} {what}{mode}{suspended}")
        }
        LedgerEvent::Held {
            order,
            user,
            reason,
        } => format!(
            "payment: order {order} for user {user} is held, not granted ({}); settle it at Stripe",
            reason.as_str()
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
            taken_back(&RefundEffect::Pack(*used))
        ),
    }
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
        RefundEffect::Pack(PackUse::Served { bytes, learned_at }) => format!(
            "its pack counts from {} on only what the user had used of it beyond the rest of their quota: {bytes} bytes served this cycle by the refund's time",
            stamp(*learned_at)
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
