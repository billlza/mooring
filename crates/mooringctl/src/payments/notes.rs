// SPDX-License-Identifier: GPL-3.0-or-later

//! The lines the payment pull and `portal payments` write: instants in UTC
//! and each event of an applied page, by order id and user id (both
//! opaque), never with the token or a label.

use mooring_daemon_core::payments::{GrantOutcome, LedgerEvent};
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
                    "; the user is suspended for quota until the next billing cycle, when the nightly apply job resumes them"
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
            user,
            amount_refunded,
            in_full,
            granted,
        } => format!(
            "payment: order {order} of user {user} refunded {amount_refunded} so far{}{}; recorded, nothing changed",
            if *in_full { ", in full" } else { "" },
            never_granted(*granted)
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
