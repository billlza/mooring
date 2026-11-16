// SPDX-License-Identifier: GPL-3.0-or-later

//! The operator's make-ups (design §9.6; the agreement's clauses 1 and 3),
//! decided against the deployment: the user named must be one it holds,
//! and traffic goes only to a user who has a quota now, which the ledger
//! cannot know. The ledger records the rest
//! ([`PaymentLedger::make_up`]).

use mooring_model::{Deployment, UnixTime, UserId};

use crate::payments::{MadeUp, MakeUpAsk, MakeUpReason, MakeUpRefusal, PaymentLedger};
use crate::period::BillingCycle;
use crate::policy::{automatic_quota, effective_policy};

/// The make-up `ask` gives `user` at `now`, for `reason`, recorded on a
/// copy of `ledger`, for the users of `deployment`; `rehearsal` when the
/// operator rehearses, which decides whether Stripe's test-mode orders
/// count towards the user's quota now. Refused, and nothing recorded, for
/// a user the deployment does not hold, for each refusal of the ledger's,
/// and for traffic when the user has no quota now (`NoQuota`), or when
/// their quota cannot be computed (`QuotaUnknown`).
pub fn decide(
    ledger: &PaymentLedger,
    deployment: &Deployment,
    rehearsal: bool,
    user: &UserId,
    ask: MakeUpAsk,
    reason: MakeUpReason,
    now: UnixTime,
) -> Result<MadeUp, MakeUpRefusal> {
    let record = deployment
        .users()
        .get(user)
        .ok_or(MakeUpRefusal::UnknownUser)?;
    let made_up = ledger.make_up(record, ask, reason, now)?;
    if let MakeUpAsk::TrafficBytes(_) = ask {
        let cycle = BillingCycle::of_instant(deployment.exit().sim.cycle(), now)
            .map_err(|_| MakeUpRefusal::QuotaUnknown)?;
        let automatic =
            automatic_quota(deployment, now).map_err(|_| MakeUpRefusal::QuotaUnknown)?;
        let paid = ledger.entitlements(rehearsal);
        if effective_policy(record, automatic, &paid, cycle, now, None)
            .quota
            .is_none()
        {
            return Err(MakeUpRefusal::NoQuota);
        }
    }
    Ok(made_up)
}
