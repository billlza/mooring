// SPDX-License-Identifier: GPL-3.0-or-later

//! The check against Stripe in the daemon's pull (design §9.6): a page the
//! portal sent while the check is on waits here, in memory, until Stripe
//! has said what it knows of each live grant on it that would give a
//! period or a pack ([`PaymentLedger::apply_checked`]).
//!
//! - **What to ask is worked out again each time** from the ledger, the
//!   deployment's users and what Stripe said so far: a user revoked
//!   meanwhile is held without asking, and a lookup whose grant no longer
//!   needs one is dropped.
//! - **A lookup that needs no request** (a renewal whose first order
//!   Mooring does not hold) is done at once; every other asks one page of
//!   Stripe's at a time, which the pull makes as its one request of a
//!   tick.
//! - **Nothing of the page is written until it is applied whole.** It is
//!   fetched again, and Stripe asked again, after the settings change, a
//!   stop, or a start of the daemon.

use std::collections::BTreeMap;

use mooring_daemon_core::payments::{
    Applied, ApplyRefusal, Checked, Confirmable, FeedPage, Lookup, Next, OrderId, PaymentLedger,
    StripeAnswerError, Verdicts,
};
use mooring_model::{UnixTime, User, UserId};

/// A page that waits for the check against Stripe.
#[derive(Debug)]
pub(crate) struct Pending {
    /// The page, as the portal sent it.
    page: FeedPage,
    /// What Stripe said so far, by order.
    verdicts: Verdicts,
    /// The lookup under way, if any: the grant it is of, and its next page.
    lookup: Option<Lookup>,
}

/// What a page that waits needs next.
#[derive(Debug)]
pub(crate) enum Wanted {
    /// Nothing more of Stripe: the page, applied to a copy of the ledger.
    Apply(Applied),
    /// The page cannot be applied, as without the check.
    Refused(ApplyRefusal),
    /// Stripe must be asked: the lookup's next request, and how many
    /// grants the page still waits for, this one included.
    Ask {
        /// The lookup.
        lookup: Lookup,
        /// The grants still to confirm.
        left: usize,
    },
}

impl Pending {
    /// `page`, with nothing asked yet. The pull drops it when the settings
    /// change.
    pub(crate) fn new(page: FeedPage) -> Self {
        Self {
            page,
            verdicts: BTreeMap::new(),
            lookup: None,
        }
    }

    /// The page.
    pub(crate) const fn page(&self) -> &FeedPage {
        &self.page
    }

    /// What the page needs next, applied to `ledger` at `now` for `users`
    /// and the `rehearsal`: lookups that need no request are done here.
    pub(crate) fn wanted(
        &mut self,
        ledger: &PaymentLedger,
        users: &BTreeMap<UserId, User>,
        now: UnixTime,
        rehearsal: bool,
    ) -> Wanted {
        loop {
            let (next, rest) =
                match ledger.apply_checked(&self.page, users, now, rehearsal, &self.verdicts) {
                    Err(refusal) => return Wanted::Refused(refusal),
                    Ok(Checked::Applied(applied)) => return Wanted::Apply(applied),
                    Ok(Checked::Unconfirmed { next, rest }) => (*next, rest),
                };
            let left = rest.len() + 1;
            if let Some(lookup) = self
                .lookup
                .as_ref()
                .filter(|lookup| lookup.target() == &next)
            {
                return Wanted::Ask {
                    lookup: lookup.clone(),
                    left,
                };
            }
            match start(next) {
                (_, Next::Ask(lookup)) => {
                    self.lookup = Some(lookup.clone());
                    return Wanted::Ask { lookup, left };
                }
                (order, Next::Done(verdict)) => {
                    self.lookup = None;
                    self.verdicts.insert(order, verdict);
                }
            }
        }
    }

    /// Reads Stripe's answer to `lookup`, the one [`Self::wanted`] asked
    /// with: its verdict is kept, or the lookup goes on with its next page.
    /// An answer that cannot be read changes nothing, and the same page is
    /// asked for again.
    pub(crate) fn read(&mut self, lookup: Lookup, body: &[u8]) -> Result<(), StripeAnswerError> {
        let order = lookup.target().order.clone();
        match lookup.read(body)? {
            Next::Ask(next) => self.lookup = Some(next),
            Next::Done(verdict) => {
                self.lookup = None;
                self.verdicts.insert(order, verdict);
            }
        }
        Ok(())
    }
}

/// The lookup of `target`, with its order.
fn start(target: Confirmable) -> (OrderId, Next) {
    let order = target.order.clone();
    (order, Lookup::start(target))
}
