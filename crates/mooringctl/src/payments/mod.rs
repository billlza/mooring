// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull (design §9.6): the daemon's pull of the entitlements
//! the user portal lists, and the operator's commands for it.
//!
//! - [`curl`]: the one request, made by `/usr/bin/curl`, with the token or
//!   Stripe's read key on its standard input.
//! - [`judge`]: what an answer, the portal's or Stripe's, comes to.
//! - [`pull`]: the daemon's [`Puller`](pull::Puller): when to ask, the
//!   ledger written before it is kept, and stops.
//! - [`confirm`]: a page that waits for the check against Stripe.
//! - [`notes`]: the lines it logs.
//! - [`command`]: `portal connect | rehearsal | disconnect | payments`,
//!   and the paid entitlements the portal snapshot reads.
//! - [`stripe_check`]: `portal stripe-check on | off`.
//! - [`listing`]: what `portal payments` prints.

pub(crate) mod command;
pub(crate) mod confirm;
pub(crate) mod curl;
mod error;
pub(crate) mod judge;
pub(crate) mod listing;
pub(crate) mod notes;
pub(crate) mod pull;
pub(crate) mod stripe_check;

pub(crate) use curl::{Curl, PortalLink};
pub(crate) use error::PaymentFileError;
