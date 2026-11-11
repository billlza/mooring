// SPDX-License-Identifier: GPL-3.0-or-later

//! The payment pull (design §9.6): the daemon's pull of the entitlements
//! the user portal lists, and the operator's commands for it.
//!
//! - [`curl`]: the one request, made by `/usr/bin/curl`, with the token on
//!   its standard input.
//! - [`judge`]: what an answer comes to.
//! - [`pull`]: the daemon's [`Puller`](pull::Puller): when to ask, the
//!   ledger written before it is kept, and stops.
//! - [`notes`]: the lines it logs.
//! - [`command`]: `portal connect | rehearsal | disconnect | payments`,
//!   and the paid entitlements the portal snapshot reads.
//! - [`listing`]: what `portal payments` prints.

pub(crate) mod command;
pub(crate) mod curl;
mod error;
pub(crate) mod judge;
pub(crate) mod listing;
pub(crate) mod notes;
pub(crate) mod pull;

pub(crate) use curl::{Curl, PortalLink};
pub(crate) use error::PaymentFileError;
