// SPDX-License-Identifier: GPL-3.0-or-later

//! The console core of the exit Mac (design §15, console spec B.1-B.9): the
//! data model of `mooringctl status --follow --json` ([`MacStatusV1`]) and
//! the pure logic the daemon (M5) and Mooring.app (M7) build on.
//!
//! - [`exit`]: the exit's state machine: preflight, supervision of
//!   `mooring-exit`, direct probes, verdicts and latches.
//! - [`meter`]: the SIM meter, the line's bytes per UTC day from the
//!   egress interface's counters.
//! - [`forecast`]: the SIM forecast from the meter's daily bins.
//! - [`capacity`]: whether the uplink over the mobile line is saturated.
//! - [`usage`]: per-user usage from the agents' usage series, and activity.
//! - [`alert`]: alert conditions and the alert state machine.
//! - [`notify`]: the push notices and the daily digest (Level 0).
//! - [`network`]: the foreign-network check.
//! - [`policy`]: quota (own and automatic) and expiry evaluation.
//! - [`router`]: the M7's status types, and the MR7450 `model.json`
//!   allowlist parser and redactor ([`router::netgear`]).
//! - [`status`]: [`MacStatusV1`] itself.
//! - [`snapshot`]: a [`MacStatusV1`] assembled from what the daemon holds
//!   at one instant.
//! - [`console`]: [`ConsoleStatus`], the console's document: the
//!   deployment's status, or the router alone before `exit init`.
//! - [`control`]: the daemon's control channel, its requests, replies and
//!   line bounds.
//! - [`report`]: the remote viewer's report projected from it.
//!
//! # Purity
//!
//! Nothing here performs I/O, reads a clock, draws randomness or opens a
//! socket. Every input is a typed snapshot the daemon passes in (the
//! deployment, the agents' replies, the meter's bins, interface lists), and
//! every result is a value; applying one (suspending a user, sending a
//! notice) is the caller's explicit act.
//!
//! # Periods
//!
//! Every period is on the UTC calendar and named so ([`period`]); local
//! time is the app's to draw.
//!
//! # Operator decisions
//!
//! Decided on 2026-10-08 and modelled here: automatic quotas from 6 active
//! users (F4, [`policy::automatic_quota`]), the push notices and digest
//! of the alert channels (F6, [`notify`]; the node's dead-man pings are
//! agent-proto's `dead_man_pings`, because the node decides them alone), and
//! the remote viewer's report (F5, [`report`]). Decided on 2026-10-15 by
//! delegation and kept outside this crate: retention (F7, the caller's
//! ledger) and the agreement requirement (F9, `mooring-export`'s). Still
//! pending, so nothing here presumes them: expiry defaults.

#![deny(missing_docs)]

pub mod alert;
pub mod capacity;
pub mod console;
pub mod control;
pub mod error;
pub mod exit;
pub mod forecast;
pub mod meter;
pub mod network;
pub mod notify;
pub mod period;
pub mod policy;
pub mod report;
pub mod router;
pub mod share;
pub mod snapshot;
pub mod status;
pub mod usage;
mod wire;

#[cfg(test)]
mod tests;

pub use alert::{
    AlertCondition, AlertConditionKind, AlertKey, AlertMachine, AlertNotice, AlertSubject,
    AlertTiming, OpenAlert, Severity,
};
pub use capacity::{CapacityMonitor, CapacitySample, CapacityStatus, CapacityThresholds};
pub use console::{ConsoleStatus, UNDEPLOYED_STATUS_VERSION, UndeployedStatus};
pub use control::{DaemonReply, DaemonRequest, Refusal};
pub use error::{
    AlertError, AlertErrorKind, CapacityError, CapacityErrorKind, CarrierFaultKind, ConsoleError,
    ConsoleErrorKind, ControlError, ControlErrorKind, FieldFaultKind, FigureError, FigureErrorKind,
    ForecastError, ForecastErrorKind, NotifyError, NotifyErrorKind, PolicyError, PolicyErrorKind,
    ReportError, ReportErrorKind, RouterParseError, RouterParseErrorKind, RouterValueError,
    RouterValueErrorKind, StatusError, StatusErrorKind, UsageError, UsageErrorKind,
};
pub use forecast::{DailySimBytes, SimForecast};
pub use network::{ForeignNetworkFinding, NetworkSnapshot, foreign_networks};
pub use period::{BillingCycle, UsagePeriods};
pub use policy::{ExpiryState, PolicyAction, QuotaState, UserAction};
pub use router::{RouterReading, RouterStatus};
pub use snapshot::{NodePoll, SimTotals, SnapshotError, StatusInputs, assemble};
pub use status::{MAC_STATUS_VERSION, MacStatusParts, MacStatusV1};
pub use usage::{NodeLedger, UsageReport, UserUsage};
