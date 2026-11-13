// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's control channel (design §10.1): over `run/control.sock`,
//! mode 0600 inside the 0700 support directory, the CLI writes one request
//! line and the daemon answers with reply lines, each one JSON document and
//! a newline, each within its bound. The CLI is the only client: Mooring.app
//! runs the CLI, never the socket.
//!
//! The daemon's first line on every connection, before any reply, names
//! the protocol it speaks ([`ProtocolLine`], design §15.1), so that a
//! client of another protocol, such as an app updated under a daemon not
//! yet restarted, says so instead of failing to read a reply.
//!
//! [`DaemonRequest::Status`] answers with the latest status once, and
//! [`DaemonRequest::Subscribe`] with the latest and then each new one,
//! until either side closes. [`DaemonRequest::Retry`] (`exit retry`, M5c)
//! is queued for the daemon's next tick and answered
//! [`DaemonReply::RetryQueued`]. [`DaemonRequest::AcceptSimNetwork`] (`sim
//! accept-network`, design §10.2) waits for the daemon's loop, which
//! takes the network named as the SIM's network on record and answers
//! [`DaemonReply::SimNetworkAccepted`], or refuses and changes nothing. A
//! request the daemon will not serve is answered with
//! [`DaemonReply::Refused`], after which it closes the connection.

use serde::{Deserialize, Serialize};

use crate::console::ConsoleStatus;
use crate::error::ControlError;
use crate::sim_network::{NotAccepted, SimNetwork};

/// The daemon's runtime directory, in the support directory (design §5.1:
/// the control socket, latches and engine pid files live there).
pub const RUN_DIRECTORY: &str = "run";

/// The control socket's file name, in [`RUN_DIRECTORY`].
pub const CONTROL_SOCKET_FILE: &str = "control.sock";

/// The longest request line, its newline included. Every request is
/// short, the longest one that names a network, 143 bytes with the longest
/// name a SIM can carry (`the_longest_request_fits_a_request_line`); the
/// bound only refuses a client that sends something else.
pub const MAX_REQUEST_LINE_BYTES: usize = 256;

/// The longest reply line, its newline included: 1 MiB, the bound of the
/// agent protocol's lines. A status of the 20-user fixture deployment is a
/// few tens of KiB (`a_reply_line_holds_the_largest_fixture_status`).
pub const MAX_REPLY_LINE_BYTES: usize = 1 << 20;

/// The control channel's protocol (design §15.1), which the daemon names
/// on the first line of every connection. From the first release on, any
/// change to a request, a reply or this line's own shape raises it:
/// protocol 3 (2026-11-12) carries the status of version 3 in its `status`
/// reply, and protocol 4 (2026-11-12) the status of version 4, and adds
/// the `accept_sim_network` request with its reply and its refusals.
pub const CONTROL_PROTOCOL: u32 = 4;

/// The first line of every connection: the protocol the daemon speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLine {
    /// The daemon's [`CONTROL_PROTOCOL`].
    pub control_protocol: u32,
}

impl ProtocolLine {
    /// The line this build's daemon sends.
    pub const CURRENT: Self = Self {
        control_protocol: CONTROL_PROTOCOL,
    };
}

/// What the CLI asks the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonRequest {
    /// The latest status, once.
    Status,
    /// The latest status, then each new one, until either side closes.
    Subscribe,
    /// Clear the exit's latch and holds and run a fresh preflight
    /// (`exit retry`, design §10.2).
    Retry,
    /// Take `network` as the SIM's network on record (`sim
    /// accept-network`, design §10.2). It is the network the operator was
    /// shown as the one the M7 reports: the daemon takes it only while its
    /// record and its latest poll of the M7 still say so.
    AcceptSimNetwork {
        /// The network to take.
        network: SimNetwork,
    },
}

/// Why the daemon refused a request. It closes the connection after
/// saying so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// The daemon already serves as many clients as it accepts.
    Busy,
    /// The request was not one line holding a known request within
    /// [`MAX_REQUEST_LINE_BYTES`], or did not arrive in time.
    BadRequest,
    /// No status exists yet: the daemon's first poll has not finished. Only
    /// a `Status` request is refused for it; a subscription waits for the
    /// first status.
    NoStatusYet,
    /// The request needs a deployment, and there is none yet.
    NotDeployed,
    /// `accept_sim_network`: the daemon's record holds no network other
    /// than the one on record, so there is nothing to take.
    NoOtherSimNetwork,
    /// `accept_sim_network`: the daemon's latest poll of the M7 failed or
    /// found no data session, so what the M7 reports now is not known.
    M7NotAttached,
    /// `accept_sim_network`: the M7 no longer reports the network the
    /// request names.
    SimNetworkReportChanged,
    /// The daemon's loop did not come to the request in the time the
    /// connection waits for it. Nothing was changed.
    LoopBusy,
}

impl From<NotAccepted> for Refusal {
    fn from(reason: NotAccepted) -> Self {
        match reason {
            NotAccepted::NoOtherNetwork => Self::NoOtherSimNetwork,
            NotAccepted::NotAttached => Self::M7NotAttached,
            NotAccepted::ReportChanged => Self::SimNetworkReportChanged,
        }
    }
}

/// One line the daemon sends.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DaemonReply {
    /// A status.
    Status(ConsoleStatus),
    /// The request was refused.
    Refused {
        /// Why.
        reason: Refusal,
    },
    /// The retry is queued: the daemon's next tick runs it.
    RetryQueued,
    /// The network the request named is the SIM's network on record now.
    SimNetworkAccepted,
}

/// `value` as one line: its compact JSON and a newline, refused when the
/// line would be longer than `max` bytes (`LineTooLong`).
pub fn encode_line<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>, ControlError> {
    let mut line = serde_json::to_vec(value).map_err(|_| ControlError::Unencodable)?;
    line.push(b'\n');
    if line.len() > max {
        return Err(ControlError::LineTooLong {
            bytes: line.len(),
            max,
        });
    }
    Ok(line)
}

/// A request line (with or without its newline).
pub fn decode_request(line: &[u8]) -> Result<DaemonRequest, ControlError> {
    decode_line(line, MAX_REQUEST_LINE_BYTES)
}

/// A reply line (with or without its newline).
pub fn decode_reply(line: &[u8]) -> Result<DaemonReply, ControlError> {
    decode_line(line, MAX_REPLY_LINE_BYTES)
}

/// A connection's first line (with or without its newline), within the
/// bound of a reply line.
pub fn decode_protocol_line(line: &[u8]) -> Result<ProtocolLine, ControlError> {
    decode_line(line, MAX_REPLY_LINE_BYTES)
}

/// One JSON document on one line within `max` bytes, its newline
/// included. A line with a newline inside it, or anything after the
/// document, is malformed.
pub(crate) fn decode_line<T: for<'de> Deserialize<'de>>(
    line: &[u8],
    max: usize,
) -> Result<T, ControlError> {
    let bytes = line.len();
    if bytes > max {
        return Err(ControlError::LineTooLong { bytes, max });
    }
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    if body.contains(&b'\n') {
        return Err(ControlError::Malformed);
    }
    serde_json::from_slice(body).map_err(|_| ControlError::Malformed)
}
