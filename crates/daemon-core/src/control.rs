// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's control channel (design §10.1): over `run/control.sock`,
//! mode 0600 inside the 0700 support directory, the CLI writes one request
//! line and the daemon answers with reply lines, each one JSON document and
//! a newline, each within its bound. The CLI is the only client: Mooring.app
//! runs the CLI, never the socket.
//!
//! [`DaemonRequest::Status`] answers with the latest status once, and
//! [`DaemonRequest::Subscribe`] with the latest and then each new one,
//! until either side closes. [`DaemonRequest::Retry`] (`exit retry`, M5c)
//! is queued for the daemon's next tick and answered
//! [`DaemonReply::RetryQueued`]. A request the daemon will not serve is
//! answered with [`DaemonReply::Refused`], after which it closes the
//! connection.

use serde::{Deserialize, Serialize};

use crate::console::ConsoleStatus;
use crate::error::ControlError;

/// The daemon's runtime directory, in the support directory (design §5.1:
/// the control socket, latches and engine pid files live there).
pub const RUN_DIRECTORY: &str = "run";

/// The control socket's file name, in [`RUN_DIRECTORY`].
pub const CONTROL_SOCKET_FILE: &str = "control.sock";

/// The longest request line, its newline included. Every request is a few
/// bytes; the bound only refuses a client that sends something else.
pub const MAX_REQUEST_LINE_BYTES: usize = 256;

/// The longest reply line, its newline included: 1 MiB, the bound of the
/// agent protocol's lines. A status of the 20-user fixture deployment is a
/// few tens of KiB (`a_reply_line_holds_the_largest_fixture_status`).
pub const MAX_REPLY_LINE_BYTES: usize = 1 << 20;

/// What the CLI asks the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonRequest {
    /// The latest status, once.
    Status,
    /// The latest status, then each new one, until either side closes.
    Subscribe,
    /// Clear the exit's latch and holds and run a fresh preflight
    /// (`exit retry`, design §10.2).
    Retry,
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
    /// The request is about the exit, and there is no deployment yet.
    NotDeployed,
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

/// One JSON document on one line within `max` bytes, its newline
/// included. A line with a newline inside it, or anything after the
/// document, is malformed.
fn decode_line<T: for<'de> Deserialize<'de>>(line: &[u8], max: usize) -> Result<T, ControlError> {
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
