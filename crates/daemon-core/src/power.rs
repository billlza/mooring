// SPDX-License-Identifier: GPL-3.0-or-later

//! The power helper's protocol (design §5.1, §10.3). `mooring-power`, a
//! Swift child of the daemon in the app's bundle, holds the assertions that
//! keep the Mac awake while the exit serves on mains, reports the power
//! source, and tells the daemon when macOS is about to sleep, holding the
//! sleep until the daemon has drained the nodes. The two talk in JSON
//! lines: [`HelperEvent`] on the helper's stdout, [`HelperCommand`] on its
//! stdin, which is also its lifetime: at its end the helper releases
//! everything and exits, so a daemon that dies never leaves an assertion
//! held.

use serde::{Deserialize, Serialize};

use crate::control::{decode_line, encode_line};
use crate::error::ControlError;
use crate::status::PowerSource;

/// The longest line either side writes, its newline included.
pub const MAX_HELPER_LINE_BYTES: usize = 256;

/// The helper's own limit on a sleep the daemon has not acknowledged: past
/// it the helper lets the sleep proceed, inside IOKit's 30 s window. The
/// daemon's drain has a 4 s budget, so only a daemon that hangs meets it.
pub const HELPER_ALLOW_SLEEP_AFTER_SECS: u64 = 25;

/// What the helper tells the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperEvent {
    /// The source macOS draws power from: at start, and at each change.
    PowerSource(PowerSource),
    /// Whether the helper holds its assertions, after each command that
    /// changes them.
    Assertions {
        /// Held.
        held: bool,
    },
    /// macOS will sleep: the helper holds the sleep until the daemon
    /// answers [`HelperCommand::AllowSleep`] with this `id`, or for at most
    /// [`HELPER_ALLOW_SLEEP_AFTER_SECS`].
    WillSleep {
        /// The sleep's number, counted by the helper from 1.
        id: u64,
    },
    /// macOS woke.
    DidWake,
}

/// What the daemon tells the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HelperCommand {
    /// Hold (`true`) or release (`false`) `NetworkClientActive` and
    /// `PreventUserIdleSystemSleep`.
    Hold(bool),
    /// Let the sleep `id` proceed.
    AllowSleep {
        /// The sleep's number, from [`HelperEvent::WillSleep`].
        id: u64,
    },
}

/// One event line, as the helper writes it.
pub fn encode_event(event: &HelperEvent) -> Result<Vec<u8>, ControlError> {
    encode_line(event, MAX_HELPER_LINE_BYTES)
}

/// One command line, as the daemon writes it.
pub fn encode_command(command: &HelperCommand) -> Result<Vec<u8>, ControlError> {
    encode_line(command, MAX_HELPER_LINE_BYTES)
}

/// An event line, with or without its newline.
pub fn decode_event(line: &[u8]) -> Result<HelperEvent, ControlError> {
    decode_line(line, MAX_HELPER_LINE_BYTES)
}

/// A command line, with or without its newline.
pub fn decode_command(line: &[u8]) -> Result<HelperCommand, ControlError> {
    decode_line(line, MAX_HELPER_LINE_BYTES)
}
