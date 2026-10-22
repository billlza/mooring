// SPDX-License-Identifier: GPL-3.0-or-later

//! The tool's tests: the protocol, the arithmetic and the command line as
//! pure functions, and every measurement against a real `serve` on the
//! loopback interface. None sends a packet off this machine.

mod cli;
#[cfg(target_os = "macos")]
mod env;
mod loopback;
mod output;
mod search;
mod stats;
mod wire;
