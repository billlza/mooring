// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests of `mooringctl ssh-relay`, management SSH's
//! ProxyCommand, run as ssh runs it: the real binary, whose `main` holds
//! the process's stdin and stdout as it does for every command, with pipes
//! for its standard input and output and a one-time socket.
//!
//! Every module is test code; `#[cfg(test)]` declares that, so the
//! workspace's test-only allowances in `clippy.toml` cover them as they
//! cover `#[test]` functions.

#[cfg(test)]
mod ssh_relay;
