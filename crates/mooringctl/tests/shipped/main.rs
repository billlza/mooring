// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests of the `mooringctl` binary as it is built: its `main`
//! wires the environment every command runs in, which the in-process tests
//! replace with their own, so what `main` passes is checked here.
//!
//! Every module is test code; `#[cfg(test)]` declares that, so the
//! workspace's test-only allowances in `clippy.toml` cover them as they
//! cover `#[test]` functions.

#[cfg(test)]
mod portal_gate;
