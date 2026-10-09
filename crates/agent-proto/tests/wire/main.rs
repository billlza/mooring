// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests of the Mac–agent wire protocol.
//!
//! Every module is test code, including helpers that are not `#[test]`
//! functions (fixtures, strategies, golden assertions); `#[cfg(test)]`
//! declares that, so the workspace's test-only allowances in `clippy.toml`
//! cover them as they cover `#[test]` functions.

#[cfg(test)]
mod deadman;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod framing;
#[cfg(test)]
mod frozen_core;
#[cfg(test)]
mod golden;
#[cfg(test)]
mod kinds;
#[cfg(test)]
mod limits;
#[cfg(test)]
mod protocol_goldens;
#[cfg(test)]
mod report;
#[cfg(test)]
mod required;
#[cfg(test)]
mod roles;
#[cfg(test)]
mod roundtrip;
