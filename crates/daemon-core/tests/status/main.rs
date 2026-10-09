// SPDX-License-Identifier: GPL-3.0-or-later

//! `MacStatusV1`: the contract fixtures Mooring.app decodes, the status
//! document's invariants, and what leaves the Mac from it (the push notices
//! and the remote viewer's report), through the public API only.
//!
//! Every module is test code, including helpers that are not `#[test]`
//! functions (the scenarios and their builders); `#[cfg(test)]` declares
//! that, so the workspace's test-only allowances in `clippy.toml` cover
//! them as they cover `#[test]` functions.

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod invariants;
#[cfg(test)]
mod notify;
#[cfg(test)]
mod report;
#[cfg(test)]
mod scenarios;
#[cfg(test)]
mod support;
