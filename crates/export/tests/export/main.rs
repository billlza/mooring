// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests of `mooring-export` against the fixture deployments.
//!
//! Every module is test code, including helpers that are not `#[test]`
//! functions; `#[cfg(test)]` declares that, so the workspace's test-only
//! allowances in `clippy.toml` cover them as they cover `#[test]` functions.

#[cfg(test)]
mod certificates;
#[cfg(test)]
mod documents;
#[cfg(test)]
mod goldens;
#[cfg(test)]
mod kinds;
#[cfg(test)]
mod probes;
#[cfg(test)]
mod refusals;
#[cfg(test)]
mod support;
