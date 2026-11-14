// SPDX-License-Identifier: GPL-3.0-or-later

//! The guard's measured sets, as `nft -j list set inet mooring <set>`
//! prints them (design §11.8), parsed into each element's user address,
//! the second part of its key, its age and its counter.
//!
//! The shapes are libnftables' (`src/json.c`, `set_elem_expr_json`, the same
//! in nftables 1.0.9 and 1.1.3): a set with no element has no `elem` key;
//! an element with nothing but its key is the bare value, a string for an
//! address and `{"concat": [...]}` for a concatenated key; an element with
//! a timeout, an expiry or a statement is
//! `{"elem": {"val": ..., "timeout": s, "expires": s, "counter": {...}}}`,
//! in whole seconds, with its first statement only. Linux 6.12 leaves out
//! an element's `timeout` when it equals the set's default, which the set
//! object carries, so an element's age is the set's timeout less its
//! expiry. A protocol prints as its name (`"tcp"`), a port and a mark as
//! numbers. Keys the parser does not use are ignored; a value of the wrong
//! shape fails the whole reading, which the watch reports as the guard
//! unable to read (never as nothing found).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_agent_proto::{AbuseSet, NFT_TABLE};
use serde_json::Value;

use crate::host::{Node, Tool, run_ok};

/// A transport protocol in a meter's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Proto {
    Tcp,
    Udp,
}

/// An element's counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Counter {
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
}

/// One element of a measured set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Element {
    /// The user's source address, the key's first part.
    pub(crate) source: Ipv4Addr,
    /// The protocol, for the meters keyed by it.
    pub(crate) proto: Option<Proto>,
    /// Seconds since the element was made, when its expiry is known.
    pub(crate) age: Option<u64>,
    /// Its counter, for the sets that count.
    pub(crate) counter: Option<Counter>,
}

/// The elements of every measured set, at one reading.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Measured {
    sets: BTreeMap<AbuseSet, Vec<Element>>,
}

impl Measured {
    /// The elements of `set` (none for a set that was not read).
    pub(crate) fn elements(&self, set: AbuseSet) -> &[Element] {
        self.sets.get(&set).map_or(&[], Vec::as_slice)
    }

    /// A reading built from listings already parsed.
    #[cfg(test)]
    pub(crate) fn of(sets: BTreeMap<AbuseSet, Vec<Element>>) -> Self {
        Self { sets }
    }
}

/// Reads every measured set; `None` when nft fails for any of them or
/// prints something the parser does not read. One reading is all or
/// nothing, so no finding is decided on part of the sets.
pub(crate) fn read(node: &dyn Node) -> Option<Measured> {
    let mut sets = BTreeMap::new();
    for set in AbuseSet::ALL
        .iter()
        .copied()
        .filter(|set| set.is_measured())
    {
        let stdout = match run_ok(
            node,
            Tool::Nft,
            &["-j", "list", "set", "inet", NFT_TABLE, set.name()],
        ) {
            Ok(Ok(stdout)) => stdout,
            Ok(Err(_)) | Err(_) => return None,
        };
        sets.insert(set, parse(&stdout, set)?);
    }
    Some(Measured { sets })
}

/// The elements of `set` in one `nft -j list set` listing.
pub(crate) fn parse(stdout: &[u8], set: AbuseSet) -> Option<Vec<Element>> {
    let listing: Value = serde_json::from_slice(stdout).ok()?;
    let mut found = listing
        .get("nftables")?
        .as_array()?
        .iter()
        .filter_map(|item| item.get("set"));
    let object = found.next()?;
    if found.next().is_some() || object.get("name")?.as_str()? != set.name() {
        return None;
    }
    let timeout = match object.get("timeout") {
        None => set.timeout_secs(),
        Some(value) => Some(value.as_u64()?),
    };
    match object.get("elem") {
        None => Some(Vec::new()),
        Some(elements) => elements
            .as_array()?
            .iter()
            .map(|element| parse_element(element, set, timeout))
            .collect(),
    }
}

fn parse_element(element: &Value, set: AbuseSet, set_timeout: Option<u64>) -> Option<Element> {
    let (key, details) = match element.get("elem") {
        Some(wrapped) => (wrapped.get("val")?, Some(wrapped)),
        None => (element, None),
    };
    let parts: Vec<&Value> = match key.get("concat") {
        Some(concat) => concat.as_array()?.iter().collect(),
        None => vec![key],
    };
    let (first, rest) = parts.split_first()?;
    let source: Ipv4Addr = first.as_str()?.parse().ok()?;
    let proto = match (set, rest) {
        (AbuseSet::MeterNew | AbuseSet::MeterOut, [proto]) => Some(parse_proto(proto)?),
        (AbuseSet::MeterNew | AbuseSet::MeterOut, _) => return None,
        (
            AbuseSet::Dst | AbuseSet::Burst | AbuseSet::Login | AbuseSet::Mail | AbuseSet::Port,
            [second],
        ) => {
            second.as_u64()?;
            None
        }
        (
            AbuseSet::Dst | AbuseSet::Burst | AbuseSet::Login | AbuseSet::Mail | AbuseSet::Port,
            _,
        ) => {
            return None;
        }
        (_, []) => None,
        (_, _) => return None,
    };
    let (age, counter) = match details {
        None => (None, None),
        Some(details) => {
            let timeout = match details.get("timeout") {
                None => set_timeout,
                Some(value) => Some(value.as_u64()?),
            };
            let age = match details.get("expires") {
                None => None,
                Some(value) => {
                    let expires = value.as_u64()?;
                    timeout.map(|timeout| timeout.saturating_sub(expires))
                }
            };
            let counter = match details.get("counter") {
                None => None,
                Some(counter) => Some(Counter {
                    packets: counter.get("packets")?.as_u64()?,
                    bytes: counter.get("bytes")?.as_u64()?,
                }),
            };
            (age, counter)
        }
    };
    Some(Element {
        source,
        proto,
        age,
        counter,
    })
}

/// A protocol as nft prints it: its name, or its number when nft knows no
/// name for it (or prints numerically).
fn parse_proto(value: &Value) -> Option<Proto> {
    match (value.as_str(), value.as_u64()) {
        (Some("tcp"), _) | (None, Some(6)) => Some(Proto::Tcp),
        (Some("udp"), _) | (None, Some(17)) => Some(Proto::Udp),
        _ => None,
    }
}
