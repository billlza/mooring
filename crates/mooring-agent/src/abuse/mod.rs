// SPDX-License-Identifier: GPL-3.0-or-later

//! The abuse guard on the node (design §11.8). Each served user's flows
//! leave Xray from the user's own source address inside the node
//! ([`mooring_agent_proto::user_source`]), so the kernel limits, measures
//! and cuts one user without seeing content or keeping a destination.
//!
//! - [`state`]: the cuts and records, one file, rewritten atomically under
//!   `gate.lock`.
//! - [`sets`]: what nft prints of the measured sets.
//! - [`detect`]: each served user's figures, and the findings they reach.
//! - [`requests`]: the operator's cut and lift (`AbuseCut`, `AbuseClear`).
//!
//! The cut set `abuse_cut` holds the addresses of the users cut. Every
//! ruleset load empties it and closes the gate in one transaction, and only
//! the watch opens the gate, with one nft command line that sets the cut
//! set and then opens the gate ([`open_words`]), so the gate is never open
//! with a cut missing.

pub(crate) mod detect;
pub(crate) mod requests;
pub(crate) mod sets;
pub(crate) mod state;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AbuseCuts, AbuseSet, InstalledWatchConfig, NFT_GATE_SET, NFT_TABLE, OpaqueUserId, Principal,
    WG_INTERFACE, user_source,
};

/// The users the installed generation serves, by source address.
pub(crate) fn served_sources(config: &InstalledWatchConfig) -> BTreeMap<Ipv4Addr, OpaqueUserId> {
    config
        .emails()
        .iter()
        .filter_map(|email| match &email.principal {
            Principal::User(user) => Some((user_source(user), user.clone())),
            Principal::Probe => None,
        })
        .collect()
}

/// The addresses the cut set holds: each cut user's, in address order. The
/// one address left out is a cut user's that belongs to another served user
/// who is not cut: the renderer refuses two served users with one address,
/// so the cut user is not served then, and cutting the address would cut
/// the other user instead.
pub(crate) fn cut_addresses(
    cuts: &AbuseCuts,
    served: &BTreeMap<Ipv4Addr, OpaqueUserId>,
) -> Vec<Ipv4Addr> {
    let mut addresses: Vec<Ipv4Addr> = cuts
        .entries()
        .iter()
        .filter_map(|cut| {
            let address = user_source(&cut.user);
            match served.get(&address) {
                Some(holder) if *holder != cut.user && cuts.get(holder).is_none() => None,
                _ => Some(address),
            }
        })
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// `{ a, b, … }`, the elements of an nft set command.
fn element_list(addresses: &[Ipv4Addr]) -> String {
    let list: Vec<String> = addresses.iter().map(ToString::to_string).collect();
    format!("{{ {} }}", list.join(", "))
}

/// The nft words that set `abuse_cut` to exactly `addresses`: a flush, then
/// an add when there are any. Given as one command line, nft commits them
/// in one transaction.
pub(crate) fn sync_words(addresses: &[Ipv4Addr]) -> Vec<String> {
    let set = AbuseSet::Cut.name();
    let mut words: Vec<String> = ["flush", "set", "inet", NFT_TABLE, set]
        .map(str::to_owned)
        .to_vec();
    if !addresses.is_empty() {
        words.extend([";", "add", "element", "inet", NFT_TABLE, set].map(str::to_owned));
        words.push(element_list(addresses));
    }
    words
}

/// The nft words that set the cut set as [`sync_words`] does and then open
/// the gate, as one command line, so one transaction.
pub(crate) fn open_words(addresses: &[Ipv4Addr]) -> Vec<String> {
    let mut words = sync_words(addresses);
    words.extend([";", "delete", "element", "inet", NFT_TABLE, NFT_GATE_SET].map(str::to_owned));
    words.push(format!("{{ \"{WG_INTERFACE}\" }}"));
    words
}

/// The nft words that add `addresses` to the cut set.
pub(crate) fn add_words(addresses: &[Ipv4Addr]) -> Vec<String> {
    let mut words: Vec<String> = ["add", "element", "inet", NFT_TABLE, AbuseSet::Cut.name()]
        .map(str::to_owned)
        .to_vec();
    words.push(element_list(addresses));
    words
}

/// Borrows owned words as the `&str` arguments a tool takes.
pub(crate) fn as_args(words: &[String]) -> Vec<&str> {
    words.iter().map(String::as_str).collect()
}
