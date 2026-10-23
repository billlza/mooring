// SPDX-License-Identifier: GPL-3.0-or-later

//! The foreign-network check's snapshot (design §10.2, P0-2), from the
//! kernel's interface list: every interface's IPv4 addresses, the egress
//! exempt. `daemon-core`'s `foreign_networks` judges it.
//!
//! What the snapshot does not hold yet, with why that leaves no gap that
//! matters to the check: IPv6 addresses (`macsys` lists IPv4 only), default
//! routes (an interface that carries one holds a routable IPv4 address,
//! which is a finding already), and the personal-hotspot flag (a joined
//! hotspot gives its interface a routable IPv4 address too). CFM's TUN is
//! not exempt: while it is on, the exit is down with it named.

use std::collections::{BTreeMap, BTreeSet};

use mooring_daemon_core::network::{
    Exemptions, ForeignNetworkFinding, InterfaceObservation, NetworkSnapshot, foreign_networks,
};
use mooring_macsys::Interface;
use mooring_model::iface::BsdName;

use crate::error::LocalError;

/// The foreign networks `interfaces` show, `egress` exempt.
pub(crate) fn foreign(
    interfaces: &[Interface],
    egress: &BsdName,
) -> Result<BTreeSet<ForeignNetworkFinding>, LocalError> {
    let mut observed = BTreeMap::new();
    for interface in interfaces {
        let name = BsdName::parse(&interface.name).map_err(|_| LocalError::InterfaceName {
            name: interface.name.clone(),
        })?;
        observed.insert(
            name,
            InterfaceObservation {
                ipv4: interface.ipv4.iter().map(|address| address.addr).collect(),
                ipv6: BTreeSet::new(),
                personal_hotspot: false,
            },
        );
    }
    let snapshot = NetworkSnapshot {
        interfaces: observed,
        default_routes: BTreeSet::new(),
    };
    Ok(foreign_networks(
        &snapshot,
        &Exemptions {
            egress: egress.clone(),
            tunnels: BTreeSet::new(),
        },
    ))
}
