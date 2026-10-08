// SPDX-License-Identifier: GPL-3.0-or-later

//! Node addresses as both renderers deny them (design §8.2, §8.7): every
//! address a node VM still holds is denied to every identity, except that
//! the probe may reach each node's reflector port over TCP.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use mooring_model::Deployment;
use mooring_model::ports::Port;

use crate::error::RenderError;

/// Every live node address, and the reflector each one serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeReach {
    /// Every address a node VM still holds, in node id order.
    pub(crate) addresses: Vec<Ipv4Addr>,
    /// The same addresses grouped by reflector port, in port order.
    pub(crate) reflectors: BTreeMap<Port, Vec<Ipv4Addr>>,
}

impl NodeReach {
    pub(crate) fn of(deployment: &Deployment) -> Result<Self, RenderError> {
        let mut addresses = Vec::new();
        let mut reflectors: BTreeMap<Port, Vec<Ipv4Addr>> = BTreeMap::new();
        for (id, address) in deployment.node_addresses() {
            let port = deployment.node(&id)?.ports.reflector();
            addresses.push(address.ipv4());
            reflectors.entry(port).or_default().push(address.ipv4());
        }
        Ok(Self {
            addresses,
            reflectors,
        })
    }
}
