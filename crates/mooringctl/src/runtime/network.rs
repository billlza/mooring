// SPDX-License-Identifier: GPL-3.0-or-later

//! The network check's snapshot (design §10.2, P0-2): every interface's
//! IPv4 and IPv6 addresses from the kernel's interface list, its router's
//! identity and the DNS domain its network publishes from configd's IPv4
//! services, and the unscoped IPv4 default routes from the kernel's routing
//! table. `daemon-core`'s `network_check` judges it against the egress, the
//! uplink and the operator's declarations.
//!
//! The three reads are not one atomic snapshot. A default route whose
//! interface the list does not hold belongs to an interface that went away
//! between the two reads (the kernel removes an interface's routes with
//! it), so it is no attachment and is left out; an interface that appeared
//! after the route dump shows its addresses, which the check judges on
//! their own, and its route at the next tick, two seconds on. Two IPv4
//! services with a router on one interface identify no network: the
//! interface then has no router, so no declaration matches it (fail
//! closed). A DNS domain that is not a DNS name is no domain: the
//! institutional guard is advisory (`daemon-core::network`).
//!
//! What the snapshot does not hold: IPv6 default routes (there is no
//! AF_INET6 route dump); an interface that carries one holds a global IPv6
//! address, which is a finding already.

use std::collections::{BTreeMap, BTreeSet};

use mooring_daemon_core::network::{
    Exemptions, InterfaceObservation, IpFamily, NetworkCheck, NetworkSnapshot, network_check,
};
use mooring_macsys::{DefaultRoute, Interface, Ipv4Service};
use mooring_model::dns::DnsName;
use mooring_model::iface::{BsdName, RouterIdentity};
use mooring_model::own_network::OwnNetworks;

use crate::error::LocalError;

/// The snapshot `interfaces`, `routes` and `services` give; `services` is
/// `None` when configd could not be read, which leaves every router
/// unknown.
pub(crate) fn snapshot(
    interfaces: &[Interface],
    routes: &[DefaultRoute],
    services: Option<&[Ipv4Service]>,
) -> Result<NetworkSnapshot, LocalError> {
    let mut observed = BTreeMap::new();
    let mut names_by_index = BTreeMap::new();
    for interface in interfaces {
        let name = BsdName::parse(&interface.name).map_err(|_| LocalError::InterfaceName {
            name: interface.name.clone(),
        })?;
        names_by_index.insert(interface.index.get(), name.clone());
        let (router, domain) = services.map_or((None, None), |services| {
            router_and_domain(services, &interface.name)
        });
        observed.insert(
            name,
            InterfaceObservation {
                ipv4: interface.ipv4.iter().map(|address| address.addr).collect(),
                ipv6: interface.ipv6.iter().copied().collect(),
                router,
                domain,
            },
        );
    }
    let default_routes = routes
        .iter()
        .filter(|route| !route.scoped)
        .filter_map(|route| names_by_index.get(&route.interface_index))
        .map(|name| (IpFamily::V4, name.clone()))
        .collect::<BTreeSet<_>>();
    Ok(NetworkSnapshot {
        interfaces: observed,
        default_routes,
    })
}

/// The router identity and DNS domain of the one IPv4 service with a
/// router on `interface`; nothing when there is none, or more than one.
fn router_and_domain(
    services: &[Ipv4Service],
    interface: &str,
) -> (Option<RouterIdentity>, Option<DnsName>) {
    let mut routed = services
        .iter()
        .filter(|service| service.interface == interface && service.router.is_some());
    let (Some(service), None) = (routed.next(), routed.next()) else {
        return (None, None);
    };
    let router = service
        .router
        .zip(service.router_lladdr)
        .and_then(|(addr, lladdr)| RouterIdentity::from_observation(addr, lladdr));
    let domain = service
        .domain
        .as_deref()
        .and_then(|domain| DnsName::parse(&domain.to_ascii_lowercase()).ok());
    (router, domain)
}

/// The check of `snapshot` with `egress` and `uplink` exempt and `own`
/// declared.
pub(crate) fn check(
    snapshot: &NetworkSnapshot,
    egress: &BsdName,
    uplink: Option<&BsdName>,
    own: &OwnNetworks,
) -> NetworkCheck {
    network_check(
        snapshot,
        &Exemptions {
            egress: egress.clone(),
            uplink: uplink.cloned(),
            own,
        },
    )
}
