// SPDX-License-Identifier: GPL-3.0-or-later

//! Interface resolution (design §10.1 step 2, §10.2 preflight): the one
//! interface an `InterfaceSelector` selects, from the kernel's interface
//! list, and the exit site's interfaces resolved with it. A `LinkAddr`
//! selector names the interface's own link-layer address; a
//! `GatewayLinkAddr` selector names its default gateway's, which the
//! neighbour table gives. An interface the selector identifies must then
//! hold an IPv4 address in the selector's subnet. There is never a
//! fallback to another interface.

use mooring_daemon_core::exit::{Egress, EgressFault};
use mooring_daemon_core::status::LinkState;
use mooring_macsys::{Interface, MacsysError};
use mooring_model::ModelError;
use mooring_model::exit::{ExitSite, Uplink};
use mooring_model::iface::{
    BsdName, InterfaceIndex, InterfaceRole, InterfaceSelector, MacAddr, ResolvedInterface,
    ResolvedUplink,
};

use crate::error::LocalError;
use crate::router::link::LinkLayer;

/// Why a selector selected no single interface.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    /// No up and running interface is the selected one.
    #[error("no interface matches the selector")]
    Absent,
    /// Several interfaces are.
    #[error("{count} interfaces match the selector")]
    Ambiguous {
        /// How many.
        count: usize,
    },
    /// The selected interface has no IPv4 address.
    #[error("{} has no IPv4 address", interface.as_str())]
    NoIpv4 {
        /// The interface.
        interface: BsdName,
    },
    /// Its IPv4 addresses all lie outside the selector's subnet.
    #[error("the selected interface's IPv4 address is outside the selector's subnet")]
    SubnetMismatch,
    /// The kernel's tables could not be read.
    #[error("reading the kernel's network tables failed")]
    Kernel(#[source] MacsysError),
}

/// What one interface is to a selector.
enum Candidate {
    /// Not the selected interface.
    Other,
    /// The selected interface, with its address in the subnet.
    Selected(ResolvedInterface, LinkState),
    /// The selected interface, without a usable address.
    Unaddressed(ResolveError),
}

/// The interface `selector` selects, and its link: exactly one up, running
/// interface the selector identifies, holding an IPv4 address in the
/// selector's subnet.
pub(crate) fn resolve(
    link: &dyn LinkLayer,
    selector: &InterfaceSelector,
) -> Result<(ResolvedInterface, LinkState), ResolveError> {
    let mut selected = Vec::new();
    let mut unaddressed = Vec::new();
    for interface in link.interfaces().map_err(ResolveError::Kernel)? {
        match candidate(link, selector, &interface)? {
            Candidate::Other => {}
            Candidate::Selected(resolved, state) => selected.push((resolved, state)),
            Candidate::Unaddressed(error) => unaddressed.push(error),
        }
    }
    match (selected.len(), unaddressed.len()) {
        (1, 0) => Ok(selected.remove(0)),
        (0, 0) => Err(ResolveError::Absent),
        (0, 1) => Err(unaddressed.remove(0)),
        (found, without) => Err(ResolveError::Ambiguous {
            count: found + without,
        }),
    }
}

/// What `interface` is to `selector`.
fn candidate(
    link: &dyn LinkLayer,
    selector: &InterfaceSelector,
    interface: &Interface,
) -> Result<Candidate, ResolveError> {
    let (Some(lladdr), true, true) = (interface.lladdr, interface.up, interface.running) else {
        return Ok(Candidate::Other);
    };
    let (Ok(bsd_name), Ok(lladdr)) = (BsdName::parse(&interface.name), MacAddr::from_bytes(lladdr))
    else {
        return Ok(Candidate::Other);
    };
    let index = InterfaceIndex::from(interface.index);
    let identified = match selector {
        InterfaceSelector::LinkAddr { lladdr: wanted, .. } => lladdr == *wanted,
        InterfaceSelector::GatewayLinkAddr { gw_lladdr, .. } => {
            gateway_is(link, index, *gw_lladdr)?
        }
    };
    if !identified {
        return Ok(Candidate::Other);
    }
    if interface.ipv4.is_empty() {
        return Ok(Candidate::Unaddressed(ResolveError::NoIpv4 {
            interface: bsd_name,
        }));
    }
    let Some(address) = interface
        .ipv4
        .iter()
        .map(|address| address.addr)
        .find(|addr| selector.subnet().contains(*addr))
    else {
        return Ok(Candidate::Unaddressed(ResolveError::SubnetMismatch));
    };
    let state = LinkState {
        up: interface.up,
        speed_mbps: u32::try_from(interface.baudrate / 1_000_000)
            .ok()
            .filter(|&mbps| mbps > 0),
    };
    Ok(Candidate::Selected(
        ResolvedInterface {
            bsd_name,
            index,
            lladdr,
            ipv4: address,
        },
        state,
    ))
}

/// Whether the interface's one IPv4 default gateway has the link-layer
/// address `wanted`. An interface with no default route, with routes
/// through several gateways, or whose gateway has no usable neighbour
/// entry is not the one; tables the kernel cannot give, or hides
/// (`NeighbourTableEmpty`, design §15.6 rule 10), are an error.
fn gateway_is(
    link: &dyn LinkLayer,
    index: InterfaceIndex,
    wanted: MacAddr,
) -> Result<bool, ResolveError> {
    let gateway = match link.default_gateway(index) {
        Ok(gateway) => gateway,
        Err(MacsysError::NoDefaultRoute | MacsysError::AmbiguousDefaultRoute) => return Ok(false),
        Err(error) => return Err(ResolveError::Kernel(error)),
    };
    match link.neighbour(index, gateway) {
        Ok(found) => Ok(MacAddr::from_bytes(found).ok() == Some(wanted)),
        Err(
            MacsysError::NeighbourAbsent
            | MacsysError::NeighbourIncomplete
            | MacsysError::NotEthernet { .. }
            | MacsysError::AmbiguousNeighbour,
        ) => Ok(false),
        Err(error) => Err(ResolveError::Kernel(error)),
    }
}

/// The exit site's interfaces, as the exit machine takes them: the egress
/// and, in `Separate` mode, the uplink, checked against the site; or the
/// fault the machine reports. A kernel table that cannot be read is an
/// error of the daemon.
pub(crate) fn exit_interfaces(
    link: &dyn LinkLayer,
    site: &ExitSite,
) -> Result<Result<Egress, EgressFault>, LocalError> {
    let (egress, state) = match resolve(link, &site.egress) {
        Ok(found) => found,
        Err(ResolveError::Kernel(error)) => return Err(LocalError::Kernel(error)),
        Err(ResolveError::Absent) => return Ok(Err(EgressFault::Absent)),
        Err(ResolveError::Ambiguous { count }) => {
            return Ok(Err(EgressFault::Ambiguous {
                matches: u32::try_from(count).unwrap_or(u32::MAX),
            }));
        }
        Err(ResolveError::NoIpv4 { interface }) => {
            return Ok(Err(EgressFault::NoIpv4 { interface }));
        }
        Err(ResolveError::SubnetMismatch) => return Ok(Err(EgressFault::SubnetMismatch)),
    };
    let uplink = match &site.uplink {
        Uplink::SameAsExit => ResolvedUplink::SameAsExit,
        Uplink::Separate(selector) => match resolve(link, selector) {
            Ok((uplink, _)) => ResolvedUplink::Separate(uplink),
            Err(ResolveError::Kernel(error)) => return Err(LocalError::Kernel(error)),
            Err(_) => return Ok(Err(EgressFault::UplinkAbsent)),
        },
    };
    match site.resolve(egress, uplink) {
        Ok(interfaces) => Ok(Ok(Egress {
            interfaces,
            link: state,
        })),
        Err(ModelError::UplinkEqualsEgress) => Ok(Err(EgressFault::UplinkEqualsEgress)),
        Err(ModelError::InterfaceNotSelected {
            role: InterfaceRole::Uplink,
        }) => Ok(Err(EgressFault::UplinkAbsent)),
        // The interfaces were selected by this site's own selectors in its
        // own uplink mode, so nothing else can be refused.
        Err(error) => Err(LocalError::ExitSite(error)),
    }
}
