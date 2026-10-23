// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's link to the M7 (design §15.6 rule 4): the interface, its
//! default gateway, and the gateway's link-layer address, which must equal
//! the pinned one before the admin password is sent.
//!
//! The kernel is reached through [`LinkLayer`] ([`KernelLink`] in the
//! binary, a scripted fake in tests). [`check_identity`] is the only
//! constructor of [`VerifiedIdentity`], and the login body can only be
//! built for one, so the password cannot be sent before the check.

use std::net::{Ipv4Addr, SocketAddrV4};

use mooring_macsys::{Interface, InterfaceAddrV4, MacsysError};
use mooring_model::iface::{BsdName, InterfaceIndex, MacAddr};

use crate::error::{CommandError, LocalError};
use crate::router::error::{
    FoundLink, PRIVACY_PLACEHOLDER, RouterError, UnreachableCause, UnusableLink,
};
use crate::router::http::Endpoint;

/// The kernel's interface, routing and neighbour tables.
pub(crate) trait LinkLayer {
    /// The interface's index.
    fn interface_index(&self, name: &BsdName) -> Result<InterfaceIndex, MacsysError>;

    /// The interface's one IPv4 default gateway.
    fn default_gateway(&self, index: InterfaceIndex) -> Result<Ipv4Addr, MacsysError>;

    /// The link-layer address of `addr` on the interface.
    fn neighbour(&self, index: InterfaceIndex, addr: Ipv4Addr) -> Result<[u8; 6], MacsysError>;

    /// The interface's IPv4 addresses, in the kernel's order.
    fn ipv4_addresses(&self, index: InterfaceIndex) -> Result<Vec<InterfaceAddrV4>, MacsysError>;

    /// Every interface in the kernel's list.
    fn interfaces(&self) -> Result<Vec<Interface>, MacsysError>;
}

/// The kernel itself, through `mooring-macsys`.
#[derive(Debug)]
pub(crate) struct KernelLink;

impl LinkLayer for KernelLink {
    fn interface_index(&self, name: &BsdName) -> Result<InterfaceIndex, MacsysError> {
        mooring_macsys::interface_index(name.as_str()).map(InterfaceIndex::from)
    }

    fn default_gateway(&self, index: InterfaceIndex) -> Result<Ipv4Addr, MacsysError> {
        mooring_macsys::default_gateway_v4(index.into())
    }

    fn neighbour(&self, index: InterfaceIndex, addr: Ipv4Addr) -> Result<[u8; 6], MacsysError> {
        mooring_macsys::neighbour_v4(index.into(), addr)
    }

    fn ipv4_addresses(&self, index: InterfaceIndex) -> Result<Vec<InterfaceAddrV4>, MacsysError> {
        mooring_macsys::interface(index.into()).map(|interface| interface.ipv4)
    }

    fn interfaces(&self) -> Result<Vec<Interface>, MacsysError> {
        mooring_macsys::interfaces()
    }
}

/// The M7's attachment: an interface and its default gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attachment {
    /// The interface's name.
    pub(crate) interface: BsdName,
    /// Its index.
    pub(crate) index: InterfaceIndex,
    /// Its default gateway, the M7.
    pub(crate) gateway: Ipv4Addr,
}

impl Attachment {
    /// The M7's HTTP endpoint on `port`, reached through the interface.
    pub(crate) const fn endpoint(&self, port: u16) -> Endpoint {
        Endpoint {
            addr: SocketAddrV4::new(self.gateway, port),
            interface: self.index,
        }
    }
}

fn kernel(error: MacsysError) -> CommandError {
    CommandError::Local(LocalError::Kernel(error))
}

fn unreachable(cause: UnreachableCause) -> CommandError {
    CommandError::Router(RouterError::unreachable(cause))
}

/// The interface's index and default gateway.
pub(crate) fn attach(
    link: &dyn LinkLayer,
    interface: &BsdName,
) -> Result<Attachment, CommandError> {
    let index = link
        .interface_index(interface)
        .map_err(|error| match error {
            MacsysError::InterfaceAbsent => unreachable(UnreachableCause::InterfaceAbsent),
            other => kernel(other),
        })?;
    let gateway = link.default_gateway(index).map_err(|error| match error {
        MacsysError::NoDefaultRoute => unreachable(UnreachableCause::NoDefaultRoute),
        MacsysError::AmbiguousDefaultRoute => unreachable(UnreachableCause::AmbiguousDefaultRoute),
        other => kernel(other),
    })?;
    Ok(Attachment {
        interface: interface.clone(),
        index,
        gateway,
    })
}

/// What the neighbour table says about the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayLink {
    /// One unicast Ethernet address.
    Address(MacAddr),
    /// Something that cannot identify a device.
    Unusable(UnusableLink),
    /// No address yet: no entry, or one still being resolved.
    Unresolved,
    /// The kernel returned an empty table. The callers read this as the
    /// table hidden from this binary (design §15.6 rule 10) only once the
    /// gateway has been reached, which leaves an entry for it: `status` and
    /// `capture` after the anonymous `GET`, and `router pin` only when the
    /// read before its warm-up connection, which succeeded, was empty too.
    TableEmpty,
}

/// Looks the gateway's link-layer address up in the neighbour table. The
/// placeholder [`PRIVACY_PLACEHOLDER`] is unusable, never an address, and
/// an empty table is `TableEmpty`, which the callers judge by whether the
/// gateway has been reached.
pub(crate) fn gateway_link(
    link: &dyn LinkLayer,
    attachment: &Attachment,
) -> Result<GatewayLink, CommandError> {
    match link.neighbour(attachment.index, attachment.gateway) {
        Ok(PRIVACY_PLACEHOLDER) => Ok(GatewayLink::Unusable(UnusableLink::PrivacyPlaceholder)),
        Ok(bytes) => Ok(MacAddr::from_bytes(bytes).map_or(
            GatewayLink::Unusable(UnusableLink::NotUnicast(bytes)),
            GatewayLink::Address,
        )),
        Err(MacsysError::NeighbourTableEmpty) => Ok(GatewayLink::TableEmpty),
        Err(MacsysError::NeighbourAbsent | MacsysError::NeighbourIncomplete) => {
            Ok(GatewayLink::Unresolved)
        }
        Err(MacsysError::NotEthernet { alen }) => {
            Ok(GatewayLink::Unusable(UnusableLink::NotEthernet { alen }))
        }
        Err(MacsysError::AmbiguousNeighbour) => Ok(GatewayLink::Unusable(UnusableLink::Ambiguous)),
        Err(other) => Err(kernel(other)),
    }
}

/// Proof that the gateway's link-layer address equalled the pinned one
/// when it was checked; the login is sent only to its endpoint.
#[derive(Debug)]
pub(crate) struct VerifiedIdentity {
    endpoint: Endpoint,
}

impl VerifiedIdentity {
    /// The verified M7's endpoint.
    pub(crate) const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }
}

/// Checks that the gateway of `attachment` is the pinned M7. Run after the
/// anonymous request, which reached the gateway and so filled the
/// neighbour table, and before anything secret is sent: `GatewayUnresolved`
/// without an address, `IdentityMismatch` with another or an unusable one
/// (the placeholder too, even if it was pinned), and the local
/// `NeighbourTableHidden` for an empty table, which after that request is
/// read as the kernel hiding the table from this binary (design §15.6
/// rule 10).
///
/// The address can change between this check and the login (a residual
/// race): the check protects against the wrong network (critique C-8), not
/// against an active attacker on the Mac's cable.
pub(crate) fn check_identity(
    link: &dyn LinkLayer,
    attachment: &Attachment,
    pinned: MacAddr,
    port: u16,
) -> Result<VerifiedIdentity, CommandError> {
    let found = match gateway_link(link, attachment)? {
        GatewayLink::Address(addr) if addr == pinned => {
            return Ok(VerifiedIdentity {
                endpoint: attachment.endpoint(port),
            });
        }
        GatewayLink::Address(addr) => FoundLink::Address(addr),
        GatewayLink::Unusable(unusable) => FoundLink::Unusable(unusable),
        GatewayLink::Unresolved => {
            return Err(unreachable(UnreachableCause::GatewayUnresolved));
        }
        GatewayLink::TableEmpty => {
            return Err(CommandError::Local(LocalError::NeighbourTableHidden));
        }
    };
    Err(CommandError::Router(RouterError::IdentityMismatch {
        expected: pinned,
        found,
    }))
}
