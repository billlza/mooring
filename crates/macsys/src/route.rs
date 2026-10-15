// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's IPv4 routing and neighbour tables, read with PF_ROUTE
//! `sysctl` (the source `netstat -rn` and `arp -an` read), and the two
//! questions the router adapter asks of them: an interface's default
//! gateway, and that gateway's link-layer address.

pub(crate) mod messages;

use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::ptr;

use crate::error::{MacsysError, last_errno};

use messages::{DST, GATEWAY, NETMASK, RouteMessage, parse_table};

/// The largest table read, in bytes.
const MAX_TABLE_BYTES: usize = 16 << 20;

/// How often a read that found the table grown since it was sized
/// (`ENOMEM`) is retried before `TableChanged`.
const GROWTH_RETRIES: usize = 3;

/// A PF_ROUTE `sysctl` name: six integers.
type Mib = [libc::c_int; 6];

/// The length of a [`Mib`], as `sysctl` takes it.
const MIB_LEN: libc::c_uint = 6;

/// The kernel's IPv4 routing table (`NET_RT_DUMP`).
const ROUTE_DUMP: Mib = [
    libc::CTL_NET,
    libc::PF_ROUTE,
    0,
    libc::AF_INET,
    libc::NET_RT_DUMP,
    0,
];

/// The kernel's IPv4 neighbour (ARP) entries (`NET_RT_FLAGS`, `RTF_LLINFO`).
const NEIGHBOUR_DUMP: Mib = [
    libc::CTL_NET,
    libc::PF_ROUTE,
    0,
    libc::AF_INET,
    libc::NET_RT_FLAGS,
    libc::RTF_LLINFO,
];

/// Reads one PF_ROUTE table: its size first, then the table into a buffer
/// with a quarter more room, retrying when it grew past even that.
fn dump(mib: Mib) -> Result<Vec<u8>, MacsysError> {
    let mut name = mib;
    for _attempt in 0..=GROWTH_RETRIES {
        let mut size: libc::size_t = 0;
        // SAFETY: `name` holds `MIB_LEN` integers; a null `oldp` asks only
        // for the size, which the kernel writes to `size`; no new value is
        // set.
        let sized = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                MIB_LEN,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
                0,
            )
        };
        if sized != 0 {
            return Err(MacsysError::Sysctl {
                errno: last_errno(),
            });
        }
        if size > MAX_TABLE_BYTES {
            return Err(MacsysError::TableTooLarge);
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let room = (size + size / 4).min(MAX_TABLE_BYTES);
        let mut table = vec![0_u8; room];
        let mut filled: libc::size_t = room;
        // SAFETY: `table` is `room` writable bytes and `filled` says so;
        // the kernel writes at most that many and stores the count in
        // `filled`; no new value is set.
        let read = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                MIB_LEN,
                table.as_mut_ptr().cast(),
                &mut filled,
                ptr::null_mut(),
                0,
            )
        };
        if read == 0 {
            table.truncate(filled);
            return Ok(table);
        }
        let errno = last_errno();
        if errno != libc::ENOMEM {
            return Err(MacsysError::Sysctl { errno });
        }
    }
    Err(MacsysError::TableChanged)
}

/// One IPv4 default route through a gateway. Crate-private, like the
/// whole-table reads: callers ask the questions [`default_gateway_v4`] and
/// [`neighbour_v4`] answer, so no caller can skip their interface filter
/// and ambiguity rules (design §15.6 rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct DefaultRoute {
    /// The interface it leaves through (`rtm_index`).
    pub(crate) interface_index: u32,
    /// Its gateway.
    pub(crate) gateway: Ipv4Addr,
}

/// Every IPv4 default route through a gateway, scoped (`RTF_IFSCOPE`) and
/// unscoped: an up gateway route (`RTF_UP | RTF_GATEWAY`) to `0.0.0.0`,
/// with no netmask or an all-zero one, whose gateway is an IPv4 address.
pub(crate) fn default_routes_v4() -> Result<Vec<DefaultRoute>, MacsysError> {
    default_routes_in(&dump(ROUTE_DUMP)?)
}

/// The default routes of a `NET_RT_DUMP` table.
pub(crate) fn default_routes_in(table: &[u8]) -> Result<Vec<DefaultRoute>, MacsysError> {
    let messages = parse_table(table).map_err(|fault| MacsysError::MalformedRoute { fault })?;
    Ok(messages.iter().filter_map(default_route).collect())
}

fn default_route(message: &RouteMessage<'_>) -> Option<DefaultRoute> {
    if !message.has_flags(libc::RTF_UP | libc::RTF_GATEWAY) {
        return None;
    }
    let destination = message.addresses[DST]?.inet()?;
    let unmasked = message.addresses[NETMASK].is_none_or(|mask| mask.is_zero_mask());
    if destination != Ipv4Addr::UNSPECIFIED || !unmasked {
        return None;
    }
    Some(DefaultRoute {
        interface_index: u32::from(message.index),
        gateway: message.addresses[GATEWAY]?.inet()?,
    })
}

/// The one gateway of the IPv4 default routes leaving through `index`:
/// `NoDefaultRoute` if there is none, `AmbiguousDefaultRoute` if they name
/// more than one (the same gateway twice, scoped and unscoped, is one).
pub fn default_gateway_v4(index: NonZeroU32) -> Result<Ipv4Addr, MacsysError> {
    gateway_on(&default_routes_v4()?, index)
}

/// The one gateway of `routes` on `index`.
pub(crate) fn gateway_on(
    routes: &[DefaultRoute],
    index: NonZeroU32,
) -> Result<Ipv4Addr, MacsysError> {
    let mut found: Option<Ipv4Addr> = None;
    for route in routes
        .iter()
        .filter(|route| route.interface_index == index.get())
    {
        match found {
            None => found = Some(route.gateway),
            Some(gateway) if gateway == route.gateway => {}
            Some(_) => return Err(MacsysError::AmbiguousDefaultRoute),
        }
    }
    found.ok_or(MacsysError::NoDefaultRoute)
}

/// What a neighbour entry knows of the link layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum NeighbourLink {
    /// A six-byte (Ethernet) address.
    Ethernet([u8; 6]),
    /// Still being resolved: no address yet (`sdl_alen` 0).
    Incomplete,
    /// An address of another length.
    Other {
        /// Its length in bytes.
        alen: u8,
    },
}

/// One entry of the IPv4 neighbour (ARP) table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Neighbour {
    /// The interface the entry routes through (`rtm_index`).
    pub(crate) interface_index: u32,
    /// The neighbour's IPv4 address.
    pub(crate) addr: Ipv4Addr,
    /// Its link-layer address.
    pub(crate) link: NeighbourLink,
}

/// The kernel's IPv4 neighbour table as it returns it: the raw
/// `NET_RT_FLAGS`/`RTF_LLINFO` dump.
pub(crate) fn neighbour_table() -> Result<Vec<u8>, MacsysError> {
    dump(NEIGHBOUR_DUMP)
}

/// The neighbour entries of a `NET_RT_FLAGS`/`RTF_LLINFO` table.
pub(crate) fn neighbours_in(table: &[u8]) -> Result<Vec<Neighbour>, MacsysError> {
    let malformed = |fault| MacsysError::MalformedRoute { fault };
    let messages = parse_table(table).map_err(malformed)?;
    let mut neighbours = Vec::new();
    for message in &messages {
        let Some(addr) = message.addresses[DST].and_then(|dst| dst.inet()) else {
            continue;
        };
        let Some(link) = message.addresses[GATEWAY].and_then(|gateway| gateway.link()) else {
            continue;
        };
        let link = match link.map_err(malformed)? {
            (0, _) => NeighbourLink::Incomplete,
            (_, &[a, b, c, d, e, f]) => NeighbourLink::Ethernet([a, b, c, d, e, f]),
            (alen, _) => NeighbourLink::Other { alen },
        };
        neighbours.push(Neighbour {
            interface_index: u32::from(message.index),
            addr,
            link,
        });
    }
    Ok(neighbours)
}

/// The link-layer address of `addr` on the interface `index`, from the
/// kernel's neighbour table: `NeighbourTableEmpty` when the kernel's dump
/// holds no bytes at all, `NeighbourAbsent` when it has no entry for the
/// address (even when none of its messages is a neighbour entry),
/// `NeighbourIncomplete` while the entry is being resolved, `NotEthernet`
/// for an address that is not six bytes, `AmbiguousNeighbour` for two
/// different entries.
///
/// `NeighbourTableEmpty` states only what the kernel returned; whether an
/// empty dump means a hidden table is for the caller to judge. Measured on
/// macOS 27.0.1 (26A434) on 2026-10-14 (design §15.6 rule 10): the dump was
/// empty to a process whose code-signing identifier is not reverse-DNS, as
/// every `cargo` build's is, and to a process with an ad-hoc-signed
/// ancestor (a copy of bash, cargo or nextest); a Developer ID-signed
/// ancestor did not empty it. That it is empty to every such process, and
/// why, is an inference from those cases.
pub fn neighbour_v4(index: NonZeroU32, addr: Ipv4Addr) -> Result<[u8; 6], MacsysError> {
    neighbour_in_table(&neighbour_table()?, index, addr)
}

/// The link-layer address of `addr` on `index` in a raw
/// `NET_RT_FLAGS`/`RTF_LLINFO` dump: `NeighbourTableEmpty` when the dump
/// holds no bytes at all, else the lookup among its entries
/// (`neighbour_on`). Only the dump's own emptiness is `NeighbourTableEmpty`:
/// a dump whose messages hold no entry for `addr`, even none at all, is
/// `NeighbourAbsent`.
pub(crate) fn neighbour_in_table(
    table: &[u8],
    index: NonZeroU32,
    addr: Ipv4Addr,
) -> Result<[u8; 6], MacsysError> {
    if table.is_empty() {
        return Err(MacsysError::NeighbourTableEmpty);
    }
    neighbour_on(&neighbours_in(table)?, index, addr)
}

/// The link-layer address of `addr` on `index` among `neighbours`:
/// `NeighbourAbsent` with no entry for the address, `NeighbourIncomplete`
/// while it is being resolved, `NotEthernet` for an address that is not
/// six bytes, `AmbiguousNeighbour` for two different entries.
pub(crate) fn neighbour_on(
    neighbours: &[Neighbour],
    index: NonZeroU32,
    addr: Ipv4Addr,
) -> Result<[u8; 6], MacsysError> {
    let mut found: Option<NeighbourLink> = None;
    for neighbour in neighbours
        .iter()
        .filter(|neighbour| neighbour.interface_index == index.get() && neighbour.addr == addr)
    {
        match found {
            None => found = Some(neighbour.link),
            Some(link) if link == neighbour.link => {}
            Some(_) => return Err(MacsysError::AmbiguousNeighbour),
        }
    }
    match found {
        None => Err(MacsysError::NeighbourAbsent),
        Some(NeighbourLink::Ethernet(bytes)) => Ok(bytes),
        Some(NeighbourLink::Incomplete) => Err(MacsysError::NeighbourIncomplete),
        Some(NeighbourLink::Other { alen }) => Err(MacsysError::NotEthernet { alen }),
    }
}
