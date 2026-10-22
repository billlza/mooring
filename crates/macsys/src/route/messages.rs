// SPDX-License-Identifier: GPL-3.0-or-later

//! Safe parsing of the kernel's routing messages (`rt_msghdr` followed by
//! its socket addresses) from the bytes a PF_ROUTE `sysctl` returns.
//!
//! Every length is checked against the bytes that hold it, so a message or
//! socket address that runs past its container is `MalformedRoute`, never
//! a read out of bounds. The header's layout comes from libc's
//! `rt_msghdr` (`size_of`, `offset_of!`); the integers are in the host's
//! byte order, as the kernel writes them.

use std::mem::{offset_of, size_of};
use std::net::Ipv4Addr;

use crate::error::RouteFault;

/// The size of `rt_msghdr` (92 bytes on macOS).
pub(crate) const HEADER_LEN: usize = size_of::<libc::rt_msghdr>();

const MSGLEN_AT: usize = offset_of!(libc::rt_msghdr, rtm_msglen);
const VERSION_AT: usize = offset_of!(libc::rt_msghdr, rtm_version);
const INDEX_AT: usize = offset_of!(libc::rt_msghdr, rtm_index);
const FLAGS_AT: usize = offset_of!(libc::rt_msghdr, rtm_flags);
const ADDRS_AT: usize = offset_of!(libc::rt_msghdr, rtm_addrs);
const SDL_NLEN_AT: usize = offset_of!(libc::sockaddr_dl, sdl_nlen);
const SDL_ALEN_AT: usize = offset_of!(libc::sockaddr_dl, sdl_alen);
const SDL_DATA_AT: usize = offset_of!(libc::sockaddr_dl, sdl_data);

/// The number of socket address slots (`RTAX_MAX`).
pub(crate) const ADDRESS_SLOTS: usize = 8;

/// The slot of the destination (`RTAX_DST`).
pub(crate) const DST: usize = 0;
/// The slot of the gateway (`RTAX_GATEWAY`).
pub(crate) const GATEWAY: usize = 1;
/// The slot of the netmask (`RTAX_NETMASK`).
pub(crate) const NETMASK: usize = 2;

/// The bytes a socket address of `len` takes in a routing message: XNU's
/// `ROUNDUP32`, so a zero length still takes four bytes and every other is
/// rounded up to a multiple of four.
pub(crate) const fn sockaddr_space(len: u8) -> usize {
    if len == 0 {
        4
    } else {
        (len as usize).div_ceil(4) * 4
    }
}

/// One socket address of a routing message: its own bytes (`sa_len` of
/// them, `sa_len` and `sa_family` included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sockaddr<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> Sockaddr<'a> {
    /// Whether this socket address is long enough to name a family and
    /// names `family`. (The kernel writes an empty netmask with no family
    /// byte at all.)
    pub(crate) fn is_family(&self, family: i32) -> bool {
        self.bytes
            .get(1)
            .is_some_and(|&found| i32::from(found) == family)
    }

    /// The IPv4 address of an `AF_INET` socket address (`sockaddr_in` or
    /// `sockaddr_inarp`, whose address is at the same offset), if this is
    /// one long enough to hold it.
    pub(crate) fn inet(&self) -> Option<Ipv4Addr> {
        if !self.is_family(libc::AF_INET) {
            return None;
        }
        let octets: [u8; 4] = self.bytes.get(4..8)?.try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }

    /// Whether this netmask selects no bits: an empty socket address, or
    /// one whose address bytes (from offset 4, as in `sockaddr_in`) are all
    /// zero. The kernel trims trailing zero bytes from netmasks, so the
    /// length may be anything up to the full `sockaddr_in`.
    pub(crate) fn is_zero_mask(&self) -> bool {
        self.bytes
            .get(4..)
            .is_none_or(|bytes| bytes.iter().all(|&byte| byte == 0))
    }

    /// The link-layer address of an `AF_LINK` socket address
    /// (`sockaddr_dl`), with its length `sdl_alen`: the `sdl_alen` bytes
    /// after `sdl_nlen` bytes of name in `sdl_data`. `None` if this is not
    /// `AF_LINK`; `SockaddrOverrun` if the name and address run past the
    /// socket address.
    pub(crate) fn link(&self) -> Option<Result<(u8, &'a [u8]), RouteFault>> {
        if !self.is_family(libc::AF_LINK) {
            return None;
        }
        Some(link_address(self.bytes))
    }
}

fn link_address(bytes: &[u8]) -> Result<(u8, &[u8]), RouteFault> {
    let nlen = *bytes.get(SDL_NLEN_AT).ok_or(RouteFault::SockaddrOverrun)?;
    let alen = *bytes.get(SDL_ALEN_AT).ok_or(RouteFault::SockaddrOverrun)?;
    let start = SDL_DATA_AT + usize::from(nlen);
    let end = start + usize::from(alen);
    let address = bytes.get(start..end).ok_or(RouteFault::SockaddrOverrun)?;
    Ok((alen, address))
}

/// One routing message: the header fields Mooring reads and its socket
/// addresses by slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteMessage<'a> {
    pub(crate) index: u16,
    pub(crate) flags: i32,
    pub(crate) addresses: [Option<Sockaddr<'a>>; ADDRESS_SLOTS],
}

impl RouteMessage<'_> {
    pub(crate) const fn has_flags(&self, flags: i32) -> bool {
        self.flags & flags == flags
    }
}

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([bytes[at], bytes[at + 1]])
}

pub(crate) fn i32_at(bytes: &[u8], at: usize) -> i32 {
    i32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Every message of a routing table dump, in order.
pub(crate) fn parse_table(table: &[u8]) -> Result<Vec<RouteMessage<'_>>, RouteFault> {
    let mut messages = Vec::new();
    let mut rest = table;
    while !rest.is_empty() {
        if rest.len() <= VERSION_AT {
            return Err(RouteFault::ShortHeader);
        }
        let length = usize::from(u16_at(rest, MSGLEN_AT));
        if length > rest.len() {
            return Err(RouteFault::LengthOverrun);
        }
        if i32::from(rest[VERSION_AT]) != libc::RTM_VERSION {
            return Err(RouteFault::Version);
        }
        if length < HEADER_LEN {
            return Err(RouteFault::ShortHeader);
        }
        let (message, next) = rest.split_at(length);
        messages.push(parse_message(message)?);
        rest = next;
    }
    Ok(messages)
}

/// One message whose length is checked: at least a header, and all of it
/// within the table.
fn parse_message(message: &[u8]) -> Result<RouteMessage<'_>, RouteFault> {
    Ok(RouteMessage {
        index: u16_at(message, INDEX_AT),
        flags: i32_at(message, FLAGS_AT),
        addresses: parse_sockaddrs(i32_at(message, ADDRS_AT), &message[HEADER_LEN..])?,
    })
}

/// The socket addresses that follow a routing message's header, by slot:
/// one for each bit of `present` (`rtm_addrs`, `ifm_addrs` or
/// `ifam_addrs`), in slot order, each rounded up to four bytes.
pub(crate) fn parse_sockaddrs(
    present: i32,
    after_header: &[u8],
) -> Result<[Option<Sockaddr<'_>>; ADDRESS_SLOTS], RouteFault> {
    let mut addresses = [None; ADDRESS_SLOTS];
    let mut rest = after_header;
    for (slot, address) in addresses.iter_mut().enumerate() {
        if present & (1 << slot) == 0 {
            continue;
        }
        let len = *rest.first().ok_or(RouteFault::SockaddrOverrun)?;
        let space = sockaddr_space(len);
        if space > rest.len() {
            return Err(RouteFault::SockaddrOverrun);
        }
        *address = Some(Sockaddr {
            bytes: &rest[..usize::from(len)],
        });
        rest = &rest[space..];
    }
    Ok(addresses)
}
