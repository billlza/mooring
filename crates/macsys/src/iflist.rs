// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's interface list, read with PF_ROUTE `sysctl`
//! `NET_RT_IFLIST2` (the source `ifconfig` and `netstat -I -b` read):
//! each interface's name, link-layer address, flags, MTU and 64-bit byte
//! counters (`if_data64`), and its IPv4 and IPv6 addresses.
//!
//! The dump is one `RTM_IFINFO2` message (`if_msghdr2`, then its `AF_LINK`
//! socket address) per interface, each followed by one `RTM_NEWADDR`
//! (`ifa_msghdr`, then netmask, address and broadcast) per address and one
//! `RTM_NEWMADDR2` per multicast membership, which is not read. Any other
//! message type is `UnexpectedType`, so a change of the dump's form is
//! refused rather than skipped.

use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use crate::error::{MacsysError, RouteFault};
use crate::route::messages::{Sockaddr, i32_at, parse_sockaddrs, u16_at};
use crate::route::{Mib, dump};

/// The slot of an address's netmask (`RTAX_NETMASK`).
const NETMASK: usize = 2;
/// The slot of an interface's own `AF_LINK` address (`RTAX_IFP`).
const IFP: usize = 4;
/// The slot of an interface address (`RTAX_IFA`).
const IFA: usize = 5;

const VERSION_AT: usize = 2;
const TYPE_AT: usize = 3;

const IFM_HEADER_LEN: usize = size_of::<libc::if_msghdr2>();
const IFM_ADDRS_AT: usize = offset_of!(libc::if_msghdr2, ifm_addrs);
const IFM_FLAGS_AT: usize = offset_of!(libc::if_msghdr2, ifm_flags);
const IFM_INDEX_AT: usize = offset_of!(libc::if_msghdr2, ifm_index);
const IFM_DATA_AT: usize = offset_of!(libc::if_msghdr2, ifm_data);
const IFI_TYPE_AT: usize = IFM_DATA_AT + offset_of!(libc::if_data64, ifi_type);
const IFI_MTU_AT: usize = IFM_DATA_AT + offset_of!(libc::if_data64, ifi_mtu);
const IFI_IBYTES_AT: usize = IFM_DATA_AT + offset_of!(libc::if_data64, ifi_ibytes);
const IFI_OBYTES_AT: usize = IFM_DATA_AT + offset_of!(libc::if_data64, ifi_obytes);
const IFI_BAUDRATE_AT: usize = IFM_DATA_AT + offset_of!(libc::if_data64, ifi_baudrate);

const IFAM_HEADER_LEN: usize = size_of::<libc::ifa_msghdr>();
const IFAM_ADDRS_AT: usize = offset_of!(libc::ifa_msghdr, ifam_addrs);
const IFAM_INDEX_AT: usize = offset_of!(libc::ifa_msghdr, ifam_index);

const SDL_NLEN_AT: usize = offset_of!(libc::sockaddr_dl, sdl_nlen);
const SDL_DATA_AT: usize = offset_of!(libc::sockaddr_dl, sdl_data);

/// One interface of the kernel's list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
    /// Its index.
    pub index: NonZeroU32,
    /// Its BSD name (`en9`).
    pub name: String,
    /// Its link type (`ifi_type`; 6 is Ethernet, `IFT_ETHER`).
    pub link_type: u8,
    /// Its own link-layer address, when that is six bytes long.
    pub lladdr: Option<[u8; 6]>,
    /// `IFF_UP`.
    pub up: bool,
    /// `IFF_RUNNING`.
    pub running: bool,
    /// Its MTU.
    pub mtu: u32,
    /// Bytes received (`ifi_ibytes`), as the kernel gives them to this
    /// process: measured on macOS 27.0.1 (26A434) on 2026-10-22, a process
    /// that is not Apple's own (a cargo build, plain or re-signed with a
    /// reverse-DNS identifier, run from a shell) reads the count modulo
    /// 2^32 and rounded down to a multiple of 1024, while `netstat -I lo0
    /// -b` showed the full count. Differences are therefore to be taken
    /// modulo 2^32 and are good to 1 KiB *(inference from one interface,
    /// lo0, read three times)*.
    pub ibytes: u64,
    /// Bytes sent (`ifi_obytes`), read as [`Interface::ibytes`] is.
    pub obytes: u64,
    /// The link's speed in bits per second (`ifi_baudrate`); 0 when the
    /// driver reports none.
    pub baudrate: u64,
    /// Its IPv4 addresses, in the kernel's order.
    pub ipv4: Vec<InterfaceAddrV4>,
    /// Its IPv6 addresses, in the kernel's order, link-local ones without
    /// the scope the kernel embeds in them.
    pub ipv6: Vec<Ipv6Addr>,
}

/// One IPv4 address of an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceAddrV4 {
    /// The address.
    pub addr: Ipv4Addr,
    /// Its prefix length, when the kernel gave a netmask.
    pub prefix_len: Option<u8>,
}

/// Every interface of the kernel's list.
pub fn interfaces() -> Result<Vec<Interface>, MacsysError> {
    interfaces_in(&dump(list_mib(0))?)
}

/// The interface with index `index`: `InterfaceAbsent` when the kernel
/// lists none (the dump is filtered by the kernel to that index).
pub fn interface(index: NonZeroU32) -> Result<Interface, MacsysError> {
    let wanted = libc::c_int::try_from(index.get()).map_err(|_| MacsysError::InterfaceAbsent)?;
    let mut found = interfaces_in(&dump(list_mib(wanted))?)?
        .into_iter()
        .filter(|interface| interface.index == index);
    match (found.next(), found.next()) {
        (Some(interface), None) => Ok(interface),
        (None, _) => Err(MacsysError::InterfaceAbsent),
        (Some(_), Some(_)) => Err(MacsysError::MalformedRoute {
            fault: RouteFault::DuplicateInterface,
        }),
    }
}

/// The `NET_RT_IFLIST2` name for every family, filtered to interface
/// `index` (0: every interface).
const fn list_mib(index: libc::c_int) -> Mib {
    [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        0,
        libc::NET_RT_IFLIST2,
        index,
    ]
}

/// The interfaces of a `NET_RT_IFLIST2` dump.
pub(crate) fn interfaces_in(table: &[u8]) -> Result<Vec<Interface>, MacsysError> {
    parse_list(table).map_err(|fault| MacsysError::MalformedRoute { fault })
}

fn parse_list(table: &[u8]) -> Result<Vec<Interface>, RouteFault> {
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut rest = table;
    while !rest.is_empty() {
        if rest.len() <= TYPE_AT {
            return Err(RouteFault::ShortHeader);
        }
        let length = usize::from(u16_at(rest, 0));
        if length > rest.len() {
            return Err(RouteFault::LengthOverrun);
        }
        if i32::from(rest[VERSION_AT]) != libc::RTM_VERSION {
            return Err(RouteFault::Version);
        }
        let rtm_type = rest[TYPE_AT];
        let (message, next) = rest.split_at(length);
        match i32::from(rtm_type) {
            libc::RTM_IFINFO2 => {
                let interface = parse_ifinfo(message)?;
                if interfaces.iter().any(|seen| seen.index == interface.index) {
                    return Err(RouteFault::DuplicateInterface);
                }
                interfaces.push(interface);
            }
            libc::RTM_NEWADDR => {
                let (index, addr) = parse_newaddr(message)?;
                let owner = interfaces
                    .iter_mut()
                    .find(|interface| u32::from(index) == interface.index.get())
                    .ok_or(RouteFault::UnknownInterface)?;
                match addr {
                    NewAddr::V4(addr) => owner.ipv4.push(addr),
                    NewAddr::V6(addr) => owner.ipv6.push(addr),
                    NewAddr::Other => {}
                }
            }
            libc::RTM_NEWMADDR2 => {}
            _ => return Err(RouteFault::UnexpectedType { rtm_type }),
        }
        rest = next;
    }
    Ok(interfaces)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0_u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_ne_bytes(word)
}

/// One `RTM_IFINFO2` message whose length lies within the table.
fn parse_ifinfo(message: &[u8]) -> Result<Interface, RouteFault> {
    if message.len() < IFM_HEADER_LEN {
        return Err(RouteFault::ShortHeader);
    }
    let addresses = parse_sockaddrs(i32_at(message, IFM_ADDRS_AT), &message[IFM_HEADER_LEN..])?;
    let link = addresses[IFP]
        .filter(|sockaddr| sockaddr.is_family(libc::AF_LINK))
        .ok_or(RouteFault::MissingLink)?;
    let index =
        NonZeroU32::new(u32::from(u16_at(message, IFM_INDEX_AT))).ok_or(RouteFault::ZeroIndex)?;
    let flags = i32_at(message, IFM_FLAGS_AT);
    Ok(Interface {
        index,
        name: link_name(link)?,
        link_type: message[IFI_TYPE_AT],
        lladdr: match link.link() {
            Some(Ok((6, &[a, b, c, d, e, f]))) => Some([a, b, c, d, e, f]),
            Some(Ok(_)) => None,
            Some(Err(fault)) => return Err(fault),
            None => return Err(RouteFault::MissingLink),
        },
        up: flags & libc::IFF_UP != 0,
        running: flags & libc::IFF_RUNNING != 0,
        mtu: u32_at(message, IFI_MTU_AT),
        ibytes: u64_at(message, IFI_IBYTES_AT),
        obytes: u64_at(message, IFI_OBYTES_AT),
        baudrate: u64_at(message, IFI_BAUDRATE_AT),
        ipv4: Vec::new(),
        ipv6: Vec::new(),
    })
}

/// The interface name of an `AF_LINK` socket address: `sdl_nlen` bytes of
/// `sdl_data`, which must be UTF-8 and not empty.
fn link_name(link: Sockaddr<'_>) -> Result<String, RouteFault> {
    let nlen = *link
        .bytes
        .get(SDL_NLEN_AT)
        .ok_or(RouteFault::SockaddrOverrun)?;
    let name = link
        .bytes
        .get(SDL_DATA_AT..SDL_DATA_AT + usize::from(nlen))
        .ok_or(RouteFault::SockaddrOverrun)?;
    match std::str::from_utf8(name) {
        Ok(name) if !name.is_empty() => Ok(name.to_owned()),
        _ => Err(RouteFault::InvalidName),
    }
}

/// The address an `RTM_NEWADDR` message gives.
enum NewAddr {
    /// An IPv4 address with its netmask.
    V4(InterfaceAddrV4),
    /// An IPv6 address.
    V6(Ipv6Addr),
    /// An address of another family, or none.
    Other,
}

/// One `RTM_NEWADDR` message: its interface index, and its address when
/// that is IPv4 or IPv6.
fn parse_newaddr(message: &[u8]) -> Result<(u16, NewAddr), RouteFault> {
    if message.len() < IFAM_HEADER_LEN {
        return Err(RouteFault::ShortHeader);
    }
    let addresses = parse_sockaddrs(i32_at(message, IFAM_ADDRS_AT), &message[IFAM_HEADER_LEN..])?;
    let index = u16_at(message, IFAM_INDEX_AT);
    let Some(ifa) = addresses[IFA] else {
        return Ok((index, NewAddr::Other));
    };
    if let Some(addr) = ifa.inet() {
        let prefix_len = addresses[NETMASK].map(prefix_of).transpose()?;
        return Ok((index, NewAddr::V4(InterfaceAddrV4 { addr, prefix_len })));
    }
    Ok((index, ifa.inet6().map_or(NewAddr::Other, NewAddr::V6)))
}

/// The prefix length of a netmask as the kernel trims it: the mask bytes
/// from offset 4, missing trailing bytes being zero. A mask whose ones are
/// not contiguous is `NonContiguousMask`.
fn prefix_of(mask: Sockaddr<'_>) -> Result<u8, RouteFault> {
    let mut octets = [0_u8; 4];
    for (octet, byte) in octets.iter_mut().zip(mask.bytes.iter().skip(4)) {
        *octet = *byte;
    }
    let bits = u32::from_be_bytes(octets);
    let ones = bits.leading_ones();
    if bits != u32::MAX && bits << ones != 0 {
        return Err(RouteFault::NonContiguousMask);
    }
    u8::try_from(ones).map_err(|_| RouteFault::NonContiguousMask)
}
