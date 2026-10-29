// SPDX-License-Identifier: GPL-3.0-or-later

//! Routing and neighbour messages built byte by byte, as the kernel lays
//! them out: an `rt_msghdr`, then each present socket address rounded up to
//! four bytes.

use std::mem::offset_of;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;

use crate::error::{MacsysError, RouteFault};
use crate::route::messages::{HEADER_LEN, sockaddr_space};
use crate::route::{
    DefaultRoute, Neighbour, NeighbourLink, default_routes_in, gateway_on, neighbour_in_table,
    neighbour_on, neighbours_in,
};

const DST: usize = 0;
const GATEWAY: usize = 1;
const NETMASK: usize = 2;

const UP_GATEWAY: i32 = libc::RTF_UP | libc::RTF_GATEWAY;

fn index(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

/// One routing message of `version` with the socket addresses in `slots`
/// (slot, bytes), in slot order.
fn message_of_version(version: u8, index: u16, flags: i32, slots: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut present = 0_i32;
    let mut body = Vec::new();
    for (slot, sockaddr) in slots {
        present |= 1 << slot;
        let space = sockaddr_space(sockaddr.first().copied().unwrap_or(0));
        let mut padded = sockaddr.clone();
        padded.resize(space, 0);
        body.extend(padded);
    }
    let mut message = vec![0_u8; HEADER_LEN];
    let length = u16::try_from(HEADER_LEN + body.len()).unwrap();
    let put = |message: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        message[at..at + bytes.len()].copy_from_slice(bytes);
    };
    put(
        &mut message,
        offset_of!(libc::rt_msghdr, rtm_msglen),
        &length.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::rt_msghdr, rtm_version),
        &[version],
    );
    put(
        &mut message,
        offset_of!(libc::rt_msghdr, rtm_index),
        &index.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::rt_msghdr, rtm_flags),
        &flags.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::rt_msghdr, rtm_addrs),
        &present.to_ne_bytes(),
    );
    message.extend(body);
    message
}

fn message(index: u16, flags: i32, slots: &[(usize, Vec<u8>)]) -> Vec<u8> {
    message_of_version(5, index, flags, slots)
}

/// A full `sockaddr_in` (or the same prefix of a `sockaddr_inarp`).
fn inet(addr: [u8; 4]) -> Vec<u8> {
    let mut sockaddr = vec![0_u8; 16];
    sockaddr[0] = 16;
    sockaddr[1] = u8::try_from(libc::AF_INET).unwrap();
    sockaddr[4..8].copy_from_slice(&addr);
    sockaddr
}

/// A netmask as the kernel trims it: `len` bytes, the mask from offset 4.
fn netmask(len: u8, mask: &[u8]) -> Vec<u8> {
    let mut sockaddr = vec![0_u8; usize::from(len)];
    if len > 0 {
        sockaddr[0] = len;
    }
    for (i, byte) in mask.iter().enumerate() {
        sockaddr[4 + i] = *byte;
    }
    sockaddr
}

/// A `sockaddr_dl` naming interface `name` with link-layer address `addr`.
fn link(if_index: u16, name: &str, addr: &[u8]) -> Vec<u8> {
    let used = 8 + name.len() + addr.len();
    let len = used.max(20);
    let mut sockaddr = vec![0_u8; len];
    sockaddr[0] = u8::try_from(len).unwrap();
    sockaddr[1] = u8::try_from(libc::AF_LINK).unwrap();
    sockaddr[2..4].copy_from_slice(&if_index.to_ne_bytes());
    sockaddr[4] = 6; // IFT_ETHER
    sockaddr[5] = u8::try_from(name.len()).unwrap();
    sockaddr[6] = u8::try_from(addr.len()).unwrap();
    sockaddr[8..8 + name.len()].copy_from_slice(name.as_bytes());
    sockaddr[8 + name.len()..used].copy_from_slice(addr);
    sockaddr
}

/// A default route on `index` through `gateway`, with an empty netmask.
fn default_route(index: u16, gateway: [u8; 4], flags: i32) -> Vec<u8> {
    message(
        index,
        flags,
        &[
            (DST, inet([0, 0, 0, 0])),
            (GATEWAY, inet(gateway)),
            (NETMASK, netmask(0, &[])),
        ],
    )
}

fn route(interface_index: u32, gateway: [u8; 4]) -> DefaultRoute {
    DefaultRoute {
        interface_index,
        gateway: Ipv4Addr::from(gateway),
        scoped: false,
    }
}

fn scoped_route(interface_index: u32, gateway: [u8; 4]) -> DefaultRoute {
    DefaultRoute {
        scoped: true,
        ..route(interface_index, gateway)
    }
}

const M7_LIKE: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x20, 0x30];

/// An ARP entry for `addr` on `index` whose gateway names `en9`.
fn arp_entry(index: u16, addr: [u8; 4], lladdr: &[u8]) -> Vec<u8> {
    message(
        index,
        libc::RTF_UP | libc::RTF_LLINFO | libc::RTF_HOST,
        &[(DST, inet(addr)), (GATEWAY, link(index, "en9", lladdr))],
    )
}

/// A message on `en9`'s index whose gateway is an IPv4 address, not a
/// link-layer one: no neighbour entry.
fn not_link_entry() -> Vec<u8> {
    message(
        9,
        libc::RTF_UP | libc::RTF_LLINFO,
        &[
            (DST, inet([192, 168, 1, 2])),
            (GATEWAY, inet([192, 168, 1, 1])),
        ],
    )
}

#[test]
fn a_default_route_message_yields_its_gateway() {
    let mut table = default_route(9, [192, 0, 2, 1], UP_GATEWAY | libc::RTF_STATIC);
    // A network route through a gateway is not a default route.
    table.extend(message(
        9,
        UP_GATEWAY,
        &[
            (DST, inet([10, 0, 0, 0])),
            (GATEWAY, inet([192, 0, 2, 2])),
            (NETMASK, netmask(5, &[255])),
        ],
    ));
    let routes = default_routes_in(&table).unwrap();
    assert_eq!(routes, [route(9, [192, 0, 2, 1])]);
    assert_eq!(
        gateway_on(&routes, index(9)),
        Ok(Ipv4Addr::new(192, 0, 2, 1))
    );
    // A scoped default route counts, and so does a full all-zero netmask.
    let scoped = message(
        9,
        UP_GATEWAY | libc::RTF_IFSCOPE,
        &[
            (DST, inet([0, 0, 0, 0])),
            (GATEWAY, inet([192, 0, 2, 7])),
            (NETMASK, netmask(8, &[0, 0, 0, 0])),
        ],
    );
    assert_eq!(
        default_routes_in(&scoped).unwrap(),
        [scoped_route(9, [192, 0, 2, 7])]
    );
    // So does a default route with no netmask at all.
    let bare = message(
        3,
        UP_GATEWAY,
        &[
            (DST, inet([0, 0, 0, 0])),
            (GATEWAY, inet([198, 51, 100, 1])),
        ],
    );
    assert_eq!(
        default_routes_in(&bare).unwrap(),
        [route(3, [198, 51, 100, 1])]
    );
}

#[test]
fn only_up_gateway_routes_to_everything_through_an_ipv4_gateway_are_default_routes() {
    let not_default = [
        // Down.
        default_route(9, [192, 0, 2, 1], libc::RTF_GATEWAY),
        // Not through a gateway.
        default_route(9, [192, 0, 2, 1], libc::RTF_UP),
        // A destination other than 0.0.0.0.
        message(
            9,
            UP_GATEWAY,
            &[(DST, inet([0, 0, 0, 1])), (GATEWAY, inet([192, 0, 2, 1]))],
        ),
        // A netmask that selects bits.
        message(
            9,
            UP_GATEWAY,
            &[
                (DST, inet([0, 0, 0, 0])),
                (GATEWAY, inet([192, 0, 2, 1])),
                (NETMASK, netmask(6, &[0, 128])),
            ],
        ),
        // A link-layer gateway (a utun's or a bridge's default route).
        message(
            9,
            UP_GATEWAY,
            &[(DST, inet([0, 0, 0, 0])), (GATEWAY, link(9, "utun3", &[]))],
        ),
        // No gateway address.
        message(9, UP_GATEWAY, &[(DST, inet([0, 0, 0, 0]))]),
    ];
    for table in not_default {
        assert_eq!(default_routes_in(&table).unwrap(), []);
    }
}

#[test]
fn routes_on_other_interfaces_are_skipped() {
    let mut table = default_route(4, [10, 1, 1, 1], UP_GATEWAY);
    table.extend(default_route(
        9,
        [192, 0, 2, 1],
        UP_GATEWAY | libc::RTF_IFSCOPE,
    ));
    let routes = default_routes_in(&table).unwrap();
    assert_eq!(
        gateway_on(&routes, index(9)),
        Ok(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(
        gateway_on(&routes, index(4)),
        Ok(Ipv4Addr::new(10, 1, 1, 1))
    );
    assert_eq!(
        gateway_on(&routes, index(5)),
        Err(MacsysError::NoDefaultRoute)
    );
}

#[test]
fn two_default_gateways_on_one_interface_are_ambiguous() {
    let mut table = default_route(9, [192, 0, 2, 1], UP_GATEWAY);
    table.extend(default_route(
        9,
        [192, 0, 2, 2],
        UP_GATEWAY | libc::RTF_IFSCOPE,
    ));
    let routes = default_routes_in(&table).unwrap();
    assert_eq!(
        gateway_on(&routes, index(9)),
        Err(MacsysError::AmbiguousDefaultRoute)
    );
    // The same gateway, scoped and unscoped, is one gateway.
    let mut twice = default_route(9, [192, 0, 2, 1], UP_GATEWAY);
    twice.extend(default_route(
        9,
        [192, 0, 2, 1],
        UP_GATEWAY | libc::RTF_IFSCOPE,
    ));
    let routes = default_routes_in(&twice).unwrap();
    assert_eq!(
        routes,
        [route(9, [192, 0, 2, 1]), scoped_route(9, [192, 0, 2, 1])]
    );
    assert_eq!(
        gateway_on(&routes, index(9)),
        Ok(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[test]
fn no_default_route_is_typed() {
    assert_eq!(default_routes_in(&[]).unwrap(), []);
    assert_eq!(gateway_on(&[], index(1)), Err(MacsysError::NoDefaultRoute));
}

#[test]
fn sockaddrs_round_up_as_the_kernel_does() {
    for (len, space) in [
        (0, 4),
        (1, 4),
        (4, 4),
        (5, 8),
        (8, 8),
        (16, 16),
        (17, 20),
        (20, 20),
        (255, 256),
    ] {
        assert_eq!(sockaddr_space(len), space, "{len}");
    }
}

#[test]
fn an_arp_entry_yields_its_link_layer_address() {
    let mut table = arp_entry(9, [192, 168, 1, 1], &M7_LIKE);
    table.extend(arp_entry(4, [10, 1, 1, 1], &[0x02, 1, 2, 3, 4, 5]));
    let neighbours = neighbours_in(&table).unwrap();
    assert_eq!(
        neighbours,
        [
            Neighbour {
                interface_index: 9,
                addr: Ipv4Addr::new(192, 168, 1, 1),
                link: NeighbourLink::Ethernet(M7_LIKE),
            },
            Neighbour {
                interface_index: 4,
                addr: Ipv4Addr::new(10, 1, 1, 1),
                link: NeighbourLink::Ethernet([0x02, 1, 2, 3, 4, 5]),
            },
        ]
    );
    assert_eq!(
        neighbour_on(&neighbours, index(9), Ipv4Addr::new(192, 168, 1, 1)),
        Ok(M7_LIKE)
    );
    // The same address on another interface is another neighbour.
    assert_eq!(
        neighbour_on(&neighbours, index(4), Ipv4Addr::new(192, 168, 1, 1)),
        Err(MacsysError::NeighbourAbsent)
    );
    // An entry whose gateway is not a link-layer address is no neighbour.
    assert_eq!(neighbours_in(&not_link_entry()).unwrap(), []);
}

#[test]
fn incomplete_and_non_ethernet_neighbours_are_typed() {
    let gateway = Ipv4Addr::new(192, 168, 1, 1);
    let lookup = |table: Vec<u8>| neighbour_in_table(&table, index(9), gateway);
    assert_eq!(
        lookup(arp_entry(9, [192, 168, 1, 1], &[])),
        Err(MacsysError::NeighbourIncomplete)
    );
    assert_eq!(
        lookup(arp_entry(9, [192, 168, 1, 1], &[1, 2, 3, 4, 5, 6, 7, 8])),
        Err(MacsysError::NotEthernet { alen: 8 })
    );
    assert_eq!(
        lookup(arp_entry(9, [192, 168, 1, 2], &M7_LIKE)),
        Err(MacsysError::NeighbourAbsent)
    );
    let mut two = arp_entry(9, [192, 168, 1, 1], &M7_LIKE);
    two.extend(arp_entry(9, [192, 168, 1, 1], &[0x02, 9, 9, 9, 9, 9]));
    assert_eq!(lookup(two), Err(MacsysError::AmbiguousNeighbour));
    let mut same = arp_entry(9, [192, 168, 1, 1], &M7_LIKE);
    same.extend(arp_entry(9, [192, 168, 1, 1], &M7_LIKE));
    assert_eq!(lookup(same), Ok(M7_LIKE));
}

/// What the lookup decides is decided on the raw dump: a dump of no bytes
/// is `NeighbourTableEmpty`, and any other dump without an entry for the
/// gateway is `NeighbourAbsent`, even one none of whose messages is a
/// neighbour entry.
#[test]
fn an_empty_dump_is_empty_and_a_dump_without_the_entry_absent() {
    let gateway = Ipv4Addr::new(192, 168, 1, 1);
    assert_eq!(
        neighbour_in_table(&[], index(9), gateway),
        Err(MacsysError::NeighbourTableEmpty)
    );
    // Messages the parse skips leave no entry, but the dump was not empty.
    let skipped = not_link_entry();
    assert_eq!(neighbours_in(&skipped).unwrap(), []);
    assert_eq!(
        neighbour_in_table(&skipped, index(9), gateway),
        Err(MacsysError::NeighbourAbsent)
    );
    for table in [
        // A permanent entry for another address on the interface, as a
        // Mac's own address has (an observation nothing here relies on).
        arp_entry(9, [192, 168, 1, 60], &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
        // An entry on another interface only.
        arp_entry(4, [10, 1, 1, 1], &M7_LIKE),
        // Another address still being resolved.
        arp_entry(9, [192, 168, 1, 7], &[]),
    ] {
        assert_eq!(neighbours_in(&table).unwrap().len(), 1);
        assert_eq!(
            neighbour_in_table(&table, index(9), gateway),
            Err(MacsysError::NeighbourAbsent)
        );
    }
}

/// A dump that holds bytes but not a whole message is malformed, never
/// empty: only a dump of no bytes is `NeighbourTableEmpty`.
#[test]
fn a_dump_of_some_bytes_short_of_a_message_is_malformed() {
    let gateway = Ipv4Addr::new(192, 168, 1, 1);
    let table = arp_entry(9, [192, 168, 1, 1], &M7_LIKE);
    assert_eq!(
        neighbour_in_table(&table[..1], index(9), gateway),
        Err(MacsysError::MalformedRoute {
            fault: RouteFault::ShortHeader
        })
    );
}

#[test]
fn truncated_or_foreign_messages_are_refused() {
    let whole = default_route(9, [192, 0, 2, 1], UP_GATEWAY);
    let malformed = |fault| MacsysError::MalformedRoute { fault };
    // Fewer bytes than a length and a version.
    for cut in 1..=2 {
        assert_eq!(
            default_routes_in(&whole[..cut]).unwrap_err(),
            malformed(RouteFault::ShortHeader)
        );
    }
    // A length past the end of the table.
    assert_eq!(
        default_routes_in(&whole[..whole.len() - 1]).unwrap_err(),
        malformed(RouteFault::LengthOverrun)
    );
    // Another message version.
    let mut old = whole.clone();
    old[offset_of!(libc::rt_msghdr, rtm_version)] = 4;
    assert_eq!(
        default_routes_in(&old).unwrap_err(),
        malformed(RouteFault::Version)
    );
    // A length shorter than the header.
    let mut short = whole[..HEADER_LEN - 4].to_vec();
    let length = u16::try_from(short.len()).unwrap().to_ne_bytes();
    short[..2].copy_from_slice(&length);
    assert_eq!(
        default_routes_in(&short).unwrap_err(),
        malformed(RouteFault::ShortHeader)
    );
    // A zero length cannot loop.
    let mut zero = whole.clone();
    zero[..2].copy_from_slice(&0_u16.to_ne_bytes());
    assert_eq!(
        default_routes_in(&zero).unwrap_err(),
        malformed(RouteFault::ShortHeader)
    );
    // A socket address past the end of its message.
    let mut overrun = whole.clone();
    let declared = u16::try_from(HEADER_LEN + 8).unwrap().to_ne_bytes();
    overrun[..2].copy_from_slice(&declared);
    assert_eq!(
        default_routes_in(&overrun[..HEADER_LEN + 8]).unwrap_err(),
        malformed(RouteFault::SockaddrOverrun)
    );
    // A link-layer address past the end of its socket address.
    let mut dl = link(9, "en9", &M7_LIKE);
    dl[6] = 40;
    let bad_link = message(
        9,
        libc::RTF_UP | libc::RTF_LLINFO,
        &[(DST, inet([192, 168, 1, 1])), (GATEWAY, dl)],
    );
    assert_eq!(
        neighbours_in(&bad_link).unwrap_err(),
        malformed(RouteFault::SockaddrOverrun)
    );
    // A version-4 message is refused by the neighbour parse too.
    let foreign = message_of_version(4, 9, libc::RTF_LLINFO, &[(DST, inet([1, 2, 3, 4]))]);
    assert_eq!(
        neighbours_in(&foreign).unwrap_err(),
        malformed(RouteFault::Version)
    );
}
