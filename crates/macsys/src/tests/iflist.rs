// SPDX-License-Identifier: GPL-3.0-or-later

//! The interface list: `NET_RT_IFLIST2` dumps built byte by byte, as the
//! kernel lays them out (an `if_msghdr2` or `ifa_msghdr`, then each present
//! socket address rounded up to four bytes), and the live list of this Mac
//! checked against `ifconfig`. Failure messages give names, counts and
//! IPv4 addresses, never a link-layer address.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::{offset_of, size_of};
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::process::Command;

use crate::error::{MacsysError, RouteFault};
use crate::iflist::{Interface, InterfaceAddrV4, interface, interfaces, interfaces_in};
use crate::interface::interface_index;
use crate::route::messages::sockaddr_space;

const NETMASK: usize = 2;
const IFP: usize = 4;
const IFA: usize = 5;
const BRD: usize = 7;

const IFT_ETHER: u8 = 6;
const IFT_LOOP: u8 = 24;

fn put(message: &mut [u8], at: usize, bytes: &[u8]) {
    message[at..at + bytes.len()].copy_from_slice(bytes);
}

/// The socket addresses of `slots`, each padded to its space, and the
/// presence bits for them.
fn sockaddrs(slots: &[(usize, Vec<u8>)]) -> (i32, Vec<u8>) {
    let mut present = 0_i32;
    let mut body = Vec::new();
    for (slot, sockaddr) in slots {
        present |= 1 << slot;
        let mut padded = sockaddr.clone();
        padded.resize(sockaddr_space(sockaddr.first().copied().unwrap_or(0)), 0);
        body.extend(padded);
    }
    (present, body)
}

/// The fields of one interface's `RTM_IFINFO2` message.
struct Info {
    index: u16,
    flags: i32,
    link_type: u8,
    mtu: u32,
    ibytes: u64,
    obytes: u64,
}

const EN9: Info = Info {
    index: 21,
    flags: libc::IFF_UP | libc::IFF_RUNNING,
    link_type: IFT_ETHER,
    mtu: 1500,
    ibytes: 0x1_0000_0001,
    obytes: 0x2_0000_0002,
};

const LO0: Info = Info {
    index: 1,
    flags: libc::IFF_UP | libc::IFF_RUNNING,
    link_type: IFT_LOOP,
    mtu: 16384,
    ibytes: 7,
    obytes: 7,
};

fn ifinfo_of(version: u8, info: &Info, slots: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let header = size_of::<libc::if_msghdr2>();
    let data = offset_of!(libc::if_msghdr2, ifm_data);
    let (present, body) = sockaddrs(slots);
    let mut message = vec![0_u8; header];
    let length = u16::try_from(header + body.len()).unwrap();
    put(
        &mut message,
        offset_of!(libc::if_msghdr2, ifm_msglen),
        &length.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::if_msghdr2, ifm_version),
        &[version],
    );
    put(
        &mut message,
        offset_of!(libc::if_msghdr2, ifm_type),
        &[u8::try_from(libc::RTM_IFINFO2).unwrap()],
    );
    put(
        &mut message,
        offset_of!(libc::if_msghdr2, ifm_addrs),
        &present.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::if_msghdr2, ifm_flags),
        &info.flags.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::if_msghdr2, ifm_index),
        &info.index.to_ne_bytes(),
    );
    put(
        &mut message,
        data + offset_of!(libc::if_data64, ifi_type),
        &[info.link_type],
    );
    put(
        &mut message,
        data + offset_of!(libc::if_data64, ifi_mtu),
        &info.mtu.to_ne_bytes(),
    );
    put(
        &mut message,
        data + offset_of!(libc::if_data64, ifi_ibytes),
        &info.ibytes.to_ne_bytes(),
    );
    put(
        &mut message,
        data + offset_of!(libc::if_data64, ifi_obytes),
        &info.obytes.to_ne_bytes(),
    );
    message.extend(body);
    message
}

fn ifinfo(info: &Info, link: Vec<u8>) -> Vec<u8> {
    ifinfo_of(5, info, &[(IFP, link)])
}

/// An `ifa_msghdr` message of type `rtm_type` for interface `index`.
fn addr_message(rtm_type: i32, index: u16, slots: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let header = size_of::<libc::ifa_msghdr>();
    let (present, body) = sockaddrs(slots);
    let mut message = vec![0_u8; header];
    let length = u16::try_from(header + body.len()).unwrap();
    put(
        &mut message,
        offset_of!(libc::ifa_msghdr, ifam_msglen),
        &length.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::ifa_msghdr, ifam_version),
        &[5],
    );
    put(
        &mut message,
        offset_of!(libc::ifa_msghdr, ifam_type),
        &[u8::try_from(rtm_type).unwrap()],
    );
    put(
        &mut message,
        offset_of!(libc::ifa_msghdr, ifam_addrs),
        &present.to_ne_bytes(),
    );
    put(
        &mut message,
        offset_of!(libc::ifa_msghdr, ifam_index),
        &index.to_ne_bytes(),
    );
    message.extend(body);
    message
}

/// An `RTM_NEWADDR` for `addr` with a netmask trimmed as the kernel trims
/// it (`mask_len` bytes, the mask from offset 4).
fn newaddr(index: u16, addr: [u8; 4], mask_len: u8, mask: &[u8]) -> Vec<u8> {
    addr_message(
        libc::RTM_NEWADDR,
        index,
        &[
            (NETMASK, netmask(mask_len, mask)),
            (IFA, inet(addr)),
            (BRD, inet([0; 4])),
        ],
    )
}

fn inet(addr: [u8; 4]) -> Vec<u8> {
    let mut sockaddr = vec![0_u8; 16];
    sockaddr[0] = 16;
    sockaddr[1] = u8::try_from(libc::AF_INET).unwrap();
    sockaddr[4..8].copy_from_slice(&addr);
    sockaddr
}

fn inet6() -> Vec<u8> {
    let mut sockaddr = vec![0_u8; 28];
    sockaddr[0] = 28;
    sockaddr[1] = u8::try_from(libc::AF_INET6).unwrap();
    sockaddr[8] = 0xfe;
    sockaddr[9] = 0x80;
    sockaddr
}

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
fn link(if_index: u16, name: &[u8], addr: &[u8]) -> Vec<u8> {
    let used = 8 + name.len() + addr.len();
    let len = used.max(20);
    let mut sockaddr = vec![0_u8; len];
    sockaddr[0] = u8::try_from(len).unwrap();
    sockaddr[1] = u8::try_from(libc::AF_LINK).unwrap();
    sockaddr[2..4].copy_from_slice(&if_index.to_ne_bytes());
    sockaddr[5] = u8::try_from(name.len()).unwrap();
    sockaddr[6] = u8::try_from(addr.len()).unwrap();
    sockaddr[8..8 + name.len()].copy_from_slice(name);
    sockaddr[8 + name.len()..used].copy_from_slice(addr);
    sockaddr
}

const EN9_LLADDR: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

fn en9_message() -> Vec<u8> {
    ifinfo(&EN9, link(EN9.index, b"en9", &EN9_LLADDR))
}

fn malformed(table: &[u8]) -> Option<RouteFault> {
    match interfaces_in(table) {
        Err(MacsysError::MalformedRoute { fault }) => Some(fault),
        _ => None,
    }
}

#[test]
fn a_list_gives_each_interface_with_its_ipv4_addresses() {
    let table = [
        ifinfo(&LO0, link(LO0.index, b"lo0", &[])),
        newaddr(LO0.index, [127, 0, 0, 1], 5, &[255]),
        addr_message(libc::RTM_NEWADDR, LO0.index, &[(IFA, inet6())]),
        addr_message(
            libc::RTM_NEWMADDR2,
            LO0.index,
            &[(IFA, inet([224, 0, 0, 1]))],
        ),
        en9_message(),
        newaddr(EN9.index, [192, 168, 1, 60], 7, &[255, 255, 255]),
        newaddr(EN9.index, [10, 0, 0, 2], 8, &[255, 255, 255, 252]),
    ]
    .concat();
    let list = interfaces_in(&table).unwrap();
    assert_eq!(
        list,
        vec![
            Interface {
                index: NonZeroU32::new(1).unwrap(),
                name: "lo0".to_owned(),
                link_type: IFT_LOOP,
                lladdr: None,
                up: true,
                running: true,
                mtu: 16384,
                ibytes: 7,
                obytes: 7,
                ipv4: vec![InterfaceAddrV4 {
                    addr: Ipv4Addr::LOCALHOST,
                    prefix_len: Some(8),
                }],
            },
            Interface {
                index: NonZeroU32::new(21).unwrap(),
                name: "en9".to_owned(),
                link_type: IFT_ETHER,
                lladdr: Some(EN9_LLADDR),
                up: true,
                running: true,
                mtu: 1500,
                ibytes: 0x1_0000_0001,
                obytes: 0x2_0000_0002,
                ipv4: vec![
                    InterfaceAddrV4 {
                        addr: Ipv4Addr::new(192, 168, 1, 60),
                        prefix_len: Some(24),
                    },
                    InterfaceAddrV4 {
                        addr: Ipv4Addr::new(10, 0, 0, 2),
                        prefix_len: Some(30),
                    },
                ],
            },
        ]
    );
}

#[test]
fn flags_masks_and_link_addresses_are_read_as_given() {
    let down = Info {
        flags: libc::IFF_UP,
        ..EN9
    };
    let table = [
        ifinfo(&down, link(EN9.index, b"en9", &[1, 2, 3, 4, 5, 6, 7, 8])),
        addr_message(libc::RTM_NEWADDR, EN9.index, &[(IFA, inet([10, 1, 2, 3]))]),
        newaddr(EN9.index, [10, 9, 9, 9], 0, &[]),
        newaddr(EN9.index, [10, 8, 8, 8], 8, &[255, 255, 255, 255]),
    ]
    .concat();
    let list = interfaces_in(&table).unwrap();
    let [en9] = list.as_slice() else {
        panic!("one interface expected, got {}", list.len());
    };
    assert!(en9.up);
    assert!(!en9.running);
    assert_eq!(
        en9.lladdr, None,
        "an 8-byte link-layer address is not Ethernet"
    );
    assert_eq!(
        en9.ipv4
            .iter()
            .map(|addr| addr.prefix_len)
            .collect::<Vec<_>>(),
        vec![None, Some(0), Some(32)]
    );
}

#[test]
fn an_empty_list_has_no_interface() {
    assert_eq!(interfaces_in(&[]), Ok(Vec::new()));
}

#[test]
fn a_list_that_breaks_its_form_is_refused() {
    let mut unexpected = en9_message();
    unexpected[offset_of!(libc::if_msghdr2, ifm_type)] = 1;
    let mut old_version = en9_message();
    old_version[offset_of!(libc::if_msghdr2, ifm_version)] = 4;
    let mut overrun = en9_message();
    overrun.truncate(overrun.len() - 1);
    let short_header = {
        let mut message = en9_message();
        let short = u16::try_from(size_of::<libc::if_msghdr2>() - 1).unwrap();
        put(&mut message, 0, &short.to_ne_bytes());
        message.truncate(usize::from(short));
        message
    };
    let short_address_header = {
        let mut message = addr_message(libc::RTM_NEWADDR, EN9.index, &[]);
        message.truncate(message.len() - 1);
        let short = u16::try_from(message.len()).unwrap();
        put(&mut message, 0, &short.to_ne_bytes());
        message
    };
    let link_overrun = {
        let mut sockaddr = link(EN9.index, b"en9", &EN9_LLADDR);
        sockaddr[6] = 40;
        ifinfo(&EN9, sockaddr)
    };
    let cases: [(&str, Vec<u8>, RouteFault); 14] = [
        (
            "a table of three bytes",
            vec![0, 0, 0],
            RouteFault::ShortHeader,
        ),
        (
            "a message past the table",
            overrun,
            RouteFault::LengthOverrun,
        ),
        ("another version", old_version, RouteFault::Version),
        (
            "a route message",
            unexpected,
            RouteFault::UnexpectedType { rtm_type: 1 },
        ),
        (
            "a short interface header",
            short_header,
            RouteFault::ShortHeader,
        ),
        (
            "a short address header",
            [en9_message(), short_address_header].concat(),
            RouteFault::ShortHeader,
        ),
        (
            "no link socket address",
            ifinfo_of(5, &EN9, &[(IFA, inet([10, 0, 0, 1]))]),
            RouteFault::MissingLink,
        ),
        (
            "index 0",
            ifinfo(&Info { index: 0, ..EN9 }, link(0, b"en9", &EN9_LLADDR)),
            RouteFault::ZeroIndex,
        ),
        (
            "an empty name",
            ifinfo(&EN9, link(EN9.index, b"", &EN9_LLADDR)),
            RouteFault::InvalidName,
        ),
        (
            "a name that is not UTF-8",
            ifinfo(&EN9, link(EN9.index, &[0xff, 0x39], &EN9_LLADDR)),
            RouteFault::InvalidName,
        ),
        (
            "a link address past its socket address",
            link_overrun,
            RouteFault::SockaddrOverrun,
        ),
        (
            "an address before its interface",
            [
                newaddr(EN9.index, [10, 0, 0, 1], 8, &[255, 255, 255]),
                en9_message(),
            ]
            .concat(),
            RouteFault::UnknownInterface,
        ),
        (
            "an interface twice",
            [en9_message(), en9_message()].concat(),
            RouteFault::DuplicateInterface,
        ),
        (
            "a netmask with a hole",
            [
                en9_message(),
                newaddr(EN9.index, [10, 0, 0, 1], 8, &[255, 0, 255]),
            ]
            .concat(),
            RouteFault::NonContiguousMask,
        ),
    ];
    for (case, table, fault) in cases {
        assert_eq!(malformed(&table), Some(fault), "{case}");
    }
}

fn ifconfig(args: &[&str]) -> String {
    let output = Command::new("/sbin/ifconfig").args(args).output().unwrap();
    assert!(output.status.success(), "ifconfig {args:?} failed");
    String::from_utf8(output.stdout).unwrap()
}

/// Each interface `ifconfig` lists, with its `ether` address and IPv4
/// addresses.
fn ifconfig_interfaces() -> BTreeMap<String, (Option<[u8; 6]>, BTreeSet<Ipv4Addr>)> {
    let mut found = BTreeMap::new();
    for name in ifconfig(&["-l"]).split_whitespace() {
        let text = ifconfig(&[name]);
        let ether = text
            .lines()
            .filter_map(|line| line.trim().strip_prefix("ether "))
            .find_map(|rest| {
                let octets: Vec<u8> = rest
                    .split_whitespace()
                    .next()?
                    .split(':')
                    .map(|octet| u8::from_str_radix(octet, 16))
                    .collect::<Result<_, _>>()
                    .ok()?;
                <[u8; 6]>::try_from(octets).ok()
            });
        let ipv4 = text
            .lines()
            .filter_map(|line| line.trim().strip_prefix("inet "))
            .filter_map(|rest| rest.split_whitespace().next()?.parse().ok())
            .collect();
        found.insert(name.to_owned(), (ether, ipv4));
    }
    found
}

#[test]
fn the_live_list_matches_ifconfig() {
    let expected = ifconfig_interfaces();
    let list = interfaces().unwrap();
    let names: BTreeSet<&str> = list
        .iter()
        .map(|interface| interface.name.as_str())
        .collect();
    assert_eq!(
        names,
        expected.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        "interface names"
    );
    for interface in &list {
        let (ether, ipv4) = &expected[&interface.name];
        assert_eq!(
            interface.index,
            interface_index(&interface.name).unwrap(),
            "{}: index",
            interface.name
        );
        if ether.is_some() {
            assert!(
                interface.lladdr == *ether,
                "{}: the link-layer address differs from ifconfig's",
                interface.name
            );
        }
        assert_eq!(
            &interface
                .ipv4
                .iter()
                .map(|addr| addr.addr)
                .collect::<BTreeSet<_>>(),
            ipv4,
            "{}: IPv4 addresses",
            interface.name
        );
    }
    let lo0 = list
        .iter()
        .find(|interface| interface.name == "lo0")
        .unwrap();
    assert!(lo0.up && lo0.running);
    assert!(
        lo0.ipv4.contains(&InterfaceAddrV4 {
            addr: Ipv4Addr::LOCALHOST,
            prefix_len: Some(8),
        }),
        "lo0 lacks 127.0.0.1/8"
    );
}

/// One interface is read by index, and its byte counters move with
/// traffic. The step is 64 KiB because this process reads them rounded
/// down to a multiple of 1024 and modulo 2^32 (measured on macOS 27.0.1,
/// see `Interface::obytes`), so the difference is taken modulo 2^32.
#[test]
fn one_interface_is_read_by_index_and_its_counters_move() {
    const SENT: u64 = 64 * 1024;
    let index = interface_index("lo0").unwrap();
    let before = interface(index).unwrap();
    assert_eq!(before.name, "lo0");
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..64 {
        socket.send_to(&[0; 1024], "127.0.0.1:9").unwrap();
    }
    let after = interface(index).unwrap();
    let moved = |before: u64, after: u64| after.wrapping_sub(before) & u64::from(u32::MAX);
    assert!(
        moved(before.obytes, after.obytes) >= SENT - 1024,
        "lo0's sent bytes did not move"
    );
    assert!(
        moved(before.ibytes, after.ibytes) >= SENT - 1024,
        "lo0's received bytes did not move"
    );
    let absent = NonZeroU32::new(u32::from(u16::MAX)).unwrap();
    assert_eq!(interface(absent), Err(MacsysError::InterfaceAbsent));
}
