// SPDX-License-Identifier: GPL-3.0-or-later

//! The live tables of this Mac. The crate never shells out; these tests run
//! `netstat` and `arp` only as oracles, reading the same kernel tables, and
//! compare. They read local tables and send nothing. Failure messages give
//! counts and IPv4 addresses, never a link-layer address.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::process::Command;

use crate::error::MacsysError;
use crate::interface::interface_index;
use crate::route::{
    Neighbour, NeighbourLink, default_gateway_v4, default_routes_v4, neighbour_table, neighbour_v4,
    neighbours_in,
};

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(output.status.success(), "{program} failed");
    String::from_utf8(output.stdout).unwrap()
}

/// Every entry of the live neighbour table with a link-layer gateway.
fn neighbours_v4() -> Vec<Neighbour> {
    neighbours_in(&neighbour_table().unwrap()).unwrap()
}

#[test]
fn lo0_has_an_index_and_no_default_route() {
    let lo0 = interface_index("lo0").unwrap();
    assert_eq!(default_gateway_v4(lo0), Err(MacsysError::NoDefaultRoute));
}

#[test]
fn an_absent_or_invalid_interface_is_typed() {
    assert_eq!(interface_index("zz9"), Err(MacsysError::InterfaceAbsent));
    assert_eq!(
        interface_index("zzzzzzzzzzzzzz9"),
        Err(MacsysError::InterfaceAbsent)
    );
    for invalid in ["", "en\0", "en\u{0}9", "zzzzzzzzzzzzzzz9"] {
        assert_eq!(
            interface_index(invalid),
            Err(MacsysError::InvalidInterfaceName),
            "{invalid:?}"
        );
    }
}

/// The live routing and neighbour tables parse, and their entries name an
/// interface and a gateway, or an address. The neighbour half checks
/// nothing under cargo or nextest on macOS 27.0.1 (26A434): this
/// ad-hoc-signed binary, under an ad-hoc-signed runner, reads an empty dump
/// there (design §15.6 rule 10). On macOS before 27 it parses the live
/// entries *(inference: the hiding is reported from macOS 27 on)*.
#[test]
fn the_routing_and_arp_tables_parse() {
    let routes = default_routes_v4().unwrap();
    let neighbours = neighbours_v4();
    for route in &routes {
        assert_ne!(route.interface_index, 0);
        assert_ne!(route.gateway, Ipv4Addr::UNSPECIFIED);
    }
    for neighbour in &neighbours {
        assert_ne!(neighbour.addr, Ipv4Addr::UNSPECIFIED);
    }
}

/// `netstat -rn -f inet`'s up IPv4 default routes through an IPv4
/// gateway, as (interface index, gateway, scoped), `I` being `RTF_IFSCOPE`.
fn netstat_default_routes() -> BTreeSet<(u32, Ipv4Addr, bool)> {
    run("/usr/sbin/netstat", &["-rn", "-f", "inet"])
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [destination, gateway, flags, netif, ..] = fields.as_slice() else {
                return None;
            };
            if *destination != "default" || !flags.contains('U') || !flags.contains('G') {
                return None;
            }
            let gateway: Ipv4Addr = gateway.parse().ok()?;
            Some((
                interface_index(netif).unwrap().get(),
                gateway,
                flags.contains('I'),
            ))
        })
        .collect()
}

fn macsys_default_routes() -> BTreeSet<(u32, Ipv4Addr, bool)> {
    default_routes_v4()
        .unwrap()
        .into_iter()
        .map(|route| (route.interface_index, route.gateway, route.scoped))
        .collect()
}

/// The default routes equal `netstat`'s, scoped ones included (on this Mac
/// the M7's interface has a scoped default route). The comparison is made
/// on a table that did not change while `netstat` read it.
#[test]
fn default_routes_match_netstat() {
    for _attempt in 0..3 {
        let before = macsys_default_routes();
        let oracle = netstat_default_routes();
        let after = macsys_default_routes();
        if before == after {
            assert_eq!(before, oracle);
            return;
        }
    }
    panic!("the routing table kept changing");
}

/// Parses one hexadecimal octet as `arp` prints it (no leading zero).
fn octet(text: &str) -> Option<u8> {
    if text.is_empty() || text.len() > 2 {
        return None;
    }
    u8::from_str_radix(text, 16).ok()
}

/// `arp -an`'s complete entries as (address, link-layer address).
fn arp_entries() -> BTreeSet<(Ipv4Addr, [u8; 6])> {
    run("/usr/sbin/arp", &["-an"])
        .lines()
        .filter_map(|line| {
            let addr = line.split_once('(')?.1.split_once(')')?.0.parse().ok()?;
            let lladdr = line.split_once(" at ")?.1.split_whitespace().next()?;
            let octets: Vec<u8> = lladdr.split(':').map(octet).collect::<Option<_>>()?;
            Some((addr, <[u8; 6]>::try_from(octets).ok()?))
        })
        .collect()
}

fn macsys_neighbours() -> BTreeSet<(Ipv4Addr, [u8; 6])> {
    neighbours_v4()
        .into_iter()
        .filter_map(|neighbour| match neighbour.link {
            NeighbourLink::Ethernet(bytes) => Some((neighbour.addr, bytes)),
            NeighbourLink::Incomplete | NeighbourLink::Other { .. } => None,
        })
        .collect()
}

/// The kernel's own neighbour dump, read and classified by `neighbour_v4`.
/// `lo0` has no neighbour entries, so a TEST-NET-1 address there is
/// `NeighbourAbsent` in a dump that holds any bytes and
/// `NeighbourTableEmpty` in a dump of none. Under cargo or nextest, both ad
/// hoc signed, macOS 27.0.1 (26A434) returns this binary an empty dump
/// (design §15.6 rule 10), so there the test checks that branch through the
/// real `sysctl` read. The comparison is made on a dump whose emptiness did
/// not change around the lookup.
#[test]
fn the_live_neighbour_dump_is_classified_by_its_emptiness() {
    let lo0 = interface_index("lo0").unwrap();
    let documentation = Ipv4Addr::new(192, 0, 2, 1);
    for _attempt in 0..3 {
        let before = neighbour_table().unwrap().is_empty();
        let found = neighbour_v4(lo0, documentation);
        let after = neighbour_table().unwrap().is_empty();
        if before == after {
            let expected = if before {
                MacsysError::NeighbourTableEmpty
            } else {
                MacsysError::NeighbourAbsent
            };
            assert_eq!(found, Err(expected));
            return;
        }
    }
    panic!("the neighbour dump kept changing between empty and not");
}

/// Every complete neighbour entry that stayed the same while `arp` ran is
/// in `arp`'s output, with the same link-layer address, and every entry
/// `arp` shows was seen by one of the two reads around it.
///
/// On macOS 27.0.1 (26A434), under an ad-hoc-signed runner, this checks
/// nothing. Measured there on 2026-10-14 (design §15.6 rule 10): the
/// kernel showed the table to a reader whose code-signing identifier is
/// reverse-DNS, and to no reader with an ad-hoc-signed ancestor; that it
/// shows it only to readers with such an identifier and no such ancestor is
/// an inference from the measured cases. This test binary is linker-signed
/// ad hoc as `mooring_macsys-<hash>` and runs under cargo or nextest, both
/// ad hoc signed, so there it and its `arp` child both read an empty table,
/// and only their agreement on that is checked. Re-signed ad hoc with a
/// reverse-DNS identifier and run from a shell, the binary reads the entries
/// (10 stable ones that day), but its `arp` child, whose parent is then that
/// ad-hoc-signed binary, reads none, and the test fails with a message
/// naming the rule. On macOS before 27 both read the table and the test
/// compares them *(inference: the hiding is reported from macOS 27 on)*; it
/// is kept because it compares again wherever the kernel shows the table.
/// The parse of real entries is covered by messages built byte by byte
/// (`messages.rs`), and the kernel read by
/// `the_live_neighbour_dump_is_classified_by_its_emptiness`. (On 2026-10-13
/// the empty reads were put down to local network privacy; the 2026-10-14
/// measurement refuted that.)
#[test]
fn neighbours_match_the_arp_tool() {
    let before = macsys_neighbours();
    let oracle = arp_entries();
    let after = macsys_neighbours();
    let stable: BTreeSet<_> = before.intersection(&after).copied().collect();
    assert!(
        !oracle.is_empty() || stable.is_empty(),
        "arp read no entry while this binary read {} stable ones: on macOS 27.0.1 the kernel hid \
         the table from a process with an ad-hoc-signed ancestor, as this binary is to arp (design \
         §15.6 rule 10), so this run cannot compare the two",
        stable.len()
    );
    let missing = stable.difference(&oracle).count();
    assert_eq!(
        missing, 0,
        "{missing} stable entries are not in arp's output"
    );
    let seen: BTreeSet<_> = before.union(&after).copied().collect();
    let unseen: Vec<Ipv4Addr> = oracle.difference(&seen).map(|(addr, _)| *addr).collect();
    assert!(
        unseen.is_empty(),
        "arp shows entries for {unseen:?} that were not read"
    );
    let stable_addrs: BTreeSet<Ipv4Addr> = stable.iter().map(|(addr, _)| *addr).collect();
    let differing: Vec<Ipv4Addr> = oracle
        .iter()
        .filter(|entry| stable_addrs.contains(&entry.0) && !stable.contains(entry))
        .map(|(addr, _)| *addr)
        .collect();
    assert!(
        differing.is_empty(),
        "arp shows other link-layer addresses for {differing:?}"
    );
}
