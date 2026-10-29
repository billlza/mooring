// SPDX-License-Identifier: GPL-3.0-or-later

//! configd's IPv4 services against `scutil` as the oracle, which reads the
//! same dynamic store, and the parser of the link-layer addresses it
//! prints. The oracle runs only here; the crate never shells out. Failure
//! messages give interface names and counts, never a link-layer address.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::configd::{Ipv4Service, ipv4_services, link_layer_address};

/// One service as both sides describe it: the interface, the router, the
/// router's link-layer address and the DNS domain.
type Described = (String, Option<String>, Option<[u8; 6]>, Option<String>);

/// Runs `scutil` with `commands` on its standard input and returns its
/// output.
fn scutil(commands: &str) -> String {
    let mut child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{commands}\nquit\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "scutil failed");
    String::from_utf8(output.stdout).unwrap()
}

/// The top-level `Key : value` lines of a dictionary `scutil show` prints
/// (two spaces of indentation; nested values are indented further).
fn top_level(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let entry = line.strip_prefix("  ")?;
        if entry.starts_with(' ') {
            return None;
        }
        let (found, value) = entry.split_once(" : ")?;
        (found == key).then(|| value.to_owned())
    })
}

fn scutil_services() -> BTreeSet<Described> {
    scutil("list State:/Network/Service/[^/]+/IPv4")
        .lines()
        .filter_map(|line| line.split_once(" = ").map(|(_, key)| key.to_owned()))
        .map(|key| {
            let service = scutil(&format!("show {key}"));
            let dns = scutil(&format!("show {}/DNS", key.strip_suffix("/IPv4").unwrap()));
            (
                top_level(&service, "InterfaceName").unwrap(),
                top_level(&service, "Router"),
                top_level(&service, "ARPResolvedHardwareAddress")
                    .map(|text| link_layer_address(&text).unwrap()),
                top_level(&dns, "DomainName"),
            )
        })
        .collect()
}

fn describe(service: &Ipv4Service) -> Described {
    (
        service.interface.clone(),
        service.router.map(|router| router.to_string()),
        service.router_lladdr,
        service.domain.clone(),
    )
}

fn macsys_services() -> BTreeSet<Described> {
    ipv4_services().unwrap().iter().map(describe).collect()
}

/// The live IPv4 services equal `scutil`'s, interface, router, resolved
/// link-layer address and DNS domain included. The comparison is made on a
/// store that did not change while `scutil` read it.
#[test]
fn the_live_ipv4_services_match_scutil() {
    for _attempt in 0..3 {
        let before = macsys_services();
        let oracle = scutil_services();
        let after = macsys_services();
        if before == after {
            assert_eq!(
                before.len(),
                oracle.len(),
                "service count ({} interfaces listed)",
                before
                    .iter()
                    .map(|(interface, ..)| interface.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            for (
                (interface, router, lladdr, domain),
                (o_interface, o_router, o_lladdr, o_domain),
            ) in before.iter().zip(&oracle)
            {
                assert_eq!(interface, o_interface);
                assert_eq!(router, o_router, "{interface}: router");
                assert!(
                    lladdr == o_lladdr,
                    "{interface}: the link-layer address differs"
                );
                assert_eq!(domain, o_domain, "{interface}: domain");
            }
            return;
        }
    }
    panic!("the dynamic store kept changing");
}

/// Every live service names an interface the kernel lists, and a resolved
/// link-layer address is a unicast one.
#[test]
fn every_live_service_names_a_listed_interface() {
    let names: BTreeSet<String> = crate::iflist::interfaces()
        .unwrap()
        .into_iter()
        .map(|interface| interface.name)
        .collect();
    for service in ipv4_services().unwrap() {
        assert!(
            names.contains(&service.interface),
            "{} is not in the interface list",
            service.interface
        );
        if let Some(lladdr) = service.router_lladdr {
            assert_eq!(lladdr[0] & 1, 0, "{}: a group address", service.interface);
            assert_ne!(lladdr, [0; 6], "{}: an all-zero address", service.interface);
        }
    }
}

#[test]
fn link_layer_addresses_are_parsed_as_configd_prints_them() {
    assert_eq!(
        link_layer_address("44:64:3c:7b:d4:bf"),
        Some([0x44, 0x64, 0x3c, 0x7b, 0xd4, 0xbf])
    );
    assert_eq!(
        link_layer_address("0:55:7b:b5:7d:f8"),
        Some([0x00, 0x55, 0x7b, 0xb5, 0x7d, 0xf8])
    );
    assert_eq!(
        link_layer_address("00:55:7B:B5:7D:F8"),
        Some([0x00, 0x55, 0x7b, 0xb5, 0x7d, 0xf8])
    );
    for bad in [
        "",
        "44:64:3c:7b:d4",
        "44:64:3c:7b:d4:bf:00",
        "44:64:3c:7b:d4:zz",
        "444:64:3c:7b:d4:bf",
        "44:64:3c:7b:d4:",
        "44-64-3c-7b-d4-bf",
        " 44:64:3c:7b:d4:bf",
    ] {
        assert_eq!(link_layer_address(bad), None, "{bad:?}");
    }
}
