// SPDX-License-Identifier: GPL-3.0-or-later

//! configd's IPv4 services against `scutil` as the oracle, which reads the
//! same dynamic store; what is read from a service's dictionaries, built
//! here with every field present, absent or of the wrong form; and the
//! parser of the link-layer addresses configd prints. The oracle runs only
//! here; the crate never shells out. Failure messages give interface names
//! and counts, never a live link-layer address.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;

use crate::configd::{
    Dictionary, Ipv4Service, as_dictionary, as_string, dictionary, dns_key, ipv4_services, keys,
    link_layer_address, open, service, services_in,
};
use crate::error::{ConfigdFault, MacsysError};

/// A link-layer address of the locally administered range, as configd
/// prints one (octets without leading zeros).
const ROUTER_LLADDR: &str = "2:0:5e:10:20:30";

/// A dictionary of `entries`, keyed as configd keys its own.
fn dictionary_of(entries: &[(&str, CFType)]) -> Dictionary {
    let pairs: Vec<(CFString, CFType)> = entries
        .iter()
        .map(|(key, value)| (CFString::new(key), value.clone()))
        .collect();
    Dictionary::from_CFType_pairs(&pairs)
}

fn text(value: &str) -> CFType {
    CFString::new(value).as_CFType()
}

fn number(value: i32) -> CFType {
    CFNumber::from(value).as_CFType()
}

fn fault(fault: ConfigdFault) -> MacsysError {
    MacsysError::Configd { fault }
}

/// The IPv4 dictionary of a service on `en9` with a router whose
/// link-layer address configd resolved, and one more key, which is not
/// read.
fn en9_ipv4() -> Vec<(&'static str, CFType)> {
    vec![
        ("InterfaceName", text("en9")),
        ("Router", text("192.168.1.1")),
        ("ARPResolvedHardwareAddress", text(ROUTER_LLADDR)),
        ("ConfirmedInterfaceName", text("en10")),
    ]
}

/// `entries` with the entry `key` replaced by `value`, or left out when
/// `value` is `None`.
fn with(
    entries: &[(&'static str, CFType)],
    key: &'static str,
    value: Option<CFType>,
) -> Vec<(&'static str, CFType)> {
    let mut changed: Vec<_> = entries
        .iter()
        .filter(|(found, _)| *found != key)
        .cloned()
        .collect();
    changed.extend(value.map(|value| (key, value)));
    changed
}

#[test]
fn a_service_is_read_with_every_field_configd_gives() {
    let dns = dictionary_of(&[
        ("DomainName", text("home.example")),
        ("ServerAddresses", text("192.168.1.1")),
    ]);
    assert_eq!(
        service(&dictionary_of(&en9_ipv4()), Some(&dns)),
        Ok(Ipv4Service {
            interface: "en9".to_owned(),
            router: Some(Ipv4Addr::new(192, 168, 1, 1)),
            router_lladdr: Some([0x02, 0x00, 0x5e, 0x10, 0x20, 0x30]),
            domain: Some("home.example".to_owned()),
        })
    );
}

/// A router, its link-layer address and the domain are each read as
/// absent when configd gives none, the domain also when the service has no
/// DNS settings at all.
#[test]
fn a_service_without_a_router_an_address_or_a_domain_reads_none_of_them() {
    let bare = dictionary_of(&[("InterfaceName", text("en0"))]);
    let expected = Ok(Ipv4Service {
        interface: "en0".to_owned(),
        router: None,
        router_lladdr: None,
        domain: None,
    });
    assert_eq!(service(&bare, None), expected);
    assert_eq!(service(&bare, Some(&dictionary_of(&[]))), expected);
    // An empty domain is none: DHCP option 15 cannot carry one.
    let empty_domain = dictionary_of(&[("DomainName", text(""))]);
    assert_eq!(service(&bare, Some(&empty_domain)), expected);
    let unresolved = dictionary_of(&with(&en9_ipv4(), "ARPResolvedHardwareAddress", None));
    assert_eq!(
        service(&unresolved, None).map(|service| (service.router, service.router_lladdr)),
        Ok((Some(Ipv4Addr::new(192, 168, 1, 1)), None))
    );
}

/// A service is never read as something it is not: each field that is not
/// as configd documents it is refused with its fault.
#[test]
fn a_service_that_is_not_as_configd_documents_it_is_refused() {
    let ipv4 = en9_ipv4();
    let cases = [
        (
            "no interface name",
            with(&ipv4, "InterfaceName", None),
            ConfigdFault::InterfaceNameMissing,
        ),
        (
            "an empty interface name",
            with(&ipv4, "InterfaceName", Some(text(""))),
            ConfigdFault::InterfaceNameMissing,
        ),
        (
            "an interface name that is a number",
            with(&ipv4, "InterfaceName", Some(number(9))),
            ConfigdFault::NotAString,
        ),
        (
            "a router that is a number",
            with(&ipv4, "Router", Some(number(1))),
            ConfigdFault::NotAString,
        ),
        (
            "a router of three octets",
            with(&ipv4, "Router", Some(text("192.168.1"))),
            ConfigdFault::Router,
        ),
        (
            "an IPv6 router",
            with(&ipv4, "Router", Some(text("fe80::1"))),
            ConfigdFault::Router,
        ),
        (
            "a link-layer address of five octets",
            with(
                &ipv4,
                "ARPResolvedHardwareAddress",
                Some(text("2:0:5e:10:20")),
            ),
            ConfigdFault::HardwareAddress,
        ),
        (
            "a link-layer address that is a number",
            with(&ipv4, "ARPResolvedHardwareAddress", Some(number(2))),
            ConfigdFault::NotAString,
        ),
    ];
    for (case, entries, expected) in cases {
        assert_eq!(
            service(&dictionary_of(&entries), None),
            Err(fault(expected)),
            "{case}"
        );
    }
    let numbered_domain = dictionary_of(&[("DomainName", number(15))]);
    assert_eq!(
        service(&dictionary_of(&ipv4), Some(&numbered_domain)),
        Err(fault(ConfigdFault::NotAString)),
        "a domain that is a number"
    );
}

/// Keys and values are checked for their type before they are read, and a
/// service's DNS key is found from its IPv4 key.
#[test]
fn keys_and_values_are_read_only_as_the_types_configd_gives() {
    assert_eq!(
        as_string(&text("State:/Network/Service/A/IPv4")).map(|key| key.to_string()),
        Ok("State:/Network/Service/A/IPv4".to_owned())
    );
    assert_eq!(
        as_string(&number(4)).map(|key| key.to_string()),
        Err(fault(ConfigdFault::NotAString))
    );
    let empty = dictionary_of(&[]);
    assert_eq!(
        as_dictionary(&empty.as_CFType()).map(|found| found.len()),
        Ok(0)
    );
    assert_eq!(
        as_dictionary(&text("en9")).map(|found| found.len()),
        Err(fault(ConfigdFault::NotADictionary))
    );
    assert_eq!(
        dns_key(&CFString::new("State:/Network/Service/A-1/IPv4")).map(|key| key.to_string()),
        Ok("State:/Network/Service/A-1/DNS".to_owned())
    );
    assert_eq!(
        dns_key(&CFString::new("State:/Network/Service/A-1/IPv6")).map(|key| key.to_string()),
        Err(fault(ConfigdFault::UnexpectedKey))
    );
}

/// The services of a key list, read from a store this test holds: in the
/// list's order, a service whose dictionary vanished after the list was
/// made is left out without its DNS key being read, and a service without
/// DNS settings has no domain.
#[test]
fn a_key_list_is_read_in_order_and_a_vanished_service_left_out() {
    let held: BTreeMap<&str, Dictionary> = [
        ("State:/Network/Service/A/IPv4", dictionary_of(&en9_ipv4())),
        (
            "State:/Network/Service/A/DNS",
            dictionary_of(&[("DomainName", text("home.example"))]),
        ),
        (
            "State:/Network/Service/C/IPv4",
            dictionary_of(&[("InterfaceName", text("en0"))]),
        ),
    ]
    .into_iter()
    .collect();
    let keys = CFArray::from_CFTypes(&[
        text("State:/Network/Service/A/IPv4"),
        text("State:/Network/Service/B/IPv4"),
        text("State:/Network/Service/C/IPv4"),
    ]);
    let mut asked = Vec::new();
    let services = services_in(&keys, |key| {
        let key = key.to_string();
        let found = held.get(key.as_str()).cloned();
        asked.push(key);
        Ok(found)
    })
    .unwrap();
    assert_eq!(
        services
            .iter()
            .map(|service| (service.interface.as_str(), service.domain.as_deref()))
            .collect::<Vec<_>>(),
        [("en9", Some("home.example")), ("en0", None)]
    );
    assert_eq!(
        asked,
        [
            "State:/Network/Service/A/IPv4",
            "State:/Network/Service/A/DNS",
            "State:/Network/Service/B/IPv4",
            "State:/Network/Service/C/IPv4",
            "State:/Network/Service/C/DNS",
        ]
    );
}

/// A key list holding something other than a string is refused before
/// anything is read, and a read that fails fails the list.
#[test]
fn a_key_list_is_refused_for_a_key_that_is_not_a_string_or_a_failed_read() {
    let mut asked = 0;
    let numbered = CFArray::from_CFTypes(&[number(4)]);
    assert_eq!(
        services_in(&numbered, |_| {
            asked += 1;
            Ok(None)
        }),
        Err(fault(ConfigdFault::NotAString))
    );
    assert_eq!(asked, 0);
    let keys = CFArray::from_CFTypes(&[text("State:/Network/Service/A/IPv4")]);
    assert_eq!(
        services_in(&keys, |_| Err(fault(ConfigdFault::NotADictionary))),
        Err(fault(ConfigdFault::NotADictionary))
    );
}

/// A key the store does not hold reads as absent, as a service's missing
/// DNS settings do, and is no error; a key list the store will not give is
/// `KeyListUnavailable` (a pattern that is no regular expression makes
/// configd answer with none).
#[test]
fn the_live_store_answers_an_absent_key_and_refuses_a_broken_pattern() {
    let store = open().unwrap();
    let absent = CFString::new("State:/Network/Service/mooring-test-absent/DNS");
    assert!(dictionary(&store, &absent).unwrap().is_none());
    assert_eq!(
        keys(&store, "[").map(|keys| keys.len()),
        Err(fault(ConfigdFault::KeyListUnavailable))
    );
}

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
        "+4:64:3c:7b:d4:bf",
        "44:64:3c:7b:d4:+f",
    ] {
        assert_eq!(link_layer_address(bad), None, "{bad:?}");
    }
}
