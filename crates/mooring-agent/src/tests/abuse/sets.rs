// SPDX-License-Identifier: GPL-3.0-or-later

//! What nft prints of the measured sets (design §11.8), in the shapes
//! libnftables gives them on Debian 13 (Linux 6.12: an element's timeout
//! left out when it equals the set's) and on Linux 6.8 (always printed).

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use mooring_agent_proto::AbuseSet;

use crate::abuse::sets::{Counter, Element, Proto, parse, read};
use crate::host::Tool;
use crate::tests::watch::world::listing;
use crate::tests::{FakeNode, failed, ok};

const USER: Ipv4Addr = Ipv4Addr::new(198, 18, 7, 42);

fn parsed(set: AbuseSet, elements: &[&str]) -> Option<Vec<Element>> {
    let elements: Vec<String> = elements
        .iter()
        .map(|element| (*element).to_owned())
        .collect();
    parse(listing(set.name(), &elements).as_bytes(), set)
}

#[test]
fn an_empty_set_has_no_elements() {
    for set in AbuseSet::ALL
        .iter()
        .copied()
        .filter(|set| set.is_measured())
    {
        assert_eq!(parsed(set, &[]), Some(Vec::new()), "{set:?}");
    }
}

/// Debian 13 prints a dynamic element's expiry and its counter, and leaves
/// out its timeout, which is the set's: the age is the set's timeout less
/// the expiry.
#[test]
fn an_elements_age_is_the_sets_timeout_less_its_expiry() {
    let burst = parsed(
        AbuseSet::Burst,
        &[r#"{"elem":{"val":{"concat":["198.18.7.42",3071]},"expires":97,"counter":{"packets":12,"bytes":720}}}"#],
    )
    .unwrap();
    assert_eq!(
        burst,
        [Element {
            source: USER,
            proto: None,
            age: Some(23),
            counter: Some(Counter {
                packets: 12,
                bytes: 720
            }),
        }]
    );
    // Linux 6.8 prints the element's timeout, which wins.
    let meter = parsed(
        AbuseSet::MeterOut,
        &[r#"{"elem":{"val":{"concat":["198.18.7.42","udp"]},"timeout":60,"expires":15,"counter":{"packets":45000,"bytes":54000000}}}"#],
    )
    .unwrap();
    assert_eq!(meter[0].age, Some(45));
    assert_eq!(meter[0].proto, Some(Proto::Udp));
    // No expiry, no age.
    let dst = parsed(
        AbuseSet::Dst,
        &[r#"{"elem":{"val":{"concat":["198.18.7.42",17]},"counter":{"packets":1,"bytes":60}}}"#],
    )
    .unwrap();
    assert_eq!(dst[0].age, None);
}

/// A key with nothing else is printed bare; protocols may be printed as
/// numbers; keys the parser does not use are ignored.
#[test]
fn bare_keys_numbered_protocols_and_unknown_keys_are_read() {
    let meter = parsed(
        AbuseSet::MeterNew,
        &[
            r#"{"concat":["198.18.7.42",6]}"#,
            r#"{"elem":{"val":{"concat":["198.18.7.42","tcp"]},"expires":30,"counter":{"packets":9,"bytes":540},"comment":"x"}}"#,
        ],
    )
    .unwrap();
    assert_eq!(meter[0].proto, Some(Proto::Tcp));
    assert_eq!(meter[0].counter, None);
    assert_eq!(meter[1].proto, Some(Proto::Tcp));
    assert_eq!(meter[1].age, Some(30));
    let capped = parsed(AbuseSet::Capped, &[r#""198.18.7.42""#]).unwrap();
    assert_eq!(capped[0].source, USER);
    let port = parsed(
        AbuseSet::Port,
        &[r#"{"elem":{"val":{"concat":["198.18.7.42",443]},"expires":290}}"#],
    )
    .unwrap();
    assert_eq!(port[0].age, Some(10));
}

/// Anything of another shape fails the whole listing: the watch reports
/// the guard unable to read rather than decide on part of it.
#[test]
fn a_value_of_the_wrong_shape_fails_the_listing() {
    for (set, element) in [
        (AbuseSet::Dst, r#"{"concat":["198.18.7.42"]}"#),
        (AbuseSet::Dst, r#"{"concat":["198.18.7.42","x"]}"#),
        (AbuseSet::Dst, r#"{"concat":["2001:db8::1",3]}"#),
        (AbuseSet::Dst, r#""198.18.7.42""#),
        (AbuseSet::MeterNew, r#"{"concat":["198.18.7.42","icmp"]}"#),
        (AbuseSet::MeterNew, r#"{"concat":["198.18.7.42",1]}"#),
        (AbuseSet::MeterNew, r#""198.18.7.42""#),
        (AbuseSet::MeterIn, r#"{"concat":["198.18.7.42","tcp"]}"#),
        (AbuseSet::MeterIn, r#"{"elem":{"expires":3}}"#),
        (
            AbuseSet::MeterIn,
            r#"{"elem":{"val":"198.18.7.42","expires":"3"}}"#,
        ),
        (
            AbuseSet::MeterIn,
            r#"{"elem":{"val":"198.18.7.42","counter":{"packets":1}}}"#,
        ),
        (
            AbuseSet::MeterIn,
            r#"{"elem":{"val":"198.18.7.42","timeout":-1}}"#,
        ),
        (AbuseSet::Capped, r#"7"#),
    ] {
        assert_eq!(parsed(set, &[element]), None, "{set:?} {element}");
    }
    let dst = AbuseSet::Dst;
    for listing in [
        "",
        "{}",
        r#"{"nftables":{}}"#,
        r#"{"nftables":[{"metainfo":{}}]}"#,
        r#"{"nftables":[{"set":{"name":"user_port"}}]}"#,
        r#"{"nftables":[{"set":{"name":"user_dst"}},{"set":{"name":"user_dst"}}]}"#,
        r#"{"nftables":[{"set":{"name":"user_dst","elem":{}}}]}"#,
        r#"{"nftables":[{"set":{"name":"user_dst","timeout":"5m"}}]}"#,
    ] {
        assert_eq!(parse(listing.as_bytes(), dst), None, "{listing}");
    }
}

/// One reading lists every measured set, and is all or nothing.
#[test]
fn a_reading_lists_every_measured_set_or_fails_whole() {
    let node = FakeNode::answering(
        1_000,
        Box::new(|tool, args| {
            Ok(match (tool, args) {
                (Tool::Nft, ["-j", "list", "set", "inet", "mooring", name]) => {
                    ok(listing(name, &[]).as_bytes())
                }
                _ => failed(b""),
            })
        }),
    );
    let measured = read(&node).unwrap();
    let listed: BTreeSet<String> = node.calls().into_iter().collect();
    let expected: BTreeSet<String> = AbuseSet::ALL
        .iter()
        .filter(|set| set.is_measured())
        .map(|set| format!("/usr/sbin/nft -j list set inet mooring {}", set.name()))
        .collect();
    assert_eq!(listed, expected);
    assert!(measured.elements(AbuseSet::Dst).is_empty());
    assert!(measured.elements(AbuseSet::Cut).is_empty(), "never listed");
    for failing in ["user_mail", "meter_in"] {
        let node = FakeNode::answering(
            1_000,
            Box::new(move |tool, args| {
                Ok(match (tool, args) {
                    (Tool::Nft, ["-j", "list", "set", "inet", "mooring", name])
                        if *name == failing =>
                    {
                        failed(b"Error: No such file or directory\n")
                    }
                    (Tool::Nft, ["-j", "list", "set", "inet", "mooring", name]) => {
                        ok(listing(name, &[]).as_bytes())
                    }
                    _ => failed(b""),
                })
            }),
        );
        assert_eq!(read(&node), None, "{failing}");
    }
    let garbled = FakeNode::answering(
        1_000,
        Box::new(|tool, args| {
            Ok(match (tool, args) {
                (Tool::Nft, ["-j", "list", "set", "inet", "mooring", "user_port"]) => {
                    ok(b"not json")
                }
                (Tool::Nft, ["-j", "list", "set", "inet", "mooring", name]) => {
                    ok(listing(name, &[]).as_bytes())
                }
                _ => failed(b""),
            })
        }),
    );
    assert_eq!(read(&garbled), None);
}

/// The hosted lane (`.github/workflows/ci.yml`, "The rendered rulesets on a
/// Linux kernel") loads a rendered ruleset into a network namespace, gives
/// each measured set one element of 198.18.0.5, and writes what
/// `nft -j list set` prints into the directory `MOORING_NFT_LISTINGS`
/// names; this reads each listing with the watch's parser. It runs there,
/// with `--ignored`, and nowhere else: this Mac has no Linux kernel.
#[test]
#[ignore = "run by the hosted lane, which writes the listings from a real kernel"]
fn real_nft_listings_are_read() {
    let dir =
        std::env::var_os("MOORING_NFT_LISTINGS").expect("the lane names the directory of listings");
    let source = Ipv4Addr::new(198, 18, 0, 5);
    for set in AbuseSet::ALL
        .iter()
        .copied()
        .filter(|set| set.is_measured())
    {
        let path = std::path::Path::new(&dir).join(format!("{}.json", set.name()));
        let bytes = std::fs::read(&path).expect("a listing per measured set");
        let elements = parse(&bytes, set)
            .unwrap_or_else(|| panic!("{set:?}: {}", String::from_utf8_lossy(&bytes)));
        assert_eq!(elements.len(), 1, "{set:?}");
        let element = &elements[0];
        assert_eq!(element.source, source, "{set:?}");
        assert!(
            element.age.is_some_and(|age| age < 600),
            "{set:?}: an element added now is young: {element:?}"
        );
        let expected = match set {
            AbuseSet::Burst => Some((3, 180)),
            AbuseSet::Login => Some((2, 120)),
            AbuseSet::MeterNew => Some((9, 540)),
            AbuseSet::MeterOut => Some((1_000, 1_200_000)),
            AbuseSet::MeterIn => Some((7, 9_000)),
            AbuseSet::Capped => Some((4, 240)),
            _ => None,
        };
        assert_eq!(
            element
                .counter
                .map(|counter| (counter.packets, counter.bytes)),
            expected,
            "{set:?}"
        );
        let proto = match set {
            AbuseSet::MeterNew => Some(Proto::Tcp),
            AbuseSet::MeterOut => Some(Proto::Udp),
            _ => None,
        };
        assert_eq!(element.proto, proto, "{set:?}");
    }
}
