// SPDX-License-Identifier: GPL-3.0-or-later

//! `exit allow-network`, `exit disallow-network` and `exit allowed-networks`
//! against the harness (design §10.2, P0-2): what a declaration records
//! and prints, the policy it states, and every refusal, each before
//! anything is asked and writing nothing.

use std::fs;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;

use clap::Parser;
use mooring_macsys::{ConfigdFault, Interface, InterfaceAddrV4, Ipv4Service, MacsysError};
use mooring_model::exit::Uplink;
use mooring_model::ids::LocalLabel;
use mooring_model::iface::{InterfaceSelector, MacAddr, RouterIdentity};
use mooring_model::own_network::{OwnNetwork, OwnNetworkKind};
use mooring_model::time::UnixTime;
use mooring_store::{
    ALLOWED_NETWORKS_FILE, Declaration, declare_allowed_network, read_allowed_networks,
};

use super::support::{Harness, OTHER, PINNED};
use super::user::{fixture, harness_with};
use crate::error::EXIT_LOCAL;
use crate::prompt::Answer;

/// The iPhone's hotspot router, a made-up locally administered address.
const HOTSPOT: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x20, 0x60];

fn service(
    interface: &str,
    router: Option<[u8; 4]>,
    lladdr: Option<[u8; 6]>,
    domain: Option<&str>,
) -> Ipv4Service {
    Ipv4Service {
        interface: interface.to_owned(),
        router: router.map(Ipv4Addr::from),
        router_lladdr: lladdr,
        domain: domain.map(str::to_owned),
    }
}

/// A deployed harness whose `lo0` faces the pinned M7 and whose `en0` is
/// joined to the operator's hotspot, as configd describes it.
fn joined(services: Vec<Ipv4Service>) -> Harness {
    let mut harness = harness_with(fixture(|_| {}));
    harness.pin(PINNED);
    harness.link.services = Ok(services);
    harness
}

fn hotspot() -> Vec<Ipv4Service> {
    vec![service("en0", Some([172, 20, 10, 1]), Some(HOTSPOT), None)]
}

const ALLOW: [&str; 7] = [
    "exit",
    "allow-network",
    "--interface",
    "en0",
    "--name",
    "my phone",
    "--personal-hotspot",
];

const POLICY: &str = "only a connection you contract for yourself (your own phone's hotspot, your home broadband) may be allowed, never an institutional network (campus Wi-Fi, eduroam, Janet): on one the exit must stay down (P0-2)\n";

/// Runs `args` expecting the refusal `stderr`: exit 1, nothing asked, no
/// declaration written.
fn refused(harness: &mut Harness, args: &[&str], stderr: &str) {
    let outcome = harness.run(args);
    assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}: {}", outcome.stderr);
    assert_eq!(outcome.stderr, stderr, "{args:?}");
    assert_eq!(outcome.stdout, "", "{args:?}");
    assert!(harness.console.asked.is_empty(), "{args:?}");
    assert!(
        !harness.support_dir().join(ALLOWED_NETWORKS_FILE).exists(),
        "{args:?}: a declaration was written"
    );
}

#[test]
fn allow_network_declares_the_joined_network_after_stating_the_policy() {
    let mut harness = joined(hotspot());
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&ALLOW);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        format!(
            "network on en0: router 172.20.10.1 (02:00:5e:10:20:60), DNS domain none; the SSID cannot be read, so \"my phone\" is your label for it\n\
             allowed, it keeps the exit serving while this Mac is joined to it, even when it holds the default route; every exit connection stays bound to the M7\n\
             {POLICY}\
             declared \"my phone\" (personal hotspot) as an own network; the daemon allows it from its next tick while en0 keeps this router\n"
        )
    );
    assert_eq!(harness.console.asked, ["Allow this network for the exit?"]);
    let path = harness.support_dir().join(ALLOWED_NETWORKS_FILE);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let declared = read_allowed_networks(&harness.support_dir()).unwrap();
    let network = declared
        .get(&LocalLabel::parse("my phone").unwrap())
        .unwrap();
    assert_eq!(network.kind, OwnNetworkKind::PersonalHotspot);
    assert_eq!(network.router.addr(), Ipv4Addr::new(172, 20, 10, 1));
    assert_eq!(
        network.router.lladdr(),
        MacAddr::from_bytes(HOTSPOT).unwrap()
    );
    assert_eq!(network.declared_at.as_secs(), super::support::NOW);
    // Listed, then withdrawn.
    let outcome = harness.run(&["exit", "allowed-networks"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "\"my phone\": personal hotspot, router 172.20.10.1 (02:00:5e:10:20:60)\n"
    );
    // A second declaration under the same name is refused before asking.
    let outcome = harness.run(&ALLOW);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: a network named \"my phone\" is declared already; `exit disallow-network --name` withdraws it\n"
    );
    assert_eq!(harness.console.asked.len(), 1);
    let outcome = harness.run(&["exit", "disallow-network", "--name", "my phone"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "withdrew \"my phone\" (personal hotspot, router 172.20.10.1); the daemon treats that network as foreign from its next tick\n"
    );
    assert!(
        read_allowed_networks(&harness.support_dir())
            .unwrap()
            .is_empty()
    );
    let outcome = harness.run(&["exit", "allowed-networks"]);
    assert_eq!(outcome.stdout, "no network is declared\n");
    let outcome = harness.run(&["exit", "disallow-network", "--name", "my phone"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: no declared network is named \"my phone\"; `exit allowed-networks` lists them\n"
    );
}

#[test]
fn allow_network_with_yes_asks_nothing_and_records_broadband_without_the_flag() {
    let mut harness = joined(vec![service(
        "en0",
        Some([192, 168, 0, 1]),
        Some(HOTSPOT),
        Some("home.arpa"),
    )]);
    let outcome = harness.run(&[
        "exit",
        "allow-network",
        "--interface",
        "en0",
        "--name",
        "home",
        "--yes",
    ]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(harness.console.asked.is_empty());
    assert!(outcome.stdout.starts_with(
        "network on en0: router 192.168.0.1 (02:00:5e:10:20:60), DNS domain home.arpa; the SSID cannot be read, so \"home\" is your label for it\n"
    ));
    assert!(outcome.stdout.ends_with(
        "declared \"home\" (broadband) as an own network; the daemon allows it from its next tick while en0 keeps this router\n"
    ));
    let declared = read_allowed_networks(&harness.support_dir()).unwrap();
    assert_eq!(
        declared
            .get(&LocalLabel::parse("home").unwrap())
            .map(|network| network.kind),
        Some(OwnNetworkKind::Broadband)
    );
}

/// Every refusal exits 1, names its cause, asks nothing and writes nothing.
#[test]
fn allow_network_refuses_the_exits_own_path_and_a_network_it_cannot_identify() {
    // The pinned interface.
    refused(
        &mut joined(hotspot()),
        &["exit", "allow-network", "--interface", "lo0", "--name", "x"],
        "mooringctl: lo0 faces the M7 (the pinned interface or the separate uplink): it is the exit's own path, not a network to allow\n",
    );
    // The separate uplink: en7 behind the home router, named by the
    // deployment's uplink selector.
    let mut uplinked = harness_with(fixture(|parts| {
        parts.exit.uplink = Uplink::Separate(InterfaceSelector::GatewayLinkAddr {
            gw_lladdr: MacAddr::from_bytes(OTHER).unwrap(),
            subnet: "192.168.0.0/24".parse().unwrap(),
        });
    }));
    uplinked.pin(PINNED);
    uplinked.link.listed = Ok(vec![Interface {
        index: NonZeroU32::new(7).unwrap(),
        name: "en7".to_owned(),
        link_type: 6,
        lladdr: Some([0x02, 0x6d, 0x6f, 0x6f, 0x72, 0x07]),
        up: true,
        running: true,
        mtu: 1500,
        ibytes: 0,
        obytes: 0,
        baudrate: 0,
        ipv4: vec![InterfaceAddrV4 {
            addr: Ipv4Addr::new(192, 168, 0, 20),
            prefix_len: Some(24),
        }],
        ipv6: Vec::new(),
    }]);
    uplinked
        .link
        .routes
        .insert(7, (Ok(Ipv4Addr::new(192, 168, 0, 1)), Ok(OTHER)));
    uplinked.link.services = Ok(vec![service(
        "en7",
        Some([192, 168, 0, 1]),
        Some(OTHER),
        None,
    )]);
    refused(
        &mut uplinked,
        &[
            "exit",
            "allow-network",
            "--interface",
            "en7",
            "--name",
            "home",
        ],
        "mooringctl: en7 faces the M7 (the pinned interface or the separate uplink): it is the exit's own path, not a network to allow\n",
    );
    // No service with a router on the interface: none at all, or one
    // without a router.
    for services in [Vec::new(), vec![service("en0", None, None, None)]] {
        refused(
            &mut joined(services),
            &ALLOW,
            "mooringctl: en0 has no IPv4 service with a router: join the network first and wait for its router to resolve\n",
        );
    }
    refused(
        &mut joined(vec![
            service("en0", Some([172, 20, 10, 1]), Some(HOTSPOT), None),
            service("en0", Some([192, 168, 0, 1]), Some(OTHER), None),
        ]),
        &ALLOW,
        "mooringctl: en0 has 2 IPv4 services with a router, so the network cannot be told apart\n",
    );
    refused(
        &mut joined(vec![service("en0", Some([172, 20, 10, 1]), None, None)]),
        &ALLOW,
        "mooringctl: the router of en0 has no resolved link-layer address yet: wait a few seconds after joining and try again\n",
    );
    refused(
        &mut joined(vec![service(
            "en0",
            Some([172, 20, 10, 1]),
            Some([0x02, 0, 0, 0, 0, 0]),
            None,
        )]),
        &ALLOW,
        "mooringctl: the router of en0 shows a link-layer address that identifies no device\n  caused by: link-layer address 02:00:00:00:00:00 is the privacy placeholder, which identifies no device\n",
    );
    refused(
        &mut joined(vec![service(
            "en0",
            Some([172, 20, 10, 1]),
            Some([0x01, 0x00, 0x5e, 0, 0, 1]),
            None,
        )]),
        &ALLOW,
        "mooringctl: the router of en0 shows a link-layer address that identifies no device\n  caused by: link-layer address must be a unicast aa:bb:cc:dd:ee:ff\n",
    );
    // The M7 itself, reached over its Wi-Fi.
    refused(
        &mut joined(vec![service(
            "en0",
            Some([192, 168, 1, 1]),
            Some(PINNED),
            None,
        )]),
        &ALLOW,
        "mooringctl: the router of en0 is the pinned M7: the M7's network is the exit's own path, not a network to allow\n",
    );
    // configd cannot be read.
    let mut blind = joined(Vec::new());
    blind.link.services = Err(MacsysError::Configd {
        fault: ConfigdFault::StoreUnavailable,
    });
    refused(
        &mut blind,
        &ALLOW,
        "mooringctl: reading configd's network services failed\n  caused by: the system configuration store could not be opened\n",
    );
}

#[test]
fn allow_network_refuses_institutional_networks_and_a_hotspot_that_is_not_apples() {
    for domain in ["dur.ac.uk", "DUR.AC.UK", "eduroam.ac.uk", "ac.uk"] {
        refused(
            &mut joined(vec![service(
                "en0",
                Some([10, 249, 64, 1]),
                Some(OTHER),
                Some(domain),
            )]),
            &[
                "exit",
                "allow-network",
                "--interface",
                "en0",
                "--name",
                "campus",
            ],
            &format!(
                "mooringctl: en0 is on {}, a UK academic network (Janet): the exit must stay down on it (P0-2), so it cannot be allowed\n",
                domain.to_ascii_lowercase()
            ),
        );
    }
    refused(
        &mut joined(vec![service(
            "en0",
            Some([192, 168, 1, 1]),
            Some(OTHER),
            None,
        )]),
        &ALLOW,
        "mooringctl: --personal-hotspot names Apple's Personal Hotspot, whose router is 172.20.10.1; the router of en0 is 192.168.1.1\n",
    );
}

#[test]
fn allow_network_records_nothing_without_a_yes() {
    let mut declined = joined(hotspot());
    declined.console.answers.push_back(Answer::No);
    let outcome = declined.run(&ALLOW);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: not recorded: the answer was not yes\n"
    );
    assert!(outcome.stdout.ends_with(POLICY), "{}", outcome.stdout);
    assert!(!declined.support_dir().join(ALLOWED_NETWORKS_FILE).exists());
    let mut unattended = joined(hotspot());
    unattended.console.answers.push_back(Answer::NoTerminal);
    let outcome = unattended.run(&ALLOW);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        "mooringctl: not recorded: no terminal to ask and --yes was not given\n"
    );
    assert!(
        !unattended
            .support_dir()
            .join(ALLOWED_NETWORKS_FILE)
            .exists()
    );
    // A corrupt declarations file is named, not replaced.
    let mut corrupt = joined(hotspot());
    let path = corrupt.support_dir().join(ALLOWED_NETWORKS_FILE);
    fs::write(&path, b"{}").unwrap();
    let outcome = corrupt.run(&["exit", "allowed-networks"]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: the allowed-networks file failed\n  caused by: allowed-networks file {} is corrupt: it is not an allowed-networks document of version 1\n",
            path.display()
        )
    );
    let outcome = corrupt.run(&ALLOW);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert!(outcome.stderr.contains("is corrupt"), "{}", outcome.stderr);
    assert!(corrupt.console.asked.is_empty());
    assert_eq!(fs::read(&path).unwrap(), b"{}");
}

/// A declarations file that cannot hold another network refuses the
/// declaration before anything is asked, says how to make room, and is left
/// as it is.
#[test]
fn allow_network_refuses_a_declaration_the_file_cannot_hold() {
    let mut harness = joined(hotspot());
    let dir = harness.support_dir();
    // Declared through the store until it says the file is full.
    let router = RouterIdentity::new(
        Ipv4Addr::new(192, 168, 0, 1),
        MacAddr::parse("02:00:5e:10:20:40").unwrap(),
    )
    .unwrap();
    let mut count = 0;
    loop {
        let filler = OwnNetwork {
            kind: OwnNetworkKind::Broadband,
            router,
            declared_at: UnixTime::from_secs(1_793_300_000),
        };
        let name = LocalLabel::parse(&format!("filler {count:03}")).unwrap();
        match declare_allowed_network(&dir, name, filler).unwrap() {
            Declaration::Recorded => count += 1,
            Declaration::Full { .. } => break,
            Declaration::AlreadyDeclared => unreachable!("fillers are distinct"),
        }
    }
    let path = dir.join(ALLOWED_NETWORKS_FILE);
    let before = fs::read(&path).unwrap();
    let outcome = harness.run(&ALLOW);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: the allowed-networks file is full: {count} networks are declared and another does not fit within its 16 KiB; `exit disallow-network --name` withdraws one first\n"
        )
    );
    assert_eq!(outcome.stdout, "");
    assert!(harness.console.asked.is_empty());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(read_allowed_networks(&dir).unwrap().len(), count);
    // The remedy it names: withdrawing one makes room for this one.
    let outcome = harness.run(&["exit", "disallow-network", "--name", "filler 000"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    harness.console.answers.push_back(Answer::Yes);
    let outcome = harness.run(&ALLOW);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let declared = read_allowed_networks(&dir).unwrap();
    assert_eq!(declared.len(), count);
    assert!(
        declared
            .get(&LocalLabel::parse("my phone").unwrap())
            .is_some()
    );
}

#[test]
fn the_name_is_a_local_label() {
    let allowed = |name: &str| {
        crate::cli::Cli::try_parse_from([
            "mooringctl",
            "exit",
            "allow-network",
            "--interface",
            "en0",
            "--name",
            name,
        ])
        .is_ok()
    };
    assert!(allowed("my phone"));
    assert!(allowed(&"x".repeat(64)));
    assert!(allowed("我的手机"));
    assert!(!allowed(""));
    assert!(!allowed(" padded"));
    assert!(!allowed("tab\there"));
    assert!(!allowed(&"x".repeat(65)));
}
