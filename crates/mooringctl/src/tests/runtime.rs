// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit runtime's parts (design §10.1, §10.2): interface resolution and
//! the exit site's interfaces against a scripted interface list, the
//! foreign-network snapshot, the direct probe against a loopback
//! reflector, the engine's check, start and stop against a stand-in
//! script, the power helper's lines and pipes, the SIM meter's thread, and the
//! engine an earlier daemon left.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mooring_daemon_core::exit::EgressFault;
use mooring_daemon_core::meter::{COUNTER_MODULUS, CounterReading, CycleBytes, SimMeter};
use mooring_daemon_core::network::{AllowedNetwork, ForeignNetworkFinding, IpFamily};
use mooring_daemon_core::period::BillingCycle;
use mooring_daemon_core::status::{LinkState, PowerSource, ProbeStage};
use mooring_macsys::{DefaultRoute, Interface, InterfaceAddrV4, Ipv4Service, MacsysError};
use mooring_model::dns::DnsName;
use mooring_model::exit::Uplink;
use mooring_model::ids::LocalLabel;
use mooring_model::iface::{BsdName, InterfaceIndex, InterfaceSelector, MacAddr, RouterIdentity};
use mooring_model::own_network::{OwnNetwork, OwnNetworkKind, OwnNetworks};
use mooring_model::sim::{CycleRule, PeriodDays};
use mooring_model::{CalendarDate, UnixTime};
use mooring_store::{SIM_METER_FILE, USAGE_DIRECTORY};

use super::support::{FakeLink, PINNED, Route};
use crate::error::LocalError;
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::meter::{MeterThread, Reader, Watched};
use crate::runtime::network::{check, snapshot};
use crate::runtime::ports::{ENGINE_PID_FILE, stop_stale_engine};
use crate::runtime::power::read_lines;
use crate::runtime::probe::{direct, in_chain};
use crate::runtime::resolve::{ResolveError, exit_interfaces, resolve};

/// `SIGKILL`'s number on macOS.
const SIGKILL: i32 = 9;

/// The egress's own link-layer address in the fixtures.
const OWN: [u8; 6] = [0x02, 0x6d, 0x6f, 0x6f, 0x72, 0x01];
const OTHER: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x07];

fn interface(index: u32, name: &str, own: [u8; 6], addr: Option<[u8; 4]>, up: bool) -> Interface {
    Interface {
        index: NonZeroU32::new(index).unwrap(),
        name: name.to_owned(),
        link_type: 6,
        lladdr: Some(own),
        up,
        running: up,
        mtu: 1500,
        ibytes: 0,
        obytes: 0,
        baudrate: 1_000_000_000,
        ipv4: addr
            .map(|addr| InterfaceAddrV4 {
                addr: Ipv4Addr::from(addr),
                prefix_len: Some(24),
            })
            .into_iter()
            .collect(),
        ipv6: Vec::new(),
    }
}

/// A link whose interfaces at `routes` each have a default gateway and a
/// neighbour entry for it.
fn link(listed: Vec<Interface>, routes: &[(u32, Route)]) -> FakeLink {
    let mut link = FakeLink::pinned();
    link.listed = Ok(listed);
    link.routes = routes
        .iter()
        .map(|(index, route)| (*index, *route))
        .collect::<BTreeMap<_, _>>();
    link
}

fn behind_the_m7() -> InterfaceSelector {
    InterfaceSelector::GatewayLinkAddr {
        gw_lladdr: MacAddr::from_bytes(PINNED).unwrap(),
        subnet: "192.168.1.0/24".parse().unwrap(),
    }
}

const M7: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

#[test]
fn the_selector_resolves_the_one_interface_behind_the_m7() {
    let link = link(
        vec![
            interface(4, "en0", [2, 0, 0, 0, 0, 1], Some([10, 0, 0, 5]), true),
            interface(9, "en9", OWN, Some([192, 168, 1, 20]), true),
        ],
        &[
            (4, (Ok(Ipv4Addr::new(10, 0, 0, 1)), Ok(OTHER))),
            (9, (Ok(M7), Ok(PINNED))),
        ],
    );
    let (resolved, state) = resolve(&link, &behind_the_m7()).unwrap();
    assert_eq!(resolved.bsd_name.as_str(), "en9");
    assert_eq!(resolved.ipv4, Ipv4Addr::new(192, 168, 1, 20));
    assert_eq!(resolved.lladdr, MacAddr::from_bytes(OWN).unwrap());
    assert_eq!(resolved.index, InterfaceIndex::new(9).unwrap());
    assert_eq!(
        state,
        LinkState {
            up: true,
            speed_mbps: Some(1000)
        }
    );
    // A selector of the interface's own address.
    let own = InterfaceSelector::LinkAddr {
        lladdr: MacAddr::from_bytes(OWN).unwrap(),
        subnet: "192.168.1.0/24".parse().unwrap(),
    };
    assert_eq!(resolve(&link, &own).unwrap().0.bsd_name.as_str(), "en9");
    // A driver that reports no speed is shown without one.
    let mut unrated = interface(9, "en9", OWN, Some([192, 168, 1, 20]), true);
    unrated.baudrate = 0;
    let (_, state) = resolve(
        &self::link(vec![unrated], &[(9, (Ok(M7), Ok(PINNED)))]),
        &behind_the_m7(),
    )
    .unwrap();
    assert_eq!(state.speed_mbps, None);
}

#[test]
fn an_identified_interface_without_a_usable_address_says_so() {
    for (addr, wanted) in [
        (None, "NoIpv4"),
        (Some([192, 168, 2, 20]), "SubnetMismatch"),
    ] {
        let link = link(
            vec![interface(9, "en9", OWN, addr, true)],
            &[(9, (Ok(M7), Ok(PINNED)))],
        );
        let error = resolve(&link, &behind_the_m7()).unwrap_err();
        let found = match error {
            ResolveError::NoIpv4 { interface } if interface.as_str() == "en9" => "NoIpv4",
            ResolveError::SubnetMismatch => "SubnetMismatch",
            other => panic!("{other:?}"),
        };
        assert_eq!(found, wanted);
    }
}

#[test]
fn nothing_down_another_gateway_or_two_matches_are_refused() {
    let en9 = |up| interface(9, "en9", OWN, Some([192, 168, 1, 20]), up);
    for (listed, routes) in [
        (vec![], vec![]),
        (vec![en9(false)], vec![(9, (Ok(M7), Ok(PINNED)))]),
        (vec![en9(true)], vec![(9, (Ok(M7), Ok(OTHER)))]),
        (
            vec![en9(true)],
            vec![(9, (Err(MacsysError::NoDefaultRoute), Ok(PINNED)))],
        ),
        (
            vec![en9(true)],
            vec![(9, (Err(MacsysError::AmbiguousDefaultRoute), Ok(PINNED)))],
        ),
        (
            vec![en9(true)],
            vec![(9, (Ok(M7), Err(MacsysError::NeighbourAbsent)))],
        ),
        (
            vec![en9(true)],
            vec![(9, (Ok(M7), Err(MacsysError::NeighbourIncomplete)))],
        ),
    ] {
        assert!(
            matches!(
                resolve(&link(listed, &routes), &behind_the_m7()),
                Err(ResolveError::Absent)
            ),
            "{routes:?}"
        );
    }
    let two = link(
        vec![
            interface(8, "en8", OWN, Some([192, 168, 1, 21]), true),
            en9(true),
        ],
        &[(8, (Ok(M7), Ok(PINNED))), (9, (Ok(M7), Ok(PINNED)))],
    );
    assert!(matches!(
        resolve(&two, &behind_the_m7()),
        Err(ResolveError::Ambiguous { count: 2 })
    ));
    // One behind the M7 with an address and one without are two as well.
    let mixed = link(
        vec![interface(8, "en8", OWN, None, true), en9(true)],
        &[(8, (Ok(M7), Ok(PINNED))), (9, (Ok(M7), Ok(PINNED)))],
    );
    assert!(matches!(
        resolve(&mixed, &behind_the_m7()),
        Err(ResolveError::Ambiguous { count: 2 })
    ));
    // Tables that cannot be read are an error, never "not there".
    for routes in [
        vec![(9, (Err(MacsysError::Sysctl { errno: 12 }), Ok(PINNED)))],
        vec![(9, (Ok(M7), Err(MacsysError::NeighbourTableEmpty)))],
    ] {
        assert!(matches!(
            resolve(&link(vec![en9(true)], &routes), &behind_the_m7()),
            Err(ResolveError::Kernel(_))
        ));
    }
    let mut unlisted = link(vec![], &[]);
    unlisted.listed = Err(MacsysError::TableChanged);
    assert!(matches!(
        resolve(&unlisted, &behind_the_m7()),
        Err(ResolveError::Kernel(MacsysError::TableChanged))
    ));
}

#[test]
fn the_exit_site_resolves_to_the_machine_s_egress_or_its_fault() {
    let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
    let site = fixture.deployment.exit().clone();
    let en8 = interface(8, "en8", OWN, Some([192, 168, 1, 20]), true);
    let egress = exit_interfaces(&link(vec![en8.clone()], &[]), &site)
        .unwrap()
        .unwrap();
    assert_eq!(egress.interfaces.egress().bsd_name.as_str(), "en8");
    assert_eq!(egress.link.speed_mbps, Some(1000));
    for (listed, fault) in [
        (vec![], EgressFault::Absent),
        (
            vec![
                en8.clone(),
                interface(9, "en9", OWN, Some([192, 168, 1, 21]), true),
            ],
            EgressFault::Ambiguous { matches: 2 },
        ),
        (
            vec![interface(8, "en8", OWN, None, true)],
            EgressFault::NoIpv4 {
                interface: BsdName::parse("en8").unwrap(),
            },
        ),
        (
            vec![interface(8, "en8", OWN, Some([10, 1, 1, 1]), true)],
            EgressFault::SubnetMismatch,
        ),
    ] {
        assert_eq!(
            exit_interfaces(&link(listed, &[]), &site)
                .unwrap()
                .unwrap_err(),
            fault
        );
    }
    // A separate uplink that is absent, or that is the egress itself.
    let mut separate = site.clone();
    separate.uplink = Uplink::Separate(InterfaceSelector::LinkAddr {
        lladdr: MacAddr::from_bytes([2, 0, 0, 0, 0, 0x42]).unwrap(),
        subnet: "10.0.0.0/24".parse().unwrap(),
    });
    assert_eq!(
        exit_interfaces(&link(vec![en8.clone()], &[]), &separate)
            .unwrap()
            .unwrap_err(),
        EgressFault::UplinkAbsent
    );
    separate.uplink = Uplink::Separate(site.egress);
    assert_eq!(
        exit_interfaces(&link(vec![en8.clone()], &[]), &separate)
            .unwrap()
            .unwrap_err(),
        EgressFault::UplinkEqualsEgress
    );
    let mut broken = link(vec![en8], &[]);
    broken.listed = Err(MacsysError::TableChanged);
    assert!(matches!(
        exit_interfaces(&broken, &site),
        Err(LocalError::Kernel(MacsysError::TableChanged))
    ));
}

fn name(text: &str) -> BsdName {
    BsdName::parse(text).unwrap()
}

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

fn default_route(interface_index: u32, gateway: [u8; 4], scoped: bool) -> DefaultRoute {
    DefaultRoute {
        interface_index,
        gateway: Ipv4Addr::from(gateway),
        scoped,
    }
}

/// The iPhone's hotspot router, a made-up locally administered address.
const HOTSPOT: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x20, 0x60];

/// The exit Mac joined to the operator's hotspot on en0 beside the M7 on
/// en8, with CFM's TUN holding the unscoped default and a VM bridge.
fn joined() -> Vec<Interface> {
    let mut utun8 = interface(20, "utun8", OTHER, Some([198, 18, 64, 1]), true);
    utun8.ipv6 = vec!["2001:2:0:64::1".parse().unwrap()];
    vec![
        interface(1, "lo0", OWN, Some([127, 0, 0, 1]), true),
        interface(8, "en8", OWN, Some([192, 168, 1, 20]), true),
        interface(4, "en0", OTHER, Some([172, 20, 10, 2]), true),
        utun8,
        interface(30, "bridge100", OTHER, Some([192, 168, 64, 1]), true),
    ]
}

fn routes() -> Vec<DefaultRoute> {
    vec![
        default_route(8, [192, 168, 1, 1], true),
        default_route(4, [172, 20, 10, 1], false),
        default_route(20, [198, 18, 64, 2], false),
        // An interface that went away between the two reads.
        default_route(99, [10, 0, 0, 1], false),
    ]
}

fn services(domain: Option<&str>) -> Vec<Ipv4Service> {
    vec![
        service("en0", Some([172, 20, 10, 1]), Some(HOTSPOT), domain),
        service("en8", Some([192, 168, 1, 1]), Some(PINNED), None),
        service("utun8", None, None, None),
        // The router's link-layer address is not resolved yet.
        service("bridge100", Some([192, 168, 64, 1]), None, None),
        // A service on an interface the kernel does not list.
        service("en7", Some([10, 0, 0, 1]), Some(OTHER), None),
    ]
}

fn hotspot() -> RouterIdentity {
    RouterIdentity::new(
        Ipv4Addr::new(172, 20, 10, 1),
        MacAddr::from_bytes(HOTSPOT).unwrap(),
    )
    .unwrap()
}

fn declared() -> OwnNetworks {
    let mut own = OwnNetworks::new();
    own.insert(
        LocalLabel::parse("my phone").unwrap(),
        OwnNetwork {
            kind: OwnNetworkKind::PersonalHotspot,
            router: hotspot(),
            declared_at: UnixTime::from_secs(1_793_300_000),
        },
    );
    own
}

#[test]
fn the_snapshot_holds_addresses_routers_domains_and_unscoped_default_routes() {
    let services = services(Some("DUR.AC.UK"));
    let seen = snapshot(&joined(), &routes(), Some(&services)).unwrap();
    let en0 = &seen.interfaces[&name("en0")];
    assert_eq!(en0.ipv4, [Ipv4Addr::new(172, 20, 10, 2)].into());
    assert_eq!(en0.router, Some(hotspot()));
    // The domain is lowercased: DNS names are case-insensitive.
    assert_eq!(en0.domain.as_ref().map(DnsName::as_str), Some("dur.ac.uk"));
    let utun8 = &seen.interfaces[&name("utun8")];
    assert_eq!(utun8.ipv6, ["2001:2:0:64::1".parse().unwrap()].into());
    assert_eq!((utun8.router, &utun8.domain), (None, &None));
    assert_eq!(
        seen.interfaces[&name("en8")].router,
        Some(
            RouterIdentity::new(
                Ipv4Addr::new(192, 168, 1, 1),
                MacAddr::from_bytes(PINNED).unwrap()
            )
            .unwrap()
        )
    );
    // An unresolved link-layer address identifies no router yet.
    assert_eq!(seen.interfaces[&name("bridge100")].router, None);
    // A service on an unlisted interface is no interface.
    assert!(!seen.interfaces.contains_key(&name("en7")));
    // Scoped routes and the vanished interface's route are left out.
    assert_eq!(
        seen.default_routes,
        [(IpFamily::V4, name("en0")), (IpFamily::V4, name("utun8"))].into()
    );
    // Two services with a router on one interface identify no network;
    // a placeholder address identifies no device; a domain that is no DNS
    // name is no domain.
    let ambiguous = vec![
        service(
            "en0",
            Some([172, 20, 10, 1]),
            Some(HOTSPOT),
            Some("example.com"),
        ),
        service(
            "en0",
            Some([192, 168, 0, 1]),
            Some(OTHER),
            Some("example.com"),
        ),
    ];
    let en0 = &snapshot(&joined(), &[], Some(&ambiguous))
        .unwrap()
        .interfaces[&name("en0")];
    assert_eq!((en0.router, &en0.domain), (None, &None));
    let placeholder = vec![service(
        "en0",
        Some([172, 20, 10, 1]),
        Some([0x02, 0, 0, 0, 0, 0]),
        Some("not a domain!"),
    )];
    let en0 = &snapshot(&joined(), &[], Some(&placeholder))
        .unwrap()
        .interfaces[&name("en0")];
    assert_eq!((en0.router, &en0.domain), (None, &None));
    // Without configd no router is known.
    let blind = snapshot(&joined(), &routes(), None).unwrap();
    assert!(
        blind
            .interfaces
            .values()
            .all(|observed| observed.router.is_none())
    );
    assert_eq!(blind.default_routes.len(), 2);
    // An interface whose name is no BSD name is a daemon error.
    let odd = vec![interface(1, "not a name", OWN, Some([10, 0, 0, 1]), true)];
    assert!(matches!(
        snapshot(&odd, &[], None),
        Err(LocalError::InterfaceName { name }) if name == "not a name"
    ));
}

#[test]
fn the_check_allows_cfm_tun_and_a_declared_network_and_exempts_the_uplink() {
    let services = services(None);
    let seen = snapshot(&joined(), &routes(), Some(&services)).unwrap();
    let own = declared();
    let none = OwnNetworks::new();
    let found = check(&seen, &name("en8"), None, &own);
    assert_eq!(
        found.allowed,
        [
            AllowedNetwork::Own {
                interface: name("en0"),
                kind: OwnNetworkKind::PersonalHotspot,
            },
            AllowedNetwork::BenchmarkingTun {
                interface: name("utun8"),
            },
        ]
        .into()
    );
    assert_eq!(
        found.foreign,
        [ForeignNetworkFinding::RoutableIpv4 {
            interface: name("bridge100"),
        }]
        .into()
    );
    // Undeclared, the hotspot is foreign with its default route.
    let strict = check(&seen, &name("en8"), None, &none);
    assert_eq!(
        strict.foreign,
        [
            ForeignNetworkFinding::RoutableIpv4 {
                interface: name("bridge100"),
            },
            ForeignNetworkFinding::RoutableIpv4 {
                interface: name("en0"),
            },
            ForeignNetworkFinding::DefaultRoute {
                interface: name("en0"),
                family: IpFamily::V4,
            },
        ]
        .into()
    );
    // The separate uplink is exempt like the egress.
    let uplinked = check(&seen, &name("en8"), Some(&name("bridge100")), &own);
    assert!(uplinked.foreign.is_empty(), "{:?}", uplinked.foreign);
    // The same list with the egress elsewhere names en8 too.
    assert!(check(&seen, &name("en0"), None, &none).foreign.contains(
        &ForeignNetworkFinding::RoutableIpv4 {
            interface: name("en8"),
        }
    ));
}

/// A reflector on loopback that answers each connection with `answer`.
fn reflector(answer: &'static [u8]) -> SocketAddrV4 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.write_all(answer).unwrap();
        }
    });
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn lo0() -> InterfaceIndex {
    super::support::lo0()
}

/// A reflector answers and closes at once; on loopback its close can come
/// before the connect's poll looks, which socket2 reports as a hang-up
/// with no error (about 1 connect in 170 here). Every probe still reads
/// its answer.
#[test]
fn a_reflector_that_closes_before_the_connect_is_polled_is_still_read() {
    for _ in 0..1000 {
        assert_eq!(
            direct(lo0(), reflector(b"45.67.89.10\n")),
            Ok(Ipv4Addr::new(45, 67, 89, 10))
        );
    }
}

#[test]
fn the_direct_probe_reads_the_address_the_reflector_saw() {
    assert_eq!(
        direct(lo0(), reflector(b"45.67.89.10\n")),
        Ok(Ipv4Addr::new(45, 67, 89, 10))
    );
    for (answer, stage) in [
        (&b"not an address\n"[..], ProbeStage::Parse),
        (b"45.67.89.10", ProbeStage::Read),
        (b"", ProbeStage::Read),
    ] {
        let failure = direct(lo0(), reflector(answer)).unwrap_err();
        assert_eq!(failure.stage, stage, "{answer:?}");
    }
    let long: &'static [u8] = Box::leak(vec![b'1'; 100].into_boxed_slice());
    assert_eq!(
        direct(lo0(), reflector(long)).unwrap_err().stage,
        ProbeStage::Parse
    );
    // Nothing listens: the connection is refused.
    let closed = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let failure = direct(lo0(), SocketAddrV4::new(Ipv4Addr::LOCALHOST, closed)).unwrap_err();
    assert_eq!(failure.stage, ProbeStage::Connect);
    assert_eq!(failure.kind, Some(ErrorKind::ConnectionRefused));
}

/// A stand-in engine: `check` accepts the config `good`, or any JSON
/// object, and refuses any other with a line on stderr; `run` keeps its
/// config beside itself (`<binary>.ran`) and runs until killed, or exits
/// at once for the config `exit`.
pub(crate) fn stand_in(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("engine");
    fs::write(&path, STAND_IN).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The stand-in's script.
pub(crate) const STAND_IN: &str = "#!/bin/sh\ncase \"$1 $2 $3\" in\n\"check -c stdin\") config=$(cat); [ \"$config\" = good ] || [ \"${config#\\{}\" != \"$config\" ] || { echo \"refused: $config\" >&2; exit 3; } ;;\n\"run -c stdin\") cat > \"$0.ran\"; [ \"$(cat \"$0.ran\")\" = exit ] && exit 0; exec sleep 30 ;;\n*) exit 64 ;;\nesac\n";

#[test]
fn an_engine_checks_its_config_on_stdin_and_starts_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(&stand_in(dir.path()));
    engine.check(b"good").unwrap();
    match engine.check(b"bad\x1b") {
        Err(EngineError::Rejected { code, stderr }) => {
            assert_eq!(code, Some(3));
            assert_eq!(stderr, "refused: bad\\x1b\n");
        }
        other => panic!("{other:?}"),
    }
    let mut running = engine.start(b"the config").unwrap();
    // The config reaches the engine, which keeps running.
    let ran = dir.path().join("engine.ran");
    for _ in 0..200 {
        if fs::read(&ran).is_ok_and(|bytes| bytes == b"the config") {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read(&ran).unwrap(), b"the config");
    assert!(running.exited().unwrap().is_none());
    assert!(running.pid() > 0);
    let status = running.stop().unwrap();
    assert_eq!(status.signal(), Some(SIGKILL));
    // An engine that exits by itself is seen to have exited, and stopping
    // it only reaps it.
    let mut quick = engine.start(b"exit").unwrap();
    let mut exited = None;
    for _ in 0..200 {
        exited = quick.exited().unwrap();
        if exited.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(exited.is_some_and(|status| status.success()));
    assert!(quick.stop().unwrap().success());
}

#[test]
fn the_in_chain_probe_reads_the_line_at_the_end_of_the_chain() {
    let answering = reflector(b"31.120.5.6\n");
    let (ip, latency) = in_chain(answering.port()).unwrap();
    assert_eq!(ip, Ipv4Addr::new(31, 120, 5, 6));
    assert!(latency < Duration::from_secs(5));
    // Nothing listens on the inbound: `mooring-probe` is not there.
    let closed = {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let failure = in_chain(closed).unwrap_err();
    assert_eq!(failure.stage, ProbeStage::Connect);
    assert_eq!(
        in_chain(reflector(b"no\n").port()).unwrap_err().stage,
        ProbeStage::Parse
    );
}

#[test]
fn a_missing_engine_is_a_spawn_failure() {
    let engine = Engine::new(std::path::Path::new("/nonexistent/mooring-exit"));
    assert!(matches!(
        engine.check(b"good"),
        Err(EngineError::Spawn { .. })
    ));
    assert!(matches!(
        engine.start(b"good"),
        Err(EngineError::Spawn { .. })
    ));
}

/// The helper's lines are read as events, in order, until the output
/// ends; a line that is not an event, one cut short or one past the bound
/// ends the reading, saying which.
#[test]
fn the_power_helpers_lines_are_read_as_events_until_one_is_not() {
    use mooring_daemon_core::power::{HelperEvent, MAX_HELPER_LINE_BYTES};

    let read = |input: &[u8]| {
        let mut events = Vec::new();
        let ended = read_lines(input, |event| {
            events.push(event);
            true
        });
        (events, ended)
    };
    let (events, ended) =
        read(b"{\"power_source\":\"ac\"}\n\"did_wake\"\n{\"will_sleep\":{\"id\":3}}\n");
    assert_eq!(
        events,
        [
            HelperEvent::PowerSource(PowerSource::Ac),
            HelperEvent::DidWake,
            HelperEvent::WillSleep { id: 3 }
        ]
    );
    assert_eq!(ended, "the power helper exited");
    let (events, ended) = read(b"\"did_wake\"\n{\"power_source\":\"solar\"}\n\"did_wake\"\n");
    assert_eq!(events, [HelperEvent::DidWake]);
    assert!(
        ended.starts_with("the power helper wrote a line that is not an event"),
        "{ended}"
    );
    let (events, ended) = read(b"\"did_wake\"");
    assert_eq!(events, []);
    assert_eq!(ended, "the power helper's output ended within a line");
    let long = vec![b' '; MAX_HELPER_LINE_BYTES + 10];
    let (events, ended) = read(&long);
    assert_eq!(events, []);
    assert_eq!(
        ended,
        "the power helper wrote a line longer than its protocol allows"
    );
    // A reader that stops taking events ends the reading.
    let ended = read_lines(&b"\"did_wake\"\n\"did_wake\"\n"[..], |_| false);
    assert_eq!(ended, "the daemon stopped reading the power helper");
}

/// The helper lies beside the daemon's executable; one that is not there
/// cannot be started, which names it.
#[test]
fn the_power_helper_lies_beside_mooringctl() {
    use crate::runtime::power::{helper_path, spawn_at};

    assert_eq!(
        helper_path(std::path::Path::new(
            "/A/Mooring.app/Contents/MacOS/mooringctl"
        )),
        std::path::Path::new("/A/Mooring.app/Contents/MacOS/mooring-power")
    );
    let missing = std::path::Path::new("/nonexistent/mooring-power");
    let error = spawn_at(missing).unwrap_err();
    assert!(
        matches!(&error, LocalError::PowerHelperSpawn { path, .. } if path == missing),
        "{error:?}"
    );
}

/// A helper process that writes events and ends: they arrive in order on
/// the link, then the end; the daemon's commands reach its stdin.
#[test]
fn a_helper_process_is_read_and_written_through_its_pipes() {
    use crate::runtime::power::{PowerMessage, spawn_at};
    use mooring_daemon_core::power::{HelperCommand, HelperEvent};

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("mooring-power");
    let seen = dir.path().join("seen");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '{{\"power_source\":\"battery\"}}\\n'\nIFS= read -r line\nprintf '%s\\n' \"$line\" > '{}'\nprintf '\"did_wake\"\\n'\n",
            seen.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let mut link = spawn_at(&script).unwrap();
    let wait = Duration::from_secs(10);
    assert_eq!(
        link.messages.recv_timeout(wait).unwrap(),
        PowerMessage::Event(HelperEvent::PowerSource(PowerSource::Battery))
    );
    link.send(&HelperCommand::Hold(true)).unwrap();
    assert_eq!(
        link.messages.recv_timeout(wait).unwrap(),
        PowerMessage::Event(HelperEvent::DidWake)
    );
    assert_eq!(
        link.messages.recv_timeout(wait).unwrap(),
        PowerMessage::Ended("the power helper exited".to_owned())
    );
    assert_eq!(fs::read_to_string(&seen).unwrap(), "{\"hold\":true}\n");
}

/// A closed link reaps its helper: one that exits at the end of its input
/// is waited for, one that ignores it is killed after
/// [`HELPER_EXIT_WAIT`](crate::runtime::power::HELPER_EXIT_WAIT); a link
/// dropped unclosed reaps it too. None is left behind, not even a zombie.
#[test]
fn a_closed_helper_is_reaped_and_one_that_lingers_is_killed() {
    use crate::runtime::power::{PowerMessage, spawn_at};
    use mooring_daemon_core::power::HelperEvent;

    let dir = tempfile::tempdir().unwrap();
    let start = |name: &str, rest: &str| {
        let script = dir.path().join(name);
        let pid_file = dir.path().join(format!("{name}.pid"));
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho $$ > '{}'\nprintf '{{\"power_source\":\"ac\"}}\\n'\n{rest}\n",
                pid_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let link = spawn_at(&script).unwrap();
        assert_eq!(
            link.messages.recv_timeout(Duration::from_secs(10)).unwrap(),
            PowerMessage::Event(HelperEvent::PowerSource(PowerSource::Ac))
        );
        let pid = fs::read_to_string(pid_file).unwrap().trim().to_owned();
        (link, pid)
    };
    // Gone: `ps` lists no such process, running or zombie.
    let gone = |pid: &str| {
        let listed = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        !listed.status.success() && listed.stdout.is_empty()
    };
    let (link, pid) = start("obedient", "cat > /dev/null");
    assert_eq!(link.close(), "exit status: 0");
    assert!(gone(&pid), "{pid}");
    let (link, pid) = start("lingering", "exec /bin/sleep 30");
    let closing = Instant::now();
    let end = link.close();
    assert!(end.starts_with("killed after 1s: signal: 9"), "{end}");
    assert!(closing.elapsed() < Duration::from_secs(5));
    assert!(gone(&pid), "{pid}");
    let (link, pid) = start("dropped", "cat > /dev/null");
    drop(link);
    assert!(gone(&pid), "{pid}");
}

/// 2026-10-24T00:00:00Z.
const MIDNIGHT: u64 = 1_792_800_000;

fn watched() -> Watched {
    Watched {
        index: InterfaceIndex::new(8).unwrap(),
        lladdr: MacAddr::from_bytes(OWN).unwrap(),
    }
}

fn counted(at: u64, rx: u64) -> CounterReading {
    CounterReading {
        at: UnixTime::from_secs(at),
        boot: UnixTime::from_secs(MIDNIGHT - 3_600),
        index: watched().index,
        lladdr: watched().lladdr,
        rx,
        tx: 0,
    }
}

/// A reader that gives `readings` in order, then none.
fn scripted(readings: Vec<CounterReading>) -> (Reader, Arc<Mutex<VecDeque<CounterReading>>>) {
    let queue = Arc::new(Mutex::new(VecDeque::from(readings)));
    let shared = Arc::clone(&queue);
    (
        Box::new(move |asked: Watched| {
            assert_eq!(asked, watched());
            Ok(shared.lock().unwrap().pop_front())
        }),
        queue,
    )
}

fn one_day() -> BillingCycle {
    BillingCycle::containing(
        CycleRule::FixedDays {
            days: PeriodDays::new(1).unwrap(),
            anchor: CalendarDate::parse("2026-10-01").unwrap(),
        },
        CalendarDate::parse("2026-10-24").unwrap(),
    )
    .unwrap()
}

/// Waits until `done` holds, for at most 5 s.
fn until(done: impl Fn() -> bool) {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(5), "timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn the_meter_thread_counts_what_it_reads_and_writes_the_file_when_it_stops() {
    let support = tempfile::tempdir().unwrap();
    let (reader, queue) = scripted(vec![
        counted(MIDNIGHT + 10, 1_000),
        counted(MIDNIGHT + 12, 5_096),
        counted(MIDNIGHT + 14, 9_192),
    ]);
    let meter = MeterThread::start(
        support.path().to_path_buf(),
        SimMeter::new(),
        reader,
        Duration::from_millis(5),
        Duration::from_secs(3_600),
    )
    .unwrap();
    // Nothing is read until the loop says which interface the egress is.
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(queue.lock().unwrap().len(), 3);
    meter.watch(Some(watched())).unwrap();
    until(|| queue.lock().unwrap().is_empty());
    until(|| meter.meter().unwrap().cycle_bytes(one_day()).rx == 8_192);
    assert_eq!(
        meter.meter().unwrap().cycle_bytes(one_day()),
        CycleBytes {
            rx: 8_192,
            tx: 0,
            short: false
        }
    );
    let file = support.path().join(USAGE_DIRECTORY).join(SIM_METER_FILE);
    assert!(!file.exists(), "written before its interval");
    drop(meter);
    let written = SimMeter::decode(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(written.cycle_bytes(one_day()).rx, 8_192);
    assert_eq!(written.last(), Some(&counted(MIDNIGHT + 14, 9_192)));
}

#[test]
fn a_reading_the_meter_refuses_ends_the_thread_with_its_fault() {
    let support = tempfile::tempdir().unwrap();
    let (reader, _) = scripted(vec![
        counted(MIDNIGHT, 1),
        counted(MIDNIGHT + 2, COUNTER_MODULUS),
    ]);
    let meter = MeterThread::start(
        support.path().to_path_buf(),
        SimMeter::new(),
        reader,
        Duration::from_millis(5),
        Duration::from_secs(3_600),
    )
    .unwrap();
    meter.watch(Some(watched())).unwrap();
    until(|| meter.meter().is_err());
    match meter.meter() {
        Err(LocalError::MeterFault { fault }) => {
            assert_eq!(
                fault,
                "the SIM meter failed: an egress counter read 4294967296, which is not below 2^32"
            );
        }
        other => panic!("{other:?}"),
    }
    let failing: Reader = Box::new(|_| Err(LocalError::Kernel(MacsysError::TableChanged)));
    let meter = MeterThread::start(
        support.path().to_path_buf(),
        SimMeter::new(),
        failing,
        Duration::from_millis(5),
        Duration::from_secs(3_600),
    )
    .unwrap();
    meter.watch(Some(watched())).unwrap();
    until(|| meter.meter().is_err());
    assert!(matches!(meter.meter(), Err(LocalError::MeterFault { .. })));
}

#[test]
fn a_meter_write_that_fails_is_noted_and_tried_again() {
    let support = tempfile::tempdir().unwrap();
    fs::write(support.path().join(USAGE_DIRECTORY), b"").unwrap();
    let (reader, _) = scripted(vec![counted(MIDNIGHT, 1)]);
    let meter = MeterThread::start(
        support.path().to_path_buf(),
        SimMeter::new(),
        reader,
        Duration::from_millis(5),
        Duration::from_millis(10),
    )
    .unwrap();
    meter.watch(Some(watched())).unwrap();
    until(|| meter.write_failure().unwrap().is_some());
    assert!(
        meter
            .write_failure()
            .unwrap()
            .unwrap()
            .starts_with("the SIM meter's file failed"),
    );
    // Once the path is free the next write succeeds.
    fs::remove_file(support.path().join(USAGE_DIRECTORY)).unwrap();
    until(|| meter.write_failure().unwrap().is_none());
    assert!(
        support
            .path()
            .join(USAGE_DIRECTORY)
            .join(SIM_METER_FILE)
            .exists()
    );
}

#[test]
fn a_stale_engine_is_stopped_only_when_it_is_this_engine() {
    let run = tempfile::tempdir().unwrap();
    let pid_file = run.path().join(ENGINE_PID_FILE);
    let sleep = std::path::Path::new("/bin/sleep");
    // Another program at the pid is left running.
    let mut other = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    fs::write(&pid_file, format!("{}\n", other.id())).unwrap();
    assert_eq!(
        stop_stale_engine(
            run.path(),
            ENGINE_PID_FILE,
            std::path::Path::new("/nonexistent/mooring-exit")
        )
        .unwrap(),
        None
    );
    assert!(!pid_file.exists());
    assert!(other.try_wait().unwrap().is_none());
    // This engine is stopped.
    fs::write(&pid_file, format!("{}\n", other.id())).unwrap();
    assert_eq!(
        stop_stale_engine(run.path(), ENGINE_PID_FILE, sleep).unwrap(),
        Some(other.id())
    );
    assert_eq!(other.wait().unwrap().signal(), Some(SIGKILL));
    assert!(!pid_file.exists());
    // No file, or one that is not a pid, stops nothing.
    assert_eq!(
        stop_stale_engine(run.path(), ENGINE_PID_FILE, sleep).unwrap(),
        None
    );
    fs::write(&pid_file, b"not a pid\n").unwrap();
    assert_eq!(
        stop_stale_engine(run.path(), ENGINE_PID_FILE, sleep).unwrap(),
        None
    );
    assert!(!pid_file.exists());
}
