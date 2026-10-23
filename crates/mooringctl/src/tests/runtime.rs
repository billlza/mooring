// SPDX-License-Identifier: GPL-3.0-or-later

//! The exit runtime's parts (design §10.1, §10.2): interface resolution and
//! the exit site's interfaces against a scripted interface list, the
//! foreign-network snapshot, the direct probe against a loopback
//! reflector, the engine's check, start and stop against a stand-in
//! script, the power source's line, the SIM meter's thread, and the
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
use mooring_daemon_core::network::ForeignNetworkFinding;
use mooring_daemon_core::period::BillingCycle;
use mooring_daemon_core::status::{LinkState, PowerSource, ProbeStage};
use mooring_macsys::{Interface, InterfaceAddrV4, MacsysError};
use mooring_model::exit::Uplink;
use mooring_model::iface::{BsdName, InterfaceIndex, InterfaceSelector, MacAddr};
use mooring_model::sim::{CycleRule, PeriodDays};
use mooring_model::{CalendarDate, UnixTime};
use mooring_store::{SIM_METER_FILE, USAGE_DIRECTORY};

use super::support::{FakeLink, PINNED, Route};
use crate::error::LocalError;
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::meter::{MeterThread, Reader, Watched};
use crate::runtime::network::foreign;
use crate::runtime::ports::{ENGINE_PID_FILE, stop_stale_engine};
use crate::runtime::power::parse;
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

#[test]
fn every_routable_interface_but_the_egress_is_foreign() {
    let listed = vec![
        interface(1, "lo0", OWN, Some([127, 0, 0, 1]), true),
        interface(8, "en8", OWN, Some([192, 168, 1, 20]), true),
        interface(4, "en0", OTHER, Some([172, 20, 10, 2]), true),
        interface(20, "utun3", OTHER, None, true),
        interface(30, "bridge100", OTHER, Some([192, 168, 64, 1]), true),
        interface(31, "bridge0", OTHER, Some([169, 254, 3, 3]), true),
    ];
    let found = foreign(&listed, &BsdName::parse("en8").unwrap()).unwrap();
    let names: Vec<String> = found
        .iter()
        .map(|finding| match finding {
            ForeignNetworkFinding::RoutableIpv4 { interface } => interface.as_str().to_owned(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(names, ["bridge100", "en0"]);
    // The same list with the egress elsewhere names en8 too.
    assert_eq!(
        foreign(&listed, &BsdName::parse("en0").unwrap())
            .unwrap()
            .len(),
        2
    );
    let odd = vec![interface(1, "not a name", OWN, Some([10, 0, 0, 1]), true)];
    assert!(matches!(
        foreign(&odd, &BsdName::parse("en8").unwrap()),
        Err(LocalError::InterfaceName { name }) if name == "not a name"
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

#[test]
fn pmset_names_the_power_source_on_its_first_line() {
    for (stdout, source) in [
        (
            &b"Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; charged\n"[..],
            PowerSource::Ac,
        ),
        (b"Now drawing from 'Battery Power'\n", PowerSource::Battery),
        (b"Now drawing from 'UPS Power'", PowerSource::Battery),
    ] {
        assert_eq!(parse(stdout).unwrap(), source);
    }
    for stdout in [
        &b""[..],
        b"\n",
        b"Now drawing from 'Solar Power'\n",
        b" Now drawing from 'AC Power'\n",
        b"-InternalBattery-0\nNow drawing from 'AC Power'\n",
    ] {
        assert!(matches!(parse(stdout), Err(LocalError::PowerUnreadable)));
    }
    // This Mac answers one of them.
    assert!(crate::runtime::power::power_source().is_ok());
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
