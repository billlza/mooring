// SPDX-License-Identifier: GPL-3.0-or-later

//! Every measurement against a real `serve` on 127.0.0.1, with the probes
//! bound to the loopback interface. Loopback has no NAT, so these check the
//! tools and the protocol, not a carrier: the mapping is the socket's own,
//! nothing is filtered and nothing times out.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use mooring_model::Pairing;

use crate::measure::nat_behaviour::{Filtering, Mapping};
use crate::measure::port_ceiling::Stop;
use crate::measure::{nat_behaviour, nat_timeout, pooling, port_ceiling, public_ips, rtt, uplink};
use crate::net::Bind;
use crate::output::Output;
use crate::serve::{Counts, MAX_PENDING, Ports, ServeConfig, Server};
use crate::wire::{Delay, EchoAnswer, EchoKind, EchoRequest, reflector_line};

#[cfg(target_os = "macos")]
const LOOPBACK: &str = "lo0";
#[cfg(target_os = "linux")]
const LOOPBACK: &str = "lo";

fn server(ceiling_max: u16) -> Server {
    Server::start(ServeConfig {
        listen: Ipv4Addr::LOCALHOST,
        reflector: 0,
        echo: (0, 0),
        ceiling: 0,
        ceiling_max,
        sink: 0,
    })
    .unwrap()
}

fn at(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn bind() -> Bind {
    Bind::interface(LOOPBACK).unwrap()
}

/// Output captured in memory: the JSON lines and the notes.
#[derive(Default)]
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Captured {
    fn output(&mut self) -> Output<'_> {
        Output::new(&mut self.stdout, &mut self.stderr)
    }

    fn lines(&self) -> Vec<serde_json::Value> {
        String::from_utf8(self.stdout.clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

/// Waits up to two seconds for the server's counts to satisfy `ready`.
fn counts_when(server: &Server, ready: impl Fn(&Counts) -> bool) -> Counts {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let counts = server.counts();
        if ready(&counts) || Instant::now() >= deadline {
            return counts;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_servers_listen_and_stop() {
    let server = server(16);
    let Ports {
        reflector,
        echo_a,
        echo_b,
        ceiling,
        sink,
    } = server.ports();
    let ports = [reflector, echo_a, echo_b, ceiling, sink];
    assert!(ports.iter().all(|&port| port != 0));
    let mut stream = TcpStream::connect(at(reflector)).unwrap();
    let mut line = String::new();
    stream.read_to_string(&mut line).unwrap();
    assert_eq!(
        line,
        reflector_line(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            stream.local_addr().unwrap().port()
        ))
    );
    let counts = server.stop().unwrap();
    assert_eq!(counts.reflector_served, 1);
    assert!(
        TcpStream::connect(at(reflector)).is_err(),
        "the reflector still listens"
    );
}

#[test]
fn the_echo_answers_now_from_the_other_port_and_later() {
    let server = server(16);
    let ports = server.ports();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mine = SocketAddrV4::new(Ipv4Addr::LOCALHOST, socket.local_addr().unwrap().port());
    let cases = [
        (EchoKind::Now, ports.echo_a),
        (EchoKind::FromOtherPort, ports.echo_b),
        (
            EchoKind::Delayed(Delay::new(Duration::from_millis(300)).unwrap()),
            ports.echo_a,
        ),
    ];
    for (index, (kind, from)) in cases.into_iter().enumerate() {
        let request = EchoRequest {
            kind,
            nonce: [u8::try_from(index).unwrap(); 16],
        };
        let sent = Instant::now();
        socket.send_to(&request.encode(), at(ports.echo_a)).unwrap();
        let mut buffer = [0_u8; 64];
        let (len, source) = socket.recv_from(&mut buffer).unwrap();
        let answer = EchoAnswer::decode(&buffer[..len]).unwrap();
        assert_eq!(source.port(), from, "{kind:?}");
        assert_eq!(answer.server_port, from, "{kind:?}");
        assert_eq!(answer.observed, mine, "{kind:?}");
        assert_eq!(answer.nonce, request.nonce);
        if let EchoKind::Delayed(_) = kind {
            assert!(
                sent.elapsed() >= Duration::from_millis(300),
                "answered early"
            );
        }
    }
    socket.send_to(b"not a request", at(ports.echo_a)).unwrap();
    let counts = counts_when(&server, |counts| counts.echo_refused == 1);
    assert_eq!(counts.echo_answered, 3);
    assert_eq!(counts.echo_refused, 1);
    server.stop().unwrap();
}

#[test]
fn delayed_answers_wait_in_a_bounded_queue() {
    let server = server(16);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let request = EchoRequest {
        kind: EchoKind::Delayed(Delay::new(Duration::from_secs(600)).unwrap()),
        nonce: [1; 16],
    }
    .encode();
    let extra = 50;
    for _ in 0..MAX_PENDING + extra {
        socket.send_to(&request, at(server.ports().echo_a)).unwrap();
        thread::sleep(Duration::from_micros(50));
    }
    let counts = counts_when(&server, |counts| {
        counts.echo_delayed_dropped >= extra as u64
    });
    assert_eq!(counts.echo_delayed_dropped, extra as u64);
    assert_eq!(counts.echo_answered, 0);
    server.stop().unwrap();
}

#[test]
fn the_sink_refuses_a_bad_opening_line_and_reports_a_good_one() {
    let server = server(16);
    let mut bad = TcpStream::connect(at(server.ports().sink)).unwrap();
    bad.write_all(b"HELLO\n").unwrap();
    let mut rest = Vec::new();
    bad.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "a bad line got an answer");
    let mut good = TcpStream::connect(at(server.ports().sink)).unwrap();
    good.write_all(b"MFK1 SINK 1\n").unwrap();
    good.write_all(&[0; 1000]).unwrap();
    good.shutdown(std::net::Shutdown::Write).unwrap();
    let mut report = String::new();
    good.read_to_string(&mut report).unwrap();
    assert_eq!(report, "{\"bytes_per_second\":[1000]}\n");
    let counts = counts_when(&server, |counts| {
        counts.sink_refused == 1 && counts.sink_sessions == 1
    });
    assert_eq!((counts.sink_refused, counts.sink_sessions), (1, 1));
    server.stop().unwrap();
}

#[test]
fn serving_for_a_while_records_the_counts_and_stops() {
    let server = server(16);
    let reflector = server.ports().reflector;
    let mut captured = Captured::default();
    let counts = server
        .serve_for(
            Duration::from_millis(900),
            Duration::from_millis(300),
            &mut captured.output(),
        )
        .unwrap();
    let lines = captured.lines();
    assert!(
        (2..=3).contains(&lines.len()),
        "{} count lines",
        lines.len()
    );
    assert!(lines.iter().all(|line| line["echo_answered"] == 0));
    assert_eq!(counts.reflector_served, 0);
    assert!(TcpStream::connect(at(reflector)).is_err(), "still serving");
}

#[test]
fn nat_timeout_finds_no_timeout_on_loopback() {
    let server = server(16);
    let mut captured = Captured::default();
    let plan = nat_timeout::Plan {
        echo: at(server.ports().echo_a),
        min: Delay::new(Duration::from_millis(200)).unwrap(),
        max: Delay::new(Duration::from_millis(600)).unwrap(),
        resolution: Duration::from_millis(100),
    };
    let summary = nat_timeout::run(&bind(), plan, &mut captured.output()).unwrap();
    assert_eq!(summary.alive_up_to_ms, Some(600));
    assert_eq!(summary.dead_from_ms, None);
    assert_eq!(summary.max_keepalive, None, "0.6 s admits no keepalive");
    let lines = captured.lines();
    assert_eq!(lines.len(), 3, "two probes and the summary");
    assert_eq!(lines[0]["idle_ms"], 200);
    assert_eq!(lines[1]["idle_ms"], 600);
    assert_eq!(lines[2]["measure"], "udp-nat-timeout");
    server.stop().unwrap();
}

#[test]
fn a_silent_echo_server_stops_a_measurement() {
    let unused = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let plan = nat_timeout::Plan {
        echo: at(port),
        min: Delay::new(Duration::from_secs(1)).unwrap(),
        max: Delay::new(Duration::from_secs(2)).unwrap(),
        resolution: Duration::from_secs(1),
    };
    let mut captured = Captured::default();
    let error = nat_timeout::run(&bind(), plan, &mut captured.output()).unwrap_err();
    assert!(
        matches!(error, crate::error::FieldkitError::Silent { .. }),
        "{error}"
    );
    assert!(captured.stdout.is_empty());
}

#[test]
fn nat_behaviour_on_loopback_keeps_the_port_and_admits_the_other() {
    let server = server(16);
    let ports = server.ports();
    let mut captured = Captured::default();
    let summary = nat_behaviour::run(
        &bind(),
        at(ports.echo_a),
        at(ports.echo_b),
        &mut captured.output(),
    )
    .unwrap();
    assert_eq!(summary.public_ip, Ipv4Addr::LOCALHOST);
    assert_eq!(summary.mapping, Mapping::SameForBothPorts);
    assert_eq!(summary.filtering, Filtering::AdmitsUncontactedPort);
    assert_eq!(captured.lines()[0]["filtering"], "admits_uncontacted_port");
    server.stop().unwrap();
}

#[test]
fn public_ips_records_each_sample_and_the_distinct_addresses() {
    let server = server(16);
    let mut captured = Captured::default();
    let plan = public_ips::Plan {
        reflector: at(server.ports().reflector),
        duration: Duration::from_millis(500),
        interval: Duration::from_millis(200),
    };
    let summary = public_ips::run(&bind(), plan, &mut captured.output()).unwrap();
    assert_eq!(summary.samples, 3);
    assert_eq!(summary.failures, 0);
    assert_eq!(summary.addresses.len(), 1);
    assert_eq!(summary.addresses[0].ip, Ipv4Addr::LOCALHOST);
    assert_eq!(summary.addresses[0].samples, 3);
    assert_eq!(captured.lines().len(), 4);
    server.stop().unwrap();
}

#[test]
fn public_ips_stops_when_its_first_sample_fails() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let plan = public_ips::Plan {
        reflector: at(port),
        duration: Duration::from_secs(1),
        interval: Duration::from_secs(1),
    };
    let mut captured = Captured::default();
    assert!(public_ips::run(&bind(), plan, &mut captured.output()).is_err());
}

#[test]
fn pooling_on_loopback_is_paired_over_tcp_and_udp() {
    let server = server(16);
    let mut captured = Captured::default();
    let plan = pooling::Plan {
        reflector: at(server.ports().reflector),
        more_reflectors: vec![at(server.ports().reflector)],
        echo: Some(at(server.ports().echo_a)),
        flows: 4,
        duration: Duration::from_millis(300),
        interval: Duration::from_millis(200),
    };
    let summary = pooling::run(&bind(), &plan, &mut captured.output()).unwrap();
    assert_eq!(summary.rounds, 2);
    assert_eq!(summary.single_address_rounds, 2);
    assert_eq!(summary.silent_rounds, 0);
    assert!(summary.udp);
    assert_eq!(summary.pairing, Pairing::Paired);
    let rounds = captured.lines();
    assert_eq!(rounds[0]["flows_answered"], 12);
    assert_eq!(rounds[0]["tcp_addresses"], serde_json::json!(["127.0.0.1"]));
    assert_eq!(rounds[0]["udp_addresses"], serde_json::json!(["127.0.0.1"]));
    assert_eq!(rounds[0]["flows_failed"], 0);
    server.stop().unwrap();
}

#[test]
fn port_ceiling_holds_up_to_its_max() {
    let server = server(32);
    let plan = port_ceiling::Plan {
        target: at(server.ports().ceiling),
        max: 10,
        timeout: Duration::from_secs(2),
    };
    let mut captured = Captured::default();
    let summary = port_ceiling::run(&bind(), plan, &mut captured.output()).unwrap();
    assert_eq!(summary.held, 10);
    assert_eq!(summary.stopped_by, Stop::ReachedMax);
    assert_eq!(summary.last_failure, None);
    let counts = counts_when(&server, |counts| counts.ceiling_held_peak == 10);
    assert_eq!(counts.ceiling_held_peak, 10);
    server.stop().unwrap();
}

#[test]
fn port_ceiling_tells_the_targets_limit_from_the_lines() {
    let server = server(5);
    let plan = port_ceiling::Plan {
        target: at(server.ports().ceiling),
        max: 20,
        timeout: Duration::from_secs(1),
    };
    let mut captured = Captured::default();
    let summary = port_ceiling::run(&bind(), plan, &mut captured.output()).unwrap();
    assert_eq!(summary.held, 5);
    assert_eq!(summary.stopped_by, Stop::TargetRefused);
    assert!(summary.last_failure.is_some());
    server.stop().unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let plan = port_ceiling::Plan {
        target: at(port),
        max: 20,
        timeout: Duration::from_secs(1),
    };
    let summary = port_ceiling::run(&bind(), plan, &mut captured.output()).unwrap();
    assert_eq!(summary.held, 0);
    assert_eq!(summary.stopped_by, Stop::ConnectFailed);
}

#[test]
fn uplink_measures_the_rate_the_rtt_and_the_bytes() {
    let server = server(16);
    let mut captured = Captured::default();
    let plan = uplink::Plan {
        sink: at(server.ports().sink),
        echo: at(server.ports().echo_a),
        duration: Duration::from_millis(100),
        interval: Duration::from_secs(60),
        seconds: 2,
        warmup: 1,
        flows: 2,
    };
    let summary = uplink::run(&bind(), plan, &mut captured.output()).unwrap();
    assert_eq!((summary.samples, summary.failures), (1, 0));
    let spread = summary.goodput_bps.unwrap();
    assert!(
        spread.p50 > 1_000_000,
        "loopback ran at {} bit/s",
        spread.p50
    );
    let baseline = summary.baseline.unwrap();
    assert_eq!(
        (baseline.p10_bps(), baseline.p50_bps()),
        (spread.p10, spread.p50)
    );
    assert!(summary.delivered_bytes > 0);
    assert!(summary.app_bytes >= summary.delivered_bytes);
    assert!(summary.idle_rtt_p50_us.is_some());
    assert!(summary.loaded_rtt_p50_us.is_some());
    #[cfg(target_os = "macos")]
    assert!(summary.interface_bytes.is_some());
    let note = String::from_utf8(captured.stderr.clone()).unwrap();
    assert!(
        note.starts_with("fieldkit: the first sample carried "),
        "{note}"
    );
    assert!(
        note.contains(" 1 samples at that rate carry about "),
        "{note}"
    );
    let sample = &captured.lines()[0];
    assert_eq!(sample["per_flow_bps"].as_array().unwrap().len(), 2);
    assert!(sample["fairness_permille"].as_u64().unwrap() > 0);
    server.stop().unwrap();
}

#[test]
fn rtt_times_connects_and_counts_failures() {
    let server = server(16);
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let plan = rtt::Plan {
        targets: vec![at(server.ports().reflector), at(port)],
        count: 2,
        timeout: Duration::from_secs(1),
    };
    let mut captured = Captured::default();
    let summary = rtt::run(&bind(), &plan, &mut captured.output()).unwrap();
    assert_eq!(summary.targets[0].connect_us.unwrap().count, 2);
    assert_eq!(summary.targets[0].failures, 0);
    assert_eq!(summary.targets[1].connect_us, None);
    assert_eq!(summary.targets[1].failures, 2);
    server.stop().unwrap();
}

#[test]
fn the_volume_note_scales_the_first_sample_to_the_run() {
    let first = uplink::Measured {
        goodput_bps: 0,
        per_flow_bps: Vec::new(),
        fairness_permille: None,
        idle_rtt_us: None,
        loaded_rtt_us: None,
        loaded_rtt_lost: 0,
        app_bytes: 0,
        delivered_bytes: 250_000_000,
        interface_bytes: None,
    };
    let plan = uplink::Plan {
        sink: at(1),
        echo: at(2),
        duration: Duration::from_secs(24 * 3600),
        interval: Duration::from_secs(15 * 60),
        seconds: 20,
        warmup: 3,
        flows: 1,
    };
    assert_eq!(
        uplink::volume_note(&first, plan),
        "the first sample carried 250 MB; 96 samples at that rate carry about 24000 MB"
    );
}

#[test]
fn the_rate_leaves_out_the_warm_up() {
    assert_eq!(uplink::rate_after_warmup(&[100, 1000, 3000], 1), 16_000);
    assert_eq!(uplink::rate_after_warmup(&[100, 1000, 3000], 0), 10_933);
    assert_eq!(uplink::rate_after_warmup(&[100], 1), 0);
    assert_eq!(uplink::rate_after_warmup(&[], 0), 0);
}

#[test]
fn counter_deltas_follow_a_32_bit_wrap_and_refuse_a_reset() {
    assert_eq!(uplink::counter_delta(10, 30), Some(20));
    assert_eq!(
        uplink::counter_delta(u64::from(u32::MAX) - 1023, 1024),
        Some(2048)
    );
    assert_eq!(uplink::counter_delta(1 << 33, 5), None);
    assert_eq!(uplink::counter_delta(7, 7), Some(0));
}
