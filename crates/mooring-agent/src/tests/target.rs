// SPDX-License-Identifier: GPL-3.0-or-later

//! The target check against a stand-in node whose tools print what the
//! pinned ones print, and the handshake sampler against local servers that
//! answer as TLS servers do.

use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::num::NonZeroU16;
use std::thread;
use std::time::Duration;

use mooring_agent_proto::{
    AgentError, BlobLen, CertName, Generation, HttpProbe, HttpStatus, HttpVersion, RedirectUrl,
    Sha256Hex, TargetFacts, TargetHost, TargetTool, TlsGroup, TlsProbe, TlsVersion, UnixTime,
    WatchConfig, WatchTarget,
};

use super::{FakeNode, exited, ok, scratch};
use crate::blobs::{digest_of, put};
use crate::host::Tool;
use crate::paths::Paths;
use crate::store::{read_json, write_json};
use crate::target::sampler::{self, RANDOM_BYTES};
use crate::target::{TargetReading, TlsDetails, TlsPing, parse_curl, parse_getent, parse_tls_ping};

fn host() -> TargetHost {
    TargetHost::new("www.example.com").unwrap()
}

/// `xray tls ping` for a TLS 1.3 target, as the pinned source prints it:
/// the part without SNI first, then the details a tabwriter aligned.
const PING_TLS13: &str = "TLS ping:  www.example.com\n\
Using IP:  127.0.0.1:443\n\
-------------------\n\
Pinging without SNI\n\
Handshake failure:  remote error: tls: unrecognized name\n\
-------------------\n\
Pinging with SNI\n\
Handshake succeeded\n\
TLS Version:                       TLS 1.3\n\
TLS Post-Quantum key exchange:     true (X25519MLKEM768)\n\
Certificate chain's total length:  4431 (certs count: 3)\n\
Cert's signature algorithm:        SHA256-RSA\n\
Cert's publicKey algorithm:        ECDSA\n\
Cert's leaf SHA256:                0a1b2c\n\
Cert's CA <R11> SHA256:            3d4e5f\n\
Cert's allowed domains:            [www.example.com example.com]\n\
-------------------\n\
TLS ping finished\n";

fn tls13() -> TlsDetails {
    TlsDetails {
        version: TlsVersion::Tls13,
        group: Some(TlsGroup::X25519_MLKEM768),
        chain_bytes: 4431,
        chain_certs: 3,
        leaf_names: vec![
            CertName::new("www.example.com").unwrap(),
            CertName::new("example.com").unwrap(),
        ],
    }
}

#[test]
fn a_completed_tls_1_3_ping_is_read_from_its_sni_part() {
    assert_eq!(
        parse_tls_ping(&ok(PING_TLS13.as_bytes())),
        Some(TlsPing::Completed(tls13()))
    );
}

#[test]
fn a_tls_1_2_ping_with_rsa_key_transport_has_no_group() {
    let text = "TLS ping:  www.example.com\n\
        Pinging with SNI\n\
        Handshake succeeded\n\
        TLS Version:  TLS 1.2\n\
        TLS Post-Quantum key exchange:  false (RSA Exchange)\n\
        Certificate chain's total length:  2900 (certs count: 2)\n\
        -------------------\n";
    assert_eq!(
        parse_tls_ping(&ok(text.as_bytes())),
        Some(TlsPing::Completed(TlsDetails {
            version: TlsVersion::Tls12,
            group: None,
            chain_bytes: 2900,
            chain_certs: 2,
            leaf_names: Vec::new(),
        }))
    );
}

#[test]
fn a_group_go_has_no_name_for_is_read_by_its_code_point() {
    for (name, group) in [
        ("X25519", TlsGroup::X25519),
        ("CurveP256", TlsGroup::SECP256R1),
        ("CurveP384", TlsGroup::SECP384R1),
        ("CurveP521", TlsGroup::new(25)),
        ("SecP256r1MLKEM768", TlsGroup::new(4587)),
        ("SecP384r1MLKEM1024", TlsGroup::new(4589)),
        ("CurveID(25497)", TlsGroup::new(25497)),
    ] {
        let text = PING_TLS13.replace("true (X25519MLKEM768)", &format!("false ({name})"));
        let Some(TlsPing::Completed(details)) = parse_tls_ping(&ok(text.as_bytes())) else {
            panic!("{name}");
        };
        assert_eq!(details.group, Some(group), "{name}");
    }
    let unknown = PING_TLS13.replace("true (X25519MLKEM768)", "false (CurveFoo)");
    assert_eq!(parse_tls_ping(&ok(unknown.as_bytes())), None);
}

#[test]
fn a_failed_handshake_and_a_failed_dial_are_told_apart() {
    let failed_handshake = "TLS ping:  www.example.com\n\
        Pinging without SNI\n\
        Handshake failure:  EOF\n\
        -------------------\n\
        Pinging with SNI\n\
        Handshake failure:  remote error: tls: handshake failure\n\
        -------------------\n\
        TLS ping finished\n";
    assert_eq!(
        parse_tls_ping(&ok(failed_handshake.as_bytes())),
        Some(TlsPing::HandshakeFailed)
    );
    let dial = exited(
        1,
        b"TLS ping:  www.example.com\nUsing IP:  127.0.0.1:443\n-------------------\nPinging without SNI\n",
        b"Failed to dial tcp: dial tcp 127.0.0.1:443: connect: connection refused\n",
    );
    assert_eq!(parse_tls_ping(&dial), Some(TlsPing::ConnectFailed));
}

/// Only Xray's own fatal exit (status 1) after a failed dial is a connect
/// failure: the same words under another status (a `timeout` that killed
/// it, a crash) are not read as one.
#[test]
fn a_dial_failure_is_only_xrays_own_fatal_exit() {
    let killed = exited(
        137,
        b"TLS ping:  www.example.com\n",
        b"Failed to dial tcp: dial tcp 127.0.0.1:443: i/o timeout\n",
    );
    assert_eq!(parse_tls_ping(&killed), None);
}

#[test]
fn tls_ping_output_of_another_shape_is_refused() {
    for bad in [
        // Another failure than a dial.
        exited(1, b"", b"invalid IP: 300.1.1.1\n"),
        // No SNI part at all.
        ok(b"TLS ping:  www.example.com\n"),
        // A version Xray does not offer.
        ok(PING_TLS13.replace("TLS 1.3", "TLS 1.1").as_bytes()),
        // A detail missing.
        ok(PING_TLS13
            .replace(
                "Certificate chain's total length:  4431 (certs count: 3)\n",
                "",
            )
            .as_bytes()),
        // A name that is not a certificate name.
        ok(PING_TLS13
            .replace("[www.example.com example.com]", "[www.exämple.com]")
            .as_bytes()),
        // Something else after the SNI line.
        ok(b"Pinging with SNI\nPanic\n"),
    ] {
        assert_eq!(parse_tls_ping(&bad), None, "{bad:?}");
    }
}

#[test]
fn getent_lines_give_the_set_of_addresses() {
    assert_eq!(
        parse_getent(
            b"198.51.100.7    STREAM www.example.com\n198.51.100.7    DGRAM  \n198.51.100.8    RAW    \n"
        ),
        Some(BTreeSet::from([
            Ipv4Addr::new(198, 51, 100, 7),
            Ipv4Addr::new(198, 51, 100, 8)
        ]))
    );
    assert_eq!(parse_getent(b"www.example.com STREAM\n"), None);
    assert_eq!(parse_getent(b"\xff\n"), None);
}

/// A node whose `timeout`-wrapped tools answer as `answer` says, by the
/// program `timeout` runs.
fn node_answering(answer: impl Fn(&str, &[&str]) -> crate::host::ToolOutput + 'static) -> FakeNode {
    FakeNode::answering(
        1000,
        Box::new(move |tool, args| {
            assert_eq!(tool, Tool::Timeout, "every target tool runs under timeout");
            assert_eq!(&args[..2], ["--kill-after=2", "10"]);
            Ok(answer(args[2], &args[3..]))
        }),
    )
}

#[test]
fn resolution_reads_getents_exit_status() {
    for (code, stdout, expected) in [
        (
            0,
            &b"198.51.100.7    STREAM www.example.com\n"[..],
            Ok(BTreeSet::from([Ipv4Addr::new(198, 51, 100, 7)])),
        ),
        (2, b"", Ok(BTreeSet::new())),
    ] {
        let node = node_answering(move |program, args| {
            assert_eq!(program, "/usr/bin/getent");
            assert_eq!(args, ["ahostsv4", "www.example.com"]);
            exited(code, stdout, b"")
        });
        assert_eq!(crate::target::resolve(&node, &host()), expected);
    }
    for (code, text) in [(124, "did not answer in time"), (1, "getent: broken")] {
        let node = node_answering(move |_, _| exited(code, b"", b"getent: broken\n"));
        let Err(AgentError::TargetFactsUnavailable { tool, stderr_tail }) =
            crate::target::resolve(&node, &host())
        else {
            panic!("{code}");
        };
        assert_eq!(tool, TargetTool::Resolver);
        assert!(stderr_tail.as_str().contains(text), "{code}");
    }
}

#[test]
fn curls_write_out_is_read_whether_or_not_a_response_came() {
    assert_eq!(
        parse_curl(b"200 2 "),
        Some(HttpProbe::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
            redirect: None,
        })
    );
    assert_eq!(
        parse_curl(b"301 1.1 https://www.example.com/en/"),
        Some(HttpProbe::Responded {
            status: HttpStatus::new(301).unwrap(),
            version: HttpVersion::Http11,
            redirect: Some(RedirectUrl::new("https://www.example.com/en/").unwrap()),
        })
    );
    assert_eq!(
        parse_curl(b"200 1 "),
        Some(HttpProbe::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http10,
            redirect: None,
        })
    );
    assert_eq!(
        parse_curl(b"200 3 ").map(|probe| match probe {
            HttpProbe::Responded { version, .. } => version,
            HttpProbe::Failed => HttpVersion::Http10,
        }),
        Some(HttpVersion::Http3)
    );
    assert_eq!(parse_curl(b"000 0 "), Some(HttpProbe::Failed));
    for bad in [&b"200 2"[..], b"200 4 ", b"700 2 ", b"abc 2 ", b""] {
        assert_eq!(parse_curl(bad), None, "{bad:?}");
    }
}

#[test]
fn curl_goes_to_the_resolved_address_and_a_timeout_is_no_answer() {
    let node = node_answering(|program, args| {
        assert_eq!(program, "/usr/bin/curl");
        assert_eq!(
            args,
            [
                "--http2",
                "-sS",
                "-o",
                "/dev/null",
                "--connect-timeout",
                "5",
                "--max-time",
                "8",
                "--resolve",
                "www.example.com:443:198.51.100.7",
                "-w",
                "%{http_code} %{http_version} %{redirect_url}",
                "https://www.example.com/",
            ]
        );
        exited(124, b"", b"")
    });
    assert_eq!(
        crate::target::http_probe(&node, &host(), Ipv4Addr::new(198, 51, 100, 7)),
        Ok(HttpProbe::Failed)
    );
    let garbled = node_answering(|_, _| exited(0, b"garbled", b""));
    assert!(matches!(
        crate::target::http_probe(&garbled, &host(), Ipv4Addr::new(198, 51, 100, 7)),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::Curl,
            ..
        })
    ));
}

#[test]
fn a_tls_ping_that_does_not_finish_is_unavailable() {
    let node = node_answering(|_, _| exited(124, b"TLS ping:  www.example.com\n", b""));
    assert!(matches!(
        crate::target::tls_ping(
            &node,
            std::path::Path::new("/opt/xray"),
            &host(),
            Ipv4Addr::LOCALHOST
        ),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::XrayTlsPing,
            ..
        })
    ));
}

/// A canned first flight: a ServerHello record, a ChangeCipherSpec and an
/// application-data record of `payload` bytes.
fn flight(payload: usize) -> Vec<u8> {
    let mut hello = vec![0x02, 0x00, 0x00, 0x46, 0x03, 0x03];
    hello.extend([0x42; 32]);
    hello.extend([0x00; 36]);
    let mut out = vec![0x16, 0x03, 0x03, 0x00, 0x4a];
    out.extend(hello);
    out.extend([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    out.extend([0x17, 0x03, 0x03]);
    out.extend(u16::try_from(payload).unwrap().to_be_bytes());
    out.extend(vec![0xaa; payload]);
    out
}

/// What a test server does on each connection.
#[derive(Clone)]
enum Server {
    /// Writes the first part, waits, writes the second, then keeps the
    /// connection open until the client closes it.
    Flight(Vec<u8>, Duration, Vec<u8>),
    /// Reads the hello and says nothing.
    Silent,
    /// Reads the hello and closes.
    Close,
}

/// A server on 127.0.0.1 that answers `connections` connections as `how`
/// says, after reading each whole hello and checking its SNI.
fn serve(how: Server, connections: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut header = [0; 5];
            stream.read_exact(&mut header).unwrap();
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            assert!(
                body.windows(15).any(|window| window == b"www.example.com"),
                "the hello names the target"
            );
            match &how {
                Server::Flight(first, gap, second) => {
                    stream.write_all(first).unwrap();
                    thread::sleep(*gap);
                    stream.write_all(second).unwrap();
                    // Wait for the client to give up, as a server waiting
                    // for its next flight would.
                    let _closed = stream.read(&mut [0; 1]);
                }
                Server::Silent => {
                    let _closed = stream.read(&mut [0; 1]);
                }
                Server::Close => {}
            }
        }
    });
    address
}

fn random() -> [u8; RANDOM_BYTES] {
    let mut bytes = [0; RANDOM_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap();
    }
    bytes
}

#[test]
fn the_hello_is_a_tls_record_with_its_random_session_and_key_share() {
    let hello = sampler::client_hello(&host(), &random());
    assert_eq!(&hello[..3], [0x16, 0x03, 0x01]);
    assert_eq!(
        usize::from(u16::from_be_bytes([hello[3], hello[4]])),
        hello.len() - 5
    );
    assert_eq!(hello[5], 0x01, "a ClientHello");
    let body_length =
        usize::from(hello[6]) << 16 | usize::from(hello[7]) << 8 | usize::from(hello[8]);
    assert_eq!(body_length, hello.len() - 9);
    assert_eq!(&hello[9..11], [0x03, 0x03]);
    assert_eq!(&hello[11..43], &random()[..32]);
    assert_eq!(hello[43], 32);
    assert_eq!(&hello[44..76], &random()[32..64]);
    // The X25519 share ends the hello.
    assert_eq!(&hello[hello.len() - 32..], &random()[64..]);
    assert_eq!(&hello[hello.len() - 36..hello.len() - 34], [0x00, 0x1d]);
    let find = |needle: &[u8]| hello.windows(needle.len()).any(|window| window == needle);
    assert!(find(b"\x00\x0fwww.example.com"), "SNI");
    assert!(find(b"\x02h2\x08http/1.1"), "ALPN");
    assert!(
        find(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]),
        "TLS 1.3 and 1.2"
    );
}

#[test]
fn only_a_server_hello_that_asks_for_nothing_more_starts_a_flight() {
    assert_eq!(sampler::check_server_hello(&flight(10)), Ok(()));
    let mut retry = flight(10);
    retry[11..43].copy_from_slice(&[
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ]);
    for (bad, text) in [
        (retry, "another hello"),
        (vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28], "alert"),
        (b"HTTP/1.1 400 Bad Request\r\n".to_vec(), "not TLS"),
        (
            vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x0b, 0x00, 0x00, 0x00],
            "not a ServerHello",
        ),
        (flight(10)[..20].to_vec(), "cut short"),
    ] {
        let error = sampler::check_server_hello(&bad).unwrap_err();
        assert!(error.contains(text), "{error}");
    }
}

#[test]
fn a_sample_times_the_flight_to_its_last_byte_and_counts_all_of_it() {
    let whole = flight(3000);
    let address = serve(
        Server::Flight(
            whole[..100].to_vec(),
            Duration::from_millis(40),
            whole[100..].to_vec(),
        ),
        1,
    );
    let sample = sampler::sample(address, &host(), &random()).unwrap();
    assert_eq!(usize::try_from(sample.bytes).unwrap(), whole.len());
    assert!(sample.micros >= 40_000, "{sample:?}");
    assert!(
        u128::from(sample.micros) < sampler::IDLE.as_micros(),
        "the quiet after the flight is not counted: {sample:?}"
    );
}

#[test]
fn a_target_that_does_not_answer_a_hello_is_no_sample() {
    let silent = serve(Server::Silent, 1);
    assert_eq!(
        sampler::sample(silent, &host(), &random()),
        Err("the target sent nothing back".to_owned())
    );
    let closing = serve(Server::Close, 1);
    assert_eq!(
        sampler::sample(closing, &host(), &random()),
        Err("the target closed without an answer".to_owned())
    );
    let gone = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let refused = sampler::sample(gone, &host(), &random()).unwrap_err();
    assert!(refused.starts_with("connect:"), "{refused}");
}

#[test]
fn the_p95_is_the_nearest_rank() {
    let mut twenty: Vec<u64> = (1..=20).rev().collect();
    assert_eq!(sampler::p95(&mut twenty), Some(19));
    assert_eq!(sampler::p95(&mut [7]), Some(7));
    assert_eq!(sampler::p95(&mut [3, 1]), Some(3));
    assert_eq!(sampler::p95(&mut []), None);
}

/// Stores `bytes` as a blob and returns its digest.
fn stored(paths: &Paths, bytes: &[u8]) -> Sha256Hex {
    let sha = digest_of(bytes).unwrap();
    put(
        paths,
        sha,
        BlobLen::new(u64::try_from(bytes.len()).unwrap()).unwrap(),
        &mut Cursor::new(bytes.to_vec()),
    )
    .unwrap();
    sha
}

/// A node for a whole check: the name resolves to `resolved`, the Xray
/// answers `ping`, and curl gets an HTTP/2 200.
fn check_node(resolved: &'static [u8], ping: &'static str) -> FakeNode {
    node_answering(move |program, args| match program {
        "/usr/bin/getent" => {
            if resolved.is_empty() {
                exited(2, b"", b"")
            } else {
                exited(0, resolved, b"")
            }
        }
        "/usr/bin/curl" => exited(0, b"200 2 ", b""),
        xray => {
            assert!(xray.ends_with("/xray"), "{xray}");
            assert_eq!(&args[..3], ["tls", "ping", "-ip"]);
            exited(0, ping.as_bytes(), b"")
        }
    })
}

#[test]
fn a_whole_check_installs_the_xray_and_measures_the_target() {
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let whole = flight(2000);
    let address = serve(
        Server::Flight(
            whole[..50].to_vec(),
            Duration::from_millis(1),
            whole[50..].to_vec(),
        ),
        usize::from(mooring_agent_proto::TARGET_HANDSHAKE_SAMPLES),
    );
    let node = check_node(b"127.0.0.1       STREAM www.example.com\n", PING_TLS13);
    let facts = crate::target::check_at(&paths, &node, host(), xray, address.port()).unwrap();
    let TlsProbe::Completed(session) = &facts.tls else {
        panic!("{facts:?}");
    };
    assert_eq!(
        usize::try_from(session.first_flight_bytes).unwrap(),
        whole.len()
    );
    assert!(session.handshake_p95_micros >= 1_000);
    assert_eq!(
        (
            session.version,
            session.group,
            session.chain_bytes,
            session.chain_certs
        ),
        (TlsVersion::Tls13, Some(TlsGroup::X25519_MLKEM768), 4431, 3)
    );
    assert_eq!(session.leaf_names, tls13().leaf_names);
    assert_eq!(facts.resolved, BTreeSet::from([Ipv4Addr::LOCALHOST]));
    assert_eq!(
        facts.http,
        HttpProbe::Responded {
            status: HttpStatus::new(200).unwrap(),
            version: HttpVersion::Http2,
            redirect: None,
        }
    );
    // The Xray went into the engine store, runnable.
    let installed = crate::txn::stage::store_path(&paths, crate::txn::stage::XRAY, &xray);
    assert_eq!(std::fs::read(&installed).unwrap(), b"#!xray");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    let calls = node.calls();
    assert!(
        calls[1].ends_with(&format!(
            "{} tls ping -ip 127.0.0.1 www.example.com",
            installed.display()
        )),
        "{calls:#?}"
    );
}

#[test]
fn a_name_without_an_address_is_reported_without_probing() {
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let node = check_node(b"", PING_TLS13);
    assert_eq!(
        crate::target::check(&paths, &node, host(), xray),
        Ok(TargetFacts {
            host: host(),
            resolved: BTreeSet::new(),
            tls: TlsProbe::ConnectFailed,
            http: HttpProbe::Failed,
        })
    );
    assert_eq!(node.calls().len(), 1, "only the resolver ran");
}

#[test]
fn a_check_needs_its_xray_stored() {
    let (_dir, paths) = scratch();
    let missing = Sha256Hex::from_bytes([3; 32]);
    let node = check_node(b"", PING_TLS13);
    assert_eq!(
        crate::target::check(&paths, &node, host(), missing),
        Err(AgentError::BlobMissing { sha256: missing })
    );
    assert!(node.calls().is_empty());
}

/// A node with generation 1 installed, configured for `www.example.com` at
/// 198.51.100.7.
fn configured() -> (tempfile::TempDir, Paths) {
    let (dir, paths) = scratch();
    let generation = paths.generation(Generation::new(1));
    std::fs::create_dir_all(&generation).unwrap();
    write_json(
        &generation.join("watch.json"),
        &WatchConfig {
            keepalive_secs: NonZeroU16::new(10).unwrap(),
            target: target(),
            emails: BTreeSet::new(),
        },
        0o640,
    )
    .unwrap();
    std::os::unix::fs::symlink("gen-1", paths.current()).unwrap();
    (dir, paths)
}

fn target() -> WatchTarget {
    WatchTarget {
        host: host(),
        ipv4: Ipv4Addr::new(198, 51, 100, 7),
    }
}

/// The hourly check with the name resolving to `resolved`, the ping
/// printing `ping` and curl printing `curl`; returns its reading and the
/// tools it ran.
fn hourly(resolved: &'static [u8], ping: &'static str, curl: &'static [u8]) -> (bool, Vec<String>) {
    let (_dir, paths) = configured();
    let node = node_answering(move |program, _| match program {
        "/usr/bin/getent" => exited(0, resolved, b""),
        "/usr/bin/curl" => exited(0, curl, b""),
        _ => exited(0, ping.as_bytes(), b""),
    });
    let reading = crate::target::watch(&paths, &node).unwrap();
    assert_eq!(
        read_json(&paths.target_reading()).unwrap(),
        Some(reading.clone())
    );
    assert_eq!(reading.target, target());
    assert_eq!(reading.at, UnixTime::from_secs(1000));
    (reading.degraded, node.calls())
}

const AT_TARGET: &[u8] = b"198.51.100.7    STREAM www.example.com\n";

#[test]
fn the_hourly_check_passes_a_target_that_still_answers() {
    let (degraded, calls) = hourly(AT_TARGET, PING_TLS13, b"200 2 ");
    assert!(!degraded);
    assert!(
        calls[1].contains(
            "/etc/mooring/current/engines/xray tls ping -ip 198.51.100.7 www.example.com"
        ),
        "{calls:#?}"
    );
}

#[test]
fn the_hourly_check_degrades_a_target_that_moved_or_stopped_answering() {
    let (moved, calls) = hourly(
        b"198.51.100.8    STREAM www.example.com\n",
        PING_TLS13,
        b"200 2 ",
    );
    assert!(moved);
    assert_eq!(calls.len(), 1, "nothing is probed at another address");
    let failed_handshake = "Pinging with SNI\nHandshake failure:  EOF\n";
    assert!(hourly(AT_TARGET, failed_handshake, b"200 2 ").0);
    assert!(hourly(AT_TARGET, PING_TLS13, b"200 1.1 ").0, "not HTTP/2");
    assert!(hourly(AT_TARGET, PING_TLS13, b"000 0 ").0, "no answer");
}

#[test]
fn the_hourly_check_degrades_a_target_it_cannot_resolve() {
    let (_dir, paths) = configured();
    let node = node_answering(|_, _| exited(124, b"", b""));
    assert!(crate::target::watch(&paths, &node).unwrap().degraded);
    assert_eq!(node.calls().len(), 1);
}

#[test]
fn target_check_is_served_to_ops_alone() {
    use super::serve::{ask, frame};
    use mooring_agent_proto::{LineRequest, RequestKind, Response, Role};
    let (_dir, paths) = scratch();
    let xray = stored(&paths, b"#!xray");
    let node = check_node(b"", PING_TLS13);
    let request = LineRequest::TargetCheck { host: host(), xray };
    assert_eq!(
        ask(&paths, &node, Role::Ops, frame(&request)),
        Ok(Response::TargetFacts(Box::new(TargetFacts {
            host: host(),
            resolved: BTreeSet::new(),
            tls: TlsProbe::ConnectFailed,
            http: HttpProbe::Failed,
        })))
    );
    assert_eq!(
        ask(&paths, &node, Role::Viewer, frame(&request)),
        Err(AgentError::RoleNotPermitted {
            role: Role::Viewer,
            request: RequestKind::TargetCheck,
        })
    );
}

#[test]
fn a_reading_is_the_state_groups_to_read() {
    let (_dir, paths) = configured();
    let node = node_answering(|_, _| exited(124, b"", b""));
    crate::target::watch(&paths, &node).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(paths.target_reading())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    let _: TargetReading = read_json(&paths.target_reading()).unwrap().unwrap();
}
