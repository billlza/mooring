// SPDX-License-Identifier: GPL-3.0-or-later

//! The tools the check runs (design §11.7), against a stand-in node:
//! `xray tls ping`'s output read as the pinned source prints it (its SNI
//! part only, any other shape refused), `getent ahostsv4`'s lines and exit
//! status, and curl's write-out whether or not a response came, with curl
//! sent to the address it is given. A tool that cannot start or prints
//! nothing known of, and a `getent` or `xray tls ping` that `timeout` ends,
//! are reported as the error the Mac reads; a curl that it ends, as no
//! answer.

use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, HttpProbe, HttpStatus, HttpVersion, IoOp, RedirectUrl, StderrTail, TargetTool,
    TlsGroup, TlsVersion,
};

use super::world::{PING_TLS13, host, node_answering, tls13};
use crate::target::probes::{TlsDetails, TlsPing, parse_curl, parse_getent, parse_tls_ping};
use crate::tests::{ENOENT, FakeNode, exited, ok};

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
        assert_eq!(crate::target::probes::resolve(&node, &host()), expected);
    }
    for (code, text) in [(124, "did not answer in time"), (1, "getent: broken")] {
        let node = node_answering(move |_, _| exited(code, b"", b"getent: broken\n"));
        let Err(AgentError::TargetFactsUnavailable { tool, stderr_tail }) =
            crate::target::probes::resolve(&node, &host())
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
        crate::target::probes::http_probe(&node, &host(), Ipv4Addr::new(198, 51, 100, 7)),
        Ok(HttpProbe::Failed)
    );
    let garbled = node_answering(|_, _| exited(0, b"garbled", b""));
    assert!(matches!(
        crate::target::probes::http_probe(&garbled, &host(), Ipv4Addr::new(198, 51, 100, 7)),
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
        crate::target::probes::tls_ping(
            &node,
            Path::new("/opt/xray"),
            &host(),
            Ipv4Addr::LOCALHOST
        ),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::XrayTlsPing,
            ..
        })
    ));
}

#[test]
fn a_tool_the_check_cannot_start_is_a_spawn_failure() {
    let unstartable = FakeNode::answering(
        1000,
        Box::new(|_, _| Err(io::Error::from_raw_os_error(ENOENT))),
    );
    let spawn = AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: Some(ENOENT),
    };
    let address = Ipv4Addr::new(198, 51, 100, 7);
    assert_eq!(
        crate::target::probes::resolve(&unstartable, &host()).unwrap_err(),
        spawn
    );
    assert_eq!(
        crate::target::probes::tls_ping(&unstartable, Path::new("/opt/xray"), &host(), address)
            .unwrap_err(),
        spawn
    );
    assert_eq!(
        crate::target::probes::http_probe(&unstartable, &host(), address).unwrap_err(),
        spawn
    );
    for call in unstartable.calls() {
        assert!(
            call.starts_with("/usr/bin/timeout --kill-after=2 10 "),
            "{call}"
        );
    }
}

#[test]
fn a_resolver_that_prints_no_address_is_unavailable() {
    let node = node_answering(|_, _| exited(0, b"www.example.com STREAM\n", b""));
    assert_eq!(
        crate::target::probes::resolve(&node, &host()),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::Resolver,
            stderr_tail: StderrTail::scrubbed(b"www.example.com STREAM\n", &[]),
        })
    );
}

#[test]
fn a_ping_xray_prints_nothing_known_of_is_unavailable_with_both_streams() {
    let node = node_answering(|_, _| {
        exited(
            0,
            b"TLS ping:  www.example.com\n",
            b"panic: runtime error\n",
        )
    });
    assert_eq!(
        crate::target::probes::tls_ping(
            &node,
            Path::new("/opt/xray"),
            &host(),
            Ipv4Addr::LOCALHOST
        ),
        Err(AgentError::TargetFactsUnavailable {
            tool: TargetTool::XrayTlsPing,
            stderr_tail: StderrTail::scrubbed(
                b"TLS ping:  www.example.com\npanic: runtime error\n",
                &[]
            ),
        })
    );
}
