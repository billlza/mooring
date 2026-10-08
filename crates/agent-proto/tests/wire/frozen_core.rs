// SPDX-License-Identifier: GPL-3.0-or-later

//! The frozen upgrade core (design §11.1): `Hello`, `HaveBlobs`, `PutBlob`,
//! `ActivateAgent` and `Confirm`, and their replies, never change across
//! protocol versions. Each frame is pinned byte for byte by a golden file in
//! `contract/agent-proto-golden/`.
//!
//! A snapshot holds the line without its terminator (insta trims trailing
//! whitespace); `assert_golden` separately requires that the frame is that
//! line plus exactly one `\n`, and that the line has no other whitespace at
//! its edges and no line breaks, so the comparison is exact.
//!
//! The values are spelled out here rather than taken from shared fixtures,
//! so editing a fixture cannot move a golden.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::path::Path;

use mooring_agent_proto::{
    AcceptLocal, Arch, BlobLen, EgressViolationHold, Generation, Halt, HelloInfo, Holds, HostFacts,
    HostProfileVersion, IfName, KernelIdent, KernelRelease, LineRequest, MacDrainHold, PortRange,
    Reply, Request, RequestKind, Response, Sha256Hex, ShutdownReason, SshdDirective, UnixTime,
    read_blob, read_reply, read_request, write_put_blob, write_reply, write_request,
};

fn digest(text: &str) -> Sha256Hex {
    text.parse().unwrap()
}

const AGENT_SHA: &str = "5f0e7c0b3a1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f";
const XRAY_SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn assert_golden(name: &str, frame: &[u8]) {
    let frame = std::str::from_utf8(frame).unwrap();
    let line = frame
        .strip_suffix('\n')
        .expect("a frame ends with a newline");
    assert!(!line.contains(['\n', '\r']), "{name}: one line");
    assert_eq!(line.trim(), line, "{name}: no edge whitespace");
    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path("../../../../contract/agent-proto-golden");
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.set_description(
        "SPDX-License-Identifier: GPL-3.0-or-later. Frozen upgrade core (design 11.1): this line, plus one newline, must never change.",
    );
    settings.bind(|| insta::assert_snapshot!(name, line));
}

fn request_frame(request: &LineRequest) -> Vec<u8> {
    let mut frame = Vec::new();
    write_request(&mut frame, request).unwrap();
    assert_eq!(
        read_request(&mut Cursor::new(frame.as_slice())).unwrap(),
        Request::Line(request.clone())
    );
    frame
}

fn reply_frame(reply: &Reply) -> Vec<u8> {
    let mut frame = Vec::new();
    write_reply(&mut frame, reply).unwrap();
    assert_eq!(
        read_reply(&mut Cursor::new(frame.as_slice())).unwrap(),
        *reply
    );
    frame
}

fn hello_request() -> Vec<u8> {
    request_frame(&LineRequest::Hello)
}

fn hello_response() -> Vec<u8> {
    let info = HelloInfo {
        protocol: 1,
        agent_sha: digest(AGENT_SHA),
        host_profile_version: HostProfileVersion::new(1),
        host: HostFacts {
            uplink: IfName::new("eth0").unwrap(),
            vps4: Ipv4Addr::new(203, 0, 113, 10),
            arch: Arch::Amd64,
            ip_local_port_range: PortRange::new(32768, 60999).unwrap(),
            debian_major: 13,
            kernel: KernelRelease::new("6.12.48+deb13-amd64").unwrap(),
            congestion_control: KernelIdent::new("bbr").unwrap(),
            qdisc: KernelIdent::new("fq").unwrap(),
        },
        wgexit_accept_local: AcceptLocal::Enabled,
        sshd_mismatches: BTreeSet::from([SshdDirective::MaxAuthTries]),
        halted: Some(Halt {
            at: UnixTime::from_secs(1_791_000_000),
            reason: ShutdownReason::Operator,
        }),
        holds: Holds {
            mac_drain: Some(MacDrainHold {
                handshake_at_drain: None,
            }),
            egress_violation: Some(EgressViolationHold {
                at: UnixTime::from_secs(1_791_000_100),
                generation: Generation::new(41),
            }),
            operator: None,
        },
        client_ip: Ipv4Addr::new(198, 51, 100, 20),
    };
    reply_frame(&Ok(Response::Hello(Box::new(info))))
}

fn have_blobs_request() -> Vec<u8> {
    let request = LineRequest::HaveBlobs {
        blobs: BTreeSet::from([digest(XRAY_SHA), digest(AGENT_SHA)]),
    };
    request_frame(&request)
}

fn have_blobs_response() -> Vec<u8> {
    let reply = Ok(Response::Blobs {
        present: BTreeSet::from([digest(XRAY_SHA)]),
    });
    reply_frame(&reply)
}

fn put_blob_request() -> Vec<u8> {
    let payload = b"agent binary bytes\n";
    let mut frame = Vec::new();
    write_put_blob(&mut frame, digest(AGENT_SHA), payload).unwrap();
    let header_len = frame.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let (header, rest) = frame.split_at(header_len);
    assert_eq!(
        rest, payload,
        "the payload follows the header line verbatim"
    );

    let mut reader = Cursor::new(frame.as_slice());
    let request = read_request(&mut reader).unwrap();
    assert_eq!(
        request,
        Request::PutBlob {
            sha256: digest(AGENT_SHA),
            len: BlobLen::new(19).unwrap(),
        }
    );
    let mut received = Vec::new();
    read_blob(&mut reader, BlobLen::new(19).unwrap(), &mut received).unwrap();
    assert_eq!(received, payload);
    header.to_vec()
}

fn put_blob_response() -> Vec<u8> {
    let reply = Ok(Response::BlobStored {
        sha256: digest(AGENT_SHA),
    });
    reply_frame(&reply)
}

fn activate_agent_request() -> Vec<u8> {
    let request = LineRequest::ActivateAgent {
        sha: digest(AGENT_SHA),
    };
    request_frame(&request)
}

fn activate_agent_response() -> Vec<u8> {
    let reply = Ok(Response::AwaitingConfirm {
        generation: Generation::new(41),
    });
    reply_frame(&reply)
}

fn confirm_request() -> Vec<u8> {
    let request = LineRequest::Confirm {
        generation: Generation::new(41),
    };
    request_frame(&request)
}

fn confirm_response() -> Vec<u8> {
    let reply = Ok(Response::Confirmed {
        generation: Generation::new(41),
    });
    reply_frame(&reply)
}

/// Which frame of a frozen exchange a golden pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Frame {
    Request,
    Response,
}

/// Builds one frame, checking that it reads back.
type BuildFrame = fn() -> Vec<u8>;

/// Every frozen-core golden: the exchange, the frame, and the function
/// that builds the frame.
const GOLDENS: [(RequestKind, Frame, BuildFrame); 10] = [
    (RequestKind::Hello, Frame::Request, hello_request),
    (RequestKind::Hello, Frame::Response, hello_response),
    (RequestKind::HaveBlobs, Frame::Request, have_blobs_request),
    (RequestKind::HaveBlobs, Frame::Response, have_blobs_response),
    (RequestKind::PutBlob, Frame::Request, put_blob_request),
    (RequestKind::PutBlob, Frame::Response, put_blob_response),
    (
        RequestKind::ActivateAgent,
        Frame::Request,
        activate_agent_request,
    ),
    (
        RequestKind::ActivateAgent,
        Frame::Response,
        activate_agent_response,
    ),
    (RequestKind::Confirm, Frame::Request, confirm_request),
    (RequestKind::Confirm, Frame::Response, confirm_response),
];

/// The snapshot name of a golden: the request kind in snake case, then
/// `.request` or `.response`.
fn golden_name(kind: RequestKind, frame: Frame) -> String {
    let mut name = String::new();
    for (index, letter) in format!("{kind:?}").chars().enumerate() {
        if letter.is_ascii_uppercase() && index > 0 {
            name.push('_');
        }
        name.push(letter.to_ascii_lowercase());
    }
    match frame {
        Frame::Request => name + ".request",
        Frame::Response => name + ".response",
    }
}

#[test]
fn frozen_core_frames_match_their_goldens() {
    for (kind, frame, build) in GOLDENS {
        assert_golden(&golden_name(kind, frame), &build());
    }
}

/// Every frozen exchange has its request and its response golden, and
/// `contract/agent-proto-golden/` holds exactly those files, so a golden
/// left behind for a frame that is no longer asserted fails here (design
/// §16 L2, "a stale golden").
#[test]
fn the_golden_directory_holds_exactly_the_frozen_core_frames() {
    let pinned: BTreeSet<_> = GOLDENS
        .iter()
        .map(|(kind, frame, _)| (*kind, *frame))
        .collect();
    let frozen: BTreeSet<_> = RequestKind::ALL
        .iter()
        .filter(|kind| kind.is_frozen_core())
        .flat_map(|kind| [(*kind, Frame::Request), (*kind, Frame::Response)])
        .collect();
    assert_eq!(pinned, frozen);

    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contract/agent-proto-golden");
    let found: BTreeSet<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let expected: BTreeSet<String> = GOLDENS
        .iter()
        .map(|(kind, frame, _)| format!("{}.snap", golden_name(*kind, *frame)))
        .collect();
    assert_eq!(found, expected);
}

#[test]
fn exactly_five_requests_are_frozen() {
    let frozen: Vec<_> = RequestKind::ALL
        .iter()
        .copied()
        .filter(|kind| kind.is_frozen_core())
        .collect();
    assert_eq!(
        frozen,
        [
            RequestKind::Hello,
            RequestKind::HaveBlobs,
            RequestKind::PutBlob,
            RequestKind::ActivateAgent,
            RequestKind::Confirm
        ]
    );
}
