// SPDX-License-Identifier: GPL-3.0-or-later

//! The stand-ins the target tests share: the target's name, a node whose
//! tools answer as a test says (each under `timeout`, as every target
//! tool runs), a completed TLS 1.3 ping as Xray prints it and as it is
//! read, and servers on 127.0.0.1 that answer a ClientHello with a canned
//! first flight, silence, a close or a reset.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use mooring_agent_proto::{CertName, TargetHost, TlsGroup, TlsVersion};

use crate::host::Tool;
use crate::target::probes::TlsDetails;
use crate::tests::FakeNode;

pub(super) fn host() -> TargetHost {
    TargetHost::new("www.example.com").unwrap()
}

/// `xray tls ping` for a TLS 1.3 target, as the pinned source prints it:
/// the part without SNI first, then the details a tabwriter aligned.
pub(super) const PING_TLS13: &str = "TLS ping:  www.example.com\n\
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

pub(super) fn tls13() -> TlsDetails {
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

/// A node whose `timeout`-wrapped tools answer as `answer` says, by the
/// program `timeout` runs.
pub(super) fn node_answering(
    answer: impl Fn(&str, &[&str]) -> crate::host::ToolOutput + 'static,
) -> FakeNode {
    FakeNode::answering(
        1000,
        Box::new(move |tool, args| {
            assert_eq!(tool, Tool::Timeout, "every target tool runs under timeout");
            assert_eq!(&args[..2], ["--kill-after=2", "10"]);
            Ok(answer(args[2], &args[3..]))
        }),
    )
}

/// A canned first flight: a ServerHello record, a ChangeCipherSpec and an
/// application-data record of `payload` bytes.
pub(super) fn flight(payload: usize) -> Vec<u8> {
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
pub(super) enum Server {
    /// Writes the first part, waits, writes the second, then keeps the
    /// connection open until the client closes it.
    Flight(Vec<u8>, Duration, Vec<u8>),
    /// Reads the hello and says nothing.
    Silent,
    /// Reads the hello and closes.
    Close,
    /// Reads the hello's record header alone and closes, which, with the
    /// rest unread, resets the connection.
    Reset,
}

/// A server on 127.0.0.1 that answers `connections` connections as `how`
/// says, after reading each whole hello and checking its SNI.
pub(super) fn serve(how: Server, connections: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut header = [0; 5];
            stream.read_exact(&mut header).unwrap();
            if let Server::Reset = how {
                continue;
            }
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
                Server::Close | Server::Reset => {}
            }
        }
    });
    address
}
