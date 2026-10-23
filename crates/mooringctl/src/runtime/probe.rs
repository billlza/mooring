// SPDX-License-Identifier: GPL-3.0-or-later

//! The direct probe (design §10.2): a TCP connection bound to the egress
//! interface (`IP_BOUND_IF`) to a node's reflector, which answers with the
//! address it saw, one line `<IPv4>\n`, within 5 s. That address is the
//! carrier's public address as the internet sees the line.

use std::io::{ErrorKind, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use mooring_daemon_core::status::ProbeStage;
use mooring_model::iface::InterfaceIndex;
use socket2::{Domain, Protocol, Socket, Type};

/// The longest the whole probe may take.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The most bytes read for the reflector's line: an IPv4 address and its
/// newline fit in 16.
const MAX_LINE_BYTES: usize = 64;

/// A failed probe: where it failed, with the operating system's error
/// kind when there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProbeFailure {
    pub(crate) stage: ProbeStage,
    pub(crate) kind: Option<ErrorKind>,
}

/// Probes `reflector` through the interface `index`.
pub(crate) fn direct(
    index: InterfaceIndex,
    reflector: SocketAddrV4,
) -> Result<Ipv4Addr, ProbeFailure> {
    let started = Instant::now();
    let failed = |stage| {
        move |error: std::io::Error| ProbeFailure {
            stage,
            kind: Some(error.kind()),
        }
    };
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(failed(ProbeStage::Connect))?;
    socket
        .bind_device_by_index_v4(Some(NonZeroU32::from(index)))
        .map_err(failed(ProbeStage::Connect))?;
    socket
        .connect_timeout(&SocketAddr::V4(reflector).into(), PROBE_TIMEOUT)
        .map_err(failed(ProbeStage::Connect))?;
    let mut stream: TcpStream = socket.into();
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let left = PROBE_TIMEOUT.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(ProbeFailure {
                stage: ProbeStage::Read,
                kind: Some(ErrorKind::TimedOut),
            });
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(failed(ProbeStage::Read))?;
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(ProbeFailure {
                    stage: ProbeStage::Read,
                    kind: Some(ErrorKind::UnexpectedEof),
                });
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > MAX_LINE_BYTES {
                    return Err(ProbeFailure {
                        stage: ProbeStage::Parse,
                        kind: None,
                    });
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(failed(ProbeStage::Read)(error)),
        }
    }
    std::str::from_utf8(&line)
        .ok()
        .and_then(|text| text.parse::<Ipv4Addr>().ok())
        .ok_or(ProbeFailure {
            stage: ProbeStage::Parse,
            kind: None,
        })
}
