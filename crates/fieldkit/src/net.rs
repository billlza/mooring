// SPDX-License-Identifier: GPL-3.0-or-later

//! Sockets bound to one interface, so every probe leaves through the M7
//! (design §22 M2b: the Mac joins no other network's path while a test
//! runs), and the small pieces every probe shares: nonces, the echo
//! exchange, timed connects and line reads.

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mooring_model::UnixTime;
use socket2::{Domain, Protocol, Socket, Type};

use crate::error::FieldkitError;
use crate::wire::{EchoAnswer, EchoKind, EchoRequest};

/// The interface every probe socket is bound to.
#[derive(Debug, Clone)]
pub(crate) struct Bind {
    name: String,
    #[cfg(target_os = "macos")]
    index: std::num::NonZeroU32,
}

impl Bind {
    /// Binds to the interface named `name` (`en9`), which must exist.
    #[cfg(target_os = "macos")]
    pub(crate) fn interface(name: &str) -> Result<Self, FieldkitError> {
        let index =
            mooring_macsys::interface_index(name).map_err(|error| FieldkitError::Interface {
                name: name.to_owned(),
                reason: error.to_string(),
            })?;
        Ok(Self {
            name: name.to_owned(),
            index,
        })
    }

    /// Binds to the interface named `name` (`eth0`), which `SO_BINDTODEVICE`
    /// checks when the first socket is bound.
    #[cfg(target_os = "linux")]
    pub(crate) fn interface(name: &str) -> Result<Self, FieldkitError> {
        if name.is_empty() || name.len() > 15 || name.contains('\0') {
            return Err(FieldkitError::Interface {
                name: name.to_owned(),
                reason: "not an interface name".to_owned(),
            });
        }
        Ok(Self {
            name: name.to_owned(),
        })
    }

    /// The interface's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The interface's index (macOS).
    #[cfg(target_os = "macos")]
    pub(crate) const fn index(&self) -> std::num::NonZeroU32 {
        self.index
    }

    fn socket(&self, kind: Type, protocol: Protocol) -> Result<Socket, FieldkitError> {
        let socket = Socket::new(Domain::IPV4, kind, Some(protocol))
            .map_err(|source| FieldkitError::socket("create", source))?;
        #[cfg(target_os = "macos")]
        let bound = socket.bind_device_by_index_v4(Some(self.index));
        #[cfg(target_os = "linux")]
        let bound = socket.bind_device(Some(self.name.as_bytes()));
        bound.map_err(|source| FieldkitError::socket("bind to the interface", source))?;
        Ok(socket)
    }

    /// A UDP socket on the interface with an ephemeral port.
    pub(crate) fn udp(&self) -> Result<UdpSocket, FieldkitError> {
        let socket = self.socket(Type::DGRAM, Protocol::UDP)?;
        socket
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .map_err(|source| FieldkitError::socket("bind a UDP port", source))?;
        Ok(socket.into())
    }

    /// A TCP connection from the interface to `peer`, within `timeout`.
    ///
    /// A peer that answers and closes at once, as the reflector does, can
    /// hang up before `connect_timeout`'s poll looks, and socket2 then
    /// reports the hang-up with no error set (`ErrorKind::Other`, "no error
    /// set after POLLHUP", socket2 0.6.5 `sys/unix.rs`) although the
    /// connection was made and the answer waits to be read: about 1 connect
    /// in 170 on loopback on this Mac. A socket that has a peer is
    /// connected, so that report, and only it, is the connection it is, as
    /// in `mooringctl`'s probe (`runtime/probe.rs`).
    pub(crate) fn connect(
        &self,
        peer: SocketAddrV4,
        timeout: Duration,
    ) -> Result<TcpStream, Connect> {
        let socket = self
            .socket(Type::STREAM, Protocol::TCP)
            .map_err(Connect::Setup)?;
        match socket.connect_timeout(&SocketAddr::V4(peer).into(), timeout) {
            Err(error)
                if error.kind() == io::ErrorKind::Other
                    && error.raw_os_error().is_none()
                    && socket.peer_addr().is_ok() => {}
            connected => connected.map_err(Connect::Failed)?,
        }
        Ok(socket.into())
    }
}

/// Why a connection was not made: the socket could not be set up (the
/// tool's failure), or the connect itself failed (what is measured).
#[derive(Debug)]
pub(crate) enum Connect {
    /// The socket could not be made or bound.
    Setup(FieldkitError),
    /// The connect failed or timed out.
    Failed(io::Error),
}

/// Unique nonces for one run: the process id and a counter. They only
/// pair answers with requests, so they need not be unpredictable.
#[derive(Debug)]
pub(crate) struct Nonces {
    process: u32,
    counter: AtomicU64,
}

impl Nonces {
    /// Nonces for this process.
    pub(crate) fn new() -> Self {
        Self {
            process: std::process::id(),
            counter: AtomicU64::new(0),
        }
    }

    /// The next nonce.
    pub(crate) fn next(&self) -> [u8; 16] {
        let mut nonce = [0_u8; 16];
        nonce[..4].copy_from_slice(&self.process.to_be_bytes());
        nonce[4..12].copy_from_slice(&self.counter.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        nonce
    }
}

/// Sends `request` to `server` from `socket` `copies` times, `spacing`
/// apart, and waits until `deadline` for the answer with its nonce from
/// `answer_from` (the server's address the answer must come from). Other
/// datagrams (late answers to earlier requests, or anything from another
/// address) are not this answer and are passed over. `None` if none came.
pub(crate) fn exchange(
    socket: &UdpSocket,
    server: SocketAddrV4,
    answer_from: SocketAddrV4,
    request: &EchoRequest,
    copies: u8,
    spacing: Duration,
    deadline: Instant,
) -> Result<Option<(EchoAnswer, Duration)>, FieldkitError> {
    let bytes = request.encode();
    let sent = Instant::now();
    let mut next_copy = sent;
    let mut remaining = copies.max(1);
    let mut buffer = [0_u8; 64];
    loop {
        let now = Instant::now();
        if remaining > 0 && now >= next_copy {
            socket
                .send_to(&bytes, SocketAddr::V4(server))
                .map_err(|source| FieldkitError::peer(server, "send an echo request", source))?;
            remaining -= 1;
            next_copy = now + spacing;
        }
        if now >= deadline {
            return Ok(None);
        }
        let wake = if remaining > 0 {
            next_copy.min(deadline)
        } else {
            deadline
        };
        let wait = wake
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));
        socket
            .set_read_timeout(Some(wait))
            .map_err(|source| FieldkitError::socket("set a read timeout", source))?;
        match socket.recv_from(&mut buffer) {
            Ok((len, SocketAddr::V4(from))) if from == answer_from => {
                let answer = EchoAnswer::decode(&buffer[..len])
                    .map_err(|source| FieldkitError::Protocol { peer: from, source })?;
                if answer.nonce == request.nonce {
                    return Ok(Some((answer, sent.elapsed())));
                }
            }
            Ok(_) => {}
            Err(error) if timed_out(&error) => {}
            Err(source) => {
                return Err(FieldkitError::peer(
                    server,
                    "receive an echo answer",
                    source,
                ));
            }
        }
    }
}

/// One immediate echo, as a reachability check: three copies a second
/// apart, five seconds in all. `Silent` if none is answered.
pub(crate) fn echo_now(
    socket: &UdpSocket,
    server: SocketAddrV4,
    nonces: &Nonces,
) -> Result<(EchoAnswer, Duration), FieldkitError> {
    let request = EchoRequest {
        kind: EchoKind::Now,
        nonce: nonces.next(),
    };
    exchange(
        socket,
        server,
        server,
        &request,
        3,
        Duration::from_secs(1),
        Instant::now() + Duration::from_secs(5),
    )?
    .ok_or(FieldkitError::Silent { peer: server })
}

/// Whether an I/O error is a read or write timeout.
pub(crate) fn timed_out(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Reads one line of at most `max` bytes, `\n` included, from `stream`
/// within its read timeout; `None` when the peer closes first.
pub(crate) fn read_line(stream: &mut impl Read, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while line.len() < max {
        if stream.read(&mut byte)? == 0 {
            return Ok(None);
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(Some(line));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "the line is too long",
    ))
}

/// The time now, in whole seconds since 1970.
pub(crate) fn now_unix() -> Result<UnixTime, FieldkitError> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FieldkitError::Clock)?;
    Ok(UnixTime::from_secs(since.as_secs()))
}

/// A network failure a measurement records as data (a connect that timed
/// out, a reset), as opposed to the tool's own failure, which stops it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Failure {
    /// What failed, from the I/O error.
    pub(crate) reason: String,
}

impl Failure {
    pub(crate) fn of(what: &str, error: &io::Error) -> Self {
        Self {
            reason: format!("{what}: {error}"),
        }
    }
}

/// Asks the reflector at `reflector` for the source it sees, within
/// `timeout` for the connect and again for the line.
pub(crate) fn ask_reflector(
    bind: &Bind,
    reflector: SocketAddrV4,
    timeout: Duration,
) -> Result<Result<SocketAddrV4, Failure>, FieldkitError> {
    let mut stream = match bind.connect(reflector, timeout) {
        Ok(stream) => stream,
        Err(Connect::Setup(error)) => return Err(error),
        Err(Connect::Failed(error)) => return Ok(Err(Failure::of("connect", &error))),
    };
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|source| FieldkitError::socket("set a read timeout", source))?;
    let line = match read_line(&mut stream, crate::wire::MAX_LINE) {
        Ok(Some(line)) => line,
        Ok(None) => {
            let closed = io::Error::new(io::ErrorKind::UnexpectedEof, "closed before its line");
            return Ok(Err(Failure::of("read", &closed)));
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return Err(FieldkitError::Protocol {
                peer: reflector,
                source: crate::wire::WireError::Line,
            });
        }
        Err(error) => return Ok(Err(Failure::of("read", &error))),
    };
    crate::wire::parse_reflector_line(&line)
        .map(Ok)
        .map_err(|source| FieldkitError::Protocol {
            peer: reflector,
            source,
        })
}
