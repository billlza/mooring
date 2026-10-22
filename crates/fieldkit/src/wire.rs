// SPDX-License-Identifier: GPL-3.0-or-later

//! What the probes and the servers say to each other. Every message is
//! fixed in form and bounded in size, and anything else is refused.
//!
//! - **UDP echo** (ports A and B, 27950 and 27951 by default): a 32-byte
//!   request and a 32-byte answer, so the server never sends more than it
//!   received. The answer carries the source address the server saw, which
//!   is the probe's public mapping.
//! - **TCP reflector** (27900): on accept the server writes one line,
//!   `MFK1 <ipv4>:<port>\n`, the source it saw, and closes.
//! - **TCP port-ceiling target** (27960): on accept the server writes one
//!   byte, [`CEILING_ACK`], and holds the connection until the probe closes
//!   it, so the probe can tell a connection the server holds from one only
//!   the kernel's backlog took.
//! - **TCP sink** (27970): the probe writes the line `MFK1 SINK <seconds>\n`
//!   and then data; the server counts what arrives in each whole second
//!   after the line, for `seconds` seconds, then answers one line of JSON,
//!   [`SinkReport`], at once, while the probe may still be sending, and
//!   drains the rest. The probe stops sending when the report arrives, so
//!   the line stays saturated for the whole window.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The first four bytes of every datagram, and the first word of every
/// line.
pub(crate) const MAGIC: [u8; 4] = *b"MFK1";

/// The length of every echo datagram, request or answer.
pub(crate) const DATAGRAM_LEN: usize = 32;

/// The longest delay a [`EchoKind::Delayed`] request may ask for, in
/// milliseconds (ten minutes).
const MAX_DELAY_MILLIS: u32 = 600_000;

/// The byte the port-ceiling target writes for each connection it holds.
pub(crate) const CEILING_ACK: u8 = b'+';

/// The longest sink measurement, in seconds.
pub(crate) const MAX_SINK_SECONDS: u16 = 120;

/// The longest reflector line, `MFK1 255.255.255.255:65535\n` with room.
pub(crate) const MAX_LINE: usize = 64;

/// The longest sink report: one count per second.
pub(crate) const MAX_REPORT: usize = 64 + 24 * MAX_SINK_SECONDS as usize;

/// What an echo request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EchoKind {
    /// An answer now, from the port that received the request.
    Now,
    /// An answer after a delay, from the port that received the request:
    /// whether the probe's mapping outlives that idle time.
    Delayed(Delay),
    /// An answer now, from the server's other echo port: whether the
    /// probe's NAT lets in a port the probe has not sent to.
    FromOtherPort,
}

/// The delay of an [`EchoKind::Delayed`] request: 1 ms to ten minutes,
/// whole milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Delay(u32);

impl Delay {
    /// Accepts 1 ms to ten minutes; sub-millisecond parts are dropped.
    pub(crate) fn new(delay: Duration) -> Result<Self, WireError> {
        match u32::try_from(delay.as_millis()) {
            Ok(millis) => Self::from_millis(millis),
            Err(_) => Err(WireError::Delay),
        }
    }

    fn from_millis(millis: u32) -> Result<Self, WireError> {
        if (1..=MAX_DELAY_MILLIS).contains(&millis) {
            Ok(Self(millis))
        } else {
            Err(WireError::Delay)
        }
    }

    /// The delay.
    pub(crate) fn duration(self) -> Duration {
        Duration::from_millis(u64::from(self.0))
    }

    /// The delay halfway between two, rounded down: valid whenever both
    /// are.
    pub(crate) const fn midpoint(self, other: Self) -> Self {
        Self(self.0 / 2 + other.0 / 2 + (self.0 % 2 + other.0 % 2) / 2)
    }
}

impl EchoKind {
    const fn code(self) -> u8 {
        match self {
            Self::Now => 1,
            Self::Delayed(_) => 2,
            Self::FromOtherPort => 3,
        }
    }
}

/// An echo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct EchoRequest {
    /// What it asks for.
    pub(crate) kind: EchoKind,
    /// Matches the answer to the request.
    pub(crate) nonce: [u8; 16],
}

/// An echo answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct EchoAnswer {
    /// The request's kind code (1, 2 or 3).
    pub(crate) kind: u8,
    /// The request's nonce.
    pub(crate) nonce: [u8; 16],
    /// The port the server sent this answer from.
    pub(crate) server_port: u16,
    /// The source address the server saw on the request.
    pub(crate) observed: SocketAddrV4,
}

/// Why a datagram, line or report is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub(crate) enum WireError {
    /// Not 32 bytes long.
    #[error("the datagram is {len} bytes long, not 32")]
    Length {
        /// Its length.
        len: usize,
    },
    /// Does not start with `MFK1`.
    #[error("the message does not start with MFK1")]
    Magic,
    /// A request where an answer was due, or the other way round.
    #[error("the datagram goes the wrong way")]
    Direction,
    /// An unknown kind code.
    #[error("the datagram's kind {code} is unknown")]
    Kind {
        /// The code.
        code: u8,
    },
    /// A delay on a kind that takes none, or a delay over ten minutes.
    #[error("the datagram's delay is not one its kind allows")]
    Delay,
    /// Bytes that must be zero are not.
    #[error("the datagram's reserved bytes are not zero")]
    Reserved,
    /// A line that is not of its form.
    #[error("the line is not of its form")]
    Line,
}

const DIRECTION_AT: usize = 5;
const SERVER_PORT_AT: usize = 6;
const NONCE_AT: usize = 8;
const DELAY_AT: usize = 24;
const OBSERVED_IP_AT: usize = 24;
const OBSERVED_PORT_AT: usize = 28;

const REQUEST: u8 = 0;
const ANSWER: u8 = 1;

fn header(bytes: &[u8], direction: u8) -> Result<(), WireError> {
    if bytes.len() != DATAGRAM_LEN {
        return Err(WireError::Length { len: bytes.len() });
    }
    if bytes[..4] != MAGIC {
        return Err(WireError::Magic);
    }
    if bytes[DIRECTION_AT] != direction {
        return Err(WireError::Direction);
    }
    Ok(())
}

fn nonce_at(bytes: &[u8]) -> [u8; 16] {
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&bytes[NONCE_AT..NONCE_AT + 16]);
    nonce
}

impl EchoRequest {
    /// The request's 32 bytes.
    pub(crate) fn encode(&self) -> [u8; DATAGRAM_LEN] {
        let mut bytes = [0_u8; DATAGRAM_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = self.kind.code();
        bytes[DIRECTION_AT] = REQUEST;
        bytes[NONCE_AT..NONCE_AT + 16].copy_from_slice(&self.nonce);
        if let EchoKind::Delayed(Delay(millis)) = self.kind {
            bytes[DELAY_AT..DELAY_AT + 4].copy_from_slice(&millis.to_be_bytes());
        }
        bytes
    }

    /// A request, refusing anything not exactly of its form.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        header(bytes, REQUEST)?;
        if bytes[SERVER_PORT_AT..NONCE_AT] != [0, 0] || bytes[DELAY_AT + 4..] != [0, 0, 0, 0] {
            return Err(WireError::Reserved);
        }
        let millis = u32::from_be_bytes([
            bytes[DELAY_AT],
            bytes[DELAY_AT + 1],
            bytes[DELAY_AT + 2],
            bytes[DELAY_AT + 3],
        ]);
        let kind = match (bytes[4], millis) {
            (1, 0) => EchoKind::Now,
            (3, 0) => EchoKind::FromOtherPort,
            (2, millis) => EchoKind::Delayed(Delay::from_millis(millis)?),
            (1 | 3, _) => return Err(WireError::Delay),
            (code, _) => return Err(WireError::Kind { code }),
        };
        Ok(Self {
            kind,
            nonce: nonce_at(bytes),
        })
    }
}

impl EchoAnswer {
    /// The answer to `request` as seen from `observed`, sent from
    /// `server_port`.
    pub(crate) const fn to(
        request: &EchoRequest,
        observed: SocketAddrV4,
        server_port: u16,
    ) -> Self {
        Self {
            kind: request.kind.code(),
            nonce: request.nonce,
            server_port,
            observed,
        }
    }

    /// The answer's 32 bytes.
    pub(crate) fn encode(&self) -> [u8; DATAGRAM_LEN] {
        let mut bytes = [0_u8; DATAGRAM_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = self.kind;
        bytes[DIRECTION_AT] = ANSWER;
        bytes[SERVER_PORT_AT..NONCE_AT].copy_from_slice(&self.server_port.to_be_bytes());
        bytes[NONCE_AT..NONCE_AT + 16].copy_from_slice(&self.nonce);
        bytes[OBSERVED_IP_AT..OBSERVED_IP_AT + 4].copy_from_slice(&self.observed.ip().octets());
        bytes[OBSERVED_PORT_AT..OBSERVED_PORT_AT + 2]
            .copy_from_slice(&self.observed.port().to_be_bytes());
        bytes
    }

    /// An answer, refusing anything not exactly of its form.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        header(bytes, ANSWER)?;
        if bytes[OBSERVED_PORT_AT + 2..] != [0, 0] {
            return Err(WireError::Reserved);
        }
        let kind = bytes[4];
        if !(1..=3).contains(&kind) {
            return Err(WireError::Kind { code: kind });
        }
        let ip = Ipv4Addr::new(
            bytes[OBSERVED_IP_AT],
            bytes[OBSERVED_IP_AT + 1],
            bytes[OBSERVED_IP_AT + 2],
            bytes[OBSERVED_IP_AT + 3],
        );
        let port = u16::from_be_bytes([bytes[OBSERVED_PORT_AT], bytes[OBSERVED_PORT_AT + 1]]);
        Ok(Self {
            kind,
            nonce: nonce_at(bytes),
            server_port: u16::from_be_bytes([bytes[SERVER_PORT_AT], bytes[SERVER_PORT_AT + 1]]),
            observed: SocketAddrV4::new(ip, port),
        })
    }
}

/// The reflector's line for a probe seen from `observed`.
pub(crate) fn reflector_line(observed: SocketAddrV4) -> String {
    format!("MFK1 {observed}\n")
}

/// The source address in a reflector line.
pub(crate) fn parse_reflector_line(line: &[u8]) -> Result<SocketAddrV4, WireError> {
    let text = std::str::from_utf8(line).map_err(|_| WireError::Line)?;
    let address = text
        .strip_prefix("MFK1 ")
        .and_then(|rest| rest.strip_suffix('\n'))
        .ok_or(WireError::Line)?;
    address.parse().map_err(|_| WireError::Line)
}

/// The sink's opening line for a measurement of `seconds`.
pub(crate) fn sink_line(seconds: u16) -> String {
    format!("MFK1 SINK {seconds}\n")
}

/// The seconds a sink's opening line asks for: 1 to 120.
pub(crate) fn parse_sink_line(line: &[u8]) -> Result<u16, WireError> {
    let text = std::str::from_utf8(line).map_err(|_| WireError::Line)?;
    let seconds: u16 = text
        .strip_prefix("MFK1 SINK ")
        .and_then(|rest| rest.strip_suffix('\n'))
        .and_then(|digits| {
            digits
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| digits.parse().ok())
                .flatten()
        })
        .ok_or(WireError::Line)?;
    if (1..=MAX_SINK_SECONDS).contains(&seconds) {
        Ok(seconds)
    } else {
        Err(WireError::Line)
    }
}

/// What the sink counted: the bytes that arrived in each whole second
/// after the opening line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SinkReport {
    /// One count per second, `seconds` of them.
    pub(crate) bytes_per_second: Vec<u64>,
}

impl SinkReport {
    /// A report line from the sink, refusing one whose length is not the
    /// seconds asked for.
    pub(crate) fn parse(line: &[u8], seconds: u16) -> Result<Self, WireError> {
        let report: Self = serde_json::from_slice(line).map_err(|_| WireError::Line)?;
        if report.bytes_per_second.len() == usize::from(seconds) {
            Ok(report)
        } else {
            Err(WireError::Line)
        }
    }
}
