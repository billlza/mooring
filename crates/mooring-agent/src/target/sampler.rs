// SPDX-License-Identifier: GPL-3.0-or-later

//! The handshake sampler (design §11.7, `TargetTool::HandshakeSampler`):
//! the p95 handshake time over [`TARGET_HANDSHAKE_SAMPLES`] handshakes and
//! the size of the target's first flight, which `xray tls ping` measures
//! neither of. Mooring's Rust code has no TLS stack (§6.3), so the sampler
//! sends a ClientHello it builds itself (TLS 1.3 and 1.2, an X25519 key
//! share, the name as SNI, ALPN `h2` and `http/1.1`), never completes the
//! handshake, and times the target's answer: from the hello's last byte to
//! the last byte of the server's first flight, which ends when the server
//! goes quiet for [`IDLE`] waiting for the client's next flight. The
//! flight's size counts every byte of it, record headers included.
//!
//! The hello offers no certificate compression, so a target that would
//! compress its chain for a browser is measured at its larger size: the
//! measure errs on the side of refusing a target.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use mooring_agent_proto::{
    AgentError, StderrTail, TARGET_HANDSHAKE_SAMPLES, TargetHost, TargetTool,
};

/// How long a connection may take.
const CONNECT: Duration = Duration::from_secs(3);

/// The quiet that ends the server's first flight. A target that passes the
/// 5 ms handshake rule is a neighbour of the node, so a flight spread over
/// two round trips (more than the initial congestion window) never pauses
/// this long.
pub(crate) const IDLE: Duration = Duration::from_millis(300);

/// How long the server may take to start answering.
const DEADLINE: Duration = Duration::from_secs(3);

/// The most of a flight read: far above REALITY's 16 KiB limit.
const MAX_FLIGHT: usize = 64 * 1024;

/// The random bytes one hello takes: its random, its session id and its
/// key share.
pub(crate) const RANDOM_BYTES: usize = 96;

/// What the sampler measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Measured {
    /// The 95th percentile handshake time, by nearest rank.
    pub(crate) p95_micros: u64,
    /// The largest first flight seen.
    pub(crate) first_flight_bytes: u32,
}

/// One handshake's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sample {
    /// From the hello's last byte to the flight's last byte.
    pub(crate) micros: u64,
    /// The flight's bytes.
    pub(crate) bytes: u32,
}

/// [`RANDOM_BYTES`] from the kernel.
pub(crate) fn urandom() -> io::Result<[u8; RANDOM_BYTES]> {
    let mut bytes = [0; RANDOM_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn unavailable(text: &str) -> AgentError {
    AgentError::TargetFactsUnavailable {
        tool: TargetTool::HandshakeSampler,
        stderr_tail: StderrTail::scrubbed(text.as_bytes(), &[]),
    }
}

/// Samples [`TARGET_HANDSHAKE_SAMPLES`] handshakes with the target at
/// `address`, each hello with fresh bytes from `random`.
pub(crate) fn measure(
    address: SocketAddr,
    host: &TargetHost,
    mut random: impl FnMut() -> io::Result<[u8; RANDOM_BYTES]>,
) -> Result<Measured, AgentError> {
    let mut times = Vec::with_capacity(usize::from(TARGET_HANDSHAKE_SAMPLES));
    let mut largest = 0;
    for _ in 0..TARGET_HANDSHAKE_SAMPLES {
        let random = random().map_err(|error| unavailable(&format!("randomness: {error}")))?;
        let sample = sample(address, host, &random).map_err(|text| unavailable(&text))?;
        times.push(sample.micros);
        largest = largest.max(sample.bytes);
    }
    Ok(Measured {
        p95_micros: p95(&mut times).ok_or_else(|| unavailable("no handshake was sampled"))?,
        first_flight_bytes: largest,
    })
}

/// The 95th percentile of `times` by nearest rank: the ⌈0.95·n⌉-th
/// smallest; `None` for no times.
pub(crate) fn p95(times: &mut [u64]) -> Option<u64> {
    times.sort_unstable();
    let rank = (times.len() * 95).div_ceil(100);
    times.get(rank.checked_sub(1)?).copied()
}

/// One handshake: the hello sent, the server's first flight read until it
/// goes quiet, and its first record checked to be a ServerHello. A failure
/// is described for the Mac.
pub(crate) fn sample(
    address: SocketAddr,
    host: &TargetHost,
    random: &[u8; RANDOM_BYTES],
) -> Result<Sample, String> {
    let mut stream = TcpStream::connect_timeout(&address, CONNECT)
        .map_err(|error| format!("connect: {error}"))?;
    stream
        .set_nodelay(true)
        .and_then(|()| stream.set_read_timeout(Some(IDLE)))
        .map_err(|error| format!("socket: {error}"))?;
    stream
        .write_all(&client_hello(host, random))
        .map_err(|error| format!("send: {error}"))?;
    let sent = Instant::now();
    let mut flight = Vec::new();
    let mut last = None;
    let mut buffer = [0; 16 * 1024];
    while flight.len() < MAX_FLIGHT {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                flight.extend_from_slice(&buffer[..read]);
                last = Some(Instant::now());
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if last.is_some() {
                    break;
                }
                if sent.elapsed() >= DEADLINE {
                    return Err("the target sent nothing back".to_owned());
                }
            }
            Err(error) => return Err(format!("receive: {error}")),
        }
    }
    let last = last.ok_or_else(|| "the target closed without an answer".to_owned())?;
    check_server_hello(&flight)?;
    Ok(Sample {
        micros: u64::try_from(last.duration_since(sent).as_micros()).unwrap_or(u64::MAX),
        bytes: u32::try_from(flight.len()).map_err(|_| "the flight is too large".to_owned())?,
    })
}

/// `SHA-256("HelloRetryRequest")`, the random of a ServerHello that asks
/// for another hello (RFC 8446 §4.1.3).
const RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Checks that `flight` begins with a ServerHello record that does not ask
/// for another hello: a target that answers with an alert, or with
/// anything but TLS, has no first flight to measure.
pub(crate) fn check_server_hello(flight: &[u8]) -> Result<(), String> {
    match flight.first() {
        Some(0x16) => {}
        Some(0x15) => return Err("the target answered with an alert".to_owned()),
        _ => return Err("the target's answer is not TLS".to_owned()),
    }
    // Record header (5), then the handshake header: its type (1), its
    // length (3), the version (2) and the random (32).
    if flight.get(5) != Some(&0x02) {
        return Err("the target's first record is not a ServerHello".to_owned());
    }
    match flight.get(11..43) {
        Some(random) if random == RETRY_RANDOM => {
            Err("the target asked for another hello".to_owned())
        }
        Some(_) => Ok(()),
        None => Err("the target's ServerHello is cut short".to_owned()),
    }
}

/// Appends `body` with its length as `width` big-endian bytes (1, 2 or 3).
fn with_length(out: &mut Vec<u8>, width: usize, body: &[u8]) {
    let length = body.len().to_be_bytes();
    out.extend_from_slice(&length[length.len() - width..]);
    out.extend_from_slice(body);
}

/// An extension: its type and its data, with the data's length.
fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    with_length(out, 2, data);
}

/// The cipher suites offered: TLS 1.3's three, then TLS 1.2's ECDHE suites
/// with AES-GCM and ChaCha20-Poly1305.
const CIPHER_SUITES: [u16; 9] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
];

/// The signature schemes offered: ECDSA, RSA-PSS and RSA PKCS#1 with
/// SHA-256, -384 and -512.
const SIGNATURE_SCHEMES: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// The hello for `host`, its random, session id and X25519 key share taken
/// from `random` in that order. Any 32 bytes are an X25519 public key; no
/// shared secret is ever computed.
pub(crate) fn client_hello(host: &TargetHost, random: &[u8; RANDOM_BYTES]) -> Vec<u8> {
    let (hello_random, rest) = random.split_at(32);
    let (session, share) = rest.split_at(32);
    let mut extensions = Vec::new();
    let mut names = vec![0x00];
    with_length(&mut names, 2, host.as_str().as_bytes());
    let mut server_name = Vec::new();
    with_length(&mut server_name, 2, &names);
    extension(&mut extensions, 0x0000, &server_name);
    let mut groups = Vec::new();
    with_length(&mut groups, 2, &[0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]);
    extension(&mut extensions, 0x000a, &groups);
    extension(&mut extensions, 0x000b, &[0x01, 0x00]);
    let schemes: Vec<u8> = SIGNATURE_SCHEMES
        .iter()
        .flat_map(|scheme| scheme.to_be_bytes())
        .collect();
    let mut signatures = Vec::new();
    with_length(&mut signatures, 2, &schemes);
    extension(&mut extensions, 0x000d, &signatures);
    let mut protocols = Vec::new();
    with_length(&mut protocols, 1, b"h2");
    with_length(&mut protocols, 1, b"http/1.1");
    let mut alpn = Vec::new();
    with_length(&mut alpn, 2, &protocols);
    extension(&mut extensions, 0x0010, &alpn);
    extension(&mut extensions, 0x0017, &[]);
    extension(&mut extensions, 0xff01, &[0x00]);
    extension(&mut extensions, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);
    extension(&mut extensions, 0x002d, &[0x01, 0x01]);
    let mut key_share = vec![0x00, 0x1d];
    with_length(&mut key_share, 2, share);
    let mut shares = Vec::new();
    with_length(&mut shares, 2, &key_share);
    extension(&mut extensions, 0x0033, &shares);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(hello_random);
    with_length(&mut body, 1, session);
    let suites: Vec<u8> = CIPHER_SUITES
        .iter()
        .flat_map(|suite| suite.to_be_bytes())
        .collect();
    with_length(&mut body, 2, &suites);
    body.extend_from_slice(&[0x01, 0x00]);
    with_length(&mut body, 2, &extensions);
    let mut handshake = vec![0x01];
    with_length(&mut handshake, 3, &body);
    let mut record = vec![0x16, 0x03, 0x01];
    with_length(&mut record, 2, &handshake);
    record
}
