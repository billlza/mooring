// SPDX-License-Identifier: GPL-3.0-or-later

//! Framing over `std::io` (design §11.1).
//!
//! * A request is one line of JSON on the agent's stdin: at most
//!   [`MAX_REQUEST_LINE_BYTES`] bytes before the terminating `\n`.
//! * `PutBlob` is followed by exactly `len` raw bytes and then the end of
//!   input.
//! * The reply is one line of JSON on stdout, at most
//!   [`MAX_RESPONSE_LINE_BYTES`] bytes before its `\n`, and then the end of
//!   output.
//!
//! Writers emit compact JSON terminated by a single `\n`. Readers take the
//! bytes up to the first `\n` as the line; JSON permits whitespace around
//! the value, so a `\r` before the `\n` (CRLF) is accepted as such, and the
//! limit counts it. A `\r` alone does not end a line.
//!
//! The agent reads with [`read_request`], then for `PutBlob`
//! [`read_blob`] (which also requires the end of input) and otherwise
//! [`expect_end_of_input`]; the Mac closes its side after writing, as one
//! SSH session carries one request. Readers never panic on malformed input;
//! every failure is a [`ReadError`].

use std::fmt;
use std::io::{self, BufRead, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::macros::closed_enum;
use crate::{AgentError, BlobLen, IoOp, LineRequest, Reply, Request, Sha256Hex};

/// The longest request line, excluding its `\n`: 1 MiB.
pub const MAX_REQUEST_LINE_BYTES: usize = 1024 * 1024;

/// The longest reply line, excluding its `\n`: 1 MiB. The Mac refuses a
/// longer one.
pub const MAX_RESPONSE_LINE_BYTES: usize = 1024 * 1024;

/// The chunk size used to copy a blob payload.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// A frame that could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// Reading the input failed.
    #[error("reading the frame failed")]
    Io(#[source] io::Error),
    /// Writing a blob payload to its sink failed.
    #[error("writing the blob payload failed")]
    Sink(#[source] io::Error),
    /// The input ended before any byte arrived.
    #[error("the input is empty")]
    Empty,
    /// The input ended before the line's `\n`.
    #[error("the input ended after {len} bytes without a newline")]
    Unterminated {
        /// The bytes received.
        len: usize,
    },
    /// The line is longer than the limit.
    #[error("the line exceeds {limit} bytes")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// The line is not a valid frame: not UTF-8 JSON, an unknown variant
    /// or field, a missing field, or a value that breaks its type's rule.
    ///
    /// Only the decoder's classification and position are kept, never its
    /// message: a decoder message quotes unknown names from the peer
    /// verbatim, and a reply comes from a VPS that may be compromised, so
    /// its text could carry terminal escapes into a log (design §10.5).
    #[error("the line is not a valid frame ({cause} at line {line}, column {column})")]
    Malformed {
        /// What kind of decoding failure it was.
        cause: MalformedCause,
        /// The 1-based line of the failure within the frame.
        line: usize,
        /// The 1-based column of the failure.
        column: usize,
    },
    /// The blob payload ended early.
    #[error("the blob payload ended after {received} of {expected} bytes")]
    BlobTruncated {
        /// The declared length.
        expected: u64,
        /// The bytes received.
        received: u64,
    },
    /// Input continued after the frame.
    #[error("input continues after the frame")]
    TrailingBytes,
}

closed_enum! {
    /// How a frame failed to decode, as the JSON decoder classifies it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum MalformedCause {
        /// The bytes are not JSON (or not UTF-8).
        Syntax,
        /// Valid JSON that is not a frame of this protocol: an unknown
        /// variant or field, a missing field, or a value that breaks its
        /// type's rule.
        Data,
        /// The JSON value ends early.
        Eof,
        /// The decoder failed reading its input; frames are decoded from
        /// memory, so this classification is only kept to be total.
        Io,
    }
}

impl MalformedCause {
    fn of(error: &serde_json::Error) -> Self {
        match error.classify() {
            serde_json::error::Category::Syntax => Self::Syntax,
            serde_json::error::Category::Data => Self::Data,
            serde_json::error::Category::Eof => Self::Eof,
            serde_json::error::Category::Io => Self::Io,
        }
    }
}

impl fmt::Display for MalformedCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Syntax => "invalid JSON",
            Self::Data => "not a frame of this protocol",
            Self::Eof => "truncated JSON",
            Self::Io => "input error",
        })
    }
}

closed_enum! {
    /// The variant of a [`ReadError`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum ReadErrorKind {
        /// [`ReadError::Io`].
        Io,
        /// [`ReadError::Sink`].
        Sink,
        /// [`ReadError::Empty`].
        Empty,
        /// [`ReadError::Unterminated`].
        Unterminated,
        /// [`ReadError::TooLarge`].
        TooLarge,
        /// [`ReadError::Malformed`].
        Malformed,
        /// [`ReadError::BlobTruncated`].
        BlobTruncated,
        /// [`ReadError::TrailingBytes`].
        TrailingBytes,
    }
}

impl ReadError {
    /// The variant, without its data.
    pub const fn kind(&self) -> ReadErrorKind {
        match self {
            Self::Io(_) => ReadErrorKind::Io,
            Self::Sink(_) => ReadErrorKind::Sink,
            Self::Empty => ReadErrorKind::Empty,
            Self::Unterminated { .. } => ReadErrorKind::Unterminated,
            Self::TooLarge { .. } => ReadErrorKind::TooLarge,
            Self::Malformed { .. } => ReadErrorKind::Malformed,
            Self::BlobTruncated { .. } => ReadErrorKind::BlobTruncated,
            Self::TrailingBytes => ReadErrorKind::TrailingBytes,
        }
    }

    /// The error the agent replies with when reading a request failed.
    /// Input that is not a request of this protocol — empty, unterminated
    /// or malformed — is [`AgentError::UnknownRequest`].
    pub fn to_agent_error(&self) -> AgentError {
        match self {
            Self::Io(error) => AgentError::Io {
                op: IoOp::ReadRequest,
                errno: error.raw_os_error(),
            },
            Self::Sink(error) => AgentError::Io {
                op: IoOp::WriteBlob,
                errno: error.raw_os_error(),
            },
            Self::Empty | Self::Unterminated { .. } | Self::Malformed { .. } => {
                AgentError::UnknownRequest
            }
            Self::TooLarge { .. } => AgentError::RequestTooLarge,
            Self::BlobTruncated { expected, received } => AgentError::BlobTruncated {
                expected: *expected,
                received: *received,
            },
            Self::TrailingBytes => AgentError::TrailingInput,
        }
    }
}

/// A frame that could not be written.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// Writing the output failed.
    #[error("writing the frame failed")]
    Io(#[source] io::Error),
    /// The value could not be encoded as JSON.
    #[error("encoding the frame failed")]
    Encode(#[source] serde_json::Error),
    /// The encoded line is longer than the limit.
    #[error("the encoded line is {len} bytes, over the {limit} byte limit")]
    TooLarge {
        /// The encoded length.
        len: usize,
        /// The limit.
        limit: usize,
    },
    /// The blob payload is longer than [`crate::MAX_BLOB_BYTES`].
    #[error("the blob payload is {len} bytes, over the limit")]
    BlobTooLarge {
        /// The payload length.
        len: u64,
    },
}

closed_enum! {
    /// The variant of a [`WriteError`], without its data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum WriteErrorKind {
        /// [`WriteError::Io`].
        Io,
        /// [`WriteError::Encode`].
        Encode,
        /// [`WriteError::TooLarge`].
        TooLarge,
        /// [`WriteError::BlobTooLarge`].
        BlobTooLarge,
    }
}

impl WriteError {
    /// The variant, without its data.
    pub const fn kind(&self) -> WriteErrorKind {
        match self {
            Self::Io(_) => WriteErrorKind::Io,
            Self::Encode(_) => WriteErrorKind::Encode,
            Self::TooLarge { .. } => WriteErrorKind::TooLarge,
            Self::BlobTooLarge { .. } => WriteErrorKind::BlobTooLarge,
        }
    }
}

/// Reads one request line and decodes it. Nothing after the `\n` is
/// consumed, so a `PutBlob` payload stays in `reader` for [`read_blob`].
pub fn read_request<R: BufRead>(reader: &mut R) -> Result<Request, ReadError> {
    decode_line(reader, MAX_REQUEST_LINE_BYTES)
}

/// Copies a `PutBlob` payload of exactly `len` bytes from `reader` into
/// `sink`, then requires the end of input. `reader` must be the one
/// [`read_request`] read the header from.
pub fn read_blob<R: Read, W: Write>(
    reader: &mut R,
    len: BlobLen,
    sink: &mut W,
) -> Result<(), ReadError> {
    let expected = len.get();
    let mut payload = reader.by_ref().take(expected);
    let mut buffer = vec![0_u8; COPY_CHUNK_BYTES];
    let mut received = 0_u64;
    while received < expected {
        let read = match payload.read(&mut buffer) {
            Ok(0) => return Err(ReadError::BlobTruncated { expected, received }),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadError::Io(error)),
        };
        sink.write_all(&buffer[..read]).map_err(ReadError::Sink)?;
        received += read as u64;
    }
    sink.flush().map_err(ReadError::Sink)?;
    expect_end_of_input(reader)
}

/// Requires that `reader` holds no further bytes.
pub fn expect_end_of_input<R: Read>(reader: &mut R) -> Result<(), ReadError> {
    let mut probe = [0_u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(ReadError::TrailingBytes),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ReadError::Io(error)),
        }
    }
}

/// Reads the agent's reply line, decodes it and requires the end of
/// output.
pub fn read_reply<R: BufRead>(reader: &mut R) -> Result<Reply, ReadError> {
    let reply = decode_line(reader, MAX_RESPONSE_LINE_BYTES)?;
    expect_end_of_input(reader)?;
    Ok(reply)
}

/// Writes one request line. A `PutBlob` has no line of its own: it is
/// written with its payload by [`write_put_blob`], so it is not a
/// [`LineRequest`].
pub fn write_request<W: Write>(writer: &mut W, request: &LineRequest) -> Result<(), WriteError> {
    write_line(writer, request, MAX_REQUEST_LINE_BYTES)
}

/// Writes a `PutBlob` frame: the header line, whose `len` is taken from
/// `payload`, and the payload itself. `sha256` must be the payload's digest;
/// the agent verifies it.
pub fn write_put_blob<W: Write>(
    writer: &mut W,
    sha256: Sha256Hex,
    payload: &[u8],
) -> Result<(), WriteError> {
    let len = payload.len() as u64;
    let len = BlobLen::new(len).map_err(|_| WriteError::BlobTooLarge { len })?;
    let header = Request::PutBlob { sha256, len };
    let mut frame = encode_line(&header, MAX_REQUEST_LINE_BYTES)?;
    frame.extend_from_slice(payload);
    writer.write_all(&frame).map_err(WriteError::Io)?;
    writer.flush().map_err(WriteError::Io)
}

/// Writes the agent's reply line.
pub fn write_reply<W: Write>(writer: &mut W, reply: &Reply) -> Result<(), WriteError> {
    write_line(writer, reply, MAX_RESPONSE_LINE_BYTES)
}

fn decode_line<R: BufRead, T: DeserializeOwned>(
    reader: &mut R,
    limit: usize,
) -> Result<T, ReadError> {
    let line = read_line(reader, limit)?;
    serde_json::from_slice(&line).map_err(|error| ReadError::Malformed {
        cause: MalformedCause::of(&error),
        line: error.line(),
        column: error.column(),
    })
}

/// Reads up to and including the first `\n`, returning the bytes before it.
/// At most `limit + 1` bytes are consumed.
fn read_line<R: BufRead>(reader: &mut R, limit: usize) -> Result<Vec<u8>, ReadError> {
    let cap = (limit as u64).saturating_add(1);
    let mut line = Vec::new();
    let read = reader
        .by_ref()
        .take(cap)
        .read_until(b'\n', &mut line)
        .map_err(ReadError::Io)?;
    if read == 0 {
        return Err(ReadError::Empty);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(line);
    }
    if line.len() > limit {
        Err(ReadError::TooLarge { limit })
    } else {
        Err(ReadError::Unterminated { len: line.len() })
    }
}

fn encode_line<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, WriteError> {
    let mut line = serde_json::to_vec(value).map_err(WriteError::Encode)?;
    if line.len() > limit {
        return Err(WriteError::TooLarge {
            len: line.len(),
            limit,
        });
    }
    line.push(b'\n');
    Ok(line)
}

fn write_line<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
    limit: usize,
) -> Result<(), WriteError> {
    let line = encode_line(value, limit)?;
    writer.write_all(&line).map_err(WriteError::Io)?;
    writer.flush().map_err(WriteError::Io)
}
