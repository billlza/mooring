// SPDX-License-Identifier: GPL-3.0-or-later

//! Framing: limits (exactly at and one over), CRLF, malformed input,
//! unknown fields, `PutBlob` length mismatches and the agent's error mapping.

use std::io::{self, BufReader, Cursor, Read, Write};

use mooring_agent_proto::{
    AgentError, BlobLen, IoOp, LineRequest, MAX_BLOB_BYTES, MAX_REQUEST_LINE_BYTES,
    MAX_RESPONSE_LINE_BYTES, MalformedCause, ReadError, ReadErrorKind, Reply, Request, RequestKind,
    Response, ResponseKind, WriteError, WriteErrorKind, expect_end_of_input, read_blob, read_reply,
    read_request, write_put_blob, write_reply, write_request,
};

use crate::fixtures;

const DIGEST: &str = "0303030303030303030303030303030303030303030303030303030303030303";

fn read(bytes: &[u8]) -> Result<Request, ReadError> {
    read_request(&mut Cursor::new(bytes))
}

fn read_kind(bytes: &[u8]) -> ReadErrorKind {
    read(bytes).unwrap_err().kind()
}

/// `"Hello"` padded with JSON whitespace to exactly `len` bytes.
fn padded_hello(len: usize) -> Vec<u8> {
    let mut line = br#""Hello""#.to_vec();
    line.resize(len, b' ');
    line
}

struct FailingIo;

impl Read for FailingIo {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(5))
    }
}

impl Write for FailingIo {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(28))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Counts bytes written, so a 128 MiB payload needs no buffer.
#[derive(Default)]
struct CountingSink(u64);

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns `Interrupted` before every successful read.
struct Interrupting<R> {
    inner: R,
    interrupt_next: bool,
}

impl<R: Read> Read for Interrupting<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.interrupt_next = !self.interrupt_next;
        if self.interrupt_next {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        } else {
            self.inner.read(buffer)
        }
    }
}

// ---- request line limit -------------------------------------------------

#[test]
fn a_request_line_of_exactly_the_limit_is_accepted() {
    let mut frame = padded_hello(MAX_REQUEST_LINE_BYTES);
    frame.push(b'\n');
    assert_eq!(read(&frame).unwrap(), Request::Line(LineRequest::Hello));
}

#[test]
fn a_request_line_one_byte_over_the_limit_is_refused() {
    let mut frame = padded_hello(MAX_REQUEST_LINE_BYTES + 1);
    frame.push(b'\n');
    let error = read(&frame).unwrap_err();
    assert!(
        matches!(
            error,
            ReadError::TooLarge {
                limit: MAX_REQUEST_LINE_BYTES
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.to_agent_error(), AgentError::RequestTooLarge);
}

#[test]
fn an_oversized_line_consumes_at_most_one_byte_past_the_limit() {
    let frame = padded_hello(MAX_REQUEST_LINE_BYTES + 10);
    let mut cursor = Cursor::new(frame.as_slice());
    assert_eq!(
        read_request(&mut cursor).unwrap_err().kind(),
        ReadErrorKind::TooLarge
    );
    assert_eq!(cursor.position(), (MAX_REQUEST_LINE_BYTES + 1) as u64);
}

#[test]
fn the_writer_refuses_a_line_over_the_limit() {
    let blobs = (0_u32..16_000)
        .map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&index.to_be_bytes());
            mooring_agent_proto::Sha256Hex::from_bytes(bytes)
        })
        .collect();
    let mut out = Vec::new();
    let error = write_request(&mut out, &LineRequest::HaveBlobs { blobs }).unwrap_err();
    assert!(
        matches!(error, WriteError::TooLarge { len, limit: MAX_REQUEST_LINE_BYTES } if len > MAX_REQUEST_LINE_BYTES),
        "{error:?}"
    );
    assert!(
        out.is_empty(),
        "nothing is written when the line is refused"
    );
}

// ---- reply line limit ---------------------------------------------------

#[test]
fn a_reply_line_of_exactly_the_limit_is_accepted_and_one_over_is_refused() {
    let mut exact = br#"{"Ok":"BootstrapRevoked"}"#.to_vec();
    exact.resize(MAX_RESPONSE_LINE_BYTES, b' ');
    exact.push(b'\n');
    assert_eq!(
        read_reply(&mut Cursor::new(exact.as_slice())).unwrap(),
        Ok(Response::BootstrapRevoked)
    );

    let mut over = br#"{"Ok":"BootstrapRevoked"}"#.to_vec();
    over.resize(MAX_RESPONSE_LINE_BYTES + 1, b' ');
    over.push(b'\n');
    let error = read_reply(&mut Cursor::new(over.as_slice())).unwrap_err();
    assert!(
        matches!(
            error,
            ReadError::TooLarge {
                limit: MAX_RESPONSE_LINE_BYTES
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_reply_must_be_the_only_output() {
    let mut out = Vec::new();
    write_reply(&mut out, &Ok(Response::BootstrapRevoked)).unwrap();
    out.extend_from_slice(b"{}\n");
    assert_eq!(
        read_reply(&mut Cursor::new(out.as_slice()))
            .unwrap_err()
            .kind(),
        ReadErrorKind::TrailingBytes
    );
}

#[test]
fn replies_round_trip_through_the_frame() {
    let mut replies: Vec<Reply> = ResponseKind::ALL
        .iter()
        .map(|kind| Ok(fixtures::response(*kind)))
        .collect();
    replies.extend(
        mooring_agent_proto::AgentErrorKind::ALL
            .iter()
            .map(|kind| Err(fixtures::agent_error(*kind))),
    );
    for reply in replies {
        let mut out = Vec::new();
        write_reply(&mut out, &reply).unwrap();
        assert_eq!(out.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(out.last(), Some(&b'\n'));
        assert_eq!(read_reply(&mut Cursor::new(out.as_slice())).unwrap(), reply);
    }
}

// ---- line termination and CRLF ------------------------------------------

#[test]
fn crlf_is_accepted_as_json_whitespace() {
    assert_eq!(
        read(b"\"Hello\"\r\n").unwrap(),
        Request::Line(LineRequest::Hello)
    );
    assert_eq!(
        read(b"{\"Confirm\":{\"generation\":7}}\r\n").unwrap(),
        fixtures::request(RequestKind::Confirm)
    );
}

#[test]
fn a_carriage_return_alone_does_not_end_the_line() {
    let error = read(b"\"Hello\"\r").unwrap_err();
    assert!(
        matches!(error, ReadError::Unterminated { len: 8 }),
        "{error:?}"
    );
}

#[test]
fn the_carriage_return_counts_towards_the_limit() {
    let mut frame = padded_hello(MAX_REQUEST_LINE_BYTES);
    frame.extend_from_slice(b"\r\n");
    assert_eq!(read_kind(&frame), ReadErrorKind::TooLarge);
}

#[test]
fn writers_terminate_with_a_single_line_feed() {
    for kind in RequestKind::ALL
        .iter()
        .filter(|kind| **kind != RequestKind::PutBlob)
    {
        let mut out = Vec::new();
        write_request(&mut out, &fixtures::line_request(*kind)).unwrap();
        assert!(!out.contains(&b'\r'));
        assert_eq!(
            out.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "{kind:?}"
        );
        assert_eq!(out.last(), Some(&b'\n'));
        let mut cursor = Cursor::new(out.as_slice());
        assert_eq!(read_request(&mut cursor).unwrap(), fixtures::request(*kind));
        expect_end_of_input(&mut cursor).unwrap();
    }
}

#[test]
fn empty_and_unterminated_input_are_typed() {
    assert_eq!(read_kind(b""), ReadErrorKind::Empty);
    let error = read(b"\"Hello\"").unwrap_err();
    assert!(
        matches!(error, ReadError::Unterminated { len: 7 }),
        "{error:?}"
    );
    assert_eq!(read_kind(b"\n"), ReadErrorKind::Malformed);
    for error in [ReadError::Empty, ReadError::Unterminated { len: 7 }] {
        assert_eq!(error.to_agent_error(), AgentError::UnknownRequest);
    }
}

#[test]
fn requests_survive_interrupted_reads() {
    let mut frame = Vec::new();
    write_request(&mut frame, &fixtures::line_request(RequestKind::Apply)).unwrap();
    let mut reader = BufReader::with_capacity(
        16,
        Interrupting {
            inner: Cursor::new(frame),
            interrupt_next: false,
        },
    );
    assert_eq!(
        read_request(&mut reader).unwrap(),
        fixtures::request(RequestKind::Apply)
    );
    expect_end_of_input(&mut reader).unwrap();
}

// ---- malformed input and unknown fields ---------------------------------

#[test]
fn malformed_lines_are_rejected_as_unknown_requests() {
    let header = serde_json::to_string(&fixtures::bundle_header()).unwrap();
    let nested_unknown = format!(
        "{{\"Apply\":{}}}",
        header.replacen("\"debian_major\":13", "\"debian_major\":13,\"extra\":1", 1)
    );
    let unknown_file = format!(
        "{{\"Apply\":{}}}",
        header.replacen("\"WatchConfig\"", "\"Extra\":\"00\",\"WatchConfig\"", 1)
    );
    let cases: Vec<String> = vec![
        "not json".into(),
        "{}".into(),
        "[]".into(),
        "null".into(),
        "\"Frobnicate\"".into(),
        "\"hello\"".into(),
        "{\"Hello\":{}}".into(),
        "{\"Hello\":null,\"Status\":null}".into(),
        "\"Hello\" x".into(),
        "\"Hello\"\"Hello\"".into(),
        "{\"Confirm\":{\"generation\":7,\"extra\":1}}".into(),
        "{\"Confirm\":{}}".into(),
        "{\"Confirm\":{\"generation\":\"7\"}}".into(),
        "{\"Confirm\":{\"generation\":-1}}".into(),
        "{\"Confirm\":{\"generation\":18446744073709551616}}".into(),
        format!(
            "{{\"PutBlob\":{{\"sha256\":\"{}\",\"len\":5}}}}",
            "abcdef0123456789".repeat(4).to_ascii_uppercase()
        ),
        format!("{{\"PutBlob\":{{\"sha256\":\"{DIGEST}\"}}}}"),
        "{\"TargetCheck\":{\"host\":\"-oProxyCommand=x\"}}".into(),
        "{\"Usage\":{\"month\":\"2026-13\"}}".into(),
        "{\"ClearHold\":{\"hold\":\"MacDrain\"}}".into(),
        nested_unknown,
        unknown_file,
    ];
    for case in cases {
        let mut frame = case.clone().into_bytes();
        frame.push(b'\n');
        let error = read(&frame).unwrap_err();
        assert_eq!(error.kind(), ReadErrorKind::Malformed, "{case}");
        assert_eq!(error.to_agent_error(), AgentError::UnknownRequest, "{case}");
    }
}

#[test]
fn invalid_utf8_is_malformed() {
    assert_eq!(read_kind(b"\"Hel\xfflo\"\n"), ReadErrorKind::Malformed);
    assert_eq!(
        read_kind(b"\xef\xbb\xbf\"Hello\"\n"),
        ReadErrorKind::Malformed
    );
}

#[test]
fn a_clear_hold_for_mac_drain_cannot_be_expressed() {
    // MacDrain clears itself; only EgressViolation and Operator are clearable.
    assert!(read(b"{\"ClearHold\":{\"hold\":\"Operator\"}}\n").is_ok());
    assert_eq!(
        read_kind(b"{\"ClearHold\":{\"hold\":\"MacDrain\"}}\n"),
        ReadErrorKind::Malformed
    );
}

// ---- PutBlob ------------------------------------------------------------

fn put_blob_frame(len: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame =
        format!("{{\"PutBlob\":{{\"sha256\":\"{DIGEST}\",\"len\":{len}}}}}\n").into_bytes();
    frame.extend_from_slice(payload);
    frame
}

/// Reads a `PutBlob` frame the way the agent does.
fn receive_blob(frame: &[u8]) -> Result<Vec<u8>, ReadError> {
    let mut reader = Cursor::new(frame);
    let Request::PutBlob { len, .. } = read_request(&mut reader)? else {
        panic!("not a PutBlob frame");
    };
    let mut sink = Vec::new();
    read_blob(&mut reader, len, &mut sink)?;
    Ok(sink)
}

#[test]
fn put_blob_with_exactly_len_bytes_is_received() {
    assert_eq!(
        receive_blob(&put_blob_frame(5, b"hello")).unwrap(),
        b"hello"
    );
    assert_eq!(receive_blob(&put_blob_frame(0, b"")).unwrap(), b"");
    // The payload may contain newlines and anything else.
    assert_eq!(
        receive_blob(&put_blob_frame(3, b"\n\r\0")).unwrap(),
        b"\n\r\0"
    );
}

#[test]
fn put_blob_with_fewer_bytes_is_truncated() {
    let error = receive_blob(&put_blob_frame(5, b"hel")).unwrap_err();
    assert!(
        matches!(
            error,
            ReadError::BlobTruncated {
                expected: 5,
                received: 3
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        error.to_agent_error(),
        AgentError::BlobTruncated {
            expected: 5,
            received: 3
        }
    );
    let error = receive_blob(&put_blob_frame(5, b"")).unwrap_err();
    assert!(
        matches!(
            error,
            ReadError::BlobTruncated {
                expected: 5,
                received: 0
            }
        ),
        "{error:?}"
    );
}

#[test]
fn put_blob_with_more_bytes_has_trailing_input() {
    let error = receive_blob(&put_blob_frame(5, b"hello!")).unwrap_err();
    assert_eq!(error.kind(), ReadErrorKind::TrailingBytes);
    assert_eq!(error.to_agent_error(), AgentError::TrailingInput);
}

#[test]
fn put_blob_survives_crlf_after_the_header() {
    let mut frame =
        format!("{{\"PutBlob\":{{\"sha256\":\"{DIGEST}\",\"len\":2}}}}\r\n").into_bytes();
    frame.extend_from_slice(b"ab");
    assert_eq!(receive_blob(&frame).unwrap(), b"ab");
}

#[test]
fn put_blob_length_is_bounded_exactly_at_128_mib() {
    let at_limit = put_blob_frame(MAX_BLOB_BYTES, b"");
    let Request::PutBlob { len, .. } = read(&at_limit).unwrap() else {
        panic!("not a PutBlob");
    };
    assert_eq!(len, BlobLen::MAX);
    let over = put_blob_frame(MAX_BLOB_BYTES + 1, b"");
    assert_eq!(read_kind(&over), ReadErrorKind::Malformed);
}

#[test]
fn a_full_128_mib_payload_is_copied_and_then_end_of_input_is_required() {
    let mut payload = io::repeat(0x5a).take(MAX_BLOB_BYTES);
    let mut sink = CountingSink::default();
    read_blob(&mut payload, BlobLen::MAX, &mut sink).unwrap();
    assert_eq!(sink.0, MAX_BLOB_BYTES);

    let mut longer = io::repeat(0x5a).take(MAX_BLOB_BYTES + 1);
    let mut sink = CountingSink::default();
    let error = read_blob(&mut longer, BlobLen::MAX, &mut sink).unwrap_err();
    assert_eq!(error.kind(), ReadErrorKind::TrailingBytes);
    assert_eq!(
        sink.0, MAX_BLOB_BYTES,
        "never more than len bytes reach the sink"
    );
}

#[test]
fn write_put_blob_derives_len_from_the_payload() {
    let mut frame = Vec::new();
    let digest = DIGEST.parse().unwrap();
    write_put_blob(&mut frame, digest, b"payload\n").unwrap();
    assert_eq!(receive_blob(&frame).unwrap(), b"payload\n");
    let mut reader = Cursor::new(frame.as_slice());
    assert_eq!(
        read_request(&mut reader).unwrap(),
        Request::PutBlob {
            sha256: digest,
            len: BlobLen::new(8).unwrap()
        }
    );
}

#[test]
fn write_put_blob_refuses_a_payload_over_128_mib() {
    let oversized = vec![0_u8; usize::try_from(MAX_BLOB_BYTES + 1).unwrap()];
    let mut out = Vec::new();
    let error = write_put_blob(&mut out, DIGEST.parse().unwrap(), &oversized).unwrap_err();
    assert!(
        matches!(error, WriteError::BlobTooLarge { len } if len == MAX_BLOB_BYTES + 1),
        "{error:?}"
    );
    assert!(out.is_empty());
}

// ---- I/O failures and the agent's error mapping --------------------------

#[test]
fn io_failures_keep_their_side_and_errno() {
    let error = read_request(&mut BufReader::new(FailingIo)).unwrap_err();
    assert_eq!(error.kind(), ReadErrorKind::Io);
    assert_eq!(
        error.to_agent_error(),
        AgentError::Io {
            op: IoOp::ReadRequest,
            errno: Some(5)
        }
    );

    let mut payload: &[u8] = b"abc";
    let error = read_blob(&mut payload, BlobLen::new(3).unwrap(), &mut FailingIo).unwrap_err();
    assert_eq!(error.kind(), ReadErrorKind::Sink);
    assert_eq!(
        error.to_agent_error(),
        AgentError::Io {
            op: IoOp::WriteBlob,
            errno: Some(28)
        }
    );

    let error = read_blob(&mut FailingIo, BlobLen::new(3).unwrap(), &mut Vec::new()).unwrap_err();
    assert_eq!(error.kind(), ReadErrorKind::Io);
    assert_eq!(
        expect_end_of_input(&mut FailingIo).unwrap_err().kind(),
        ReadErrorKind::Io
    );

    let error = write_reply(&mut FailingIo, &Err(AgentError::NodeHalted)).unwrap_err();
    assert_eq!(error.kind(), WriteErrorKind::Io);
    let error = write_put_blob(&mut FailingIo, DIGEST.parse().unwrap(), b"x").unwrap_err();
    assert_eq!(error.kind(), WriteErrorKind::Io);
}

/// A reply from a compromised VPS can name unknown fields and variants
/// with terminal escapes in them; the error keeps only the decoder's
/// classification and position, so nothing the peer chose reaches a log.
#[test]
fn a_hostile_reply_cannot_put_control_characters_into_the_error() {
    let escaped = b"{\"Ok\":{\"\\u001b]0;pwned\\u0007\":null}}\n".to_vec();
    let raw = b"{\"Ok\":{\"\x1b]0;pwned\x07\":null}}\n".to_vec();
    let variant = b"{\"\\u001b[2J\":null}\n".to_vec();
    for (frame, cause) in [
        (escaped, MalformedCause::Data),
        (raw, MalformedCause::Syntax),
        (variant, MalformedCause::Data),
    ] {
        let error = read_reply(&mut Cursor::new(frame.as_slice())).unwrap_err();
        assert!(
            matches!(error, ReadError::Malformed { cause: found, line: 1, .. } if found == cause),
            "{error:?}"
        );
        let mut texts = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(&error);
        while let Some(inner) = source {
            texts.push(inner.to_string());
            source = inner.source();
        }
        for text in texts {
            assert!(!text.chars().any(char::is_control), "{text:?}");
            assert!(!text.contains("pwned") && !text.contains("[2J"), "{text:?}");
        }
    }
}
