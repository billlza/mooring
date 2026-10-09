// SPDX-License-Identifier: GPL-3.0-or-later

//! Byte-exact wire goldens in `contract/agent-proto-golden/`, shared by the
//! frozen upgrade core (`frozen_core`) and the other protocol-1 frames
//! (`protocol_goldens`).
//!
//! A snapshot holds the line without its terminator (insta trims trailing
//! whitespace); `golden_line` separately requires that the frame is that
//! line plus exactly one `\n`, and that the line has no other whitespace at
//! its edges and no line breaks, so the comparison is exact. Each golden
//! module calls `insta::assert_snapshot!` itself, so a snapshot's `source`
//! names the module that pins it.

use std::io::Cursor;

use mooring_agent_proto::{
    LineRequest, Reply, Request, RequestKind, read_reply, read_request, write_reply, write_request,
};

/// Which frame of an exchange a golden pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Frame {
    Request,
    Response,
}

/// Builds one frame, checking that it reads back.
pub(crate) type BuildFrame = fn() -> Vec<u8>;

/// A golden: the exchange, the frame, and the function that builds it.
pub(crate) type Golden = (RequestKind, Frame, BuildFrame);

/// The frame's line: `frame` without its single terminating `\n`, checked
/// to be one line with no whitespace at its edges.
pub(crate) fn golden_line<'a>(name: &str, frame: &'a [u8]) -> &'a str {
    let frame = std::str::from_utf8(frame).unwrap();
    let line = frame
        .strip_suffix('\n')
        .expect("a frame ends with a newline");
    assert!(!line.contains(['\n', '\r']), "{name}: one line");
    assert_eq!(line.trim(), line, "{name}: no edge whitespace");
    line
}

/// The insta settings of `contract/agent-proto-golden/`, with
/// `description` (which starts with the SPDX line) in each snapshot.
pub(crate) fn golden_settings(description: &str) -> insta::Settings {
    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path("../../../../contract/agent-proto-golden");
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.set_description(description);
    settings
}

pub(crate) fn request_frame(request: &LineRequest) -> Vec<u8> {
    let mut frame = Vec::new();
    write_request(&mut frame, request).unwrap();
    assert_eq!(
        read_request(&mut Cursor::new(frame.as_slice())).unwrap(),
        Request::Line(request.clone())
    );
    frame
}

pub(crate) fn reply_frame(reply: &Reply) -> Vec<u8> {
    let mut frame = Vec::new();
    write_reply(&mut frame, reply).unwrap();
    assert_eq!(
        read_reply(&mut Cursor::new(frame.as_slice())).unwrap(),
        *reply
    );
    frame
}

/// The snapshot name of a golden: the request kind in snake case, then
/// `.request` or `.response`.
pub(crate) fn golden_name(kind: RequestKind, frame: Frame) -> String {
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
