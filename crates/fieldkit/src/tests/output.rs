// SPDX-License-Identifier: GPL-3.0-or-later

//! The output streams and the errors' messages.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::error::FieldkitError;
use crate::output::Output;

#[test]
fn records_are_json_lines_and_notes_go_to_stderr() {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let mut output = Output::new(&mut stdout, &mut stderr);
    output.record(&serde_json::json!({"a": 1})).unwrap();
    output.record(&[1, 2]).unwrap();
    output.note("100 connections held").unwrap();
    assert_eq!(stdout, b"{\"a\":1}\n[1,2]\n");
    assert_eq!(stderr, b"fieldkit: 100 connections held\n");
}

struct Broken;

impl io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken pipe"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_output_that_cannot_be_written_is_an_error() {
    let (mut broken, mut also) = (Broken, Broken);
    let mut output = Output::new(&mut broken, &mut also);
    assert!(matches!(
        output.record(&1),
        Err(FieldkitError::Output { .. })
    ));
    assert!(matches!(
        output.note("x"),
        Err(FieldkitError::Output { .. })
    ));
}

#[test]
fn errors_name_the_peer_and_what_failed() {
    let peer = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 27950);
    assert_eq!(
        FieldkitError::Silent { peer }.to_string(),
        "203.0.113.7:27950 never answered an echo request; is `fieldkit serve` running and its port open?"
    );
    assert_eq!(
        FieldkitError::OpenFilesLimit {
            have: 256,
            want: 8256
        }
        .to_string(),
        "the open-files limit is 256, below the 8256 this measurement needs"
    );
    assert_eq!(
        FieldkitError::peer(peer, "connect", io::Error::other("refused")).to_string(),
        "203.0.113.7:27950: connect: refused"
    );
}
