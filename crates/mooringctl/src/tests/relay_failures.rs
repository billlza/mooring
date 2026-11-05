// SPDX-License-Identifier: GPL-3.0-or-later

//! The relay between standard input and output and a connection (design
//! §10.5) when its input fails: an interrupted read is read again, any
//! other failure is the relay's, and a sending thread that panicked is
//! reported as such. Its copying otherwise is the node tests'.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

use crate::node::dial::relay;

/// Input that is interrupted once, then gives `data`, then fails.
struct Flaky {
    steps: Vec<io::Result<&'static [u8]>>,
}

impl Read for Flaky {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.steps.remove(0)?;
        buf[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }
}

/// A connection whose peer has finished sending, and that peer.
fn peer_done_sending() -> (UnixStream, UnixStream) {
    let (ours, peer) = UnixStream::pair().unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    (ours, peer)
}

#[test]
fn an_interrupted_read_is_read_again_and_a_failed_one_ends_the_relay() {
    let (ours, mut peer) = peer_done_sending();
    let input = Flaky {
        steps: vec![
            Err(io::Error::from(io::ErrorKind::Interrupted)),
            Ok(b"sent"),
            Err(io::Error::other("the terminal went away")),
        ],
    };
    let error = relay(ours, input, Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "the terminal went away");
    let mut received = [0_u8; 4];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"sent");
    // The same input ending instead: the relay ends with it, and the peer
    // sees the end of what was sent.
    let (ours, mut peer) = peer_done_sending();
    let input = Flaky {
        steps: vec![
            Err(io::Error::from(io::ErrorKind::Interrupted)),
            Ok(b"sent"),
            Ok(b""),
        ],
    };
    relay(ours, input, Vec::new()).unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"sent");
}

/// Input whose read panics.
struct Panicking;

impl Read for Panicking {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        std::panic::resume_unwind(Box::new("the input broke"))
    }
}

#[test]
fn a_sending_thread_that_panicked_is_the_relay_s_failure() {
    let (ours, _peer) = peer_done_sending();
    let mut output = Vec::new();
    let error = relay(ours, Panicking, &mut output).unwrap_err();
    assert_eq!(error.to_string(), "the sending thread panicked");
    output.flush().unwrap();
    assert!(output.is_empty());
}
