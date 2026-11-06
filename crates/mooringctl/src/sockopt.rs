// SPDX-License-Identifier: GPL-3.0-or-later

//! Options set on a connected TCP stream, read alike whether or not its
//! connection has ended first.

use std::io::{self, ErrorKind};
use std::net::TcpStream;

/// What `set`, the outcome of setting an option on `stream`, comes to.
///
/// macOS refuses every option, with EINVAL ("The socket has been shut
/// down", `setsockopt(2)`), once both directions of a stream are shut: a
/// reset shuts them (1,000 resets of 1,000 on this Mac, 2026-11-06), and
/// so do a dropped connection and a close from each end. Linux sets the
/// option. Such a stream needs none of the options set on streams here,
/// the timeouts, nodelay and linger: a read on it returns at once, with
/// what had arrived, then the error that ended it if there is one, then
/// the end, and a write fails at once. So that refusal, on a stream that
/// has no peer left, is `Ok`, and the stream's next read or write reports
/// it as it would have with the option set: a line that came before a
/// reset is still read. Any other refusal, and that one on a stream that
/// still has its peer, is returned as it is. fieldkit's `net.rs` and the
/// agent's sampler (`target/sampler.rs`) read a refusal the same way.
pub(crate) fn option_outcome(stream: &TcpStream, set: io::Result<()>) -> io::Result<()> {
    match set {
        Err(refusal)
            if refusal.kind() == ErrorKind::InvalidInput
                && refusal.raw_os_error().is_some()
                && stream.peer_addr().is_err() =>
        {
            Ok(())
        }
        set => set,
    }
}
