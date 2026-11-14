// SPDX-License-Identifier: GPL-3.0-or-later

//! A write on the control socket whose peer has gone (design §10.1). The
//! daemon writes to clients that may close at any time, and the CLI writes
//! its request to a daemon that, when it is busy, has refused it and
//! closed without reading. Both ends read such a write's failure here, so
//! that they agree on which failures say that the peer has gone.

use std::io::ErrorKind;

/// Whether a write that failed with `kind` found the socket's peer gone.
///
/// A write begun after the peer closed fails with a broken pipe. On macOS
/// one that the close overtakes can fail with "not connected" (`ENOTCONN`)
/// instead. Measured on macOS 27.2 on 2026-11-12, 3000 writes for each
/// schedule: 22 of the writes that a close landed in while they waited for
/// room, 3 of the 1500-byte writes racing a close, and none of the writes
/// begun after it. The CLI's request to a daemon that refused it and
/// closed met it 5 times in 3000, and reported an I/O error where the
/// refusal was there to read. A reset was not seen on a Unix socket here,
/// and is read the same way, as it was before "not connected" was. No
/// other kind says that the peer has gone: a timeout, a full buffer and a
/// refused permission are the failures they are.
#[must_use]
pub(crate) const fn gone(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::BrokenPipe | ErrorKind::NotConnected | ErrorKind::ConnectionReset
    )
}
