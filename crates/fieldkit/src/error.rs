// SPDX-License-Identifier: GPL-3.0-or-later

//! The tool's typed errors. A measurement that cannot be made fails with
//! one of these and exit status 1; a measurement that finds an answer,
//! however bad (no keepalive fits, the server's limit is lower than the
//! carrier's), reports it and exits 0.

use std::io;
use std::net::SocketAddrV4;

use crate::wire::WireError;

/// Why the tool stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FieldkitError {
    /// The interface to bind to cannot be used.
    #[error("interface {name}: {reason}")]
    Interface {
        /// Its name.
        name: String,
        /// What is wrong.
        reason: String,
    },
    /// A socket could not be made, bound or set up.
    #[error("socket setup ({what}) failed: {source}")]
    Socket {
        /// What was being done.
        what: &'static str,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// A peer could not be reached or stopped answering.
    #[error("{peer}: {what}: {source}")]
    Peer {
        /// The peer.
        peer: SocketAddrV4,
        /// What was being done.
        what: &'static str,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// A peer answered with something that is not of the protocol.
    #[error("{peer} answered outside the protocol: {source}")]
    Protocol {
        /// The peer.
        peer: SocketAddrV4,
        /// What was wrong.
        #[source]
        source: WireError,
    },
    /// No answer came from the echo server at all, so nothing can be
    /// measured against it.
    #[error(
        "{peer} never answered an echo request; is `fieldkit serve` running and its port open?"
    )]
    Silent {
        /// The server.
        peer: SocketAddrV4,
    },
    /// The open-files limit is below what the measurement needs.
    #[error("the open-files limit is {have}, below the {want} this measurement needs")]
    OpenFilesLimit {
        /// The limit in force.
        have: u64,
        /// The limit needed.
        want: u64,
    },
    /// The open-files limit could not be read or raised.
    #[error("the open-files limit: {reason}")]
    Limit {
        /// What failed.
        reason: String,
    },
    /// A file named on the command line could not be read or parsed.
    #[error("{path}: {reason}")]
    Input {
        /// The path.
        path: String,
        /// What failed.
        reason: String,
    },
    /// The output could not be written.
    #[error("writing the output failed: {source}")]
    Output {
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// A thread of the measurement or server failed.
    #[error("a worker thread stopped: {what}")]
    Worker {
        /// Which.
        what: &'static str,
    },
    /// The system clock reads before 1970.
    #[error("the system clock reads before 1970")]
    Clock,
    /// A measured value breaks one of the model's rules.
    #[error("a measured value breaks the model's rule: {0}")]
    Model(#[from] mooring_model::ModelError),
}

impl FieldkitError {
    /// A socket setup error.
    pub(crate) const fn socket(what: &'static str, source: io::Error) -> Self {
        Self::Socket { what, source }
    }

    /// An error talking to `peer`.
    pub(crate) const fn peer(peer: SocketAddrV4, what: &'static str, source: io::Error) -> Self {
        Self::Peer { peer, what, source }
    }
}
