// SPDX-License-Identifier: GPL-3.0-or-later

//! The Mac's side of a node (design §10.5, §11.1, §13.2): management SSH,
//! bound to the interface that faces the M7, and the agent's requests over
//! it, one per session.

pub(crate) mod adopt;
pub(crate) mod apply;
pub(crate) mod dial;
pub(crate) mod engines;
pub(crate) mod files;
pub(crate) mod new;
pub(crate) mod session;
pub(crate) mod ssh;
pub(crate) mod target;

use std::collections::BTreeSet;
use std::io;

use mooring_agent_proto::{
    AgentError, LineRequest, ReadError, RequestKind, Response, ResponseKind, Sha256Hex, WriteError,
};

/// One node's agent: each call is one request and its reply.
pub(crate) trait AgentLink {
    /// Sends `request` and returns the agent's reply; the agent's own
    /// refusal is [`NodeError::Agent`].
    fn request(&mut self, request: &LineRequest) -> Result<Response, NodeError>;

    /// Uploads `payload` as the blob `sha256`.
    fn put_blob(&mut self, sha256: Sha256Hex, payload: &[u8]) -> Result<Response, NodeError>;
}

/// Uploads every blob of `wanted` the node does not hold, asking first with
/// `HaveBlobs` (design §11.1); `source` gives each missing blob's bytes.
/// Returns how many were uploaded.
pub(crate) fn upload_missing(
    session: &mut dyn NodeSession,
    wanted: BTreeSet<Sha256Hex>,
    mut source: impl FnMut(&Sha256Hex) -> Result<Vec<u8>, crate::error::LocalError>,
) -> Result<usize, crate::error::CommandError> {
    let reply = session.request(&LineRequest::HaveBlobs {
        blobs: wanted.clone(),
    })?;
    let Response::Blobs { present } = reply else {
        return Err(NodeError::Unexpected {
            request: RequestKind::HaveBlobs,
            response: reply.kind(),
        }
        .into());
    };
    let mut uploaded = 0;
    for sha256 in wanted.difference(&present) {
        let bytes = source(sha256)?;
        let reply = session.put_blob(*sha256, &bytes)?;
        if reply != (Response::BlobStored { sha256: *sha256 }) {
            return Err(NodeError::Unexpected {
                request: RequestKind::PutBlob,
                response: reply.kind(),
            }
            .into());
        }
        uploaded += 1;
    }
    Ok(uploaded)
}

/// One node as one [`ssh::SshTarget`] reaches it: agent requests, and the
/// two other kinds of session adoption needs.
pub(crate) trait NodeSession: AgentLink {
    /// Runs the target's remote command with `input` on its stdin; it must
    /// print nothing and exit 0.
    fn run(&mut self, input: &[u8]) -> Result<(), NodeError>;

    /// The reply to a session with nothing on its stdin, which the agent
    /// answers `UnknownRequest` when the forced command runs it.
    fn empty_request(&mut self) -> Result<Response, NodeError>;
}

/// How the Mac reaches nodes: `/usr/bin/ssh` in the binary
/// ([`ssh::SshLinks`]), a script in tests.
pub(crate) trait NodeLinks {
    /// The sessions to `target`.
    fn open(&self, target: ssh::SshTarget) -> Box<dyn NodeSession + '_>;
}

/// A failure between the Mac and a node's agent.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NodeError {
    /// `/usr/bin/ssh` could not be started or waited for.
    #[error("cannot run /usr/bin/ssh")]
    Spawn(#[source] io::Error),
    /// One of ssh's pipes was missing or its reader failed.
    #[error("the ssh session's pipes failed")]
    Pipe,
    /// Reading the session's output failed.
    #[error("reading the ssh session's output failed")]
    Read(#[source] io::Error),
    /// The session ended without a reply: ssh could not connect, log in or
    /// check the host key, or the remote side printed nothing. Its stderr
    /// is escaped (design §10.5).
    #[error(
        "ssh ended without a reply (exit status {}):\n{stderr}",
        code.map_or_else(|| "none".to_owned(), |code| code.to_string())
    )]
    Ssh {
        /// ssh's exit status, if it exited.
        code: Option<i32>,
        /// Its stderr, escaped and capped.
        stderr: String,
    },
    /// The request could not be encoded.
    #[error("the request could not be encoded")]
    Encode(#[source] WriteError),
    /// The reply was not one line of a reply within the limits.
    #[error("the agent's reply could not be read")]
    Reply(#[source] ReadError),
    /// The agent refused the request.
    #[error("the agent refused the request")]
    Agent(#[source] AgentError),
    /// The agent answered with a reply to another request.
    #[error("the agent answered {request:?} with {response:?}")]
    Unexpected {
        /// The request sent.
        request: RequestKind,
        /// The reply's kind.
        response: ResponseKind,
    },
    /// The connection to the node through the M7 could not be opened.
    #[error("cannot connect to the node through the M7")]
    Connect(#[source] io::Error),
    /// Relaying the connection failed.
    #[error("relaying the connection to the node failed")]
    Relay(#[source] io::Error),
}
