// SPDX-License-Identifier: GPL-3.0-or-later

//! Management connections to a node through the M7 (design §10.5).
//!
//! The process that starts ssh checks that the interface's default gateway
//! is the pinned M7 ([`facing_the_m7`]) and opens the TCP connection itself,
//! bound to that interface (`IP_BOUND_IF`), so the connection leaves through
//! the M7's line and no other way (P0-2). ssh reaches that connection
//! through its ProxyCommand, `mooringctl ssh-relay <socket>` ([`ssh_relay`]),
//! which connects to a one-time Unix socket in the node's private directory
//! and relays its standard input and output there; the process that opened
//! the connection splices the socket to it ([`RelaySocket`]).
//!
//! The ProxyCommand used to check and dial by itself. On macOS 27.0.1, on
//! 2026-10-23, the kernel's neighbour table, which proves that the gateway
//! is the M7, was empty to it under `mooringctl`'s ssh, while `mooringctl`
//! itself, ssh and a ProxyCommand under a shell's ssh all read it; so the
//! check and the connection moved to the process that starts ssh.

use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::num::NonZeroU32;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use mooring_model::iface::{BsdName, InterfaceIndex};
use socket2::{Domain, Protocol, Socket, Type};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::router;

/// How long the connection may take to open: ssh's own `ConnectTimeout`.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// An interface whose default gateway [`facing_the_m7`] found to be the
/// pinned M7. Only that check makes one, so a management connection cannot
/// be opened through an interface nobody checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct M7Egress {
    index: InterfaceIndex,
}

impl M7Egress {
    /// The interface's index, which connections bind to.
    pub(crate) fn index(self) -> InterfaceIndex {
        self.index
    }

    /// An egress for tests, which have no M7 to check.
    #[cfg(test)]
    pub(crate) fn for_tests(index: InterfaceIndex) -> Self {
        Self { index }
    }
}

/// `interface`, after checking that its default gateway is the pinned M7:
/// the check `exit init` makes, so management traffic leaves only through
/// the M7.
pub(crate) fn facing_the_m7(env: &Env<'_>, interface: &BsdName) -> Result<M7Egress, CommandError> {
    let pinned = router::pinned_address(&support_dir(env)?)?;
    let candidate = router::pin_candidate(&env.router, interface)?;
    if candidate.lladdr != pinned {
        return Err(LocalError::EgressNotTheRouter {
            interface: interface.clone(),
            found: candidate.lladdr,
            pinned,
        }
        .into());
    }
    Ok(M7Egress {
        index: candidate.attachment.index,
    })
}

/// A TCP connection to `target` through `egress`, bound to its interface,
/// opened within `timeout`.
pub(crate) fn connect(
    egress: &M7Egress,
    target: SocketAddrV4,
    timeout: Duration,
) -> Result<TcpStream, NodeError> {
    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(NodeError::Connect)?;
    socket
        .bind_device_by_index_v4(Some(NonZeroU32::from(egress.index())))
        .map_err(NodeError::Connect)?;
    socket
        .connect_timeout(&SocketAddr::V4(target).into(), timeout)
        .map_err(NodeError::Connect)?;
    Ok(socket.into())
}

/// `ssh-relay <socket>`, management SSH's ProxyCommand: connects to the
/// one-time socket of the process that started ssh, and relays standard
/// input and output over it until both directions end.
pub(crate) fn ssh_relay(socket: &Path) -> Result<(), CommandError> {
    let stream = UnixStream::connect(socket).map_err(NodeError::Relay)?;
    relay(stream, io::stdin(), io::stdout()).map_err(|error| NodeError::Relay(error).into())
}

/// A stream whose two halves are used from two threads.
pub(crate) trait Duplex: Read + Write + Send + Sized {
    /// Another handle on the same stream.
    fn try_clone(&self) -> io::Result<Self>;

    /// Shuts one or both halves.
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

impl Duplex for TcpStream {
    fn try_clone(&self) -> io::Result<Self> {
        TcpStream::try_clone(self)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }
}

impl Duplex for UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        UnixStream::try_clone(self)
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        UnixStream::shutdown(self, how)
    }
}

/// Copies `input` to the connection and the connection to `output`, each
/// in its own thread, until both directions end: the end of `input` shuts
/// the connection's sending half, and the peer's end finishes `output`.
pub(crate) fn relay(
    stream: impl Duplex,
    mut input: impl Read + Send,
    mut output: impl Write + Send,
) -> io::Result<()> {
    let mut sending = stream.try_clone()?;
    let mut receiving = stream;
    thread::scope(|scope| {
        let sender = scope.spawn(move || -> io::Result<()> {
            io::copy(&mut input, &mut sending)?;
            shut_sending(&sending)
        });
        let received = io::copy(&mut receiving, &mut output).and_then(|_| output.flush());
        let sent = sender
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the sending thread panicked")));
        received.and(sent)
    })
}

/// Joins `helper` (the ProxyCommand's end) and `node` (the connection to
/// the node) until both directions end: each direction's end shuts the
/// other side's sending half, so ssh's end reaches the node, and the
/// node's end reaches the ProxyCommand, which then exits.
fn splice(helper: UnixStream, node: TcpStream) -> io::Result<()> {
    let mut from_helper = helper.try_clone()?;
    let mut to_helper = helper;
    let mut from_node = node.try_clone()?;
    let mut to_node = node;
    thread::scope(|scope| {
        let up = scope.spawn(move || -> io::Result<()> {
            io::copy(&mut from_helper, &mut to_node)?;
            shut_sending(&to_node)
        });
        let down = io::copy(&mut from_node, &mut to_helper).and_then(|_| shut_sending(&to_helper));
        let up = up
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the splicing thread panicked")));
        down.and(up)
    })
}

/// Shuts `stream`'s sending half. A stream whose peer has gone, or which
/// [`RelaySocket::stop`] shut, has none left to shut: that is no failure.
fn shut_sending(stream: &impl Duplex) -> io::Result<()> {
    match stream.shutdown(Shutdown::Write) {
        Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
        shut => shut,
    }
}

/// Tells one process's relay sockets apart.
static RELAY_SOCKETS: AtomicU64 = AtomicU64::new(0);

/// How often a relay socket waiting for its ProxyCommand looks whether ssh
/// has ended.
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// How [`RelaySocket::serve`] ended.
#[derive(Debug)]
pub(crate) enum Served {
    /// The ProxyCommand connected, and the splice ended so.
    Spliced(io::Result<()>),
    /// ssh ended before its ProxyCommand connected.
    Stopped,
}

/// The one-time socket through which ssh's ProxyCommand reaches a
/// connection this process opened: bound in a private directory (the
/// node's, mode 0700), it accepts one connection and is unlinked as soon
/// as that connection arrives.
#[derive(Debug)]
pub(crate) struct RelaySocket {
    path: PathBuf,
    listener: UnixListener,
    stopping: AtomicBool,
}

impl RelaySocket {
    /// Binds a socket of a name no other socket of this process has, in
    /// `dir`, which must be private to the operator.
    pub(crate) fn bind(dir: &Path) -> Result<Self, NodeError> {
        let number = RELAY_SOCKETS.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("relay-{}-{number}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).map_err(NodeError::Relay)?;
        let socket = Self {
            path,
            listener,
            stopping: AtomicBool::new(false),
        };
        // Waiting for the ProxyCommand looks at `stopping` between tries.
        socket
            .listener
            .set_nonblocking(true)
            .map_err(NodeError::Relay)?;
        Ok(socket)
    }

    /// The socket's path, for the ProxyCommand.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Waits for the ProxyCommand, unlinks the socket, and splices the
    /// ProxyCommand to `node` until both directions end; after
    /// [`Self::stop`] it waits no longer. An error is the socket's own
    /// (accepting, unlinking); how the splice ended is in
    /// [`Served::Spliced`].
    pub(crate) fn serve(&self, node: TcpStream) -> io::Result<Served> {
        let helper = loop {
            match self.listener.accept() {
                Ok((helper, _)) => break helper,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if self.stopping.load(Ordering::SeqCst) {
                        return Ok(Served::Stopped);
                    }
                    thread::sleep(ACCEPT_POLL);
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        };
        self.unlink()?;
        // A socket accepted from a non-blocking listener is non-blocking
        // on macOS; the splice blocks.
        helper.set_nonblocking(false)?;
        Ok(Served::Spliced(splice(helper, node)))
    }

    /// Ends [`Self::serve`] once ssh has ended: a serve still waiting for
    /// the ProxyCommand returns, and `node`, another handle on the
    /// connection it splices, is shut, so a node that keeps its end open
    /// cannot hold the splice.
    pub(crate) fn stop(&self, node: &TcpStream) -> io::Result<()> {
        self.stopping.store(true, Ordering::SeqCst);
        match node.shutdown(Shutdown::Both) {
            Err(error) if error.kind() != ErrorKind::NotConnected => Err(error),
            _ => Ok(()),
        }
    }

    /// Removes the socket's path; one that is gone already is fine.
    fn unlink(&self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

impl Drop for RelaySocket {
    /// A session that failed before its ProxyCommand connected leaves no
    /// socket behind. The session's own error is the one reported, so a
    /// failure to remove the path here has nowhere to go.
    fn drop(&mut self) {
        let _ = self.unlink();
    }
}
