// SPDX-License-Identifier: GPL-3.0-or-later

//! `dial-bound --interface <bsd> <address> <port>` (design §10.5): the
//! ProxyCommand of management SSH. It connects to a node through the
//! interface that faces the M7, with the socket bound to it
//! (`IP_BOUND_IF`), so the connection leaves through the M7's line and no
//! other way (P0-2), and relays its stdin and stdout over it.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::num::NonZeroU32;
use std::thread;
use std::time::Duration;

use mooring_model::iface::{BsdName, InterfaceIndex};
use mooring_model::ipv4::PublicIpv4;
use socket2::{Domain, Protocol, Socket, Type};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::node::NodeError;
use crate::router;

/// How long the connection may take to open: ssh's own `ConnectTimeout`.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// `dial-bound`: checks that the interface's default gateway is the pinned
/// M7, connects to `address:port` through it, and relays standard input
/// and output until both directions end.
pub(crate) fn dial_bound(
    env: &Env<'_>,
    interface: &BsdName,
    address: Ipv4Addr,
    port: u16,
) -> Result<(), CommandError> {
    let index = facing_the_m7(env, interface)?;
    let address = PublicIpv4::new(address).map_err(LocalError::NodeAddress)?;
    let stream = connect(index, SocketAddrV4::new(address.get(), port))?;
    relay(stream, io::stdin(), io::stdout()).map_err(|error| NodeError::Relay(error).into())
}

/// The index of `interface`, after checking that its default gateway is
/// the pinned M7: the check `exit init` makes, so management traffic
/// leaves only through the M7.
pub(crate) fn facing_the_m7(
    env: &Env<'_>,
    interface: &BsdName,
) -> Result<InterfaceIndex, CommandError> {
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
    Ok(candidate.attachment.index)
}

/// A TCP connection to `target` bound to the interface `index`.
pub(crate) fn connect(index: InterfaceIndex, target: SocketAddrV4) -> Result<TcpStream, NodeError> {
    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(NodeError::Connect)?;
    socket
        .bind_device_by_index_v4(Some(NonZeroU32::from(index)))
        .map_err(NodeError::Connect)?;
    socket
        .connect_timeout(&SocketAddr::V4(target).into(), CONNECT_TIMEOUT)
        .map_err(NodeError::Connect)?;
    Ok(socket.into())
}

/// Copies `input` to the connection and the connection to `output`, each
/// in its own thread, until both directions end: the end of `input` shuts
/// the connection's sending half, and the peer's end finishes `output`.
pub(crate) fn relay(
    stream: TcpStream,
    mut input: impl Read + Send,
    mut output: impl Write + Send,
) -> io::Result<()> {
    let mut sending = stream.try_clone()?;
    let mut receiving = stream;
    thread::scope(|scope| {
        let sender = scope.spawn(move || -> io::Result<()> {
            io::copy(&mut input, &mut sending)?;
            sending.shutdown(Shutdown::Write)
        });
        let received = io::copy(&mut receiving, &mut output).and_then(|_| output.flush());
        let sent = sender
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("the sending thread panicked")));
        received.and(sent)
    })
}
