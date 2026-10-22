// SPDX-License-Identifier: GPL-3.0-or-later

//! The command line and what each command does.

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::process::ExitCode;

use mooring_agent_proto::{AgentError, Generation, HostProfile, PROTOCOL, Role};

use crate::host::Node;
use crate::paths::Paths;
use crate::serve::Session;
use crate::{fail, gate, reflect, serve, store, txn, watch};

/// The reflector's port (design §5.3).
const REFLECTOR_PORT: u16 = 27900;

/// A command line, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Invocation {
    /// `serve-ssh --role <role>`.
    ServeSsh(Role),
    /// `reflect --listen <vps4> [--port <port>]`.
    Reflect(SocketAddrV4),
    /// `halted-check`.
    HaltedCheck,
    /// `gate-close`.
    GateClose,
    /// `self-test`.
    SelfTest,
    /// `txn <N>`, the transaction unit.
    Txn(Generation),
    /// `txn-revert <N>`, the confirm timer.
    TxnRevert(Generation),
    /// `txn-recover`, at boot.
    TxnRecover,
    /// `watch`, the `mooring-watch` unit.
    Watch,
}

/// Parses the arguments after the program name.
pub(crate) fn parse(args: &[String]) -> Result<Invocation, String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["serve-ssh", "--role", role] => role
            .parse::<Role>()
            .map(Invocation::ServeSsh)
            .map_err(|_| format!("unknown role {role:?}")),
        ["reflect", "--listen", address] => listen(address, None),
        ["reflect", "--listen", address, "--port", port] => listen(address, Some(port)),
        ["halted-check"] => Ok(Invocation::HaltedCheck),
        ["gate-close"] => Ok(Invocation::GateClose),
        ["self-test"] => Ok(Invocation::SelfTest),
        ["txn", generation] => generation_arg(generation).map(Invocation::Txn),
        ["txn-revert", generation] => generation_arg(generation).map(Invocation::TxnRevert),
        ["txn-recover"] => Ok(Invocation::TxnRecover),
        ["watch"] => Ok(Invocation::Watch),
        _ => Err("usage: mooring-agent serve-ssh --role <bootstrap|ops|viewer> | reflect --listen <ipv4> [--port <port>] | halted-check | gate-close | self-test | txn <N> | txn-revert <N> | txn-recover | watch".to_owned()),
    }
}

/// A generation number: digits only, at least 1.
fn generation_arg(text: &str) -> Result<Generation, String> {
    text.bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| text.parse::<u64>().ok())
        .flatten()
        .filter(|&generation| generation > 0)
        .map(Generation::new)
        .ok_or_else(|| format!("{text:?} is not a generation"))
}

fn listen(address: &str, port: Option<&str>) -> Result<Invocation, String> {
    let ip: Ipv4Addr = address
        .parse()
        .map_err(|_| format!("{address:?} is not an IPv4 address"))?;
    let port = match port {
        None => REFLECTOR_PORT,
        Some(port) => port
            .parse()
            .map_err(|_| format!("{port:?} is not a port"))?,
    };
    Ok(Invocation::Reflect(SocketAddrV4::new(ip, port)))
}

/// Runs one invocation against `paths` and `node`.
pub(crate) fn run(
    invocation: Invocation,
    paths: &Paths,
    node: &dyn Node,
    stderr: &mut dyn Write,
) -> ExitCode {
    match invocation {
        Invocation::ServeSsh(role) => {
            let connection = std::env::var("SSH_CONNECTION").ok();
            let session = Session {
                role,
                ssh_connection: connection.as_deref(),
            };
            let mut input = io::stdin().lock();
            let mut output = io::stdout().lock();
            match serve::serve(paths, node, session, &mut input, &mut output) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(stderr, &format!("writing the reply failed: {error}")),
            }
        }
        Invocation::Reflect(address) => {
            match TcpListener::bind(address).and_then(|listener| reflect::serve(&listener)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(stderr, &format!("the reflector stopped: {error}")),
            }
        }
        Invocation::HaltedCheck => {
            if gate::may_start_engines(paths) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Invocation::GateClose => {
            let closed =
                store::Lock::exclusive(&paths.gate_lock()).and_then(|_lock| gate::close(node));
            match closed {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(stderr, &format!("closing the gate failed: {error}")),
            }
        }
        Invocation::Txn(generation) => match txn::run(paths, node, generation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(
                stderr,
                &format!("transaction {} could not run: {error}", generation.get()),
            ),
        },
        Invocation::TxnRevert(generation) => {
            match txn::revert_pending(paths, node, txn::Why::Unconfirmed(generation)) {
                // Confirmed, rolled back or failed before the timer fired.
                Ok(_) | Err(AgentError::NotAwaitingConfirm) => ExitCode::SUCCESS,
                Err(error) => fail(
                    stderr,
                    &format!("reverting {} failed: {error}", generation.get()),
                ),
            }
        }
        Invocation::Watch => watch::run(paths, node, stderr),
        Invocation::TxnRecover => match txn::revert_pending(paths, node, txn::Why::Rebooted) {
            // Nothing was pending.
            Ok(_) | Err(AgentError::NotAwaitingConfirm) => ExitCode::SUCCESS,
            Err(error) => fail(
                stderr,
                &format!("reverting the change pending at boot failed: {error}"),
            ),
        },
        Invocation::SelfTest => match self_test(paths) {
            Ok(()) => {
                let printed = writeln!(io::stdout().lock(), "{PROTOCOL}");
                if printed.is_ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(error) => fail(stderr, &format!("self-test failed: {error}")),
        },
    }
}

/// The self-test `ActivateAgent` runs on a new agent before switching to
/// it (design §11.2): the embedded host profile renders, and the state
/// files this agent reads parse.
pub(crate) fn self_test(paths: &Paths) -> Result<(), AgentError> {
    let _files = HostProfile::CURRENT.files();
    gate::holds(paths)?;
    gate::halted(paths)?;
    Ok(())
}
