// SPDX-License-Identifier: GPL-3.0-or-later

//! Management SSH from the Mac (design §10.5): `/usr/bin/ssh` with the
//! design's options over a connection this process opened through the M7
//! ([`crate::node::dial`]), and one agent request per session, as the
//! forced command serves one (§11.1).
//!
//! Each session opens its own connection to the node before ssh starts,
//! bound to the egress its caller checked; ssh's ProxyCommand,
//! `mooringctl ssh-relay`, reaches that connection through a one-time
//! socket in the node's private directory, and this process splices the
//! two.
//!
//! A target with a deadline (the sleep drain's, design §10.3) opens its
//! connection within what is left of it, and runs each session in a
//! process group of its own, which is killed when the deadline passes:
//! ssh's own timeouts (`ConnectTimeout`, the server-alive probes) allow a
//! session far longer than the drain's budget, and the group ends the
//! ProxyCommand with ssh. A target without one runs as before, in the
//! caller's group, so a terminal's Ctrl-C still ends ssh with `mooringctl`.

use std::ffi::OsString;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use mooring_agent_proto::{
    LineRequest, MAX_RESPONSE_LINE_BYTES, Response, Sha256Hex, read_reply, write_put_blob,
    write_request,
};
use mooring_macsys::GroupKill;
use mooring_model::ipv4::PublicIpv4;

use crate::node::dial::{CONNECT_TIMEOUT, M7Egress, RelaySocket, Served};
use crate::node::{AgentLink, NodeError, NodeLinks, NodeSession};

/// The ssh binary: OpenSSH as macOS ships it (OpenSSH_10.3p1 on this Mac).
pub(crate) const SSH: &str = "/usr/bin/ssh";

/// The most stderr bytes kept from one session, after escaping.
pub(crate) const MAX_STDERR_BYTES: usize = 4096;

/// The port every node's sshd listens on.
pub(crate) const SSH_PORT: u16 = 22;

/// How a session opens its connection to a node:
/// [`crate::node::dial::connect`] in the binary, a local listener in tests.
pub(crate) type Connect =
    dyn Fn(&M7Egress, SocketAddrV4, Duration) -> Result<TcpStream, NodeError> + Sync;

/// What runs at the other end of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Remote {
    /// The key's forced command: the agent in its role.
    ForcedCommand,
    /// An explicit command, for the one session of an existing VPS's
    /// bootstrap that logs in with the operator's own root key.
    Command(String),
}

/// One node as management SSH reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshTarget {
    /// The node's address.
    pub(crate) address: PublicIpv4,
    /// The private key to log in with.
    pub(crate) identity: PathBuf,
    /// The node's pinned host key, as a known-hosts file.
    pub(crate) known_hosts: PathBuf,
    /// The Mac's interface to the M7, checked, which each session's
    /// connection is bound to.
    pub(crate) egress: M7Egress,
    /// The node's private directory (mode 0700), where each session's
    /// relay socket is.
    pub(crate) relay_dir: PathBuf,
    /// This mooringctl, which ssh runs as its ProxyCommand.
    pub(crate) mooringctl: PathBuf,
    /// What the session runs.
    pub(crate) remote: Remote,
    /// When set, the instant by which each session ends: past it ssh and
    /// its ProxyCommand are killed, and the session fails as
    /// [`NodeError::PastDeadline`] unless its reply had arrived whole.
    pub(crate) deadline: Option<Instant>,
}

impl SshTarget {
    /// The ssh command line (design §10.5) for a session whose relay socket
    /// is `relay`, with `BatchMode` so that ssh never asks at the terminal.
    pub(crate) fn args(&self, relay: &Path) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["-F".into(), "/dev/null".into(), "-i".into()];
        args.push(self.identity.clone().into_os_string());
        let mut proxy = OsString::from("ProxyCommand=");
        proxy.push(quoted(&self.mooringctl));
        proxy.push(" ssh-relay ");
        proxy.push(quoted(relay));
        let mut known_hosts = OsString::from("UserKnownHostsFile=");
        known_hosts.push(quoted(&self.known_hosts));
        for option in [
            OsString::from("IdentitiesOnly=yes"),
            proxy,
            known_hosts,
            "StrictHostKeyChecking=yes".into(),
            "PasswordAuthentication=no".into(),
            "KbdInteractiveAuthentication=no".into(),
            "ClearAllForwardings=yes".into(),
            "ForwardAgent=no".into(),
            "ConnectTimeout=15".into(),
            "ServerAliveInterval=15".into(),
            "ServerAliveCountMax=4".into(),
            "BatchMode=yes".into(),
        ] {
            args.push("-o".into());
            args.push(option);
        }
        args.push(format!("root@{}", self.address.get()).into());
        if let Remote::Command(command) = &self.remote {
            args.push(command.into());
        }
        args
    }

    /// How long a session's connection may take to open: ssh's own
    /// `ConnectTimeout`, or what is left of the deadline when that is less.
    /// `None` once the deadline has passed.
    fn connect_within(&self) -> Option<Duration> {
        match self.deadline {
            None => Some(CONNECT_TIMEOUT),
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                (!left.is_zero()).then(|| left.min(CONNECT_TIMEOUT))
            }
        }
    }

    /// Whether the deadline, if there is one, has passed.
    fn past_deadline(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

/// `path` in single quotes for the line ssh hands to `/bin/sh` (the
/// ProxyCommand and the known-hosts file name): a quote inside is closed,
/// escaped and reopened.
fn quoted(path: &Path) -> OsString {
    let text = path.as_os_str().to_string_lossy().replace('\'', r"'\''");
    format!("'{text}'").into()
}

/// The agent behind [`SshTarget`]: each request is one ssh session over a
/// connection [`Self::connect`] opens.
pub(crate) struct SshAgent<'c> {
    pub(crate) target: SshTarget,
    pub(crate) connect: &'c Connect,
}

impl std::fmt::Debug for SshAgent<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshAgent")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl SshAgent<'_> {
    /// Runs one session that writes `input` to the remote side, and
    /// returns how ssh exited with what it printed: at most one reply line
    /// and the end of output on stdout, and stderr escaped and capped.
    ///
    /// The connection to the node opens first, within the deadline if
    /// there is one; a connection given up because the deadline passed is
    /// [`NodeError::PastDeadline`]. With the deadline, a watcher kills the
    /// session's group when it passes; the group lives until ssh is
    /// reaped, after the watcher is joined, so its id names no other
    /// group. Once ssh has closed its stdout, the relay stops: one still
    /// waiting for the ProxyCommand returns, and the node's connection is
    /// shut, which ends the ProxyCommand that holds ssh's stderr open.
    fn session(&self, input: &[u8]) -> Result<Session, NodeError> {
        let within = self
            .target
            .connect_within()
            .ok_or(NodeError::PastDeadline)?;
        let address = SocketAddrV4::new(self.target.address.get(), SSH_PORT);
        let node = (self.connect)(&self.target.egress, address, within).map_err(|error| {
            if self.target.past_deadline() {
                NodeError::PastDeadline
            } else {
                error
            }
        })?;
        let handle = node.try_clone().map_err(NodeError::Relay)?;
        let relay = RelaySocket::bind(&self.target.relay_dir)?;
        let mut command = Command::new(SSH);
        command
            .args(self.target.args(relay.path()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if self.target.deadline.is_some() {
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(NodeError::Spawn)?;
        let group = child.id();
        let mut stdin = child.stdin.take().ok_or(NodeError::Pipe)?;
        let stdout = child.stdout.take().ok_or(NodeError::Pipe)?;
        let stderr = child.stderr.take().ok_or(NodeError::Pipe)?;
        let (written, read, errors, ended, served, stopped) = std::thread::scope(|scope| {
            let served = scope.spawn(|| relay.serve(node));
            let errors = scope.spawn(|| read_capped(stderr, MAX_STDERR_BYTES * 4));
            let read = scope.spawn(|| read_capped(stdout, MAX_RESPONSE_LINE_BYTES + 2));
            let watcher = self.target.deadline.map(|deadline| {
                let (finished, finish) = mpsc::channel::<()>();
                let watcher = scope.spawn(move || end_at(deadline, group, &finish));
                (finished, watcher)
            });
            let written = stdin.write_all(input).and_then(|()| stdin.flush());
            drop(stdin);
            let read = read.join();
            let stopped = relay.stop(&handle);
            let errors = errors.join();
            let ended = watcher.map(|(finished, watcher)| {
                drop(finished);
                watcher.join()
            });
            let served = served.join();
            (written, read, errors, ended, served, stopped)
        });
        let status = child.wait().map_err(NodeError::Spawn)?;
        let past_deadline = match ended {
            None => false,
            Some(joined) => joined
                .map_err(|_| NodeError::Pipe)?
                .map_err(NodeError::End)?,
        };
        let mut stderr = escaped(
            &errors
                .map_err(|_| NodeError::Pipe)?
                .map_err(NodeError::Read)?,
        );
        let relay = match (served.map_err(|_| NodeError::Pipe)?, stopped) {
            (Err(error), _) | (Ok(_), Err(error)) => Err(NodeError::Relay(error)),
            (Ok(Served::Spliced(Err(error))), Ok(())) => {
                stderr.push_str(&format!("\n(the relay to the node ended with: {error})"));
                Ok(())
            }
            (Ok(Served::Spliced(Ok(()))) | Ok(Served::Stopped), Ok(())) => Ok(()),
        };
        Ok(Session {
            past_deadline,
            code: status.code(),
            stdout: read
                .map_err(|_| NodeError::Pipe)?
                .map_err(NodeError::Read)?,
            stderr,
            written,
            relay,
        })
    }

    /// Runs the target's remote command with `input` on its stdin, for a
    /// command that prints nothing: it must exit 0 with an empty stdout.
    fn run_command(&self, input: &[u8]) -> Result<(), NodeError> {
        self.session(input)?.ran()
    }

    /// The reply of one request session ([`Session::replied`]).
    fn reply(&self, input: &[u8]) -> Result<Response, NodeError> {
        self.session(input)?.replied()
    }
}

/// Waits until the session finishes (`finish` is disconnected) or
/// `deadline` passes, and then kills its `group`; says whether it did. A
/// group whose members were all exiting as the deadline passed ended by
/// itself, and its reply, if whole, stands.
fn end_at(
    deadline: Instant,
    group: u32,
    finish: &mpsc::Receiver<()>,
) -> Result<bool, mooring_macsys::MacsysError> {
    match finish.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Err(mpsc::RecvTimeoutError::Timeout) => {
            mooring_macsys::kill_group(group).map(|kill| kill == GroupKill::Killed)
        }
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(false),
    }
}

/// What one ssh session left.
#[derive(Debug)]
pub(crate) struct Session {
    /// Whether the session's group was killed at its deadline.
    pub(crate) past_deadline: bool,
    /// ssh's exit status, if it exited.
    pub(crate) code: Option<i32>,
    /// What it printed, capped.
    pub(crate) stdout: Vec<u8>,
    /// Its stderr, escaped and capped, with how the relay's splice ended
    /// when that was an error.
    pub(crate) stderr: String,
    /// How writing its input went.
    pub(crate) written: std::io::Result<()>,
    /// The relay socket's own failure, if it had one: the cause of a
    /// session that has no reply, unless the deadline passed.
    pub(crate) relay: Result<(), NodeError>,
}

impl Session {
    /// A command session's outcome: exit 0 with nothing printed, all its
    /// input written. Otherwise it failed ([`Self::failure`]).
    pub(crate) fn ran(self) -> Result<(), NodeError> {
        if matches!(
            (self.code, self.stdout.is_empty(), &self.written),
            (Some(0), true, Ok(()))
        ) {
            return Ok(());
        }
        Err(self.failure())
    }

    /// A request session's reply. The reply decides: without one the
    /// session failed ([`Self::failure`]; a broken pipe on the request
    /// follows from that failure); with one, an agent that refused a
    /// request may have answered before reading all of it. A session
    /// killed at its deadline without a whole reply is
    /// [`NodeError::PastDeadline`]; a whole one stands.
    pub(crate) fn replied(self) -> Result<Response, NodeError> {
        if self.stdout.is_empty() {
            return Err(self.failure());
        }
        match reply(&self.stdout) {
            Err(NodeError::Reply(_)) if self.past_deadline => Err(NodeError::PastDeadline),
            replied => replied,
        }
    }

    /// Why a session without its outcome failed: killed at its deadline,
    /// then the relay socket's own failure, then ssh's, which its status
    /// and stderr say.
    fn failure(self) -> NodeError {
        if self.past_deadline {
            return NodeError::PastDeadline;
        }
        match self.relay {
            Err(error) => error,
            Ok(()) => NodeError::Ssh {
                code: self.code,
                stderr: self.stderr,
            },
        }
    }
}

impl NodeSession for SshAgent<'_> {
    fn run(&mut self, input: &[u8]) -> Result<(), NodeError> {
        self.run_command(input)
    }

    fn empty_request(&mut self) -> Result<Response, NodeError> {
        self.reply(&[])
    }
}

/// [`NodeLinks`] over `/usr/bin/ssh`, each session's connection opened by
/// `connect`.
#[derive(Clone, Copy)]
pub(crate) struct SshLinks<'c> {
    pub(crate) connect: &'c Connect,
}

impl SshLinks<'static> {
    /// The binary's: connections through [`crate::node::dial::connect`].
    pub(crate) const SYSTEM: Self = Self {
        connect: &crate::node::dial::connect,
    };
}

impl NodeLinks for SshLinks<'_> {
    fn open(&self, target: SshTarget) -> Box<dyn NodeSession + '_> {
        Box::new(SshAgent {
            target,
            connect: self.connect,
        })
    }
}

impl AgentLink for SshAgent<'_> {
    fn request(&mut self, request: &LineRequest) -> Result<Response, NodeError> {
        let mut input = Vec::new();
        write_request(&mut input, request).map_err(NodeError::Encode)?;
        self.reply(&input)
    }

    fn put_blob(&mut self, sha256: Sha256Hex, payload: &[u8]) -> Result<Response, NodeError> {
        let mut input = Vec::new();
        write_put_blob(&mut input, sha256, payload).map_err(NodeError::Encode)?;
        self.reply(&input)
    }
}

/// The reply in `stdout`: one line and nothing after it.
pub(crate) fn reply(stdout: &[u8]) -> Result<Response, NodeError> {
    read_reply(&mut BufReader::new(stdout))
        .map_err(NodeError::Reply)?
        .map_err(NodeError::Agent)
}

/// Reads at most `limit` bytes, and drains the rest so the writer never
/// blocks.
fn read_capped(mut source: impl Read, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = source.read(&mut chunk)?;
        if read == 0 {
            return Ok(kept);
        }
        let room = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..read.min(room)]);
    }
}

/// `bytes` as text for the operator: printable ASCII kept, newlines kept,
/// everything else escaped as `\xNN`, at most [`MAX_STDERR_BYTES`] bytes
/// (design §10.5: control characters in every remote string are escaped).
pub(crate) fn escaped(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &byte in bytes {
        if text.len() >= MAX_STDERR_BYTES {
            text.push_str("\\[…]");
            break;
        }
        match byte {
            b'\n' => text.push('\n'),
            0x20..=0x7e if byte != b'\\' => text.push(char::from(byte)),
            _ => text.push_str(&format!("\\x{byte:02x}")),
        }
    }
    text
}
