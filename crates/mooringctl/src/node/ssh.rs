// SPDX-License-Identifier: GPL-3.0-or-later

//! Management SSH from the Mac (design §10.5): `/usr/bin/ssh` with the
//! design's options, its ProxyCommand the interface-bound dialler, and one
//! agent request per session, as the forced command serves one (§11.1).
//!
//! A target with a deadline (the sleep drain's, design §10.3) runs each
//! session in a process group of its own, which is killed when the
//! deadline passes: ssh's own timeouts (`ConnectTimeout`, the
//! server-alive probes) allow a session far longer than the drain's
//! budget, and the group ends the dialler with ssh, so no reader waits on
//! a dialler still connecting. A target without one runs as before, in
//! the caller's group, so a terminal's Ctrl-C still ends ssh with
//! `mooringctl`.

use std::ffi::OsString;
use std::io::{BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Instant;

use mooring_agent_proto::{
    LineRequest, MAX_RESPONSE_LINE_BYTES, Response, Sha256Hex, read_reply, write_put_blob,
    write_request,
};
use mooring_macsys::GroupKill;
use mooring_model::iface::BsdName;
use mooring_model::ipv4::PublicIpv4;

use crate::node::{AgentLink, NodeError, NodeLinks, NodeSession};

/// The ssh binary: OpenSSH as macOS ships it (OpenSSH_10.3p1 on this Mac).
pub(crate) const SSH: &str = "/usr/bin/ssh";

/// The most stderr bytes kept from one session, after escaping.
pub(crate) const MAX_STDERR_BYTES: usize = 4096;

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
    /// The Mac's interface to the M7, which the dialler binds to.
    pub(crate) interface: BsdName,
    /// This mooringctl, which ssh runs as the dialler.
    pub(crate) mooringctl: PathBuf,
    /// What the session runs.
    pub(crate) remote: Remote,
    /// When set, the instant by which each session ends: past it ssh and
    /// its dialler are killed, and the session fails as
    /// [`NodeError::PastDeadline`] unless its reply had arrived whole.
    pub(crate) deadline: Option<Instant>,
}

impl SshTarget {
    /// The ssh command line (design §10.5), with `BatchMode` so that ssh
    /// never asks at the terminal.
    pub(crate) fn args(&self) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["-F".into(), "/dev/null".into(), "-i".into()];
        args.push(self.identity.clone().into_os_string());
        let mut proxy = OsString::from("ProxyCommand=");
        proxy.push(quoted(&self.mooringctl));
        proxy.push(format!(
            " dial-bound --interface {} %h %p",
            self.interface.as_str()
        ));
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
}

/// `path` in single quotes for the line ssh hands to `/bin/sh` (the
/// ProxyCommand and the known-hosts file name): a quote inside is closed,
/// escaped and reopened.
fn quoted(path: &Path) -> OsString {
    let text = path.as_os_str().to_string_lossy().replace('\'', r"'\''");
    format!("'{text}'").into()
}

/// The agent behind [`SshTarget`]: each request is one ssh session.
#[derive(Debug)]
pub(crate) struct SshAgent {
    pub(crate) target: SshTarget,
}

impl SshAgent {
    /// Runs one session that writes `input` to the remote side, and
    /// returns how ssh exited with what it printed: at most one reply line
    /// and the end of output on stdout, and stderr escaped and capped. With
    /// the target's deadline, a watcher kills the session's group when it
    /// passes; the group lives until ssh is reaped, after the watcher is
    /// joined, so its id names no other group.
    fn session(&self, input: &[u8]) -> Result<Session, NodeError> {
        let mut command = Command::new(SSH);
        command
            .args(self.target.args())
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
        let (written, read, errors, ended) = std::thread::scope(|scope| {
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
            let errors = errors.join();
            let ended = watcher.map(|(finished, watcher)| {
                drop(finished);
                watcher.join()
            });
            (written, read, errors, ended)
        });
        let status = child.wait().map_err(NodeError::Spawn)?;
        let past_deadline = match ended {
            None => false,
            Some(joined) => joined
                .map_err(|_| NodeError::Pipe)?
                .map_err(NodeError::End)?,
        };
        Ok(Session {
            past_deadline,
            code: status.code(),
            stdout: read
                .map_err(|_| NodeError::Pipe)?
                .map_err(NodeError::Read)?,
            stderr: escaped(
                &errors
                    .map_err(|_| NodeError::Pipe)?
                    .map_err(NodeError::Read)?,
            ),
            written,
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
    /// Its stderr, escaped and capped.
    pub(crate) stderr: String,
    /// How writing its input went.
    pub(crate) written: std::io::Result<()>,
}

impl Session {
    /// A command session's outcome: exit 0 with nothing printed, all its
    /// input written. A session killed at its deadline otherwise is
    /// [`NodeError::PastDeadline`].
    pub(crate) fn ran(self) -> Result<(), NodeError> {
        match (self.code, self.stdout.is_empty(), self.written) {
            (Some(0), true, Ok(())) => Ok(()),
            _ if self.past_deadline => Err(NodeError::PastDeadline),
            (code, _, _) => Err(NodeError::Ssh {
                code,
                stderr: self.stderr,
            }),
        }
    }

    /// A request session's reply. The reply decides: without one the
    /// session failed in ssh, whose status and stderr say why (a broken
    /// pipe on the request follows from that failure); with one, an agent
    /// that refused a request may have answered before reading all of it.
    /// A session killed at its deadline without a whole reply is
    /// [`NodeError::PastDeadline`]; a whole one stands.
    pub(crate) fn replied(self) -> Result<Response, NodeError> {
        if self.stdout.is_empty() {
            return Err(if self.past_deadline {
                NodeError::PastDeadline
            } else {
                NodeError::Ssh {
                    code: self.code,
                    stderr: self.stderr,
                }
            });
        }
        match reply(&self.stdout) {
            Err(NodeError::Reply(_)) if self.past_deadline => Err(NodeError::PastDeadline),
            replied => replied,
        }
    }
}

impl NodeSession for SshAgent {
    fn run(&mut self, input: &[u8]) -> Result<(), NodeError> {
        self.run_command(input)
    }

    fn empty_request(&mut self) -> Result<Response, NodeError> {
        self.reply(&[])
    }
}

/// [`NodeLinks`] over `/usr/bin/ssh`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SshLinks;

impl NodeLinks for SshLinks {
    fn open(&self, target: SshTarget) -> Box<dyn NodeSession + '_> {
        Box::new(SshAgent { target })
    }
}

impl AgentLink for SshAgent {
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
