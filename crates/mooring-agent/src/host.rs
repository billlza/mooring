// SPDX-License-Identifier: GPL-3.0-or-later

//! What the agent runs on the node: a closed set of tools at fixed paths,
//! the clock and sleeping. Handlers reach the node only through [`Node`],
//! so tests stand in for it.

use std::io;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::{SystemTime, UNIX_EPOCH};

use mooring_agent_proto::{AgentError, IoOp, UnixTime};

/// A tool the agent runs, at its Debian 13 path. Nothing else is ever
/// executed, and a request never names a program or an argument directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Tool {
    /// `nft` (the gate set and the ruleset).
    Nft,
    /// `systemctl` (the engines).
    Systemctl,
    /// `ip` (the uplink and its address).
    Ip,
    /// `sshd -T` (the effective sshd configuration).
    Sshd,
    /// `wg` (the Mac peer's handshake, `syncconf`).
    Wg,
    /// `wg-quick` (`strip`).
    WgQuick,
    /// `systemd-run` (transaction units and timers).
    SystemdRun,
    /// `ss` (the health gate's listeners).
    Ss,
    /// `stat -f` (the free space of the agent's filesystem).
    Stat,
    /// `chronyc` (whether the clock is synchronised).
    Chronyc,
    /// `dpkg-query` (which of `Bootstrap`'s packages are installed).
    DpkgQuery,
    /// `apt-get` (`Bootstrap`'s packages).
    AptGet,
    /// `groupadd` (the state group).
    Groupadd,
    /// `useradd` (the profile's accounts).
    Useradd,
    /// `usermod` (an account that differs from the profile).
    Usermod,
    /// `ssh-keygen` (the new host key).
    SshKeygen,
    /// `sysctl --system`.
    Sysctl,
    /// `systemd-tmpfiles --create`.
    SystemdTmpfiles,
    /// `systemd-analyze verify` (the staged units).
    SystemdAnalyze,
    /// `timeout`, which bounds the target check's tools.
    Timeout,
    /// `getent ahostsv4` (the target's addresses).
    Getent,
    /// `curl --http2` (the target's HTTP answer).
    Curl,
}

impl Tool {
    /// The tool's absolute path on Debian 13 (checked on the London VPS on
    /// 2026-10-22, except `wg` and `wg-quick`, which `wireguard-tools`
    /// installs there, and the tools added for `Bootstrap` in M4e, checked
    /// in a Debian 13 VM).
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Nft => "/usr/sbin/nft",
            Self::Systemctl => "/usr/bin/systemctl",
            Self::Ip => "/usr/bin/ip",
            Self::Sshd => "/usr/sbin/sshd",
            Self::Wg => "/usr/bin/wg",
            Self::WgQuick => "/usr/bin/wg-quick",
            Self::SystemdRun => "/usr/bin/systemd-run",
            Self::Ss => "/usr/bin/ss",
            Self::Stat => "/usr/bin/stat",
            Self::Chronyc => "/usr/bin/chronyc",
            Self::DpkgQuery => "/usr/bin/dpkg-query",
            Self::AptGet => "/usr/bin/apt-get",
            Self::Groupadd => "/usr/sbin/groupadd",
            Self::Useradd => "/usr/sbin/useradd",
            Self::Usermod => "/usr/sbin/usermod",
            Self::SshKeygen => "/usr/bin/ssh-keygen",
            Self::Sysctl => "/usr/sbin/sysctl",
            Self::SystemdTmpfiles => "/usr/bin/systemd-tmpfiles",
            Self::SystemdAnalyze => "/usr/bin/systemd-analyze",
            Self::Timeout => "/usr/bin/timeout",
            Self::Getent => "/usr/bin/getent",
            Self::Curl => "/usr/bin/curl",
        }
    }
}

/// What a tool printed and how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ToolOutput {
    /// Whether it exited 0.
    pub(crate) success: bool,
    /// Its exit status; `None` when a signal ended it.
    pub(crate) code: Option<i32>,
    /// Its standard output.
    pub(crate) stdout: Vec<u8>,
    /// Its standard error.
    pub(crate) stderr: Vec<u8>,
}

/// The node, as the handlers use it.
pub(crate) trait Node {
    /// Runs `tool` with `args`, waits for it and returns its output.
    fn run(&self, tool: Tool, args: &[&str]) -> io::Result<ToolOutput>;
    /// Runs a staged program (an engine binary or a new agent) by its
    /// absolute path, with `env` as its only environment besides `PATH` and
    /// `LC_ALL`.
    fn run_program(
        &self,
        program: &Path,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> io::Result<ToolOutput>;
    /// The time now.
    fn now(&self) -> UnixTime;
    /// Waits `duration`.
    fn sleep(&self, duration: Duration);
}

/// The real node (Linux only: the tools' paths are Debian's).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RealNode;

#[cfg(target_os = "linux")]
impl Node for RealNode {
    fn run(&self, tool: Tool, args: &[&str]) -> io::Result<ToolOutput> {
        self.run_program(Path::new(tool.path()), args, &[])
    }

    fn run_program(
        &self,
        program: &Path,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> io::Result<ToolOutput> {
        let output = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin")
            .env("LC_ALL", "C")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .output()?;
        Ok(ToolOutput {
            success: output.status.success(),
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn now(&self) -> UnixTime {
        // A clock before 1970 reads as 1970; every time the agent records
        // is compared with others it recorded, never with a fixed date.
        UnixTime::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
        )
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Runs `tool` and requires it to exit 0; the error is the protocol's
/// `Io{SpawnProcess}` for a tool that could not start, and `stderr` comes
/// back for a tool that failed so the caller can name the failure.
pub(crate) fn run_ok(
    node: &dyn Node,
    tool: Tool,
    args: &[&str],
) -> Result<Result<Vec<u8>, Vec<u8>>, AgentError> {
    let output = node.run(tool, args).map_err(|error| AgentError::Io {
        op: IoOp::SpawnProcess,
        errno: error.raw_os_error(),
    })?;
    Ok(if output.success {
        Ok(output.stdout)
    } else {
        Err(output.stderr)
    })
}
