// SPDX-License-Identifier: GPL-3.0-or-later

//! `Hello` (design §11.1): the agent, the host facts its configuration
//! depends on, the sshd directives sshd does not enforce, and the gate's
//! holds and halt marker. Every fact is read live; one that cannot be read,
//! or is ambiguous, is `HostFactUnavailable{field}`, never a guess.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::net::Ipv4Addr;

use mooring_agent_proto::{
    AcceptLocal, AgentError, Arch, HelloInfo, HostFact, HostFacts, HostProfile, HostProfileVersion,
    IfName, IoOp, KernelIdent, KernelRelease, PROTOCOL, PortRange, Sha256Hex, SshdDirective,
};

use crate::blobs::digest_of;
use crate::gate;
use crate::host::{Node, Tool, run_ok};
use crate::paths::Paths;
use crate::store::{io_error, malformed, read_json};

/// Everything `Hello` reports.
pub(crate) fn hello(
    paths: &Paths,
    node: &dyn Node,
    ssh_connection: Option<&str>,
) -> Result<HelloInfo, AgentError> {
    Ok(HelloInfo {
        protocol: PROTOCOL,
        agent_sha: own_sha(paths)?,
        host_profile_version: installed_profile(paths)?,
        host: host_facts(paths, node)?,
        wgexit_accept_local: accept_local(paths)?,
        sshd_mismatches: sshd_mismatches(node, &HostProfile::CURRENT)?,
        halted: gate::halted(paths)?,
        holds: gate::holds(paths)?,
        client_ip: client_ip(ssh_connection)?,
    })
}

/// The digest of the running agent's own executable.
pub(crate) fn own_sha(paths: &Paths) -> Result<Sha256Hex, AgentError> {
    let own =
        File::open(paths.own_executable()).map_err(|error| io_error(IoOp::ReadBlob, &error))?;
    digest_of(own).map_err(|error| io_error(IoOp::ReadBlob, &error))
}

/// The host profile version the agent installed
/// (`/var/lib/mooring/host-profile.json`, written by `Bootstrap` and by
/// transactions). An agent that has installed none cannot answer `Hello`.
fn installed_profile(paths: &Paths) -> Result<HostProfileVersion, AgentError> {
    read_json(&paths.host_profile())?.ok_or(AgentError::Io {
        op: IoOp::ReadState,
        errno: Some(ENOENT),
    })
}

/// `ENOENT` on Linux: the record does not exist.
const ENOENT: i32 = 2;

/// The Mac's address, the first field of `SSH_CONNECTION` (`client_ip
/// client_port server_ip server_port`), which sshd always sets for a
/// forced command. Its absence, or an address that is not IPv4, means the
/// request did not come over the Mac's SSH session.
pub(crate) fn client_ip(ssh_connection: Option<&str>) -> Result<Ipv4Addr, AgentError> {
    ssh_connection
        .and_then(|value| value.split(' ').next())
        .and_then(|address| address.parse().ok())
        .ok_or(AgentError::Io {
            op: IoOp::ReadRequest,
            errno: None,
        })
}

/// The live host facts, each read as design §11.1 names it.
pub(crate) fn host_facts(paths: &Paths, node: &dyn Node) -> Result<HostFacts, AgentError> {
    let uplink = uplink(paths)?;
    Ok(HostFacts {
        vps4: vps4(node, &uplink)?,
        uplink,
        arch: arch(std::env::consts::ARCH)?,
        ip_local_port_range: port_range(paths)?,
        debian_major: debian_major(paths)?,
        kernel: proc_text(paths, "kernel/osrelease", HostFact::Kernel)
            .and_then(|text| KernelRelease::new(text).map_err(|_| unavailable(HostFact::Kernel)))?,
        congestion_control: kernel_ident(
            paths,
            "net/ipv4/tcp_congestion_control",
            HostFact::CongestionControl,
        )?,
        qdisc: kernel_ident(paths, "net/core/default_qdisc", HostFact::Qdisc)?,
    })
}

const fn unavailable(field: HostFact) -> AgentError {
    AgentError::HostFactUnavailable { field }
}

/// The one line of a `/proc/sys` file, without its newline.
fn proc_text(paths: &Paths, key: &str, field: HostFact) -> Result<String, AgentError> {
    let text = fs::read_to_string(paths.proc_sys(key)).map_err(|_| unavailable(field))?;
    let mut lines = text.lines();
    match (lines.next(), lines.next()) {
        (Some(line), None) if !line.is_empty() => Ok(line.to_owned()),
        _ => Err(unavailable(field)),
    }
}

fn kernel_ident(paths: &Paths, key: &str, field: HostFact) -> Result<KernelIdent, AgentError> {
    KernelIdent::new(proc_text(paths, key, field)?).map_err(|_| unavailable(field))
}

/// `net.ipv4.ip_local_port_range`: two numbers separated by whitespace.
fn port_range(paths: &Paths) -> Result<PortRange, AgentError> {
    let field = HostFact::IpLocalPortRange;
    let text = proc_text(paths, "net/ipv4/ip_local_port_range", field)?;
    let mut numbers = text.split_whitespace().map(str::parse::<u16>);
    match (numbers.next(), numbers.next(), numbers.next()) {
        (Some(Ok(low)), Some(Ok(high)), None) => {
            PortRange::new(low, high).map_err(|_| unavailable(field))
        }
        _ => Err(unavailable(field)),
    }
}

/// The CPU architecture of this build of the agent, which is the node's.
pub(crate) fn arch(build: &str) -> Result<Arch, AgentError> {
    match build {
        "x86_64" => Ok(Arch::Amd64),
        "aarch64" => Ok(Arch::Arm64),
        _ => Err(unavailable(HostFact::Arch)),
    }
}

/// The Debian major release: `ID=debian` and `VERSION_ID` in
/// `/etc/os-release`, quoted or not.
fn debian_major(paths: &Paths) -> Result<u16, AgentError> {
    let field = HostFact::DebianMajor;
    let text = fs::read_to_string(paths.os_release()).map_err(|_| unavailable(field))?;
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(|value| value.trim_matches('"'))
    };
    if value("ID") != Some("debian") {
        return Err(unavailable(field));
    }
    value("VERSION_ID")
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
        .ok_or(unavailable(field))
}

/// `RTF_UP` in `/proc/net/route`'s flags.
const RTF_UP: u16 = 0x1;

/// The interface of the up IPv4 default routes in `/proc/net/route`, which
/// must be one.
pub(crate) fn uplink(paths: &Paths) -> Result<IfName, AgentError> {
    let field = HostFact::Uplink;
    let table = fs::read_to_string(paths.at("/proc/net/route")).map_err(|_| unavailable(field))?;
    let defaults: BTreeSet<&str> = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let columns: Vec<&str> = line.split_whitespace().collect();
            // Iface Destination Gateway Flags RefCnt Use Metric Mask …
            let flags = u16::from_str_radix(columns.get(3)?, 16).ok()?;
            let up = flags & RTF_UP != 0;
            (columns.get(1) == Some(&"00000000") && columns.get(7) == Some(&"00000000") && up)
                .then(|| columns[0])
        })
        .collect();
    let mut interfaces = defaults.into_iter();
    match (interfaces.next(), interfaces.next()) {
        (Some(name), None) => IfName::new(name).map_err(|_| unavailable(field)),
        _ => Err(unavailable(field)),
    }
}

/// The one global IPv4 address on `uplink`, from `ip -j -4 addr show dev`.
pub(crate) fn vps4(node: &dyn Node, uplink: &IfName) -> Result<Ipv4Addr, AgentError> {
    let field = HostFact::Vps4;
    let stdout = run_ok(
        node,
        Tool::Ip,
        &["-j", "-4", "addr", "show", "dev", uplink.as_str()],
    )?
    .map_err(|_| unavailable(field))?;
    let listing: serde_json::Value =
        serde_json::from_slice(&stdout).map_err(|_| unavailable(field))?;
    let addresses: Vec<Ipv4Addr> = listing
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|interface| interface.get("addr_info")?.as_array())
        .flatten()
        .filter(|info| {
            info.get("family").and_then(|family| family.as_str()) == Some("inet")
                && info.get("scope").and_then(|scope| scope.as_str()) == Some("global")
        })
        .filter_map(|info| info.get("local")?.as_str()?.parse().ok())
        .collect();
    match addresses.as_slice() {
        [address] => Ok(*address),
        _ => Err(unavailable(field)),
    }
}

/// `net.ipv4.conf.wgexit.accept_local`; no such file means no `wgexit`.
fn accept_local(paths: &Paths) -> Result<AcceptLocal, AgentError> {
    match fs::read_to_string(paths.wgexit_accept_local()) {
        Ok(text) => match text.trim_end_matches('\n') {
            "0" => Ok(AcceptLocal::Disabled),
            "1" => Ok(AcceptLocal::Enabled),
            _ => Err(malformed(IoOp::ReadState)),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(AcceptLocal::NoInterface),
        Err(error) => Err(io_error(IoOp::ReadState, &error)),
    }
}

/// The profile's directives whose lines in `sshd -T` differ from the
/// profile's, compared as multisets (`AllowUsers` adds up across files).
pub(crate) fn sshd_mismatches(
    node: &dyn Node,
    profile: &HostProfile,
) -> Result<BTreeSet<SshdDirective>, AgentError> {
    let stdout = run_ok(node, Tool::Sshd, &["-T"])?.map_err(|_| malformed(IoOp::ReadState))?;
    let text = String::from_utf8(stdout).map_err(|_| malformed(IoOp::ReadState))?;
    Ok(mismatches_in(&text, profile))
}

/// The mismatches between `sshd -T`'s output `text` and `profile`.
pub(crate) fn mismatches_in(text: &str, profile: &HostProfile) -> BTreeSet<SshdDirective> {
    SshdDirective::ALL
        .iter()
        .copied()
        .filter(|directive| {
            let keyword = directive.keyword().to_ascii_lowercase();
            let mut live: Vec<String> = text
                .lines()
                .filter(|line| line.split(' ').next() == Some(keyword.as_str()))
                .map(str::to_owned)
                .collect();
            let mut expected = profile.sshd_effective_lines(*directive);
            live.sort_unstable();
            expected.sort_unstable();
            live != expected
        })
        .collect()
}
