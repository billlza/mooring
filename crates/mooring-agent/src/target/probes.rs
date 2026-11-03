// SPDX-License-Identifier: GPL-3.0-or-later

//! The tools the check runs on the node (design §11.7): `getent ahostsv4`
//! for the name's IPv4 addresses, and the probes `xray tls ping` for the
//! handshake and `curl --http2` for the HTTP answer, each with the parser
//! of what it prints. `xray tls ping` sets no time limit of its own, so
//! every tool runs under `timeout`, and a target that does not answer
//! holds up neither the Mac's request nor the hourly unit for long: a
//! `getent` or `xray tls ping` that `timeout` ends is
//! `TargetFactsUnavailable`, a curl that it ends is `HttpProbe::Failed`.
//! The handshake sampler, the third probe beside `xray tls ping` and curl,
//! is a module of its own: it runs in the agent's process.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, CertName, HttpProbe, HttpStatus, HttpVersion, IoOp, RedirectUrl, StderrTail,
    TargetHost, TargetTool, TlsGroup, TlsVersion,
};

use crate::host::{Node, Tool, ToolOutput};
use crate::store::io_error;

/// The longest any one tool of the check may run.
const TOOL_SECS: u64 = 10;

/// `timeout`'s exit status when the time ran out.
const TIMED_OUT: i32 = 124;

/// `getent`'s exit status when the name has no address. glibc's `getent`
/// gives it for every failure of `getaddrinfo`, a resolver that does not
/// answer included, so such a name is reported as resolving to nothing.
const NOT_FOUND: i32 = 2;

/// The port every probe uses (design §11.7).
pub(super) const TLS_PORT: u16 = 443;

fn unavailable(tool: TargetTool, text: &[u8]) -> AgentError {
    AgentError::TargetFactsUnavailable {
        tool,
        stderr_tail: StderrTail::scrubbed(text, &[]),
    }
}

/// Runs `program` with `args` under `timeout`, which ends it after
/// [`TOOL_SECS`] and kills it two seconds later if it is still there.
fn bounded(node: &dyn Node, program: &str, args: &[&str]) -> Result<ToolOutput, AgentError> {
    let secs = TOOL_SECS.to_string();
    let mut all = vec!["--kill-after=2", secs.as_str(), program];
    all.extend(args);
    node.run(Tool::Timeout, &all)
        .map_err(|error| io_error(IoOp::SpawnProcess, &error))
}

/// The IPv4 addresses `host` resolves to on the node, empty when it has
/// none.
pub(crate) fn resolve(
    node: &dyn Node,
    host: &TargetHost,
) -> Result<BTreeSet<Ipv4Addr>, AgentError> {
    let output = bounded(node, Tool::Getent.path(), &["ahostsv4", host.as_str()])?;
    match output.code {
        Some(0) => parse_getent(&output.stdout)
            .ok_or_else(|| unavailable(TargetTool::Resolver, &output.stdout)),
        Some(NOT_FOUND) => Ok(BTreeSet::new()),
        Some(TIMED_OUT) => Err(unavailable(
            TargetTool::Resolver,
            b"getent did not answer in time",
        )),
        _ => Err(unavailable(TargetTool::Resolver, &output.stderr)),
    }
}

/// `getent ahostsv4`'s lines: an address, then the socket type and, on the
/// first line, the canonical name.
pub(crate) fn parse_getent(stdout: &[u8]) -> Option<BTreeSet<Ipv4Addr>> {
    let text = std::str::from_utf8(stdout).ok()?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().next()?.parse().ok())
        .collect()
}

/// What `xray tls ping` found with the target's name as SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TlsPing {
    /// No TCP connection.
    ConnectFailed,
    /// The handshake failed.
    HandshakeFailed,
    /// The handshake completed.
    Completed(TlsDetails),
}

/// The handshake's details as `xray tls ping` prints them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsDetails {
    pub(crate) version: TlsVersion,
    pub(crate) group: Option<TlsGroup>,
    pub(crate) chain_bytes: u32,
    pub(crate) chain_certs: u16,
    pub(crate) leaf_names: Vec<CertName>,
}

/// `xray tls ping -ip <address> <host>` with the Xray at `xray`.
pub(crate) fn tls_ping(
    node: &dyn Node,
    xray: &Path,
    host: &TargetHost,
    address: Ipv4Addr,
) -> Result<TlsPing, AgentError> {
    let address = address.to_string();
    let output = bounded(
        node,
        &xray.display().to_string(),
        &["tls", "ping", "-ip", &address, host.as_str()],
    )?;
    if output.code == Some(TIMED_OUT) {
        return Err(unavailable(
            TargetTool::XrayTlsPing,
            b"xray tls ping did not finish in time",
        ));
    }
    parse_tls_ping(&output).ok_or_else(|| {
        let text = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
        unavailable(TargetTool::XrayTlsPing, &text)
    })
}

/// Reads `xray tls ping`'s output (Xray v26.9.30
/// `main/commands/all/tls/ping.go`): it pings without SNI, then with it;
/// only the second part is read. A dial that fails ends it at once with
/// `Failed to dial tcp` on stderr and exit status 1; a handshake that fails
/// prints `Handshake failure:` and goes on. Each detail is a label and a
/// value that a tabwriter aligned. Anything else is `None`.
pub(crate) fn parse_tls_ping(output: &ToolOutput) -> Option<TlsPing> {
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.success {
        return (output.code == Some(1) && stderr.contains("Failed to dial tcp"))
            .then_some(TlsPing::ConnectFailed);
    }
    let mut lines = stdout
        .lines()
        .skip_while(|line| line.trim() != "Pinging with SNI")
        .skip(1);
    match lines.next()?.trim() {
        line if line.starts_with("Handshake failure:") => return Some(TlsPing::HandshakeFailed),
        "Handshake succeeded" => {}
        _ => return None,
    }
    let details: Vec<&str> = lines
        .take_while(|line| !line.starts_with("-------------------"))
        .collect();
    let value = |label: &str| {
        details
            .iter()
            .find_map(|line| line.strip_prefix(label))
            .map(str::trim)
    };
    let version = match value("TLS Version:")? {
        "TLS 1.3" => TlsVersion::Tls13,
        "TLS 1.2" => TlsVersion::Tls12,
        _ => return None,
    };
    let exchange = value("TLS Post-Quantum key exchange:")?;
    let name = exchange.split_once('(')?.1.strip_suffix(')')?;
    let group = match name {
        "RSA Exchange" => None,
        name => Some(group_named(name)?),
    };
    let (bytes, count) =
        value("Certificate chain's total length:")?.split_once(" (certs count: ")?;
    let chain_bytes = bytes.trim().parse().ok()?;
    let chain_certs = count.strip_suffix(')')?.parse().ok()?;
    let leaf_names = match value("Cert's allowed domains:") {
        None => Vec::new(),
        Some(list) => list
            .strip_prefix('[')?
            .strip_suffix(']')?
            .split_whitespace()
            .map(|name| CertName::new(name).ok())
            .collect::<Option<_>>()?,
    };
    Some(TlsPing::Completed(TlsDetails {
        version,
        group,
        chain_bytes,
        chain_certs,
        leaf_names,
    }))
}

/// A group by the name Go's `CurveID.String` gives it, or `CurveID(<n>)`
/// for one it has no name for.
fn group_named(name: &str) -> Option<TlsGroup> {
    Some(match name {
        "CurveP256" => TlsGroup::SECP256R1,
        "CurveP384" => TlsGroup::SECP384R1,
        "CurveP521" => TlsGroup::new(0x0019),
        "X25519" => TlsGroup::X25519,
        "X25519MLKEM768" => TlsGroup::X25519_MLKEM768,
        "SecP256r1MLKEM768" => TlsGroup::new(0x11eb),
        "SecP384r1MLKEM1024" => TlsGroup::new(0x11ed),
        other => TlsGroup::new(
            other
                .strip_prefix("CurveID(")?
                .strip_suffix(')')?
                .parse()
                .ok()?,
        ),
    })
}

/// `curl --http2` of `https://<host>/` at `address`.
pub(crate) fn http_probe(
    node: &dyn Node,
    host: &TargetHost,
    address: Ipv4Addr,
) -> Result<HttpProbe, AgentError> {
    let resolve = format!("{host}:{TLS_PORT}:{address}");
    let url = format!("https://{host}/");
    let output = bounded(
        node,
        Tool::Curl.path(),
        &[
            "--http2",
            "-sS",
            "-o",
            "/dev/null",
            "--connect-timeout",
            "5",
            "--max-time",
            "8",
            "--resolve",
            &resolve,
            "-w",
            "%{http_code} %{http_version} %{redirect_url}",
            &url,
        ],
    )?;
    if output.code == Some(TIMED_OUT) {
        return Ok(HttpProbe::Failed);
    }
    parse_curl(&output.stdout).ok_or_else(|| {
        let text = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
        unavailable(TargetTool::Curl, &text)
    })
}

/// curl's `-w '%{http_code} %{http_version} %{redirect_url}'`, which it
/// writes whether or not a response came: status `000` when none did.
pub(crate) fn parse_curl(stdout: &[u8]) -> Option<HttpProbe> {
    let text = std::str::from_utf8(stdout).ok()?;
    let mut fields = text.splitn(3, ' ');
    let (status, version, redirect) = (fields.next()?, fields.next()?, fields.next()?);
    if status == "000" {
        return Some(HttpProbe::Failed);
    }
    let version = match version {
        "1" => HttpVersion::Http10,
        "1.1" => HttpVersion::Http11,
        "2" => HttpVersion::Http2,
        "3" => HttpVersion::Http3,
        _ => return None,
    };
    Some(HttpProbe::Responded {
        status: HttpStatus::new(status.parse().ok()?).ok()?,
        version,
        redirect: match redirect {
            "" => None,
            url => Some(RedirectUrl::new(url).ok()?),
        },
    })
}
