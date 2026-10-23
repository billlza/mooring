// SPDX-License-Identifier: GPL-3.0-or-later

//! `TargetCheck` (design §11.7) and the hourly target check (§11.3): what
//! the node measures about a REALITY target. The Mac evaluates the rules;
//! the agent only measures, and reports a collector that cannot run as
//! `TargetFactsUnavailable{tool}`, never a guess.
//!
//! The name is resolved once (`getent ahostsv4`), and every probe then goes
//! to the same IPv4: `xray tls ping -ip`, `curl --resolve` and the
//! handshake sampler. `xray tls ping` sets no time limit of its own, so
//! every tool runs under `timeout`, and a target that does not answer
//! holds up neither the Mac's request nor the hourly unit for long.

pub(crate) mod sampler;

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use mooring_agent_proto::{
    AgentError, CertName, HttpProbe, HttpStatus, HttpVersion, IoOp, RedirectUrl, Sha256Hex,
    StderrTail, TargetFacts, TargetHost, TargetTool, TlsGroup, TlsProbe, TlsSession, TlsVersion,
    UnixTime, WatchConfig, WatchTarget,
};
use serde::{Deserialize, Serialize};

use crate::host::{Node, Tool, ToolOutput};
use crate::paths::Paths;
use crate::store::{io_error, read_json, write_json};
use crate::txn::stage::{self, XRAY};

/// The longest any one tool of the check may run.
pub(crate) const TOOL_SECS: u64 = 10;

/// `timeout`'s exit status when the time ran out.
const TIMED_OUT: i32 = 124;

/// `getent`'s exit status when the name has no address. glibc's `getent`
/// gives it for every failure of `getaddrinfo`, a resolver that does not
/// answer included, so such a name is reported as resolving to nothing.
const NOT_FOUND: i32 = 2;

/// The port every probe uses (design §11.7).
const TLS_PORT: u16 = 443;

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

/// The Xray stored as blob `sha`, installed in the engine store (0755)
/// unless an intact copy is there: a node is checked before its first
/// `Apply`, when no generation holds an Xray.
fn install_xray(paths: &Paths, sha: &Sha256Hex) -> Result<PathBuf, AgentError> {
    if !crate::blobs::present(paths, &[*sha].into())?.contains(sha) {
        return Err(AgentError::BlobMissing { sha256: *sha });
    }
    let target = stage::store_path(paths, XRAY, sha);
    if !stage::stored_intact(&target, sha)? {
        let dir = target
            .parent()
            .ok_or(crate::store::malformed(IoOp::WriteState))?;
        std::fs::create_dir_all(dir).map_err(|error| io_error(IoOp::WriteState, &error))?;
        stage::copy_blob(&paths.blob(sha), &target, XRAY.mode)?;
    }
    Ok(target)
}

/// `TargetCheck{host, xray}`.
pub(crate) fn check(
    paths: &Paths,
    node: &dyn Node,
    host: TargetHost,
    xray: Sha256Hex,
) -> Result<TargetFacts, AgentError> {
    check_at(paths, node, host, xray, TLS_PORT)
}

/// [`check`], with the handshake sampler on `port` (443 on a node; a test
/// server's port in tests).
pub(crate) fn check_at(
    paths: &Paths,
    node: &dyn Node,
    host: TargetHost,
    xray: Sha256Hex,
    port: u16,
) -> Result<TargetFacts, AgentError> {
    let program = install_xray(paths, &xray)?;
    let resolved = resolve(node, &host)?;
    // With no address there is nothing to connect to.
    let Some(&address) = resolved.iter().next() else {
        return Ok(TargetFacts {
            host,
            resolved,
            tls: TlsProbe::ConnectFailed,
            http: HttpProbe::Failed,
        });
    };
    let tls = match tls_ping(node, &program, &host, address)? {
        TlsPing::ConnectFailed => TlsProbe::ConnectFailed,
        TlsPing::HandshakeFailed => TlsProbe::HandshakeFailed,
        TlsPing::Completed(details) => {
            let measured = sampler::measure(
                SocketAddr::new(address.into(), port),
                &host,
                sampler::urandom,
            )?;
            TlsProbe::Completed(TlsSession {
                version: details.version,
                group: details.group,
                chain_bytes: details.chain_bytes,
                chain_certs: details.chain_certs,
                leaf_names: details.leaf_names,
                handshake_p95_micros: measured.p95_micros,
                first_flight_bytes: measured.first_flight_bytes,
            })
        }
    };
    let http = http_probe(node, &host, address)?;
    Ok(TargetFacts {
        host,
        resolved,
        tls,
        http,
    })
}

/// The hourly check's latest result (`/var/lib/mooring/watch/target.json`),
/// with the target it checked: a result about another target than the
/// configured one says nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetReading {
    /// When it was checked.
    pub(crate) at: UnixTime,
    /// What was checked.
    pub(crate) target: WatchTarget,
    /// Whether the check failed (`TargetDegraded`).
    pub(crate) degraded: bool,
}

/// The reading's mode: the state group reads it.
const READING_MODE: u32 = 0o640;

/// `target-watch`, the hourly unit: checks the configured target with the
/// current generation's Xray and records the result. The target is
/// degraded when its name no longer resolves to the configured address,
/// when the TLS handshake with it does not complete, or when it does not
/// answer over HTTP/2.
pub(crate) fn watch(paths: &Paths, node: &dyn Node) -> Result<TargetReading, AgentError> {
    let config: WatchConfig =
        read_json(&paths.watch_config())?.ok_or(crate::store::malformed(IoOp::ReadState))?;
    let target = config.target;
    let xray = stage::program(&paths.current(), XRAY);
    let degraded = match resolve(node, &target.host) {
        Ok(resolved) if resolved.contains(&target.ipv4) => {
            let tls = tls_ping(node, &xray, &target.host, target.ipv4);
            let http = http_probe(node, &target.host, target.ipv4);
            !matches!(tls, Ok(TlsPing::Completed(_)))
                || !matches!(
                    http,
                    Ok(HttpProbe::Responded {
                        version: HttpVersion::Http2,
                        ..
                    })
                )
        }
        Ok(_) | Err(_) => true,
    };
    let reading = TargetReading {
        at: node.now(),
        target,
        degraded,
    };
    write_json(&paths.target_reading(), &reading, READING_MODE)?;
    Ok(reading)
}

/// Whether the latest hourly check found `target` degraded; no check of it
/// yet is no news.
pub(crate) fn degraded(paths: &Paths, target: &WatchTarget) -> Result<bool, AgentError> {
    Ok(read_json::<TargetReading>(&paths.target_reading())?
        .is_some_and(|reading| reading.target == *target && reading.degraded))
}
