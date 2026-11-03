// SPDX-License-Identifier: GPL-3.0-or-later

//! `TargetCheck` (design §11.7): what the node measures about a REALITY
//! target. The Mac evaluates the rules; the check only measures, and
//! reports a collector that cannot run as `TargetFactsUnavailable{tool}`,
//! never a guess. The hourly target check (§11.3), which judges the
//! configured target on the node itself, is [`hourly`].
//!
//! `TargetCheck` installs the Xray it names from the blob store, resolves
//! the name once (`getent ahostsv4`) and sends every probe to the same
//! IPv4: `xray tls ping -ip` and `curl --resolve`, which [`probes`] runs
//! under `timeout` as it runs `getent`, and the handshake sampler
//! ([`sampler`]).

pub(crate) mod hourly;
pub(crate) mod probes;
pub(crate) mod sampler;

use std::net::SocketAddr;
use std::path::PathBuf;

use mooring_agent_proto::{
    AgentError, HttpProbe, IoOp, Sha256Hex, TargetFacts, TargetHost, TlsProbe, TlsSession,
};

use crate::host::Node;
use crate::paths::Paths;
use crate::store::io_error;
use crate::txn::stage::{self, XRAY};
use probes::{TLS_PORT, TlsPing, http_probe, resolve, tls_ping};

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
