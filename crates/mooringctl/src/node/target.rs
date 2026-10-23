// SPDX-License-Identifier: GPL-3.0-or-later

//! `node target check|set <id> <host>` (design §11.7, §13.2 step 4): the
//! node measures a candidate REALITY target with its own Xray, and the Mac
//! judges the facts (`qualify`). `check` prints the facts and every rule
//! the target fails, leaving out the operator's attestation; `set`
//! measures again, qualifies with the attestation, and stores the target.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use mooring_agent_proto::{LineRequest, RequestKind, Response, TargetHost};
use mooring_model::dns::DnsName;
use mooring_model::iface::BsdName;
use mooring_model::node::NodeLifecycle;
use mooring_model::target::{
    EvidenceUrl, HttpOutcome, TargetAttestation, TargetFacts, TargetRejection, TlsOutcome, qualify,
};
use mooring_model::{NodeId, StateV2};
use mooring_render::target_facts;
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::node::engines::Engines;
use crate::node::session::{deployed_node, ops_session};
use crate::node::{NodeError, upload_missing};
use crate::state::{load, output, state_change};

/// What both target commands are given.
#[derive(Debug, Clone)]
pub(crate) struct TargetArgs<'a> {
    pub(crate) node: &'a NodeId,
    pub(crate) host: &'a DnsName,
    pub(crate) interface: &'a BsdName,
    pub(crate) engines: &'a Path,
}

/// The operator's attestation, as `node target set` takes it.
#[derive(Debug, Clone)]
pub(crate) struct Attested<'a> {
    pub(crate) same_asn: bool,
    pub(crate) not_cdn: bool,
    pub(crate) evidence: &'a str,
}

/// `node target check`.
pub(crate) fn check(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    args: &TargetArgs<'_>,
) -> Result<(), CommandError> {
    let (_, facts) = measure(env, args)?;
    describe(out, &facts)?;
    // The attestation is the operator's, given to `set`: it is judged
    // unattested here, and its two rules are left out of the verdict.
    let unattested = TargetAttestation {
        same_asn: false,
        not_cdn: false,
        evidence_url: EvidenceUrl::parse("https://mooring.invalid/not-attested")
            .map_err(LocalError::Target)?,
        at: (env.clock)()?,
    };
    let refused: Vec<TargetRejection> = match qualify(&facts, unattested) {
        Ok(_) => Vec::new(),
        Err(rejected) => rejected
            .reasons()
            .iter()
            .filter(|reason| {
                !matches!(
                    reason,
                    TargetRejection::SameAsnNotAttested | TargetRejection::CdnNotExcluded
                )
            })
            .cloned()
            .collect(),
    };
    if refused.is_empty() {
        writeln!(
            out,
            "{} passes every rule; `node target set` stores it with your attestation (same ASN, not a CDN)",
            args.host
        )
        .map_err(output)?;
    }
    for reason in &refused {
        writeln!(out, "refused: {}", rejection(reason)).map_err(output)?;
    }
    Ok(())
}

/// `node target set ... --same-asn --not-cdn --evidence <url> [--yes]`: a
/// configuration change that stores the qualified target. A node whose
/// target changes needs every user's file exported again, because the SNI
/// is part of each client's configuration (design §11.7).
pub(crate) fn set(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    args: &TargetArgs<'_>,
    attested: &Attested<'_>,
    yes: bool,
) -> Result<(), CommandError> {
    let (state, facts) = measure(env, args)?;
    describe(out, &facts)?;
    let attestation = TargetAttestation {
        same_asn: attested.same_asn,
        not_cdn: attested.not_cdn,
        evidence_url: EvidenceUrl::parse(attested.evidence).map_err(LocalError::Target)?,
        at: (env.clock)()?,
    };
    let target = match qualify(&facts, attestation) {
        Ok(qualified) => qualified.into_target(),
        Err(rejected) => {
            for reason in rejected.reasons() {
                writeln!(out, "refused: {}", rejection(reason)).map_err(output)?;
            }
            return Err(LocalError::TargetRefused {
                host: args.host.clone(),
            }
            .into());
        }
    };
    let node = &state.deployment.nodes()[args.node];
    if let Some(existing) = &node.reality.target {
        writeln!(
            out,
            "this replaces {}: every user's file must be exported again after `node apply`",
            existing.host()
        )
        .map_err(output)?;
    }
    confirm(env, yes, "Store this target?")?;
    let store = Store::new(support_dir(env)?);
    let state = store
        .update_config(state.deployment.config_generation(), |mut parts| {
            for candidate in &mut parts.nodes {
                if candidate.id == *args.node {
                    candidate.reality.target = Some(target.clone());
                }
            }
            Ok::<_, std::convert::Infallible>(parts)
        })
        .map_err(state_change)?;
    writeln!(
        out,
        "stored {} as {}'s target (generation {}); next: `mooringctl node apply {}`",
        args.host,
        args.node,
        state.deployment.config_generation(),
        args.node
    )
    .map_err(output)?;
    Ok(())
}

/// Uploads the node's Xray if it lacks it, and has the node measure the
/// host with it.
fn measure(
    env: &mut Env<'_>,
    args: &TargetArgs<'_>,
) -> Result<(StateV2, TargetFacts), CommandError> {
    let state = load(&Store::new(support_dir(env)?))?;
    let node = deployed_node(state.deployment.nodes(), args.node)?;
    let arch = match &node.lifecycle {
        NodeLifecycle::Adopted { site } | NodeLifecycle::Applied { site, .. } => {
            site.host_facts.arch
        }
        other => {
            return Err(LocalError::NodeNotDeployed {
                node: node.id.clone(),
                stage: other.stage(),
            }
            .into());
        }
    };
    let engines = Engines::open(args.engines, env.engine_pins)?;
    let xray = engines.catalog().for_arch(arch).xray;
    let mut session = ops_session(env, node, args.interface, None)?;
    upload_missing(session.as_mut(), BTreeSet::from([xray]), |sha256| {
        engines
            .blob(sha256)?
            .ok_or(LocalError::EngineMissing { sha256: *sha256 })
    })?;
    let host = TargetHost::new(args.host.as_str()).map_err(|_| LocalError::TargetHost {
        host: args.host.clone(),
    })?;
    let reply = session.request(&LineRequest::TargetCheck { host, xray })?;
    let Response::TargetFacts(facts) = reply else {
        return Err(NodeError::Unexpected {
            request: RequestKind::TargetCheck,
            response: reply.kind(),
        }
        .into());
    };
    let facts = target_facts(args.host, &facts).map_err(LocalError::Render)?;
    Ok((state, facts))
}

/// The facts, one line each.
fn describe(out: &mut dyn Write, facts: &TargetFacts) -> Result<(), CommandError> {
    let resolved: Vec<String> = facts
        .resolved_ipv4
        .iter()
        .map(ToString::to_string)
        .collect();
    writeln!(
        out,
        "{}: resolves to {}",
        facts.host,
        if resolved.is_empty() {
            "nothing".to_owned()
        } else {
            resolved.join(", ")
        }
    )
    .map_err(output)?;
    let tls = match &facts.tls {
        TlsOutcome::ConnectFailed => "TLS: no connection on 443".to_owned(),
        TlsOutcome::HandshakeFailed => "TLS: the handshake failed".to_owned(),
        TlsOutcome::Completed(session) => format!("TLS: {session:?}"),
    };
    writeln!(out, "{tls}").map_err(output)?;
    let http = match facts.http {
        HttpOutcome::Failed => "HTTP: no answer".to_owned(),
        HttpOutcome::Responded { status, version } => {
            format!("HTTP: {} over {version:?}", status.get())
        }
    };
    writeln!(out, "{http}").map_err(output)?;
    Ok(())
}

/// A rejection in words, as the model names it.
fn rejection(reason: &TargetRejection) -> String {
    format!("{reason:?}")
}
