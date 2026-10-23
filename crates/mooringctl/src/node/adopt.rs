// SPDX-License-Identifier: GPL-3.0-or-later

//! `node adopt <id> --address <ipv4> --interface <bsd> --root-identity
//! <key> --agent <binary>` (design §13.2 step 3, for a VPS that exists
//! already): installs the agent with the operator's own root key, then
//! hands the VPS to Mooring's keys.
//!
//! 1. The agent is uploaded over SSH with the operator's root key, over a
//!    connection this process opens bound to the M7 (`node::dial`), checked
//!    against the host key `node new` pinned.
//! 2. `Bootstrap` runs with that key. It replaces root's `authorized_keys`
//!    with the bootstrap and operations lines, so the operator's own key
//!    stops working, and it generates a new host key, which the Mac pins at
//!    once, in `known_hosts` and in the state.
//! 3. The operations key must reach the forced command: an empty request
//!    is answered `UnknownRequest` (otherwise `ForcedCommandNotActive`).
//! 4. `Hello` gives the node's site (`render::adoption_site`), and asserts
//!    Debian 13, a 6.12-series kernel, bbr and fq.
//! 5. `RevokeBootstrap`, then the node is recorded `Adopted`; the store
//!    deletes the bootstrap key from the keychain after that commit, and the
//!    command deletes its file.
//!
//! The design reboots between steps 3 and 4. A VPS made by hand is
//! rebooted from its provider's console, which Mooring does not reach, so
//! the reboot is the operator's, and `Hello` checks the running system.
//! A run that stopped after step 2 is resumed with `--resume`, which starts
//! at step 3: the operator's root key no longer works then.

use std::fs;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use mooring_agent_proto::{AgentError, LineRequest, RequestKind, Response, Sha256Hex};
use mooring_model::iface::BsdName;
use mooring_model::ipv4::PublicIpv4;
use mooring_model::node::{NodeAddress, NodeLifecycle, SshPin};
use mooring_model::secret::{SecretKind, SecretMaterial, SecretRef};
use mooring_model::{Ed25519Pub, NodeId, Sha256Digest};
use mooring_render::{adoption_site, ssh_ed25519_key, ssh_ed25519_pub};
use mooring_store::{Store, update_config_with_secrets};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::node::dial::facing_the_m7;
use crate::node::files::NodeFiles;
use crate::node::ssh::{Remote, SshTarget};
use crate::node::{NodeError, NodeSession};
use crate::state::{load, output, state_change};

/// The largest agent binary read, in bytes.
const MAX_AGENT_BYTES: u64 = 64 * 1024 * 1024;

/// What `node adopt` was given.
#[derive(Debug, Clone)]
pub(crate) struct AdoptArgs<'a> {
    pub(crate) node: &'a NodeId,
    pub(crate) address: Ipv4Addr,
    pub(crate) interface: &'a BsdName,
    pub(crate) root_identity: Option<&'a Path>,
    pub(crate) agent: &'a Path,
    pub(crate) resume: bool,
    pub(crate) yes: bool,
}

/// `node adopt`. Every step's failure is reported with the step; the state
/// records the new host key as soon as the node reports it, and the node as
/// `Adopted` only at the end.
pub(crate) fn adopt(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    args: &AdoptArgs<'_>,
) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let store = Store::new(support.clone());
    let state = load(&store)?;
    let node = state
        .deployment
        .nodes()
        .get(args.node)
        .ok_or_else(|| LocalError::UnknownNode {
            node: args.node.clone(),
        })?;
    if node.lifecycle != NodeLifecycle::Planned {
        return Err(LocalError::NodeNotPlanned {
            node: args.node.clone(),
            stage: node.lifecycle.stage(),
        }
        .into());
    }
    let address = PublicIpv4::new(args.address).map_err(LocalError::NodeAddress)?;
    let egress = facing_the_m7(env, args.interface)?;
    let agent = read_agent(args.agent)?;
    let agent_sha = Sha256Hex::from_bytes(*Sha256Digest::of(&agent).as_bytes());
    let files = NodeFiles::of(&support, args.node);
    files.create_dir()?;
    let ops = files.ops_public(args.node)?;
    let seed = match env
        .secrets
        .get(&SecretRef::NodeSshBootstrapPrivate(args.node.clone()))
        .map_err(LocalError::Keychain)?
    {
        SecretMaterial::Ed25519Seed(seed) => seed,
        other => {
            return Err(LocalError::SecretKind {
                expected: SecretKind::Ed25519Seed,
                found: other.kind(),
            }
            .into());
        }
    };
    let bootstrap = files.write_bootstrap_key(args.node, seed)?;
    let mooringctl = std::env::current_exe().map_err(LocalError::CurrentExe)?;
    let links = env.nodes;
    let target = |identity: &Path, remote: Remote| {
        links.open(SshTarget {
            address,
            identity: identity.to_path_buf(),
            known_hosts: files.known_hosts(),
            egress,
            relay_dir: files.dir().to_path_buf(),
            mooringctl: mooringctl.clone(),
            remote,
            deadline: None,
        })
    };
    let mut generation = state.deployment.config_generation();
    if args.resume {
        files.pin_host_key(address.get(), node.ssh.host_ed25519)?;
    } else {
        let root_identity = args.root_identity.ok_or(LocalError::RootIdentityMissing)?;
        files.pin_host_key(address.get(), node.ssh.host_ed25519)?;
        writeln!(
            out,
            "adopting {} at {}: Bootstrap replaces root's authorized_keys there, so the key {} stops working and only Mooring's operations key, forced to the agent, logs in afterwards; the VPS gets a new host key",
            args.node,
            address.get(),
            root_identity.display()
        )
        .map_err(output)?;
        confirm(env, args.yes, "Hand this VPS to Mooring?")?;
        let staged = format!("/root/.mooring-agent-{agent_sha}");
        target(root_identity, Remote::Command(upload_command(&staged)))
            .run(&agent)
            .map_err(|error| step(Step::Upload, error))?;
        let reply = target(
            root_identity,
            Remote::Command(format!(
                "{staged} serve-ssh --role bootstrap; status=$?; rm -f {staged}; exit $status"
            )),
        )
        .request(&LineRequest::Bootstrap {
            expected_agent_sha: agent_sha,
            bootstrap_pubkey: ssh_ed25519_key(&bootstrap).map_err(LocalError::Render)?,
            ops_pubkey: ssh_ed25519_key(&ops).map_err(LocalError::Render)?,
        })
        .map_err(|error| step(Step::Bootstrap, error))?;
        let Response::BootstrapDone { host_pubkey } = reply else {
            return Err(unexpected(Step::Bootstrap, RequestKind::Bootstrap, &reply));
        };
        let host = ssh_ed25519_pub(&host_pubkey).map_err(LocalError::Render)?;
        files.pin_host_key(address.get(), host)?;
        generation = pin_in_state(&store, args.node, generation, host)?;
        writeln!(
            out,
            "bootstrapped {}: new host key {} pinned",
            args.node,
            mooring_keys::SshPublicKey::from(host).fingerprint()
        )
        .map_err(output)?;
    }
    let ops_key = files.ops_key();
    forced_command_active(target(&ops_key, Remote::Command("true".to_owned())).as_mut())?;
    let mut agent_link = target(&ops_key, Remote::ForcedCommand);
    let reply = agent_link
        .request(&LineRequest::Hello)
        .map_err(|error| step(Step::Hello, error))?;
    let Response::Hello(hello) = reply else {
        return Err(unexpected(Step::Hello, RequestKind::Hello, &reply));
    };
    check_host(&hello.host)?;
    let site =
        adoption_site(NodeAddress::Public(address), &hello.host).map_err(LocalError::Render)?;
    let reply = agent_link
        .request(&LineRequest::RevokeBootstrap)
        .map_err(|error| step(Step::RevokeBootstrap, error))?;
    if reply != Response::BootstrapRevoked {
        return Err(unexpected(
            Step::RevokeBootstrap,
            RequestKind::RevokeBootstrap,
            &reply,
        ));
    }
    update_config_with_secrets(&store, env.secrets, generation, Vec::new(), |mut parts| {
        for candidate in &mut parts.nodes {
            if candidate.id == *args.node {
                candidate.lifecycle = NodeLifecycle::Adopted { site: site.clone() };
            }
        }
        Ok(parts)
    })
    .map_err(state_change)?;
    files.remove_bootstrap_key()?;
    writeln!(
        out,
        "adopted {}: Debian {}, kernel {}, {} on {}; the Mac's address as the node saw it: {}\nnext: `mooringctl node target check {}`, then `node apply {}`",
        args.node,
        hello.host.debian_major,
        hello.host.kernel.as_str(),
        hello.host.uplink.as_str(),
        hello.host.vps4,
        hello.client_ip,
        args.node,
        args.node
    )
    .map_err(output)?;
    Ok(())
}

/// The adoption step a failure happened at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Uploading the agent with the operator's root key.
    Upload,
    /// `Bootstrap` with the operator's root key.
    Bootstrap,
    /// The operations key's forced command.
    ForcedCommand,
    /// `Hello` over the operations key.
    Hello,
    /// `RevokeBootstrap` over the operations key.
    RevokeBootstrap,
}

impl Step {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Upload => "uploading the agent",
            Self::Bootstrap => "Bootstrap",
            Self::ForcedCommand => "the operations key's forced command",
            Self::Hello => "Hello",
            Self::RevokeBootstrap => "RevokeBootstrap",
        }
    }
}

fn step(at: Step, source: NodeError) -> CommandError {
    LocalError::AdoptStep { step: at, source }.into()
}

fn unexpected(at: Step, request: RequestKind, reply: &Response) -> CommandError {
    step(
        at,
        NodeError::Unexpected {
            request,
            response: reply.kind(),
        },
    )
}

/// The remote command that stores the agent: it writes stdin to
/// `<staged>.part` with mode 0700 and renames it into place. `staged` is
/// built from a hex digest, so it needs no quoting.
fn upload_command(staged: &str) -> String {
    format!(
        "umask 077 && cat > {staged}.part && chmod 0700 {staged}.part && mv {staged}.part {staged}"
    )
}

/// Reads the agent binary, at most [`MAX_AGENT_BYTES`].
fn read_agent(path: &Path) -> Result<Vec<u8>, LocalError> {
    let failed = |source| LocalError::AgentFile {
        path: path.to_path_buf(),
        source,
    };
    let file = fs::File::open(path).map_err(failed)?;
    let mut bytes = Vec::new();
    file.take(MAX_AGENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() as u64 > MAX_AGENT_BYTES || bytes.is_empty() {
        return Err(LocalError::AgentSize {
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

/// Records `host` as the planned node's pinned host key: the key the VPS
/// has from now on. A configuration change; returns the new generation.
fn pin_in_state(
    store: &Store,
    node: &NodeId,
    generation: mooring_model::counters::ConfigGeneration,
    host: Ed25519Pub,
) -> Result<mooring_model::counters::ConfigGeneration, LocalError> {
    let state = store
        .update_config(generation, |mut parts| {
            for candidate in &mut parts.nodes {
                if candidate.id == *node {
                    candidate.ssh = SshPin { host_ed25519: host };
                }
            }
            Ok::<_, std::convert::Infallible>(parts)
        })
        .map_err(state_change)?;
    Ok(state.deployment.config_generation())
}

/// Step 3: an empty request over the operations key must reach the agent,
/// which answers it `UnknownRequest`. A session that runs the command
/// instead (no forced command) prints nothing.
fn forced_command_active(agent: &mut dyn NodeSession) -> Result<(), CommandError> {
    match agent.empty_request() {
        Err(NodeError::Agent(AgentError::UnknownRequest)) => Ok(()),
        Err(NodeError::Ssh { code: Some(0), .. }) => Err(LocalError::ForcedCommandNotActive.into()),
        Err(error) => Err(step(Step::ForcedCommand, error)),
        Ok(reply) => Err(unexpected(Step::ForcedCommand, RequestKind::Hello, &reply)),
    }
}

/// The facts adoption asserts and does not record (design §13.2 step 3):
/// Debian 13, a 6.12-series kernel, bbr and fq.
pub(crate) fn check_host(host: &mooring_agent_proto::HostFacts) -> Result<(), LocalError> {
    let kernel = host.kernel.as_str();
    let checks = [
        (
            host.debian_major == 13,
            "Debian 13",
            host.debian_major.to_string(),
        ),
        (
            kernel.starts_with("6.12.") || kernel == "6.12",
            "a 6.12-series kernel",
            kernel.to_owned(),
        ),
        (
            host.congestion_control.as_str() == "bbr",
            "bbr congestion control",
            host.congestion_control.as_str().to_owned(),
        ),
        (
            host.qdisc.as_str() == "fq",
            "the fq queueing discipline",
            host.qdisc.as_str().to_owned(),
        ),
    ];
    for (holds, wanted, found) in checks {
        if !holds {
            return Err(LocalError::HostUnsupported { wanted, found });
        }
    }
    Ok(())
}
