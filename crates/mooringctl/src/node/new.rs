// SPDX-License-Identifier: GPL-3.0-or-later

//! `node new <id> --role primary|standby --host-key <file>` (design §13.2
//! step 1, for a VPS that exists already): plans a node, with fresh secrets
//! and the VPS's own host key pinned.
//!
//! The design's provisioning makes the VPS from cloud-init user-data that
//! carries a one-time host key. A VPS made by hand, as lon1 was on
//! 2026-10-22, already has its host key, so the operator gives that key,
//! read on the VPS, and `node adopt` checks the first connection against
//! it. No user-data is written.

use std::fs;
use std::io::Write;
use std::path::Path;

use mooring_keys::credentials;
use mooring_keys::{Hy2Certificate, RealityKeyPair, SshKeyPair, SshPublicKey, WgKeyPair};
use mooring_model::node::{Hy2Server, Node, NodeLifecycle, NodeRole, RealityServer, SshPin};
use mooring_model::ports::{DEBIAN_EPHEMERAL_PORTS, PortPlan};
use mooring_model::secret::SecretEntry;
use mooring_model::wg::{Keepalive, WgLink};
use mooring_model::{Ed25519Pub, NodeId, UserNodePublic, UserStatus};
use mooring_store::{Store, update_config_with_secrets};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::exit::confirm;
use crate::state::{load, output, state_change};

/// The longest host-key file read, in bytes: one public key line.
const MAX_HOST_KEY_BYTES: u64 = 4096;

/// `node new`: a `Planned` node with its REALITY, tunnel and Hysteria2
/// keys, its probe credentials and its one-time bootstrap key, the next
/// tunnel index, the default port plan, and `host_key` pinned. Every user
/// that is active or suspended gets credentials on it, as `user add` gives
/// them on every node, so the node serves them once applied. The secrets
/// go to the keychain before the state that references them. A
/// configuration change: users' files need a new export once the node is
/// applied.
pub(crate) fn new(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    id: NodeId,
    role: NodeRole,
    host_key: &Path,
    yes: bool,
) -> Result<(), CommandError> {
    let store = Store::new(support_dir(env)?);
    let state = load(&store)?;
    if state.deployment.nodes().contains_key(&id) {
        return Err(LocalError::NodeExists { node: id }.into());
    }
    let host = read_host_key(host_key)?;
    let now = (env.clock)()?;
    let keys = |error| LocalError::Keys(error);
    let (reality_private, reality_public) = RealityKeyPair::generate().map_err(keys)?.into_parts();
    let (vps_private, vps_public) = WgKeyPair::generate().map_err(keys)?.into_parts();
    let (mac_private, mac_public) = WgKeyPair::generate().map_err(keys)?.into_parts();
    let (certificate, hy2_key) = Hy2Certificate::generate(now).map_err(keys)?.into_parts();
    let (bootstrap_seed, _) = SshKeyPair::generate().map_err(keys)?.into_parts();
    let ports = PortPlan::with_defaults(DEBIAN_EPHEMERAL_PORTS).map_err(LocalError::NodePlan)?;
    let mut secrets = vec![
        SecretEntry::NodeRealityPrivate(id.clone(), reality_private),
        SecretEntry::NodeWgVpsPrivate(id.clone(), vps_private),
        SecretEntry::NodeWgMacPrivate(id.clone(), mac_private),
        SecretEntry::NodeHy2Key(id.clone(), hy2_key),
        SecretEntry::NodeSshBootstrapPrivate(id.clone(), bootstrap_seed),
        SecretEntry::ProbeVlessUuid(id.clone(), credentials::credential_uuid().map_err(keys)?),
        SecretEntry::ProbeHy2Password(id.clone(), credentials::password().map_err(keys)?),
        SecretEntry::ProbeLoopUuid(id.clone(), credentials::credential_uuid().map_err(keys)?),
    ];
    for (listener, _) in ports.hy2_listeners() {
        secrets.push(SecretEntry::NodeHy2Obfs(
            id.clone(),
            listener,
            credentials::password().map_err(keys)?,
        ));
    }
    let served: Vec<_> = state
        .deployment
        .users()
        .values()
        .filter(|user| {
            matches!(
                user.status,
                UserStatus::Active | UserStatus::Suspended { .. }
            )
        })
        .map(|user| user.id.clone())
        .collect();
    let mut credentials_of = Vec::new();
    for user in &served {
        credentials_of.push((user.clone(), credentials::short_id().map_err(keys)?));
        secrets.push(SecretEntry::UserVlessUuid(
            user.clone(),
            id.clone(),
            credentials::credential_uuid().map_err(keys)?,
        ));
        secrets.push(SecretEntry::UserHy2Password(
            user.clone(),
            id.clone(),
            credentials::password().map_err(keys)?,
        ));
        secrets.push(SecretEntry::UserLoopUuid(
            user.clone(),
            id.clone(),
            credentials::credential_uuid().map_err(keys)?,
        ));
    }
    let node = Node {
        id: id.clone(),
        role,
        ports,
        wg_index: state.deployment.next_wg_index(),
        ssh: SshPin { host_ed25519: host },
        reality: RealityServer {
            public_key: reality_public,
            probe_short_id: credentials::short_id().map_err(keys)?,
            target: None,
        },
        hy2: Hy2Server { certificate },
        wg: WgLink {
            vps_pub: vps_public,
            mac_pub: mac_public,
            keepalive: Keepalive::DEFAULT,
        },
        lifecycle: NodeLifecycle::Planned,
    };
    writeln!(
        out,
        "node {id}: {}, tunnel 10.77.{}.0/30, host key {} pinned; users served: {}",
        match role {
            NodeRole::Primary => "primary",
            NodeRole::Standby => "standby",
        },
        node.wg_index.get(),
        SshPublicKey::from(host).fingerprint(),
        if served.is_empty() {
            "none yet".to_owned()
        } else {
            served
                .iter()
                .map(|user| user.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    )
    .map_err(output)?;
    confirm(env, yes, "Plan this node?")?;
    let next = state
        .deployment
        .next_wg_index()
        .next()
        .map_err(LocalError::NodePlan)?;
    update_config_with_secrets(
        &store,
        env.secrets,
        state.deployment.config_generation(),
        secrets,
        |mut parts| {
            for user in &mut parts.users {
                if let Some((_, short_id)) =
                    credentials_of.iter().find(|(served, _)| *served == user.id)
                {
                    user.per_node.insert(
                        id.clone(),
                        UserNodePublic {
                            short_id: *short_id,
                        },
                    );
                }
            }
            parts.nodes.push(node);
            parts.next_wg_index = next;
            Ok(parts)
        },
    )
    .map_err(state_change)?;
    writeln!(out, "planned node {id}; next: `mooringctl node adopt {id}`").map_err(output)?;
    Ok(())
}

/// The Ed25519 host key in `path`: one OpenSSH public key line,
/// `ssh-ed25519 <base64>`, with an optional comment.
fn read_host_key(path: &Path) -> Result<Ed25519Pub, LocalError> {
    let read = |source| LocalError::HostKeyFile {
        path: path.to_path_buf(),
        source,
    };
    let metadata = fs::metadata(path).map_err(read)?;
    if metadata.len() > MAX_HOST_KEY_BYTES {
        return Err(LocalError::HostKey {
            path: path.to_path_buf(),
        });
    }
    let text = fs::read_to_string(path).map_err(read)?;
    let mut tokens = text.split_ascii_whitespace();
    let key = match (tokens.next(), tokens.next()) {
        (Some(kind), Some(blob)) => format!("{kind} {blob}"),
        _ => {
            return Err(LocalError::HostKey {
                path: path.to_path_buf(),
            });
        }
    };
    Ed25519Pub::parse_ssh_authorized_key(&key).map_err(|_| LocalError::HostKey {
        path: path.to_path_buf(),
    })
}
