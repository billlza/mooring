// SPDX-License-Identifier: GPL-3.0-or-later

//! The operations key's sessions to an adopted node (design §10.5): the
//! node's address from its site, its pinned host key, and the interface
//! that faces the M7.

use std::time::Instant;

use mooring_model::NodeId;
use mooring_model::iface::BsdName;
use mooring_model::node::{Node, NodeAddress, NodeLifecycle};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::node::NodeSession;
use crate::node::dial::facing_the_m7;
use crate::node::files::NodeFiles;
use crate::node::ssh::{Remote, SshTarget};

/// The node `id` in `nodes`, which must be adopted or applied.
pub(crate) fn deployed_node<'d>(
    nodes: &'d std::collections::BTreeMap<NodeId, Node>,
    id: &NodeId,
) -> Result<&'d Node, LocalError> {
    let node = nodes
        .get(id)
        .ok_or_else(|| LocalError::UnknownNode { node: id.clone() })?;
    match node.lifecycle {
        NodeLifecycle::Adopted { .. } | NodeLifecycle::Applied { .. } => Ok(node),
        _ => Err(LocalError::NodeNotDeployed {
            node: id.clone(),
            stage: node.lifecycle.stage(),
        }),
    }
}

/// The operations key's sessions to `node`, after checking that
/// `interface` faces the M7, each ending by `deadline` if there is one
/// ([`SshTarget::deadline`]). The node's `known_hosts` is rewritten from
/// the state's pin, so the pin in the state is the one ssh checks.
pub(crate) fn ops_session<'a>(
    env: &Env<'a>,
    node: &Node,
    interface: &BsdName,
    deadline: Option<Instant>,
) -> Result<Box<dyn NodeSession + 'a>, CommandError> {
    facing_the_m7(env, interface)?;
    let site = match &node.lifecycle {
        NodeLifecycle::Adopted { site } | NodeLifecycle::Applied { site, .. } => site,
        other => {
            return Err(LocalError::NodeNotDeployed {
                node: node.id.clone(),
                stage: other.stage(),
            }
            .into());
        }
    };
    let NodeAddress::Public(address) = site.address;
    let files = NodeFiles::of(&support_dir(env)?, &node.id);
    files.create_dir()?;
    files.pin_host_key(address.get(), node.ssh.host_ed25519)?;
    let links = env.nodes;
    let session: Box<dyn NodeSession + 'a> = links.open(SshTarget {
        address,
        identity: files.ops_key(),
        known_hosts: files.known_hosts(),
        interface: interface.clone(),
        mooringctl: std::env::current_exe().map_err(LocalError::CurrentExe)?,
        remote: Remote::ForcedCommand,
        deadline,
    });
    Ok(session)
}
