// SPDX-License-Identifier: GPL-3.0-or-later

//! `node repin <id> --host-key <file> [--yes]` (design §13.2): replaces a
//! planned node's pinned SSH host key, as after reinstalling its VPS.
//!
//! The pin is what `node adopt` checks its first connection against, the
//! one it makes with the operator's own root key, so a pin that matches an
//! impostor hands that host the node. The command therefore names both
//! keys' fingerprints and asks for the new one to be checked on the
//! provider's console, not read over the network. It reads the key as
//! `node new --host-key` does, contacts nothing, and records the pin as a
//! configuration change, as `node adopt` records the key `Bootstrap`
//! makes. `known_hosts` is left alone: every adoption writes it from the
//! state's pin before it connects.

use std::fs;
use std::io::Write;
use std::path::Path;

use mooring_keys::SshPublicKey;
use mooring_model::NodeId;
use mooring_store::Store;

use crate::app::{Env, support_dir};
use crate::error::CommandError;
use crate::exit::confirm;
use crate::node::files::{NodeFiles, read_public_key};
use crate::node::planned::{PlannedAction, pin_in_state, planned};
use crate::state::{load, output};

/// `node repin`. The key already pinned writes nothing and asks nothing.
pub(crate) fn repin(
    env: &mut Env<'_>,
    out: &mut dyn Write,
    id: &NodeId,
    host_key: &Path,
    yes: bool,
) -> Result<(), CommandError> {
    let support = support_dir(env)?;
    let store = Store::new(support.clone());
    let state = load(&store)?;
    let node = planned(&state.deployment, id, PlannedAction::Repinned)?;
    let host = read_public_key(host_key)?;
    let pinned = node.ssh.host_ed25519;
    let fingerprint = SshPublicKey::from(host).fingerprint();
    if host == pinned {
        writeln!(
            out,
            "node {id} pins host key {fingerprint} already; nothing was written"
        )
        .map_err(output)?;
        return Ok(());
    }
    writeln!(
        out,
        "node {id}: planned, host key {} pinned; {} holds {fingerprint}\n`node adopt {id}` logs in as root with your own key to whichever host holds the new key: compare it with the fingerprint the provider's console shows (on the VPS, `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), since a key read over the network, by ssh-keyscan or a first ssh, is no check",
        SshPublicKey::from(pinned).fingerprint(),
        host_key.display()
    )
    .map_err(output)?;
    if fs::symlink_metadata(NodeFiles::of(&support, id).dir()).is_ok() {
        writeln!(
            out,
            "`node adopt {id}` ran on this Mac: if its Bootstrap ran and the VPS was not reinstalled since, the only key to pin is the one Bootstrap made (adoption pins it itself, or says that it could not), and `node adopt {id} --resume` goes on from there; after a reinstall, pin the reinstalled VPS's key and adopt it with --root-identity"
        )
        .map_err(output)?;
    }
    confirm(env, yes, "Pin the new host key?")?;
    let generation = pin_in_state(
        &store,
        id,
        state.deployment.config_generation(),
        host,
        PlannedAction::Repinned,
    )?;
    writeln!(
        out,
        "re-pinned node {id} to host key {fingerprint} (configuration generation {}); next: `mooringctl node adopt {id}`",
        generation.get()
    )
    .map_err(output)?;
    Ok(())
}
