// SPDX-License-Identifier: GPL-3.0-or-later

//! `viewer_authorized_keys` (design §15.9, decision F5): the remote
//! viewers' keys, which sshd reads for the unprivileged viewer account.
//!
//! One line per viewer, in key order, and nothing else: the viewer role's
//! `restrict,command="…serve-ssh --role viewer"` options, a space and the
//! key's `ssh-ed25519` form. With no viewer the file is empty. A viewer's
//! label is Mac-only and is never written.

use std::collections::BTreeMap;

use mooring_agent_proto::{Role, SshEd25519Key};
use mooring_model::{Ed25519Pub, Viewer};
use zeroize::Zeroizing;

use crate::encode;
use crate::error::RenderError;
use crate::wire;

/// The file's bytes for `viewers`.
pub(crate) fn file(
    viewers: &BTreeMap<Ed25519Pub, Viewer>,
) -> Result<Zeroizing<Vec<u8>>, RenderError> {
    let keys = viewers
        .values()
        .map(|viewer| wire::ssh_ed25519_key(&viewer.key))
        .collect::<Result<Vec<SshEd25519Key>, RenderError>>()?;
    Ok(encode::text(|sink| {
        for key in &keys {
            sink.put(Role::Viewer.authorized_keys_options());
            sink.put(" ");
            sink.put(key.as_str());
            sink.put("\n");
        }
    }))
}
