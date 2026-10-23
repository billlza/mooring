// SPDX-License-Identifier: GPL-3.0-or-later

//! A node's files in the support directory (design §10.5, §12):
//! `ssh/<node>/` (0700) holds the operations key `ops_ed25519` (0600) and
//! its `.pub`, the pinned host key as `known_hosts` (0600) and, while the
//! node is adopted, the one-time bootstrap key `bootstrap_ed25519` (0600).
//! `/usr/bin/ssh` reads keys from files only, so these keys are files, not
//! keychain items. Each ssh session's one-time relay socket is bound there
//! too, so only the operator reaches it (`crate::node::dial::RelaySocket`).

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mooring_keys::{SshComment, SshKeyPair, SshPublicKey};
use mooring_model::secret::Ed25519Seed;
use mooring_model::{Ed25519Pub, NodeId};

use crate::error::LocalError;

/// The most bytes read from a public key file: one line.
const MAX_PUBLIC_KEY_BYTES: u64 = 4096;

/// One node's directory of SSH files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeFiles {
    dir: PathBuf,
}

impl NodeFiles {
    /// `<support>/ssh/<node>`.
    pub(crate) fn of(support: &Path, node: &NodeId) -> Self {
        Self {
            dir: support.join("ssh").join(node.as_str()),
        }
    }

    /// The directory, private to the operator (mode 0700, [`Self::create_dir`]).
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The operations key.
    pub(crate) fn ops_key(&self) -> PathBuf {
        self.dir.join("ops_ed25519")
    }

    fn ops_public_path(&self) -> PathBuf {
        self.dir.join("ops_ed25519.pub")
    }

    /// The pinned host key.
    pub(crate) fn known_hosts(&self) -> PathBuf {
        self.dir.join("known_hosts")
    }

    /// The one-time bootstrap key, present only while the node is adopted.
    pub(crate) fn bootstrap_key(&self) -> PathBuf {
        self.dir.join("bootstrap_ed25519")
    }

    /// Creates `ssh/` and `ssh/<node>/` with mode 0700, and sets 0700 on
    /// them if they exist already.
    pub(crate) fn create_dir(&self) -> Result<(), LocalError> {
        let failed = |path: &Path| {
            let path = path.to_path_buf();
            move |source| LocalError::NodeFile { path, source }
        };
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(failed(&self.dir))?;
        for dir in [self.dir.parent().unwrap_or(&self.dir), &self.dir] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(failed(dir))?;
        }
        Ok(())
    }

    /// The operations key's public half: the one written before, or a new
    /// key written now (`ops_ed25519` 0600 and its `.pub`), named after the
    /// node.
    pub(crate) fn ops_public(&self, node: &NodeId) -> Result<Ed25519Pub, LocalError> {
        let public = self.ops_public_path();
        if self.ops_key().exists() {
            return read_public_key(&public);
        }
        let pair = SshKeyPair::generate().map_err(LocalError::Keys)?;
        let comment = SshComment::parse(&format!("mooring-ops-{}", node.as_str()))
            .map_err(LocalError::Keys)?;
        let private = pair
            .openssh_private_key(&comment)
            .map_err(LocalError::Keys)?;
        let (_, key) = pair.into_parts();
        write_new(&self.ops_key(), private.expose_pem().as_bytes())?;
        write_new(&public, format!("{}\n", key.line(&comment)).as_bytes())?;
        read_public_key(&public)
    }

    /// Writes the one-time bootstrap key from its seed, replacing an
    /// earlier copy.
    pub(crate) fn write_bootstrap_key(
        &self,
        node: &NodeId,
        seed: Ed25519Seed,
    ) -> Result<Ed25519Pub, LocalError> {
        let pair = SshKeyPair::from_seed(seed).map_err(LocalError::Keys)?;
        let comment = SshComment::parse(&format!("mooring-bootstrap-{}", node.as_str()))
            .map_err(LocalError::Keys)?;
        let private = pair
            .openssh_private_key(&comment)
            .map_err(LocalError::Keys)?;
        replace(&self.bootstrap_key(), private.expose_pem().as_bytes())?;
        let (_, public) = pair.into_parts();
        Ed25519Pub::parse_ssh_authorized_key(&public.authorized_key()).map_err(LocalError::NodePlan)
    }

    /// Removes the bootstrap key; one that is gone already is fine.
    pub(crate) fn remove_bootstrap_key(&self) -> Result<(), LocalError> {
        let path = self.bootstrap_key();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(LocalError::NodeFile { path, source }),
        }
    }

    /// Pins `host` for `address` as the only line of `known_hosts`.
    pub(crate) fn pin_host_key(
        &self,
        address: Ipv4Addr,
        host: Ed25519Pub,
    ) -> Result<(), LocalError> {
        let line = SshPublicKey::from(host).known_hosts_line(address);
        replace(&self.known_hosts(), format!("{line}\n").as_bytes())
    }
}

/// The Ed25519 key of an OpenSSH public key line in `path`.
pub(crate) fn read_public_key(path: &Path) -> Result<Ed25519Pub, LocalError> {
    let read = |source| LocalError::HostKeyFile {
        path: path.to_path_buf(),
        source,
    };
    if fs::metadata(path).map_err(read)?.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(LocalError::HostKey {
            path: path.to_path_buf(),
        });
    }
    let text = fs::read_to_string(path).map_err(read)?;
    let mut tokens = text.split_ascii_whitespace();
    match (tokens.next(), tokens.next()) {
        (Some(kind), Some(blob)) => Ed25519Pub::parse_ssh_authorized_key(&format!("{kind} {blob}"))
            .map_err(|_| LocalError::HostKey {
                path: path.to_path_buf(),
            }),
        _ => Err(LocalError::HostKey {
            path: path.to_path_buf(),
        }),
    }
}

/// Writes a new file with mode 0600; an existing one is an error.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), LocalError> {
    let failed = |source| LocalError::NodeFile {
        path: path.to_path_buf(),
        source,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(failed)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(failed)
}

/// Replaces `path` with `bytes` through a temporary file (mode 0600) and a
/// rename, so the file is always whole.
fn replace(path: &Path, bytes: &[u8]) -> Result<(), LocalError> {
    let temporary = path.with_extension("partial");
    let failed = |path: &Path| {
        let path = path.to_path_buf();
        move |source| LocalError::NodeFile { path, source }
    };
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(failed(&temporary)(source)),
    }
    write_new(&temporary, bytes)?;
    fs::rename(&temporary, path).map_err(failed(path))
}
