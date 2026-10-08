// SPDX-License-Identifier: GPL-3.0-or-later

//! cloud-init user-data for a planned node (design §8.9, §13.2).
//!
//! It injects the one-time Ed25519 host key generated on the Mac, so the
//! first SSH contact is pinned, and the bootstrap key as root's only
//! authorised key. User-data stays readable from the provider's metadata
//! service, so this host key is a first-contact pin only: Bootstrap
//! replaces it on the VPS. The file is secret-bearing (mode 0600 on the
//! Mac, deleted after adoption).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mooring_agent_proto::SshEd25519Key;
use mooring_model::exact::TextSink;
use mooring_model::node::NodeLifecycle;
use mooring_model::{Deployment, Ed25519Pub, NodeId};
use zeroize::Zeroizing;

use crate::encode;
use crate::error::{HostKeyRule, RenderError};
use crate::wire::ssh_ed25519_key;

const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
const END: &str = "-----END OPENSSH PRIVATE KEY-----\n";
/// OpenSSH wraps the private key's base64 at 70 columns.
const MAX_LINE: usize = 70;
/// The `openssh-key-v1` header of an unencrypted file holding one key, up to
/// its public key: the magic, cipher `none`, KDF `none`, empty KDF options,
/// one key, and the length of the Ed25519 public key blob (OpenSSH
/// `PROTOCOL.key`).
const HEADER: &[u8] = b"openssh-key-v1\0\0\0\0\x04none\0\0\0\x04none\0\0\0\0\0\0\0\x01\0\0\0\x33";
/// The block size the private section is padded to (the `none` cipher's).
const BLOCK_SIZE: usize = 8;
/// An OpenSSH Ed25519 private key: the seed, then the public key.
const PRIVATE_KEY_LEN: usize = 64;

/// Packages installed at first boot.
const PACKAGES: [&str; 5] = [
    "wireguard-tools",
    "nftables",
    "chrony",
    "unattended-upgrades",
    "curl",
];

/// The one-time host private key in OpenSSH's `openssh-key-v1` armor, as
/// `mooring-keys` writes it: one unencrypted Ed25519 key. Parsing reads the
/// public key from the file, so [`cloud_init`] can require it to be the
/// node's pin; the private key itself is opaque to the renderer.
pub struct OpensshHostKey {
    text: Zeroizing<String>,
    public: Ed25519Pub,
}

impl OpensshHostKey {
    /// Accepts the BEGIN line, base64 lines of at most 70 characters and the
    /// END line, each ending in one newline, around one unencrypted
    /// `openssh-key-v1` Ed25519 key (see [`HostKeyRule`]).
    pub fn parse(text: &str) -> Result<Self, RenderError> {
        let invalid = |rule| RenderError::InvalidHostKey { rule };
        let body = text
            .strip_prefix(BEGIN)
            .and_then(|rest| rest.strip_suffix(END))
            .ok_or(invalid(HostKeyRule::Armor))?;
        let file = decode_body(body).ok_or(invalid(HostKeyRule::Body))?;
        let public = file_public_key(&file).ok_or(invalid(HostKeyRule::Contents))?;
        Ok(Self {
            text: Zeroizing::new(text.to_owned()),
            public,
        })
    }

    /// The public key of the host key pair.
    #[must_use]
    pub const fn public_key(&self) -> Ed25519Pub {
        self.public
    }

    fn lines(&self) -> std::str::Lines<'_> {
        self.text.lines()
    }
}

impl fmt::Debug for OpensshHostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpensshHostKey(<redacted>)")
    }
}

/// The bytes the armored body encodes, if it is non-empty lines of at most
/// 70 standard base64 characters, each ending in a newline, that decode
/// together. The buffers holding the key are zeroized.
fn decode_body(body: &str) -> Option<Zeroizing<Vec<u8>>> {
    let lines_ok = body.ends_with('\n')
        && body.split_terminator('\n').all(|line| {
            (1..=MAX_LINE).contains(&line.len())
                && line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        });
    if !lines_ok {
        return None;
    }
    let mut joined = Zeroizing::new(String::with_capacity(body.len()));
    body.lines().for_each(|line| joined.push_str(line));
    let mut file = Zeroizing::new(vec![0_u8; base64::decoded_len_estimate(joined.len())]);
    let len = STANDARD.decode_slice(joined.as_bytes(), &mut file).ok()?;
    file.truncate(len);
    Some(file)
}

/// The public key of an `openssh-key-v1` file holding one unencrypted
/// Ed25519 key, if the private section is well formed and holds the same
/// public key as the header.
fn file_public_key(file: &[u8]) -> Option<Ed25519Pub> {
    let mut reader = SshReader(file.strip_prefix(HEADER)?);
    let public = Ed25519Pub::from_ssh_blob(reader.take(Ed25519Pub::SSH_BLOB_LEN)?).ok()?;
    let private = reader.string()?;
    (reader.0.is_empty() && section_public_key(private)? == *public.as_bytes()).then_some(public)
}

/// The public key the private section holds: two equal check integers,
/// `string "ssh-ed25519"`, `string public[32]`, `string seed[32] ||
/// public[32]`, `string comment`, then `1, 2, 3, …` up to the block size.
fn section_public_key(section: &[u8]) -> Option<[u8; 32]> {
    let mut reader = SshReader(section);
    let checks_equal = reader.take(4)? == reader.take(4)?;
    let key_type = reader.string()?;
    let public: [u8; 32] = reader.string()?.try_into().ok()?;
    let private = reader.string()?;
    let _comment = reader.string()?;
    let padding = reader.0;
    let padded = section.len().is_multiple_of(BLOCK_SIZE)
        && padding.len() < BLOCK_SIZE
        && padding
            .iter()
            .copied()
            .eq(1..=padding.len().try_into().ok()?);
    let valid = checks_equal
        && key_type == Ed25519Pub::SSH_KEY_TYPE.as_bytes()
        && private.len() == PRIVATE_KEY_LEN
        && private.ends_with(&public)
        && padded;
    valid.then_some(public)
}

/// Reads SSH wire encodings (RFC 4251 §5) from the front of a buffer.
struct SshReader<'a>(&'a [u8]);

impl<'a> SshReader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }

    /// A `string`: a `uint32` length, then that many bytes.
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?);
        self.take(usize::try_from(len).ok()?)
    }
}

/// The keys one node's user-data carries.
#[derive(Debug)]
pub struct CloudInitKeys {
    /// The one-time host private key, whose public key must be the node's
    /// pinned host key.
    pub host_private: OpensshHostKey,
    /// The bootstrap key root accepts during adoption.
    pub bootstrap_public: SshEd25519Key,
}

/// Rendered cloud-init user-data. It holds the one-time host private key,
/// so its bytes are zeroized on drop and `Debug` shows only the length.
pub struct UserData(Zeroizing<Vec<u8>>);

impl UserData {
    /// The YAML text, ending with one newline.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for UserData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserData")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Renders the user-data of planned `node`. The host key pair must be the
/// one pinned on the node, so the first SSH contact verifies against it; the
/// public key line is the pin's.
pub fn cloud_init(
    deployment: &Deployment,
    node: &NodeId,
    keys: &CloudInitKeys,
) -> Result<UserData, RenderError> {
    let planned = deployment.node(node)?;
    if planned.lifecycle != NodeLifecycle::Planned {
        return Err(RenderError::NodeNotPlanned {
            node: node.clone(),
            stage: planned.lifecycle.stage(),
        });
    }
    if keys.host_private.public_key() != planned.ssh.host_ed25519 {
        return Err(RenderError::HostKeyNotPinned { node: node.clone() });
    }
    let host_public = ssh_ed25519_key(&planned.ssh.host_ed25519)?;
    Ok(UserData(encode::text(|sink| {
        write(keys, &host_public, sink);
    })))
}

fn write(keys: &CloudInitKeys, host_public: &SshEd25519Key, sink: &mut dyn TextSink) {
    sink.put("#cloud-config\n");
    sink.put("ssh_deletekeys: true\n");
    sink.put("ssh_genkeytypes: []\n");
    sink.put("ssh_keys:\n  ed25519_private: |\n");
    for line in keys.host_private.lines() {
        sink.put("    ");
        sink.put(line);
        sink.put("\n");
    }
    sink.put("  ed25519_public: \"");
    sink.put(host_public.as_str());
    sink.put("\"\n");
    sink.put("disable_root: false\n");
    sink.put("users:\n  - name: root\n    ssh_authorized_keys:\n      - \"");
    sink.put(keys.bootstrap_public.as_str());
    sink.put("\"\n");
    sink.put("package_update: true\n");
    sink.put("packages:\n");
    for package in PACKAGES {
        sink.put("  - ");
        sink.put(package);
        sink.put("\n");
    }
}
