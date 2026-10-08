// SPDX-License-Identifier: GPL-3.0-or-later

//! Ed25519 SSH keys and a small OpenSSH encoder (design §6.3, §8.9, §10.5).
//!
//! The formats follow OpenSSH (`PROTOCOL.key`, `sshkey.c`) and RFC 8709:
//! - the public key blob is `string "ssh-ed25519"`, `string key[32]`;
//! - a public line is `ssh-ed25519 <base64 blob>[ <comment>]`;
//! - a `known_hosts` line is `<host> ssh-ed25519 <base64 blob>`;
//! - the fingerprint is `SHA256:` and the unpadded base64 SHA-256 of the blob;
//! - the private key file is `openssh-key-v1`, unencrypted (cipher and KDF
//!   `none`), one key, two equal check integers, padding `1, 2, 3, …` to the
//!   8-byte block, base64 wrapped at 70 columns between the
//!   `OPENSSH PRIVATE KEY` markers.
//!
//! Every format is golden-tested against `/usr/bin/ssh-keygen`.

use std::fmt;
use std::net::Ipv4Addr;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ed25519_dalek::SigningKey;
use mooring_model::secret::Ed25519Seed;
use mooring_model::{Ed25519Pub, Secret, Sha256Digest};
use zeroize::Zeroizing;

use crate::error::KeysError;
use crate::random::{OsRandom, RandomSource, draw};

/// The OpenSSH key type name of Ed25519 keys.
const KEY_TYPE: &str = Ed25519Pub::SSH_KEY_TYPE;
/// The magic that opens an `openssh-key-v1` private key.
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
/// The cipher and KDF name of an unencrypted private key.
const NONE: &[u8] = b"none";
/// The block size the private section is padded to (the `none` cipher's).
const BLOCK_SIZE: usize = 8;
/// The line width OpenSSH wraps the private key's base64 at.
const PEM_LINE_LEN: usize = 70;
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----\n";

/// A comment for an SSH key: at most 64 characters of `A-Z`, `a-z`, `0-9`,
/// `.`, `_`, `@`, `+` and `-`; the default is empty (no comment).
///
/// The alphabet keeps the comment a single token in every OpenSSH file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SshComment(String);

impl SshComment {
    /// The longest comment accepted, in bytes.
    pub const MAX_LEN: usize = 64;

    /// Validates `text` as a comment.
    pub fn parse(text: &str) -> Result<Self, KeysError> {
        let valid = text.len() <= Self::MAX_LEN
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._@+-".contains(&byte));
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(KeysError::InvalidSshComment)
        }
    }

    /// The comment as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The SHA-256 fingerprint of an SSH public key, displayed as OpenSSH
/// prints it: `SHA256:` followed by 43 characters of unpadded base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshFingerprint([u8; 32]);

impl SshFingerprint {
    /// The raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SshFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHA256:{}", STANDARD_NO_PAD.encode(self.0))
    }
}

/// An Ed25519 public key in its OpenSSH encodings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshPublicKey(Ed25519Pub);

impl SshPublicKey {
    /// Wraps an Ed25519 public key.
    #[must_use]
    pub const fn new(key: Ed25519Pub) -> Self {
        Self(key)
    }

    /// The Ed25519 public key.
    #[must_use]
    pub const fn key(&self) -> Ed25519Pub {
        self.0
    }

    /// `ssh-ed25519 <base64>`, the `authorized_keys` form without a comment
    /// that the agent protocol carries.
    #[must_use]
    pub fn authorized_key(&self) -> String {
        self.0.ssh_authorized_key()
    }

    /// The public line, as `ssh-keygen -y` prints it: the
    /// [`authorized_key`](Self::authorized_key) form, then the comment if
    /// there is one.
    #[must_use]
    pub fn line(&self, comment: &SshComment) -> String {
        let key = self.authorized_key();
        if comment.as_str().is_empty() {
            key
        } else {
            format!("{key} {}", comment.as_str())
        }
    }

    /// The `known_hosts` line pinning this host key for `host` on port 22,
    /// the form `ssh` looks up when it is given the bare address.
    #[must_use]
    pub fn known_hosts_line(&self, host: Ipv4Addr) -> String {
        format!("{host} {}", self.authorized_key())
    }

    /// The SHA-256 fingerprint of the key.
    #[must_use]
    pub fn fingerprint(&self) -> SshFingerprint {
        SshFingerprint(*Sha256Digest::of(&self.0.ssh_blob()).as_bytes())
    }
}

impl From<Ed25519Pub> for SshPublicKey {
    fn from(key: Ed25519Pub) -> Self {
        Self(key)
    }
}

/// An OpenSSH private key file (`openssh-key-v1`, unencrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpensshPrivateKey(Secret<String>);

impl OpensshPrivateKey {
    /// Borrows the file text, which ends with a newline.
    #[must_use]
    pub fn expose_pem(&self) -> &str {
        self.0.expose_secret()
    }
}

/// An Ed25519 SSH key pair: the operations key, the one-time bootstrap key
/// or the one-time host key of a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyPair {
    seed: Ed25519Seed,
    public: SshPublicKey,
}

impl SshKeyPair {
    /// Generates a key pair from a seed drawn from the operating system's
    /// random source.
    pub fn generate() -> Result<Self, KeysError> {
        Self::generate_from(&mut OsRandom)
    }

    pub(crate) fn generate_from(source: &mut impl RandomSource) -> Result<Self, KeysError> {
        let bytes = draw::<32>(source)?;
        let seed = Ed25519Seed::from_bytes(*bytes).map_err(KeysError::MaterialRejected)?;
        Self::from_seed(seed)
    }

    /// Derives the public key of a stored seed (RFC 8032 §5.1.5).
    pub fn from_seed(seed: Ed25519Seed) -> Result<Self, KeysError> {
        let signing = SigningKey::from_bytes(seed.expose_bytes());
        let public = Ed25519Pub::from_bytes(signing.verifying_key().to_bytes())
            .map_err(KeysError::MaterialRejected)?;
        Ok(Self {
            seed,
            public: SshPublicKey(public),
        })
    }

    /// The private seed.
    #[must_use]
    pub const fn seed(&self) -> &Ed25519Seed {
        &self.seed
    }

    /// The public key.
    #[must_use]
    pub const fn public(&self) -> SshPublicKey {
        self.public
    }

    /// Splits the pair into its seed and public key.
    #[must_use]
    pub fn into_parts(self) -> (Ed25519Seed, SshPublicKey) {
        (self.seed, self.public)
    }

    /// The private key file. Like `ssh-keygen`, it draws the check integer
    /// from the random source.
    pub fn openssh_private_key(
        &self,
        comment: &SshComment,
    ) -> Result<OpensshPrivateKey, KeysError> {
        self.openssh_private_key_from(&mut OsRandom, comment)
    }

    pub(crate) fn openssh_private_key_from(
        &self,
        source: &mut impl RandomSource,
        comment: &SshComment,
    ) -> Result<OpensshPrivateKey, KeysError> {
        let check = draw::<4>(source)?;
        Ok(self.encode_private_key(comment, u32::from_be_bytes(*check)))
    }

    /// Encodes the private key file with the given check integer.
    fn encode_private_key(&self, comment: &SshComment, check: u32) -> OpensshPrivateKey {
        let private = self.private_section(comment, check);
        let blob = self.public.0.ssh_blob();
        let mut file = SshBuffer::with_capacity(
            AUTH_MAGIC.len()
                + string_len(NONE.len()) * 2
                + string_len(0)
                + 4
                + string_len(blob.len())
                + string_len(private.len()),
        );
        file.put_raw(AUTH_MAGIC);
        file.put_string(NONE);
        file.put_string(NONE);
        file.put_string(b"");
        file.put_u32(1);
        file.put_string(&blob);
        file.put_string(private.as_bytes());
        OpensshPrivateKey(Secret::new(armor(file.as_bytes())))
    }

    /// The private section: check integers, the key and the comment,
    /// padded with `1, 2, 3, …` to the block size.
    fn private_section(&self, comment: &SshComment, check: u32) -> SshBuffer {
        let public = self.public.0.as_bytes();
        let comment = comment.as_str().as_bytes();
        let unpadded = 4
            + 4
            + string_len(KEY_TYPE.len())
            + string_len(public.len())
            + string_len(self.seed.expose_bytes().len() + public.len())
            + string_len(comment.len());
        let padding = (BLOCK_SIZE - unpadded % BLOCK_SIZE) % BLOCK_SIZE;
        let mut section = SshBuffer::with_capacity(unpadded + padding);
        section.put_u32(check);
        section.put_u32(check);
        section.put_string(KEY_TYPE.as_bytes());
        section.put_string(public);
        // OpenSSH's Ed25519 private key is the seed followed by the public key.
        section.put_string_parts(&[self.seed.expose_bytes(), public]);
        section.put_string(comment);
        for byte in (1_u8..).take(padding) {
            section.put_raw(&[byte]);
        }
        section
    }
}

/// The encoded length of an SSH `string` holding `len` bytes.
const fn string_len(len: usize) -> usize {
    4 + len
}

/// A zeroizing byte buffer with the SSH wire encoders. Callers size it
/// exactly, so it never reallocates and leaves no copy of a secret behind.
struct SshBuffer(Zeroizing<Vec<u8>>);

impl SshBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    fn put_raw(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn put_u32(&mut self, value: u32) {
        self.put_raw(&value.to_be_bytes());
    }

    /// Writes an SSH `string`.
    fn put_string(&mut self, bytes: &[u8]) {
        self.put_string_parts(&[bytes]);
    }

    /// Writes one SSH `string` holding the concatenation of `parts`, without
    /// first copying them into a temporary buffer.
    ///
    /// Every string written here is under 256 bytes (the largest, the
    /// private section, is at most 200 bytes with a 64-byte comment), so the
    /// length always fits its `u32` prefix.
    fn put_string_parts(&mut self, parts: &[&[u8]]) {
        let len: usize = parts.iter().map(|part| part.len()).sum();
        self.put_u32(len as u32);
        for part in parts {
            self.put_raw(part);
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Base64-encodes `bytes` (never empty) between the private key markers,
/// 70 characters per line and every line ending in a newline, as OpenSSH's
/// `sshbuf_dtob64` writes it.
fn armor(bytes: &[u8]) -> String {
    let body = Zeroizing::new(STANDARD.encode(bytes));
    let lines = body.len().div_ceil(PEM_LINE_LEN);
    let mut text = Zeroizing::new(String::with_capacity(
        PEM_BEGIN.len() + body.len() + lines + PEM_END.len(),
    ));
    text.push_str(PEM_BEGIN);
    for (position, symbol) in body.chars().enumerate() {
        if position > 0 && position.is_multiple_of(PEM_LINE_LEN) {
            text.push('\n');
        }
        text.push(symbol);
    }
    text.push('\n');
    text.push_str(PEM_END);
    std::mem::take(&mut *text)
}

#[cfg(test)]
mod tests;
