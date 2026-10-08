// SPDX-License-Identifier: GPL-3.0-or-later

//! Key, credential and certificate generation for Mooring (design §6, §7,
//! §12).
//!
//! - [`x25519`]: REALITY and WireGuard key pairs (RFC 7748), stored clamped.
//! - [`credentials`]: credential UUIDs, REALITY short ids, passwords and
//!   opaque user ids.
//! - [`cert`]: the per-node Hysteria2 certificate (ECDSA P-256). Only the
//!   certificate is generated here; `mooring-export` derives its SNI and
//!   its SPKI and DER pins from it.
//! - [`ssh`]: Ed25519 SSH keys and the OpenSSH encodings: public and
//!   `known_hosts` lines, the SHA-256 fingerprint and the `openssh-key-v1`
//!   private key file.
//!
//! Randomness comes from the operating system through `getrandom`, except
//! the certificate's P-256 key, which `rcgen` draws from `ring`'s system
//! random source. Nothing here reads a clock: the certificate's issue time
//! is a parameter. Generated material is returned in `mooring-model` types;
//! private material lives only in `Secret`-backed types, whose `Debug` is
//! redacted and which are zeroized on drop.

#![deny(missing_docs)]

mod error;
mod random;
#[cfg(test)]
mod testing;

pub mod cert;
pub mod credentials;
pub mod ssh;
pub mod x25519;

pub use cert::Hy2Certificate;
pub use error::{CertStep, KeysError, KeysErrorKind};
pub use ssh::{OpensshPrivateKey, SshComment, SshFingerprint, SshKeyPair, SshPublicKey};
pub use x25519::{RealityKeyPair, WgKeyPair};
