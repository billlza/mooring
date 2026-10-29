// SPDX-License-Identifier: GPL-3.0-or-later

//! The own-network declarations (design §10.2, P0-2): the networks the
//! operator contracts for, which `mooringctl exit allow-network` declares
//! and the daemon reads every tick, kept beside `state.json` as
//! `allowed-networks.json`. Like the router identity, the file is a fact
//! about the Mac's attachments, not a deployment record: it never reaches
//! the repository, a fixture, an export or a report, and `state.json` keeps
//! its version.
//!
//! Version 1 (2026-10-29): `{"version": 1, "networks": [{"name", "kind",
//! "router": {"addr", "lladdr"}, "declared_at"}, …]}`, sorted by name. The
//! CLI's declare and revoke are each one read-modify-write under the
//! store's exclusive lock, so two commands cannot lose each other's change;
//! the daemon reads without the lock, as the durable write replaces the
//! file atomically.
//!
//! The file is bounded at [`MAX_ALLOWED_NETWORKS_BYTES`] on both sides: a
//! reader refuses a larger file as corrupt, so a declaration that would
//! take the document past the bound is refused (`Full`) with the file
//! unchanged, and a reader never meets a file this module wrote and
//! refuses. A withdrawal only shrinks the document, and so makes room.

use std::fmt;
use std::path::Path;

use mooring_model::ids::LocalLabel;
use mooring_model::iface::RouterIdentity;
use mooring_model::own_network::{OwnNetwork, OwnNetworkKind, OwnNetworks};
use mooring_model::time::UnixTime;
use serde::{Deserialize, Serialize};

use crate::durable::{self, Bounded, LockMode, StateLock, read_bounded};
use crate::error::{IoOp, StoreError};
use crate::store::LOCK_FILE;

/// The declarations' file name.
pub const ALLOWED_NETWORKS_FILE: &str = "allowed-networks.json";

/// The largest declarations file read or written, in bytes: a larger file
/// is corrupt to a reader, so a writer never makes one (a declaration with a
/// short label is about 190 bytes, so this bounds the count too, at about
/// 85).
pub const MAX_ALLOWED_NETWORKS_BYTES: usize = 16 * 1024;

/// The format version this build reads and writes.
const ALLOWED_NETWORKS_VERSION: u32 = 1;

/// Why a declarations file cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedNetworksFault {
    /// The file is larger than [`MAX_ALLOWED_NETWORKS_BYTES`].
    TooLarge,
    /// The file is not a version-1 declaration document: not JSON, a
    /// missing, unknown or ill-typed key, a label, kind, address or
    /// link-layer address the model refuses.
    Undecodable,
    /// The file names a format version other than 1.
    UnsupportedVersion,
    /// The file declares one name twice.
    DuplicateName,
}

impl fmt::Display for AllowedNetworksFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "it is larger than 16384 bytes",
            Self::Undecodable => "it is not an allowed-networks document of version 1",
            Self::UnsupportedVersion => "it names a format version other than 1",
            Self::DuplicateName => "it declares one name twice",
        })
    }
}

/// What declaring a network did. Two of the three write nothing, so a
/// caller must look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Declaration {
    /// The network is declared and the file written.
    Recorded,
    /// A network of that name was declared already; nothing was written.
    AlreadyDeclared,
    /// With this network the file would be larger than
    /// [`MAX_ALLOWED_NETWORKS_BYTES`], which no reader accepts; nothing was
    /// written. Withdrawing a declaration makes room.
    Full {
        /// How many networks are declared.
        declared: usize,
    },
}

/// The document on disk: keys in this order, unknown keys refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    networks: Vec<Entry>,
}

/// One declaration on disk.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: LocalLabel,
    kind: OwnNetworkKind,
    router: RouterIdentity,
    declared_at: UnixTime,
}

/// The version alone, read first so that another version is named as such
/// whatever keys it has.
#[derive(Deserialize)]
struct Version {
    version: u32,
}

/// Reads the declarations in `dir`: none when the file does not exist; any
/// other read failure is `Io`, and a file that is not a version-1
/// declaration document is `AllowedNetworksCorrupt`.
pub fn read_allowed_networks(dir: &Path) -> Result<OwnNetworks, StoreError> {
    let path = dir.join(ALLOWED_NETWORKS_FILE);
    let corrupt = |fault| StoreError::AllowedNetworksCorrupt {
        path: path.clone(),
        fault,
    };
    let bytes = match read_bounded(&path, MAX_ALLOWED_NETWORKS_BYTES, IoOp::ReadAllowedNetworks)? {
        Bounded::Absent => return Ok(OwnNetworks::new()),
        Bounded::TooLarge => return Err(corrupt(AllowedNetworksFault::TooLarge)),
        Bounded::Document(bytes) => bytes,
    };
    let version: Version =
        serde_json::from_slice(&bytes).map_err(|_| corrupt(AllowedNetworksFault::Undecodable))?;
    if version.version != ALLOWED_NETWORKS_VERSION {
        return Err(corrupt(AllowedNetworksFault::UnsupportedVersion));
    }
    let document: Document =
        serde_json::from_slice(&bytes).map_err(|_| corrupt(AllowedNetworksFault::Undecodable))?;
    let mut networks = OwnNetworks::new();
    for entry in document.networks {
        let network = OwnNetwork {
            kind: entry.kind,
            router: entry.router,
            declared_at: entry.declared_at,
        };
        if networks.insert(entry.name, network).is_some() {
            return Err(corrupt(AllowedNetworksFault::DuplicateName));
        }
    }
    Ok(networks)
}

/// The version-1 document for `networks`, pretty-printed and ending in a
/// newline: the file's bytes, exactly.
fn encode(networks: &OwnNetworks) -> Result<Vec<u8>, StoreError> {
    let document = Document {
        version: ALLOWED_NETWORKS_VERSION,
        networks: networks
            .iter()
            .map(|(name, network)| Entry {
                name: name.clone(),
                kind: network.kind,
                router: network.router,
                declared_at: network.declared_at,
            })
            .collect(),
    };
    let mut bytes =
        serde_json::to_vec_pretty(&document).map_err(|source| StoreError::Encode { source })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The document for `networks` when it is within
/// [`MAX_ALLOWED_NETWORKS_BYTES`], the bound every reader holds the file to,
/// and `None` when it is not: the one place the bound meets a write.
fn encode_within_bound(networks: &OwnNetworks) -> Result<Option<Vec<u8>>, StoreError> {
    let bytes = encode(networks)?;
    Ok((bytes.len() <= MAX_ALLOWED_NETWORKS_BYTES).then_some(bytes))
}

/// Whether the file can hold `networks`, so that declaring the last of them
/// would be `Recorded` rather than `Full`. The CLI asks before it asks the
/// operator anything; the answer under the lock is the store's.
pub fn allowed_networks_fit(networks: &OwnNetworks) -> Result<bool, StoreError> {
    Ok(encode_within_bound(networks)?.is_some())
}

/// Writes a document from [`encode`] with the store's durable write
/// (temporary file, fsync, rename, directory fsync; mode 0600). The caller
/// holds the exclusive lock. The directory must exist: the store never
/// creates it.
fn write_allowed_networks(dir: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    durable::write_durably(dir, ALLOWED_NETWORKS_FILE, bytes)
}

/// Declares `network` under `name` in `dir`, under the store's exclusive
/// lock: the file is read, the declaration added and the file written, or
/// nothing is written when the name is in use (`AlreadyDeclared`) or the
/// file cannot hold another network (`Full`).
pub fn declare_allowed_network(
    dir: &Path,
    name: LocalLabel,
    network: OwnNetwork,
) -> Result<Declaration, StoreError> {
    let _lock = StateLock::acquire(&dir.join(LOCK_FILE), LockMode::Exclusive)?;
    let mut networks = read_allowed_networks(dir)?;
    if networks.get(&name).is_some() {
        return Ok(Declaration::AlreadyDeclared);
    }
    let declared = networks.len();
    networks.insert(name, network);
    let Some(bytes) = encode_within_bound(&networks)? else {
        return Ok(Declaration::Full { declared });
    };
    write_allowed_networks(dir, &bytes)?;
    Ok(Declaration::Recorded)
}

/// Withdraws the declaration named `name` in `dir`, under the store's
/// exclusive lock, returning it; `None`, and nothing written, when no
/// declaration has that name.
pub fn revoke_allowed_network(
    dir: &Path,
    name: &LocalLabel,
) -> Result<Option<OwnNetwork>, StoreError> {
    let _lock = StateLock::acquire(&dir.join(LOCK_FILE), LockMode::Exclusive)?;
    let mut networks = read_allowed_networks(dir)?;
    let Some(removed) = networks.remove(name) else {
        return Ok(None);
    };
    // The document only shrinks: read within the bound, it stays within it.
    write_allowed_networks(dir, &encode(&networks)?)?;
    Ok(Some(removed))
}
