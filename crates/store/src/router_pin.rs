// SPDX-License-Identifier: GPL-3.0-or-later

//! The router identity (design §15.6 rule 4): the M7 gateway's link-layer
//! address, which `mooringctl router pin` records and the router adapter
//! compares before it sends the M7's admin password.
//!
//! It lives beside `state.json` as `router-identity.json`, outside the
//! state: it is a fact about the Mac's attachment, not a deployment record,
//! and it never reaches the repository or a fixture.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use mooring_model::iface::MacAddr;
use mooring_model::time::UnixTime;
use serde::{Deserialize, Serialize};

use crate::durable::{self, LockMode, StateLock};
use crate::error::{IoOp, StoreError};
use crate::store::LOCK_FILE;

/// The router identity's file name.
pub const ROUTER_PIN_FILE: &str = "router-identity.json";

/// The largest router identity file read, in bytes; a larger file is
/// corrupt (the document is about 90 bytes).
pub const MAX_ROUTER_PIN_BYTES: usize = 4096;

/// The format version this build reads and writes.
const ROUTER_PIN_VERSION: u32 = 1;

/// The recorded identity of the M7: its gateway's link-layer address, and
/// when it was recorded (informational; only the address is compared).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterPin {
    /// The M7 gateway's link-layer address on the Mac's interface.
    pub gateway_lladdr: MacAddr,
    /// When `mooringctl router pin` recorded it (the Mac's clock).
    pub pinned_at: UnixTime,
}

/// Why a router identity file cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouterPinFault {
    /// The file is larger than [`MAX_ROUTER_PIN_BYTES`].
    TooLarge,
    /// The file is not a version-1 router identity: not JSON, a missing,
    /// unknown or ill-typed key, or an address that is not a unicast
    /// link-layer address.
    Undecodable,
    /// The file names a format version other than 1.
    UnsupportedVersion,
}

impl fmt::Display for RouterPinFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "it is larger than 4096 bytes",
            Self::Undecodable => "it is not a version-1 router identity document",
            Self::UnsupportedVersion => "it names a format version other than 1",
        })
    }
}

/// The document on disk: keys in this order, unknown keys refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinDocument {
    version: u32,
    gateway_lladdr: MacAddr,
    pinned_at: UnixTime,
}

/// The version alone, read first so that another version is named as such
/// whatever keys it has.
#[derive(Deserialize)]
struct PinVersion {
    version: u32,
}

/// Reads the router identity recorded in `dir`: `Ok(None)` only when the
/// file does not exist; any other read failure is `Io`, and a file that is
/// not a version-1 router identity is `RouterPinCorrupt`.
pub fn read_router_pin(dir: &Path) -> Result<Option<RouterPin>, StoreError> {
    let path = dir.join(ROUTER_PIN_FILE);
    let io_error = |source: io::Error| StoreError::Io {
        op: IoOp::ReadRouterPin,
        path: path.clone(),
        source,
    };
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    // One byte past the limit is read, so an oversized file is detected
    // without reading it all (usize to u64 is lossless on every target).
    let mut bytes = Vec::with_capacity(MAX_ROUTER_PIN_BYTES + 1);
    file.take(MAX_ROUTER_PIN_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let corrupt = |fault| StoreError::RouterPinCorrupt {
        path: path.clone(),
        fault,
    };
    if bytes.len() > MAX_ROUTER_PIN_BYTES {
        return Err(corrupt(RouterPinFault::TooLarge));
    }
    let version: PinVersion =
        serde_json::from_slice(&bytes).map_err(|_| corrupt(RouterPinFault::Undecodable))?;
    if version.version != ROUTER_PIN_VERSION {
        return Err(corrupt(RouterPinFault::UnsupportedVersion));
    }
    let document: PinDocument =
        serde_json::from_slice(&bytes).map_err(|_| corrupt(RouterPinFault::Undecodable))?;
    Ok(Some(RouterPin {
        gateway_lladdr: document.gateway_lladdr,
        pinned_at: document.pinned_at,
    }))
}

/// Records `pin` in `dir`, replacing any earlier one, under the store's
/// exclusive lock and with the store's durable write (temporary file,
/// fsync, rename, directory fsync; mode 0600). The directory must exist:
/// the store never creates it.
///
/// The format is `{"version":1,"gateway_lladdr":"aa:bb:cc:dd:ee:ff",
/// "pinned_at":<seconds>}`, pretty-printed, with a final newline.
pub fn write_router_pin(dir: &Path, pin: &RouterPin) -> Result<(), StoreError> {
    let document = PinDocument {
        version: ROUTER_PIN_VERSION,
        gateway_lladdr: pin.gateway_lladdr,
        pinned_at: pin.pinned_at,
    };
    let mut bytes =
        serde_json::to_vec_pretty(&document).map_err(|source| StoreError::Encode { source })?;
    bytes.push(b'\n');
    let _lock = StateLock::acquire(&dir.join(LOCK_FILE), LockMode::Exclusive)?;
    durable::write_durably(dir, ROUTER_PIN_FILE, &bytes)
}
