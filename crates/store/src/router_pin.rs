//! The router identity (design §15.6 rule 4): the M7 gateway's link-layer
//! address, which `mooringctl router pin` records and the router adapter
//! compares before it sends the M7's admin password, and the Mac's
//! interface to the M7, which the daemon polls on before a deployment
//! exists (design §5.1).
//!
//! It lives beside `state.json` as `router-identity.json`, outside the
//! state: it is a fact about the Mac's attachment, not a deployment record,
//! and it never reaches the repository or a fixture.
//!
//! Version 2 (2026-10-23, M7) records the interface; version 1, which
//! `router pin` wrote before, has none. A version-1 file is still read, as
//! a pin without an interface ([`StoredPin::WithoutInterface`]), so that
//! the identity check keeps working and the daemon can say what is
//! missing; `router pin --interface <bsd>` rewrites it as version 2. Once
//! no version-1 file remains, reading version 1 can go.

use std::fmt;
use std::path::Path;

use mooring_model::iface::{BsdName, MacAddr};
use mooring_model::time::UnixTime;
use serde::{Deserialize, Serialize};

use crate::durable::{self, Bounded, LockMode, StateLock, read_bounded};
use crate::error::{IoOp, StoreError};
use crate::store::LOCK_FILE;

/// The router identity's file name.
pub const ROUTER_PIN_FILE: &str = "router-identity.json";

/// The largest router identity file read, in bytes; a larger file is
/// corrupt (the document is about 110 bytes).
pub const MAX_ROUTER_PIN_BYTES: usize = 4096;

/// The format version this build writes.
const ROUTER_PIN_VERSION: u32 = 2;

/// The earlier format version this build still reads.
const ROUTER_PIN_VERSION_WITHOUT_INTERFACE: u32 = 1;

/// The recorded identity of the M7: its gateway's link-layer address, the
/// Mac's interface to it, and when they were recorded (informational; only
/// the address is compared).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterPin {
    /// The M7 gateway's link-layer address on the Mac's interface.
    pub gateway_lladdr: MacAddr,
    /// The Mac's interface to the M7, as `router pin --interface` named it.
    pub interface: BsdName,
    /// When `mooringctl router pin` recorded it (the Mac's clock).
    pub pinned_at: UnixTime,
}

/// The router identity as a file records it: version 2, or version 1, which
/// records no interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredPin {
    /// A version-2 file.
    Current(RouterPin),
    /// A version-1 file: the address alone.
    WithoutInterface {
        /// The M7 gateway's link-layer address.
        gateway_lladdr: MacAddr,
        /// When it was recorded.
        pinned_at: UnixTime,
    },
}

impl StoredPin {
    /// The pinned address, which the identity check compares.
    #[must_use]
    pub const fn gateway_lladdr(&self) -> MacAddr {
        match self {
            Self::Current(pin) => pin.gateway_lladdr,
            Self::WithoutInterface { gateway_lladdr, .. } => *gateway_lladdr,
        }
    }

    /// The recorded interface; `None` in a version-1 file.
    #[must_use]
    pub const fn interface(&self) -> Option<&BsdName> {
        match self {
            Self::Current(pin) => Some(&pin.interface),
            Self::WithoutInterface { .. } => None,
        }
    }
}

/// Why a router identity file cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouterPinFault {
    /// The file is larger than [`MAX_ROUTER_PIN_BYTES`].
    TooLarge,
    /// The file is not a router identity of its version: not JSON, a
    /// missing, unknown or ill-typed key, an address that is not a unicast
    /// link-layer address, or an interface that is not a BSD name.
    Undecodable,
    /// The file names a format version other than 1 or 2.
    UnsupportedVersion,
}

impl fmt::Display for RouterPinFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "it is larger than 4096 bytes",
            Self::Undecodable => "it is not a router identity document of the version it names",
            Self::UnsupportedVersion => "it names a format version other than 1 or 2",
        })
    }
}

/// The version-2 document on disk: keys in this order, unknown keys
/// refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinDocument {
    version: u32,
    gateway_lladdr: MacAddr,
    interface: BsdName,
    pinned_at: UnixTime,
}

/// The version-1 document, read only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinDocumentWithoutInterface {
    #[serde(rename = "version")]
    _version: u32,
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
/// not a router identity of version 1 or 2 is `RouterPinCorrupt`.
pub fn read_router_pin(dir: &Path) -> Result<Option<StoredPin>, StoreError> {
    let path = dir.join(ROUTER_PIN_FILE);
    let corrupt = |fault| StoreError::RouterPinCorrupt {
        path: path.clone(),
        fault,
    };
    let bytes = match read_bounded(&path, MAX_ROUTER_PIN_BYTES, IoOp::ReadRouterPin)? {
        Bounded::Absent => return Ok(None),
        Bounded::TooLarge => return Err(corrupt(RouterPinFault::TooLarge)),
        Bounded::Document(bytes) => bytes,
    };
    let version: PinVersion =
        serde_json::from_slice(&bytes).map_err(|_| corrupt(RouterPinFault::Undecodable))?;
    match version.version {
        ROUTER_PIN_VERSION => {
            let document: PinDocument =
                serde_json::from_slice(&bytes).map_err(|_| corrupt(RouterPinFault::Undecodable))?;
            Ok(Some(StoredPin::Current(RouterPin {
                gateway_lladdr: document.gateway_lladdr,
                interface: document.interface,
                pinned_at: document.pinned_at,
            })))
        }
        ROUTER_PIN_VERSION_WITHOUT_INTERFACE => {
            let document: PinDocumentWithoutInterface =
                serde_json::from_slice(&bytes).map_err(|_| corrupt(RouterPinFault::Undecodable))?;
            Ok(Some(StoredPin::WithoutInterface {
                gateway_lladdr: document.gateway_lladdr,
                pinned_at: document.pinned_at,
            }))
        }
        _ => Err(corrupt(RouterPinFault::UnsupportedVersion)),
    }
}

/// Records `pin` in `dir` as version 2, replacing any earlier one, under
/// the store's exclusive lock and with the store's durable write (temporary
/// file, fsync, rename, directory fsync; mode 0600). The directory must
/// exist: the store never creates it.
///
/// The format is `{"version":2,"gateway_lladdr":"aa:bb:cc:dd:ee:ff",
/// "interface":"en9","pinned_at":<seconds>}`, pretty-printed, with a final
/// newline.
pub fn write_router_pin(dir: &Path, pin: &RouterPin) -> Result<(), StoreError> {
    let document = PinDocument {
        version: ROUTER_PIN_VERSION,
        gateway_lladdr: pin.gateway_lladdr,
        interface: pin.interface.clone(),
        pinned_at: pin.pinned_at,
    };
    let mut bytes =
        serde_json::to_vec_pretty(&document).map_err(|source| StoreError::Encode { source })?;
    bytes.push(b'\n');
    let _lock = StateLock::acquire(&dir.join(LOCK_FILE), LockMode::Exclusive)?;
    durable::write_durably(dir, ROUTER_PIN_FILE, &bytes)
}
